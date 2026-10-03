"""Tests for the Linux serial link and updater; a fake device answers on a pseudo-terminal."""

import base64
import hashlib
import json
import os
import struct
import sys
import tempfile
import threading
import unittest
import zlib
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tinytouch_serial as ts  # noqa: E402
import tinytouch_update as tu  # noqa: E402


class FakeDevice(threading.Thread):
    """Protocol 6 console of firmware 0.1.28, enough for STATUS, AUTH and OTA."""

    def __init__(self, fail_write_at=None):
        super().__init__(daemon=True)
        # Holding the slave open keeps reads on the master from failing with EIO before the
        # port under test opens it.
        self.master, self.slave = os.openpty()
        self.path = os.ttyname(self.slave)
        self.fail_write_at = fail_write_at
        self.received = bytearray()
        self.commands = []
        self.token = None
        self.expected = None

    def reply(self, line):
        os.write(self.master, (line + "\r\n").encode())

    def run(self):
        buffer = b""
        while True:
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                return
            buffer += chunk
            while b"\n" in buffer:
                raw, buffer = buffer.split(b"\n", 1)
                self.handle(raw.decode().strip())

    def handle(self, line):
        self.commands.append(line.split()[:2] if line.startswith("OTA WRITE") else line)
        words = line.split()
        if line == "STATUS":
            self.reply("LOG ms=1 event=noise value=0")
            self.reply("OK STATUS protocol=6 firmware=0.1.28 mode=piv fingerprints=0 ota=idle")
        elif line == "AUTH":
            self.reply("OK AUTH first_setup=1")
        elif line == "OTA ABORT" or (words[:2] == ["OTA", "ABORT"] and words[2:] == [self.token]):
            self.token = None
            self.reply("OK OTA ABORT")
        elif words[:2] == ["OTA", "BEGIN"]:
            self.token, self.expected = words[2], (int(words[3]), words[4])
            self.begun_token = self.token
            self.received.clear()
            self.reply("OK OTA BEGIN next=0")
        elif words[:2] == ["OTA", "WRITE"] and words[2] == self.token:
            offset, data = int(words[3]), base64.b64decode(words[4])
            if offset == self.fail_write_at or offset != len(self.received):
                self.reply("ERR OTA WRITE")
                return
            self.received += data
            self.reply(f"OK OTA WRITE next={len(self.received)}")
        elif words[:2] == ["OTA", "COMMIT"] and words[2] == self.token:
            size, digest = self.expected
            ok = len(self.received) == size and hashlib.sha256(self.received).hexdigest() == digest
            self.reply("OK OTA STAGED power_cycle=required" if ok else "ERR OTA COMMIT")
        else:
            self.reply("ERR COMMAND")


def signed_image(key, body=b"\xa5" * (2 * tu.SECTOR)):
    """An image laid out like an ESP-IDF v2 signed app, signed by `key`."""
    digest = hashlib.sha256(body).digest()
    numbers = key.public_key().public_numbers()
    signature = key.sign(digest, padding.PSS(padding.MGF1(hashes.SHA256()), 32),
                         utils.Prehashed(hashes.SHA256()))
    block = (bytes([tu.SIG_MAGIC, tu.SIG_VERSION, 0, 0]) + digest
             + numbers.n.to_bytes(384, "little") + numbers.e.to_bytes(4, "little")
             + bytes(388) + int.from_bytes(signature, "big").to_bytes(384, "little"))
    block += struct.pack("<I", zlib.crc32(block)) + bytes(16)
    return body + block + b"\xff" * (tu.SECTOR - len(block))


def key_sha256(key):
    spki = key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


class SignatureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    def test_valid_image_returns_its_key(self):
        image = signed_image(self.key)
        self.assertEqual(tu.signing_key_sha256(image), key_sha256(self.key))
        tu.check_image(image, pinned=key_sha256(self.key))

    def test_other_key_is_refused(self):
        with self.assertRaisesRegex(tu.UpdateError, "not with upstream"):
            tu.check_image(signed_image(self.key))

    def test_changed_body_is_refused(self):
        image = bytearray(signed_image(self.key))
        image[10] ^= 1
        with self.assertRaisesRegex(tu.UpdateError, "digest"):
            tu.signing_key_sha256(bytes(image))

    def test_forged_signature_is_refused(self):
        image = bytearray(signed_image(self.key))
        start = 2 * tu.SECTOR
        image[start + 900] ^= 1
        image[start + 1196:start + 1200] = struct.pack("<I", zlib.crc32(image[start:start + 1196]))
        with self.assertRaisesRegex(tu.UpdateError, "does not verify"):
            tu.signing_key_sha256(bytes(image))

    def test_unsigned_image_is_refused(self):
        with self.assertRaisesRegex(tu.UpdateError, "no signature block"):
            tu.signing_key_sha256(b"\x00" * (3 * tu.SECTOR))


class ReleaseTest(unittest.TestCase):
    image = b"\x01" * 5000

    def fake_get(self, manifest):
        files = {"release-manifest.json": json.dumps(manifest).encode(),
                 "tiny_touch_unified.bin": self.image}
        return lambda url: files[url.rsplit("/", 1)[1]]

    def manifest(self, **ota):
        entry = {"file": "tiny_touch_unified.bin", "size": len(self.image),
                 "sha256": hashlib.sha256(self.image).hexdigest(), **ota}
        return {"version": "0.1.34", "ota": entry}

    def test_matching_release(self):
        image, _ = tu.fetch_release("0.1.34", self.fake_get(self.manifest()))
        self.assertEqual(image, self.image)

    def test_hash_mismatch(self):
        with self.assertRaisesRegex(tu.UpdateError, "does not match"):
            tu.fetch_release("0.1.34", self.fake_get(self.manifest(sha256="0" * 64)))

    def test_path_in_file_name(self):
        with self.assertRaisesRegex(tu.UpdateError, "malformed"):
            tu.fetch_release("0.1.34", self.fake_get(self.manifest(file="../x.bin")))

    def test_other_version_in_manifest(self):
        with self.assertRaisesRegex(tu.UpdateError, "does not describe"):
            tu.fetch_release("0.1.33", self.fake_get(self.manifest()))


class SerialTest(unittest.TestCase):
    def test_terminal_lines(self):
        self.assertTrue(ts.is_terminal("PING", "PONG 6"))
        self.assertTrue(ts.is_terminal("OTA WRITE t 0 x", "OK OTA WRITE next=3072"))
        self.assertTrue(ts.is_terminal("FINGER LIST", "ERR LOCKED run=AUTH"))
        self.assertFalse(ts.is_terminal("STATUS", "LOG ms=1 event=x value=0"))

    def test_find_ports_matches_strings_too(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            for name, vendor, product in (("ttyACM0", "303a", "tinyTouch"),
                                          ("ttyACM1", "303a", "Other ESP32")):
                usb = root / "devices" / name
                (usb / "iface").mkdir(parents=True)
                for attr, value in (("idVendor", vendor), ("idProduct", "4001"),
                                    ("manufacturer", product), ("product", product)):
                    (usb / attr).write_text(value + "\n")
                tty = root / "class" / "tty" / name
                tty.mkdir(parents=True)
                (tty / "device").symlink_to(usb / "iface")
            self.assertEqual(ts.find_ports(root), ["/dev/ttyACM0"])

    def test_status_skips_log_lines(self):
        device = FakeDevice()
        device.start()
        with ts.Port(device.path) as port:
            self.assertEqual(port.status()["firmware"], "0.1.28")


class StageTest(unittest.TestCase):
    image = bytes(range(256)) * 40  # 10240 bytes: three full chunks and a short one

    def test_uploads_whole_image_and_commits(self):
        device = FakeDevice()
        device.start()
        with ts.Port(device.path) as port:
            tu.stage(port, self.image, say=lambda _: None)
        self.assertEqual(bytes(device.received), self.image)
        self.assertEqual(device.commands[:2], ["OTA ABORT", "AUTH"])
        self.assertTrue(device.commands[-1].startswith("OTA COMMIT "))

    def test_failed_write_aborts_with_token(self):
        device = FakeDevice(fail_write_at=tu.CHUNK)
        device.start()
        with ts.Port(device.path) as port, self.assertRaises(ts.DeviceError):
            tu.stage(port, self.image, say=lambda _: None)
        self.assertEqual(device.commands[-1], f"OTA ABORT {device.begun_token}")
        self.assertIsNone(device.token)
        self.assertFalse(any(isinstance(c, str) and c.startswith("OTA COMMIT")
                             for c in device.commands))


if __name__ == "__main__":
    unittest.main()
