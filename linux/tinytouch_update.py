#!/usr/bin/env python3
"""Update a tinyTouch to a stock upstream release through the device's own serial OTA.

The device writes the image to its spare app slot, checks the SHA-256 and upstream's RSA signature
at commit, and boots the new image on the next power cycle, falling back if it fails to start.
Before anything reaches the device this tool checks the image against the release manifest and
verifies its signature block against upstream's pinned release key.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import secrets
import struct
import sys
import urllib.request
import zlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

from tinytouch_serial import DeviceError, Port, find_ports, fields

RELEASES = "https://github.com/ZimengXiong/tinyTouch/releases/download"
# SHA-256 of the SubjectPublicKeyInfo of upstream's app-signing key (RSA-3072), read from the
# signature blocks of the v0.1.28 and v0.1.34 release images.
UPSTREAM_KEY_SHA256 = "94d87aaf1562bf2a9ea71fa62497e47581d0e5bfbba8df5917f9d3eeefbbc99f"
CHUNK = 3072  # FIRMWARE_UPDATE_CHUNK_MAX in firmware_update.h
SECTOR = 4096
SIG_MAGIC, SIG_VERSION, SIG_BLOCK_LEN = 0xE7, 0x02, 1216


class UpdateError(Exception):
    pass


def download(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=30) as response:
        return response.read()


def fetch_release(version: str, get=download) -> tuple[bytes, dict]:
    """The release's OTA image, checked against its manifest."""
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise UpdateError(f"not a stable release version: {version}")
    root = f"{RELEASES}/v{version}"
    manifest = json.loads(get(f"{root}/release-manifest.json"))
    ota = manifest.get("ota") if isinstance(manifest, dict) else None
    if manifest.get("version") != version or not isinstance(ota, dict):
        raise UpdateError("the release manifest does not describe this version's OTA image")
    name, size, digest = ota.get("file"), ota.get("size"), ota.get("sha256")
    if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+\.bin", name)
            or type(size) is not int or size <= 0
            or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
        raise UpdateError("the release manifest's OTA entry is malformed")
    image = get(f"{root}/{name}")
    if len(image) != size or hashlib.sha256(image).hexdigest() != digest:
        raise UpdateError("the downloaded image does not match the release manifest")
    return image, manifest


def signing_key_sha256(image: bytes) -> str:
    """Verify the image's ESP-IDF v2 signature block; return its key's SubjectPublicKeyInfo hash.

    The block sits in the image's last 4 KiB sector: magic, version, 2 reserved, SHA-256 of
    everything before the sector, modulus (384 LE), exponent (4 LE), R^-1 (384), M' (4),
    RSA-PSS signature (384 LE), CRC-32 of the preceding 1196 bytes, 16 bytes padding.
    """
    if len(image) < 2 * SECTOR or len(image) % SECTOR:
        raise UpdateError("the image is not sector-aligned with a signature sector")
    body, block = image[:-SECTOR], image[-SECTOR:][:SIG_BLOCK_LEN]
    if block[0] != SIG_MAGIC or block[1] != SIG_VERSION:
        raise UpdateError("the image has no signature block")
    if zlib.crc32(block[:1196]) != struct.unpack("<I", block[1196:1200])[0]:
        raise UpdateError("the signature block is corrupt")
    digest = hashlib.sha256(body).digest()
    if block[4:36] != digest:
        raise UpdateError("the image does not match its signature block's digest")
    modulus = int.from_bytes(block[36:420], "little")
    exponent = int.from_bytes(block[420:424], "little")
    signature = int.from_bytes(block[812:1196], "little").to_bytes(384, "big")
    key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
    try:
        key.verify(signature, digest, padding.PSS(padding.MGF1(hashes.SHA256()), 32),
                   utils.Prehashed(hashes.SHA256()))
    except InvalidSignature:
        raise UpdateError("the image's signature does not verify") from None
    spki = key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def check_image(image: bytes, pinned: str = UPSTREAM_KEY_SHA256) -> None:
    if signing_key_sha256(image) != pinned:
        raise UpdateError("the image is signed, but not with upstream's release key")


def stage(port: Port, image: bytes, say=print) -> None:
    """Upload and commit the image; the device boots it after the next power cycle."""
    # An interrupted earlier upload may still hold the OTA session; aborting it is safe because
    # the running firmware lives in the other slot.
    port.command("OTA ABORT", 4, check=False)
    say("Authorising (touch the sensor if it asks; a unit with no fingers needs none)...")
    port.command("AUTH", 30)
    token = secrets.token_hex(16)
    digest = hashlib.sha256(image).hexdigest()
    # BEGIN erases the spare slot, which takes a few seconds.
    if port.command(f"OTA BEGIN {token} {len(image)} {digest}", 30)[-1] != "OK OTA BEGIN next=0":
        raise UpdateError("the device did not start the upload at offset 0")
    try:
        shown = -1
        for offset in range(0, len(image), CHUNK):
            chunk = image[offset:offset + CHUNK]
            line = port.command(
                f"OTA WRITE {token} {offset} {base64.b64encode(chunk).decode()}", 10)[-1]
            if fields(line).get("next") != str(offset + len(chunk)):
                raise UpdateError(f"unexpected reply at offset {offset}: {line}")
            percent = (offset + len(chunk)) * 100 // len(image)
            if percent // 10 != shown:
                shown = percent // 10
                say(f"Uploaded {percent}%")
        say("Verifying on the device...")
        line = port.command(f"OTA COMMIT {token}", 30)[-1]
    except BaseException:
        try:
            port.command(f"OTA ABORT {token}", 4, check=False)
        except DeviceError:
            pass
        raise
    if line != "OK OTA STAGED power_cycle=required":
        raise UpdateError(f"the device did not confirm the staged image: {line}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("version", help="stock upstream release to install, e.g. 0.1.34")
    parser.add_argument("--port", help="serial node (default: the one attached tinyTouch)")
    parser.add_argument("--check", action="store_true",
                        help="download and verify, read the device's status, write nothing")
    args = parser.parse_args(argv)
    try:
        image, _ = fetch_release(args.version)
        check_image(image)
        print(f"Image v{args.version}: {len(image)} bytes, sha256 "
              f"{hashlib.sha256(image).hexdigest()}, signed with upstream's release key.")
        ports = [args.port] if args.port else find_ports()
        if len(ports) != 1:
            raise UpdateError(f"expected one tinyTouch, found {len(ports)}")
        with Port(ports[0]) as port:
            status = port.status()
            print("Device: " + " ".join(f"{k}={status.get(k)}" for k in
                                        ("protocol", "firmware", "mode", "fingerprints", "ota")))
            if status.get("protocol") != "6" or status.get("ota") != "idle":
                raise UpdateError("the device needs protocol=6 and ota=idle")
            if status.get("firmware") == args.version:
                print("Already on this version.")
                return 0
            if args.check:
                print("Check passed; nothing written.")
                return 0
            stage(port, image)
        print("Staged. Unplug the tinyTouch and plug it back in to boot the new firmware.")
        return 0
    except (UpdateError, DeviceError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
