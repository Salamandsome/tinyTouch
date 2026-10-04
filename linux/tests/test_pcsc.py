"""Tests for the pcscd driver-bundle generator, against a copy of a minimal ccid bundle."""

import importlib.util
import plistlib
import sys
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "make_driver_bundle", Path(__file__).resolve().parents[1] / "pcsc" / "make-driver-bundle.py")
mdb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mdb)


def fake_system_bundle(root: Path) -> Path:
    bundle = root / "ifd-ccid.bundle"
    (bundle / "Contents" / "Linux").mkdir(parents=True)
    (bundle / "Contents" / "Linux" / "libccid.so").write_bytes(b"\x7fELF")
    plist = {"CFBundleExecutable": "libccid.so", "ifdVendorID": ["0x1050"],
             "ifdProductID": ["0x0407"], "ifdFriendlyName": ["Yubikey"], "ifdLogLevel": "0x0003"}
    with open(bundle / "Contents" / "Info.plist", "wb") as handle:
        plistlib.dump(plist, handle)
    return bundle


class BundleTest(unittest.TestCase):
    def test_adds_tinytouch_once_and_links_the_driver(self):
        with tempfile.TemporaryDirectory() as tmp:
            system = fake_system_bundle(Path(tmp) / "sys")
            target = Path(tmp) / "out"
            for _ in range(2):  # idempotent
                bundle = mdb.make_bundle(target, system)
            with open(bundle / "Contents" / "Info.plist", "rb") as handle:
                plist = plistlib.load(handle)
            self.assertEqual(plist["ifdVendorID"], ["0x1050", "0x303A"])
            self.assertEqual(plist["ifdProductID"], ["0x0407", "0x4001"])
            self.assertEqual(plist["ifdFriendlyName"], ["Yubikey", "tinyTouch"])
            self.assertEqual(plist["ifdLogLevel"], "0x0003")
            link = bundle / "Contents" / "Linux" / "libccid.so"
            self.assertTrue(link.is_symlink())
            self.assertEqual(link.resolve(), (system / "Contents" / "Linux" / "libccid.so"))

    def test_missing_driver_binary_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            system = fake_system_bundle(Path(tmp) / "sys")
            (system / "Contents" / "Linux" / "libccid.so").unlink()
            with self.assertRaises(FileNotFoundError):
                mdb.make_bundle(Path(tmp) / "out", system)


if __name__ == "__main__":
    unittest.main()
