"""Tests for the pcscd driver-bundle generator, against a copy of a minimal ccid bundle."""

import importlib.util
import io
import os
import plistlib
import sys
import tempfile
import unittest
import unittest.mock
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

    def test_existing_entry_is_not_duplicated_and_a_file_at_the_link_is_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            system = fake_system_bundle(Path(tmp) / "sys")
            plist_path = system / "Contents" / "Info.plist"
            with open(plist_path, "rb") as handle:
                plist = plistlib.load(handle)
            for key, value in (("ifdVendorID", "0x303A"), ("ifdProductID", "0x4001"),
                               ("ifdFriendlyName", "tinyTouch")):
                plist[key].append(value)
            with open(plist_path, "wb") as handle:
                plistlib.dump(plist, handle)
            target = Path(tmp) / "out"
            link = target / "ifd-ccid.bundle" / "Contents" / "Linux" / "libccid.so"
            link.parent.mkdir(parents=True)
            link.write_bytes(b"stale copy")  # a regular file, not a symlink
            bundle = mdb.make_bundle(target, system)
            with open(bundle / "Contents" / "Info.plist", "rb") as handle:
                self.assertEqual(plistlib.load(handle)["ifdVendorID"], ["0x1050", "0x303A"])
            self.assertTrue(link.is_symlink())

    def test_main_reports_errors_and_sets_a_permissive_umask(self):
        with tempfile.TemporaryDirectory() as tmp:
            system = fake_system_bundle(Path(tmp) / "sys")
            with unittest.mock.patch.object(mdb, "SYSTEM_BUNDLE", system), \
                    unittest.mock.patch("sys.stderr", new=io.StringIO()) as err:
                self.assertEqual(mdb.main(["/proc/nonexistent/out"]), 1)
                self.assertIn("error:", err.getvalue())
                old = os.umask(0o077)
                try:
                    self.assertEqual(mdb.main([str(Path(tmp) / "out")]), 0)
                    plist = Path(tmp) / "out" / "ifd-ccid.bundle" / "Contents" / "Info.plist"
                    # pcscd runs as its own user and must be able to read what sudo wrote.
                    self.assertEqual(plist.stat().st_mode & 0o777, 0o644)
                    self.assertEqual(plist.parent.stat().st_mode & 0o777, 0o755)
                finally:
                    os.umask(old)

    def test_mismatched_reader_lists_are_refused(self):
        # pcscd exits at startup on lists of unequal length: no reader would work.
        with tempfile.TemporaryDirectory() as tmp:
            system = fake_system_bundle(Path(tmp) / "sys")
            plist_path = system / "Contents" / "Info.plist"
            with open(plist_path, "rb") as handle:
                plist = plistlib.load(handle)
            plist["ifdProductID"].append("0x0001")
            with open(plist_path, "wb") as handle:
                plistlib.dump(plist, handle)
            with self.assertRaisesRegex(ValueError, "lengths"):
                mdb.make_bundle(Path(tmp) / "out", system)
            self.assertFalse((Path(tmp) / "out").exists())

    def test_missing_driver_binary_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            system = fake_system_bundle(Path(tmp) / "sys")
            (system / "Contents" / "Linux" / "libccid.so").unlink()
            with self.assertRaises(FileNotFoundError):
                mdb.make_bundle(Path(tmp) / "out", system)


if __name__ == "__main__":
    unittest.main()
