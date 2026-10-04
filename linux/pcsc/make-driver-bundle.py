#!/usr/bin/env python3
"""Make a pcscd driver directory whose CCID driver knows the tinyTouch.

The stock ccid driver matches readers by USB ID and does not list 303a:4001, so pcscd ignores
the tinyTouch. Both pcscd and libccid read drivers from $PCSCLITE_HP_DROPDIR instead of
/usr/lib/pcsc/drivers when it is set, so this writes a copy of the ccid bundle there with the
tinyTouch added, and links the driver binary rather than copying it. Re-run after a ccid upgrade.
"""

from __future__ import annotations

import argparse
import os
import plistlib
import sys
from pathlib import Path

SYSTEM_BUNDLE = Path("/usr/lib/pcsc/drivers/ifd-ccid.bundle")
VENDOR, PRODUCT, NAME = "0x303A", "0x4001", "tinyTouch"


def add_tinytouch(plist: dict) -> dict:
    """The driver's Info.plist with the tinyTouch in its three parallel reader lists."""
    lists = plist["ifdVendorID"], plist["ifdProductID"], plist["ifdFriendlyName"]
    if len({len(entries) for entries in lists}) != 1:
        # pcscd exits at startup on unequal lengths, so no reader would work at all.
        raise ValueError("the driver's reader lists have different lengths")
    ids = list(zip(*lists))
    if (VENDOR, PRODUCT, NAME) not in ids:
        ids.append((VENDOR, PRODUCT, NAME))
    plist = dict(plist)
    plist["ifdVendorID"], plist["ifdProductID"], plist["ifdFriendlyName"] = map(list, zip(*ids))
    return plist


def make_bundle(target: Path, system: Path = SYSTEM_BUNDLE) -> Path:
    """Write <target>/ifd-ccid.bundle from <system>; returns the bundle path."""
    with open(system / "Contents" / "Info.plist", "rb") as handle:
        plist = add_tinytouch(plistlib.load(handle))
    binary = system / "Contents" / "Linux" / plist["CFBundleExecutable"]
    if not binary.is_file():
        raise FileNotFoundError(binary)
    bundle = target / system.name
    (bundle / "Contents" / "Linux").mkdir(parents=True, exist_ok=True)
    with open(bundle / "Contents" / "Info.plist", "wb") as handle:
        plistlib.dump(plist, handle)
    link = bundle / "Contents" / "Linux" / binary.name
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(binary)
    return bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", type=Path,
                        help="driver directory to write, e.g. /etc/tinytouch/pcsc-drivers")
    args = parser.parse_args(argv)
    # pcscd runs as its own user; sudo keeps the caller's umask, which may be 077.
    os.umask(0o022)
    try:
        bundle = make_bundle(args.target)
    except (OSError, KeyError, ValueError, plistlib.InvalidFileException) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote {bundle} with the tinyTouch added.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
