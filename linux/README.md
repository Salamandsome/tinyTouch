# tinyTouch on Linux

Host support for Linux, in progress. Needs Python 3 and `python-cryptography`.

## Device access

`udev/70-tinytouch.rules` gives the logged-in user the device's serial port, keeps ModemManager
off it and the device out of USB autosuspend:

    sudo install -m 0644 linux/udev/70-tinytouch.rules /etc/udev/rules.d/
    sudo udevadm control --reload

then replug the tinyTouch.

## Updating the firmware

    python3 linux/tinytouch_update.py 0.1.34 --check   # download, verify, read status; writes nothing
    python3 linux/tinytouch_update.py 0.1.34           # upload, then replug the tinyTouch

The tool downloads the stock release, checks it against the release manifest and checks its
signature against upstream's release key before sending anything. The device writes the image to
its spare slot, checks the hash and signature again, and switches only when both pass. If the new
firmware fails to start, the device falls back to the old one. Settings, fingerprints and keys are
kept. A unit with fingerprints enrolled asks for a touch first.

Run the tests with `python3 -m unittest discover -s linux/tests`.
