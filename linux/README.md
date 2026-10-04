# tinyTouch on Linux

An unofficial Linux port, maintained in a fork; upstream tinyTouch does not support it. Host
support is in progress. Needs Python 3.9 or newer; `tinytouch_update.py` (and `tinytouch.py
update`) also needs `python-cryptography`.

## Device access

`udev/70-tinytouch.rules` gives the logged-in user the device's serial port, keeps ModemManager
off it and the device out of USB autosuspend:

    sudo install -m 0644 linux/udev/70-tinytouch.rules /etc/udev/rules.d/
    sudo udevadm control --reload

then replug the tinyTouch. To remove the rule:

    sudo rm /etc/udev/rules.d/70-tinytouch.rules && sudo udevadm control --reload

## Updating the firmware

    python3 linux/tinytouch_update.py 0.1.34 --check   # download, verify, read status; writes nothing
    python3 linux/tinytouch_update.py 0.1.34           # upload, then replug the tinyTouch

The tool downloads the stock release, checks it against the release manifest and checks its
signature against upstream's release key before sending anything. The device writes the image to
its spare slot, checks the hash and signature again, and switches only when both pass. The device
goes back to the old firmware only if the new image fails before it finishes starting; firmware
that starts but then misbehaves stays. Settings, fingerprints and keys are kept. A unit with
fingerprints enrolled asks for a touch first.

The tool refuses a release older than the device's firmware unless given `--allow-downgrade`.

## Smart card (pcscd)

The PC talks to the device's PIV smart card through `pcscd` and the `ccid` driver (packages
`ccid opensc pcsc-tools python-pyscard`). The stock driver does not list the tinyTouch's USB ID,
so `pcsc/make-driver-bundle.py` writes a driver directory with it added, and a `pcscd` drop-in
points there; nothing under `/usr` is changed.

    sudo systemctl enable --now pcscd.socket
    sudo python3 linux/pcsc/make-driver-bundle.py /etc/tinytouch/pcsc-drivers
    sudo install -D -m 0644 linux/pcsc/pcscd-tinytouch.conf /etc/systemd/system/pcscd.service.d/tinytouch.conf
    sudo systemctl daemon-reload

Re-run the first `python3` line after a `ccid` upgrade. `pcsc_scan -r` then lists the reader and
`pkcs15-tool --list-certificates` shows the two certificates. To undo: remove the drop-in and
`/etc/tinytouch/pcsc-drivers`, run `daemon-reload`, and `disable --now pcscd.socket`.

The firmware reconnects over USB whenever the device wakes from USB suspend, which drops the
smart card and the serial port for about a second. The udev rule keeps the device awake.

## Setting up the device

`tinytouch.py` sets up and inspects the tinyTouch over its serial port. Each command opens the
port, does its job and closes it; close any other program using the port first.

    python3 linux/tinytouch.py status            # state; --json for every field
    python3 linux/tinytouch.py status --check    # fails unless set up as Linux needs
    python3 linux/tinytouch.py fingers           # enrolled fingers and free slots
    python3 linux/tinytouch.py enroll            # enroll the first free finger
    python3 linux/tinytouch.py delete 2          # delete finger 2
    python3 linux/tinytouch.py piv-create        # create the smart-card keys, once
    python3 linux/tinytouch.py config            # all settings; `config NAME [VALUE]`
    python3 linux/tinytouch.py logs              # recent device log
    python3 linux/tinytouch.py update 0.1.34     # same as tinytouch_update.py

`--port /dev/ttyACMn` picks the device when several are attached; the tools refuse a node that is
not an attached tinyTouch. Commands that change something ask for a touch on the sensor first.

After any command that asked for a touch, the device stays authorised for about two minutes.
During that time any program running as you can change the device without a touch.

`piv_touch` and the device mode cannot be set with this tool; both are already right on a stock
unit (`status --check` shows them).

Recommended order on a new device:

1. `status --check` passes, or shows what to change (`config piv_auto_type off` for example).
2. `enroll` twice, with two different fingers. Follow the prompts: four views of the finger,
   each touched twice. Until the first finger is enrolled the device approves changes without
   a touch.
3. `piv-create`, once two fingers are enrolled.

What cannot be undone:

- `piv-create` runs once. New keys need a factory reset, which also erases the fingers and
  settings; this tool does not offer one. It asks you to type `create` first.
- `enroll --replace` deletes the finger's old views before capturing new ones, and `delete`
  removes a finger. Both ask you to type a word first, and refuse to remove the last enrolled
  finger unless given `--force`: with no finger enrolled, the device approves changes without
  a touch.

An enrollment that is interrupted (Ctrl-C, timeout, unplug) is rolled back by the device; the
other fingers are not changed.

The tests are run by hand, from the repository root:

    python3 -m unittest discover -s linux/tests
