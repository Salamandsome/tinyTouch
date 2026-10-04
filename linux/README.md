# tinyTouch on Linux

An unofficial Linux port, maintained in a fork; upstream tinyTouch does not support it. Host
support is in progress. Needs Python 3.9 or newer (3.10 for the sudo verifier);
`tinytouch_update.py` (and `tinytouch.py update`) also needs `python-cryptography`.

## Device access

`udev/70-tinytouch.rules` gives the logged-in user the device's serial port and keeps
ModemManager off it. `udev/93-tinytouch-power.rules` keeps the device out of USB autosuspend:
the firmware reconnects over USB whenever the device wakes from suspend, dropping the smart card
and the serial port for about a second, and the `ccid` package's own rule would otherwise
re-enable autosuspend for it.

    sudo install -m 0644 linux/udev/70-tinytouch.rules linux/udev/93-tinytouch-power.rules /etc/udev/rules.d/
    sudo udevadm control --reload

then replug the tinyTouch. To remove the rule:

    sudo rm /etc/udev/rules.d/70-tinytouch.rules /etc/udev/rules.d/93-tinytouch-power.rules && sudo udevadm control --reload

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
    sudo systemctl restart pcscd.service

Re-run the `python3` line after a `ccid` upgrade, then restart `pcscd.service` again.
`pcsc_scan -r` then lists the reader and `pkcs15-tool --list-certificates` shows the two
certificates. While the drop-in is in place `pcscd` reads drivers only from that directory, so
a reader whose driver is another package would stop working; none is handled yet. To undo:
remove the drop-in and `/etc/tinytouch/pcsc-drivers`, run `daemon-reload` and restart
`pcscd.service`; disable `pcscd.socket` only if it was enabled for this.

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

## Fingerprint for sudo

With this set up, `sudo` asks for a touch on the tinyTouch before it asks for your password. The
check is done by `tinytouch_piv.py`, run by PAM's stock `pam_exec` module: it sends the device's
smart card a fresh random challenge, which the card signs with its 9A key only in the few
seconds after an enrolled finger touched the sensor, and checks the signature against the public
key paired with your user. The password always works too. Needs Python 3.10 or newer,
`python-pyscard` and `python-cryptography`, and the smart-card setup above.

### Install

Root runs the verifier, so it is installed as a root-owned copy outside this checkout; it never
runs from the checkout as root.

    sudo install -d -m 0755 /usr/local/lib/tinytouch /etc/tinytouch /etc/tinytouch/keys
    sudo install -m 0755 linux/tinytouch_piv.py /usr/local/lib/tinytouch/tinytouch-verify
    sudo install -m 0644 linux/tinytouch_serial.py /usr/local/lib/tinytouch/

Repeat the two `install` lines after updating the checkout.

### Pair

Pairing records the device's public key as yours in `/etc/tinytouch/keys/USER.pem`:

    sudo /usr/local/lib/tinytouch/tinytouch-verify --enrol --user "$USER"

(`sudo python3 linux/tinytouch.py pair --user "$USER"` does the same by starting the installed
copy.) It refuses unless `status --check` passes, the device has keys and at least one finger
is enrolled, and the serial port is free. It shows the key's SHA-256 fingerprint and asks for one
touch, checked exactly as `sudo` will check it. A key already paired with another user is
refused. An earlier key file for the same user is replaced, and its copy kept under
`/var/lib/tinytouch/backup/<UTC time>/keys/`. After a factory reset the device has new keys:
pair again.

To try it without touching PAM (exit status 0 means verified):

    sudo env PAM_TYPE=auth PAM_USER="$USER" PAM_SERVICE=tinytouch-test /usr/local/lib/tinytouch/tinytouch-verify --timeout 10; echo $status

(`$?` instead of `$status` in bash.)

### The sudo PAM file

On Arch, `/etc/pam.d/sudo` belongs to the `sudo` package as a backup file: an upgrade then
leaves its new version beside it as `sudo.pacnew`, and `pacman -Qkk sudo` reports it modified.
Before changing it, open a root shell in another terminal (`sudo -i`) and keep it open until
`sudo` has been tried in a new terminal. Save the current file outside `/etc/pam.d`:

    sudo sh -c 'd=/var/lib/tinytouch/backup/$(date -u +%Y%m%dT%H%M%SZ) && install -d -m 0700 "$d" && cp -p /etc/pam.d/sudo "$d/sudo" && echo "$d"'

Then, from the root shell, edit `/etc/pam.d/sudo` so it reads (the stock file plus the two lines
after the first):

    #%PAM-1.0
    auth		requisite	pam_faillock.so preauth
    auth		sufficient	pam_exec.so quiet quiet_log stdout seteuid /usr/local/lib/tinytouch/tinytouch-verify --timeout 10
    auth		include		system-auth
    account		include		system-auth
    session		include		system-auth
    session		optional	pam_systemd.so class=none

`requisite pam_faillock.so preauth` makes a locked-out user (five wrong passwords) fail before
the touch is offered. `sufficient pam_exec.so` lets a verified touch complete the
authentication; any other outcome goes on to the password. `quiet_log` keeps `pam_exec` from
logging each fallback to the password as an error.

### What happens

- With the device plugged in and paired, `sudo` shows
  `Touch tinyTouch to approve sudo, or press Enter for password.` A touch with an enrolled finger
  approves the command. Enter goes straight to the password prompt. After 10 seconds without
  either, the password prompt appears.
- Device unplugged, or not paired with you: the password prompt appears at once.
- A touch made before the prompt appeared is not used; the verifier says
  `An earlier touch was ignored; touch again.` One touch approves one request.
- After a wrong password, `sudo` runs the stack again, so the touch is offered again for another
  10 seconds.
- A touch starts sudo's timestamp exactly as a password does: later `sudo` commands in the same
  terminal don't ask again for a while.
- During a faillock lockout `sudo` refuses silently, before the touch line, until the lockout
  ends. A timeout or Enter never counts as a failed attempt, and a touch does not reset the
  count of wrong passwords.
- `sudo` in an SSH session, and `sudo` with no terminal (`sudo -n`, scripts, background jobs),
  never offer the touch: they go straight to the password, or fail.
- If the verifier fails in any way, it is killed after 15 seconds at most, or exits when `sudo`
  is interrupted; either way the password prompt (or nothing, after Ctrl-C) follows.

Each run logs one line to the system journal: `journalctl -t tinytouch-verify`.

### Undo

From the root shell, put the saved file back:

    cp /var/lib/tinytouch/backup/<UTC time>/sudo /etc/pam.d/sudo

and check that it is the packaged file again: the two hashes match, `cmp` prints nothing, and
`pacman -Qkk sudo` (as root) no longer mentions `/etc/pam.d/sudo`:

    md5sum /etc/pam.d/sudo
    sed -n '/%BACKUP%/,$p' /var/lib/pacman/local/sudo-*/files | grep pam.d/sudo
    cmp /etc/pam.d/sudo /var/lib/tinytouch/backup/<UTC time>/sudo
    pacman -Qkk sudo

To remove everything: `rm -r /usr/local/lib/tinytouch /etc/tinytouch/keys`.

If `sudo` stops working and no root shell is open: `run0` (systemd's own elevation, which uses
polkit rather than sudo's PAM file) gives a root shell, as does logging in as root on a text
console (Ctrl-Alt-F3) if root has a password.

### Limits

- This is our own code in the authentication path. It is small, single-file and fails toward
  the password, but it has not had an outside review.
- The fingerprint sensor has no liveness detection, and its false-match rate is not published.
- Wrong fingers are not counted or rate-limited by the host, which cannot see them; the device
  only waits 800 ms between attempts.
- A factory reset makes new keys (the touch then stops working until you pair again) and turns
  `piv_auto_type` back on (`status --check` reports it).
- A `tinytouch.py` command that asks for a touch also lets the card sign for 30 seconds without
  a new one. The verifier uses up or rejects such signatures, so `sudo` still needs its own
  touch; with no finger enrolled, that command needs no touch at all.
- If the verifier ever hangs and its 15-second watchdog kills it, the terminal may be left not
  showing what you type; `stty sane` (typed blind) or `reset` fixes it.
- Two prompts waiting at once (two terminals, or `sudo` and a polkit dialog) race for one touch:
  whichever asks first after the touch gets it.

The tests are run by hand, from the repository root:

    python3 -m unittest discover -s linux/tests
