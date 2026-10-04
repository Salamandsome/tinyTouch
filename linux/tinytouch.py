#!/usr/bin/env python3
"""Set up and inspect a tinyTouch over its serial console (firmware 0.1.34, protocol 6).

Ports the parts of upstream's macos/cli.py that a Linux host needs; functions cite their
upstream counterparts. Each command opens the port, does its work and closes it.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import sys
import time

import tinytouch_serial as ts
from tinytouch_serial import (DeviceError, DeviceGone, DeviceRefused, DeviceTimeout, Port,
                              find_ports)

AUTH_TIMEOUT = 20.0  # the firmware waits 7 s for a touch (fingerprint.c FINGER_WAIT_MS)
ENROLL_TIMEOUT = 300.0  # as upstream enroll_finger; four views take the firmware up to ~200 s
CREATE_TIMEOUT = 90.0  # two RSA-2048 keys; upstream allows 45 s
RETURN_TIMEOUT = 60.0
FINGERS, VIEWS, TEMPLATE_LIMIT = 10, 4, 40  # finger_profiles.h
VIEW_NAMES = ("left edge", "right edge", "top", "center")  # upstream ENROLLMENT_VIEWS
CHECKS = (("protocol", "6"), ("mode", "piv"), ("piv_auto_type", "0"), ("piv_touch", "off"),
          ("ota", "idle"), ("sensor", "ready"))
SUMMARY = ("firmware", "build", "protocol", "mode", "piv", "sensor", "fingerprints", "ota",
           "piv_auto_type", "piv_touch", "piv_visible")

# Pairing runs only from this root-owned copy of tinytouch_piv.py (linux/README.md).
VERIFIER = "/usr/local/lib/tinytouch/tinytouch-verify"

COLORS = {"off": 0, "blue": 1, "green": 2, "cyan": 3, "red": 4, "purple": 5, "yellow": 6,
          "white": 7}
ON_OFF = {"off": 0, "on": 1}
# Upstream's SETTINGS without "mode" (SET MODE is not exposed): name -> (wire name, choices or
# inclusive range). The name is also the STATUS field.
SETTINGS: dict[str, tuple[str, dict[str, int] | tuple[int, int]]] = {
    "led": ("LED", {"off": 0, "on": 1, "only-auth": 2}),
    "piv_delay_ms": ("PIV_DELAY", (0, 5000)),
    "typing_delay_ms": ("TYPE_DELAY", (1, 100)),
    "submit_enter": ("SUBMIT_ENTER", ON_OFF),
    "touch_cooldown_ms": ("COOLDOWN", (100, 5000)),
    "led_idle_color": ("LED_IDLE_COLOR", COLORS),
    "led_success_color": ("LED_SUCCESS_COLOR", COLORS),
    "led_failure_color": ("LED_FAILURE_COLOR", COLORS),
    "led_idle_end_color": ("LED_IDLE_END_COLOR", COLORS),
    "led_idle_effect": ("LED_IDLE_EFFECT",
                        {"breathe": 1, "flash": 2, "steady": 3, "fade-in": 5, "fade-out": 6}),
    "led_idle_cycles": ("LED_IDLE_CYCLES", (0, 255)),
    "led_feedback_ms": ("LED_FEEDBACK_MS", (50, 2000)),
    "piv_auto_type": ("PIV_AUTO_TYPE", ON_OFF),
}

ask = input


class CliError(Exception):
    pass


def say(text: str = "") -> None:
    print(text, flush=True)


def human_error(exc: Exception) -> str:
    """Device failures as the next useful action (upstream human_error)."""
    line = str(exc)
    if isinstance(exc, DeviceGone):
        return f"{line}: the tinyTouch is reconnecting or was unplugged; try again in a moment"
    if not isinstance(exc, DeviceRefused):
        return line
    known = {
        "ERR AUTH no_match": "No enrolled finger matched in time. Try again.",
        "ERR AUTH sensor=offline": "The fingerprint sensor is unavailable. Replug the tinyTouch.",
        "ERR FINGER inventory_unavailable":
            "Could not read the fingerprint inventory; nothing was changed.",
        "ERR COMMAND": "The firmware does not know this command; this tool needs 0.1.34.",
        "ERR PIV BUSY": "The device is already creating keys.",
        "ERR PIV CREATE": "The device did not create the keys (ERR PIV CREATE).",
    }
    if line in known:
        return known[line]
    if line.startswith("ERR LOCKED"):
        return "The authorisation expired. Try again."
    return f"the device refused: {line}"


def confirm(word: str) -> None:
    try:
        answer = ask(f"Type '{word}' to go ahead: ")
    except EOFError:
        answer = ""
    if answer.strip() != word:
        raise CliError("cancelled; nothing was changed")


def open_port(args: argparse.Namespace) -> Port:
    nodes = find_ports()
    if args.port:
        # Commands written to some other serial device could do anything to it.
        if os.path.realpath(args.port) not in nodes:
            raise CliError(f"{args.port} is not an attached tinyTouch")
        nodes = [os.path.realpath(args.port)]
    if not nodes:
        raise CliError("no tinyTouch found (plugged in, udev rule installed?)")
    if len(nodes) > 1:
        raise CliError(f"found {len(nodes)} tinyTouch units; choose one with --port")
    try:
        return Port(nodes[0])
    except OSError as exc:
        if exc.errno == errno.EBUSY:
            raise CliError(f"{nodes[0]} is in use by another program") from None
        raise CliError(f"cannot open {nodes[0]}: {exc.strerror}") from None


def device_status(port: Port, *, sensor: bool = False) -> dict[str, str]:
    """STATUS, refusing other protocols (upstream protocol6, sensor_ready)."""
    status = port.status()
    if status.get("protocol") != "6":
        raise CliError(f"this tool speaks protocol 6; the device reports {status.get('protocol')}")
    if sensor and status.get("sensor") != "ready":
        raise CliError("the fingerprint sensor is unavailable; replug the tinyTouch")
    return status


def finger_inventory(port: Port) -> tuple[dict[int, int], int, int]:
    """Views per enrolled finger, capacity in templates, and the finger with a pending
    journal (upstream finger_inventory; config_console.c fingerprint_list)."""
    data = ts.fields(port.command("FINGER LIST", 6)[-1])
    try:
        groups = {} if data["groups"] == "none" else {
            int(n): int(v) for n, v in (item.split(":") for item in data["groups"].split(","))}
        capacity, pending = int(data["capacity"]), int(data["pending"])
        if any(not 1 <= n <= FINGERS or not 0 <= v <= VIEWS for n, v in groups.items()):
            raise ValueError
    except (KeyError, ValueError):
        raise CliError("the device returned an invalid fingerprint inventory") from None
    return groups, capacity, pending


def fits(finger: int, capacity: int) -> bool:
    """Whether the finger's template block exists on this sensor (finger_profiles_block_fits)."""
    slots = [0 if s == TEMPLATE_LIMIT else s
             for s in range((finger - 1) * VIEWS + 1, finger * VIEWS + 1)]
    return capacity >= TEMPLATE_LIMIT or max(slots) < capacity


def complete_others(groups: dict[int, int], pending: int, finger: int) -> list[int]:
    """Fingers other than `finger` that can still authorise: a partial or pending one may be
    rolled back by the next enroll or delete."""
    return [n for n, views in groups.items() if n not in (finger, pending) and views == VIEWS]


def authorize(port: Port, purpose: str) -> str:
    """AUTH; with no finger enrolled the firmware grants it without a touch (authorize)."""
    def prompt(line: str) -> None:
        if line == "EVENT TOUCH":
            say(f"Touch the sensor with an enrolled finger to {purpose}.")
    line = port.command("AUTH", AUTH_TIMEOUT, on_line=prompt)[-1]
    if line == "OK AUTH first_setup=1":
        say("No finger is enrolled, so the device allowed this without a touch.")
    return line


def cmd_status(args: argparse.Namespace) -> int:
    with open_port(args) as port:
        status = port.status()
    if args.json:
        say(json.dumps(status, indent=2, sort_keys=True))
    elif not args.check:
        for key in SUMMARY:
            say(f"{key:15} {status.get(key, '-')}")
    if not args.check:
        return 0
    failed = [(key, want) for key, want in CHECKS if status.get(key) != want]
    for key, want in failed:
        say(f"FAIL {key}={status.get(key, '-')} (needs {want})")
    if not failed:
        say("All checks passed.")
    return 1 if failed else 0


def cmd_logs(args: argparse.Namespace) -> int:
    """Upstream command_logs."""
    with open_port(args) as port:
        lines = [line for line in port.command("LOGS", 4) if line.startswith("LOG ")]
    for line in lines:
        say(line)
    if not lines:
        say("No log entries.")
    return 0


def cmd_fingers(args: argparse.Namespace) -> int:
    """Upstream command_fingers."""
    with open_port(args) as port:
        device_status(port)
        groups, capacity, pending = finger_inventory(port)
    for finger, views in sorted(groups.items()):
        state = "enrolled" if views == VIEWS else f"{views} of {VIEWS} views"
        if finger == pending:
            state = "unfinished enrollment, cleaned up on the next enroll or delete"
        say(f"Finger {finger}: {state}")
    if not groups:
        say("No fingers enrolled.")
    free = [n for n in range(1, FINGERS + 1) if n not in groups and fits(n, capacity)]
    say(f"Free: {', '.join(map(str, free)) or 'none'}")
    return 0


def enrollment_prompt(finger: int):
    """Upstream enroll_finger's event_handler, as plain lines."""
    view = 0

    def show(line: str) -> None:
        nonlocal view
        event = line.removeprefix("EVENT ")
        if event.startswith("VIEW "):
            view = min(max(int(event[5:]) - 1, 0), VIEWS - 1)
            say(f"Finger {finger}: View {view + 1} of {VIEWS} ({VIEW_NAMES[view]}).")
        elif event == "TOUCH":
            say(f"  Touch the sensor with the {VIEW_NAMES[view]} of the finger.")
        elif event == "TOUCH_AGAIN":
            say(f"  Touch it again with the {VIEW_NAMES[view]}.")
        elif event == "LIFT":
            say("  Lift your finger off the sensor.")
    return show


def cmd_enroll(args: argparse.Namespace) -> int:
    """Upstream enroll_finger, with guards for the last finger."""
    with open_port(args) as port:
        device_status(port, sensor=True)
        groups, capacity, pending = finger_inventory(port)
        finger = args.finger or next(
            (n for n in range(1, FINGERS + 1) if n not in groups and fits(n, capacity)), 0)
        if not finger:
            raise CliError("no free finger slot; delete a finger first")
        if not fits(finger, capacity):
            raise CliError(f"this sensor has no room for finger {finger}")
        replace = finger in groups
        others = complete_others(groups, pending, finger)
        if replace and not args.replace:
            raise CliError(f"finger {finger} is already enrolled; use --replace to enroll it again")
        if replace:
            if not others and not args.force:
                raise CliError(
                    f"finger {finger} is the only enrolled finger; replacing deletes its views "
                    "first, and if enrollment then fails none are left and AUTH needs no touch. "
                    "Enroll another finger first, or use --force")
            say(f"Replacing deletes finger {finger}'s current views before capturing new ones.")
            confirm("replace")
        if not any(groups.values()):
            say("No finger is enrolled yet: until one is, the device grants AUTH with no touch.")
        authorize(port, f"enroll finger {finger}")
        say(f"Enrolling finger {finger}: four views, each touched twice.")
        try:
            port.command(f"FINGER ENROLL_GROUP {finger}" + (" REPLACE" if replace else ""),
                         ENROLL_TIMEOUT, on_line=enrollment_prompt(finger))
        except (DeviceError, KeyboardInterrupt):
            note = (f"Enrollment of finger {finger} did not finish; the device rolls it back, "
                    "and other fingers are unchanged.")
            if replace:
                note += f" Finger {finger}'s old views were already deleted; enroll it again."
            print(note, file=sys.stderr)
            raise
        groups, _, _ = finger_inventory(port)
    if groups.get(finger) != VIEWS:
        raise CliError(f"finger {finger} does not report all {VIEWS} views; enroll it again")
    say(f"Finger {finger} is enrolled.")
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    """Upstream command_delete, with a guard for the last finger."""
    finger = args.finger
    with open_port(args) as port:
        device_status(port)
        groups, _, pending = finger_inventory(port)
        if finger not in groups:
            raise CliError(f"finger {finger} is not enrolled")
        last = not complete_others(groups, pending, finger)
        if last and not args.force:
            raise CliError(f"finger {finger} is the last enrolled finger; with none, the device "
                           "grants AUTH without a touch. Use --force to delete it anyway")
        if last:
            say("Warning: with no finger left, anyone holding the device can authorise it "
                "without a touch.")
        confirm("delete")
        authorize(port, f"delete finger {finger}")
        port.command(f"FINGER DELETE_GROUP {finger}", 25)
        groups, _, _ = finger_inventory(port)
    if finger in groups:
        raise CliError(f"finger {finger} is still listed after deleting it")
    say(f"Finger {finger} was deleted.")
    if last:
        say("No fingers remain: the device now grants AUTH without a touch. Enroll one soon.")
    return 0


def cmd_piv_create(args: argparse.Namespace) -> int:
    """Upstream command_keys and the PIV part of command_setup, after enrollment rather than
    before it, so the keys are never on a device that authorises without a touch."""
    port = open_port(args)
    try:
        status = device_status(port, sensor=True)
        if status.get("mode") != "piv":
            raise CliError(f"the device is in {status.get('mode')} mode, not piv")
        if status.get("piv") != "unconfigured":
            raise CliError(f"the device already has PIV keys (piv={status.get('piv')}); new keys "
                           "need a factory reset, which this tool does not do")
        groups, _, _ = finger_inventory(port)
        if int(status.get("fingerprints", "0")) < 1 or VIEWS not in groups.values():
            raise CliError("enroll a finger first (two are recommended): until then AUTH needs "
                           "no touch")
        say("This creates the device's PIV keys once. They cannot be replaced without a factory "
            "reset, which also erases fingers and settings. It takes up to a minute, then the "
            "device reconnects.")
        confirm("create")
        if authorize(port, "create the PIV keys") == "OK AUTH first_setup=1":
            raise CliError("the device has no enrolled finger after all; stopping")
        lost = False
        try:
            say("Creating keys; keep your finger off the sensor.")
            port.command("PIV CREATE", CREATE_TIMEOUT)  # EVENT PIV_CREATE, then the reply
            say("Keys created; waiting for the device to reconnect.")
        except (DeviceTimeout, DeviceGone):
            lost = True
            say("The device's reply was lost; waiting for it to come back to read its status.")
        except KeyboardInterrupt:
            print("The device finishes creating the keys regardless; check 'status' in a "
                  "minute. Do not run piv-create again before it reports piv.", file=sys.stderr)
            raise
        status = status_after_return(port)
    finally:
        port.close()
    if status.get("piv") != "ready":
        raise CliError(f"the device reports piv={status.get('piv')}: no keys were made. Check "
                       "'status' before trying again")
    say(("The reply was lost, but " if lost else "") + "the device reports piv=ready.")
    return 0


def status_after_return(port: Port) -> dict[str, str]:
    """STATUS once the device is back from re-enumerating. Key generation holds the console,
    so STATUS waits for it to finish."""
    deadline = time.monotonic() + RETURN_TIMEOUT + CREATE_TIMEOUT
    while True:
        port = ts.wait_for_return(port, RETURN_TIMEOUT, find=find_ports)
        try:
            with port:
                return port.status(CREATE_TIMEOUT)
        except DeviceGone:
            if time.monotonic() > deadline:
                raise


def setting_name(text: str) -> str:
    """Upstream setting_name, without the guessing."""
    name = text.lower().replace("-", "_")
    name = {"type_delay": "typing_delay_ms", "cooldown": "touch_cooldown_ms"}.get(name, name)
    if name not in SETTINGS:
        raise CliError(f"unknown setting '{text}'; settings: {', '.join(SETTINGS)}")
    return name


def setting_value(name: str, text: str) -> str:
    """The wire value for `text` (upstream setting_value)."""
    allowed = SETTINGS[name][1]
    text = text.strip().lower()
    if isinstance(allowed, dict):
        if text in allowed:
            return str(allowed[text])
        if text in map(str, allowed.values()):
            return text
        raise CliError(f"{name} takes one of: {', '.join(allowed)}")
    low, high = allowed
    if text.isdecimal() and low <= int(text) <= high:
        return str(int(text))
    raise CliError(f"{name} takes a whole number from {low} to {high}")


def shown(name: str, raw: str | None) -> str:
    """A STATUS value in the user's terms (upstream SettingSpec.decode)."""
    allowed = SETTINGS[name][1]
    if raw is None or not isinstance(allowed, dict) or raw in allowed:
        return raw or "-"
    return next((label for label, code in allowed.items() if str(code) == raw), raw)


def cmd_config(args: argparse.Namespace) -> int:
    """Upstream command_config and apply_settings, one setting at a time."""
    names = [setting_name(args.name)] if args.name else list(SETTINGS)
    value = setting_value(names[0], args.value) if args.value is not None else None
    with open_port(args) as port:
        status = device_status(port)
        if value is not None:
            name = names[0]
            authorize(port, f"change {name}")
            try:
                port.command(f"SET {SETTINGS[name][0]} {value}", 5)
            except DeviceRefused as exc:
                if str(exc) != "ERR SET LED reconnect_required":
                    raise
                say("Saved; replug the tinyTouch to finish applying the LED setting.")
            status = port.status()
            if shown(name, status.get(name)) != shown(name, value):
                raise CliError(f"the device reports {name}={shown(name, status.get(name))} "
                               "after the change")
    for name in names:
        say(f"{name}={shown(name, status.get(name))}")
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    import tinytouch_update  # needs python-cryptography, which no other command does
    return tinytouch_update.main([args.version] + (["--check"] if args.check else [])
                                 + (["--allow-downgrade"] if args.allow_downgrade else [])
                                 + (["--port", args.port] if args.port else []))


def cmd_pair(args: argparse.Namespace) -> int:
    """Hand over, through sudo, to the installed verifier's --enrol: root writes
    /etc/tinytouch/keys only from code it owns, never from this user-writable checkout, so this
    command itself refuses to run as root."""
    if os.geteuid() == 0:
        raise CliError("run `tinytouch.py pair` as yourself, not as root: it starts the installed "
                       "verifier through sudo, so no code from this checkout runs as root")
    if not os.path.isfile(VERIFIER):
        raise CliError(f"{VERIFIER} is not installed. Pairing runs only from that root-owned "
                       "copy, never from this checkout as root; install it first "
                       "(linux/README.md, Fingerprint for sudo)")
    try:
        os.execvp("sudo", ["sudo", VERIFIER, "--enrol", "--user", args.user])
    except OSError as exc:
        raise CliError(f"cannot run sudo: {exc.strerror}") from None
    return 1  # not reached: execvp replaced this process


def finger(text: str) -> int:
    if not (text.isdecimal() and 1 <= int(text) <= FINGERS):
        raise argparse.ArgumentTypeError(f"a finger number from 1 to {FINGERS}")
    return int(text)


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    top.add_argument("--port", help="serial node (default: the one attached tinyTouch)")
    commands = top.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def add(name: str, run, text: str) -> argparse.ArgumentParser:
        sub = commands.add_parser(name, help=text, description=text)
        sub.set_defaults(run=run)
        return sub

    sub = add("status", cmd_status, "show the device's state")
    sub.add_argument("--json", action="store_true", help="print every STATUS field as JSON")
    sub.add_argument("--check", action="store_true",
                     help="exit non-zero unless the device is set as the Linux port needs")
    add("logs", cmd_logs, "show the device's recent log")
    add("fingers", cmd_fingers, "list enrolled fingers")
    sub = add("enroll", cmd_enroll, "enroll a finger (four views)")
    sub.add_argument("--finger", type=finger, help="finger number 1-10 (default: first free)")
    sub.add_argument("--replace", action="store_true",
                     help="enroll an enrolled finger again; its old views are deleted first")
    sub.add_argument("--force", action="store_true", help="allow replacing the only finger")
    sub = add("delete", cmd_delete, "delete an enrolled finger")
    sub.add_argument("finger", type=finger, help="finger number 1-10")
    sub.add_argument("--force", action="store_true", help="allow deleting the last finger")
    add("piv-create", cmd_piv_create, "create the PIV keys, once (needs an enrolled finger)")
    sub = add("config", cmd_config, "read all settings, read one, or set one")
    sub.add_argument("name", nargs="?", help=", ".join(SETTINGS))
    sub.add_argument("value", nargs="?", help="new value (asks for a touch)")
    sub = add("update", cmd_update, "update the firmware to a stock upstream release")
    sub.add_argument("version", help="release, e.g. 0.1.34")
    sub.add_argument("--check", action="store_true", help="verify only; write nothing")
    sub.add_argument("--allow-downgrade", action="store_true",
                     help="install a release older than the device's firmware")
    sub = add("pair", cmd_pair, "pair the attached tinyTouch with a user for sudo (asks sudo)")
    sub.add_argument("--user", required=True, help="the user whose touch it approves")
    return top


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.run(args)
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130
    except (CliError, DeviceError) as exc:
        print(f"error: {human_error(exc)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
