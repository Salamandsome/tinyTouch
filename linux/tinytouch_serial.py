"""Serial (CDC-ACM) link to a tinyTouch on Linux, using only the standard library."""

from __future__ import annotations

import errno
import fcntl
import os
import re
import select
import struct
import termios
import time
from pathlib import Path
from typing import Callable

VENDOR_ID = "303a"
PRODUCT_ID = "4001"
NAME = "tinyTouch"
# Protocol 6 groups live writes under these verbs (macos/cli.py is_terminal).
GROUPED = {"SET", "HOST", "FINGER", "RESET", "OTA", "LED"}


class DeviceError(Exception):
    pass


class DeviceRefused(DeviceError):
    """The device answered with an ERR line (the message); the session stays usable."""


class DeviceTimeout(DeviceError):
    pass


class DeviceGone(DeviceError):
    """The serial node hung up or vanished: the device is reconnecting or was unplugged."""


GONE = {errno.ENODEV, errno.EIO, errno.ENXIO}


def gone(path: str, exc: OSError) -> DeviceError | OSError:
    return DeviceGone(f"{path} went away ({exc.strerror})") if exc.errno in GONE else exc


def find_ports(sys_root: Path = Path("/sys")) -> list[str]:
    """Serial nodes of attached tinyTouch units. 303a:4001 is Espressif's default ID, so the
    manufacturer and product strings are matched too."""
    ports = []
    for tty in sorted((sys_root / "class" / "tty").glob("ttyACM*")):
        usb_device = (tty / "device").resolve().parent
        try:
            ids = [(usb_device / name).read_text().strip()
                   for name in ("idVendor", "idProduct", "manufacturer", "product")]
        except OSError:
            continue
        if ids == [VENDOR_ID, PRODUCT_ID, NAME, NAME]:
            ports.append(f"/dev/{tty.name}")
    return ports


def is_terminal(command: str, line: str) -> bool:
    """Whether `line` ends the device's reply to `command` (as upstream macos/cli.py)."""
    words = command.split()
    verb = words[0]
    if line in ("ERR COMMAND", "ERR LINE") or line.startswith("ERR LOCKED"):
        return True
    if verb == "PING":
        return line.startswith("PONG") or line.startswith("ERR PING")
    fields = line.split()
    if len(fields) < 2 or fields[0] not in {"OK", "ERR"}:
        return False
    if fields[1] == verb:
        return True
    return len(words) > 1 and verb in GROUPED and fields[1] == words[1]


def fields(line: str) -> dict[str, str]:
    return dict(re.findall(r"([A-Za-z_]+)=([^ ]+)", line))


class Port:
    """One exclusive session on the device's serial port; the firmware serves one client."""

    def __init__(self, path: str):
        self.path = path
        self.broken = False
        try:
            self.fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        except OSError as exc:
            raise gone(path, exc) from None
        try:
            fcntl.ioctl(self.fd, termios.TIOCEXCL)
            attrs = termios.tcgetattr(self.fd)
            attrs[0] = attrs[1] = attrs[3] = 0
            # HUPCL: if this process dies, the kernel's last close still drops DTR, which tells
            # the firmware the host left (an enrollment then rolls back).
            attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL | termios.HUPCL
            attrs[4] = attrs[5] = termios.B115200
            termios.tcsetattr(self.fd, termios.TCSANOW, attrs)
            # The firmware answers only while DTR is asserted; upstream also drops RTS.
            for request, line in ((termios.TIOCMBIS, termios.TIOCM_DTR),
                                  (termios.TIOCMBIC, termios.TIOCM_RTS)):
                try:
                    fcntl.ioctl(self.fd, request, struct.pack("I", line))
                except OSError:
                    pass  # a pseudo-terminal (tests) has no modem lines
            termios.tcflush(self.fd, termios.TCIOFLUSH)
        except BaseException:
            os.close(self.fd)
            raise
        self.buffer = b""

    def __enter__(self) -> Port:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        if self.fd >= 0:
            try:
                fcntl.ioctl(self.fd, termios.TIOCMBIC, struct.pack("I", termios.TIOCM_DTR))
            except OSError:
                pass  # gone already, or a pseudo-terminal
            os.close(self.fd)
            self.fd = -1

    def write_line(self, text: str) -> None:
        data = (text + "\n").encode("ascii")
        deadline = time.monotonic() + 5
        while data:
            if time.monotonic() > deadline:
                raise DeviceError(f"write to {self.path} timed out")
            select.select([], [self.fd], [], 0.2)
            try:
                data = data[os.write(self.fd, data):]
            except BlockingIOError:
                pass
            except OSError as exc:
                raise gone(self.path, exc) from None

    def read_line(self, deadline: float) -> str | None:
        while b"\n" not in self.buffer:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            if select.select([self.fd], [], [], min(left, 0.2))[0]:
                try:
                    chunk = os.read(self.fd, 4096)
                except BlockingIOError:
                    continue
                except OSError as exc:
                    raise gone(self.path, exc) from None
                if not chunk:  # hang-up: the USB device detached
                    raise DeviceGone(f"{self.path} went away")
                self.buffer += chunk
        raw, self.buffer = self.buffer.split(b"\n", 1)
        return raw.decode("utf-8", "replace").strip()

    def command(self, command: str, timeout: float = 8.0, *, check: bool = True,
                on_line: Callable[[str], None] | None = None) -> list[str]:
        """Send one command and return its reply lines, the terminal one last. Earlier lines
        (EVENT prompts, LOG lines) also go to `on_line` as they arrive."""
        if self.broken:
            raise DeviceError("the session is out of sync after an unfinished command; reopen it")
        lines: list[str] = []
        try:
            self.write_line(command)
            deadline = time.monotonic() + timeout
            while True:
                line = self.read_line(deadline)
                if line is None:
                    raise DeviceTimeout(f"no reply to {command.split()[0]} within {timeout:g} s")
                if not line:
                    continue
                lines.append(line)
                if is_terminal(command, line):
                    break
                if on_line:
                    on_line(line)
        except BaseException:
            # The device may still answer; that late reply would be read as the next one's.
            self.broken = True
            raise
        if check and lines[-1].startswith("ERR"):
            raise DeviceRefused(lines[-1])
        return lines

    def status(self, timeout: float = 4.0) -> dict[str, str]:
        line = self.command("STATUS", timeout)[-1]
        if not line.startswith("OK STATUS "):
            raise DeviceError(f"unexpected STATUS reply: {line}")
        return fields(line)


def wait_for_return(port: Port, timeout: float = 60.0, find: Callable[[], list[str]] | None = None,
                    gone_within: float = 10.0) -> Port:
    """Close `port` once its device has left the bus (or `gone_within` passed), then wait for one
    tinyTouch to come back and return a new session on it (macos/cli.py wait_for_reconnect)."""
    find = find or find_ports
    deadline = time.monotonic() + timeout
    gone_by = min(deadline, time.monotonic() + gone_within)
    try:
        while port.fd >= 0 and time.monotonic() < gone_by and port.path in find():
            port.read_line(min(gone_by, time.monotonic() + 0.2))  # a late line is moot now
    except DeviceGone:
        pass
    port.close()
    while True:
        nodes = find()
        if len(nodes) == 1:
            try:
                return Port(nodes[0])
            except (OSError, DeviceError):
                pass  # udev may not have applied its permissions yet
        if time.monotonic() >= deadline:
            raise DeviceGone(f"the tinyTouch did not come back within {timeout:g} s")
        time.sleep(0.2)
