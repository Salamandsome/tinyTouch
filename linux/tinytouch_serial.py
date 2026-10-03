"""Serial (CDC-ACM) link to a tinyTouch on Linux, using only the standard library."""

from __future__ import annotations

import fcntl
import os
import re
import select
import struct
import termios
import time
from pathlib import Path

VENDOR_ID = "303a"
PRODUCT_ID = "4001"
NAME = "tinyTouch"
# Protocol 6 groups live writes under these verbs (macos/cli.py is_terminal).
GROUPED = {"SET", "HOST", "FINGER", "RESET", "OTA", "LED"}


class DeviceError(Exception):
    pass


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
        self.fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        try:
            fcntl.ioctl(self.fd, termios.TIOCEXCL)
            attrs = termios.tcgetattr(self.fd)
            attrs[0] = attrs[1] = attrs[3] = 0
            attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
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
                if not chunk:
                    raise DeviceError(f"{self.path} closed")
                self.buffer += chunk
        raw, self.buffer = self.buffer.split(b"\n", 1)
        return raw.decode("utf-8", "replace").strip()

    def command(self, command: str, timeout: float = 8.0, *, check: bool = True) -> list[str]:
        """Send one command and return its reply lines, the terminal one last."""
        self.write_line(command)
        deadline = time.monotonic() + timeout
        lines: list[str] = []
        while True:
            line = self.read_line(deadline)
            if line is None:
                raise DeviceError(f"no reply to {command.split()[0]} within {timeout:g} s")
            if not line:
                continue
            lines.append(line)
            if is_terminal(command, line):
                break
        if check and lines[-1].startswith("ERR"):
            raise DeviceError(lines[-1])
        return lines

    def status(self) -> dict[str, str]:
        line = self.command("STATUS", 4)[-1]
        if not line.startswith("OK STATUS "):
            raise DeviceError(f"unexpected STATUS reply: {line}")
        return fields(line)
