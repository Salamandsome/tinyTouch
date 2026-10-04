"""Session behaviour of the serial link: events, timeouts, hang-ups, re-enumeration, DTR."""

import fcntl
import sys
import termios
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tinytouch_serial as ts  # noqa: E402
from fake_device import FakeDevice, new_state  # noqa: E402


class ModemLines:
    """Records modem-line ioctls, which a pseudo-terminal rejects as the real ones would not."""

    def __init__(self):
        self.calls = []
        self.requests = []  # every ioctl, as (fd, request)
        self.real = fcntl.ioctl

    def __call__(self, fd, request, *args):
        self.requests.append((fd, request))
        if request in (termios.TIOCMBIS, termios.TIOCMBIC):
            self.calls.append((request, int.from_bytes(args[0], sys.byteorder)))
            raise OSError(25, "Inappropriate ioctl for device")
        return self.real(fd, request, *args)

    def dropped_dtr(self):
        return (termios.TIOCMBIC, termios.TIOCM_DTR) in self.calls


class EventTest(unittest.TestCase):
    def test_events_go_to_the_callback(self):
        device = FakeDevice(new_state(fingers={1: 4}))
        seen = []
        with ts.Port(device.path) as port:
            lines = port.command("AUTH", 5, on_line=seen.append)
        self.assertEqual(seen, ["EVENT TOUCH"])
        self.assertEqual(lines[-1], "OK AUTH")

    def test_err_reply_keeps_the_session(self):
        device = FakeDevice()
        with ts.Port(device.path) as port:
            with self.assertRaises(ts.DeviceRefused) as caught:
                port.command("PIV CREATE", 5)
            self.assertEqual(str(caught.exception), "ERR LOCKED run=AUTH")
            self.assertEqual(port.status()["protocol"], "6")


class TimeoutTest(unittest.TestCase):
    def test_timeout_invalidates_the_session(self):
        device = FakeDevice(new_state(silent={"LOGS"}))
        with ts.Port(device.path) as port:
            with self.assertRaises(ts.DeviceTimeout):
                port.command("LOGS", 0.3)
            with self.assertRaisesRegex(ts.DeviceError, "reopen"):
                port.status()
        self.assertEqual(device.state.commands, ["LOGS"])  # nothing sent after the timeout

    def test_interrupt_invalidates_the_session(self):
        device = FakeDevice(new_state(silent={"LOGS"}))
        port = ts.Port(device.path)
        timer = threading.Timer(0.2, __import__("_thread").interrupt_main)
        timer.start()
        with self.assertRaises(KeyboardInterrupt):
            port.command("LOGS", 5)
        with self.assertRaises(ts.DeviceError):
            port.status()
        port.close()


class GoneTest(unittest.TestCase):
    def test_hangup_is_device_gone(self):
        device = FakeDevice(new_state(silent={"LOGS"}))
        with ts.Port(device.path) as port:
            threading.Timer(0.2, device.vanish).start()
            with self.assertRaises(ts.DeviceGone):
                port.command("LOGS", 5)

    def test_write_eio_is_device_gone(self):
        device = FakeDevice()
        with ts.Port(device.path) as port:
            device.vanish()
            with self.assertRaises(ts.DeviceGone):
                port.command("STATUS", 2)


class ReturnTest(unittest.TestCase):
    def test_waits_for_device_to_leave_and_come_back(self):
        state = new_state()
        device = FakeDevice(state)
        port = ts.Port(device.path)
        returned = []
        threading.Thread(target=lambda: returned.append(device.reenumerate(gap=0.5))).start()
        fresh = ts.wait_for_return(port, 5, find=lambda: list(state.paths))
        with fresh:
            self.assertEqual(fresh.status()["piv"], "unconfigured")
        self.assertEqual(fresh.path, returned[0].path)
        self.assertEqual(state.commands, ["STATUS"])
        self.assertEqual(port.fd, -1)

    def test_gives_up_after_timeout(self):
        state = new_state()
        device = FakeDevice(state)
        port = ts.Port(device.path)
        device.vanish()
        started = time.monotonic()
        with self.assertRaisesRegex(ts.DeviceGone, "did not come back"):
            ts.wait_for_return(port, 0.5, find=lambda: [])
        self.assertLess(time.monotonic() - started, 3)

    def test_two_devices_are_never_opened(self):
        # Which one is ours is unknowable, so neither gets the next command.
        device = FakeDevice()
        port = ts.Port(device.path)
        device.vanish()
        others = [FakeDevice(), FakeDevice()]
        with mock.patch.object(ts, "Port", wraps=ts.Port) as opened, \
                self.assertRaisesRegex(ts.DeviceGone, "did not come back"):
            ts.wait_for_return(port, 0.5, find=lambda: [d.path for d in others])
        self.assertEqual(opened.call_count, 0)
        self.assertEqual([d.state.commands for d in others], [[], []])


class ExclusiveTest(unittest.TestCase):
    def test_open_is_exclusive(self):
        # TIOCEXCL keeps a second program (another tool, ModemManager) off the session.
        device = FakeDevice()
        modem = ModemLines()
        with mock.patch.object(ts.fcntl, "ioctl", modem):
            ts.Port(device.path).close()
        self.assertIn(termios.TIOCEXCL, [request for _, request in modem.requests])


class StatusTimeoutTest(unittest.TestCase):
    def test_status_outlasts_the_sensor_retries(self):
        # fingerprint.c fingerprint_count retries with recovery for up to ~14 s.
        device = FakeDevice()
        with ts.Port(device.path) as port, \
                mock.patch.object(port, "command", wraps=port.command) as command:
            port.status()
        self.assertGreaterEqual(command.call_args.args[1], 15)


class DtrTest(unittest.TestCase):
    def test_close_drops_dtr(self):
        device = FakeDevice()
        modem = ModemLines()
        with mock.patch.object(ts.fcntl, "ioctl", modem):
            port = ts.Port(device.path)
            self.assertFalse(modem.dropped_dtr())
            port.close()
        self.assertTrue(modem.dropped_dtr())

    def test_hangup_on_close_is_set(self):
        # Covers a host killed outright: the kernel then drops DTR on the last close.
        device = FakeDevice()
        with ts.Port(device.path) as port:
            self.assertTrue(termios.tcgetattr(port.fd)[2] & termios.HUPCL)


if __name__ == "__main__":
    unittest.main()
