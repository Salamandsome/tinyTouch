"""The PAM verifier and pairing (tinytouch_piv.py) against a fake pcsc layer and a software card.

Everything runs in temporary directories: the key store, sysfs, /proc and /run lookups and the
smart-card module are the verifier's module-level names, patched here. Nothing touches the
system or a device.
"""

import io
import json
import os
import pwd
import re
import signal
import stat
import subprocess
import sys
import tempfile
import termios
import threading
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

TESTS = Path(__file__).resolve().parent
LINUX = TESTS.parent
sys.path.insert(0, str(TESTS))
sys.path.insert(0, str(LINUX))
import tinytouch_piv as tp  # noqa: E402
import tinytouch_serial as ts  # noqa: E402
from fake_device import FakeDevice, new_state  # noqa: E402
from fake_pcsc import FakeCard, FakeScard, self_signed, shared_key, spki_pem  # noqa: E402
from test_serial import ModemLines  # noqa: E402

USER = pwd.getpwuid(os.getuid()).pw_name
PROMPT = "Touch tinyTouch to approve tinytouch-test."
SUDO_PROMPT = "Touch tinyTouch to approve sudo, or press Enter for password."


class Recorder(io.StringIO):
    """Standard output that remembers what had been flushed."""

    def __init__(self):
        super().__init__()
        self.flushed = ""

    def flush(self):
        super().flush()
        self.flushed = self.getvalue()


def child_env(env: dict) -> dict:
    """A subprocess test's environment, keeping the run's PYTHONDONTWRITEBYTECODE."""
    env = dict(env)
    if "PYTHONDONTWRITEBYTECODE" in os.environ:
        env["PYTHONDONTWRITEBYTECODE"] = os.environ["PYTHONDONTWRITEBYTECODE"]
    return env


def spki_der(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


@unittest.skipUnless(tp.USER_NAME.fullmatch(USER), "the test user's name is not a PAM user name")
class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="tinytouch-verify-"))
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.tmp)])
        self.root = self.tmp / "root"
        self.keys = self.root / "etc" / "tinytouch" / "keys"
        self.keys.mkdir(parents=True)
        for directory in (self.root, self.root / "etc", self.keys.parent, self.keys):
            directory.chmod(0o755)
        self.sys = self.tmp / "sys"
        self.add_usb("1-1", "1d6b", "0002", "Linux", "xHCI Host Controller")
        (self.sys / "bus" / "usb" / "devices" / "usb1").mkdir()
        self.add_usb("1-4", "303a", "4001", "tinyTouch", "tinyTouch")
        self.cgroup = self.tmp / "cgroup"
        self.cgroup.write_text("0::/user.slice/user-1000.slice/session-4.scope\n")
        self.sessions = self.tmp / "sessions"
        self.sessions.mkdir()
        (self.sessions / "4").write_text("UID=1000\nUSER=someone\nREMOTE=0\nTYPE=wayland\n")
        self.proc = self.tmp / "proc"
        self.proc.mkdir()
        self.scard = FakeScard()
        self.card = self.scard.card
        self.logs = []
        self.parent = os.getppid()
        patches = mock.patch.multiple(
            tp, SYS_ROOT=self.sys, KEY_DIR=self.keys, TRUSTED_ROOT=self.root,
            TRUSTED_UID=os.getuid(), BACKUP_ROOT=self.root / "var" / "lib" / "tinytouch" / "backup",
            PROC=self.proc, PROC_CGROUP=self.cgroup, SESSIONS_DIR=self.sessions, POLL=0.01,
            READER_WAIT=0.3, scard=self.scard, write_log=self.capture_log,
            getppid=lambda: self.parent)
        patches.start()
        self.addCleanup(patches.stop)
        self.env = {"PAM_TYPE": "auth", "PAM_USER": USER, "PAM_SERVICE": "tinytouch-test"}

    def add_usb(self, name, vendor, product, manufacturer, title):
        device = self.sys / "bus" / "usb" / "devices" / name
        device.mkdir(parents=True)
        for field, value in (("idVendor", vendor), ("idProduct", product),
                             ("manufacturer", manufacturer), ("product", title)):
            (device / field).write_text(value + "\n")

    def capture_log(self, priority, line):
        self.logs.append((priority, line))

    def enrol_keys(self, *keys, mode=0o644, user=USER):
        path = self.keys / f"{user}.pem"
        path.write_bytes(b"".join(spki_pem(k) for k in keys))
        path.chmod(mode)
        return path

    def run_main(self, *argv, env=None):
        out = Recorder()
        started = time.monotonic()
        with redirect_stdout(out):
            code = tp.main(list(argv), dict(self.env if env is None else env))
        self.elapsed = time.monotonic() - started
        self.out, self.flushed = out.getvalue(), out.flushed
        return code

    def assert_card_left_clean(self):
        self.assertEqual(self.scard.outside_transaction, 0)
        self.assertEqual(self.scard.in_transaction, set())
        self.assertEqual(self.scard.handles, {})
        self.assertEqual(self.scard.contexts, self.scard.released)

    def results(self):
        return [line for _, line in self.logs]


class VerifyTest(Fixture):
    def setUp(self):
        super().setUp()
        self.enrol_keys(self.card.key)

    def test_touch_is_verified(self):
        self.card.on_ga[2] = "touch"
        self.assertEqual(self.run_main("--timeout", "5"), 0)
        self.assertEqual(self.out, PROMPT + "\n")
        self.assertEqual(self.flushed, self.out)
        # probe refused, touched challenge signed, then the window-kind probes: 9A refused (slot
        # used), 9D signed (the touch window's second operation)
        self.assertEqual(self.card.results, [0x6982, 0x9000, 0x6982, 0x9000])
        self.assertEqual(self.card.ga_slots, [0x9A, 0x9A, 0x9A, 0x9D])
        self.assertTrue(all(len(b) == 256 for b in self.card.blocks))
        self.assertEqual(len(set(self.card.blocks)), len(self.card.blocks))  # a nonce each
        self.assert_card_left_clean()
        self.assertIn("result=ok", self.results()[-1])

    def test_probe_goes_before_the_prompt(self):
        seen = []
        out = Recorder()
        self.card.on_ga[1] = lambda card: seen.append(out.getvalue())
        self.card.on_ga[2] = "touch"
        with redirect_stdout(out):
            self.assertEqual(tp.main(["--timeout", "5"], dict(self.env)), 0)
        self.assertEqual(seen, [""])

    def test_forged_signature(self):
        self.card.tamper = lambda reply: reply[:-1] + bytes([reply[-1] ^ 1])
        self.card.on_ga[2] = "touch"
        self.assertEqual(self.run_main("--timeout", "5"), 5)
        self.assert_card_left_clean()

    def test_short_or_garbage_reply(self):
        for tamper in (lambda r: r[:200], lambda r: b"\x01\x02",
                       lambda r: b"\x7c\x82\x01\x05\x82\x82\x01\x01" + r[8:] + b"\x00",
                       lambda r: r + b"\x00", lambda r: r[:1] + b"\x81" + r[2:]):
            with self.subTest(tamper=tamper):
                self.card.window = None
                self.card.tamper = tamper
                self.card.on_ga = {self.card.ga_count + 2: "touch"}
                self.assertEqual(self.run_main("--timeout", "5"), 5)

    def test_signature_by_another_key(self):
        self.scard.cards = {"tinyTouch 00 00": FakeCard(shared_key(1), self_signed(self.card.key))}
        self.scard.card.on_ga[2] = "touch"
        self.assertEqual(self.run_main("--timeout", "5"), 5)

    def test_refused_for_ever_times_out(self):
        self.assertEqual(self.run_main("--timeout", "0.5"), 1)
        self.assertGreaterEqual(self.elapsed, 0.5)
        self.assertLess(self.elapsed, 1.0)
        self.assertEqual(self.out, PROMPT + "\n")
        self.assertIn("reason=timeout", self.results()[-1])

    def test_absent_device_is_fast(self):
        subprocess.run(["rm", "-rf", str(self.sys / "bus" / "usb" / "devices" / "1-4")])
        self.assertEqual(self.run_main("--timeout", "5"), 2)
        self.assertLess(self.elapsed, 0.05)
        self.assertEqual(self.scard.calls, [])
        self.assertEqual(self.out, "")

    def test_other_espressif_device_is_absent(self):
        (self.sys / "bus" / "usb" / "devices" / "1-4" / "product").write_text("Other\n")
        self.assertEqual(self.run_main(), 2)

    def test_reader_that_never_shows_is_absent(self):
        self.scard.hidden_polls = 10 ** 6
        self.assertEqual(self.run_main("--timeout", "5"), 2)
        self.assertLess(self.elapsed, 1.0)
        self.assertEqual(self.out, "")

    def test_cold_pcscd_reader_shows_late(self):
        self.scard.hidden_polls = 5
        self.card.on_ga[2] = "touch"
        self.assertEqual(self.run_main("--timeout", "5"), 0)

    def test_unknown_key(self):
        self.enrol_keys(shared_key(1))
        self.assertEqual(self.run_main(), 3)
        self.assertEqual(self.card.ga_count, 0)
        self.assertEqual(self.out, "")
        self.assert_card_left_clean()

    def test_no_key_file(self):
        (self.keys / f"{USER}.pem").unlink()
        self.assertEqual(self.run_main(), 3)
        self.assertEqual(self.scard.calls, [])

    def test_no_key_directory(self):
        subprocess.run(["rm", "-rf", str(self.keys.parent)])
        self.assertEqual(self.run_main(), 3)

    def test_several_keys_and_readers(self):
        other = FakeCard(shared_key(1))
        self.scard.cards = {"tinyTouch 00 00": other, "tinyTouch 01 00": self.card}
        self.enrol_keys(shared_key(2), self.card.key)
        self.card.on_ga[2] = "touch"
        self.assertEqual(self.run_main("--timeout", "5"), 0)
        self.assertEqual(other.ga_count, 0)
        self.assert_card_left_clean()

    def test_card_without_certificate(self):
        self.card.cert = b""
        self.assertEqual(self.run_main(), 3)

    def test_certificate_with_unknown_key_algorithm(self):
        rsa_oid = bytes.fromhex("06092a864886f70d010101")  # rsaEncryption, in the SPKI only
        self.assertEqual(self.card.cert.count(rsa_oid), 1)
        self.card.cert = self.card.cert.replace(rsa_oid, rsa_oid[:-1] + b"\x63")
        self.assertEqual(self.run_main(), 3)
        self.assertIn("reason=other_key", self.results()[-1])
        self.assert_card_left_clean()

    def test_stale_touch_window_is_discarded(self):
        self.card.touch()  # a touch made before sudo started
        self.card.on_ga[3] = "touch"
        self.assertEqual(self.run_main("--timeout", "5"), 0)
        self.assertEqual(self.card.results, [0x9000, 0x6982, 0x9000, 0x6982, 0x9000])
        self.assertEqual(self.out, "An earlier touch was ignored; touch again.\n" + PROMPT + "\n")
        self.assertEqual(sum("event=stale_window" in line for line in self.results()), 1)
        self.assertEqual([p for p, line in self.logs if "stale_window" in line],
                         [tp.syslog.LOG_WARNING])

    def test_stale_auth_window_is_drained(self):
        self.card.auth()  # the CLI's serial AUTH: eight operations, slots may repeat
        self.card.on_ga[10] = "touch"
        self.assertEqual(self.run_main("--timeout", "5"), 0)
        self.assertEqual(self.card.results, [0x9000] * 8 + [0x6982, 0x9000, 0x6982, 0x9000])

    def test_auth_window_after_refusal_is_rejected(self):
        self.card.on_ga[2] = "auth"
        self.assertEqual(self.run_main("--timeout", "5"), 5)
        self.assertEqual(self.card.results, [0x6982, 0x9000, 0x9000])
        self.assertIn("reason=auth_window", self.results()[-1])

    def auth_window_with(self, operations):
        def hook(card):
            card.auth()
            card.window.operations = operations
        return hook

    def test_auth_window_with_one_operation_left_is_rejected(self):
        # The main challenge spends its last operation, so the 9A probe is refused as in a touch
        # window; the 9D probe tells them apart.
        self.card.on_ga[2] = self.auth_window_with(1)
        self.assertEqual(self.run_main("--timeout", "5"), 5)
        self.assertEqual(self.card.results, [0x6982, 0x9000, 0x6982, 0x6982])
        self.assertEqual(self.card.ga_slots, [0x9A, 0x9A, 0x9A, 0x9D])
        self.assertIn("reason=window_kind", self.results()[-1])
        self.assertIn("result=bad_signature", self.results()[-1])
        self.assert_card_left_clean()

    def test_auth_window_with_two_operations_left_is_rejected(self):
        self.card.on_ga[2] = self.auth_window_with(2)
        self.assertEqual(self.run_main("--timeout", "5"), 5)
        self.assertEqual(self.card.results, [0x6982, 0x9000, 0x9000])
        self.assertIn("reason=auth_window", self.results()[-1])

    def test_touch_window_with_9d_already_spent_fails_closed(self):
        def touched_then_9d_used(card):
            card.touch()
            card.window.slots |= 0x02  # another client's GA 9D, as piv.c accounts it
            card.window.operations -= 1
        self.card.on_ga[2] = touched_then_9d_used
        self.assertEqual(self.run_main("--timeout", "5"), 5)
        self.assertEqual(self.card.results, [0x6982, 0x9000, 0x6982, 0x6982])
        self.assertIn("reason=window_kind", self.results()[-1])

    def test_malformed_9d_probe_reply_is_rejected(self):
        def tamper_9d(card):
            card.touch()
            card.tamper = lambda reply: reply if card.ga_count < 4 else reply[:200]
        self.card.on_ga[2] = tamper_9d
        self.assertEqual(self.run_main("--timeout", "5"), 5)
        self.assertEqual(self.card.results, [0x6982, 0x9000, 0x6982, 0x9000])
        self.assertIn("reason=window_kind", self.results()[-1])

    def test_window_kind_probes_use_fresh_blocks(self):
        self.card.on_ga[2] = "touch"
        self.assertEqual(self.run_main("--timeout", "5"), 0)
        self.assertEqual(len(self.card.blocks), 4)
        self.assertEqual(len(set(self.card.blocks)), 4)

    def test_retry_before_any_refusal_is_not_a_refusal(self):
        # A stale window, then a sharing violation on the first challenge: the stale signature
        # that follows must still be discarded.
        self.card.touch()
        real = tp.find_card

        def found_then_busy(*args):
            found = real(*args)
            self.scard.busy_begins = 1
            return found
        with mock.patch.object(tp, "find_card", found_then_busy):
            self.assertEqual(self.run_main("--timeout", "0.5"), 1)
        self.assertEqual(self.scard.busy_begins, 0)
        self.assertEqual(self.card.results[0], 0x9000)  # the stale window signed, and was ignored
        self.assertIn("reason=timeout", self.results()[-1])

    def test_signature_through_get_response(self):
        self.card.chunk_ga = True
        self.card.on_ga[2] = "touch"
        self.assertEqual(self.run_main("--timeout", "5"), 0)

    def test_get_response_rounds_are_bounded(self):
        start = []

        def endless(card):
            start.append(card.get_responses)
            card.chunk_ga = card.endless_61 = True
        self.card.on_ga[1] = endless
        self.card.on_ga[2] = "touch"
        self.assertEqual(self.run_main("--timeout", "5"), 5)
        self.assertEqual(self.card.get_responses - start[0], tp.MAX_GET_RESPONSE)

    def test_endless_certificate_is_no_match(self):
        self.card.endless_61 = True
        self.assertEqual(self.run_main(), 3)
        self.assertEqual(self.card.get_responses, tp.MAX_GET_RESPONSE)

    def test_reset_card_reconnects(self):
        self.card.on_ga[2] = lambda card: self.scard.reset_at.add(self.scard.transmits + 1)
        self.card.on_ga[3] = "touch"
        self.assertEqual(self.run_main("--timeout", "5"), 0)
        self.assertEqual(self.scard.reconnects, 1)
        self.assert_card_left_clean()

    def test_sharing_violation_keeps_polling(self):
        self.card.on_ga[1] = lambda card: setattr(self.scard, "busy_begins", 3)
        self.card.on_ga[2] = "touch"
        self.assertEqual(self.run_main("--timeout", "5"), 0)
        self.assertEqual(self.scard.busy_begins, 0)

    def test_sharing_violation_until_the_deadline(self):
        self.card.on_ga[1] = lambda card: setattr(self.scard, "busy_begins", 10 ** 6)
        self.assertEqual(self.run_main("--timeout", "0.3"), 1)

    def test_card_removed_while_waiting(self):
        self.card.on_ga[2] = lambda card: setattr(self.scard, "removed_at",
                                                  self.scard.transmits + 1)
        self.assertEqual(self.run_main("--timeout", "5"), 2)
        self.assert_card_left_clean()

    def test_internal_error_is_70(self):
        self.card.on_ga[1] = lambda card: setattr(self.scard, "raise_at",
                                                  self.scard.transmits + 1)
        self.assertEqual(self.run_main("--timeout", "5"), 70)
        self.assertIn("result=internal", self.results()[-1])
        self.assertIn("error=RuntimeError", self.results()[-1])
        self.assertIn(f"service=tinytouch-test user={USER} tty= ", self.results()[-1])

    def test_parent_gone_ends_the_wait(self):
        calls = []

        def parent():
            calls.append(1)
            return self.parent if len(calls) < 5 else 1
        with mock.patch.object(tp, "getppid", parent):
            self.assertEqual(self.run_main("--timeout", "5"), 1)
        self.assertLess(self.elapsed, 1.0)
        self.assert_card_left_clean()
        self.assertIn(f"service=tinytouch-test user={USER} tty= result=password reason=parent_gone",
                      self.results()[-1])

    def test_log_failure_does_not_change_the_result(self):
        def broken(priority, line):
            raise OSError("no syslog")
        self.card.on_ga[2] = "touch"
        with mock.patch.object(tp, "write_log", broken):
            self.assertEqual(self.run_main("--timeout", "5"), 0)

    def test_timeout_zero_waits_until_parent_goes(self):
        calls = []

        def parent():
            calls.append(1)
            return self.parent if len(calls) < 40 else 1
        with mock.patch.object(tp, "getppid", parent):
            self.assertEqual(self.run_main("--timeout", "0"), 1)
        self.assertGreater(self.card.ga_count, 10)


class RequestTest(Fixture):
    """PAM_TYPE, PAM_USER, remote sessions and the terminal."""

    def setUp(self):
        super().setUp()
        self.enrol_keys(self.card.key)

    def test_pam_type_must_be_auth(self):
        for value in ("account", "", "auth\n", "AUTH", None):
            with self.subTest(value=value):
                env = dict(self.env, PAM_TYPE=value)
                if value is None:
                    del env["PAM_TYPE"]
                self.assertEqual(self.run_main(env=env), 4)
                self.assertEqual(self.scard.calls, [])
                self.assertEqual(self.out, "")

    def test_user_must_be_valid_and_exist(self):
        for name in ("", "../" + USER, USER + "/..", "Root", "a" * 33, "root\n", "-x",
                     "no_such_user_tinytouch", None):
            with self.subTest(name=name):
                env = dict(self.env, PAM_USER=name)
                if name is None:
                    del env["PAM_USER"]
                self.assertEqual(self.run_main(env=env), 3)
                self.assertEqual(self.scard.calls, [])

    def test_user_name_rule_does_not_rely_on_nss(self):
        me = pwd.getpwnam(USER)
        with mock.patch.object(tp.pwd, "getpwnam", lambda name: me):
            for name in ("../" + USER, "Root", "a" * 33, USER + "\n", "x/../" + USER):
                with self.subTest(name=name):
                    self.assertEqual(self.run_main(env=dict(self.env, PAM_USER=name)), 3)
                    self.assertEqual(self.scard.calls, [])

    def test_remote_session_never_prompts(self):
        (self.sessions / "4").write_text("UID=1000\nREMOTE=1\nREMOTE_HOST=192.0.2.1\n")
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.out, "")
        self.assertEqual(self.scard.calls, [])
        self.assertIn("reason=remote", self.results()[-1])

    def test_unreadable_session_counts_as_remote(self):
        (self.sessions / "4").unlink()
        (self.sessions / "4").mkdir()
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.scard.calls, [])

    def test_no_login_session_is_local(self):
        self.cgroup.write_text("0::/system.slice/polkit-agent-helper@1.service\n")
        self.card.on_ga[2] = "touch"
        self.assertEqual(self.run_main("--timeout", "5"), 0)

    def test_session_ids_with_letters(self):
        self.cgroup.write_text("0::/user.slice/user-1000.slice/session-c2.scope\n")
        (self.sessions / "c2").write_text("REMOTE=1\n")
        self.assertEqual(self.run_main(), 1)

    def test_sudo_needs_a_terminal(self):
        env = dict(self.env, PAM_SERVICE="sudo")
        self.assertEqual(self.run_main(env=env), 1)
        self.assertLess(self.elapsed, 0.05)
        self.assertEqual(self.out, "")
        self.assertEqual(self.scard.calls, [])
        self.assertIn("reason=no_tty", self.results()[-1])

    def pty(self):
        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        return master, slave, os.ttyname(slave)

    def test_sudo_rejects_bad_terminals(self):
        _, slave, path = self.pty()
        dev = self.tmp / "dev"
        (dev / "pts").mkdir(parents=True)
        (dev / "pts" / "7").write_text("not a terminal")
        (dev / "pts" / "8").symlink_to(path)
        cases = {"regular file": (str(dev / "pts" / "7"), USER, str(dev)),
                 "symlink": (str(dev / "pts" / "8"), USER, str(dev)),
                 "someone else's": (path, "root", "/dev"),
                 "not under /dev/pts": (str(dev / "x"), USER, str(dev)),
                 "dot-dot": ("/dev/pts/../pts/" + path.rsplit("/", 1)[1], USER, "/dev"),
                 "newline": (path + "\n", USER, "/dev"),
                 "display": (":0", USER, "/dev")}
        for name, (tty, user, dev_root) in cases.items():
            with self.subTest(name), mock.patch.object(tp, "DEV", dev_root):
                env = dict(self.env, PAM_SERVICE="sudo", PAM_TTY=tty, PAM_USER=user)
                self.assertEqual(self.run_main(env=env), 1)
                self.assertEqual(self.out, "")
                self.assertEqual(self.scard.calls, [])

    def test_other_services_work_without_a_terminal(self):
        env = dict(self.env, PAM_TTY=":0")
        self.card.on_ga[2] = "touch"
        self.assertEqual(self.run_main("--timeout", "5", env=env), 0)
        self.assertEqual(self.out, PROMPT + "\n")

    def test_sudo_with_terminal_offers_enter(self):
        _, slave, path = self.pty()
        self.card.on_ga[2] = "touch"
        env = dict(self.env, PAM_SERVICE="sudo", PAM_TTY=path)
        self.assertEqual(self.run_main("--timeout", "5", env=env), 0)
        self.assertEqual(self.out, SUDO_PROMPT + "\n")
        self.assertTrue(termios.tcgetattr(slave)[3] & termios.ECHO)

    def test_enter_ends_the_wait_with_echo_off_meanwhile(self):
        master, slave, path = self.pty()
        echo_during = []

        def press_enter():
            time.sleep(0.3)
            echo_during.append(termios.tcgetattr(slave)[3] & termios.ECHO)
            self.pressed = time.monotonic()
            os.write(master, b"\n")
        threading.Thread(target=press_enter, daemon=True).start()
        env = dict(self.env, PAM_SERVICE="sudo", PAM_TTY=path)
        self.assertEqual(self.run_main("--timeout", "10", env=env), 1)
        self.assertLess(time.monotonic() - self.pressed, 0.2)
        self.assertEqual(echo_during, [0])
        self.assertTrue(termios.tcgetattr(slave)[3] & termios.ECHO)
        self.assertIn("reason=enter", self.results()[-1])
        self.assert_card_left_clean()

    def test_typing_without_enter_keeps_waiting(self):
        master, slave, path = self.pty()
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ICANON  # single keys reach the verifier
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        os.write(master, b"abc")
        env = dict(self.env, PAM_SERVICE="sudo", PAM_TTY=path)
        self.assertEqual(self.run_main("--timeout", "0.4", env=env), 1)
        self.assertIn("reason=timeout", self.results()[-1])


class KeyStoreTest(Fixture):
    def setUp(self):
        super().setUp()
        self.path = self.enrol_keys(self.card.key)

    def assert_config_error(self):
        self.assertEqual(self.run_main("--timeout", "0.3"), 4)
        self.assertEqual(self.scard.calls, [])
        self.assertIn("reason=key_file", self.results()[-1])

    def test_good_file_is_accepted(self):
        self.card.on_ga[2] = "touch"
        self.assertEqual(self.run_main("--timeout", "5"), 0)

    def test_file_modes(self):
        for mode in (0o664, 0o646, 0o666, 0o744, 0o755, 0o4644):
            with self.subTest(mode=oct(mode)):
                self.path.chmod(mode)
                self.assert_config_error()

    def test_stricter_file_mode_is_fine(self):
        self.path.chmod(0o600)
        self.card.on_ga[2] = "touch"
        self.assertEqual(self.run_main("--timeout", "5"), 0)

    def test_writable_directories(self):
        for directory in (self.keys, self.keys.parent, self.root / "etc", self.root):
            for mode in (0o775, 0o757, 0o1777):
                with self.subTest(directory=directory.name, mode=oct(mode)):
                    directory.chmod(mode)
                    self.assert_config_error()
                    directory.chmod(0o755)

    def test_owner(self):
        with mock.patch.object(tp, "TRUSTED_UID", os.getuid() + 1):
            self.assert_config_error()

    @staticmethod
    def owned_by_someone_else(real, which):
        def stat_call(target, *args, **kwargs):
            info = real(target, *args, **kwargs)
            if not which(target, info):
                return info
            fields = list(info[:10])
            fields[4] = info.st_uid + 1
            return os.stat_result(fields)
        return stat_call

    def test_file_owner_alone(self):
        fstat = self.owned_by_someone_else(os.fstat, lambda fd, info: stat.S_ISREG(info.st_mode))
        with mock.patch.object(tp.os, "fstat", fstat):
            self.assert_config_error()

    def test_directory_owner_alone(self):
        for directory in (self.keys, self.keys.parent, self.root):
            with self.subTest(directory=directory.name):
                lstat = self.owned_by_someone_else(
                    os.lstat, lambda path, info, d=directory: Path(path) == d)
                with mock.patch.object(tp.os, "lstat", lstat):
                    self.assert_config_error()

    def test_symlinked_file(self):
        real = self.keys / "real.pem"
        self.path.rename(real)
        self.path.symlink_to(real)
        self.assert_config_error()

    def test_symlinked_directory(self):
        moved = self.keys.parent / "real-keys"
        self.keys.rename(moved)
        self.keys.symlink_to(moved)
        self.assert_config_error()

    def test_not_a_regular_file(self):
        self.path.unlink()
        self.path.mkdir(mode=0o755)
        self.assert_config_error()

    def test_contents(self):
        small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        curve = ec.generate_private_key(ec.SECP256R1())
        for name, data in (("empty", b""), ("text", b"hello\n"),
                           ("rsa-1024", spki_pem(small)), ("ec", spki_pem(curve)),
                           ("good then broken", spki_pem(self.card.key)
                            + b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"),
                           ("too large", spki_pem(self.card.key) + b"#" * 70000)):
            with self.subTest(name):
                self.path.write_bytes(data)
                self.assert_config_error()


class ArgumentsTest(Fixture):
    def test_bad_arguments_are_a_config_error(self):
        for argv in (["--timeout", "-1"], ["--timeout", "abc"], ["--timeout", "nan"],
                     ["--timeout", "99999"], ["--frobnicate"], ["--timeout"]):
            with self.subTest(argv=argv):
                self.assertEqual(self.run_main(*argv), 4)
                self.assertEqual(self.out, "")

    def test_help_is_never_a_success_under_pam(self):
        self.assertEqual(self.run_main("--help"), 1)
        self.assertIn("--timeout", self.out)
        self.assertEqual(self.run_main("--help", env={}), 0)


class SourceTest(unittest.TestCase):
    source = (LINUX / "tinytouch_piv.py").read_text()

    def test_no_bare_exit(self):
        self.assertIsNone(re.search(r"\bexit\(\s*\)", self.source))
        self.assertIsNone(re.search(r"^\s*(sys\.)?exit\((?!main\()", self.source, re.M))

    def test_isolation_comes_first(self):
        first_import = self.source.index("\nimport argparse")
        self.assertLess(self.source.index("ENV = isolate()"), first_import)
        body = self.source[self.source.index("def isolate"):]
        self.assertLess(body.index("os.dup2(null, 2)"), body.index("os.environ.clear()"))
        self.assertEqual(self.source.splitlines()[0], "#!/usr/bin/python3 -I")

    def test_only_allowed_imports(self):
        modules = set(re.findall(r"^\s*(?:from|import) ([a-z_]+)", self.source, re.M))
        allowed = {"argparse", "contextlib", "ctypes", "datetime", "errno", "hashlib",
                   "importlib", "math", "os", "pwd", "re", "select", "signal", "stat", "sys",
                   "syslog", "tempfile", "termios", "time", "pathlib", "cryptography",
                   "smartcard"}
        self.assertLessEqual(modules, allowed)

    def test_checks_cover_status_check(self):
        import tinytouch
        self.assertLessEqual(set(tinytouch.CHECKS), set(tp.DEVICE_CHECKS))


class LogTest(Fixture):
    def test_no_secrets_and_no_control_characters(self):
        self.enrol_keys(self.card.key)
        self.card.touch()
        self.card.on_ga[3] = "touch"
        env = dict(self.env, PAM_SERVICE="evil\x1b[2J\nservice=" + "x" * 200,
                   PAM_TTY="\r\x07", PAM_USER=USER)
        self.assertEqual(self.run_main("--timeout", "5", env=env), 0)
        text = "\n".join(self.results())
        secrets = [s.hex() for s in self.card.signatures + self.card.blocks]
        secrets += [b.hex()[-64:] for b in self.card.blocks]  # SHA-256(nonce)
        der = spki_der(self.card.key)
        secrets += [der.hex(), der.hex()[16:48], spki_pem(self.card.key).decode().split("\n")[2]]
        for secret in secrets:
            self.assertNotIn(secret, text)
            self.assertNotIn(secret.upper(), text)
        for _, line in self.logs:
            self.assertTrue(line.isprintable(), line)
            for value in re.findall(r"=(\S*)", line):
                self.assertLessEqual(len(value), 64 + 12)
        service = re.search(r"service=(\S+)", self.results()[-1])[1]
        self.assertLessEqual(len(service), 64)
        self.assertNotIn("\x1b", service)
        self.assertIn(f"key={tp.key_id(der)[:16]} ", self.results()[-1])
        self.assertEqual(self.logs[-1][0], tp.syslog.LOG_NOTICE)


# A verifier process with the fakes patched in, for what needs a real process: fd 2, signals,
# the watchdog and parent death. The configuration comes as JSON in argv[1].
DRIVER = r"""
import json, os, sys
config = json.loads(sys.argv[1])
sys.path[:0] = config["path"]
import tinytouch_piv as tp
env = tp.isolate()
import fake_pcsc
from pathlib import Path
from cryptography.hazmat.primitives import serialization
key = serialization.load_pem_private_key(Path(config["key"]).read_bytes(), None)
scard = fake_pcsc.FakeScard({"tinyTouch 00 00": fake_pcsc.FakeCard(key)})
card = scard.card
for name in ("SYS_ROOT", "KEY_DIR", "TRUSTED_ROOT", "PROC_CGROUP", "SESSIONS_DIR"):
    setattr(tp, name, Path(config[name]))
tp.TRUSTED_UID, tp.POLL, tp.scard = os.getuid(), 0.02, scard
tp.write_log = lambda priority, line: None
event = config.get("event")


def leak(card):
    os.write(2, b"leak\n")
    sys.stderr.write("leak\n")
    sys.stderr.flush()
    raise RuntimeError("injected")


if event == "stderr":
    card.on_ga[1] = leak
elif event == "hang":
    card.on_ga[1] = lambda c: setattr(scard, "hang_at", scard.transmits + 1)
    transmit = scard.SCardTransmit

    def marked(handle, protocol, apdu):
        if scard.transmits + 1 == scard.hang_at and config.get("marker"):
            Path(config["marker"]).write_text("stuck")  # the test waits for this
        return transmit(handle, protocol, apdu)
    scard.SCardTransmit = marked
sys.exit(tp.main(config["argv"], env, guarded=True))
"""


class ProcessTest(Fixture):
    def setUp(self):
        super().setUp()
        self.enrol_keys(self.card.key)
        self.key_file = self.tmp / "card.key"
        self.key_file.write_bytes(self.card.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))

    def driver(self, argv, event=None, env=None):
        self.marker = self.tmp / "stuck"
        config = {"path": [str(TESTS), str(LINUX)], "key": str(self.key_file), "argv": argv,
                  "event": event, "marker": str(self.marker), "SYS_ROOT": str(self.sys),
                  "KEY_DIR": str(self.keys), "TRUSTED_ROOT": str(self.root),
                  "PROC_CGROUP": str(self.cgroup), "SESSIONS_DIR": str(self.sessions)}
        return [sys.executable, "-c", DRIVER, json.dumps(config)], child_env(env or self.env)

    def test_nothing_reaches_stderr(self):
        command, env = self.driver(["--timeout", "5"], event="stderr")
        done = subprocess.run(command, env=env, capture_output=True, timeout=30)
        self.assertEqual(done.returncode, 70)
        self.assertEqual(done.stderr, b"")
        self.assertEqual(done.stdout, b"")

    def test_prompt_is_flushed_while_waiting(self):
        command, env = self.driver(["--timeout", "3"])
        process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        line = process.stdout.readline()
        still_running = process.poll() is None
        process.wait(timeout=15)
        self.assertEqual(line.decode(), PROMPT + "\n")
        self.assertTrue(still_running)
        self.assertEqual(process.returncode, 1)
        self.assertEqual(process.stderr.read(), b"")
        process.stdout.close()
        process.stderr.close()

    def test_watchdog_fires_even_if_sigalrm_was_ignored_and_blocked(self):
        def inherit_ignored_alarm():
            signal.signal(signal.SIGALRM, signal.SIG_IGN)
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
        command, env = self.driver(["--timeout", "1"], event="hang")
        started = time.monotonic()
        done = subprocess.run(command, env=env, capture_output=True, timeout=30,
                              preexec_fn=inherit_ignored_alarm)
        self.assertEqual(done.returncode, -signal.SIGALRM)
        self.assertLess(time.monotonic() - started, 8.5)
        self.assertEqual(done.stderr, b"")

    def test_parent_death_ends_the_verifier_and_restores_echo(self):
        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        command, env = self.driver(["--timeout", "60"], event="hang",
                                   env=dict(self.env, PAM_SERVICE="sudo",
                                            PAM_TTY=os.ttyname(slave)))
        middle = subprocess.Popen(
            [sys.executable, "-c", "import subprocess, sys\n"
             "p = subprocess.Popen(sys.argv[1:], stdout=subprocess.DEVNULL)\n"
             "print(p.pid, flush=True)\np.wait()\n"] + command,
            env=env, stdout=subprocess.PIPE)
        child = int(middle.stdout.readline())
        middle.stdout.close()
        deadline = time.monotonic() + 10
        while not self.marker.exists():  # stuck inside the smart-card call, echo off
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.02)
        time.sleep(0.1)
        self.assertFalse(termios.tcgetattr(slave)[3] & termios.ECHO)
        middle.kill()
        middle.wait()
        deadline = time.monotonic() + 3
        while True:
            try:
                state = Path(f"/proc/{child}/stat").read_text().rsplit(")", 1)[1].split()[0]
            except FileNotFoundError:
                break
            if state == "Z":
                break
            self.assertLess(time.monotonic(), deadline, "the verifier outlived its parent")
            time.sleep(0.02)
        self.assertTrue(termios.tcgetattr(slave)[3] & termios.ECHO)

    def test_installed_program_isolates_itself(self):
        script = LINUX / "tinytouch_piv.py"
        for env, code in (({}, 0), ({"PAM_TYPE": "auth"}, 1)):
            done = subprocess.run([sys.executable, "-I", str(script), "--help"],
                                  env=child_env(env),
                                  capture_output=True, timeout=30)
            self.assertEqual(done.returncode, code)
            self.assertIn(b"--timeout", done.stdout)
            self.assertEqual(done.stderr, b"")


class EnrolTest(Fixture):
    def setUp(self):
        super().setUp()
        self.state = new_state(piv="ready", fingers={1: 4})
        self.device = FakeDevice(self.state)
        self.addCleanup(self.device.vanish)
        self.installed = self.root / "usr" / "local" / "lib" / "tinytouch" / "tinytouch-verify"
        self.installed.parent.mkdir(parents=True)
        for directory in (self.root / "usr", self.root / "usr" / "local",
                          self.root / "usr" / "local" / "lib", self.installed.parent):
            directory.chmod(0o755)
        self.installed.write_bytes((LINUX / "tinytouch_piv.py").read_bytes())
        self.installed.chmod(0o755)
        self.serial_copy = self.installed.parent / "tinytouch_serial.py"
        self.serial_copy.write_bytes((LINUX / "tinytouch_serial.py").read_bytes())
        self.serial_copy.chmod(0o644)
        patches = [mock.patch.object(tp, "geteuid", lambda: 0),
                   mock.patch.object(tp, "SELF", self.installed),
                   mock.patch.object(tp, "ENROL_TIMEOUT", 5.0),
                   mock.patch.object(ts, "find_ports", lambda: list(self.state.paths)),
                   mock.patch.object(ts.fcntl, "ioctl", ModemLines())]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.path = self.keys / f"{USER}.pem"

    def pair(self, *extra):
        return self.run_main("--enrol", "--user", USER, *extra, env={})

    def test_pairs_after_a_fresh_touch(self):
        self.card.on_ga[2] = "touch"
        self.assertEqual(self.pair(), 0)
        self.assertEqual(self.path.read_bytes(), spki_pem(self.card.key))
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o644)
        self.assertIn(f"SHA256:{tp.key_id(spki_der(self.card.key))}", self.out)
        self.assertIn(f"wrote {self.path}", self.out)
        self.assertEqual(self.card.results, [0x6982, 0x9000, 0x6982, 0x9000])
        self.assertEqual(self.state.commands, ["STATUS"])
        self.assertEqual([p.name for p in self.keys.iterdir()], [self.path.name])
        self.assert_card_left_clean()
        # The verifier accepts what pairing wrote.
        self.card.on_ga[6] = "touch"
        self.assertEqual(self.run_main("--timeout", "5"), 0)

    def test_creates_missing_directories(self):
        subprocess.run(["rm", "-rf", str(self.keys.parent)])
        self.card.on_ga[2] = "touch"
        self.assertEqual(self.pair(), 0)
        for directory in (self.keys, self.keys.parent):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)

    def test_backs_up_the_previous_file(self):
        old = self.enrol_keys(shared_key(1))
        before = old.read_bytes()
        self.card.on_ga[2] = "touch"
        self.assertEqual(self.pair(), 0)
        self.assertEqual(self.path.read_bytes(), spki_pem(self.card.key))
        backups = list((self.root / "var" / "lib" / "tinytouch" / "backup").glob("*/keys/*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), before)
        self.assertRegex(backups[0].parent.parent.name, r"^\d{8}T\d{6}Z$")
        self.assertEqual(stat.S_IMODE(backups[0].parent.parent.stat().st_mode), 0o700)
        self.assertIn(str(backups[0]), self.out)

    def test_failed_write_leaves_the_old_file(self):
        old = self.enrol_keys(shared_key(1))
        before = old.read_bytes()
        self.card.on_ga[2] = "touch"
        real, calls = os.replace, []

        def failing(src, dst):
            calls.append(dst)
            if len(calls) == 2:  # the backup's rename succeeds, the key file's fails
                raise OSError("disk full")
            return real(src, dst)
        with mock.patch.object(tp.os, "replace", failing):
            self.assertEqual(self.pair(), 70)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.keys.iterdir()), [self.path.name])

    def test_refuses_a_key_paired_with_another_user(self):
        self.enrol_keys(self.card.key, user="someone_else")
        self.assertEqual(self.pair(), 4)
        self.assertIn("someone_else", self.out)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.card.ga_count, 0)

    def test_already_paired_is_left_alone(self):
        self.enrol_keys(self.card.key)
        before = self.path.stat().st_mtime_ns
        self.assertEqual(self.pair(), 0)
        self.assertIn("already paired", self.out)
        self.assertEqual(self.path.stat().st_mtime_ns, before)
        self.assertEqual(self.card.ga_count, 0)

    def assert_refused(self, text, code=4):
        self.assertEqual(self.pair(), code)
        self.assertIn(text, self.out)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.scard.transmits, 0)

    def test_refuses_with_no_finger(self):
        self.state.fingers = {}
        self.assert_refused("no finger is enrolled")

    def test_refuses_when_status_check_fails(self):
        self.state.values["piv_auto_type"] = 1
        self.assert_refused("piv_auto_type=1")

    def test_refuses_without_keys(self):
        self.state.piv = "unconfigured"
        self.assert_refused("piv=unconfigured")

    def test_refuses_a_busy_serial_port(self):
        holder = self.proc / "4242" / "fd"
        holder.mkdir(parents=True)
        (holder / "5").symlink_to(self.device.path)
        self.assert_refused("in use by another program")
        self.assertEqual(self.state.commands, [])

    def test_refuses_without_a_serial_port(self):
        self.state.paths[:] = []
        self.assert_refused("no tinyTouch serial port")

    def test_refuses_without_root(self):
        with mock.patch.object(tp, "geteuid", lambda: 1000):
            self.assert_refused("as root")
        self.assertEqual(self.state.commands, [])

    def test_refuses_to_run_from_a_checkout(self):
        with mock.patch.object(tp, "SELF", LINUX / "tinytouch_piv.py"):
            self.assert_refused("installed, root-owned")
        self.installed.chmod(0o775)
        self.assert_refused("installed, root-owned")
        self.assertEqual(self.state.commands, [])

    def test_refuses_an_untrusted_serial_module(self):
        self.serial_copy.chmod(0o664)
        self.assert_refused("tinytouch_serial.py")
        self.serial_copy.chmod(0o644)
        fstat = KeyStoreTest.owned_by_someone_else(
            os.fstat, lambda fd, info: os.readlink(f"/proc/self/fd/{fd}") == str(self.serial_copy))
        with mock.patch.object(tp.os, "fstat", fstat):
            self.assert_refused("tinytouch_serial.py")
        self.serial_copy.unlink()
        self.assert_refused("tinytouch_serial.py")
        self.assertEqual(self.state.commands, [])

    def test_serial_module_writes_no_bytecode(self):
        # Imported afresh from beside the installed verifier, as under `python3 -I`.
        path = [p for p in sys.path if Path(p).resolve() != LINUX]
        with mock.patch.dict(sys.modules), mock.patch.object(sys, "path", path), \
                mock.patch.object(sys, "dont_write_bytecode", False):
            sys.modules.pop("tinytouch_serial", None)
            module = tp.serial_module()
            self.assertTrue(sys.dont_write_bytecode)
        self.assertEqual(Path(module.__file__), self.serial_copy)
        self.assertFalse((self.installed.parent / "__pycache__").exists())

    def test_refuses_bad_user_names(self):
        for name in ("../x", "no_such_user_tinytouch", ""):
            with self.subTest(name=name):
                self.assertEqual(self.run_main("--enrol", "--user", name, env={}), 4)
        self.assertEqual(self.run_main("--enrol", env={}), 4)
        self.assertEqual(self.state.commands, [])

    def test_no_touch_writes_nothing(self):
        self.assertEqual(self.pair("--timeout", "0.3"), 1)
        self.assertIn("no touch", self.out)
        self.assertFalse(self.path.exists())

    def test_stale_touch_does_not_pair(self):
        self.card.touch()
        self.assertEqual(self.pair("--timeout", "0.3"), 1)
        self.assertIn("earlier touch was ignored", self.out)
        self.assertFalse(self.path.exists())

    def test_card_without_certificate(self):
        self.card.cert = b""
        self.assertEqual(self.pair(), 3)
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
