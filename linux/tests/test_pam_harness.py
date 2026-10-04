"""The ctypes PAM harness against throwaway PAM stacks in a temporary directory (no root, no
/etc): pam_permit, pam_deny, pam_echo for the conversation, and pam_exec as the verifier's PAM
line uses it."""

import ctypes
import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

HARNESS = Path(__file__).resolve().parents[1] / "tools" / "pam_harness.py"
SERVICE = "tinytouch-harness-test"


def module_exists(name: str) -> bool:
    return any(Path(d, name).exists() for d in ("/usr/lib/security", "/lib/security",
                                                "/usr/lib64/security",
                                                "/usr/lib/x86_64-linux-gnu/security"))


@unittest.skipUnless(module_exists("pam_permit.so"), "Linux-PAM modules not found")
class HarnessTest(unittest.TestCase):
    def setUp(self):
        self.confdir = Path(tempfile.mkdtemp(prefix="tinytouch-pam-"))
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.confdir)])

    def run_stack(self, text: str, *extra):
        (self.confdir / SERVICE).write_text(text)
        return subprocess.run([sys.executable, str(HARNESS), SERVICE, "--confdir",
                               str(self.confdir), *extra],
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              timeout=30)

    def test_symbols_load(self):
        sys.path.insert(0, str(HARNESS.parent))
        try:
            import pam_harness
        finally:
            sys.path.remove(str(HARNESS.parent))
        pam, _ = pam_harness.load()
        for name in ("pam_start_confdir", "pam_authenticate", "pam_end", "pam_set_item"):
            self.assertTrue(hasattr(pam, name))

    def test_conversation_error_is_reported_and_freed(self):
        sys.path.insert(0, str(HARNESS.parent))
        try:
            import pam_harness as ph
        finally:
            sys.path.remove(str(HARNESS.parent))
        _, real = ph.load()
        freed = []

        class Libc:
            calloc, strdup = real.calloc, real.strdup

            @staticmethod
            def free(pointer):
                freed.append(pointer)
                real.free(pointer)
        callback = ph.converse(Libc())
        prompts = [ph.Message(ph.PAM_PROMPT_ECHO_OFF, b"Password: "),
                   ph.Message(ph.PAM_PROMPT_ECHO_ON, b"Name: ")]
        messages = (ctypes.POINTER(ph.Message) * 2)(*(ctypes.pointer(m) for m in prompts))
        responses = ctypes.POINTER(ph.Response)()
        err = io.StringIO()
        with mock.patch.object(ph.getpass, "getpass", return_value="secret"), \
                mock.patch.object(ph, "input", side_effect=RuntimeError("broken"), create=True), \
                redirect_stderr(err):
            result = callback(2, ctypes.cast(messages, ctypes.POINTER(ctypes.POINTER(ph.Message))),
                              ctypes.pointer(responses), None)
        self.assertEqual(result, ph.PAM_CONV_ERR)
        self.assertIn("RuntimeError", err.getvalue())
        self.assertEqual(len(freed), 2)  # the first answer's copy, then the array
        self.assertFalse(responses)  # nothing handed to libpam

    def test_permit(self):
        done = self.run_stack("auth required pam_permit.so\n")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("Success", done.stdout)

    def test_deny(self):
        done = self.run_stack("auth required pam_deny.so\n")
        self.assertEqual(done.returncode, 7)  # PAM_AUTH_ERR

    @unittest.skipUnless(module_exists("pam_echo.so"), "pam_echo not found")
    def test_messages_are_shown(self):
        done = self.run_stack("auth optional pam_echo.so hello from pam\n"
                              "auth required pam_permit.so\n")
        self.assertEqual(done.returncode, 0)
        self.assertIn("hello from pam", done.stdout)

    @unittest.skipUnless(module_exists("pam_exec.so"), "pam_exec not found")
    def test_pam_exec_stdout_and_sufficient(self):
        script = self.confdir / "helper"
        for code, expected in ((0, 0), (1, 7)):
            with self.subTest(code=code):
                script.write_text(f"#!/bin/sh\necho \"PAM_TTY=$PAM_TTY PAM_TYPE=$PAM_TYPE\"\n"
                                  f"exit {code}\n")
                script.chmod(0o755)
                done = self.run_stack(f"auth sufficient pam_exec.so quiet quiet_log stdout "
                                      f"{script}\nauth required pam_deny.so\n",
                                      "--tty", "/dev/pts/999")
                self.assertEqual(done.returncode, expected, done.stdout)
                self.assertIn("PAM_TTY=/dev/pts/999 PAM_TYPE=auth", done.stdout)

    def test_missing_service_file(self):
        done = subprocess.run([sys.executable, str(HARNESS), "absent-service", "--confdir",
                               str(self.confdir)], capture_output=True, text=True, timeout=30)
        self.assertEqual(done.returncode, 2)
        self.assertIn("has no file", done.stderr)


if __name__ == "__main__":
    unittest.main()
