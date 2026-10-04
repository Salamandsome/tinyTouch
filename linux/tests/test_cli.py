"""The tinytouch command line against a fake firmware 0.1.34 console on a pseudo-terminal."""

import importlib
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tinytouch as tt  # noqa: E402
import tinytouch_serial as ts  # noqa: E402
from fake_device import FakeDevice, new_state  # noqa: E402
from test_serial import ModemLines  # noqa: E402

ONE = {1: 4}
TWO = {1: 4, 2: 4}


class CliTest(unittest.TestCase):
    def run_cli(self, *argv, state=None, answers=(), device=True):
        state = state or new_state()
        if device:
            FakeDevice(state)
        answers = list(answers)
        self.prompts = []

        def ask(prompt):
            self.prompts.append(prompt)
            if not answers:
                raise EOFError
            return answers.pop(0)

        out, err = io.StringIO(), io.StringIO()
        self.modem = ModemLines()
        with mock.patch.object(tt, "ask", ask), \
                mock.patch.object(tt, "find_ports", lambda: list(state.paths)), \
                mock.patch.object(ts.fcntl, "ioctl", self.modem), \
                redirect_stdout(out), redirect_stderr(err):
            code = tt.main(list(argv))
        self.state, self.out, self.err = state, out.getvalue(), err.getvalue()
        return code

    def sent(self, prefix):
        return [c for c in self.state.commands if c.startswith(prefix)]


class ParserTest(CliTest):
    def test_only_the_safe_commands_exist(self):
        self.assertEqual(set(tt.parser()._subparsers._group_actions[0].choices),
                         {"status", "logs", "fingers", "enroll", "delete", "piv-create",
                          "config", "update", "pair"})

    def test_no_device(self):
        self.assertEqual(self.run_cli("status", device=False), 1)
        self.assertIn("no tinyTouch", self.err)
        self.assertNotIn("Traceback", self.err)

    def test_port_must_be_a_tinytouch(self):
        state = new_state()
        device = FakeDevice(state)
        other = FakeDevice(new_state())  # a serial device find_ports does not list
        self.assertEqual(self.run_cli("--port", other.path, "status", state=state,
                                      device=False), 1)
        self.assertIn("not an attached tinyTouch", self.err)
        self.assertEqual(other.state.commands, [])
        self.assertEqual(self.run_cli("--port", device.path, "status", state=state,
                                      device=False), 0)
        self.assertEqual(state.commands, ["STATUS"])

    def test_other_protocol_is_refused(self):
        self.assertEqual(self.run_cli("fingers", state=new_state(protocol="5")), 1)
        self.assertIn("protocol 6", self.err)
        self.assertEqual(self.state.commands, ["STATUS"])

    def test_status_works_without_cryptography(self):
        # Only update needs python-cryptography; make it unimportable and load tinytouch afresh.
        state = new_state()
        hidden = {name: None for name in sys.modules if name.split(".")[0] == "cryptography"}
        with mock.patch.dict(sys.modules, {**hidden, "cryptography": None}):
            for name in ("tinytouch", "tinytouch_update"):
                sys.modules.pop(name, None)
            fresh = importlib.import_module("tinytouch")
            with mock.patch.object(tt, "main", fresh.main), \
                    mock.patch.object(fresh, "find_ports", lambda: list(state.paths)):
                self.assertEqual(self.run_cli("status", state=state), 0)
        self.assertIn("0.1.34", self.out)


class StatusTest(CliTest):
    def test_human(self):
        self.assertEqual(self.run_cli("status"), 0)
        self.assertIn("0.1.34", self.out)
        self.assertIn("unconfigured", self.out)

    def test_json(self):
        self.assertEqual(self.run_cli("status", "--json"), 0)
        self.assertEqual(json.loads(self.out)["piv_auto_type"], "0")

    def test_check_passes(self):
        self.assertEqual(self.run_cli("status", "--check"), 0)
        self.assertIn("All checks passed", self.out)

    def test_check_failures(self):
        state = new_state(mode="hid", sensor="offline", ota="staged", piv_touch="on")
        state.values["piv_auto_type"] = 1
        self.assertEqual(self.run_cli("status", "--check", state=state), 1)
        for name in ("mode", "sensor", "ota", "piv_touch", "piv_auto_type"):
            self.assertIn(name, self.out)
        self.assertNotIn("protocol", self.out)


class ReadTest(CliTest):
    def test_logs(self):
        self.assertEqual(self.run_cli("logs"), 0)
        self.assertIn("event=touch_detected", self.out)
        self.assertNotIn("OK LOGS", self.out)

    def test_fingers(self):
        self.assertEqual(self.run_cli("fingers", state=new_state(fingers={1: 4, 3: 2})), 0)
        self.assertIn("Finger 1: enrolled", self.out)
        self.assertIn("Finger 3: 2 of 4 views", self.out)
        self.assertNotIn("AUTH", self.state.commands)

    def test_no_fingers(self):
        self.assertEqual(self.run_cli("fingers"), 0)
        self.assertIn("No fingers enrolled", self.out)

    def test_small_sensor_offers_only_fitting_fingers(self):
        # Capacity 20 holds templates 1-19, so fingers 1-4 (finger_profiles_block_fits).
        self.assertEqual(self.run_cli("fingers", state=new_state(capacity=20)), 0)
        self.assertIn("Free: 1, 2, 3, 4\n", self.out)

    def test_fits(self):
        self.assertTrue(tt.fits(4, 20))
        self.assertFalse(tt.fits(5, 20))
        self.assertTrue(tt.fits(10, 40))  # its last view is template 0
        self.assertFalse(tt.fits(10, 39))
        self.assertFalse(tt.fits(1, 0))


class EnrollTest(CliTest):
    def test_first_free_finger_with_prompts(self):
        self.assertEqual(self.run_cli("enroll", state=new_state(fingers={1: 4})), 0)
        self.assertEqual(self.sent("FINGER ENROLL"), ["FINGER ENROLL_GROUP 2"])
        self.assertEqual(self.state.fingers, TWO)
        for text in ("Touch the sensor with an enrolled finger", "View 4 of 4", "Lift",
                     "again", "Finger 2 is enrolled"):
            self.assertIn(text, self.out)

    def test_sensor_not_ready_is_refused(self):
        self.assertEqual(self.run_cli("enroll", state=new_state(sensor="offline")), 1)
        self.assertIn("sensor is unavailable", self.err)
        self.assertEqual(self.sent("AUTH"), [])

    def test_finger_without_room_is_refused(self):
        state = new_state(capacity=20)
        self.assertEqual(self.run_cli("enroll", "--finger", "5", state=state), 1)
        self.assertIn("no room for finger 5", self.err)
        self.assertEqual(self.sent("AUTH"), [])
        state = new_state(capacity=20, fingers={n: 4 for n in range(1, 5)})
        self.assertEqual(self.run_cli("enroll", state=state), 1)
        self.assertIn("no free finger slot", self.err)
        self.assertEqual(self.sent("AUTH"), [])

    def test_incomplete_result_is_an_error(self):
        state = new_state(fingers=dict(ONE), enroll_views=3)
        self.assertEqual(self.run_cli("enroll", state=state), 1)
        self.assertIn("does not report all 4 views", self.err)
        self.assertNotIn("is enrolled", self.out)

    def test_partial_or_pending_other_finger_does_not_count(self):
        for state in (new_state(fingers={1: 4, 2: 3}), new_state(fingers=dict(TWO), pending=2)):
            self.assertEqual(self.run_cli("enroll", "--finger", "1", "--replace", state=state,
                                          answers=["replace"]), 1)
            self.assertIn("only enrolled finger", self.err)
            self.assertEqual(self.sent("AUTH"), [])

    def test_zero_fingers_says_auth_is_free(self):
        self.assertEqual(self.run_cli("enroll"), 0)
        self.assertIn("no touch", self.out)
        self.assertEqual(self.state.fingers, ONE)

    def test_occupied_finger_needs_replace(self):
        self.assertEqual(self.run_cli("enroll", "--finger", "1", state=new_state(fingers=ONE)), 1)
        self.assertIn("--replace", self.err)
        self.assertEqual(self.sent("AUTH"), [])

    def test_replace_declined(self):
        state = new_state(fingers=dict(TWO))
        self.assertEqual(self.run_cli("enroll", "--finger", "1", "--replace", state=state,
                                      answers=["no"]), 1)
        self.assertEqual(self.sent("AUTH"), [])
        self.assertEqual(self.state.fingers, TWO)

    def test_replace_confirmed(self):
        state = new_state(fingers=dict(TWO))
        self.assertEqual(self.run_cli("enroll", "--finger", "1", "--replace", state=state,
                                      answers=["replace"]), 0)
        self.assertEqual(self.sent("FINGER ENROLL"), ["FINGER ENROLL_GROUP 1 REPLACE"])

    def test_replacing_the_only_finger_needs_force(self):
        state = new_state(fingers=dict(ONE))
        self.assertEqual(self.run_cli("enroll", "--finger", "1", "--replace", state=state,
                                      answers=["replace"]), 1)
        self.assertIn("--force", self.err)
        self.assertEqual(self.sent("AUTH"), [])
        self.assertEqual(self.run_cli("enroll", "--finger", "1", "--replace", "--force",
                                      state=state, answers=["replace"]), 0)
        self.assertEqual(self.sent("FINGER ENROLL"), ["FINGER ENROLL_GROUP 1 REPLACE"])

    def test_failed_touch_stops_before_enrolling(self):
        state = new_state(fingers=dict(ONE), auth_reply="ERR AUTH no_match")
        self.assertEqual(self.run_cli("enroll", state=state), 1)
        self.assertIn("No enrolled finger matched", self.err)
        self.assertEqual(self.sent("FINGER ENROLL"), [])

    def test_interrupt_mid_enrollment_drops_dtr(self):
        state = new_state(fingers=dict(ONE), enroll_stall_after=2, enroll_interrupt=True)
        self.assertEqual(self.run_cli("enroll", state=state), 130)
        self.assertTrue(self.modem.dropped_dtr())
        self.assertIn("rolls it back", self.err)
        self.assertEqual(self.state.fingers, ONE)

    def test_timeout_mid_enrollment_drops_dtr(self):
        state = new_state(fingers=dict(ONE), enroll_stall_after=1)
        with mock.patch.object(tt, "ENROLL_TIMEOUT", 0.5):
            self.assertEqual(self.run_cli("enroll", state=state), 1)
        self.assertTrue(self.modem.dropped_dtr())
        self.assertIn("rolls it back", self.err)
        self.assertNotIn("Traceback", self.err)


class DeleteTest(CliTest):
    def test_delete_confirmed(self):
        self.assertEqual(self.run_cli("delete", "2", state=new_state(fingers=dict(TWO)),
                                      answers=["delete"]), 0)
        self.assertEqual(self.state.fingers, ONE)
        self.assertEqual(self.sent("FINGER DELETE"), ["FINGER DELETE_GROUP 2"])

    def test_delete_declined(self):
        self.assertEqual(self.run_cli("delete", "2", state=new_state(fingers=dict(TWO)),
                                      answers=["y"]), 1)
        self.assertEqual(self.state.fingers, TWO)
        self.assertEqual(self.sent("AUTH"), [])

    def test_last_finger_needs_force(self):
        state = new_state(fingers=dict(ONE))
        self.assertEqual(self.run_cli("delete", "1", state=state, answers=["delete"]), 1)
        self.assertIn("--force", self.err)
        self.assertEqual(self.sent("AUTH"), [])
        self.assertEqual(self.run_cli("delete", "1", "--force", state=state,
                                      answers=["delete"]), 0)
        self.assertEqual(self.state.fingers, {})
        self.assertIn("without a touch", self.out)

    def test_partial_or_pending_other_finger_does_not_count(self):
        for state in (new_state(fingers={1: 4, 2: 3}), new_state(fingers=dict(TWO), pending=2)):
            self.assertEqual(self.run_cli("delete", "1", state=state, answers=["delete"]), 1)
            self.assertIn("last enrolled finger", self.err)
            self.assertEqual(self.sent("AUTH"), [])

    def test_finger_still_listed_is_an_error(self):
        state = new_state(fingers=dict(TWO), delete_ignored=True)
        self.assertEqual(self.run_cli("delete", "2", state=state, answers=["delete"]), 1)
        self.assertIn("still listed", self.err)
        self.assertNotIn("was deleted", self.out)

    def test_unknown_finger(self):
        self.assertEqual(self.run_cli("delete", "5", state=new_state(fingers=dict(ONE))), 1)
        self.assertEqual(self.sent("AUTH"), [])


class PivCreateTest(CliTest):
    def test_needs_an_enrolled_finger(self):
        self.assertEqual(self.run_cli("piv-create", answers=["create"]), 1)
        self.assertIn("enroll", self.err)
        self.assertEqual(self.sent("AUTH"), [])

    def test_partial_finger_is_not_enough(self):
        self.assertEqual(self.run_cli("piv-create", state=new_state(fingers={1: 3}),
                                      answers=["create"]), 1)
        self.assertEqual(self.sent("AUTH"), [])

    def test_sensor_not_ready_is_refused(self):
        state = new_state(fingers=dict(ONE), sensor="offline")
        self.assertEqual(self.run_cli("piv-create", state=state, answers=["create"]), 1)
        self.assertIn("sensor is unavailable", self.err)
        self.assertEqual(self.sent("AUTH"), [])

    def test_auth_without_touch_aborts(self):
        # The inventory showed a finger, yet AUTH reports none: never make keys then.
        state = new_state(fingers=dict(ONE), auth_reply="OK AUTH first_setup=1")
        self.assertEqual(self.run_cli("piv-create", state=state, answers=["create"]), 1)
        self.assertIn("no enrolled finger after all", self.err)
        self.assertEqual(self.sent("PIV"), [])
        self.assertEqual(self.state.piv, "unconfigured")

    def test_refuses_existing_keys(self):
        state = new_state(fingers=dict(ONE), piv="ready")
        self.assertEqual(self.run_cli("piv-create", state=state, answers=["create"]), 1)
        self.assertIn("factory reset", self.err)
        self.assertEqual(self.sent("AUTH"), [])

    def test_declined(self):
        self.assertEqual(self.run_cli("piv-create", state=new_state(fingers=dict(ONE)),
                                      answers=["yes"]), 1)
        self.assertEqual(self.sent("AUTH"), [])
        self.assertEqual(self.state.piv, "unconfigured")

    def test_creates_and_follows_reenumeration(self):
        state = new_state(fingers=dict(ONE))
        self.assertEqual(self.run_cli("piv-create", state=state, answers=["create"]), 0)
        self.assertEqual(self.sent("PIV"), ["PIV CREATE"])
        self.assertEqual(self.state.commands[-1], "STATUS")  # on the returned device
        self.assertIn("piv=ready", self.out)

    def test_lost_reply_resolved_by_status(self):
        state = new_state(fingers=dict(ONE), create="lost")
        self.assertEqual(self.run_cli("piv-create", state=state, answers=["create"]), 0)
        self.assertIn("reply was lost", self.out)
        self.assertIn("piv=ready", self.out)
        self.assertEqual(self.sent("PIV"), ["PIV CREATE"])

    def test_host_timeout_resolved_by_status(self):
        state = new_state(fingers=dict(ONE), create="slow")
        with mock.patch.object(tt, "CREATE_TIMEOUT", 0.3):
            self.assertEqual(self.run_cli("piv-create", state=state, answers=["create"]), 0)
        self.assertIn("reply was lost", self.out)
        self.assertIn("piv=ready", self.out)
        self.assertEqual(self.sent("PIV"), ["PIV CREATE"])

    def test_device_refusal(self):
        state = new_state(fingers=dict(ONE), create="fail")
        self.assertEqual(self.run_cli("piv-create", state=state, answers=["create"]), 1)
        self.assertIn("PIV CREATE", self.err)
        self.assertEqual(self.state.piv, "unconfigured")


class ConfigTest(CliTest):
    def test_read_all(self):
        self.assertEqual(self.run_cli("config"), 0)
        self.assertIn("piv_auto_type=off", self.out)
        self.assertIn("led_idle_effect=steady", self.out)
        self.assertNotIn("mode", self.out)

    def test_read_one(self):
        self.assertEqual(self.run_cli("config", "led"), 0)
        self.assertEqual(self.out.strip(), "led=on")
        self.assertEqual(self.sent("AUTH"), [])

    def test_set(self):
        self.assertEqual(self.run_cli("config", "led-idle-color", "purple"), 0)
        self.assertEqual(self.state.commands[1:3], ["AUTH", "SET LED_IDLE_COLOR 5"])
        self.assertEqual(self.state.values["led_idle_color"], 5)
        self.assertIn("led_idle_color=purple", self.out)

    def test_set_led_mode(self):
        self.assertEqual(self.run_cli("config", "led", "only-auth"), 0)
        self.assertEqual(self.state.led, "only-auth")

    def test_out_of_range(self):
        self.assertEqual(self.run_cli("config", "touch_cooldown_ms", "50"), 1)
        self.assertIn("100", self.err)
        self.assertEqual(self.sent("SET"), [])

    def test_read_back_mismatch_is_an_error(self):
        state = new_state(set_ignored=True)
        self.assertEqual(self.run_cli("config", "led-idle-color", "purple", state=state), 1)
        self.assertIn("reports led_idle_color=blue after the change", self.err)

    def test_mode_is_not_a_setting(self):
        self.assertEqual(self.run_cli("config", "mode", "hid"), 1)
        self.assertEqual(self.sent("SET"), [])


class UpdateTest(CliTest):
    def test_delegates(self):
        import tinytouch_update
        with mock.patch.object(tinytouch_update, "main", return_value=0) as update:
            self.assertEqual(tt.main(["--port", "/dev/null", "update", "0.1.34", "--check"]), 0)
            self.assertEqual(tt.main(["update", "0.1.33", "--allow-downgrade"]), 0)
        self.assertEqual(update.call_args_list,
                         [mock.call(["0.1.34", "--check", "--port", "/dev/null"]),
                          mock.call(["0.1.33", "--allow-downgrade"])])


class PairTest(CliTest):
    def test_execs_the_installed_verifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            verifier = Path(tmp) / "tinytouch-verify"
            verifier.write_text("")
            with mock.patch.object(tt, "VERIFIER", str(verifier)), \
                    mock.patch.object(tt.os, "execv") as execv:
                tt.main(["pair", "--user", "someone"])
        execv.assert_called_once_with(str(verifier),
                                      [str(verifier), "--enrol", "--user", "someone"])

    def test_refuses_without_the_installed_verifier(self):
        with mock.patch.object(tt, "VERIFIER", "/nonexistent/tinytouch-verify"), \
                mock.patch.object(tt.os, "execv") as execv:
            self.assertEqual(self.run_cli("pair", "--user", "someone", device=False), 1)
        self.assertIn("never from this checkout", self.err)
        execv.assert_not_called()

    def test_user_is_required(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            tt.main(["pair"])


if __name__ == "__main__":
    unittest.main()
