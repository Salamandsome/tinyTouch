"""A pseudo-terminal stand-in for the serial console of firmware 0.1.34.

Reply lines follow firmware/tiny_touch_unified/main/config_console.c; enrollment events follow
fingerprint.c fingerprint_enroll_finger; OTA follows firmware_update.c.
"""

import _thread
import base64
import hashlib
import os
import select
import threading
import time
from types import SimpleNamespace

SETTINGS = {"TYPE_DELAY": "typing_delay_ms", "SUBMIT_ENTER": "submit_enter",
            "COOLDOWN": "touch_cooldown_ms", "LED_IDLE_COLOR": "led_idle_color",
            "LED_SUCCESS_COLOR": "led_success_color", "LED_FAILURE_COLOR": "led_failure_color",
            "LED_IDLE_END_COLOR": "led_idle_end_color", "LED_IDLE_EFFECT": "led_idle_effect",
            "LED_IDLE_CYCLES": "led_idle_cycles", "LED_FEEDBACK_MS": "led_feedback_ms",
            "PIV_AUTO_TYPE": "piv_auto_type", "PIV_DELAY": "piv_delay_ms"}


def new_state(**changes):
    state = SimpleNamespace(
        fingers={}, piv="unconfigured", mode="piv", sensor="ready", ota="idle", led="on",
        protocol="6", firmware="0.1.34", capacity=40, pending=0,
        values={"typing_delay_ms": 1, "submit_enter": 1, "touch_cooldown_ms": 800,
                "led_idle_color": 1, "led_success_color": 2, "led_failure_color": 4,
                "led_idle_end_color": 1, "led_idle_effect": 3, "led_idle_cycles": 0,
                "led_feedback_ms": 350, "piv_auto_type": 0, "piv_delay_ms": 50},
        piv_touch="off", authorized=False, commands=[], paths=[],
        auth_reply="OK AUTH",
        # Enrollment: stop after this many views and wait (None: run to the end); with
        # interrupt, raise KeyboardInterrupt in the main thread as Ctrl-C would.
        enroll_stall_after=None, enroll_interrupt=False,
        create="ok",  # ok | slow (1 s) | lost (keys made, leaves without replying) | fail
        # Writes that report success without taking effect, for the read-back checks.
        enroll_views=4, delete_ignored=False, set_ignored=False,
        staged_reply="OK OTA STAGED power_cycle=required", uploaded=bytearray(), ota_token=None,
        silent=set())  # commands that never get a reply
    for key, value in changes.items():
        setattr(state, key, value)
    return state


class FakeDevice(threading.Thread):
    def __init__(self, state=None):
        super().__init__(daemon=True)
        self.state = state or new_state()
        # Holding the slave open keeps reads on the master from failing with EIO before the
        # port under test opens it.
        self.master, self.slave = os.openpty()
        self.path = os.ttyname(self.slave)
        self.alive = True
        self.state.paths[:] = [self.path]
        self.start()

    def reply(self, line):
        os.write(self.master, (line + "\r\n").encode())

    def run(self):
        buffer = b""
        while self.alive:
            # Polling lets another thread's vanish() take effect; a blocked read would keep the
            # master open.
            if not select.select([self.master], [], [], 0.05)[0]:
                continue
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                break
            buffer += chunk
            while self.alive and b"\n" in buffer:
                raw, buffer = buffer.split(b"\n", 1)
                self.handle(raw.decode().strip())
        if self.master >= 0:
            self.close()

    def close(self):
        os.close(self.master)
        os.close(self.slave)
        self.master = self.slave = -1

    def vanish(self):
        """Drop off the bus, as during USB re-enumeration; the port under test reads EOF."""
        self.alive = False
        self.state.paths[:] = []
        if threading.current_thread() is self:
            self.close()
        else:
            self.join()

    def reenumerate(self, gap=0.3):
        self.vanish()
        time.sleep(gap)
        return FakeDevice(self.state)

    def views(self):
        return sum(self.state.fingers.values())

    def status_line(self):
        s, v = self.state, self.state.values
        return ("OK STATUS protocol=%s firmware=%s build=test mode=%s piv=%s sensor=%s "
                "fingerprints=%d hosts=0 ota=%s led=%s led_only_auth=1 finger_groups=1 "
                "config_values=1 custom_config=1 typing_delay_ms=%d submit_enter=%d "
                "touch_cooldown_ms=%d led_idle_color=%d led_success_color=%d "
                "led_failure_color=%d led_idle_end_color=%d led_idle_effect=%d led_idle_cycles=%d "
                "led_feedback_ms=%d piv_auto_type=%d led_control=manual led_sync=synced "
                "piv_touch=%s piv_touch_active=off piv_visible=yes piv_delay_ms=%d" % (
                    s.protocol, s.firmware, s.mode, s.piv, s.sensor, self.views(), s.ota, s.led, v["typing_delay_ms"],
                    v["submit_enter"], v["touch_cooldown_ms"], v["led_idle_color"],
                    v["led_success_color"], v["led_failure_color"], v["led_idle_end_color"],
                    v["led_idle_effect"], v["led_idle_cycles"], v["led_feedback_ms"],
                    v["piv_auto_type"], s.piv_touch, v["piv_delay_ms"]))

    def locked(self):
        if not self.state.authorized:
            self.reply("ERR LOCKED run=AUTH")
        return not self.state.authorized

    def handle(self, line):
        s = self.state
        s.commands.append(line)
        words = line.split()
        if line in s.silent:
            return
        if line == "STATUS":
            self.reply(self.status_line())
        elif line == "LOGS":
            self.reply("LOG ms=1200 event=touch_detected value=1")
            self.reply("LOG ms=1500 event=finger_no_match value=0")
            self.reply("OK LOGS")
        elif line == "AUTH":
            if self.views() == 0:
                s.authorized = True
                self.reply("OK AUTH first_setup=1")
                return
            self.reply("EVENT TOUCH")
            s.authorized = s.auth_reply.startswith("OK AUTH")
            self.reply(s.auth_reply)
        elif line == "FINGER LIST":
            groups = ",".join(f"{n}:{c}" for n, c in sorted(s.fingers.items())) or "none"
            self.reply(f"OK FINGER LIST groups={groups} available={10 - len(s.fingers)} "
                       f"capacity={s.capacity} pending={s.pending}")
        elif words[:2] == ["FINGER", "ENROLL_GROUP"]:
            if not self.locked():
                self.enroll(int(words[2]), words[3:] == ["REPLACE"])
        elif words[:2] == ["FINGER", "DELETE_GROUP"]:
            if not self.locked():
                if not s.delete_ignored:
                    s.fingers.pop(int(words[2]), None)
                self.reply("OK FINGER")
        elif words[0] == "SET" and len(words) == 3 and words[1] != "MODE":
            if self.locked():
                return
            if s.set_ignored:
                pass
            elif words[1] == "LED":
                s.led = {"0": "off", "1": "on", "2": "only-auth"}[words[2]]
            elif words[1] == "PIV_TOUCH":
                s.piv_touch = "on" if words[2] == "1" else "off"
            else:
                s.values[SETTINGS[words[1]]] = int(words[2])
            self.reply("OK SET")
        elif line == "PIV CREATE":
            if not self.locked():
                self.create()
        elif words[0] == "OTA":
            self.ota(words[1:])
        else:
            self.reply("ERR COMMAND")

    def enroll(self, finger, replace):
        s = self.state
        if finger in s.fingers and not replace:
            self.reply("ERR FINGER enrollment_failed")
            return
        s.fingers.pop(finger, None)  # REPLACE deletes the old views before capturing
        for view in range(1, 5):
            if view - 1 == s.enroll_stall_after:
                if s.enroll_interrupt:
                    _thread.interrupt_main()
                return  # waits for a touch that never comes
            for event in ("LIFT", f"VIEW {view}", "TOUCH", "LIFT", "TOUCH_AGAIN"):
                self.reply(f"EVENT {event}")
        s.fingers[finger] = s.enroll_views
        self.reply("OK FINGER ENROLL_GROUP")

    def create(self):
        s = self.state
        self.reply("EVENT PIV_CREATE")
        if s.piv == "ready" or s.create == "fail":
            self.reply("ERR PIV CREATE")
            return
        time.sleep(1.0 if s.create == "slow" else 0.1)
        s.piv = "ready"
        if s.create in ("ok", "slow"):
            self.reply("OK PIV CREATE")
            time.sleep(0.3)
        self.reenumerate()

    def ota(self, words):
        s = self.state
        if words == ["ABORT"] or words == ["ABORT", s.ota_token]:
            s.ota_token = None
            self.reply("OK OTA ABORT")
        elif self.locked():
            return
        elif words[0] == "BEGIN":
            s.ota_token, s.ota_expected = words[1], (int(words[2]), words[3])
            s.uploaded.clear()
            self.reply("OK OTA BEGIN next=0")
        elif words[0] == "WRITE" and words[1] == s.ota_token and int(words[2]) == len(s.uploaded):
            s.uploaded += base64.b64decode(words[3])
            self.reply(f"OK OTA WRITE next={len(s.uploaded)}")
        elif words[0] == "COMMIT" and words[1] == s.ota_token:
            size, digest = s.ota_expected
            ok = len(s.uploaded) == size and hashlib.sha256(s.uploaded).hexdigest() == digest
            self.reply(s.staged_reply if ok else "ERR OTA COMMIT")
        else:
            self.reply("ERR OTA")
