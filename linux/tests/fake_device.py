"""A pseudo-terminal stand-in for the serial console of firmware 0.1.34.

Reply lines follow firmware/tiny_touch_unified/main/config_console.c; enrollment events follow
fingerprint.c fingerprint_enroll_finger.
"""

import _thread
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
        return ("OK STATUS protocol=6 firmware=0.1.34 build=test mode=%s piv=%s sensor=%s "
                "fingerprints=%d hosts=0 ota=%s led=%s led_only_auth=1 finger_groups=1 "
                "config_values=1 custom_config=1 typing_delay_ms=%d submit_enter=%d "
                "touch_cooldown_ms=%d led_idle_color=%d led_success_color=%d "
                "led_failure_color=%d led_idle_end_color=%d led_idle_effect=%d led_idle_cycles=%d "
                "led_feedback_ms=%d piv_auto_type=%d led_control=manual led_sync=synced "
                "piv_touch=%s piv_touch_active=off piv_visible=yes piv_delay_ms=%d" % (
                    s.mode, s.piv, s.sensor, self.views(), s.ota, s.led, v["typing_delay_ms"],
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
            s.authorized = s.auth_reply == "OK AUTH"
            self.reply(s.auth_reply)
        elif line == "FINGER LIST":
            groups = ",".join(f"{n}:{c}" for n, c in sorted(s.fingers.items())) or "none"
            self.reply(f"OK FINGER LIST groups={groups} available={10 - len(s.fingers)} "
                       f"capacity=40 pending=0")
        elif words[:2] == ["FINGER", "ENROLL_GROUP"]:
            if not self.locked():
                self.enroll(int(words[2]), words[3:] == ["REPLACE"])
        elif words[:2] == ["FINGER", "DELETE_GROUP"]:
            if not self.locked():
                s.fingers.pop(int(words[2]), None)
                self.reply("OK FINGER")
        elif words[0] == "SET" and len(words) == 3 and words[1] != "MODE":
            if self.locked():
                return
            if words[1] == "LED":
                s.led = {"0": "off", "1": "on", "2": "only-auth"}[words[2]]
            elif words[1] == "PIV_TOUCH":
                s.piv_touch = "on" if words[2] == "1" else "off"
            else:
                s.values[SETTINGS[words[1]]] = int(words[2])
            self.reply("OK SET")
        elif line == "PIV CREATE":
            if not self.locked():
                self.create()
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
        s.fingers[finger] = 4
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
