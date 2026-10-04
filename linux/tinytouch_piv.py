#!/usr/bin/python3 -I
"""tinyTouch fingerprint verifier for PAM, and pairing of a user with the attached tinyTouch.

`pam_exec ... stdout seteuid` runs this once per authentication. It asks the tinyTouch's PIV card
to sign a fresh challenge with its 9A key, which the firmware allows only for a few seconds after
an enrolled finger touches the sensor, checks the signature against the public key enrolled for
the user, and checks that the card's window was a touch's (see await_touch). Exit 0 means
verified; any other exit sends PAM on to the password.

    tinytouch-verify [--timeout S]          from PAM (S=10 for sudo; 0 waits until PAM goes)
    tinytouch-verify --enrol --user NAME    as root: pair the attached tinyTouch with NAME

Installed root-owned as /usr/local/lib/tinytouch/tinytouch-verify; see linux/README.md.
"""

import os


def isolate() -> dict:
    """The first thing the program does. With `stdout`, pam_exec joins stderr to the pipe it
    shows the user, so fd 2 goes to /dev/null before anything can write a traceback there. The
    environment is emptied before any library reads it (libpcsclite honours PCSCLITE_CSOCK_NAME,
    OpenSSL OPENSSL_CONF); the PAM_* values come back for the verifier's own use."""
    try:
        null = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null, 2)
        os.close(null)
    except OSError:
        try:
            os.close(2)  # no /dev/null: then nowhere, rather than the user's terminal
        except OSError:
            pass
    env = dict(os.environ)
    os.environ.clear()
    return env


if __name__ == "__main__":
    ENV = isolate()

import argparse  # noqa: E402
import contextlib  # noqa: E402
import ctypes  # noqa: E402
import datetime  # noqa: E402
import errno  # noqa: E402
import hashlib  # noqa: E402
import importlib  # noqa: E402
import math  # noqa: E402
import pwd  # noqa: E402
import re  # noqa: E402
import select  # noqa: E402
import signal  # noqa: E402
import stat  # noqa: E402
import sys  # noqa: E402
import syslog  # noqa: E402
import tempfile  # noqa: E402
import termios  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402

# Exit codes; pam_exec turns every one but 0 into a failure, and the PAM line is `sufficient`.
OK, PASSWORD, ABSENT, NO_KEY, CONFIG, BAD_SIGNATURE, INTERNAL = 0, 1, 2, 3, 4, 5, 70
RESULTS = {OK: "ok", PASSWORD: "password", ABSENT: "absent", NO_KEY: "no_key",
           CONFIG: "config", BAD_SIGNATURE: "bad_signature", INTERNAL: "internal"}

# Where the verifier looks; tests point these at temporary copies.
SYS_ROOT = Path("/sys")
KEY_DIR = Path("/etc/tinytouch/keys")
BACKUP_ROOT = Path("/var/lib/tinytouch/backup")
PROC = Path("/proc")
PROC_CGROUP = Path("/proc/self/cgroup")
SESSIONS_DIR = Path("/run/systemd/sessions")
DEV = "/dev"
SELF = Path(__file__)
TRUSTED_ROOT = Path("/")  # every directory from here down to a trusted file is checked
TRUSTED_UID = 0
POLL = 0.25  # seconds between challenges: about four a second within the firmware's 10 s window
READER_WAIT = 2.0  # pcscd runs --auto-exit, so it often starts cold for this call
ENROL_TIMEOUT = 30.0
scard = None  # smartcard.scard, imported once the environment is empty
geteuid = os.geteuid
getppid = os.getppid

VENDOR, PRODUCT, NAME = "303a", "4001", "tinyTouch"  # as tinytouch_serial.find_ports
USER_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
# What `tinytouch.py status --check` requires, plus keys: pairing refuses a device without them.
DEVICE_CHECKS = (("protocol", "6"), ("mode", "piv"), ("piv_auto_type", "0"), ("piv_touch", "off"),
                 ("ota", "idle"), ("sensor", "ready"), ("piv", "ready"))

PIV_AID = bytes.fromhex("a00000030800001000")  # piv.c PIV_AID
SELECT = bytes([0x00, 0xA4, 0x04, 0x00, len(PIV_AID)]) + PIV_AID
GET_CERT_9A = bytes.fromhex("00cb3fff055c035fc10500")  # GET DATA 5FC105, Le 256
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
SIGNED_HEADER = bytes.fromhex("7c82010482820100")  # 7C{82 <256-byte signature>}
REFUSED, DONE = 0x6982, 0x9000  # no touch window open; success
SLOT_9A, SLOT_9D = 0x9A, 0x9D  # PIV authentication; key management (piv.c, both RSA-2048)
MAX_GET_RESPONSE = 8
CERT_LIMIT, SIGNED_LIMIT = 4096, 512
KEY_FILE_LIMIT = 65536
PEM_BLOCK = re.compile(rb"-----BEGIN PUBLIC KEY-----[A-Za-z0-9+/=\s]+-----END PUBLIC KEY-----")
PR_SET_PDEATHSIG = 1


class ConfigError(Exception):
    """A key file or directory that is not safely root-owned, or a key that is not RSA-2048."""


class ParentGone(Exception):
    """PAM's process went away (Ctrl-C reaches sudo but not this setsid'd child)."""


class Retry(Exception):
    """The card was reset or another client holds it: try again at the next tick."""


class Gone(Exception):
    """pcscd or the card went away."""


class Malformed(Exception):
    """The card answered outside what this firmware sends."""


# Logging: authpriv, one key=value line per run. Never the nonce, the signature or a key.

def write_log(priority: int, line: str) -> None:
    syslog.openlog("tinytouch-verify", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
    syslog.syslog(priority, line)


def clean(value: object) -> str:
    """A PAM-supplied value made safe for one key=value log line: no control characters, no
    separators, 64 characters at most."""
    text = "".join(c for c in str(value) if c.isprintable())
    return text.replace(" ", "_").replace("=", "_")[:64]


def log(priority: int, **fields: object) -> None:
    try:
        write_log(priority, " ".join(f"{k}={clean(v)}" for k, v in fields.items()))
    except Exception:
        pass  # a broken logger must not change the result


# Process guards.

def on_term(signum, frame) -> None:
    raise ParentGone()


def guard(timeout: float) -> None:
    """Make sure the verifier can never hold PAM up. Signal dispositions and masks survive
    exec, so SIGALRM is reset and unblocked before the kernel-enforced `alarm`, which kills a
    verifier stuck inside the smart-card library. PAM's death delivers SIGTERM, which unwinds
    through the `finally` blocks (so the tty's echo comes back); an orphan would otherwise take
    the user's next touch."""
    parent = getppid()
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, on_term)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGALRM, signal.SIGTERM})
    if timeout:
        signal.alarm(math.ceil(timeout) + 5)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0)
    if getppid() != parent or parent == 1:  # it died before prctl took effect
        raise ParentGone()


# Who is asking, and from where.

def pam_user(env: dict) -> pwd.struct_passwd | None:
    name = env.get("PAM_USER", "")
    if not USER_NAME.fullmatch(name):
        return None
    try:
        return pwd.getpwnam(name)
    except KeyError:
        return None


def remote_session() -> bool:
    """Whether this runs in a remote (SSH) login session, as pam_fprintd refuses: a touch at the
    desk must not approve someone else's request. Unreadable state counts as remote."""
    try:
        cgroup = PROC_CGROUP.read_text()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    # Best effort: an SSH login has its own logind session, but a multiplexer (tmux, screen)
    # started at the desk and attached over SSH runs in the desk's session and counts as local.
    found = re.search(r"/session-([A-Za-z0-9]+)\.scope(?:/|$)", cgroup, re.M)
    if not found:
        return False  # not in a login session (polkit's helper runs as a service)
    try:
        return "REMOTE=1" in (SESSIONS_DIR / found[1]).read_text().splitlines()
    except OSError:
        return True


def open_tty(path: str, user: pwd.struct_passwd) -> int | None:
    """The user's terminal, for Enter-to-skip. pam_exec runs the verifier under setsid(), so
    there is no controlling tty; PAM_TTY is opened by path, and only a real terminal the user
    owns is accepted."""
    if not re.fullmatch(re.escape(DEV) + r"/(pts/[0-9]+|tty[0-9]+)", path):
        return None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK | os.O_NOFOLLOW
                     | os.O_CLOEXEC)
    except OSError:
        return None
    info = os.fstat(fd)
    if stat.S_ISCHR(info.st_mode) and info.st_uid == user.pw_uid and os.isatty(fd):
        return fd
    os.close(fd)
    return None


@contextlib.contextmanager
def echo_off(fd: int | None):
    """No echo while waiting: a password typed early is not shown. Restored on every exit."""
    saved = None
    if fd is not None:
        try:
            saved = termios.tcgetattr(fd)
            quiet = list(saved)
            quiet[3] &= ~termios.ECHO
            termios.tcsetattr(fd, termios.TCSANOW, quiet)
        except termios.error:
            saved = None
    try:
        yield
    finally:
        if saved is not None:
            try:
                now = termios.tcgetattr(fd)
                now[3] |= saved[3] & termios.ECHO
                termios.tcsetattr(fd, termios.TCSANOW, now)
            except termios.error:
                pass


# The key store: /etc/tinytouch/keys/<user>.pem, root-owned all the way down.

def read_trusted(path: Path, allowed_mode: int = 0o644) -> bytes | None:
    """The file's bytes if it and every directory above it (from TRUSTED_ROOT) are owned by
    TRUSTED_UID, not symlinks and not group- or world-writable; None if it does not exist."""
    try:
        parts = path.relative_to(TRUSTED_ROOT).parts
    except ValueError:
        raise ConfigError(f"{path} is outside {TRUSTED_ROOT}") from None
    directory = TRUSTED_ROOT
    for part in (None,) + parts[:-1]:
        directory = directory / part if part else directory
        try:
            info = os.lstat(directory)
        except FileNotFoundError:
            return None
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != TRUSTED_UID
                or info.st_mode & 0o022):
            raise ConfigError(f"{directory} is not a root-owned, unwritable directory")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError:
        raise ConfigError(f"cannot open {path} safely") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != TRUSTED_UID
                or stat.S_IMODE(info.st_mode) & ~allowed_mode or info.st_size > KEY_FILE_LIMIT):
            raise ConfigError(f"{path} is not a root-owned file of mode {allowed_mode:o}")
        data = b""
        while chunk := os.read(fd, KEY_FILE_LIMIT + 1 - len(data)):
            data += chunk
            if len(data) > KEY_FILE_LIMIT:
                raise ConfigError(f"{path} is too large")
        return data
    finally:
        os.close(fd)


def parse_keys(data: bytes) -> list[rsa.RSAPublicKey]:
    """One or more SPKI PEM blocks, each an RSA-2048 key (the firmware's only key type)."""
    keys = []
    for block in PEM_BLOCK.findall(data):
        try:
            key = serialization.load_pem_public_key(block)
        except ValueError:
            raise ConfigError("a key block does not parse") from None
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048:
            raise ConfigError("a key is not RSA-2048")
        keys.append(key)
    if not keys:
        raise ConfigError("the key file holds no public key")
    return keys


def load_keys(user: str) -> list[rsa.RSAPublicKey] | None:
    data = read_trusted(KEY_DIR / f"{user}.pem")
    return None if data is None else parse_keys(data)


def spki(key: rsa.RSAPublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def key_id(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


# Presence and the card.

def device_present() -> bool:
    """A tinyTouch on the USB bus, from sysfs (about a millisecond; no pcscd involved)."""
    try:
        devices = list((SYS_ROOT / "bus" / "usb" / "devices").iterdir())
    except OSError:
        return False
    for device in devices:
        try:
            ids = [(device / name).read_text().strip()
                   for name in ("idVendor", "idProduct", "manufacturer", "product")]
        except OSError:
            continue
        if ids == [VENDOR, PRODUCT, NAME, NAME]:
            return True
    return False


def load_scard():
    global scard
    if scard is None:
        from smartcard import scard as module  # after isolate(): the environment is empty
        scard = module
    return scard


def tlv(buf: bytes, off: int) -> tuple[int, bytes, int]:
    """One BER-TLV with a one-byte tag: (tag, value, offset after it)."""
    if off + 2 > len(buf):
        raise Malformed("truncated TLV")
    tag, first, off = buf[off], buf[off + 1], off + 2
    if first in (0x81, 0x82):
        count = first & 0x7F
        if off + count > len(buf):
            raise Malformed("truncated length")
        length, off = int.from_bytes(buf[off:off + count], "big"), off + count
    elif first < 0x80:
        length = first
    else:
        raise Malformed("bad length")
    if off + length > len(buf):
        raise Malformed("truncated value")
    return tag, buf[off:off + length], off + length


def certificate_from_object(obj: bytes) -> bytes:
    """The DER certificate in the 9A object, 53{70 <cert>, 71 01 00, FE 00} (handle_get_data)."""
    tag, inner, end = tlv(obj, 0)
    if tag != 0x53 or end != len(obj):
        raise Malformed("not a certificate object")
    items, off = [], 0
    while off < len(inner):
        tag, value, off = tlv(inner, off)
        items.append((tag, value))
    if [t for t, _ in items] != [0x70, 0x71, 0xFE] or items[1][1] != b"\x00":
        raise Malformed("unexpected certificate object")
    return items[0][1]


def challenge_block(nonce: bytes) -> bytes:
    """PKCS#1 v1.5 signature padding of SHA-256(nonce), exactly 256 bytes: the card applies the
    raw private-key operation to it (mbedtls_rsa_private)."""
    digest_info = SHA256_DIGEST_INFO + hashlib.sha256(nonce).digest()
    return b"\x00\x01" + b"\xff" * (256 - 3 - len(digest_info)) + b"\x00" + digest_info


class Card:
    """One tinyTouch reader in shared mode. Every exchange runs inside a transaction: the
    firmware's chaining and GET RESPONSE buffers are global, so no other client may interleave."""

    def __init__(self, context: int, reader: str):
        self.reader = reader
        self.handle = None
        self.reset = False
        protocols = scard.SCARD_PROTOCOL_T0 | scard.SCARD_PROTOCOL_T1
        rc, handle, self.protocol = scard.SCardConnect(context, reader,
                                                       scard.SCARD_SHARE_SHARED, protocols)
        self.check(rc)
        self.handle = handle

    def check(self, rc: int) -> None:
        if rc == scard.SCARD_S_SUCCESS:
            return
        if rc == scard.SCARD_W_RESET_CARD:  # pcscd resets the card when a holder dies
            self.reset = True
            raise Retry()
        if rc == scard.SCARD_E_SHARING_VIOLATION:
            raise Retry()
        raise Gone(rc)

    def close(self) -> None:
        if self.handle is not None:
            try:
                scard.SCardDisconnect(self.handle, scard.SCARD_LEAVE_CARD)
            except Exception:
                pass
            self.handle = None

    @contextlib.contextmanager
    def transaction(self):
        if self.reset:
            self.reset = False
            rc, self.protocol = scard.SCardReconnect(
                self.handle, scard.SCARD_SHARE_SHARED,
                scard.SCARD_PROTOCOL_T0 | scard.SCARD_PROTOCOL_T1, scard.SCARD_LEAVE_CARD)
            self.check(rc)
        self.check(scard.SCardBeginTransaction(self.handle))
        try:
            yield
        finally:
            scard.SCardEndTransaction(self.handle, scard.SCARD_LEAVE_CARD)

    def transmit(self, apdu: bytes) -> tuple[bytes, int]:
        rc, reply = scard.SCardTransmit(self.handle, self.protocol, list(apdu))
        self.check(rc)
        reply = bytes(reply)
        if len(reply) < 2:
            raise Malformed("no status word")
        return reply[:-2], int.from_bytes(reply[-2:], "big")

    def command(self, apdu: bytes, limit: int) -> tuple[bytes, int]:
        """One command and the rest of its reply through 61xx/GET RESPONSE
        (respond_maybe_chunked), with the rounds and the length bounded."""
        data, sw = self.transmit(apdu)
        rounds = 0
        while sw >> 8 == 0x61:
            if rounds == MAX_GET_RESPONSE:
                raise Malformed("reply never ends")
            rounds += 1
            more, sw = self.transmit(bytes([0x00, 0xC0, 0x00, 0x00, sw & 0xFF]))
            data += more
            if len(data) > limit:
                raise Malformed("reply too long")
        if len(data) > limit:
            raise Malformed("reply too long")
        return data, sw

    def select(self) -> None:
        if self.command(SELECT, 256)[1] != DONE:
            raise Malformed("no PIV applet")

    def read_key(self) -> bytes | None:
        """The 9A certificate's public key (SPKI DER) if it is RSA-2048, else None."""
        data, sw = self.command(GET_CERT_9A, CERT_LIMIT)
        if sw != DONE:
            return None
        try:
            key = x509.load_der_x509_certificate(certificate_from_object(data)).public_key()
        except (Malformed, ValueError, UnsupportedAlgorithm):
            return None
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048:
            return None
        return spki(key)

    def sign(self, block: bytes, slot: int = SLOT_9A) -> tuple[int, bytes]:
        """GENERAL AUTHENTICATE on `slot` (9A, or 9D: also RSA-2048) with 7C{82 00, 81 <block>},
        in CLA 10 chained parts of at most 255 bytes, the last with CLA 00 and Le 00."""
        inner = b"\x82\x00\x81\x82\x01\x00" + block
        payload = b"\x7c\x82" + len(inner).to_bytes(2, "big") + inner
        while len(payload) > 255:
            _, sw = self.transmit(bytes([0x10, 0x87, 0x07, slot, 255]) + payload[:255])
            if sw != DONE:
                raise Malformed("chaining refused")
            payload = payload[255:]
        data, sw = self.command(bytes([0x00, 0x87, 0x07, slot, len(payload)]) + payload + b"\x00",
                                SIGNED_LIMIT)
        return sw, data


def open_context(deadline: float) -> int | None:
    while True:
        rc, context = scard.SCardEstablishContext(scard.SCARD_SCOPE_SYSTEM)
        if rc == scard.SCARD_S_SUCCESS:
            return context
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.1)


def tinytouch_readers(context: int) -> list[str]:
    rc, names = scard.SCardListReaders(context, [])
    return [n for n in names if n.startswith(NAME)] if rc == scard.SCARD_S_SUCCESS else []


def wait_for_readers(context: int, seconds: float) -> None:
    """Sleep until pcscd reports a reader change, `seconds` at most."""
    began = time.monotonic()
    scard.SCardGetStatusChange(context, max(1, int(seconds * 1000)),
                               [("\\\\?PnP?\\Notification", scard.SCARD_STATE_UNAWARE)])
    if time.monotonic() - began < 0.01:  # returned at once: don't spin
        time.sleep(min(seconds, 0.05))


def find_card(context: int, keys: dict[bytes, rsa.RSAPublicKey],
              deadline: float) -> tuple[Card, bytes] | int:
    """The tinyTouch whose 9A key is enrolled; NO_KEY if every tinyTouch reader holds another
    key, ABSENT if none answered before `deadline`."""
    mismatched: set[str] = set()
    while True:
        names = tinytouch_readers(context)
        for name in names:
            if name in mismatched:
                continue
            try:
                card = Card(context, name)
            except (Retry, Gone):
                continue  # the card may not be powered yet
            try:
                with card.transaction():
                    card.select()
                    der = card.read_key()
            except (Retry, Gone):
                card.close()
                continue
            except Malformed:
                der = None
            if der in keys:
                return card, der
            card.close()
            mismatched.add(name)
        if names and mismatched.issuperset(names):
            return NO_KEY
        left = deadline - time.monotonic()
        if left <= 0:
            return NO_KEY if mismatched else ABSENT
        wait_for_readers(context, min(left, 0.25))


def challenge(card: Card, check_kind: bool) -> tuple[bytes, int, bytes, str | None]:
    """One attempt: (nonce, status, reply, window kind or None). With `check_kind`, a signature
    is followed in the same transaction by two probes, each on a fresh random block, that tell
    the window that signed it (piv.c handle_general_authenticate):

    - a touch window (piv_note_user_presence) grants two operations, one per slot: the 9A probe
      is refused without consuming anything (slot_already_used), and the 9D probe signs;
    - the serial AUTH window (piv_note_configuration_presence) allows repeated slots: with an
      operation left it signs the 9A probe; with none (the main challenge took the last) the
      window is closed and refuses the 9D probe too.

    Returns "touch" (9A refused, 9D signed with a well-formed reply, whose value is discarded),
    "auth" (9A probe signed) or "other" (anything else)."""
    nonce = os.urandom(32)
    kind = None
    with card.transaction():
        card.select()
        sw, reply = card.sign(challenge_block(nonce))
        if sw == DONE and check_kind:
            again, _ = card.sign(challenge_block(os.urandom(32)))
            if again == DONE:
                kind = "auth"
            elif again != REFUSED:
                kind = "other"
            else:
                other, other_reply = card.sign(challenge_block(os.urandom(32)), SLOT_9D)
                well_formed = len(other_reply) == 264 and other_reply.startswith(SIGNED_HEADER)
                kind = "touch" if other == DONE and well_formed else "other"
    return nonce, sw, reply, kind


class Waiter:
    """The pause between challenges, about four a second, ended early by Enter on the tty, the
    deadline, or PAM going away."""

    def __init__(self, tty: int | None, deadline: float, parent: int):
        self.tty, self.deadline, self.parent = tty, deadline, parent

    def pause(self) -> str | None:
        if getppid() != self.parent:
            raise ParentGone()
        left = self.deadline - time.monotonic()
        if left <= 0:
            return "timeout"
        until = time.monotonic() + min(POLL, left)
        while (step := until - time.monotonic()) > 0:
            if self.tty is None:
                time.sleep(step)
            elif select.select([self.tty], [], [], step)[0]:
                try:
                    typed = os.read(self.tty, 4096)
                except BlockingIOError:
                    typed = b"."
                except OSError:
                    typed = b""
                # A whole line in canonical mode, single keys otherwise; end of file or a
                # hang-up also ends the wait.
                if not typed or b"\n" in typed or b"\r" in typed:
                    return "enter"
        if getppid() != self.parent:
            raise ParentGone()
        return None


def await_touch(card: Card, key: rsa.RSAPublicKey, waiter: Waiter, prompt: str,
                note=lambda event: None) -> tuple[int, str]:
    """The fresh-touch rule. The first full challenge goes out before the prompt: a signature
    then comes from a window opened earlier (a stray touch, the CLI's AUTH) and is discarded.
    The probe must be full-size, because the firmware spends the window before it checks the
    length. A signature counts only after the card has refused at least once in this run (a
    Retry is not a refusal), and only from a touch window (challenge): an AUTH window with an
    operation left is rejected as `auth_window`, one with none left, or a touch window whose 9D
    operation someone else already used, as `window_kind`."""
    refused = prompted = False
    while True:
        try:
            nonce, sw, reply, kind = challenge(card, check_kind=refused)
        except Retry:
            sw = None
        if sw == REFUSED:
            refused = True
        elif sw == DONE and not refused:
            note("stale_window")
            if not prompted:
                print("An earlier touch was ignored; touch again.", flush=True)
        elif sw == DONE:
            if len(reply) != 264 or not reply.startswith(SIGNED_HEADER):
                return BAD_SIGNATURE, "malformed"
            try:
                key.verify(reply[8:], nonce, padding.PKCS1v15(), hashes.SHA256())
            except InvalidSignature:
                return BAD_SIGNATURE, "bad_signature"
            if kind == "auth":
                return BAD_SIGNATURE, "auth_window"
            if kind != "touch":
                return BAD_SIGNATURE, "window_kind"
            return OK, "verified"
        elif sw is not None:
            return BAD_SIGNATURE, "malformed"
        if not prompted:
            print(prompt, flush=True)  # a whole line, flushed: pam_exec reads lines
            prompted = True
        event = waiter.pause()
        if event:
            return PASSWORD, event


# Verification under PAM.

def service_label(service: str) -> str:
    return service if re.fullmatch(r"[A-Za-z0-9._-]{1,32}", service) else "this request"


def verify(timeout: float, env: dict) -> int:
    start = time.monotonic()
    parent = getppid()
    service, tty_path = env.get("PAM_SERVICE", ""), env.get("PAM_TTY", "")
    fields = {"service": service, "user": env.get("PAM_USER", ""), "tty": tty_path}

    def finish(code: int, reason: str, key: str = "") -> int:
        priority = syslog.LOG_NOTICE if code in (OK, PASSWORD, ABSENT, NO_KEY) else syslog.LOG_ERR
        log(priority, **fields, result=RESULTS[code], reason=reason, key=key[:16],
            ms=int((time.monotonic() - start) * 1000))
        return code

    if env.get("PAM_TYPE") != "auth":
        return finish(CONFIG, "pam_type")
    user = pam_user(env)
    if user is None:
        return finish(NO_KEY, "user")
    if remote_session():
        return finish(PASSWORD, "remote")
    tty = open_tty(tty_path, user) if tty_path else None
    try:
        # sudo without a terminal (sudo -n, a script) must not wait and take the next touch.
        if service == "sudo" and tty is None:
            return finish(PASSWORD, "no_tty")
        try:
            keys = load_keys(user.pw_name)
        except ConfigError:
            return finish(CONFIG, "key_file")
        if keys is None:
            return finish(NO_KEY, "not_enrolled")
        if not device_present():
            return finish(ABSENT, "sysfs")
        load_scard()
        context = open_context(start + READER_WAIT)
        if context is None:
            return finish(ABSENT, "pcscd")
        card = None
        try:
            enrolled = {spki(k): k for k in keys}
            found = find_card(context, enrolled, start + READER_WAIT)
            if isinstance(found, int):
                return finish(found, "reader" if found == ABSENT else "other_key")
            card, der = found
            label = service_label(service)
            prompt = (f"Touch tinyTouch to approve {label}, or press Enter for password."
                      if tty is not None else f"Touch tinyTouch to approve {label}.")
            deadline = start + timeout if timeout else math.inf
            noted = set()

            def note(event: str) -> None:
                if event not in noted:
                    noted.add(event)
                    log(syslog.LOG_WARNING, **fields, event=event, key=key_id(der)[:16])

            with echo_off(tty):
                try:
                    code, reason = await_touch(card, enrolled[der],
                                               Waiter(tty, deadline, parent), prompt, note)
                except Malformed:
                    code, reason = BAD_SIGNATURE, "malformed"
                except Gone:
                    code, reason = ABSENT, "removed"
            return finish(code, reason, key_id(der))
        finally:
            if card is not None:
                card.close()
            scard.SCardReleaseContext(context)
    finally:
        if tty is not None:
            os.close(tty)


# Pairing (enrolment), run as root from the installed copy.

def say(text: str) -> None:
    print(text, flush=True)


def port_in_use(path: str) -> bool:
    """Whether another process holds the serial node open. Root passes TIOCEXCL, so the
    exclusive open that protects the CLI cannot be relied on here."""
    target = os.path.realpath(path)
    for fd_dir in PROC.glob("[0-9]*/fd"):
        if fd_dir.parent.name == str(os.getpid()):
            continue
        try:
            links = list(fd_dir.iterdir())
        except OSError:
            continue
        for link in links:
            try:
                if os.readlink(link) == target:
                    return True
            except OSError:
                continue
    return False


def serial_module():
    """tinytouch_serial, installed beside this file (python -I leaves its directory off the
    path; the directory and the file were checked to be root-owned before this runs). Root
    writes no bytecode cache beside it."""
    sys.dont_write_bytecode = True
    try:
        return importlib.import_module("tinytouch_serial")
    except ImportError:
        sys.path.insert(0, str(SELF.parent))
        return importlib.import_module("tinytouch_serial")


def device_problems() -> list[str]:
    """Why the attached device may not be paired: the `status --check` conditions, keys, and at
    least one enrolled finger (with none, the serial AUTH grants windows without a touch)."""
    try:
        trusted = read_trusted(SELF.parent / "tinytouch_serial.py", 0o644) is not None
    except ConfigError:
        trusted = False
    if not trusted:
        return ["tinytouch_serial.py is not installed beside the verifier as a root-owned "
                "file of mode 644 (repeat the install lines in linux/README.md)"]
    try:
        ts = serial_module()
    except ImportError:
        return ["tinytouch_serial.py is not installed beside the verifier"]
    ports = ts.find_ports()
    if len(ports) != 1:
        return ["no tinyTouch serial port found" if not ports
                else "several tinyTouch units are attached; leave only one"]
    if port_in_use(ports[0]):
        return [f"{ports[0]} is in use by another program; close it and try again"]
    try:
        with ts.Port(ports[0]) as port:
            status = port.status()
    except OSError as exc:
        if exc.errno == errno.EBUSY:
            return [f"{ports[0]} is in use by another program; close it and try again"]
        return [f"cannot open {ports[0]}: {exc.strerror}"]
    except ts.DeviceError as exc:
        return [f"cannot read the device's status: {exc}"]
    problems = [f"{key}={status.get(key, '-')} (needs {want})"
                for key, want in DEVICE_CHECKS if status.get(key) != want]
    if not status.get("fingerprints", "0").isdecimal() or int(status["fingerprints"]) < 1:
        problems.append("no finger is enrolled (enroll one first: without one the device "
                        "grants access without a touch)")
    return problems


def enrolled_owners(der: bytes) -> set[str]:
    """Users whose key file already holds this key."""
    owners = set()
    for path in sorted(KEY_DIR.glob("*.pem")) if KEY_DIR.is_dir() else []:
        try:
            blocks = PEM_BLOCK.findall(path.read_bytes())
        except OSError:
            continue
        for block in blocks:
            try:
                if spki(serialization.load_pem_public_key(block)) == der:
                    owners.add(path.stem)
            except (ValueError, AttributeError):
                continue
    return owners


def make_dirs(path: Path, mode: int) -> None:
    missing = []
    while not path.exists():
        missing.append(path)
        path = path.parent
    for directory in reversed(missing):
        directory.mkdir()
        os.chmod(directory, mode)


def write_atomically(path: Path, data: bytes, mode: int) -> None:
    """Temp file in the same directory, fsync, rename over, fsync the directory."""
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temp, path)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        os.unlink(temp)
        raise
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def back_up(path: Path) -> Path:
    """A copy of `path` under BACKUP_ROOT/<UTC timestamp>/keys/ (root 0700)."""
    make_dirs(BACKUP_ROOT, 0o700)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for suffix in [""] + [f"-{n}" for n in range(1, 100)]:
        folder = BACKUP_ROOT / (stamp + suffix)
        try:
            folder.mkdir(mode=0o700)
        except FileExistsError:
            continue
        os.chmod(folder, 0o700)
        (folder / "keys").mkdir(mode=0o700)
        copy = folder / "keys" / path.name
        write_atomically(copy, path.read_bytes(), 0o600)
        return copy
    raise OSError(errno.EEXIST, "no free backup folder")


def enrol(name: str | None, timeout: float) -> int:
    if geteuid() != 0:
        say("error: pairing writes /etc/tinytouch/keys; run it as root")
        return CONFIG
    if not name or not USER_NAME.fullmatch(name):
        say("error: --user needs a valid user name")
        return CONFIG
    try:
        pwd.getpwnam(name)
    except KeyError:
        say(f"error: there is no user {name}")
        return CONFIG
    try:
        trusted = read_trusted(SELF, 0o755) is not None
    except ConfigError:
        trusted = False
    if not trusted:
        say("error: pairing runs only from the installed, root-owned verifier "
            "(/usr/local/lib/tinytouch/tinytouch-verify), never from a checkout")
        return CONFIG
    problems = device_problems()
    if problems:
        say("error: the tinyTouch is not ready to pair:")
        for problem in problems:
            say(f"  {problem}")
        return CONFIG
    start = time.monotonic()
    load_scard()
    context = open_context(start + READER_WAIT)
    if context is None:
        say("error: pcscd does not answer")
        return ABSENT
    card = None
    try:
        names = []
        while not names and time.monotonic() < start + READER_WAIT:
            names = tinytouch_readers(context)
            if not names:
                wait_for_readers(context, 0.25)
        if len(names) != 1:
            say("error: " + ("no tinyTouch smart card found (is pcscd set up?)" if not names
                             else "several tinyTouch smart cards; leave only one attached"))
            return ABSENT
        card = Card(context, names[0])
        with card.transaction():
            card.select()
            der = card.read_key()
        if der is None:
            say("error: the card has no RSA-2048 key in slot 9A (run piv-create first)")
            return NO_KEY
        say(f"tinyTouch key: SHA256:{key_id(der)}")
        owners = enrolled_owners(der)
        if owners - {name}:
            say(f"error: this key is already paired with {', '.join(sorted(owners - {name}))}; "
                "one key belongs to one user")
            return CONFIG
        if name in owners:
            say(f"This tinyTouch is already paired with {name}; nothing changed.")
            return OK
        key = serialization.load_der_public_key(der)
        waiter = Waiter(None, start + timeout if timeout else math.inf, getppid())
        code, reason = await_touch(card, key, waiter, f"Touch tinyTouch to pair it with {name}.")
        if code != OK:
            say({"timeout": "error: no touch in time; nothing changed"}.get(
                reason, f"error: the touch did not verify ({reason}); nothing changed"))
            return code
        path = KEY_DIR / f"{name}.pem"
        make_dirs(KEY_DIR, 0o755)
        if path.exists():
            say(f"Backed up the previous key file to {back_up(path)}")
        write_atomically(path, key.public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo),
                         0o644)
        try:
            if not load_keys(name):
                raise ConfigError("unreadable")
        except ConfigError as exc:
            say(f"error: wrote {path}, but the verifier will not accept it: {exc}")
            return CONFIG
        log(syslog.LOG_NOTICE, user=name, result="paired", key=key_id(der)[:16])
        say(f"Paired: wrote {path}")
        return OK
    except Malformed:
        say("error: the card gave an unexpected answer")
        return BAD_SIGNATURE
    except (Gone, Retry):
        say("error: the smart card went away or is busy; try again")
        return ABSENT
    finally:
        if card is not None:
            card.close()
        scard.SCardReleaseContext(context)


# Entry points.

class Usage(Exception):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message: str):  # argparse would print to stderr and exit 2 ("absent")
        raise Usage(message)


def timeout_value(text: str) -> float:
    value = float(text)
    if not 0 <= value <= 3600 or math.isnan(value):
        raise ValueError(text)
    return value


def parser() -> Parser:
    top = Parser(prog="tinytouch-verify", add_help=False,
                 description=__doc__.splitlines()[0])
    top.add_argument("--timeout", type=timeout_value, default=None,
                     help="seconds to wait for a touch (default 10; 0: until PAM goes away)")
    top.add_argument("--enrol", action="store_true",
                     help="as root: pair the attached tinyTouch with --user")
    top.add_argument("--user", help="the user to pair (with --enrol)")
    top.add_argument("--help", action="store_true", help="show this help")
    return top


def main(argv: list[str], env: dict, *, guarded: bool = False) -> int:
    """Run once; `guarded` adds the watchdog and parent-death signal (the installed program)."""
    fields = {"service": env.get("PAM_SERVICE", ""), "user": env.get("PAM_USER", ""),
              "tty": env.get("PAM_TTY", "")}
    try:
        try:
            args = parser().parse_args(argv)
        except Usage:
            log(syslog.LOG_ERR, result=RESULTS[CONFIG], reason="arguments")
            return CONFIG
        if args.help:
            print(parser().format_help(), end="", flush=True)
            return PASSWORD if "PAM_TYPE" in env else OK  # never a success under PAM
        if args.enrol:
            timeout = ENROL_TIMEOUT if args.timeout is None else args.timeout
            if guarded:
                guard(timeout + 55 if timeout else 0)  # the serial STATUS may take 20 s
            return enrol(args.user, timeout)
        timeout = 10.0 if args.timeout is None else args.timeout
        if guarded:
            guard(timeout)
        return verify(timeout, env)
    except ParentGone:
        log(syslog.LOG_NOTICE, **fields, result=RESULTS[PASSWORD], reason="parent_gone")
        return PASSWORD
    except BaseException as exc:
        log(syslog.LOG_ERR, **fields, result=RESULTS[INTERNAL], error=type(exc).__name__)
        return INTERNAL


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:], ENV, guarded=True))
