"""A stand-in for the parts of pyscard's `smartcard.scard` the verifier uses, with a software
tinyTouch PIV card behind it.

The card follows firmware/tiny_touch_unified/main/piv.c: piv_handle_apdu_locked (CLA checks,
command chaining), handle_select, handle_get_data and respond_maybe_chunked (61xx), and
handle_general_authenticate with the user-presence window of piv_note_user_presence (a touch:
10 s, two operations, one per slot) or piv_note_configuration_presence (serial AUTH: 30 s, eight
operations, slots may repeat). Both slots hold an RSA-2048 key, as piv_init requires: 9A (`key`,
the one the certificate names) and 9D (`key_9d`).
"""

import datetime
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

PIV_AID = bytes.fromhex("a00000030800001000")
PIV_AID_VERSIONED = bytes.fromhex("a000000308000010000100")
FCI = bytes.fromhex("6111" "4f0600001000" "0100" "7907" "4f05a000000308")

_keys: list = []


def make_key():
    """A fresh RSA-2048 key; generation is slow, so tests share a small pool."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def shared_key(index: int = 0):
    while len(_keys) <= index:
        _keys.append(make_key())
    return _keys[index]


def self_signed(key) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tinyTouch PIV Authentication")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def spki_pem(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n <= 0xff:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xff])


def sw(word: int) -> bytes:
    return bytes([word >> 8, word & 0xff])


class Window:
    def __init__(self, seconds: float, operations: int, repeated: bool):
        self.until = time.monotonic() + seconds
        self.operations = operations
        self.repeated = repeated
        self.slots = 0


class FakeCard:
    def __init__(self, key=None, cert: bytes | None = None, key_9d=None):
        self.key = key or shared_key()
        self._key_9d = key_9d
        self.cert = self_signed(self.key) if cert is None else cert
        self.window: Window | None = None
        self.chain = b""
        self.chain_header = b""
        self.pending = b""
        self.ga_count = 0
        # GA number -> "touch" | "auth" (that window opens just before it runs) or a hook(card)
        self.on_ga: dict = {}
        self.tamper = None  # f(reply data) -> data, for a signed GA reply
        self.chunk_ga = False  # return a signed GA reply through 61xx, as a short-Le reader may
        self.endless_61 = False  # GET RESPONSE never finishes
        self.get_responses = 0
        self.blocks: list[bytes] = []  # every challenge block received
        self.signatures: list[bytes] = []
        self.results: list[int] = []  # status word of each GA
        self.ga_slots: list[int] = []  # P2 (0x9A or 0x9D) of each GA

    @property
    def key_9d(self):
        """The 9D key, made on first use (generation is slow)."""
        if self._key_9d is None:
            self._key_9d = shared_key(3)
        return self._key_9d

    # Presence, as touch_pin_hid.c handle_fingerprint_match and config_console.c authorize.
    def touch(self) -> None:
        self.window = Window(10.0, 2, False)

    def auth(self) -> None:
        self.window = Window(30.0, 8, True)

    def process(self, apdu: bytes) -> bytes:
        """piv_handle_apdu_locked."""
        if len(apdu) < 4:
            return sw(0x6700)
        cla, ins, p1, p2 = apdu[:4]
        if cla not in (0x00, 0x10):
            self.chain = b""
            return sw(0x6E00)
        if cla & 0x10 and ins != 0x87:
            self.chain = b""
            return sw(0x6884)
        if ins != 0xC0:
            self.pending = b""
        parsed = self.lc_data(apdu)
        if cla & 0x10:
            same = not self.chain or self.chain_header == apdu[1:4]
            if not same or parsed is None or len(self.chain) + len(parsed[0]) > 700:
                self.chain = b""
                return sw(0x6700)
            self.chain_header = apdu[1:4]
            self.chain += parsed[0]
            return sw(0x9000)
        if self.chain and self.chain_header == apdu[1:4]:
            if parsed is None or len(self.chain) + len(parsed[0]) > 700:
                self.chain = b""
                return sw(0x6700)
            data, le = self.chain + parsed[0], parsed[1]
            self.chain = b""
        else:
            self.chain = b""
            data, le = parsed if parsed else (None, self.le_only(apdu))
        if ins == 0xA4:
            if data is None:
                return sw(0x6700)
            return FCI + sw(0x9000) if data in (PIV_AID, PIV_AID_VERSIONED) else sw(0x6A82)
        if ins == 0xC0:
            return self.get_response(apdu)
        if ins == 0xCB:
            return self.get_data(data, le)
        if ins == 0x87:
            return self.general_authenticate(p1, p2, data)
        return sw(0x6D00)

    @staticmethod
    def lc_data(apdu: bytes):
        """read_lc_data for short APDUs (all the verifier sends): (data, Le) or None."""
        if len(apdu) < 6:
            return None
        lc = apdu[4]
        if lc == 0:
            return None
        if len(apdu) == 5 + lc:
            return apdu[5:5 + lc], None
        if len(apdu) == 6 + lc:
            return apdu[5:5 + lc], apdu[5 + lc] or 256
        return None

    @staticmethod
    def le_only(apdu: bytes):
        return (apdu[4] or 256) if len(apdu) == 5 else None

    def chunked(self, data: bytes, le) -> bytes:
        """respond_maybe_chunked."""
        le = 1798 if le is None else le
        if le >= len(data):
            return data + sw(0x9000)
        if (le + 12) % 64 == 0 and le > 1:
            le -= 1
        self.pending = data[le:]
        return data[:le] + sw(0x6100 | (len(self.pending) if len(self.pending) <= 255 else 0))

    def get_response(self, apdu: bytes) -> bytes:
        """handle_get_response."""
        self.get_responses += 1
        if self.endless_61:
            return b"\x00" * 16 + sw(0x6110)
        if not self.pending:
            return sw(0x6A86)
        le = self.le_only(apdu) or 1798
        take = min(len(self.pending), le)
        if (take + 12) % 64 == 0 and take > 1:
            take -= 1
        out, self.pending = self.pending[:take], self.pending[take:]
        if not self.pending:
            return out + sw(0x9000)
        return out + sw(0x6100 | (len(self.pending) if len(self.pending) <= 255 else 0))

    def get_data(self, data, le) -> bytes:
        """handle_get_data, the 9A certificate object only."""
        if data is None:
            return sw(0x6700)
        if data != bytes.fromhex("5c035fc105") or not self.cert:
            return sw(0x6A88)
        inner = b"\x70" + ber_len(len(self.cert)) + self.cert + b"\x71\x01\x00\xfe\x00"
        return self.chunked(b"\x53" + ber_len(len(inner)) + inner, le)

    def general_authenticate(self, p1: int, p2: int, data) -> bytes:
        self.ga_count += 1
        event = self.on_ga.get(self.ga_count)
        if callable(event):
            event(self)
        elif event == "touch":
            self.touch()
        elif event == "auth":
            self.auth()
        reply = self._general_authenticate(p1, p2, data)
        self.ga_slots.append(p2)
        self.results.append(int.from_bytes(reply[-2:], "big"))
        return reply

    def _general_authenticate(self, p1: int, p2: int, data) -> bytes:
        """handle_general_authenticate: the window is consumed before the length check. The
        accounting is piv.c's: a slot already used is refused only without repeats, and the window
        closes when no operation is left or, without repeats, when both slots are used."""
        if p1 != 0x07 or p2 not in (0x9A, 0x9D):
            return sw(0x6A86)
        if data is None:
            return sw(0x6700)
        challenge = self.dynamic_auth(data)
        if challenge is None:
            return sw(0x6A80)
        self.blocks.append(challenge)
        w = self.window
        valid = w is not None and time.monotonic() < w.until
        slot = 0x02 if p2 == 0x9D else 0x01
        if not valid or w.operations == 0 or (not w.repeated and w.slots & slot):
            if not valid:
                self.window = None
            return sw(0x6982)
        w.slots |= slot
        w.operations -= 1
        if w.operations == 0 or (not w.repeated and w.slots == 0x03):
            self.window = None
        if len(challenge) != 256:
            return sw(0x6700)
        key = self.key_9d if p2 == 0x9D else self.key
        n = key.private_numbers().public_numbers.n
        d = key.private_numbers().d
        signature = pow(int.from_bytes(challenge, "big"), d, n).to_bytes(256, "big")
        self.signatures.append(signature)
        reply = b"\x7c\x82\x01\x04\x82\x82\x01\x00" + signature
        if self.tamper:
            reply = self.tamper(reply)
        if self.chunk_ga:
            return self.chunked(reply, 256)
        return reply + sw(0x9000)

    @staticmethod
    def dynamic_auth(data: bytes):
        """The 7C template and parse_dynamic_auth: the challenge, or None (6A80)."""
        def tlv(buf, off):
            if off >= len(buf):
                return None
            first = buf[off]
            off += 1
            if first < 0x80:
                return first, off
            count = first & 0x7F
            if count == 0 or count > 2 or off + count > len(buf):
                return None
            return int.from_bytes(buf[off:off + count], "big"), off + count
        if len(data) < 2 or data[0] != 0x7C:
            return None
        got = tlv(data, 1)
        if got is None or got[1] + got[0] != len(data):
            return None
        inner, off = data[got[1]:], 0
        challenge, empty = None, False
        while off < len(inner):
            tag = inner[off]
            got = tlv(inner, off + 1)
            if got is None or got[0] > len(inner) - got[1]:
                return None
            length, off = got
            if tag == 0x81 and challenge is None and length:
                challenge = inner[off:off + length]
            elif tag == 0x82 and not empty and length == 0:
                empty = True
            else:
                return None
            off += length
        return challenge if challenge is not None and empty else None


class FakeScard:
    """Module-shaped: the verifier calls these as scard.SCardX(...)."""

    SCARD_S_SUCCESS = 0
    SCARD_SCOPE_USER = 0
    SCARD_SCOPE_SYSTEM = 2
    SCARD_SHARE_SHARED = 2
    SCARD_PROTOCOL_T0 = 1
    SCARD_PROTOCOL_T1 = 2
    SCARD_LEAVE_CARD = 0
    SCARD_RESET_CARD = 1
    SCARD_STATE_UNAWARE = 0
    SCARD_STATE_CHANGED = 2
    SCARD_STATE_EMPTY = 0x10
    SCARD_STATE_PRESENT = 0x20
    SCARD_E_INVALID_HANDLE = 0x80100003
    SCARD_E_UNKNOWN_READER = 0x80100009
    SCARD_E_TIMEOUT = 0x8010000A
    SCARD_E_SHARING_VIOLATION = 0x8010000B
    SCARD_E_NO_SMARTCARD = 0x8010000C
    SCARD_E_READER_UNAVAILABLE = 0x80100017
    SCARD_E_NO_SERVICE = 0x8010001D
    SCARD_E_SERVICE_STOPPED = 0x8010001E
    SCARD_E_NO_READERS_AVAILABLE = 0x8010002E
    SCARD_W_UNPOWERED_CARD = 0x80100067
    SCARD_W_RESET_CARD = 0x80100068
    SCARD_W_REMOVED_CARD = 0x80100069

    def __init__(self, cards: dict[str, FakeCard] | None = None):
        self.cards = {"tinyTouch 00 00": FakeCard()} if cards is None else cards
        self.lock = threading.Lock()
        self.hidden_polls = 0  # status-change waits before the readers show (cold pcscd)
        self.reset_at: set[int] = set()  # transmit numbers answered with SCARD_W_RESET_CARD
        self.busy_begins = 0  # transactions refused with a sharing violation
        self.removed_at: int | None = None  # transmit number from which the card is gone
        self.raise_at: int | None = None  # transmit number that raises (an internal error)
        self.hang_at: int | None = None  # transmit number that never returns
        self.transmits = 0
        self.calls: list[str] = []
        self.handles: dict[int, str] = {}
        self.in_transaction: set[int] = set()
        self.outside_transaction = 0  # APDUs sent outside a transaction (must stay 0)
        self.reconnects = 0
        self.contexts = 0
        self.released = 0
        self.next_handle = 100

    @property
    def card(self) -> FakeCard:
        return next(iter(self.cards.values()))

    def SCardEstablishContext(self, scope):
        self.calls.append("establish")
        self.contexts += 1
        return self.SCARD_S_SUCCESS, 1

    def SCardReleaseContext(self, context):
        self.calls.append("release")
        self.released += 1
        return self.SCARD_S_SUCCESS

    def SCardListReaders(self, context, groups):
        self.calls.append("list")
        if self.hidden_polls > 0 or not self.cards:
            return self.SCARD_E_NO_READERS_AVAILABLE, []
        return self.SCARD_S_SUCCESS, ["Other Reader 00 00"] + list(self.cards)

    def SCardGetStatusChange(self, context, timeout, states):
        self.calls.append("status_change")
        time.sleep(min(timeout, 20) / 1000)
        if self.hidden_polls > 0:
            self.hidden_polls -= 1
        return self.SCARD_E_TIMEOUT, [(name, state, []) for name, state in states]

    def SCardConnect(self, context, reader, share, protocols):
        self.calls.append("connect")
        if reader not in self.cards:
            return self.SCARD_E_UNKNOWN_READER, 0, 0
        assert share == self.SCARD_SHARE_SHARED
        self.next_handle += 1
        self.handles[self.next_handle] = reader
        return self.SCARD_S_SUCCESS, self.next_handle, self.SCARD_PROTOCOL_T1

    def SCardReconnect(self, handle, share, protocols, initialization):
        self.calls.append("reconnect")
        self.reconnects += 1
        assert initialization == self.SCARD_LEAVE_CARD
        return self.SCARD_S_SUCCESS, self.SCARD_PROTOCOL_T1

    def SCardDisconnect(self, handle, disposition):
        self.calls.append("disconnect")
        self.handles.pop(handle, None)
        return self.SCARD_S_SUCCESS

    def SCardBeginTransaction(self, handle):
        self.calls.append("begin")
        if self.busy_begins > 0:
            self.busy_begins -= 1
            return self.SCARD_E_SHARING_VIOLATION
        self.in_transaction.add(handle)
        return self.SCARD_S_SUCCESS

    def SCardEndTransaction(self, handle, disposition):
        self.calls.append("end")
        assert disposition == self.SCARD_LEAVE_CARD
        self.in_transaction.discard(handle)
        return self.SCARD_S_SUCCESS

    def SCardTransmit(self, handle, protocol, apdu):
        self.transmits += 1
        number = self.transmits
        if handle not in self.in_transaction:
            self.outside_transaction += 1
        if number == self.raise_at:
            raise RuntimeError("injected failure")
        if number == self.hang_at:
            while True:
                time.sleep(60)
        if number in self.reset_at:
            return self.SCARD_W_RESET_CARD, []
        if self.removed_at is not None and number >= self.removed_at:
            return self.SCARD_W_REMOVED_CARD, []
        with self.lock:
            return self.SCARD_S_SUCCESS, list(self.cards[self.handles[handle]].process(bytes(apdu)))
