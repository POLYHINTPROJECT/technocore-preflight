"""Preflight Write Validator — deterministic protocol engine.

Pure functions only: no I/O, no network, no clock, no randomness. Every output
is a total function of its inputs, so T1 predictions are reproducible offline.

Semantics model the pinned upstream technocore-chat write path:
  - src/store.py  :: clean_text (sweep->strip->length), valid_name, NAME_RE,
                     INVISIBLE_CATEGORIES, MAX_TEXT_CHARS/MAX_VALUE_CHARS
  - src/didkey.py :: did:key parsing (prefix/z-multibase/48 chars/base58btc/
                     0xed01 multicodec), NONCE_PATTERN, 86-char base64url sigs
  - src/app.py    :: _signer canonical strings ("room|nonce|stored" /
                     "ns|key|nonce|value"), verification-before-gate ordering

Wire reality: URL path parameters arrive as percent-decoded BYTES; invalid
UTF-8 becomes U+FFFD (category So -- NOT swept). `wire_decode` models this so
all downstream analysis sees what the server sees.
"""
from __future__ import annotations

import base64
import hashlib
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import quote

# ---------------------------------------------------------------- constants
# Pinned upstream: store.INVISIBLE_CATEGORIES
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})
MAX_TEXT_CHARS = 4096          # store.MAX_TEXT_CHARS (message lane)
MAX_VALUE_CHARS = 8192         # store.MAX_VALUE_CHARS (note lane)
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")     # store.NAME_RE
NONCE_RE = re.compile(r"[0-9]{1,19}")                    # didkey.NONCE_PATTERN
SIG_RE = re.compile(r"[A-Za-z0-9_-]{86}")                # didkey.SIG_RE (86, unpadded b64url)
DID_PREFIX = "did:key:"
MULTIBASE_CHARS = 48                                     # didkey.MULTIBASE_CHARS
MULTICODEC_ED25519 = b"\xed\x01"
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(B58_ALPHABET)}
ROOM_CLASSES = ("mb", "p", "d", "e")                     # composed prefixes
PRACTICAL_URL_CEILING = 16384                            # Cloudflare request-line ceiling


class PreflightError(Exception):
    """Raised for static rejections (mirrors server StoreError/DidError paths)."""


@dataclass(frozen=True)
class Verdict:
    ok: bool
    code: str            # "" when ok; otherwise a closed-vocabulary E_*/W_* code
    detail: str = ""


def _ok(detail: str = "") -> Verdict:
    return Verdict(True, "", detail)


def _bad(code: str, detail: str = "") -> Verdict:
    return Verdict(False, code, detail)


# ------------------------------------------------------------ wire decoding
def wire_decode(raw: str | bytes) -> str:
    """Model percent-decoded wire bytes becoming an in-memory string.

    The server percent-decodes path segments into bytes, then Python decodes
    them UTF-8. Bytes that are not valid UTF-8 become U+FFFD (category So),
    which the sweep does NOT replace -- so it survives into storage. Passing a
    str assumes the caller already holds the decoded form unchanged.
    """
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return raw


# ------------------------------------------------------------------- sweep
@dataclass(frozen=True)
class SweepResult:
    stored: str
    changes: tuple[tuple[int, str, str], ...]   # (index, U+XXXX, category), <=detail_cap
    change_count: int
    truncated_change_list: bool
    sha256_hex: str                              # sha256 of stored UTF-8 bytes
    char_len: int


def sweep(text: str, limit: int = MAX_TEXT_CHARS) -> SweepResult:
    """Server-exact clean_text: replace every invisible-category char with a
    space (1:1, offsets preserved), then .strip(), then enforce the limit on
    the POST-sweep length. Raises PreflightError for empty-after-sweep and
    over-length, mirroring the server's StoreError refusals."""
    out_chars: list[str] = []
    changes: list[tuple[int, str, str]] = []
    for i, ch in enumerate(text):
        cat = unicodedata.category(ch)
        if cat in INVISIBLE_CATEGORIES:
            changes.append((i, f"U+{ord(ch):04X}", cat))
            out_chars.append(" ")
        else:
            out_chars.append(ch)
    stored = "".join(out_chars).strip()
    if not stored:
        raise PreflightError(
            "E_EMPTY_AFTER_SWEEP: nothing visible survived the single-line sweep"
        )
    if len(stored) > limit:
        raise PreflightError(
            f"E_TEXT_TOO_LONG: {len(stored)} characters after sweep, limit {limit}"
        )
    cap = 20
    shown = tuple(changes[:cap])
    return SweepResult(
        stored=stored,
        changes=shown,
        change_count=len(changes),
        truncated_change_list=len(changes) > cap,
        sha256_hex=hashlib.sha256(stored.encode("utf-8")).hexdigest(),
        char_len=len(stored),
    )


# -------------------------------------------------------------- room names
def _room_classes(name: str) -> tuple[str, ...]:
    """Composed leading class prefixes (mb-, p-, d-, e-), reference behavior:
    `mb-p-x` is mailbox+unlisted; `e-commerce` really is ephemeral."""
    classes: list[str] = []
    rest = name
    changed = True
    while changed:
        changed = False
        for cls in ROOM_CLASSES:
            if rest.startswith(cls + "-"):
                classes.append(cls)
                rest = rest[len(cls) + 1:]
                changed = True
                break
    return tuple(classes)


def validate_room(name: str) -> Verdict:
    if not name:
        return _bad("E_BAD_ROOM", "empty room name")
    if not NAME_RE.fullmatch(name):
        if any(c.isupper() for c in name):
            return _bad("E_BAD_ROOM", "uppercase letters are rejected")
        if len(name) > 48:
            return _bad("E_BAD_ROOM", f"{len(name)} chars, limit 48")
        if name[0] in "-_":
            return _bad("E_BAD_ROOM", "must start with [a-z0-9]")
        return _bad("E_BAD_ROOM", "allowed: [a-z0-9][a-z0-9_-]{0,47}")
    return _ok("classes=" + (",".join(_room_classes(name)) or "none"))


# ------------------------------------------------------------------ nonce
def validate_nonce(nonce: str | int, floor: int | None = None) -> Verdict:
    s = str(nonce)
    if not NONCE_RE.fullmatch(s):
        if not s.isdigit() or not s.isascii():
            return _bad("E_BAD_NONCE_FORMAT", "must be 1-19 ASCII digits [0-9]")
        return _bad("E_BAD_NONCE_FORMAT",
                    f"{len(s)} digits; the server accepts at most 19")
    value = int(s)
    # Floor comparison happens on the parsed integer REGARDLESS of formatting
    # quirks -- the server compares ints, so '05' == 5 must be refused equally.
    if floor is not None and value <= floor:
        return _bad("E_NONCE_NOT_GREATER",
                    f"nonce {value} must be strictly greater than the last "
                    f"observed floor {floor} for this key in this room")
    if len(s) > 1 and s[0] == "0":
        # Format-valid but pointless: '01' == 1 numerically.
        return Verdict(True, "W_LEADING_ZERO_NONCE",
                       f"parses to {value}; prefer the canonical form")
    return _ok(str(value))


# -------------------------------------------------------------------- DID
def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        if ch not in _B58_INDEX:
            raise PreflightError(
                f"E_BAD_DID: invalid base58 character {ch!r} "
                "(0/O/I/l are excluded from the alphabet)")
        n = n * 58 + _B58_INDEX[ch]
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + raw


def parse_did(did: str) -> bytes:
    """Return the 32-byte Ed25519 public key, or raise PreflightError(E_BAD_DID).

    Mirrors didkey.public_key: 'did:key:' prefix, 'z' multibase, exactly 48
    multibase chars, base58btc body decoding to 34 bytes starting 0xed 0x01."""
    if not isinstance(did, str) or not did.startswith(DID_PREFIX):
        raise PreflightError("E_BAD_DID: expected did:key:z6Mk...")
    mb = did[len(DID_PREFIX):]
    if len(mb) != MULTIBASE_CHARS:
        raise PreflightError(
            f"E_BAD_DID: expected {MULTIBASE_CHARS} multibase chars, got {len(mb)}")
    if not mb.startswith("z"):
        raise PreflightError("E_BAD_DID: multibase tag must be 'z' (base58btc)")
    decoded = _b58decode(mb[1:])
    if len(decoded) != 34 or not decoded.startswith(MULTICODEC_ED25519):
        raise PreflightError(
            "E_BAD_DID: only ed25519-pub keys (0xed 0x01 varint + 32-byte key) accepted")
    return decoded[2:]


def fingerprint(did: str) -> str:
    """First 16 lowercase hex chars of SHA-256 of the full did:key STRING
    (not the key bytes). Convention per current patterns.md."""
    return hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]


# ------------------------------------------------------- canonical payloads
def canonical_msg(room: str, nonce: str | int, stored_text: str) -> bytes:
    """Exact signing payload for the signed message lane: room|nonce|stored.
    `stored_text` must already be swept (pass SweepResult.stored)."""
    return f"{room}|{int(nonce)}|{stored_text}".encode("utf-8")


def canonical_note(ns: str, key: str, nonce: str | int, stored_value: str) -> bytes:
    """Exact signing payload for the signed NOTE lanes (reserved namespaces):
    ns|key|nonce|value."""
    return f"{ns}|{key}|{int(nonce)}|{stored_value}".encode("utf-8")


# ------------------------------------------------------------- signatures
def verify_sig_b64u(pub32: bytes, sig: str, canonical: bytes) -> Verdict:
    """Ed25519 verification over the canonical bytes. Encoding checked first
    (86 unpadded base64url chars), mirroring didkey.verify's ordering."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )
    if SIG_RE.fullmatch(sig or "") is None:
        return _bad("E_BAD_SIG_ENCODING",
                    "expected 86 unpadded base64url characters")
    try:
        raw = base64.urlsafe_b64decode(sig + "==")
    except Exception as exc:                                   # pragma: no cover
        return _bad("E_BAD_SIG_ENCODING", f"undecodable: {exc}")
    try:
        Ed25519PublicKey.from_public_bytes(pub32).verify(raw, canonical)
    except InvalidSignature:
        return _bad("E_SIG_INVALID",
                    "signature does not verify for this DID over this canonical string")
    return _ok("verified")


# ---------------------------------------------------------- URL assembly
def encode_segment(text: str) -> tuple[str, int]:
    """Percent-encode one path segment leaving only unreserved characters;
    returns (encoded, encoded_length). Matches reference quote(safe='')."""
    enc = quote(text, safe="")
    return enc, len(enc)


def estimate_request_line(base: str, room: str, did: str, sig: str,
                          nonce: str | int, swept_text: str) -> Verdict:
    enc_did, l_did = encode_segment(did)
    enc_txt, l_txt = encode_segment(swept_text)
    total = len(f"{base}/r/{room}/say-signed/{enc_did}/{sig}/{int(nonce)}/{enc_txt}")
    if total > PRACTICAL_URL_CEILING:
        return _bad("E_CANONICAL_TOO_LONG",
                    f"request line ~{total} chars exceeds practical ceiling "
                    f"{PRACTICAL_URL_CEILING}; split before encrypting/posting")
    if total > PRACTICAL_URL_CEILING // 2:
        return Verdict(True, "W_URL_LONG",
                       f"request line ~{total} chars; consider splitting")
    return _ok(f"request line ~{total} chars")


# ------------------------------------------------------------ DID-note audit
def audit_note(placed_key_fp: str, value: str, did: str | None = None,
               placed_ns: str = "") -> list[tuple[str, str]]:
    """Audit one published DID note. Returns ordered findings using the spec
    vocabulary (W_NOTE_*) plus A_* audit-only codes. Order is fixed, so
    output is deterministic. `placed_ns` enables legacy-path detection
    ('did' = legacy flat namespace, 'did-XX' = canonical sharded)."""
    findings: list[tuple[str, str]] = []

    # 1) locate + parse the DID recorded INSIDE the note value
    m = re.search(r"did:key:[A-Za-z0-9]+", value)
    if m is None:
        findings.append(("A_NO_DID_IN_NOTE",
                         "no did:key substring found in the note value"))
        inner_did = None
    else:
        inner_did = m.group(0)
        try:
            parse_did(inner_did)
        except PreflightError as exc:
            findings.append(("A_BAD_DID_IN_NOTE", str(exc)))
            inner_did = None

    # 2) placement: the key this note sits at vs the fingerprint of the DID in it
    if inner_did is not None:
        expected_fp = fingerprint(inner_did)
        if placed_key_fp.lower() != placed_key_fp:
            findings.append(("W_NOTE_UPPERCASE_KEY",
                             f"key '{placed_key_fp}' uses uppercase hex; "
                             "convention is lowercase"))
        if placed_key_fp.lower() != expected_fp:
            findings.append((
                "W_NOTE_WRONG_KEY",
                f"note sits at '{placed_key_fp}' but sha256(did)[0:16] of its "
                f"DID is '{expected_fp}' -- pattern-3 readers will never resolve it"))
    # 3) namespace generation
    if placed_ns == "did":
        findings.append(("W_NOTE_LEGACY_PATH",
                         "flat /kv/did/<fp> is legacy/read-fallback only; "
                         "republish at /kv/did-<first2>/<rest14>"))

    # 4) optional structured fields
    mb = re.search(r"mailbox:([A-Za-z0-9_-]+)", value)
    if mb is not None:
        v = validate_room(mb.group(1))
        if not v.ok:
            findings.append(("W_NOTE_FIELD_MISMATCH",
                             f"mailbox:{mb.group(1)} is not a valid room name"))
        elif "mb" not in _room_classes(mb.group(1)):
            findings.append(("W_NOTE_FIELD_MISMATCH",
                             f"mailbox:{mb.group(1)} lacks the mb- class; "
                             "mailboxes should be mb-* rooms"))
    xx = re.search(r"x25519:([A-Za-z0-9_-]+)", value)
    if xx is not None:
        try:
            raw = base64.urlsafe_b64decode(xx.group(1) + "==")
            if len(raw) != 32:
                raise ValueError
        except Exception:
            findings.append(("W_NOTE_FIELD_MISMATCH",
                             "x25519: value does not decode to 32 bytes"))

    # 5) explicit cross-check against the caller's own DID
    if did is not None and inner_did is not None and inner_did != did:
        findings.append(("W_NOTE_FIELD_MISMATCH",
                         "note DID differs from the supplied service DID"))

    if not findings:
        findings.append(("A_OK", "note passes structural audit"))
    return findings


# ------------------------------------------------------ nonce-floor simulation
def simulate_nonce_floor(tail_snapshot: list[dict], did: str, room: str,
                         proposed: str | int) -> Verdict:
    """Replay the replay-protection rule over a supplied room tail.

    `tail_snapshot` is a list of stored-record dicts ({from, text, nonce?, seq})
    as served by ?format=json -- already wire-decoded, oldest first. The server
    scans such a window for records whose `from` equals the literal DID and
    refuses proposed <= max(seen nonce). Window-bounded by nature: the answer
    is only as fresh as the snapshot, and the floor FORGETS once records age
    out of the scanned window."""
    floor: int | None = None
    floor_seq: int | None = None
    for rec in tail_snapshot:
        if rec.get("from") != did:          # literal-DID match, mentions excluded
            continue
        n = rec.get("nonce")
        if n is None:
            continue                        # unsigned record: no nonce state
        if floor is None or n > floor:
            floor = n
            floor_seq = rec.get("seq")
    v = validate_nonce(proposed, floor=floor)
    if v.ok and floor is None:
        return Verdict(True, "O_NO_PRIOR_WRITES_SEEN",
                       f"no prior signed writes by this DID visible in /r/{room} "
                       "window; nonce accepted by the model")
    if v.code == "W_LEADING_ZERO_NONCE":
        return v
    if v.ok:
        return _ok(f"proposed {int(proposed)} > visible floor {floor} (seq {floor_seq})")
    return v
