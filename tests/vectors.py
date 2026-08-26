"""Source-derived test vectors for the preflight engine.

Every expected value here is derived from pinned upstream semantics
(src/store.py, src/didkey.py, src/app.py @ flop-labs/technocore-chat main,
2026-08-25) or from live-server observed behavior recorded during research
(the service DID note path, the genesis write). Nothing is guessed.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engine import preflight as pf  # noqa: E402

SERVICE_DID = "did:key:z6MkvgWDuQjhQfwaqkkDf6SAC9QNg7sCHe9xjbBeUQguQbjd"
SERVICE_FP = "11b17958c4064c71"          # sha256(SERVICE_DID)[0:16], verified live
MAILBOX = "mb-p-preflight-11b17958c4064c71"
GENESIS_CANONICAL = (
    "mb-p-preflight-11b17958c4064c71|1|"
    "PFS v1 | preflight | status=initializing ; engine_version:0.1.0"
)

# ---------------------------------------------------------------- sweep corpus
# (label, input, expected_stored). Derived from store.clean_text semantics.
SWEEP_IDENTITY = [
    ("plain ascii", "hello world", "hello world"),
    ("leading/trailing spaces strip", "  hi  ", "hi"),
    ("punct preserved", "a|b;c=d e(f)g", "a|b;c=d e(f)g"),
    ("CJK untouched", "日本語テスト", "日本語テスト"),
    ("hangul untouched", "한국어", "한국어"),
    ("kana untouched", "ひらがなカタカナ", "ひらがなカタカナ"),
    ("emoji untouched", "🚀🔥", "🚀🔥"),
    ("U+FFFD survives (So not swept)", "a\ufffdb", "a\ufffdb"),
    ("accented latin untouched", "café", "café"),
    ("variation selector VS16 untouched (Mn)", "✌️", "✌️"),
]

# single-character replacements: category -> space, offsets preserved
SWEEP_REPLACE_SINGLE = [
    ("tab (Cc)", "a\tb", "a b"),
    ("LF (Cc)", "a\nb", "a b"),
    ("CR (Cc)", "a\rb", "a b"),
    ("CRLF = two spaces", "a\r\nb", "a  b"),
    ("NUL (Cc)", "a\x00b", "a b"),
    ("C1 control U+0085 (Cc)", "a\x85b", "a b"),
    ("DEL (Cc)", "a\x7fb", "a b"),
    ("soft hyphen U+00AD (Cf)", "a\u00adb", "a b"),
    ("ZWJ U+200D (Cf)", "a\u200db", "a b"),
    ("ZWNJ U+200C (Cf)", "a\u200cb", "a b"),
    ("LRM U+200E (Cf)", "a\u200eb", "a b"),
    ("bidi LRE U+202A (Cf)", "a\u202ab", "a b"),
    ("bidi isolate LRI U+2066 (Cf)", "a\u2066b", "a b"),
    ("BOM U+FEFF (Cf)", "a\ufeffb", "a b"),
    ("LINE SEPARATOR U+2028 (Zl)", "a b", "a b"),
    ("PARA SEPARATOR U+2029 (Zp)", "a b", "a b"),
    ("private use U+E000 (Co)", "ab", "a b"),
    ("plane-15 PUA U+F3F5 (Co)", "a󳵵b", "a b"),
    ("tag char U+E0020 (Cf)", "a\U000E0020b", "a b"),
]

# Wire reality: a lone surrogate cannot survive URL transit; percent-decoded
# bytes that are invalid UTF-8 become U+FFFD (So), which is NOT swept.
WIRE_CASES = [
    ("valid utf8 passthrough", "héllo".encode("utf-8"), "héllo"),
    ("4-byte emoji passthrough", "🚀".encode("utf-8"), "🚀"),
    ("truncated utf8 -> one U+FFFD", b"ab\xf0\x9f", "ab\ufffd"),
    ("lone continuation byte -> U+FFFD", b"a\x80b", "a\ufffd b".replace(" ", "")),
    # each of the 3 invalid surrogate-encoding bytes becomes its own U+FFFD
    ("%ED%A0%80 lone-surrogate encoding -> three U+FFFD",
     b"a\xed\xa0\x80b", "a\ufffd\ufffd\ufffd b".replace(" ", "")),
]


def length_boundary_cases():
    """4095/4096/4097 post-sweep boundaries + invisible-padding interactions.
    Each case: (label, raw_text, outcome) where outcome is 'ok' with an
    expected stored length, or ('raise', code)."""
    base = "x" * 4095
    return [
        # post-sweep lengths 4095 / 4096 / 4097
        ("post-sweep 4095 ok", base, ("ok", 4095)),
        ("post-sweep 4096 ok", base + "y", ("ok", 4096)),
        ("post-sweep 4097 rejected", base + "yz", ("raise", "E_TEXT_TOO_LONG")),
        # trailing LF strips off: raw 4097 -> stored 4096
        ("raw 4097 w/ trailing LF fits", base + "y\n", ("ok", 4096)),
        # leading invisible chars are STRIPPED (they become spaces at the ends)
        ("leading ZWSP stripped", "\u200b" * 10 + base[2:], ("ok", 4093)),
        # interior invisibles become spaces and COUNT against the cap:
        # 2045 vis + 10 spaces + 2045 vis = 4100 > 4096 -> refused
        ("interior padding counts after replace",
         "x" * 2045 + "\u200b" * 10 + "x" * 2045, ("raise", "E_TEXT_TOO_LONG")),
    ]


# ---------------------------------------------------------------- room names
ROOMS_VALID = ["lobby", "mb-p-preflight-11b17958c4064c71", "d-jobs", "e-temp",
               "p-abc123", "a", "z" * 48, "room_1-x"]
ROOMS_INVALID = [
    ("", "empty"),
    ("Lobby", "uppercase"),
    ("-lead", "starts with dash"),
    ("_under", "starts with underscore"),
    ("has space", "space"),
    ("room:name", "colon"),
    ("r" * 49, "49 chars"),
    ("room\nname", "newline (wire %0A traversal)"),
    ("roomé", "non-ascii letter"),
]

# non-obvious VALID names whose class composition matters (reference behavior)
ROOM_CLASS_TRAPS = [
    ("e-commerce", ("e",)),          # really ephemeral!
    ("mb-p-secret", ("mb", "p")),    # mailbox AND unlisted
    ("d-flop-hq-deadbeef", ("d",)),
    ("embassy", ()),                 # 'e' not a class unless followed by '-'
    ("mbx-room", ()),                # 'mb' needs '-' right after
]

# ------------------------------------------------------------------- nonces
NONCE_VALID = ["1", "0", "9", "1234567890123456789"]       # 19 digits max
NONCE_FORMAT_INVALID = [
    "", "-1", "1.5",
    "12345678901234567890",              # 20 digits
    "١٢٣",                                # arabic-indic digits
    " 1", "1 ", "+1", "abc",
]
# Format-valid per server NONCE_RE ([0-9]{1,19} accepts them) but flagged by
# our engine with an advisory warning; the server accepts them silently.
NONCE_LEADING_ZERO_WARN = ["01", "007"]

NONCE_FLOOR_CASES = [
    # (floor_or_None, proposed, expect_ok)
    (None, "1", True),
    (1, "2", True),
    (1, "1", False),                       # equal refused: strictly greater required
    (999999999, "1000000000", True),
    (10**19 - 1, str(10**19 - 1), False),  # equal to max floor
    (5, "05", False),                      # parses to 5 == floor -> refused despite W-class form
    (5, "6", True),
]

# ---------------------------------------------------------------------- DIDs
REFERENCE_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"  # auth.md example
DID_MALFORMED = [
    ("", "empty"),
    ("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "missing prefix"),
    ("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2do", "47 multibase chars"),
    ("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doKX", "49 chars"),
    ("did:key:u6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "wrong multibase tag"),
    ("did:key:z6MOhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "invalid b58 char O"),
    ("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2dol", "invalid b58 char l"),
    ("did:key:zed01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "single-byte 0xed varint trap"),
]

SIG_MALFORMED = ["", "abc", "R" * 85, "R" * 87, "R" * 86 + "=", "R" * 86 + "!"]

SWEEP_EMPTY_AFTER = [
    ("only newlines", "\n\n"),
    ("only ZWJ", "\u200d\u200d"),
    ("only spaces", "   "),
    ("tab+BOM mix", "\t\ufeff\n"),
    ("empty string", ""),
]

# ------------------------------------------------------------ DID-note audit
NOTE_OK_VALUE = ("did:key:z6MkmzyBxvrSZveZv5YhZhfwUYQYv5LDgt5NuqVrBe5vXvPA "
                 "mailbox:mb-p-example")
FP_CORRECT = "b5f10998c3a88a93"     # sha256 of that did string [0:16] (live-verified convention)
