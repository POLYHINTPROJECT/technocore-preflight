"""Offline tests for the PFQ/PFR wire layer (engine/wire.py).

Covers: canonical rendering, tolerant parsing, round-trip determinism in both
directions, reserved-character escaping, duplicate keys, malformed cids,
unknown op/status/finding codes, truncation, empty values, sweep-unsafe wire
input, and verify-mode completeness rules.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from engine import wire as w  # noqa: E402
from engine.wire import WireError  # noqa: E402

CID = "0123456789abcdef"
REPLY = "mb-p-consumer-0000000000000000"
DID = "did:key:z6MkvgWDuQjhQfwaqkkDf6SAC9QNg7sCHe9xjbBeUQguQbjd"

PREVIEW_STRUCT = {
    "kind": "PFQ", "cid": CID, "op": "preview",
    "params": {"reply": REPLY, "room": "lobby", "nonce": "1",
               "did": DID, "text": "hello world"},
}
PREVIEW_LINE = (
    f"PFQ v1 | {CID} | preview | reply={REPLY} ; room=lobby ; nonce=1 ; "
    f"did={DID} ; text=hello world"
)
VERIFY_PRIVACY_STRUCT = {
    "kind": "PFQ", "cid": CID, "op": "verify",
    "params": {"reply": REPLY, "did": DID, "canonical": "lobby|1|hi",
               "sha256": "a" * 64},
}
AUDIT_STRUCT = {
    "kind": "PFQ", "cid": CID, "op": "audit-did-note",
    "params": {"reply": REPLY, "fp": "11b17958c4064c71",
               "value": f"{DID} mailbox:{REPLY} engine_version:0.1.0",
               "ns": "did-11", "key": "b17958c4064c71"},
}
PFR_STRUCT = {
    "kind": "PFR", "cid": CID, "status": "PASS", "engine": "0.1.0",
    "findings": [("T1-ok", "", "", "all static checks passed")],
}
PFR_LINE = f"PFR v1 | {CID} | PASS | engine=0.1.0 ; T1-ok all static checks passed"


def expect_error(testcase, code, fn, *args):
    with testcase.assertRaises(WireError) as ctx:
        fn(*args)
    testcase.assertEqual(ctx.exception.code, code,
                         f"wanted {code}, got {ctx.exception.code}: {ctx.exception}")


class TestEscaping(unittest.TestCase):
    def test_three_escapes_roundtrip(self):
        for ch in ("%", "|", ";"):
            enc = w.encode_value(ch)
            self.assertNotEqual(enc, ch)
            self.assertIn("%", enc)
            self.assertEqual(w.decode_value(enc), ch)

    def test_bad_escape_rejected(self):
        expect_error(self, "X_BAD_ENCODING", w.decode_value, "100%20")
        expect_error(self, "X_BAD_ENCODING", w.decode_value, "%2F")

    def test_lowercase_escapes_rejected(self):
        # escapes are uppercase-only by contract; %7c is not an escape
        expect_error(self, "X_BAD_ENCODING", w.decode_value, "%7c")

    def test_reserved_chars_in_values_survive_roundtrip(self):
        struct = {"kind": "PFQ", "cid": CID, "op": "preview",
                  "params": dict(PREVIEW_STRUCT["params"],
                                 text="pipe|and;semicolon%here")}

        line = w.render_pfq(struct)
        self.assertNotIn("|and", line.split("text=")[1])
        parsed = w.parse_pfq(line)
        self.assertEqual(parsed["params"]["text"], "pipe|and;semicolon%here")


class TestParsePFQ(unittest.TestCase):
    def test_canonical_preview_line_parses(self):
        got = w.parse_pfq(PREVIEW_LINE)
        self.assertEqual(got, PREVIEW_STRUCT)

    def test_whitespace_tolerance_normalizes(self):
        sloppy = (f"PFQ v1|  {CID}  |preview| reply={REPLY} ;  room=lobby ; "
                  f"nonce=1; did={DID} ;text=hello world")
        got = w.parse_pfq(sloppy)
        self.assertEqual(got["params"], PREVIEW_STRUCT["params"])
        # ...and re-renders canonically identical
        self.assertEqual(w.render_pfq(got), PREVIEW_LINE)

    def test_verify_privacy_mode(self):
        got = w.parse_pfq(w.render_pfq(VERIFY_PRIVACY_STRUCT))
        self.assertEqual(got, VERIFY_PRIVACY_STRUCT)

    def test_audit_mode(self):
        got = w.parse_pfq(w.render_pfq(AUDIT_STRUCT))
        self.assertEqual(got, AUDIT_STRUCT)

    def test_wrong_prefix(self):
        line = PREVIEW_LINE.replace("PFQ v1", "PFR v1", 1)
        expect_error(self, "X_BAD_PREFIX", w.parse_pfq, line)

    def test_version_mismatch(self):
        line = PREVIEW_LINE.replace("PFQ v1", "PFQ v2", 1)
        expect_error(self, "X_BAD_PREFIX", w.parse_pfq, line)

    def test_malformed_cid_variants(self):
        for bad in ["", "abc", "0123456789ABCDEF", "0123456789abcdef0",
                    "0123456789abcdeg"]:
            line = PREVIEW_LINE.replace(CID, bad, 1)
            expect_error(self, "X_BAD_CID", w.parse_pfq, line)

    def test_unknown_op(self):
        line = PREVIEW_LINE.replace("| preview |", "| transmogrify |", 1)
        expect_error(self, "X_BAD_OP", w.parse_pfq, line)

    def test_structure_violations(self):
        too_few = "PFQ v1 | only | two"
        expect_error(self, "X_BAD_STRUCTURE", w.parse_pfq, too_few)
        # an unescaped pipe inside a value adds a fourth field
        leaky = (f"PFQ v1 | {CID} | preview | reply={REPLY} ; room=a|b ; "
                 f"nonce=1 ; did={DID} ; text=x")
        expect_error(self, "X_BAD_STRUCTURE", w.parse_pfq, leaky)

    def test_reply_rules(self):
        base = f"PFQ v1 | {CID} | preview | {{}} ; room=r ; nonce=1 ; did={DID} ; text=t"
        missing = base.format(f"room={REPLY}")
        expect_error(self, "X_ORDER", w.parse_pfq, missing)
        not_mb = base.format(f"reply=p-sneaky")
        expect_error(self, "X_BAD_REPLY_ROOM", w.parse_pfq, not_mb)
        invalid = base.format("reply=BAD ROOM")
        expect_error(self, "X_BAD_REPLY_ROOM", w.parse_pfq, invalid)

    def test_unknown_and_missing_keys(self):
        extra = PREVIEW_LINE + " ; bogus=1"
        expect_error(self, "X_UNKNOWN_KEY", w.parse_pfq, extra)
        missing_did = PREVIEW_LINE.replace(f" ; did={DID}", "")
        expect_error(self, "X_MISSING_KEY", w.parse_pfq, missing_did)

    def test_duplicate_key(self):
        dup = PREVIEW_LINE + f" ; room=other"
        expect_error(self, "X_DUPLICATE_KEY", w.parse_pfq, dup)

    def test_empty_value(self):
        line = PREVIEW_LINE.replace("nonce=1", "nonce=", 1)
        expect_error(self, "X_EMPTY_VALUE", w.parse_pfq, line)

    def test_bad_param_token_shapes(self):
        no_eq = PREVIEW_LINE + " ; lonely"
        expect_error(self, "X_BAD_PARAM", w.parse_pfq, no_eq)
        # interior empty token (a trailing one would be trailing-whitespace,
        # rejected earlier as X_NOT_SWEEP_SAFE)
        empty_tok = PREVIEW_LINE.replace("room=lobby", "room=lobby ; ; nonce=1", 1)
        expect_error(self, "X_BAD_PARAM", w.parse_pfq, empty_tok)
        badkey = PREVIEW_LINE + " ; 2fast=1"
        expect_error(self, "X_BAD_KEY", w.parse_pfq, badkey)

    def test_verify_mode_completeness(self):
        mk = lambda params: w.render_pfq({  # noqa: E731
            "kind": "PFQ", "cid": CID, "op": "verify",
            "params": {"reply": REPLY, **params}})
        full_ok = mk({"did": DID, "nonce": "1", "room": "r", "text": "t",
                      "sig": "R" * 86})
        self.assertTrue(w.parse_pfq(full_ok)["op"] == "verify")
        half_full = mk({"did": DID, "room": "r", "text": "t"})
        expect_error(self, "X_AMBIGUOUS_MODE", w.parse_pfq, half_full)
        mixed = mk({"did": DID, "canonical": "r|1|t"})
        expect_error(self, "X_AMBIGUOUS_MODE", w.parse_pfq, mixed)
        neither = mk({"did": DID})
        expect_error(self, "X_MISSING_KEY", w.parse_pfq, neither)

    def test_closed_format_params(self):
        bad_sha = w.render_pfq(VERIFY_PRIVACY_STRUCT).replace(
            "sha256=" + "a" * 64, "sha256=ZZ")
        expect_error(self, "X_BAD_SHA256", w.parse_pfq, bad_sha)
        bad_fp = w.render_pfq(AUDIT_STRUCT).replace("fp=11b17958c4064c71",
                                                    "fp=NOPE")
        expect_error(self, "X_BAD_FP", w.parse_pfq, bad_fp)
        bad_ns = w.render_pfq(AUDIT_STRUCT).replace("ns=did-11", "ns=shard-x")
        expect_error(self, "X_BAD_NS", w.parse_pfq, bad_ns)

    def test_sweep_unsafe_line_rejected(self):
        expect_error(self, "X_NOT_SWEEP_SAFE", w.parse_pfq,
                     " PFQ v1 | x | x | x".replace("\x00", ""))
        tabbed = PREVIEW_LINE + "\t" + "  "   # trailing whitespace -> strip mismatch
        expect_error(self, "X_NOT_SWEEP_SAFE", w.parse_pfq, tabbed)

    def test_truncation_guard(self):
        long_text = "x" * 5000
        line = (f"PFQ v1 | {CID} | preview | reply={REPLY} ; room=r ; nonce=1 ; "
                f"did={DID} ; text={long_text}")
        expect_error(self, "X_LINE_TOO_LONG", w.parse_pfq, line)


class TestParsePFR(unittest.TestCase):
    def test_canonical_line(self):
        self.assertEqual(w.parse_pfr(PFR_LINE), PFR_STRUCT)

    def test_status_vocab_closed(self):
        for bad in ["OK", "pass", "WARN"]:
            line = PFR_LINE.replace("| PASS |", f"| {bad} |", 1)
            expect_error(self, "X_BAD_STATUS", w.parse_pfr, line)

    def test_engine_semver_enforced(self):
        for bad in ["0.1", "v0.1.0", "latest", "0.1.0."]:
            line = PFR_LINE.replace("engine=0.1.0", f"engine={bad}", 1)
            expect_error(self, "X_BAD_SEMVER", w.parse_pfr, line)

    def test_no_findings_rejected(self):
        expect_error(self, "X_NO_FINDINGS", w.parse_pfr,
                     f"PFR v1 | {CID} | PASS | engine=0.1.0")

    def test_unknown_t1_code(self):
        line = (f"PFR v1 | {CID} | FAIL | engine=0.1.0 ; "
                "T1-reject:E_MADE_UP nope")
        expect_error(self, "X_UNKNOWN_FINDING_CODE", w.parse_pfr, line)

    def test_unknown_t2_code(self):
        line = (f"PFR v1 | {CID} | PARTIAL | engine=0.1.0 ; "
                "T2-observe:O_TELEPATHY@seq3 saw it coming")
        expect_error(self, "X_UNKNOWN_FINDING_CODE", w.parse_pfr, line)

    def test_t2_ref_shape_enforced(self):
        good = (f"PFR v1 | {CID} | PARTIAL | engine=0.1.0 ; "
                "T2-observe:O_NONCE_FLOOR_VISIBLE@seq42 floor 7")
        parsed = w.parse_pfr(good)
        self.assertEqual(parsed["findings"][0][2], "seq42")
        # a space always terminates the ref, so the invalid shape reachable on
        # the wire is an EMPTY ref ("@" directly followed by the detail)
        bad = good.replace("@seq42", "@")
        expect_error(self, "X_BAD_OBSERVATION_REF", w.parse_pfr, bad)

    def test_all_frozen_codes_accepted(self):
        toks = [f"T1-reject:{c} d" for c in sorted(w.REJECT_CODES)] + \
               [f"T1-warn:{c} d" for c in sorted(w.WARN_CODES)] + \
               [f"T2-observe:{c}@seq1 d" for c in sorted(w.OBSERVE_CODES)]
        line = f"PFR v1 | {CID} | FAIL | engine=9.9.9 ; " + " ; ".join(toks)
        parsed = w.parse_pfr(line)
        self.assertEqual(len(parsed["findings"]),
                         len(w.REJECT_CODES) + len(w.WARN_CODES) + len(w.OBSERVE_CODES))


class TestRoundTrip(unittest.TestCase):
    STRUCTS = [PREVIEW_STRUCT, VERIFY_PRIVACY_STRUCT, AUDIT_STRUCT]

    def test_render_parse_fixed_point(self):
        """parse(render(x)) == x for every expressible struct."""
        for s in self.STRUCTS:
            with self.subTest(s["op"]):
                self.assertEqual(w.parse_pfq(w.render_pfq(s)), s)

    def test_parse_render_fixed_point(self):
        """render(parse(x)) == x for canonical lines (fixed point)."""
        for line in [PREVIEW_LINE, PFR_LINE]:
            kind = line[:3]
            if kind == "PFQ":
                self.assertEqual(w.render_pfq(w.parse_pfq(line)), line)
            else:
                self.assertEqual(w.render_pfr(w.parse_pfr(line)), line)

    def test_pfr_structs_roundtrip(self):
        cases = [
            PFR_STRUCT,
            {"kind": "PFR", "cid": CID, "status": "PARTIAL", "engine": "1.2.3-rc.1",
             "findings": [
                 ("T1-ok", "", "", "static clean"),
                 ("T2-observe", "O_NONCE_FLOOR_VISIBLE", "seq77", "floor 41"),
             ]},
            {"kind": "PFR", "cid": CID, "status": "ERROR", "engine": "0.1.0",
             "findings": [], "error": "X_BAD_OP: unknown op 'vanish'"},
        ]
        for r in cases:
            with self.subTest(r["status"]):
                line = w.render_pfr(r)
                self.assertEqual(w.parse_pfr(line), r)

    def test_details_with_reserved_chars_roundtrip(self):
        r = {"kind": "PFR", "cid": CID, "status": "FAIL", "engine": "0.1.0",
             "findings": [("T1-reject", "E_SIG_INVALID", "",
                           "covers a|b ; not %this")]}
        self.assertEqual(w.parse_pfr(w.render_pfr(r)), r)


if __name__ == "__main__":
    unittest.main()
