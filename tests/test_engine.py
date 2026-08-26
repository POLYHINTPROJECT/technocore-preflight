"""Engine conformance tests against source-derived vectors. Offline only."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests import vectors as V  # noqa: E402
from engine import preflight as pf  # noqa: E402


class TestSweepIdentity(unittest.TestCase):
    def test_identity_cases(self):
        for label, text, expected in V.SWEEP_IDENTITY:
            with self.subTest(label):
                r = pf.sweep(text)
                self.assertEqual(r.stored, expected)

    def test_replacement_cases(self):
        for label, text, expected in V.SWEEP_REPLACE_SINGLE:
            with self.subTest(label):
                r = pf.sweep(text)
                self.assertEqual(r.stored, expected, f"input={text!r}")
                # CRLF carries two invisible chars -> two replacements
                self.assertEqual(r.change_count,
                                 2 if label == "CRLF = two spaces" else 1,
                                 f"input={text!r}")

    def test_change_report_fields(self):
        r = pf.sweep("a\u200db")
        self.assertEqual(r.changes[0], (1, "U+200D", "Cf"))
        self.assertFalse(r.truncated_change_list)
        import hashlib
        self.assertEqual(r.sha256_hex, hashlib.sha256(b"a b").hexdigest())

    def test_empty_after_sweep(self):
        for label, text in V.SWEEP_EMPTY_AFTER:
            with self.subTest(label):
                with self.assertRaises(pf.PreflightError) as ctx:
                    pf.sweep(text)
                self.assertIn("E_EMPTY_AFTER_SWEEP", str(ctx.exception))

    def test_zwj_family_flattens(self):
        family = "\U0001F468\u200D\U0001F469\u200D\U0001F467"   # ZWJ emoji sequence
        r = pf.sweep(family)
        # Mechanism-exact: each ZWJ (Cf) -> space; emoji themselves survive.
        # Server docstring calls this "flattening": 👨👩👧 -> 👨 👩 👧
        self.assertEqual(r.stored, "👨 👩 👧")
        self.assertEqual(r.change_count, 2)


class TestLengthBoundaries(unittest.TestCase):
    def test_boundaries(self):
        for label, raw, outcome in V.length_boundary_cases():
            with self.subTest(label):
                if outcome[0] == "raise":
                    with self.assertRaises(pf.PreflightError) as ctx:
                        pf.sweep(raw)
                    self.assertIn(outcome[1], str(ctx.exception))
                else:
                    r = pf.sweep(raw)
                    self.assertEqual(r.char_len, outcome[1])


class TestWireDecode(unittest.TestCase):
    def test_wire_cases(self):
        for label, raw, expected in V.WIRE_CASES:
            with self.subTest(label):
                decoded = pf.wire_decode(raw)
                self.assertEqual(decoded, expected)

    def test_fffd_survives_full_pipeline(self):
        # wire -> decode -> sweep keeps U+FFFD (So is not swept)
        stored = pf.sweep(pf.wire_decode(b"a\x80b")).stored
        self.assertEqual(stored, "a\ufffd b".replace(" ", ""))


class TestRooms(unittest.TestCase):
    def test_valid_rooms(self):
        for name in V.ROOMS_VALID:
            with self.subTest(name):
                v = pf.validate_room(name)
                self.assertTrue(v.ok, v.detail)

    def test_invalid_rooms(self):
        for name, why in V.ROOMS_INVALID:
            with self.subTest(why):
                v = pf.validate_room(name)
                self.assertFalse(v.ok)
                self.assertEqual(v.code, "E_BAD_ROOM")

    def test_class_traps(self):
        for name, classes in V.ROOM_CLASS_TRAPS:
            with self.subTest(name):
                v = pf.validate_room(name)
                self.assertTrue(v.ok)
                raw = v.detail.split("classes=")[1] if "classes=" in v.detail else ""
                got = tuple(t for t in raw.split(",") if t and t != "none")
                self.assertTupleEqual(got, classes)


class TestNonce(unittest.TestCase):
    def test_format_valid(self):
        for n in V.NONCE_VALID:
            with self.subTest(n):
                v = pf.validate_nonce(n)
                self.assertTrue(v.ok or v.code == "W_LEADING_ZERO_NONCE")

    def test_format_invalid(self):
        for n in V.NONCE_FORMAT_INVALID:
            with self.subTest(repr(n)):
                v = pf.validate_nonce(n)
                self.assertFalse(v.ok)
                self.assertEqual(v.code, "E_BAD_NONCE_FORMAT")

    def test_leading_zero_warns_but_passes(self):
        for n in V.NONCE_LEADING_ZERO_WARN:
            with self.subTest(n):
                v = pf.validate_nonce(n)
                self.assertTrue(v.ok)
                self.assertEqual(v.code, "W_LEADING_ZERO_NONCE")

    def test_floor_ordering(self):
        for floor, proposed, expect_ok in V.NONCE_FLOOR_CASES:
            with self.subTest(f"{proposed} vs floor {floor}"):
                v = pf.validate_nonce(proposed, floor=floor)
                self.assertEqual(v.ok, expect_ok,
                                 f"got {v.code}: {v.detail}")
                if not expect_ok:
                    self.assertEqual(v.code, "E_NONCE_NOT_GREATER")


class TestDid(unittest.TestCase):
    def test_reference_and_service_did_parse(self):
        pub = pf.parse_did(V.REFERENCE_DID)
        self.assertEqual(len(pub), 32)
        pub2 = pf.parse_did(V.SERVICE_DID)
        self.assertEqual(len(pub2), 32)

    def test_malformed_dids(self):
        for did, why in V.DID_MALFORMED:
            with self.subTest(why):
                with self.assertRaises(pf.PreflightError) as ctx:
                    pf.parse_did(did)
                self.assertIn("E_BAD_DID", str(ctx.exception))

    def test_fingerprint_matches_live_verified_value(self):
        self.assertEqual(pf.fingerprint(V.SERVICE_DID), V.SERVICE_FP)

    def test_fingerprint_of_reference_example(self):
        # dcpf1 docstring records the live path /kv/did-b5/f10998c3a88a93 for this DID.
        did = "did:key:z6MkmzyBxvrSZveZv5YhZhfwUYQYv5LDgt5NuqVrBe5vXvPA"
        self.assertEqual(pf.fingerprint(did), "b5f10998c3a88a93")


class TestSigEncoding(unittest.TestCase):
    def test_encoding_gate_runs_before_crypto(self):
        pub = pf.parse_did(V.SERVICE_DID)
        canonical = pf.canonical_msg(
            "r", 1, "x").replace(b"x", b"x")     # any bytes; encoding check fires first
        for bad in V.SIG_MALFORMED:
            with self.subTest(f"len {len(bad)}"):
                v = pf.verify_sig_b64u(pub, bad, canonical)
                self.assertEqual(v.code, "E_BAD_SIG_ENCODING")


if __name__ == "__main__":
    unittest.main()
