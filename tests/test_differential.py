"""Differential layer: our engine vs pinned reference implementations.

Layer A: byte-equality against dcpf1/technocore-py protocol.py (imported
         directly) on every input both implementations accept. Documented
         divergence: dcpf1 refuses non-printable-ASCII on signed paths
         (assert_sweep_safe), so differential inputs are restricted to its
         accepted subset -- that refusal is a client policy, not server
         semantics.
Layer B: recorded live-server facts from the service's own initialization
         writes (2026-08-25): genesis record and DID-note receipt.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from engine import preflight as pf  # noqa: E402
from tests import vectors as V  # noqa: E402

# locate dcpf1 protocol.py (pinned copy in Temp; fall back to repo checkout)
DCPF_CANDIDATES = [
    Path(r"C:/Users/karni/AppData/Local/Temp/dcpf_protocol.py"),
    ROOT / "vendor" / "dcpf_protocol.py",
]


def load_dcpf():
    for p in DCPF_CANDIDATES:
        if p.exists():
            spec = importlib.util.spec_from_file_location("dcpf_protocol", p)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    raise FileNotFoundError("dcpf1 protocol.py not available")


class TestDifferentialDcpf1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dcpf = load_dcpf()

    def test_sweep_identity_agreement(self):
        """Byte-equality on inputs where both implementations claim parity:
        dcpf's sweep() is replace-only (no strip, no Cs/Co), so equality
        requires inputs that are strip-neutral AND free of Cs/Co."""
        import unicodedata as ud
        cases = [t for _, t, _ in V.SWEEP_IDENTITY] + \
                [t for _, t, _ in V.SWEEP_REPLACE_SINGLE]
        for text in cases:
            cats = {ud.category(c) for c in text}
            if (cats & {"Cs", "Co"}) or text != text.strip():
                continue
            with self.subTest(repr(text)[:30]):
                theirs = self.dcpf.sweep(text)
                ours = pf.sweep(text).stored
                self.assertEqual(ours, theirs)

    def test_documented_divergence_dcpf_no_strip(self):
        """FINDING (2026-08-26): dcpf1's sweep() omits the server's .strip(),
        so a signed message with leading/trailing spaces is signed over bytes
        the server will store DIFFERENTLY (stripped) -> signature mismatch ->
        403. Our engine models the server exactly (replace->strip->limit).
        Inputs affected: printable-ASCII edges like '  hi  '."""
        text = "  hi  "
        theirs = self.dcpf.msg_payload("lobby", 1, text)      # signs UNSTRIPPED
        ours = pf.canonical_msg("lobby", 1, pf.sweep(text).stored)  # signs STORED form
        self.assertNotEqual(theirs, ours)
        self.assertEqual(pf.sweep(text).stored, "hi")

    def test_known_intentional_divergence_cs_co(self):
        """dcpf's sweep set omits Cs/Co; ours matches the SERVER (which sweeps
        both). On private-use input the two implementations disagree BY DESIGN;
        the server agrees with US."""
        text = "a\ue000b"                      # U+E000, category Co
        theirs = self.dcpf.sweep(text)        # keeps PUA char
        ours = pf.sweep(text).stored          # replaces with space
        self.assertEqual(theirs, text)
        self.assertEqual(ours, "a b")
        self.assertNotEqual(theirs, ours)

    def test_msg_payload_equality(self):
        payloads = [
            ("lobby", 1, "hello world"),
            (V.MAILBOX, 42, "PFS v1 | preflight"),
            ("r", 10**19 - 1, "x" * 100),
        ]
        for room, nonce, text in payloads:
            with self.subTest(room):
                theirs = self.dcpf.msg_payload(room, nonce, text)
                ours = pf.canonical_msg(room, nonce, pf.sweep(text).stored)
                self.assertEqual(ours, theirs)

    def test_note_payload_equality(self):
        theirs = self.dcpf.note_payload("room-owners", "d-jobs", 7, "did:key:z6Mk…")
        ours = pf.canonical_note("room-owners", "d-jobs", 7,
                                 pf.sweep("did:key:z6Mk…").stored)
        self.assertEqual(ours, theirs)

    def test_room_validation_agreement(self):
        names = list(V.ROOMS_VALID) + [n for n, _ in V.ROOMS_INVALID]
        for name in names:
            with self.subTest(repr(name)):
                theirs = self.dcpf.valid_name(name)
                ours = pf.validate_room(name).ok
                self.assertEqual(ours, theirs)

    def test_fingerprint_agreement_and_live_value(self):
        for did in [V.SERVICE_DID, V.REFERENCE_DID]:
            with self.subTest(did[:24]):
                self.assertEqual(pf.fingerprint(did), self.dcpf.fingerprint(did))
        self.assertEqual(pf.fingerprint(V.SERVICE_DID), V.SERVICE_FP)

    def test_encode_segment_agreement(self):
        samples = ["PFS v1 | preflight ; x=1", "日本語", "a b  c"]
        for s in samples:
            with self.subTest(s[:20]):
                enc_ref = self.dcpf.encode_segment(s)
                enc_ours, length = pf.encode_segment(s)
                self.assertEqual(enc_ours, enc_ref)
                self.assertEqual(length, len(enc_ref))

    def test_did_parsing_agreement_on_valid_inputs(self):
        for did in [V.SERVICE_DID, V.REFERENCE_DID]:
            with self.subTest(did[:24]):
                ref_pub = self.dcpf.pub_from_did_key(did)
                our_pub = pf.parse_did(did)
                self.assertEqual(our_pub, bytes(ref_pub))


class TestRecordedLiveFacts(unittest.TestCase):
    """Byte-level assertions against live-server responses recorded during the
    service's own initialization (2026-08-25). Read-only by construction."""

    def test_genesis_canonical_matches_recorded_write(self):
        # The live signed write of seq 1 verified against exactly this payload.
        r = pf.sweep("PFS v1 | preflight | status=initializing ; engine_version:0.1.0")
        canonical = pf.canonical_msg(V.MAILBOX, 1, r.stored).decode("utf-8")
        self.assertEqual(canonical, V.GENESIS_CANONICAL)

    def test_service_did_note_audit_passes(self):
        findings = dict(pf.audit_note(
            placed_key_fp=V.SERVICE_FP,
            value=f"{V.SERVICE_DID} mailbox:{V.MAILBOX} engine_version:0.1.0",
            did=V.SERVICE_DID,
            placed_ns="did-11",
        ))
        self.assertIn("A_OK", findings)

    def test_service_note_placement_is_canonical_sharded(self):
        fp = pf.fingerprint(V.SERVICE_DID)
        shard, rest = fp[:2], fp[2:]
        self.assertEqual(f"/kv/did-{shard}/{rest}", "/kv/did-11/b17958c4064c71")

    def test_legacy_path_detection_flags_flat_namespace(self):
        findings = dict(pf.audit_note(
            placed_key_fp="11b17958c4064c71",
            value=f"{V.SERVICE_DID}",
            placed_ns="did",
        ))
        self.assertIn("W_NOTE_LEGACY_PATH", findings)


if __name__ == "__main__":
    unittest.main()
