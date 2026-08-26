"""T1 determinism/reproducibility tests: same input -> identical output objects.

Also proves offline operation: importing and running the engine must not
require any network access (no socket use anywhere in engine/preflight.py).
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from engine import preflight as pf  # noqa: E402
from tests import vectors as V  # noqa: E402


def snapshot(obj) -> str:
    if hasattr(obj, "__dict__"):
        obj = vars(obj)
    return json.dumps(obj, sort_keys=True, default=str)


class TestDeterminism(unittest.TestCase):
    INPUTS = [
        ("sweep ascii", lambda: pf.sweep("PFS v1 | preflight")),
        ("sweep mixed unicode", lambda: pf.sweep("hi \u200b there 🚀 \t x")),
        ("room ok", lambda: pf.validate_room(V.MAILBOX)),
        ("room bad", lambda: pf.validate_room("BAD ROOM")),
        ("nonce floor ok", lambda: pf.validate_nonce("5", floor=4)),
        ("nonce floor bad", lambda: pf.validate_nonce("4", floor=4)),
        ("audit note", lambda: pf.audit_note(
            "11b17958c4064c71",
            f"{V.SERVICE_DID} mailbox:{V.MAILBOX} engine_version:0.1.0",
            did=V.SERVICE_DID, placed_ns="did-11")),
        ("url estimate", lambda: pf.estimate_request_line(
            "https://technocore.chat", V.MAILBOX, V.SERVICE_DID,
            "R" * 86, 1, "PFS v1 | preflight")),
    ]

    def test_repeated_calls_identical(self):
        for label, fn in self.INPUTS:
            with self.subTest(label):
                first = fn()
                for _ in range(3):
                    again = fn()
                    self.assertEqual(snapshot(first), snapshot(again))

    def test_no_network_imports_in_engine(self):
        src = (ROOT / "engine" / "preflight.py").read_text(encoding="utf-8")
        banned = ["socket", "urllib.request", "requests", "http.client", "curl"]
        for b in banned:
            self.assertNotIn(b, src)

    def test_engine_has_zero_io(self):
        src = (ROOT / "engine" / "preflight.py").read_text(encoding="utf-8")
        for token in ["open(", "Path(", ".read_text", "subprocess"]:
            self.assertNotIn(token, src)

    def test_simulate_nonce_floor_scenarios(self):
        did = V.SERVICE_DID
        tail = [
            {"seq": 1, "from": "~someone", "text": "unsigned chatter"},
            {"seq": 2, "from": did, "text": "signed", "nonce": 10},
            {"seq": 3, "from": f"mention {did} not a writer", "text": "x"},
            {"seq": 4, "from": did, "text": "signed", "nonce": 3},  # out-of-order lower
        ]
        v_low = pf.simulate_nonce_floor(tail, did, "r", "10")   # equal to max -> refuse
        self.assertFalse(v_low.ok)
        v_high = pf.simulate_nonce_floor(tail, did, "r", "11")
        self.assertTrue(v_high.ok)
        v_fresh = pf.simulate_nonce_floor([], did, "r", "1")
        self.assertTrue(v_fresh.ok)
        self.assertEqual(v_fresh.code, "O_NO_PRIOR_WRITES_SEEN")

    def test_signature_roundtrip_with_local_keypair(self):
        # Generate an EPHEMERAL test key locally (not the service identity);
        # sign with cryptography, verify through the engine path.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        import base64
        priv = Ed25519PrivateKey.generate()
        pub_raw = priv.public_key().public_bytes(
            encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
            format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.Raw,
        )
        b58 = "".join([])  # placeholder no-op to keep flake quiet
        did = None  # build via raw key directly; DID encoding covered elsewhere
        canonical = pf.canonical_msg("some-room", 3, "hello")
        sig_raw = priv.sign(canonical)
        sig_b64u = base64.urlsafe_b64encode(sig_raw).decode().rstrip("=")
        v = pf.verify_sig_b64u(pub_raw, sig_b64u, canonical)
        self.assertTrue(v.ok, v.detail)
        # tamper -> must fail
        bad = ("A" if sig_b64u[0] != "A" else "B") + sig_b64u[1:]
        v_bad = pf.verify_sig_b64u(pub_raw, bad, canonical)
        self.assertEqual(v_bad.code, "E_SIG_INVALID")


if __name__ == "__main__":
    unittest.main()
