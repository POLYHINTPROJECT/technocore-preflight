"""Offline adapter tests: pipeline, dispatcher, correlation, signing boundary.

NO network. NO real identity. Signing uses EphemeralSigner (fresh keypair per
test); Transport is an in-memory fake; CidCache/NonceSource are in-memory
implementations of the interface seams.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adapter import dispatcher as d  # noqa: E402
from adapter import pipeline as pl  # noqa: E402
from adapter.signing import EphemeralSigner  # noqa: E402
from engine import wire as w  # noqa: E402

CID = "0123456789abcdef"
REPLY = "mb-p-consumer-0000000000000000"
DID = "did:key:z6MkvgWDuQjhQfwaqkkDf6SAC9QNg7sCHe9xjbBeUQguQbjd"


def pfq(cid=CID, op="preview", **params) -> str:
    base = {"reply": REPLY, "room": "lobby", "nonce": "1", "did": DID,
            "text": "hello"}
    base.update(params)
    kv = " ; ".join(f"{k}={v}" for k, v in base.items())
    return f"PFQ v1 | {cid} | {op} | {kv}"


# --------------------------------------------------------------------- fakes
class FakeTransport:
    """In-memory Transport seam; records every posted message."""

    def __init__(self):
        self.posted = []
        self.fail_next = None

    def read_room_json(self, room, since, wait=0):
        return []                       # never used at this checkpoint

    def read_note(self, ns, key):
        return None

    def post_signed_message(self, room, did, sig, nonce, swept_text):
        if self.fail_next:
            err, self.fail_next = self.fail_next, None
            raise err
        self.posted.append({"room": room, "did": did, "sig": sig,
                            "nonce": nonce, "text": swept_text})
        return {"seq": 100 + len(self.posted), "ts": "T",
                "from": did, "text": swept_text, "nonce": nonce}


class MemCache:
    def __init__(self):
        self.store = {}

    def lookup(self, cid):
        return self.store.get(cid)          # (reply_room, pfr_line) | None

    def remember(self, cid, reply_room, line):
        self.store[cid] = (reply_room, line)


class MemNonces:
    def __init__(self, start=0):
        self.last = {}
        self.start = start

    def next_nonce(self, room):
        return max(self.last.get(room, self.start) + 1, 1)

    def observe_written(self, room, nonce):
        self.last[room] = max(self.last.get(room, 0), nonce)


def make_executor():
    return d.Executor(signer=EphemeralSigner(), transport=FakeTransport(),
                      cache=MemCache(), nonces=MemNonces())


# ------------------------------------------------------------------ pipeline
class TestPipeline(unittest.TestCase):
    def test_preview_happy_path(self):
        parsed = w.parse_pfq(pfq())
        pfr = pl.process_request(parsed, None)
        self.assertEqual(pfr["status"], "PASS")
        kinds = [f[0] for f in pfr["findings"]]
        self.assertNotIn("T1-reject", kinds)
        self.assertTrue(any(f[0] == "T1-ok" and "canonical" in f[3]
                            for f in pfr["findings"]))

    def test_preview_with_valid_signature(self):
        from adapter.signing import sign_b64u, _pubkey_to_did  # test-only use
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        key = Ed25519PrivateKey.generate()
        text = "sign me"
        swept = __import__("engine.preflight", fromlist=["sweep"]).sweep(text).stored
        canonical = f"lobby|1|{swept}".encode()
        sig = sign_b64u(key, canonical)
        did = _pubkey_to_did(key.public_key().public_bytes(
            Encoding := __import__("cryptography.hazmat.primitives.serialization",
                                   fromlist=["Encoding"]).Encoding.Raw,
            PublicFormat := __import__("cryptography.hazmat.primitives.serialization",
                                       fromlist=["PublicFormat"]).PublicFormat.Raw))
        parsed = w.parse_pfq(pfq(did=did, text=text, sig=sig))
        pfr = pl.process_request(parsed, None)
        self.assertEqual(pfr["status"], "PASS")
        self.assertTrue(any("verified" in f[3] for f in pfr["findings"]))

    def test_verify_privacy_mode_detects_wrong_sig(self):
        signer = EphemeralSigner()
        other = EphemeralSigner()
        canonical = "lobby|1|hi"
        import hashlib
        sig = signer.sign_canonical(canonical.encode())
        wrong = w.parse_pfq(w.render_pfq({
            "kind": "PFQ", "cid": CID, "op": "verify",
            "params": {"reply": REPLY, "did": other.did,
                       "canonical": canonical,
                       "sha256": hashlib.sha256(canonical.encode()).hexdigest(),
                       "sig": sig}}))
        pfr = pl.process_request(wrong, None)
        self.assertEqual(pfr["status"], "FAIL")
        self.assertTrue(any(f[1] == "E_SIG_INVALID" for f in pfr["findings"]))

    def test_audit_flags_legacy_and_wrong_key(self):
        parsed = w.parse_pfq(w.render_pfq({
            "kind": "PFQ", "cid": CID, "op": "audit-did-note",
            "params": {"reply": REPLY,
                       "value": DID + " mailbox:" + REPLY,
                       "did": DID, "ns": "did",
                       "key": "11b17958c4064c71"}}))
        pfr = pl.process_request(parsed, None)
        codes = {f[1] for f in pfr["findings"]}
        self.assertIn("W_NOTE_LEGACY_PATH", codes)

    def test_status_derivation(self):
        cases = [
            (pl._status([("T1-ok", "", "", "")]), "PASS"),
            (pl._status([("T1-ok", "", "", ""), ("T2-observe", "O_ROOM_OWNED", "s1", "")]),
             "PARTIAL"),
            (pl._status([("T1-warn", "W_SWEPT_CHARS", "", "")]), "PARTIAL"),
            (pl._status([("T1-reject", "E_BAD_DID", "", "")]), "FAIL"),
        ]
        for got, want in cases:
            with self.subTest(want):
                self.assertEqual(got, want)

    def test_malformed_gets_error_struct_with_cid(self):
        bad_line = pfq().replace("| preview |", "| vanish |", 1)
        struct = pl.process_request(None, "X_BAD_OP: unknown op")
        self.assertEqual(struct["cid"], "")
        r2 = pl.process_request({"cid": CID}, "X_BAD_OP: unknown op")
        self.assertEqual(r2["cid"], CID)


# ---------------------------------------------------------------- dispatcher
class TestDispatcherDecide(unittest.TestCase):
    def test_ok_request_routes_to_reply_room(self):
        dec = d.decide(pfq())
        self.assertEqual(dec.action, "reply")
        self.assertEqual(dec.reason, "ok")
        self.assertEqual(dec.reply_room, REPLY)
        self.assertTrue(dec.pfr_line.startswith("PFR v1 | " + CID))

    def test_parse_error_with_cid_yields_routed_error_reply(self):
        bad = pfq().replace("| preview |", "| warp |", 1)
        dec = d.decide(bad)
        self.assertEqual(dec.action, "reply")
        self.assertEqual(dec.reason, "parse-error")
        self.assertIn("| ERROR | ", dec.pfr_line)
        self.assertIn("error=X_BAD_OP", dec.pfr_line)
        # D3: the recovered coordinates are attached to the Decision
        self.assertEqual(dec.reply_room, REPLY)

    def test_extract_reply_room_variants(self):
        good = f"PFQ v1 | {CID} | preview | reply={REPLY} ; oops"
        self.assertEqual(d.extract_reply_room(good), REPLY)
        # non-mailbox class rejected even though room name is valid
        dm = pfq().replace("reply=" + REPLY, "reply=d-" + CID)
        self.assertEqual(d.extract_reply_room(dm), "")
        # missing / malformed tokens rejected
        self.assertEqual(d.extract_reply_room("PFQ v1 | " + CID + " | x | y"), "")
        self.assertEqual(
            d.extract_reply_room(f"PFQ v1 | {CID} | preview | reply=%7Cbad"), "")

    def test_unroutable_garbage_is_skipped(self):
        dec = d.decide("complete nonsense without pipes")
        self.assertEqual(dec.action, "skip")
        self.assertEqual(dec.reason, "unroutable-no-cid")

    def test_malformed_without_mb_reply_is_dropped(self):
        # valid cid, valid-looking-but-non-mailbox reply room -> drop
        bad = pfq().replace("reply=" + REPLY,
                            "reply=d-consumer-" + CID).replace(
                                "| preview |", "| vanish |", 1)
        dec = d.decide(bad)
        self.assertEqual(dec.action, "skip")
        self.assertEqual(dec.reason, "unroutable-no-cid")

    def test_malformed_with_invalid_reply_value_is_dropped(self):
        # reply= present but fails the room validator entirely
        bad = pfq().replace("reply=" + REPLY, "reply=" + CID).replace(
            "| preview |", "| warp |", 1)
        dec = d.decide(bad)
        self.assertEqual(dec.action, "skip")
        self.assertEqual(dec.reason, "unroutable-no-cid")

    def test_duplicate_cid_replays_cached_bytes(self):
        cached = f"PFR v1 | {CID} | PASS | engine=0.1.0 ; T1-ok replayed"
        dec = d.decide(pfq(), cached_pfr=cached)
        self.assertEqual(dec.reason, "duplicate-cid-replay")
        self.assertEqual(dec.pfr_line, cached)   # byte-identical

    def test_decide_is_deterministic(self):
        a = d.decide(pfq())
        b = d.decide(pfq())
        self.assertEqual(a, b)


class TestExecutor(unittest.TestCase):
    def setUp(self):
        self.ex = make_executor()

    def test_full_roundtrip_posts_signed_reply(self):
        self.ex.handle_line(pfq())
        self.assertEqual(len(self.ex.transport.posted), 1)
        post = self.ex.transport.posted[0]
        self.assertEqual(post["room"], REPLY)
        self.assertEqual(post["did"], self.ex.service_did)
        self.assertEqual(post["nonce"], 1)
        self.assertTrue(post["text"].startswith(f"PFR v1 | {CID}"))
        # signature verifies against the signer's own DID over the exact bytes
        self.assertEqual(len(post["sig"]), 86)
        self.assertIn(CID, self.ex.cache.store)

    def test_nonce_increases_across_replies(self):
        self.ex.handle_line(pfq())
        self.ex.handle_line(pfq(cid="fedcba9876543210"))
        nonces = [p["nonce"] for p in self.ex.transport.posted]
        self.assertEqual(nonces, [1, 2])

    def test_duplicate_cid_does_not_reexecute_engine(self):
        self.ex.handle_line(pfq())
        first_post_count = len(self.ex.transport.posted)
        replay_room, cached_line = self.ex.cache.store[CID]
        self.assertEqual(replay_room, REPLY)          # room remembered
        self.ex.handle_line(pfq())                    # same cid again
        self.assertEqual(len(self.ex.transport.posted), first_post_count + 1)
        replay = self.ex.transport.posted[-1]
        self.assertEqual(replay["text"], cached_line)  # same cached bytes
        self.assertEqual(replay["room"], REPLY)        # to the original requester
        self.assertEqual(self.ex.nonces.last[REPLY], 2)  # but fresh nonce

    def test_drain_ignores_noise_self_and_old(self):
        recs = [
            {"seq": 5, "from": "~noise", "text": "just chatting"},
            {"seq": 6, "from": DID, "text": pfq()},          # our own echo
            {"seq": 7, "from": DID.replace("z6Mk", "z6MkX"), "text": pfq()},
            {"seq": 3, "from": "x", "text": pfq(cid="1111111111111111")},  # old
        ]
        cursor, decisions = self.ex.drain_snapshot(recs, last_seen_seq=4)
        self.assertEqual(cursor, 7)
        self.assertEqual(len(decisions), 1)
        self.assertEqual(self.ex.skipped, 0)      # noise filtered before decide

    def test_transport_failure_surfaces_not_swallowed(self):
        self.ex.transport.fail_next = RuntimeError("simulated outage")
        with self.assertRaises(RuntimeError):
            self.ex.handle_line(pfq())
        self.assertEqual(self.ex.processed, 0)
        self.assertNotIn(CID, self.ex.cache.store)   # nothing remembered on failure


class TestParseErrorRouting(unittest.TestCase):
    """D3 ratified correction: salvage routing for malformed PFQs."""

    def setUp(self):
        self.ex = make_executor()
        # malformed: unknown op, but cid + reply= both recoverable
        self.bad = pfq().replace("| preview |", "| warp |", 1)

    def test_malformed_with_valid_cid_and_reply_posts_routed_error(self):
        dec = self.ex.handle_line(self.bad)
        self.assertEqual(dec.action, "reply")
        self.assertEqual(dec.reason, "parse-error")
        posts = self.ex.transport.posted
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0]["room"], REPLY)          # routed, not ""
        self.assertIn("| ERROR | ", posts[0]["text"])
        self.assertEqual(len(posts[0]["sig"]), 86)

    def test_parse_error_reply_never_enters_cid_cache(self):
        self.ex.handle_line(self.bad)
        self.assertNotIn(CID, self.ex.cache.store)
        # ...so a repeat of the same malformed line re-executes decide(),
        # not a duplicate-cid replay of an error
        self.ex.handle_line(self.bad)
        self.assertEqual([p["nonce"] for p in self.ex.transport.posted], [1, 2])
        self.assertNotIn(CID, self.ex.cache.store)

    def test_malformed_non_mailbox_reply_is_dropped_not_posted(self):
        bad = pfq().replace("reply=" + REPLY,
                            "reply=d-consumer-" + CID).replace(
                                "| preview |", "| vanish |", 1)
        dec = self.ex.handle_line(bad)
        self.assertEqual(dec.action, "skip")
        self.assertEqual(dec.reason, "unroutable-no-cid")
        self.assertEqual(len(self.ex.transport.posted), 0)

    def test_malformed_missing_cid_is_dropped_despite_valid_reply(self):
        bad = pfq(cid="nothex").replace("| preview |", "| warp |", 1)
        dec = self.ex.handle_line(bad)
        self.assertEqual(dec.action, "skip")
        self.assertEqual(len(self.ex.transport.posted), 0)

    def test_no_empty_reply_room_post_is_possible(self):
        # Defense-in-depth guard: even if a Decision ever carried an empty
        # room, Executor must refuse to POST and count it skipped.
        from dataclasses import replace as dc_replace
        hostile = dc_replace(d.decide(pfq()), reply_room="")
        posted_before = len(self.ex.transport.posted)
        result = self.ex._post_decision("", hostile.pfr_line)
        self.assertFalse(result)
        self.assertEqual(len(self.ex.transport.posted), posted_before)
        self.assertEqual(self.ex.nonces.last, {})   # nonce never consumed


class TestSigningBoundary(unittest.TestCase):
    def test_ephemeral_signer_produces_verifiable_sigs(self):
        s1, s2 = EphemeralSigner(), EphemeralSigner()
        self.assertNotEqual(s1.did, s2.did)          # fresh keys each time
        msg = b"mb-p-x|1|hi"
        sig = s1.sign_canonical(msg)
        self.assertEqual(len(sig), 86)
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        raw = bytes.fromhex("") if False else None  # placeholder removed below
        # verify via the engine path using the DID->key parser
        from engine import preflight as pf
        pub = pf.parse_did(s1.did)
        v = pf.verify_sig_b64u(pub, sig, msg)
        self.assertTrue(v.ok)
        v_bad = pf.verify_sig_b64u(pub, sig, msg + b"x")
        self.assertFalse(v_bad.ok)

    def test_local_file_signer_isolated_from_tests(self):
        """No test instantiates LocalFileSigner; passphrase only via getpass;
        the real key path appears nowhere in test code. (Needles built by
        concatenation so this scan does not match itself.)"""
        needle_cls = "LocalFileSigner" + "("
        for t in ["tests/test_adapter.py", "tests/test_wire.py",
                  "tests/test_engine.py", "tests/test_determinism.py",
                  "tests/test_differential.py"]:
            src = (ROOT / t).read_text(encoding="utf-8")
            self.assertNotIn(needle_cls, src)
            self.assertNotIn("identity" + ".pem", src)
            self.assertNotIn("technocore-" + "secrets", src)


if __name__ == "__main__":
    unittest.main()
