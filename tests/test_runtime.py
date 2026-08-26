"""Offline tests for the live layer: persistence, cycles, fail-closed paths.

NO network: Transport is an in-memory double (or a raising stub for
fail-closed cases). NO identity.pem: signing uses EphemeralSigner. State
files go to a per-test temp dir, never the real runtime/state/.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adapter import dispatcher as d                     # noqa: E402
from adapter.http_transport import HttpTransport, TransportError  # noqa: E402
from adapter.signing import EphemeralSigner             # noqa: E402
from runtime.persistence import (                        # noqa: E402
    FileCidCache,
    FileCursor,
    FileNonces,
)
from runtime.service import Service                      # noqa: E402

CID = "0123456789abcdef"
REPLY = "mb-p-consumer-0000000000000000"


def pfq(cid=CID, op="preview", **params) -> str:
    base = {"reply": REPLY, "room": "lobby", "nonce": "1",
            "did": d.SERVICE_DID.replace("z6MkvgWDuQjhQfwaqkkDf6SAC9QNg7"
                                         "sCHe9xjbBeUQguQbjd", "z6MkvgWD"),}
    # build a syntactically-valid PFQ with a parseable DID
    base["did"] = ("did:key:z6MkvgWDuQjhQfwaqkkDf6SAC9QNg7sCHe9xjbBeUQguQbjd")
    base.update(params)
    kv = " ; ".join(f"{k}={v}" for k, v in base.items())
    return f"PFQ v1 | {cid} | {op} | {kv}"


class FakeTransport:
    """Programmable in-memory Transport."""

    def __init__(self, batches=None):
        self.batches = list(batches or [])
        self.posted = []
        self.read_calls = []

    def read_room_json(self, room, since, wait=0):
        self.read_calls.append((room, since, wait))
        if self.batches:
            return self.batches.pop(0)
        return []

    def read_note(self, ns, key):
        return None

    def post_signed_message(self, room, did, sig, nonce, swept_text):
        self.posted.append({"room": room, "nonce": nonce,
                            "text": swept_text, "sig": sig})
        return {"seq": 999}


def rec(seq, frm, text):
    return {"seq": seq, "from": frm, "text": text}


def make_service(tmp, batches=None, signer=None):
    return Service(
        signer=signer or EphemeralSigner(),
        transport=FakeTransport(batches),
        cache=FileCidCache(path=tmp / "cache.json"),
        nonces=FileNonces(path=tmp / "nonces.json"),
        cursor=FileCursor(path=tmp / "cursor.json"))


class TestCursorPersistence(unittest.TestCase):
    def test_cursor_survives_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "cursor.json"
            c1 = FileCursor(path=p)
            self.assertEqual(c1.seq, 0)              # absent file -> genesis
            c1.seq = 41
            c1.save()
            c2 = FileCursor(path=p)
            self.assertEqual(c2.seq, 41)

    def test_corrupt_cursor_resets_to_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "cursor.json"
            p.write_text("{not json", encoding="utf-8")
            self.assertEqual(FileCursor(path=p).seq, 0)

    def test_cycle_persists_cursor_after_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            svc = make_service(Path(tmp))
            (Path(tmp) / "cursor.json").parent.mkdir(exist_ok=True)
            noise = [rec(5, "~x", "hello world"), rec(7, "~y", "more")]
            svc.transport.batches = [noise]
            stats = svc.poll_cycle()
            self.assertEqual(stats["cursor"], 7)
            self.assertEqual(FileCursor(
                path=Path(tmp) / "cursor.json").seq, 7)


class TestNoncePersistence(unittest.TestCase):
    def test_nonce_survives_restart_and_always_rises(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "n.json"
            n1 = FileNonces(path=p)
            self.assertEqual(n1.next_nonce(REPLY), 1)
            n1.observe_written(REPLY, 1)
            n1.observe_written(REPLY, 5)             # jumps are allowed
            n2 = FileNonces(path=p)
            self.assertEqual(n2.next_nonce(REPLY), 6)
            n2.observe_written(REPLY, 4)             # stale observation ignored
            self.assertEqual(n2.next_nonce(REPLY), 6)


class TestCidCacheTTL(unittest.TestCase):
    def test_replay_within_ttl_expired_after(self):
        t = {"now": 1000.0}
        with tempfile.TemporaryDirectory() as tmp:
            c = FileCidCache(path=Path(tmp) / "c.json", ttl_s=100,
                             now=lambda: t["now"])
            c.remember(CID, REPLY, "PFR v1 | x | PASS | engine=0.1.0 ; T1-ok")
            t["now"] = 1099
            self.assertIsNotNone(c.lookup(CID))      # inside window
            t["now"] = 1101
            self.assertIsNone(c.lookup(CID))         # expired -> pruned

    def test_cache_survives_restart_with_ttl(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "c.json"
            t = {"now": 10.0}
            c1 = FileCidCache(path=p, ttl_s=100, now=lambda: t["now"])
            c1.remember(CID, REPLY, "line")
            t["now"] = 50.0
            c2 = FileCidCache(path=p, ttl_s=100, now=lambda: t["now"])
            self.assertEqual(c2.lookup(CID), (REPLY, "line"))
            t["now"] = 200.0                         # beyond TTL after restart
            self.assertIsNone(c2.lookup(CID))


class TestServiceCycles(unittest.TestCase):
    def test_valid_pfq_produces_signed_pfr_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            svc = make_service(Path(tmp), batches=[
                [rec(2, "~client", pfq())]])
            stats = svc.poll_cycle()
            self.assertEqual(stats["failed"], 0)
            self.assertEqual(stats["replied"], 1)
            self.assertEqual(len(svc.transport.posted), 1)
            post = svc.transport.posted[0]
            self.assertEqual(post["room"], REPLY)
            self.assertTrue(post["text"].startswith(f"PFR v1 | {CID} | "))
            self.assertEqual(len(post["sig"]), 86)
            self.assertGreaterEqual(stats["cursor"], 2)
            # duplicate redelivery replays byte-identical from cache
            svc.transport.batches = [[rec(2, "~client", pfq())]]
            stats2 = svc.poll_cycle(wait_s=0)
            self.assertEqual(stats2["replied"], 1)
            self.assertEqual(svc.transport.posted[-1]["text"],
                             post["text"])           # byte-identical

    def test_self_echo_suppressed_without_post(self):
        with tempfile.TemporaryDirectory() as tmp:
            svc = make_service(Path(tmp), batches=[[
                rec(3, d.SERVICE_DID, pfq(cid="ffffffffffffffff")),
            ]])
            stats = svc.poll_cycle()
            self.assertEqual(stats["replied"], 0)
            self.assertEqual(len(svc.transport.posted), 0)
            self.assertEqual(stats["cursor"], 3)      # still advances

    def test_transport_failure_fails_closed_keeps_cursor(self):
        with tempfile.TemporaryDirectory() as tmp:
            svc = make_service(Path(tmp))

            class Broken(FakeTransport):
                def read_room_json(self, room, since, wait=0):
                    raise TransportError("simulated outage", status=503)

            broken = Broken()
            broken.posted = svc.transport.posted
            svc.transport = broken
            before = svc.cursor.seq
            stats = svc.poll_cycle()
            self.assertIn("error", stats)
            self.assertEqual(stats.get("read", 0), 0)
            self.assertEqual(svc.cursor.seq, before)  # nothing advanced

    def test_signer_failure_aborts_batch_before_bad_record(self):
        class FragileSigner(EphemeralSigner):
            """Allows `allow` signatures, then fails until re-armed."""

            def __init__(self):
                super().__init__()
                self.successes = 0
                self.allow = 1

            def sign_canonical(self, canonical):
                if self.successes >= self.allow:
                    raise RuntimeError("HSM unplugged")
                sig = super().sign_canonical(canonical)
                self.successes += 1
                return sig

        with tempfile.TemporaryDirectory() as tmp:
            signer = FragileSigner()
            svc = make_service(Path(tmp), signer=signer, batches=[[
                rec(2, "~a", pfq(cid="aaaaaaaaaaaaaaaa")),
                rec(3, "~b", pfq(cid="bbbbbbbbbbbbbbbb")),   # signer dies here
                rec(4, "~c", pfq(cid="cccccccccccccccc")),   # never processed
            ]])
            stats = svc.poll_cycle()
            self.assertEqual(stats["failed"], 1)
            self.assertEqual(stats["aborted_at_seq"], 3)
            self.assertEqual(stats["cursor"], 2)     # last cleanly-done record
            self.assertEqual(len(svc.transport.posted), 1)
            # retry re-reads the poisoned window; first cid replays cached
            svc.transport.batches = [[
                rec(3, "~b", pfq(cid="bbbbbbbbbbbbbbbb")),
                rec(4, "~c", pfq(cid="cccccccccccccccc")),
            ]]
            signer.allow = 99                         # HSM back online
            stats2 = svc.poll_cycle()
            self.assertEqual(stats2["failed"], 0)
            self.assertEqual(stats2["cursor"], 4)
            self.assertEqual(len(svc.transport.posted), 3)

    def test_malformed_pfq_routes_error_via_salvage(self):
        bad = pfq().replace("| preview |", "| warp |", 1)
        with tempfile.TemporaryDirectory() as tmp:
            svc = make_service(Path(tmp), batches=[[rec(6, "~x", bad)]])
            stats = svc.poll_cycle()
            self.assertEqual(stats["failed"], 0)
            self.assertEqual(len(svc.transport.posted), 1)
            post = svc.transport.posted[0]
            self.assertEqual(post["room"], REPLY)
            self.assertIn("| ERROR | ", post["text"])
            self.assertNotIn(str(CID), str(svc.cache.store))  # never cached

    def test_empty_reply_room_never_posted_at_service_level(self):
        from dataclasses import replace as dc_replace
        with tempfile.TemporaryDirectory() as tmp:
            svc = make_service(Path(tmp))
            hostile = dc_replace(d.decide(pfq()), reply_room="")
            posted_before = len(svc.transport.posted)
            result = svc.executor._post_decision("", hostile.pfr_line)
            self.assertFalse(result)
            self.assertEqual(len(svc.transport.posted), posted_before)

    def test_reply_write_failure_aborts_batch_and_records_detail(self):
        """Regression for the 2026-08-26 live e2e failure: reply-write
        TransportError at the PFQ record aborts the batch, holds the cursor
        at the last cleanly-handled record, and records the FULL error
        (status included), not just the exception class."""
        class FailingReplyTransport(FakeTransport):
            def post_signed_message(self, room, did, sig, nonce, swept_text):
                raise TransportError(
                    "GET failed: Not Found", status=404)

        with tempfile.TemporaryDirectory() as tmp:
            svc = Service(
                signer=EphemeralSigner(),
                transport=FailingReplyTransport(),
                cache=FileCidCache(path=Path(tmp) / "c.json"),
                nonces=FileNonces(path=Path(tmp) / "n.json"),
                cursor=FileCursor(path=Path(tmp) / "cur.json"))
            svc.transport.batches = [[
                rec(1, d.SERVICE_DID, "PFS v1 | preflight | status=initializing"),
                rec(2, "~client", pfq()),
            ]]
            stats = svc.poll_cycle()
        # mirrors the observed live cycle exactly:
        self.assertEqual(stats["read"], 2)
        self.assertEqual(stats["replied"], 0)
        self.assertEqual(stats["failed"], 1)
        self.assertEqual(stats["aborted_at_seq"], 2)
        self.assertEqual(stats["cursor"], 1)          # self-echo done only
        # detail is fail-visible: class AND status survive into stats
        self.assertIn("TransportError", stats["failures"][0])
        self.assertIn("404", stats["failures"][0])


if __name__ == "__main__":
    unittest.main()
