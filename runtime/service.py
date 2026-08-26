"""Live service assembly: wiring, bounded long-poll cycles, smoke entrypoint.

The loop is ALWAYS bounded: run_cycles(max_cycles=N) never runs uncontrolled
(spec §5 / gate F6). Each cycle:

    1. read service mailbox via Transport (long-poll wait inside)
    2. drain_snapshot -> decisions (pure) + effects through seams
    3. persist cursor AFTER the batch completes (at-least-once)
       -- crash before save replays the batch; duplicate cids replay
          byte-identical cached PFRs (safe by design)

Fail-closed (gate F1): TransportError aborts the cycle WITHOUT saving the
cursor; the next start re-reads the same window. Signer/transport failures
inside Executor.handle_line raise and are caught per-line only to count them;
they never produce a fabricated response.

PRIVATE-KEY BOUNDARY (spec §0/§4): LocalFileSigner is constructed ONLY here,
ONLY in build_service(), ONLY when explicitly requested. It is never touched
by tests; the passphrase exists solely inside its getpass call.
"""
from __future__ import annotations

import time

from adapter import dispatcher as d
from adapter.http_transport import HttpTransport, TransportError
from runtime.persistence import (
    FileCidCache,
    FileCursor,
    FileNonces,
)


class Service:
    """Wires Transport + persistence + signer into one runnable object."""

    def __init__(self, signer, transport, cache, nonces, cursor,
                 mailbox: str = d.SERVICE_MAILBOX):
        self.executor = d.Executor(signer=signer, transport=transport,
                                   cache=cache, nonces=nonces)
        self.transport = transport
        self.cache = cache
        self.nonces = nonces
        self.cursor = cursor
        self.mailbox = mailbox

    def poll_cycle(self, wait_s: int = 0) -> dict:
        """One bounded read-process-persist cycle. Returns a stats dict."""
        stats = {"read": 0, "replied": 0, "skipped": 0, "failed": 0,
                 "cursor": self.cursor.seq}
        try:
            records = self.transport.read_room_json(
                self.mailbox, since=self.cursor.seq, wait=wait_s)
        except TransportError as exc:
            # Fail closed: cursor untouched, no state advance.
            stats["error"] = f"read failed: {exc}"
            return stats

        stats["read"] = len(records)

        def _seq(r):
            s = r.get("seq")
            return int(s) if isinstance(s, int) else 0

        last_done_seq = None          # last record handled without raising
        aborted_at = None
        processed = self.executor.processed
        skipped = self.executor.skipped
        for rec in sorted(records, key=_seq):
            text = rec.get("text", "")
            if not isinstance(text, str):
                last_done_seq = _seq(rec)      # unprocessable: mark and move on
                continue
            if not text.startswith(d.w.PFQ_PREFIX):
                last_done_seq = _seq(rec)      # noise: never reaches decide()
                continue
            if rec.get("from") == d.SERVICE_DID:
                last_done_seq = _seq(rec)      # self-echo guard (gate F7)
                continue
            try:
                self.executor.handle_line(text, seq_hint=rec.get("seq"))
            except Exception as exc:           # noqa: BLE001 -- fail closed
                # Full detail (status/body head for TransportError) is the
                # whole point of fail-visible diagnostics; class-only logs
                # hid the 2026-08-26 e2e reply-write failure root cause.
                stats["failed"] += 1
                stats.setdefault("failures", []).append(
                    f"seq={rec.get('seq')}: "
                    f"{exc.__class__.__name__}: {exc}")
                # Abort the batch at the first failure (at-least-once): the
                # cursor persists only through the last record that completed
                # cleanly, so the poisoned window is re-read next cycle.
                # Earlier replies replay byte-identical from the cid cache.
                aborted_at = rec.get("seq")
                break
            last_done_seq = _seq(rec)
        stats["replied"] = self.executor.processed - processed
        stats["skipped"] = self.executor.skipped - skipped

        # Persist AFTER processing (at-least-once; duplicates are safe).
        cand = last_done_seq if last_done_seq is not None else 0
        if aborted_at is not None:
            stats["aborted_at_seq"] = aborted_at
        if cand > self.cursor.seq:
            self.cursor.seq = cand
        self.cursor.save()
        stats["cursor"] = self.cursor.seq
        return stats

    def run_cycles(self, max_cycles: int, wait_s: int = 0,
                   between_sleep_s: float = 1.0) -> list[dict]:
        """Bounded batch runner. NEVER an uncontrolled loop."""
        out = []
        for i in range(max(0, int(max_cycles))):
            out.append(self.poll_cycle(wait_s=wait_s))
            if i < max_cycles - 1:
                time.sleep(between_sleep_s)
        return out


def build_service(base_url: str | None = None, live_identity: bool = False):
    """Operator entrypoint.

    live_identity=True constructs LocalFileSigner (getpass prompt for the
    passphrase, operator-typed; never logged). Tests and dry-runs pass
    live_identity=False with any interfaces.Signer (e.g. EphemeralSigner).
    """
    from adapter.signing import LocalFileSigner

    if not live_identity:
        raise ValueError(
            "build_service requires live_identity=True; dry-runs construct "
            "their own Service with a test signer")
    signer = LocalFileSigner(
        pem_path=r"C:\Users\karni\technocore-secrets\identity.pem")
    transport = HttpTransport(**({} if base_url is None
                                 else {"base_url": base_url}))
    return Service(signer=signer, transport=transport,
                   cache=FileCidCache(), nonces=FileNonces(),
                   cursor=FileCursor())
