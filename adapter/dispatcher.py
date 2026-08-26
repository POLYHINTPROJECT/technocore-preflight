"""Dispatcher: pure route decisions + one executor applying them.

`decide()` is a PURE function from (raw line, cached-PFR-or-None) to a
Decision describing exactly what should happen. `Executor.apply()` turns
decisions into effects -- every effect flows through an injected seam from
interfaces.py (Signer / Transport / CidCache / NonceSource). No network code
exists in this module.

Parse-error salvage (ratified D3 correction, 2026-08-26): a malformed PFQ
gets a routed ERROR reply only when BOTH coordinates are independently
recoverable and valid -- the 16-hex cid (regex-checked) and a reply=
mailbox (decoded, room-validated, and required to carry the mb- class,
using the SAME validator the strict parser uses). Anything else --
including lines that lack the PFQ prefix entirely -- is dropped as
unroutable: no trusted reply address exists. Parse-error replies are
never written to the cid cache.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace

from adapter import pipeline as pl
from engine import preflight as pf
from engine import wire as w

SERVICE_DID = "did:key:z6MkvgWDuQjhQfwaqkkDf6SAC9QNg7sCHe9xjbBeUQguQbjd"
SERVICE_MAILBOX = "mb-p-preflight-11b17958c4064c71"
_SEQ_RE = re.compile(r"\d+")


@dataclass(frozen=True)
class Decision:
    """What should happen to one raw mailbox line. Pure data."""
    action: str                    # "reply" | "skip"
    reason: str                    # ok | parse-error | duplicate-cid-replay |
                                   # unroutable-no-cid | not-a-request | self-echo
    reply_room: str = ""           # where the answer goes ("" -> no route)
    pfr_line: str = ""             # complete rendered response line
    seq_hint: int | None = None    # request seq when the caller knows it


def extract_cid(line: str) -> str:
    """Best-effort cid salvage for correlation only; never trusted further."""
    parts = line.split("|")
    if len(parts) >= 2:
        cand = parts[1].strip()
        if w.CID_RE.fullmatch(cand):
            return cand
    return ""


_REPLY_TOKEN_RE = re.compile(r"(?:^|[|;])\s*reply\s*=\s*([^;]+)", re.IGNORECASE)


def extract_reply_room(line: str) -> str:
    """Independent reply= salvage for parse-error routing (D3).

    Returns the decoded candidate room ONLY if it passes the exact same
    validation the strict parser applies (room regex + mb- mailbox class);
    otherwise "" -- a syntactically present but invalid room is NOT a
    trusted reply address.
    """
    m = _REPLY_TOKEN_RE.search(line)
    if not m:
        return ""
    try:
        cand = w.decode_value(m.group(1).strip())
        v = pf.validate_room(cand)
    except pf.PreflightError:
        return ""
    if not v.ok:
        return ""
    try:
        if "mb" not in pf._room_classes(cand):
            return ""
    except pf.PreflightError:
        return ""
    return cand


def decide(raw_line: str, cached_pfr: str | None = None,
           engine_version: str = pl.ENGINE_VERSION) -> Decision:
    """Pure: raw mailbox line -> Decision. Deterministic given inputs."""
    if cached_pfr is not None:
        # Duplicate cid: replay the SAME bytes; never re-execute (spec §5).
        return Decision(action="reply", reason="duplicate-cid-replay",
                        pfr_line=cached_pfr)

    parsed = None
    parse_error = None
    try:
        parsed = w.parse_pfq(raw_line)
    except w.WireError as exc:
        parse_error = exc.code

    struct = pl.process_request(parsed, parse_error, engine_version)
    cid = struct.get("cid", "")

    if struct["status"] == "ERROR":
        # D3 salvage: recover BOTH coordinates independently from the raw
        # line. The cid must be regex-valid; the reply room must pass the
        # same validator the strict parser uses (room + mb- class). Route
        # only when BOTH are safely recoverable; otherwise drop.
        if not cid:
            salvaged = extract_cid(raw_line)
            if salvaged:
                struct["cid"] = salvaged
                cid = salvaged
        reply_room = extract_reply_room(raw_line)
        if not cid or not reply_room:
            return Decision(action="skip", reason="unroutable-no-cid")
        return Decision(action="reply", reason="parse-error",
                        reply_room=reply_room, pfr_line=w.render_pfr(struct))

    reply_room = parsed["params"]["reply"]
    return Decision(action="reply", reason="ok", reply_room=reply_room,
                    pfr_line=w.render_pfr(struct))


class Executor:
    """Applies Decisions through injected seams. The only effectful object."""

    def __init__(self, signer, transport, cache, nonces,
                 service_did: str = SERVICE_DID):
        self.signer = signer          # interfaces.Signer
        self.transport = transport    # interfaces.Transport
        self.cache = cache            # interfaces.CidCache
        self.nonces = nonces          # interfaces.NonceSource
        self.service_did = service_did
        self.processed = 0
        self.skipped = 0

    def handle_line(self, raw_line: str, seq_hint: int | None = None) -> Decision:
        cid = extract_cid(raw_line)
        cached = self.cache.lookup(cid) if cid else None
        decision = decide(raw_line, cached_pfr=cached)

        if decision.action != "reply":
            self.skipped += 1
            return decision

        if decision.reason == "duplicate-cid-replay":
            reply_room, pfr_line = cached     # replay to the ORIGINAL requester
        else:
            reply_room, pfr_line = decision.reply_room, decision.pfr_line

        if self._post_decision(reply_room, pfr_line):
            if decision.reason == "ok":
                self.cache.remember(cid, reply_room, pfr_line)
            self.processed += 1
            return decision
        # Refused: no validated reply address exists (D3). Drop, never post.
        self.skipped += 1
        return replace(decision, action="skip", reason="unroutable-no-cid")

    def _post_decision(self, reply_room: str, pfr_line: str) -> bool:
        """The single effectful path: sign + post one rendered PFR.

        Returns True on success, False when refused -- an empty/unvalidated
        reply room can never reach the Transport (D3 defense in depth).
        Transport/signing failures raise and are never swallowed."""
        if not reply_room:
            return False
        nonce = self.nonces.next_nonce(reply_room)
        canonical = f"{reply_room}|{nonce}|{pfr_line}".encode("utf-8")
        sig = self.signer.sign_canonical(canonical)
        self.transport.post_signed_message(
            room=reply_room, did=self.service_did, sig=sig, nonce=nonce,
            swept_text=pfr_line)
        self.nonces.observe_written(reply_room, nonce)
        return True

    def drain_snapshot(self, records: list[dict], last_seen_seq: int
                       ) -> tuple[int, list[Decision]]:
        """Batch entry. Network reads happen OUTSIDE: callers fetch records via
        Transport.read_room_json and hand them in here. Returns new cursor."""
        cursor = last_seen_seq
        decisions: list[Decision] = []
        for rec in sorted(records, key=lambda r: int(r.get("seq", 0))):
            seq = int(rec.get("seq", 0))
            if seq <= last_seen_seq:
                continue
            cursor = max(cursor, seq)
            text = rec.get("text", "")
            if not text.startswith(w.PFQ_PREFIX):
                continue                    # not a request; ignore silently
            if rec.get("from") == SERVICE_DID:
                continue                    # never react to ourselves
            decisions.append(self.handle_line(text, seq_hint=seq))
        return cursor, decisions


def struct_cid(pfr_line: str) -> str:
    return extract_cid(pfr_line.replace(w.PFR_PREFIX, w.PFQ_PREFIX, 1))
