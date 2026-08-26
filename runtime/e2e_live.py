"""One-shot controlled live E2E test driver (spec §3/§5; ratification F1-F7).

Subcommands:
    request   Build + sign + locally verify ONE PFQ, POST it to the service
              mailbox as a disposable requester. Records context JSON.
    serve     Operator-run: constructs LocalFileSigner (passphrase typed at
              the getpass prompt, never logged), runs EXACTLY ONE bounded
              poll cycle (wait=0), exits. No retry, no loop, no daemon.
    verify    READ-ONLY: read the reply mailbox back, verify PFR signature,
              grammar, cid, routing, deterministic equality with the offline
              engine, state files, absence of self-echo.

The disposable requester keypair lives only in process memory
(EphemeralSigner): it is never serialized, copied, or persisted anywhere.
"""
from __future__ import annotations

import json
import secrets
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adapter import dispatcher as d                # noqa: E402
from adapter import pipeline as pl                 # noqa: E402
from adapter.http_transport import HttpTransport   # noqa: E402
from adapter.signing import EphemeralSigner        # noqa: E402
from engine import preflight as pf                 # noqa: E402
from engine import wire as w                       # noqa: E402
from runtime.persistence import (                   # noqa: E402
    FileCidCache,
    FileCursor,
    FileNonces,
)

CTX_DIR = Path(__file__).resolve().parent / "state" / "e2e"
CTX_FILE = CTX_DIR / "context.json"
STATS_FILE = CTX_DIR / "serve-stats.json"


def _load_ctx() -> dict:
    return json.loads(CTX_FILE.read_text(encoding="utf-8"))


# ----------------------------------------------------------------- request
def cmd_request() -> None:
    requester = EphemeralSigner()          # memory-only disposable identity
    cid = secrets.token_hex(8)             # fresh 16-hex cid
    reply = f"mb-p-j1e2e-{secrets.token_hex(6)}"     # disposable unlisted box
    draft = "j1 live e2e probe 2026-08-26"

    # inner preview signature: proves the op's sig-preview path end to end
    swept = pf.sweep(draft).stored
    inner_canonical = pf.canonical_msg("lobby", "7", swept)
    inner_sig = requester.sign_canonical(inner_canonical)

    struct = {"kind": "PFQ", "cid": cid, "op": "preview",
              "params": {"reply": reply, "room": "lobby", "nonce": "7",
                         "did": requester.did, "text": draft,
                         "sig": inner_sig}}
    line = w.render_pfq(struct)

    # transport signature: signed-lane write of the PFQ INTO the service box
    t_canonical = f"{d.SERVICE_MAILBOX}|1|{line}".encode("utf-8")
    t_sig = requester.sign_canonical(t_canonical)

    iv = pf.verify_sig_b64u(pf.parse_did(requester.did), inner_sig,
                            inner_canonical)
    tv = pf.verify_sig_b64u(pf.parse_did(requester.did), t_sig, t_canonical)

    print("=== PRE-WRITE FACTS ===")
    print("requester DID :", requester.did)
    print("reply mailbox :", reply)
    print("cid           :", cid)
    print("PFQ line      :", line)
    print(f"line length   : {len(line)} chars (cap {pf.MAX_TEXT_CHARS})")
    print("transport canonical:")
    print("  ", t_canonical.decode())
    print("inner canonical:", inner_canonical.decode())
    print("local sig checks: inner:", "OK" if iv.ok else "FAIL",
          "| transport:", "OK" if tv.ok else "FAIL")
    if not (iv.ok and tv.ok):
        print("ABORT: local verification failed; nothing sent")
        return

    print("intended writes: (a) this PFQ -> service mailbox [requester DID],"
          " (b) service PFR ->", reply, "[service DID]. Nothing else.")
    input("Press ENTER to perform write (a) ...")

    transport = HttpTransport()
    result = transport.post_signed_message(
        room=d.SERVICE_MAILBOX, did=requester.did, sig=t_sig, nonce=1,
        swept_text=line)
    print("write (a) HTTP-layer result:", json.dumps(result)[:400])

    CTX_DIR.mkdir(parents=True, exist_ok=True)
    CTX_FILE.write_text(json.dumps({
        "cid": cid, "reply": reply, "requester_did": requester.did,
        "pfq_line": line, "draft": draft, "post_result": result,
    }, indent=2), encoding="utf-8")
    print("context saved:", CTX_FILE)


# ------------------------------------------------------------------- serve
def cmd_serve() -> None:
    ctx = _load_ctx()
    from adapter.signing import LocalFileSigner   # operator-only import path
    signer = LocalFileSigner(
        pem_path=r"C:\Users\karni\technocore-secrets\identity.pem")
    print("service DID confirmed:",
          signer.did == d.SERVICE_DID,
          "(mismatch would ABORT)")
    if signer.did != d.SERVICE_DID:
        print("ABORT: loaded identity does not match frozen service DID")
        return

    cursor = FileCursor()
    if cursor.seq != 0:
        # Resume, don't abort: a previous failed attempt legitimately leaves
        # the cursor at the last cleanly-handled record (e.g. 1 = self-echo
        # done, PFQ pending). One bounded cycle from wherever state stands;
        # duplicate safety comes from the cid cache, not from cursor resets.
        print(f"resuming from persisted cursor seq={cursor.seq}")

    from runtime.service import Service

    class EchoTransport(HttpTransport):
        """Pre-write observability for controlled one-shot attempts.
        Purely presentational; delegates unchanged."""

        def post_signed_message(self, room, did, sig, nonce, swept_text):
            print("=== PRE-WRITE FACTS ===")
            print("target reply room :", room)
            parts = swept_text.split(" | ")
            print("PFQ/PFR cid       :", parts[1].strip() if len(parts) > 2 else "?")
            print("line length       :", len(swept_text), "chars")
            print("outgoing nonce    :", nonce)
            print("service DID match :", did == d.SERVICE_DID)
            return super().post_signed_message(room, did, sig, nonce,
                                               swept_text)

    svc = Service(signer=signer, transport=EchoTransport(),
                  cache=FileCidCache(), nonces=FileNonces(), cursor=cursor)
    print(f"ONE bounded cycle: read {d.SERVICE_MAILBOX} "
          f"since={cursor.seq} wait=0 ...")
    stats = svc.poll_cycle(wait_s=0)
    print("cycle stats:", json.dumps(stats, indent=2))

    ok = (stats.get("failed", 0) == 0 and stats.get("replied", 0) == 1
          and stats.get("error") is None)
    print("EXPECTED exactly-one-reply:",
          "MET" if ok else "NOT MET -> investigate, DO NOT rerun blindly")

    STATS_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATS_FILE.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    print("stats saved:", STATS_FILE)


# ------------------------------------------------------------------ verify
def cmd_verify() -> None:
    ctx = _load_ctx()
    cid, reply, line = ctx["cid"], ctx["reply"], ctx["pfq_line"]
    transport = HttpTransport()
    failures = []

    def check(name, cond, detail=""):
        print(("PASS " if cond else "FAIL "), name,
              ("-- " + str(detail) if detail and not cond else ""))
        if not cond:
            failures.append(name)

    # 1) reply mailbox readback (READ-ONLY)
    recs = transport.read_room_json(reply, since=0, wait=0)
    pfr_recs = [r for r in recs
                if str(r.get("text", "")).startswith(f"PFR v1 | {cid}")]
    check("exactly one PFR in reply mailbox", len(pfr_recs) == 1,
          f"got {len(pfr_recs)} of {len(recs)} records")
    if not pfr_recs:
        print("cannot continue verification without the PFR")
        return 1 if failures else 0
    rec = pfr_recs[0]
    text = rec["text"]

    # 2) authorship + transport signature over reconstructed canonical
    check("PFR authored by frozen service DID",
          rec.get("from") == d.SERVICE_DID, rec.get("from"))
    canon = f"{reply}|{rec.get('nonce')}|{text}".encode("utf-8")
    sv = pf.verify_sig_b64u(pf.parse_did(d.SERVICE_DID),
                            rec.get("sig", ""), canon)
    check("service signature verifies over reply|nonce|text", sv.ok, sv.detail)

    # 3) frozen grammar + cid
    try:
        parsed = w.parse_pfr(text)
        check("parses under frozen PFR grammar", True)
        check("cid matches request", parsed["cid"] == cid,
              f"{parsed['cid']} != {cid}")
    except w.WireError as exc:
        check("parses under frozen PFR grammar", False, exc)

    # 4) deterministic equality with the offline engine
    expected = w.render_pfr(pl.process_request(w.parse_pfq(line), None))
    check("byte-identical to offline engine output", text == expected,
          f"\n  live: {text!r}\n  want: {expected!r}")

    # 5) routing correctness
    check("delivered to the requested reply mailbox",
          rec.get("_room_hint", reply) == reply and ctx["post_result"]
          is not None)
    svc_recs = transport.read_room_json(d.SERVICE_MAILBOX, since=int(
        (ctx.get("post_result") or {}).get("seq") or 2), wait=0)
    check("no self-echo loop in service mailbox (nothing new after PFQ)",
          len(svc_recs) == 0, f"{len(svc_recs)} records after our PFQ")

    # 6) state files: cursor / nonce / cache, privacy scan
    cur = FileCursor()
    non = FileNonces()
    cachefile = Path(__file__).resolve().parent / "state" / "cid-cache.json"
    cache_raw = cachefile.read_text(encoding="utf-8") if cachefile.exists() \
        else "{}"
    check("cursor advanced past the PFQ seq",
          cur.seq >= int((ctx.get("post_result") or {}).get("seq") or 2),
          cur.seq)
    check("nonce state advanced to 1 for reply room",
          non.last.get(reply) == 1, non.last)
    check("cid cache contains exactly the approved replay entry",
          list(json.loads(cache_raw).keys()) == [cid], cache_raw[:200])
    blob = "\n".join(
        p.read_text(encoding="utf-8") for p in
        (Path(__file__).resolve().parent / "state").glob("*.json"))
    check("draft text absent from all persisted state", ctx["draft"] not in
          blob)

    print("\nRESULT:", "ALL CHECKS PASSED" if not failures
          else f"{len(failures)} FAILURE(S): {failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "request":
        cmd_request()
    elif cmd == "serve":
        cmd_serve()
    elif cmd == "verify":
        sys.exit(cmd_verify())
    else:
        print(__doc__)
