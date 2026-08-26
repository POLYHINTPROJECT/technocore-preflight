"""Pure request pipeline: parsed PFQ -> PFR struct. No I/O of any kind.

Receives an already-parsed request dict (engine/wire.parse_pfq output) and
returns a PFR struct ready for engine/wire.render_pfr. Engine exceptions
become typed T1 findings; unexpected exceptions become ERROR structs.

Wire representation of ERROR responses (transport-layer completion decision,
2026-08-26): a PFR whose status is ERROR carries `error=<encoded text>` in
place of finding tokens. This ADDS a parameter for the spec-mandated ERROR
status; it does not modify the frozen finding vocabularies. Flagged for
operator ratification.
"""
from __future__ import annotations

import hashlib
from typing import Any

from engine import preflight as pf
from engine import wire as w

ENGINE_VERSION = "0.1.0"


def _f(kind: str, code: str = "", ref: str = "", detail: str = "") -> tuple:
    return (kind, code, ref, detail)


def _status(findings: list[tuple]) -> str:
    kinds = {f[0] for f in findings}
    if "T1-reject" in kinds:
        return "FAIL"
    if kinds == {"T1-ok"}:
        return "PASS"
    return "PARTIAL"


def run_preview(params: dict[str, str]) -> list[tuple]:
    """spec §2A: fixed-order static checks + sweep report + sig preview."""
    findings: list[tuple] = []
    room, nonce_s, did, text = (params["room"], params["nonce"],
                                params["did"], params["text"])

    v = pf.validate_room(room)
    findings.append(_f("T1-ok", detail=v.detail) if v.ok else
                    _f("T1-reject", "E_BAD_ROOM", "", v.detail))

    nv = pf.validate_nonce(nonce_s)
    if not nv.ok:
        findings.append(_f("T1-reject", nv.code, "", nv.detail))
    elif nv.code == "W_LEADING_ZERO_NONCE":
        findings.append(_f("T1-warn", nv.code, "", nv.detail))
    else:
        findings.append(_f("T1-ok", detail=f"nonce {nv.detail}"))

    pub = None
    try:
        pub = pf.parse_did(did)
        findings.append(_f("T1-ok", detail=f"DID parses ({len(pub)}-byte key)"))
    except pf.PreflightError as exc:
        findings.append(_f("T1-reject", "E_BAD_DID", "", str(exc)))

    swept_stored = None
    try:
        s = pf.sweep(text)
        swept_stored = s.stored
        if s.change_count == 0:
            findings.append(_f("T1-ok", detail="sweep identity"))
        else:
            shown = ", ".join(f"{u}:{c}" for _, u, c in s.changes[:8])
            more = f" (+{s.change_count - 8} more)" \
                if s.change_count > len(s.changes) else ""
            findings.append(_f("T1-warn", "W_SWEPT_CHARS", "",
                               f"{s.change_count} replaced: {shown}{more}"))
        findings.append(_f("T1-ok",
                           detail=f"stored len={s.char_len} "
                                  f"sha256={s.sha256_hex[:16]}"))
    except pf.PreflightError as exc:
        msg = str(exc)
        code = "E_EMPTY_AFTER_SWEEP" if "E_EMPTY_AFTER_SWEEP" in msg else \
               ("E_TEXT_TOO_LONG" if "E_TEXT_TOO_LONG" in msg else "")
        findings.append(_f("T1-reject", code, "", msg))

    fatal = any(f[0] == "T1-reject" for f in findings)
    if not fatal and swept_stored is not None and pub is not None:
        canonical = pf.canonical_msg(room, int(nonce_s), swept_stored)
        findings.append(_f("T1-ok", detail=f"canonical bytes len={len(canonical)}"))
        sig = params.get("sig")
        if sig is not None:
            sv = pf.verify_sig_b64u(pub, sig, canonical)
            findings.append(_f("T1-ok", detail=sv.detail) if sv.ok else
                            _f("T1-reject", sv.code, "", sv.detail))
    return findings


def run_verify(params: dict[str, str]) -> list[tuple]:
    """spec §2B: proves sig-validity over the server-canonical form ONLY."""
    try:
        pub = pf.parse_did(params["did"])
    except pf.PreflightError as exc:
        return [_f("T1-reject", "E_BAD_DID", "", str(exc))]

    sig = params.get("sig")
    if sig is None:
        return [_f("T1-reject", "", "",
                   "verify requires sig=<86-char base64url>")]

    canonical_param = params.get("canonical")
    if canonical_param is not None:
        canonical = canonical_param.encode("utf-8")
        claimed = params.get("sha256")
        if claimed:
            actual = hashlib.sha256(canonical).hexdigest()
            if actual != claimed:
                # Not a frozen E-code: this is our own cross-check, not a
                # server-semantics verdict. Honest detail, deterministic.
                return [_f("T1-reject", "", "",
                           f"canonical/sha256 mismatch: claimed {claimed[:16]} "
                           f"actual {actual[:16]}")]
    else:
        try:
            swept = pf.sweep(params["text"]).stored
        except pf.PreflightError as exc:
            return [_f("T1-reject", "", "", str(exc))]
        canonical = pf.canonical_msg(params["room"], int(params["nonce"]), swept)

    sv = pf.verify_sig_b64u(pub, sig, canonical)
    return [_f("T1-ok", detail=sv.detail) if sv.ok else
            _f("T1-reject", sv.code, "", sv.detail)]


def run_audit(params: dict[str, str]) -> list[tuple]:
    """spec §2C: pure structural DID-note audit."""
    value = params["value"]
    did = params.get("did")
    fp = params.get("fp") or (pf.fingerprint(did) if did else None)
    ns = params.get("ns", "")
    key = params.get("key", "")

    # Without an explicit key we audit content only: passing the derived
    # expected fingerprint makes the placement comparison vacuous instead of
    # falsely flagging. Documented limitation of key-less audits.
    rows = pf.audit_note(placed_key_fp=key or fp or "?" * 16,
                         value=value, did=did,
                         placed_ns=ns or None)
    findings: list[tuple] = []
    for code, detail in rows:
        if code == "A_OK":
            findings.append(_f("T1-ok", detail=detail))
        elif code.startswith("W_"):
            findings.append(_f("T1-warn", code, "", detail))
        elif code.startswith(("A_NO", "A_BAD")):
            findings.append(_f("T1-reject", "", "", f"{code}: {detail}"))

    # placement verdict vs canonical sharded path (pure derivation)
    if key and fp:
        expected = f"/kv/did-{fp[:2]}/{fp[2:]}"
        if ns.startswith("did-"):
            actual = f"/kv/did-{ns[4:]}/{key}"
            findings.append(
                _f("T1-ok", "", "", f"placement {actual} is canonical")
                if actual == expected else
                _f("T1-warn", "W_NOTE_WRONG_KEY", "",
                   f"placement {actual} vs canonical {expected}"))
        elif ns == "did":
            findings.append(_f("T1-warn", "W_NOTE_LEGACY_PATH", "",
                               f"flat namespace; canonical is {expected}"))
    return findings


OPS = {"preview": run_preview, "verify": run_verify, "audit-did-note": run_audit}


def build_pfr(cid: str, op: str, findings: list[tuple],
              engine_version: str = ENGINE_VERSION,
              error: str | None = None) -> dict[str, Any]:
    """Assemble a response struct. ERROR carries `error=` text (see module
    docstring); other statuses derive from finding kinds deterministically."""
    if error is not None:
        return {"kind": "PFR", "cid": cid, "status": "ERROR",
                "engine": engine_version, "findings": [], "error": error}
    return {"kind": "PFR", "cid": cid, "status": _status(findings),
            "engine": engine_version, "findings": findings}


def process_request(parsed: dict | None, parse_error: str | None,
                    engine_version: str = ENGINE_VERSION) -> dict[str, Any]:
    """Pure entrypoint: (parsed-or-None, parse-error-or-None) -> PFR struct.

    Malformed requests get a deterministic ERROR struct when a cid was
    recoverable; otherwise cid='' marks the response unroutable (the caller
    drops it -- no trusted reply address exists for an unparseable line)."""
    if parse_error is not None:
        cid = (parsed or {}).get("cid", "")
        return build_pfr(cid, "?", [], engine_version, error=parse_error)
    op = parsed["op"]
    handler = OPS.get(op)
    if handler is None:
        return build_pfr(parsed["cid"], op, [], engine_version,
                         error=f"unknown operation {op!r}")
    try:
        findings = handler(parsed["params"])
    except Exception as exc:                    # engine invariant breach
        return build_pfr(parsed["cid"], op, [], engine_version,
                         error=f"engine fault: {exc.__class__.__name__}")
    return build_pfr(parsed["cid"], op, findings, engine_version)
