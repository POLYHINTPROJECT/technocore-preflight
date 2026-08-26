"""PFQ v1 / PFR v1 wire-format layer: pure parsing and rendering.

Frozen contract (spec/preflight-validator.md §3):

    Request:  PFQ v1 | <cid> | <op> | reply=<mb-room> ; k=v ; k=v …
    Response: PFR v1 | <cid> | <STATUS> | engine=<semver> ; findings…

This module adds ZERO entries to the frozen closed vocabularies (STATUS,
T1-reject, T1-warn, T2-observe sets live verbatim in REJECT_CODES /
WARN_CODES / OBSERVE_CODES below and must never gain members here).
Parse-layer failures use a SEPARATE X_* namespace so extension cannot be
confused with modifying the frozen sets.

Canonical spacing: single spaces around " | " and " ; ". Parsers accept
variable surrounding whitespace and normalize; renderers emit only the
canonical form, so render(parse(x)) is a fixed point and
parse(render(struct)) == struct whenever the struct is expressible
(spec-permitted round-trip).

Structural characters: "|" separates major fields, ";" separates parameter
tokens. Inside values/details they (and "%") MUST be percent-encoded --
only three escapes exist (%25 %7C %3B, uppercase), anything else is a
decoding error. Everything is decided by total functions of the input;
no clock, no randomness, no I/O.
"""
from __future__ import annotations

import re

from engine import preflight as pf
from engine.preflight import PreflightError

# ------------------------------------------------------------------ frozen
PFQ_PREFIX = "PFQ v1"
PFR_PREFIX = "PFR v1"
OPS = ("preview", "verify", "audit-did-note")
STATUSES = ("PASS", "FAIL", "PARTIAL", "ERROR")

# Frozen closed vocabularies -- DO NOT EDIT (spec §3). Parse errors use X_*.
REJECT_CODES = frozenset({
    "E_EMPTY_AFTER_SWEEP", "E_TEXT_TOO_LONG", "E_BAD_ROOM",
    "E_BAD_NONCE_FORMAT", "E_BAD_DID", "E_BAD_SIG_ENCODING",
    "E_SIG_INVALID", "E_CANONICAL_TOO_LONG",
})
WARN_CODES = frozenset({
    "W_SWEPT_CHARS", "W_URL_LONG", "W_LEADING_ZERO_NONCE",
    "W_NOTE_WRONG_KEY", "W_NOTE_LEGACY_PATH", "W_NOTE_FIELD_MISMATCH",
})
OBSERVE_CODES = frozenset({
    "O_NONCE_FLOOR_VISIBLE", "O_NO_PRIOR_WRITES_SEEN",
    "O_ROOM_OWNED", "O_CAPACITY_TIGHT",
})

# ------------------------------------------------------------- wire grammar
CID_RE = re.compile(r"[0-9a-f]{16}")
SEMVER_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?")
KEY_RE = re.compile(r"[a-z][a-z0-9_]{0,23}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
FP_RE = re.compile(r"[0-9a-f]{16}")
NS_RE = re.compile(r"did(?:-[0-9a-f]{2})?")
NOTE_KEY_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
REF_RE = re.compile(r"[0-9A-Za-z._:@/-]{1,40}")
MAX_LINE_CHARS = pf.MAX_TEXT_CHARS          # a request IS one stored message

ESCAPES = {"25": "%", "7C": "|", "3B": ";"}

# Op schemas straight from spec §2. reply is universal and handled separately.
OP_SCHEMAS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    #            required                          optional
    "preview": (("room", "nonce", "did", "text"), ("sig",)),
    "verify":  (("did",), ("sig", "nonce", "room", "text",
                           "canonical", "sha256")),
    "audit-did-note": (("value",), ("did", "fp", "ns", "key")),
}


class WireError(Exception):
    """Deterministic parse failure. .code is an X_* code, .detail explains."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


# ----------------------------------------------------------- value escaping
def encode_value(value: str) -> str:
    out = []
    for ch in value:
        if ch == "%":
            out.append("%25")
        elif ch == "|":
            out.append("%7C")
        elif ch == ";":
            out.append("%3B")
        else:
            out.append(ch)
    return "".join(out)


def decode_value(value: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch != "%":
            out.append(ch)
            i += 1
            continue
        pair = value[i + 1:i + 3]
        if pair not in ESCAPES:
            raise WireError(
                "X_BAD_ENCODING",
                f"only %25 %7C %3B escapes exist; found %{pair!r} at offset {i}")
        out.append(ESCAPES[pair])
        i += 3
    return "".join(out)


# ------------------------------------------------------------ shared pieces
def _check_line(line: str) -> None:
    if not isinstance(line, str):
        raise WireError("X_BAD_TYPE", "wire line must be str")
    if len(line) > MAX_LINE_CHARS:
        raise WireError("X_LINE_TOO_LONG",
                        f"{len(line)} chars exceeds message cap {MAX_LINE_CHARS}")
    try:
        swept = pf.sweep(line)
    except PreflightError:
        raise WireError("X_EMPTY_AFTER_SWEEP", "line has no visible content")
    if swept.stored != line:
        raise WireError(
            "X_NOT_SWEEP_SAFE",
            "line contains characters the server would replace or strip; "
            "send the post-sweep form")


def _parse_cid(field: str) -> str:
    cid = field.strip()
    if not CID_RE.fullmatch(cid):
        raise WireError(
            "X_BAD_CID",
            f"cid must be exactly 16 lowercase hex chars, got {field!r}")
    return cid


def _split_params(raw: str) -> list[list[str]]:
    """Split the params section on ';' into (key, decoded_value) pairs,
    enforcing token shape. Returns ordered pairs."""
    pairs: list[list[str]] = []
    for tok in raw.split(";"):
        tok = tok.strip()
        if not tok:
            raise WireError("X_BAD_PARAM", "empty parameter token")
        eq = tok.find("=")
        if eq <= 0:
            raise WireError("X_BAD_PARAM",
                            f"parameter {tok!r} lacks 'key=value' form")
        key = tok[:eq].strip()
        if not KEY_RE.fullmatch(key):
            raise WireError("X_BAD_KEY",
                            f"parameter key {key!r} must match [a-z][a-z0-9_]{{0,23}}")
        val = tok[eq + 1:].strip()
        if not val:
            raise WireError("X_EMPTY_VALUE", f"parameter {key!r} has an empty value")
        pairs.append([key, decode_value(val)])
    return pairs


def _dup_check(pairs: list[list[str]]) -> dict[str, str]:
    seen: dict[str, str] = {}
    for key, val in pairs:
        if key in seen:
            raise WireError("X_DUPLICATE_KEY", f"parameter {key!r} appears twice")
        seen[key] = val
    return seen


def _require_first(pairs: list[list[str]], key: str) -> None:
    if not pairs or pairs[0][0] != key:
        raise WireError("X_ORDER", f"first parameter must be {key}=…")


def _validate_reply(room: str) -> None:
    try:
        v = pf.validate_room(room)
        if not v.ok:
            raise WireError("X_BAD_REPLY_ROOM", v.detail)
        if "mb" not in pf._room_classes(room):
            raise WireError("X_BAD_REPLY_ROOM",
                            f"{room!r} lacks the mb- class; replies go to mailboxes")
    except PreflightError as exc:
        raise WireError("X_BAD_REPLY_ROOM", str(exc)) from exc


def _finding_token(f: tuple) -> str:
    kind, code, ref, detail = f
    enc = encode_value(detail)
    if kind == "T1-ok":
        return "T1-ok" + (f" {enc}" if enc else "")
    if kind in ("T1-reject", "T1-warn"):
        return f"{kind}:{code}" + (f" {enc}" if enc else "")
    if kind == "T2-observe":
        base = f"T2-observe:{code}@{ref}"
        return base + (f" {enc}" if enc else "")
    raise WireError("X_BAD_FINDING", f"unrenderable finding kind {kind!r}")


# ------------------------------------------------------------------- PFQ
def parse_pfq(line: str) -> dict:
    _check_line(line)
    parts = line.split("|")
    if len(parts) != 4:
        raise WireError(
            "X_BAD_STRUCTURE",
            f"expected exactly 3 unescaped '|' separators, got {len(parts) - 1}")
    prefix, cid_f, op_f, params_f = (p.strip() for p in parts)
    if prefix != PFQ_PREFIX:
        raise WireError("X_BAD_PREFIX", f"expected {PFQ_PREFIX!r}, got {prefix!r}")
    cid = _parse_cid(cid_f)
    op = op_f.strip()
    if op not in OPS:
        raise WireError("X_BAD_OP",
                        f"op {op!r} outside {OPS}")
    pairs = _split_params(params_f)
    _require_first(pairs, "reply")
    kv = _dup_check(pairs)
    _validate_reply(kv["reply"])

    required, optional = OP_SCHEMAS[op]
    unknown = set(kv) - {"reply"} - set(required) - set(optional)
    if unknown:
        raise WireError("X_UNKNOWN_KEY",
                        f"op {op!r} does not accept {sorted(unknown)}")
    missing = [k for k in required if k not in kv]
    if missing:
        raise WireError("X_MISSING_KEY", f"op {op!r} requires {missing}")

    # closed-format parameters
    if "sha256" in kv and not SHA256_RE.fullmatch(kv["sha256"]):
        raise WireError("X_BAD_SHA256", "must be 64 lowercase hex chars")
    if "fp" in kv and not FP_RE.fullmatch(kv["fp"]):
        raise WireError("X_BAD_FP", "must be 16 lowercase hex chars")
    if "ns" in kv and not NS_RE.fullmatch(kv["ns"]):
        raise WireError("X_BAD_NS", "expected 'did' or 'did-<2 hex>'")
    if "key" in kv and not NOTE_KEY_RE.fullmatch(kv["key"]):
        raise WireError("X_BAD_NOTE_KEY", "invalid note key name")

    # op-specific completeness (spec §2B/§2C)
    if op == "verify":
        full = ("nonce" in kv, "room" in kv, "text" in kv)
        privacy = ("canonical" in kv, "sha256" in kv)
        if any(full) and not all(full):
            raise WireError("X_AMBIGUOUS_MODE",
                            "full mode needs nonce, room AND text together")
        if any(full) and any(privacy):
            raise WireError("X_AMBIGUOUS_MODE",
                            "full mode and privacy mode are mutually exclusive")
        if not any(full):
            if not any(privacy):
                raise WireError("X_MISSING_KEY",
                                "verify needs nonce+room+text or canonical+sha256")
            if not all(privacy):
                raise WireError("X_AMBIGUOUS_MODE",
                                "privacy mode needs canonical AND sha256 together")
    if op == "audit-did-note":
        has_did, has_fp = "did" in kv, "fp" in kv
        if has_did and has_fp:
            raise WireError("X_AMBIGUOUS_MODE",
                            "give exactly one of did= or fp=")
        if not has_did and not has_fp:
            raise WireError("X_MISSING_KEY",
                            "audit-did-note needs did= or fp=")

    return {"kind": "PFQ", "cid": cid, "op": op,
            "params": {k: v for k, v in kv.items()}}


def render_pfq(q: dict) -> str:
    """Render the canonical PFQ v1 line for a parsed/constructed struct."""
    op = q["op"]
    if op not in OPS:
        raise WireError("X_BAD_OP", f"op {op!r} outside {OPS}")
    cid = q.get("cid", "")
    if not CID_RE.fullmatch(cid):
        raise WireError("X_BAD_CID", "cid must be 16 lowercase hex chars")
    kv = q.get("params", {})
    _dup_render_check(kv)
    if "reply" not in kv:
        raise WireError("X_MISSING_KEY", "reply= is mandatory")
    required, optional = OP_SCHEMAS[op]
    unknown = set(kv) - {"reply"} - set(required) - set(optional)
    if unknown:
        raise WireError("X_UNKNOWN_KEY",
                        f"op {op!r} does not accept {sorted(unknown)}")
    missing = [k for k in required if k not in kv]
    if missing:
        raise WireError("X_MISSING_KEY", f"op {op!r} requires {missing}")
    ordered = ["reply"] + [k for k in kv if k != "reply"]
    params = " ; ".join(f"{k}={encode_value(kv[k])}" for k in ordered)
    return f"{PFQ_PREFIX} | {cid} | {op} | {params}"


def _dup_render_check(kv: dict) -> None:
    if len(kv) != len(set(kv)):
        raise WireError("X_DUPLICATE_KEY", "dict cannot hold duplicate keys")


# ------------------------------------------------------------------- PFR
def parse_pfr(line: str) -> dict:
    _check_line(line)
    parts = line.split("|")
    if len(parts) != 4:
        raise WireError(
            "X_BAD_STRUCTURE",
            f"expected exactly 3 unescaped '|' separators, got {len(parts) - 1}")
    prefix, cid_f, status_f, params_f = (p.strip() for p in parts)
    if prefix != PFR_PREFIX:
        raise WireError("X_BAD_PREFIX", f"expected {PFR_PREFIX!r}, got {prefix!r}")
    cid = _parse_cid(cid_f)
    status = status_f.strip()
    if status not in STATUSES:
        raise WireError("X_BAD_STATUS",
                        f"status {status!r} outside {STATUSES}")

    tokens = [t.strip() for t in params_f.split(";")]
    if not tokens or not tokens[0]:
        raise WireError("X_BAD_PARAM", "empty parameter section")
    # First token is the only key=value: engine=<semver>. Findings are bare
    # tokens whose details carry spaces, so they must NOT go through k=v logic.
    eq = tokens[0].find("=")
    if eq <= 0 or tokens[0][:eq].strip() != "engine":
        raise WireError("X_ORDER", "first parameter must be engine=<semver>")
    engine = decode_value(tokens[0][eq + 1:].strip())
    if not engine:
        raise WireError("X_EMPTY_VALUE", "engine has an empty value")
    if not SEMVER_RE.fullmatch(engine):
        raise WireError("X_BAD_SEMVER",
                        f"engine version {engine!r} is not semver")

    # ERROR responses carry error=<text> instead of finding tokens
    # (transport-layer completion rule mirrored from render_pfr).
    if status == "ERROR":
        if len(tokens) != 2:
            raise WireError("X_BAD_STRUCTURE",
                            "ERROR response carries exactly one error= token")
        eq2 = tokens[1].find("=")
        if eq2 <= 0 or tokens[1][:eq2].strip() != "error":
            raise WireError("X_BAD_PARAM",
                            "ERROR response requires error=<text>")
        err_text = decode_value(tokens[1][eq2 + 1:].strip())
        if not err_text:
            raise WireError("X_EMPTY_VALUE", "error= text is empty")
        return {"kind": "PFR", "cid": cid, "status": status,
                "engine": engine, "findings": [], "error": err_text}

    findings = []
    for tok in tokens[1:]:
        if not tok:
            raise WireError("X_BAD_PARAM", "empty parameter token")
        head, _, detail = tok.partition(" ")
        detail = decode_value(detail.strip())
        if head == "T1-ok":
            findings.append(("T1-ok", "", "", detail))
            continue
        m = re.fullmatch(r"(T1-reject|T1-warn):([A-Z0-9_]+)", head)
        if m:
            kind, code = m.groups()
            table = REJECT_CODES if kind == "T1-reject" else WARN_CODES
            if code not in table:
                raise WireError(
                    "X_UNKNOWN_FINDING_CODE",
                    f"{kind}:{code} is outside the frozen {kind} vocabulary")
            findings.append((kind, code, "", detail))
            continue
        m = re.fullmatch(r"T2-observe:([A-Z0-9_]+)@(.*)", head)
        if m:
            code, ref = m.groups()
            if code not in OBSERVE_CODES:
                raise WireError(
                    "X_UNKNOWN_FINDING_CODE",
                    f"T2-observe:{code} is outside the frozen T2 vocabulary")
            if not ref or not REF_RE.fullmatch(ref):
                raise WireError("X_BAD_OBSERVATION_REF",
                                f"observation ref {ref!r} is malformed")
            findings.append(("T2-observe", code, ref, detail))
            continue
        raise WireError("X_BAD_FINDING", f"finding token {head!r} is malformed")

    if not findings:
        raise WireError("X_NO_FINDINGS",
                        "a PFR carries at least one finding token")
    return {"kind": "PFR", "cid": cid, "status": status,
            "engine": engine, "findings": findings}


def render_pfr(r: dict) -> str:
    status = r.get("status")
    if status not in STATUSES:
        raise WireError("X_BAD_STATUS", f"status {status!r} outside {STATUSES}")
    cid = r.get("cid", "")
    if not CID_RE.fullmatch(cid):
        raise WireError("X_BAD_CID", "cid must be 16 lowercase hex chars")
    engine = r.get("engine", "")
    if not SEMVER_RE.fullmatch(engine):
        raise WireError("X_BAD_SEMVER", f"engine version {engine!r} is not semver")

    if status == "ERROR":
        # Transport-layer completion (2026-08-26): ERROR responses carry
        # error=<encoded text> instead of finding tokens. Additive parameter;
        # frozen finding vocabularies untouched.
        err = r.get("error", "")
        if not err:
            raise WireError("X_EMPTY_VALUE", "ERROR status requires error= text")
        return (f"{PFR_PREFIX} | {cid} | ERROR | "
                f"engine={encode_value(engine)} ; error={encode_value(err)}")

    findings = r.get("findings") or ()
    if not findings:
        raise WireError("X_NO_FINDINGS",
                        "a PFR carries at least one finding token")
    tokens = [f"engine={encode_value(engine)}"] + \
             [_finding_token(f) for f in findings]
    return f"{PFR_PREFIX} | {cid} | {status} | {' ; '.join(tokens)}"
