/* J1 wire layer — JavaScript port of engine/wire.py (PFQ v1 / PFR v1).
 * Byte-exact agreement enforced by ui/tests/diff-harness.mjs.
 */
import {
  sweep, validateRoom, roomClasses, validateNonce, parseDid,
  canonicalMsg, canonicalNote, makeVerifier, estimateRequestLine,
  MAX_TEXT_CHARS, PreflightError, pyRepr, ok, bad,
} from "./engine.js";

// Python tuple rendering for error details (str(('a', 'b', 'c'))).
const pyTupleStr = (xs) => "(" + xs.map(x => `'${x}'`).join(", ") + ")";

// ---------------------------------------------------------------- constants
export const PFQ_PREFIX = "PFQ v1";
export const PFR_PREFIX = "PFR v1";
export const OPS = ["preview", "verify", "audit-did-note"];
export const STATUSES = ["PASS", "FAIL", "PARTIAL", "ERROR"];

export const REJECT_CODES = new Set([
  "E_EMPTY_AFTER_SWEEP", "E_TEXT_TOO_LONG", "E_BAD_ROOM", "E_BAD_NONCE_FORMAT",
  "E_BAD_DID", "E_BAD_SIG_ENCODING", "E_SIG_INVALID", "E_CANONICAL_TOO_LONG",
]);
export const WARN_CODES = new Set([
  "W_SWEPT_CHARS", "W_URL_LONG", "W_LEADING_ZERO_NONCE",
  "W_NOTE_WRONG_KEY", "W_NOTE_LEGACY_PATH", "W_NOTE_FIELD_MISMATCH",
]);
export const OBSERVE_CODES = new Set([
  "O_NONCE_FLOOR_VISIBLE", "O_NO_PRIOR_WRITES_SEEN",
  "O_ROOM_OWNED", "O_CAPACITY_TIGHT",
]);

export const CID_RE = /^[0-9a-f]{16}$/;
const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const KEY_RE = /^[a-z][a-z0-9_]{0,23}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const FP_RE = /^[0-9a-f]{16}$/;
const NS_RE = /^did(?:-[0-9a-f]{2})?$/;
const NOTE_KEY_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const REF_RE = /^[0-9A-Za-z._:@/-]{1,40}$/;

export class WireError extends Error {
  constructor(code, detail = "") {
    super(detail ? `${code}: ${detail}` : code);
    this.name = "WireError";
    this.code = code;
    this.detail = detail;
  }
}

// ----------------------------------------------------------- value escaping
export function encodeValue(value) {
  let out = "";
  for (const ch of value) {
    if (ch === "%") out += "%25";
    else if (ch === "|") out += "%7C";
    else if (ch === ";") out += "%3B";
    else out += ch;
  }
  return out;
}

export function decodeValue(value) {
  let out = "";
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (ch !== "%") { out += ch; continue; }
    const pair = value.slice(i + 1, i + 3);
    if (pair === "25") { out += "%"; i += 2; }
    else if (pair === "7C") { out += "|"; i += 2; }
    else if (pair === "3B") { out += ";"; i += 2; }
    else throw new WireError("X_BAD_ENCODING",
      `only %25 %7C %3B escapes exist; found %${pyRepr(pair)} at offset ${i}`);
  }
  return out;
}

// -------------------------------------------------------------- shared bits
function checkLine(line) {
  if (typeof line !== "string") throw new WireError("X_BAD_TYPE", "wire line must be str");
  if ([...line].length > MAX_TEXT_CHARS) {
    throw new WireError("X_LINE_TOO_LONG",
      `${[...line].length} chars exceeds message cap ${MAX_TEXT_CHARS}`);
  }
  try {
    const swept = sweep(line);
    if (swept.stored !== line) {
      throw new WireError("X_NOT_SWEEP_SAFE",
        "line contains characters the server would replace or strip; send the post-sweep form");
    }
  } catch (e) {
    if (e instanceof WireError) throw e;
    throw new WireError("X_EMPTY_AFTER_SWEEP", "line has no visible content");
  }
}

function parseCid(field) {
  const cid = field.trim();
  if (!CID_RE.test(cid)) {
    throw new WireError("X_BAD_CID",
      `cid must be exactly 16 lowercase hex chars, got ${pyRepr(field)}`);
  }
  return cid;
}

function splitParams(raw) {
  const pairs = [];
  for (let tok of raw.split(";")) {
    tok = tok.trim();
    if (!tok) throw new WireError("X_BAD_PARAM", "empty parameter token");
    const eq = tok.indexOf("=");
    if (eq <= 0) throw new WireError("X_BAD_PARAM", `parameter ${pyRepr(tok)} lacks 'key=value' form`);
    const key = tok.slice(0, eq).trim();
    if (!KEY_RE.test(key)) throw new WireError("X_BAD_KEY",
      `parameter key ${pyRepr(key)} must match [a-z][a-z0-9_]{0,23}`);
    const val = tok.slice(eq + 1).trim();
    if (!val) throw new WireError("X_EMPTY_VALUE", `parameter ${pyRepr(key)} has an empty value`);
    pairs.push([key, decodeValue(val)]);
  }
  return pairs;
}

function dupCheck(pairs) {
  const seen = {};
  for (const [k] of pairs) {
    if (k in seen) throw new WireError("X_DUPLICATE_KEY", `parameter ${pyRepr(k)} appears twice`);
    seen[k] = true;
  }
}

function requireFirst(pairs, key) {
  if (!pairs.length || pairs[0][0] !== key)
    throw new WireError("X_ORDER", `first parameter must be ${key}=…`);
}

export function validateReplyRoom(room) {
  const v = validateRoom(room);
  if (!v.ok) throw new WireError("X_BAD_REPLY_ROOM", v.detail || "invalid room");
  if (!roomClasses(room).includes("mb"))
    throw new WireError("X_BAD_REPLY_ROOM", `${pyRepr(room)} lacks the mb- class; replies go to mailboxes`);
}

// ------------------------------------------------------------- op schemas
export const OP_SCHEMAS = {
  preview: { required: ["room", "nonce", "did", "text"], optional: ["sig"] },
  verify: { required: ["did"], optional: ["sig", "nonce", "room", "text", "canonical", "sha256"] },
  "audit-did-note": { required: ["value"], optional: ["did", "fp", "ns", "key"] },
};

function schemaCheck(op, kv) {
  const { required, optional } = OP_SCHEMAS[op];
  const unknown = Object.keys(kv).filter(k => k !== "reply" && !required.includes(k) && !optional.includes(k));
  if (unknown.length) throw new WireError("X_UNKNOWN_KEY", `op '${op}' does not accept ${unknown.sort()}`);
  const missing = required.filter(k => !(k in kv));
  if (missing.length) throw new WireError("X_MISSING_KEY", `op '${op}' requires ${missing}`);
  if ("sha256" in kv && !SHA256_RE.test(kv.sha256))
    throw new WireError("X_BAD_SHA256", "must be 64 lowercase hex chars");
  if ("fp" in kv && !FP_RE.test(kv.fp))
    throw new WireError("X_BAD_FP", "must be 16 lowercase hex chars");
  if ("ns" in kv && !NS_RE.test(kv.ns))
    throw new WireError("X_BAD_NS", "expected 'did' or 'did-<2 hex>'");
  if ("key" in kv && !NOTE_KEY_RE.test(kv.key))
    throw new WireError("X_BAD_NOTE_KEY", "invalid note key name");

  if (op === "verify") {
    const full = ["nonce", "room", "text"].map(k => k in kv);
    const privacy = ["canonical", "sha256"].map(k => k in kv);
    if (full.some(Boolean) && !full.every(Boolean))
      throw new WireError("X_AMBIGUOUS_MODE", "full mode needs nonce, room AND text together");
    if (full.some(Boolean) && privacy.some(Boolean))
      throw new WireError("X_AMBIGUOUS_MODE", "full mode and privacy mode are mutually exclusive");
    if (!full.some(Boolean)) {
      if (!privacy.some(Boolean))
        throw new WireError("X_MISSING_KEY", "verify needs nonce+room+text or canonical+sha256");
      if (!privacy.every(Boolean))
        throw new WireError("X_AMBIGUOUS_MODE", "privacy mode needs canonical AND sha256 together");
    }
  }
  if (op === "audit-did-note") {
    const hasDid = "did" in kv, hasFp = "fp" in kv;
    if (hasDid && hasFp) throw new WireError("X_AMBIGUOUS_MODE", "give exactly one of did= or fp=");
    if (!hasDid && !hasFp) throw new WireError("X_MISSING_KEY", "audit-did-note needs did= or fp=");
  }
}

// ------------------------------------------------------------------- PFQ
export function parsePfq(line) {
  checkLine(line);
  const parts = line.split("|");
  if (parts.length !== 4) {
    throw new WireError("X_BAD_STRUCTURE",
      `expected exactly 3 unescaped '|' separators, got ${parts.length - 1}`);
  }
  const [prefixF, cidF, opF, paramsF] = parts.map(p => p.trim());
  if (prefixF !== PFQ_PREFIX) throw new WireError("X_BAD_PREFIX", `expected ${pyRepr(PFQ_PREFIX)}, got ${pyRepr(prefixF)}`);
  const cid = parseCid(cidF);
  const op = opF;
  if (!OPS.includes(op)) throw new WireError("X_BAD_OP", `op ${pyRepr(op)} outside ${pyTupleStr(OPS)}`);
  const pairs = splitParams(paramsF);
  requireFirst(pairs, "reply");
  dupCheck(pairs);
  const kv = Object.fromEntries(pairs);
  validateReplyRoom(kv.reply);
  schemaCheck(op, kv);
  return { kind: "PFQ", cid, op, params: kv };
}

export function renderPfq(q) {
  const op = q.op;
  if (!OPS.includes(op)) throw new WireError("X_BAD_OP", `op ${JSON.stringify(op)} outside ['preview','verify','audit-did-note']`);
  const cid = q.cid ?? "";
  if (!CID_RE.test(cid)) throw new WireError("X_BAD_CID", "cid must be 16 lowercase hex chars");
  const kv = q.params ?? {};
  if (Object.keys(kv).length !== new Set(Object.keys(kv)).size)
    throw new WireError("X_DUPLICATE_KEY", "dict cannot hold duplicate keys");
  if (!("reply" in kv)) throw new WireError("X_MISSING_KEY", "reply= is mandatory");
  schemaCheck(op, kv);
  const ordered = ["reply", ...Object.keys(kv).filter(k => k !== "reply")];
  const params = ordered.map(k => `${k}=${encodeValue(kv[k])}`).join(" ; ");
  return `${PFQ_PREFIX} | ${cid} | ${op} | ${params}`;
}

// -------------------------------------------------------------- findings
function findingToken(f) {
  const [kind, code, ref, detail] = f;
  const enc = encodeValue(detail);
  if (kind === "T1-ok") return "T1-ok" + (enc ? ` ${enc}` : "");
  if (kind === "T1-reject" || kind === "T1-warn")
    return `${kind}:${code}` + (enc ? ` ${enc}` : "");
  if (kind === "T2-observe") {
    const base = `T2-observe:${code}@${ref}`;
    return base + (enc ? ` ${enc}` : "");
  }
  throw new WireError("X_BAD_FINDING", `unrenderable finding kind ${kind}`);
}

// ------------------------------------------------------------------- PFR
export function parsePfr(line) {
  checkLine(line);
  const parts = line.split("|");
  if (parts.length !== 4) {
    throw new WireError("X_BAD_STRUCTURE",
      `expected exactly 3 unescaped '|' separators, got ${parts.length - 1}`);
  }
  const [prefixF, cidF, statusF, paramsF] = parts.map(p => p.trim());
  if (prefixF !== PFR_PREFIX) throw new WireError("X_BAD_PREFIX", `expected ${pyRepr(PFR_PREFIX)}, got ${pyRepr(prefixF)}`);
  const cid = parseCid(cidF);
  const status = statusF;
  if (!STATUSES.includes(status)) throw new WireError("X_BAD_STATUS", `status ${pyRepr(status)} outside ${pyTupleStr(STATUSES)}`);

  const tokens = paramsF.split(";").map(t => t.trim());
  if (!tokens.length || !tokens[0]) throw new WireError("X_BAD_PARAM", "empty parameter section");
  // First token: engine=<semver>. Findings are bare tokens with spaces.
  const eq = tokens[0].indexOf("=");
  if (eq <= 0 || tokens[0].slice(0, eq).trim() !== "engine")
    throw new WireError("X_ORDER", "first parameter must be engine=<semver>");
  const engine = decodeValue(tokens[0].slice(eq + 1).trim());
  if (!engine) throw new WireError("X_EMPTY_VALUE", "engine has an empty value");
  if (!SEMVER_RE.test(engine)) throw new WireError("X_BAD_SEMVER", `engine version ${engine} is not semver`);

  if (status === "ERROR") {
    if (tokens.length !== 2) throw new WireError("X_BAD_STRUCTURE", "ERROR response carries exactly one error= token");
    const eq2 = tokens[1].indexOf("=");
    if (eq2 <= 0 || tokens[1].slice(0, eq2).trim() !== "error")
      throw new WireError("X_BAD_PARAM", "ERROR response requires error=<text>");
    const errText = decodeValue(tokens[1].slice(eq2 + 1).trim());
    if (!errText) throw new WireError("X_EMPTY_VALUE", "error= text is empty");
    return { kind: "PFR", cid, status, engine, findings: [], error: errText };
  }

  const findings = [];
  for (let j = 1; j < tokens.length; j++) {
    const tok = tokens[j];
    if (!tok) throw new WireError("X_BAD_PARAM", "empty parameter token");
    const sp = tok.indexOf(" ");
    const head = sp < 0 ? tok : tok.slice(0, sp);
    const detail = sp < 0 ? "" : decodeValue(tok.slice(sp + 1).trim());
    if (head === "T1-ok") { findings.push(["T1-ok", "", "", detail]); continue; }
    const m1 = head.match(/^(T1-reject|T1-warn):([A-Z0-9_]+)$/);
    if (m1) {
      const frozen = m1[1] === "T1-reject" ? REJECT_CODES : WARN_CODES;
      if (!frozen.has(m1[2])) throw new WireError("X_UNKNOWN_FINDING_CODE",
        `${m1[1]}:${m1[2]} is outside the frozen ${m1[1]} vocabulary`);
      findings.push([m1[1], m1[2], "", detail]);
      continue;
    }
    const m2 = head.match(/^T2-observe:([A-Z0-9_]+)@(.*)$/s);
    if (m2) {
      const [, code, ref] = m2;
      if (!OBSERVE_CODES.has(code)) throw new WireError("X_UNKNOWN_FINDING_CODE",
        `T2-observe:${code} is outside the frozen T2 vocabulary`);
      if (!ref || !REF_RE.test(ref)) throw new WireError("X_BAD_OBSERVATION_REF", `observation ref ${pyRepr(ref)} is malformed`);
      findings.push(["T2-observe", code, ref, detail]);
      continue;
    }
    throw new WireError("X_BAD_FINDING", `finding token ${pyRepr(head)} is malformed`);
  }
  if (!findings.length) throw new WireError("X_NO_FINDINGS", "a PFR carries at least one finding token");
  return { kind: "PFR", cid, status, engine, findings };
}

export function renderPfr(r) {
  const status = r.status;
  if (!STATUSES.includes(status)) throw new WireError("X_BAD_STATUS", `status ${status} outside ${JSON.stringify(STATUSES)}`);
  const cid = r.cid ?? "";
  if (!CID_RE.test(cid)) throw new WireError("X_BAD_CID", "cid must be 16 lowercase hex chars");
  const engine = r.engine ?? "";
  if (!SEMVER_RE.test(engine)) throw new WireError("X_BAD_SEMVER", `engine version ${engine} is not semver`);

  if (status === "ERROR") {
    const err = r.error ?? "";
    if (!err) throw new WireError("X_EMPTY_VALUE", "ERROR status requires error= text");
    return `${PFR_PREFIX} | ${cid} | ERROR | engine=${encodeValue(engine)} ; error=${encodeValue(err)}`;
  }
  const findings = r.findings ?? [];
  if (!findings.length) throw new WireError("X_NO_FINDINGS", "a PFR carries at least one finding token");
  const tokens = [`engine=${encodeValue(engine)}`, ...findings.map(findingToken)];
  return `${PFR_PREFIX} | ${cid} | ${status} | ${tokens.join(" ; ")}`;
}
