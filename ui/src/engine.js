/* J1 deterministic engine — JavaScript port of engine/preflight.py.
 *
 * Pure functions only: no I/O, no network, no clock, no randomness. Every
 * output is a total function of its inputs. Byte-exact agreement with the
 * Python engine is enforced by ui/tests/diff-harness.mjs over the shared
 * vector corpus (tests/vectors.py) — never edit semantics without regenerating
 * unicode-categories.json via ui/tools/gen_unicode_tables.py.
 *
 * Unicode categories come from generated range tables (CPython unicodedata),
 * NOT from String.prototype properties — JS cannot see Cf/Cc/Co/Zl/Zp the way
 * the server does.
 */
import TABLE from "./unicode-categories.js";
import { sha256Bytes, bytesToHex } from "./sha256.js";

// ---------------------------------------------------------- category tables
export function categoryOf(codepoint) {
  let lo = 0, hi = TABLE.ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const r = TABLE.ranges[mid];
    if (codepoint < r[0]) hi = mid - 1;
    else if (codepoint > r[1]) lo = mid + 1;
    else return TABLE.cats[r[2]];
  }
  return "Cn"; // unreachable: tables are total over 0..0x10FFFF
}

export function unidataVersion() {
  return TABLE.unidata_version;
}

// ---------------------------------------------------------------- constants
// Pinned upstream: store.INVISIBLE_CATEGORIES
export const INVISIBLE_CATEGORIES = new Set(["Cc", "Cf", "Cs", "Co", "Zl", "Zp"]);
export const MAX_TEXT_CHARS = 4096;     // message lane
export const MAX_VALUE_CHARS = 8192;    // note lane
export const PRACTICAL_URL_CEILING = 16384;
export const DID_PREFIX = "did:key:";
export const MULTIBASE_CHARS = 48;

export class PreflightError extends Error {
  constructor(message) {
    super(message);
    this.name = "PreflightError";
  }
}

/** Python repr() for a single string, as used in engine error details. */
export function pyRepr(s) {
  return "'" + String(s).replace(/\\/g, "\\\\").replace(/'/g, "\\'") + "'";
}
export const ok = (detail = "") => ({ ok: true, code: "", detail });
export const bad = (code, detail = "") => ({ ok: false, code, detail });

// ------------------------------------------------------------------- sweep
export function sweep(text, limit = MAX_TEXT_CHARS) {
  // Server-exact clean_text: invisible-category chars -> single spaces
  // (1:1, offsets preserved), then trim(), then post-sweep length limit.
  const outChars = [];
  const changes = [];
  let i = 0;
  for (const ch of text) {           // iterate CODEPOINTS, not UTF-16 units
    const cp = ch.codePointAt(0);
    const cat = categoryOf(cp);
    if (INVISIBLE_CATEGORIES.has(cat)) {
      changes.push([i, `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`, cat]);
      outChars.push(" ");
    } else {
      outChars.push(ch);
    }
    i++;
  }
  // Python str.strip() removes whitespace on BOTH ends. The server strips the
  // swept string; only characters Python's strip() considers whitespace matter.
  // Python strip() whitespace == Zs + Zl + Zp + Cc tab/LF/VT/FF/CR + U+0085.
  // After the sweep, every Cc/Zl/Zp char is already a plain space, so the
  // remaining strippable set is exactly ASCII space (U+0020).
  const stored = outChars.join("").replace(/^ +/, "").replace(/ +$/, "");
  if (!stored) {
    throw new PreflightError(
      "E_EMPTY_AFTER_SWEEP: nothing visible survived the single-line sweep");
  }
  if ([...stored].length > limit) {
    throw new PreflightError(
      `E_TEXT_TOO_LONG: ${[...stored].length} characters after sweep, limit ${limit}`);
  }
  return {
    stored,
    changes,
    change_count: changes.length,
    truncated_change_list: changes.length > 20,
    sha256_hex: sha256Hex(stored),
    char_len: [...stored].length,
  };
}

// -------------------------------------------------------------- room names
export function roomClasses(name) {
  const classes = [];
  let rest = name;
  let changed = true;
  while (changed) {
    changed = false;
    for (const cls of ["mb", "p", "d", "e"]) {
      if (rest.startsWith(cls + "-")) {
        classes.push(cls);
        rest = rest.slice(cls.length + 1);
        changed = true;
        break;
      }
    }
  }
  return classes;
}

const NAME_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;
export function validateRoom(name) {
  if (!name) return bad("E_BAD_ROOM", "empty room name");
  if (!NAME_RE.test(name)) {
    if (/[A-Z]/.test(name)) return bad("E_BAD_ROOM", "uppercase letters are rejected");
    if ([...name].length > 48) return bad("E_BAD_ROOM", `${[...name].length} chars, limit 48`);
    if (name[0] === "-" || name[0] === "_") return bad("E_BAD_ROOM", "must start with [a-z0-9]");
    return bad("E_BAD_ROOM", "allowed: [a-z0-9][a-z0-9_-]{0,47}");
  }
  return ok("classes=" + (roomClasses(name).join(",") || "none"));
}

// ------------------------------------------------------------------ nonce
const NONCE_RE = /^[0-9]{1,19}$/;
export function validateNonce(nonce, floor = null) {
  const s = String(nonce);
  if (!NONCE_RE.test(s)) {
    // Python: not s.isdigit() -> format error; else length message.
    if (!/^[0-9]+$/.test(s)) {
      return bad("E_BAD_NONCE_FORMAT", "must be 1-19 ASCII digits [0-9]");
    }
    return bad("E_BAD_NONCE_FORMAT", `${s.length} digits; the server accepts at most 19`);
  }
  // The server compares arbitrary-precision ints; 19-digit values exceed
  // Number.MAX_SAFE_INTEGER, so all numeric comparison is BigInt.
  const value = BigInt(s);
  if (floor !== null && value <= BigInt(floor)) {
    return bad("E_NONCE_NOT_GREATER",
      `nonce ${value} must be strictly greater than the last observed floor ` +
      `${floor} for this key in this room`);
  }
  if (s.length > 1 && s[0] === "0") {
    return { ok: true, code: "W_LEADING_ZERO_NONCE", detail: `parses to ${value}; prefer the canonical form` };
  }
  return ok(String(value));
}

// -------------------------------------------------------------------- DID
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function b58decode(s) {
  let n = 0n;
  for (const ch of s) {
    const idx = B58_ALPHABET.indexOf(ch);
    if (idx < 0) {
      throw new PreflightError(
        `E_BAD_DID: invalid base58 character ${pyRepr(ch)} ` +
        "(0/O/I/l are excluded from the alphabet)");
    }
    n = n * 58n + BigInt(idx);
  }
  const hexLen = Math.max(2, Math.ceil(n.toString(2).length / 8) * 2);
  let raw = hexToBytes(n.toString(16).padStart(hexLen, "0"));
  const zeros = s.length - s.replace(/^1+/, "").length;
  const out = new Uint8Array(zeros + raw.length);
  out.set(raw, zeros);
  return out;
}

export function parseDid(did) {
  if (typeof did !== "string" || !did.startsWith(DID_PREFIX)) {
    throw new PreflightError("E_BAD_DID: expected did:key:z6Mk...");
  }
  const mb = did.slice(DID_PREFIX.length);
  if (mb.length !== MULTIBASE_CHARS) {
    throw new PreflightError(`E_BAD_DID: expected ${MULTIBASE_CHARS} multibase chars, got ${mb.length}`);
  }
  if (!mb.startsWith("z")) {
    throw new PreflightError("E_BAD_DID: multibase tag must be 'z' (base58btc)");
  }
  const decoded = b58decode(mb.slice(1));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new PreflightError("E_BAD_DID: only ed25519-pub keys (0xed 0x01 varint + 32-byte key) accepted");
  }
  return decoded.subarray(2);
}

export function fingerprint(did) {
  // First 16 lowercase hex chars of SHA-256 of the full did:key STRING.
  return sha256Hex(did).slice(0, 16);
}

// ------------------------------------------------------- canonical payloads
export function canonicalMsg(room, nonce, storedText) {
  return enc8(`${room}|${parseInt(nonce, 10)}|${storedText}`);
}
export function canonicalNote(ns, key, nonce, storedValue) {
  return enc8(`${ns}|${key}|${parseInt(nonce, 10)}|${storedValue}`);
}

// --------------------------------------------------------------- signatures
const SIG_RE = /^[A-Za-z0-9_-]{86}$/;

/** Injected verifier keeps the engine dependency-free (mirrors interfaces.Signer):
 *  ed25519Verify(pub32: Uint8Array, sigRaw: Uint8Array, canonical: Uint8Array) -> boolean */
export function makeVerifier(ed25519Verify) {
  return function verifySigB64u(pub32, sig, canonical) {
    if (!SIG_RE.test(sig || "")) {
      return bad("E_BAD_SIG_ENCODING", "expected 86 unpadded base64url characters");
    }
    let raw;
    try {
      raw = b64urlDecode(sig);
    } catch {
      return bad("E_BAD_SIG_ENCODING", "undecodable base64url");
    }
    try {
      if (!ed25519Verify(pub32, raw, canonical)) {
        return bad("E_SIG_INVALID",
          "signature does not verify for this DID over this canonical string");
      }
    } catch {
      return bad("E_SIG_INVALID", "signature verification failed");
    }
    return ok("verified");
  };
}

export function b64urlDecode(s) {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ------------------------------------------------------------- URL assembly
export function encodeSegment(text) {
  // Mirrors urllib.parse.quote(safe=''): unreserved = A-Za-z0-9 _.-~
  const bytes = enc8(text);
  let enc = "";
  for (const b of bytes) {
    const c = String.fromCharCode(b);
    if (/[A-Za-z0-9_.\-~]/.test(c)) enc += c;
    else enc += "%" + b.toString(16).toUpperCase().padStart(2, "0");
  }
  return [enc, enc.length];
}

export function estimateRequestLine(base, room, did, sig, nonce, sweptText) {
  const [encDid] = encodeSegment(did);
  const [encTxt] = encodeSegment(sweptText);
  const total = `${base}/r/${room}/say-signed/${encDid}/${sig}/${parseInt(nonce, 10)}/${encTxt}`.length;
  if (total > PRACTICAL_URL_CEILING) {
    return bad("E_CANONICAL_TOO_LONG",
      `request line ~${total} chars exceeds practical ceiling ${PRACTICAL_URL_CEILING}; split before encrypting/posting`);
  }
  if (total > PRACTICAL_URL_CEILING / 2) {
    return { ok: true, code: "W_URL_LONG", detail: `request line ~${total} chars; consider splitting` };
  }
  return ok(`request line ~${total} chars`);
}

// ------------------------------------------------------------ DID-note audit
export function auditNote(placedKeyFp, value, did = null, placedNs = "") {
  const findings = [];
  const m = value.match(/did:key:[A-Za-z0-9]+/);
  let innerDid = null;
  if (!m) {
    findings.push(["A_NO_DID_IN_NOTE", "no did:key substring found in the note value"]);
  } else {
    innerDid = m[0];
    try {
      parseDid(innerDid);
    } catch (exc) {
      findings.push(["A_BAD_DID_IN_NOTE", exc.message]);
      innerDid = null;
    }
  }
  if (innerDid) {
    const expectedFp = fingerprint(innerDid);
    if (placedKeyFp.toLowerCase() !== placedKeyFp) {
      findings.push(["W_NOTE_UPPERCASE_KEY", `key '${placedKeyFp}' uses uppercase hex; convention is lowercase`]);
    }
    if (placedKeyFp.toLowerCase() !== expectedFp) {
      findings.push(["W_NOTE_WRONG_KEY",
        `note sits at '${placedKeyFp}' but sha256(did)[0:16] of its DID is '${expectedFp}' -- pattern-3 readers will never resolve it`]);
    }
  }
  if (placedNs === "did") {
    findings.push(["W_NOTE_LEGACY_PATH",
      "flat /kv/did/<fp> is legacy/read-fallback only; republish at /kv/did-<first2>/<rest14>"]);
  }
  const mbm = value.match(/mailbox:([A-Za-z0-9_-]+)/);
  if (mbm) {
    const v = validateRoom(mbm[1]);
    if (!v.ok) findings.push(["W_NOTE_FIELD_MISMATCH", `mailbox:${mbm[1]} is not a valid room name`]);
    else if (!roomClasses(mbm[1]).includes("mb")) {
      findings.push(["W_NOTE_FIELD_MISMATCH", `mailbox:${mbm[1]} lacks the mb- class; mailboxes should be mb-* rooms`]);
    }
  }
  const xx = value.match(/x25519:([A-Za-z0-9_-]+)/);
  if (xx) {
    try {
      const raw = b64urlDecode(xx[1]);
      if (raw.length !== 32) throw new Error();
    } catch {
      findings.push(["W_NOTE_FIELD_MISMATCH", "x25519: value does not decode to 32 bytes"]);
    }
  }
  if (did && innerDid && innerDid !== did) {
    findings.push(["W_NOTE_FIELD_MISMATCH", "note DID differs from the supplied service DID"]);
  }
  if (!findings.length) findings.push(["A_OK", "note passes structural audit"]);
  return findings;
}

// -------------------------------------------------- nonce-floor simulation
export function simulateNonceFloor(tailSnapshot, did, room, proposed) {
  let floor = null, floorSeq = null;
  for (const rec of tailSnapshot) {
    if (rec.from !== did) continue;
    const n = rec.nonce;
    if (n === null || n === undefined) continue;
    if (floor === null || n > floor) { floor = n; floorSeq = rec.seq; }
  }
  const v = validateNonce(proposed, floor);
  if (v.ok && floor === null) {
    return { ok: true, code: "O_NO_PRIOR_WRITES_SEEN",
      detail: `no prior signed writes by this DID visible in /r/${room} window; nonce accepted by the model` };
  }
  if (v.code === "W_LEADING_ZERO_NONCE") return v;
  if (v.ok) return ok(`proposed ${parseInt(proposed, 10)} > visible floor ${floor} (seq ${floorSeq})`);
  return v;
}

// ------------------------------------------------------------------- sha256
export function sha256Hex(input) {
  const bytes = typeof input === "string"
    ? enc8(input) : input;
  return bytesToHex(sha256Bytes(bytes));
}

// ------------------------------------------------------------------ helpers
const _te = typeof TextEncoder !== "undefined" ? new TextEncoder() : null;
export function enc8(s) {
  return _te ? _te.encode(s) : new TextEncoder().encode(s);
}
export function hexToBytes(hex) {
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
