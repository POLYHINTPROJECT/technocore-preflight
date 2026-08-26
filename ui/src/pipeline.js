/* J1 pipeline — JavaScript port of adapter/pipeline.py.
 * parsed-PFQ -> PFR struct. Pure. Findings order and status derivation are
 * byte-exact against the Python implementation (diff-harness enforced).
 */
import * as pf from "./engine.js";
import { enc8 } from "./engine.js";
import { renderPfr } from "./wire.js";

export const ENGINE_VERSION = "0.1.0";

const f = (kind, code = "", ref = "", detail = "") => [kind, code, ref, detail];

function status(findings) {
  const kinds = new Set(findings.map(x => x[0]));
  if (kinds.has("T1-reject")) return "FAIL";
  if (kinds.size === 1 && kinds.has("T1-ok")) return "PASS";
  return "PARTIAL";
}

// ------------------------------------------------------------- preview
export function runPreview(params, verifySig) {
  const findings = [];
  const { room, nonce, did, text } = params;

  const v = pf.validateRoom(room);
  findings.push(v.ok ? f("T1-ok", "", "", v.detail) : f("T1-reject", "E_BAD_ROOM", "", v.detail));

  const nv = pf.validateNonce(nonce);
  if (!nv.ok) findings.push(f("T1-reject", nv.code, "", nv.detail));
  else if (nv.code === "W_LEADING_ZERO_NONCE") findings.push(f("T1-warn", nv.code, "", nv.detail));
  else findings.push(f("T1-ok", "", "", `nonce ${nv.detail}`));

  let pub = null;
  try {
    pub = pf.parseDid(did);
    findings.push(f("T1-ok", "", "", `DID parses (${pub.length}-byte key)`));
  } catch (exc) {
    // Python keeps str(exc) verbatim (incl. 'E_BAD_DID: ' prefix) in the detail.
    findings.push(f("T1-reject", "E_BAD_DID", "", exc.message));
  }

  let sweptStored = null;
  try {
    const s = pf.sweep(text);
    sweptStored = s.stored;
    if (s.change_count === 0) {
      findings.push(f("T1-ok", "", "", "sweep identity"));
    } else {
      const shown = s.changes.slice(0, 8)
        .map(([, u, c]) => `${u}:${c}`).join(", ");
      const more = s.change_count > s.changes.length ? ` (+${s.change_count - 8} more)` : "";
      findings.push(f("T1-warn", "W_SWEPT_CHARS", "",
        `${s.change_count} replaced: ${shown}${more}`));
    }
    findings.push(f("T1-ok", "", "",
      `stored len=${s.char_len} sha256=${s.sha256_hex.slice(0, 16)}`));
  } catch (exc) {
    const msg = exc.message;
    const code = msg.includes("E_EMPTY_AFTER_SWEEP") ? "E_EMPTY_AFTER_SWEEP"
      : (msg.includes("E_TEXT_TOO_LONG") ? "E_TEXT_TOO_LONG" : "");
    findings.push(f("T1-reject", code, "", msg));
  }

  const fatal = findings.some(x => x[0] === "T1-reject");
  if (!fatal && sweptStored !== null && pub !== null) {
    const canonical = pf.canonicalMsg(room, parseInt(params.nonce, 10), sweptStored);
    findings.push(f("T1-ok", "", "", `canonical bytes len=${canonical.length}`));
    const sig = params.sig ?? null;
    if (sig !== null) {
      const sv = verifySig(pub, sig, canonical);
      findings.push(sv.ok ? f("T1-ok", "", "", sv.detail) : f("T1-reject", sv.code, "", sv.detail));
    }
  }
  return findings;
}

// -------------------------------------------------------------- verify
export function runVerify(params, verifySig) {
  let pub;
  try {
    pub = pf.parseDid(params.did);
  } catch (exc) {
    return [f("T1-reject", "E_BAD_DID", "", exc.message)];
  }
  const sig = params.sig ?? null;
  if (sig === null) {
    return [f("T1-reject", "", "", "verify requires sig=<86-char base64url>")];
  }
  let canonical;
  if ("canonical" in params) {
    canonical = enc8(params.canonical);
    const claimed = params.sha256;
    if (claimed) {
      const actual = pf.sha256Hex(canonical);
      if (actual !== claimed) {
        return [f("T1-reject", "", "",
          `canonical/sha256 mismatch: claimed ${claimed.slice(0, 16)} actual ${actual.slice(0, 16)}`)];
      }
    }
  } else {
    let swept;
    try {
      swept = pf.sweep(params.text).stored;
    } catch (exc) {
      return [f("T1-reject", "", "", exc.message)];
    }
    canonical = pf.canonicalMsg(params.room, parseInt(params.nonce, 10), swept);
  }
  const sv = verifySig(pub, sig, canonical);
  return [sv.ok ? f("T1-ok", "", "", sv.detail) : f("T1-reject", sv.code, "", sv.detail)];
}

// ---------------------------------------------------------- audit-did-note
export function runAudit(params) {
  const value = params.value;
  const did = params.did ?? null;
  const fp = params.fp || (did ? pf.fingerprint(did) : null);
  const ns = params.ns ?? "";
  const key = params.key ?? "";

  const rows = pf.auditNote(key || fp || "?".repeat(16), value, did, ns || null);
  const findings = [];
  for (const [code, detail] of rows) {
    if (code === "A_OK") findings.push(f("T1-ok", "", "", detail));
    else if (code.startsWith("W_")) findings.push(f("T1-warn", code, "", detail));
    else if (code.startsWith("A_NO") || code.startsWith("A_BAD"))
      findings.push(f("T1-reject", "", "", `${code}: ${detail}`));
  }
  if (key && fp) {
    const expected = `/kv/did-${fp.slice(0, 2)}/${fp.slice(2)}`;
    if ((ns || "").startsWith("did-")) {
      const actual = `/kv/did-${ns.slice(4)}/${key}`;
      findings.push(actual === expected
        ? f("T1-ok", "", "", `placement ${actual} is canonical`)
        : f("T1-warn", "W_NOTE_WRONG_KEY", "", `placement ${actual} vs canonical ${expected}`));
    } else if (ns === "did") {
      findings.push(f("T1-warn", "W_NOTE_LEGACY_PATH", "", `flat namespace; canonical is ${expected}`));
    }
  }
  return findings;
}

export const OPS = { preview: runPreview, verify: runVerify, "audit-did-note": runAudit };

export function buildPfr(cid, op, findings, engineVersion = ENGINE_VERSION, error = null) {
  if (error !== null)
    return { kind: "PFR", cid, status: "ERROR", engine: engineVersion, findings: [], error };
  return { kind: "PFR", cid, status: status(findings), engine: engineVersion, findings };
}

/** Pure entrypoint: (parsed | null, parseErrorCodeOrNull) -> PFR struct. */
export function processRequest(parsed, parseErrorCode, verifySig, engineVersion = ENGINE_VERSION) {
  if (parseErrorCode !== null && parseErrorCode !== undefined) {
    const cid = (parsed ?? {}).cid ?? "";
    return buildPfr(cid, "?", [], engineVersion, parseErrorCode);
  }
  const op = parsed.op;
  const handler = OPS[op];
  if (!handler) {
    return buildPfr(parsed.cid, op, [], engineVersion, `unknown operation '${op}'`);
  }
  try {
    const findings = handler(parsed.params, verifySig);
    return buildPfr(parsed.cid, op, findings, engineVersion);
  } catch (exc) {
    return buildPfr(parsed.cid, op, [], engineVersion, `engine fault: ${exc.name}`);
  }
}
