/* Differential harness: replay every corpus case through the JS ports and
 * demand deep equality with the Python oracle outputs.
 *
 * Run: node ui/tests/diff-harness.mjs     (exit 0 == all cases agree)
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  sweep, validateRoom, roomClasses, validateNonce, parseDid, fingerprint,
  canonicalMsg, canonicalNote, makeVerifier, estimateRequestLine,
  encodeSegment, auditNote, PreflightError,
} from "../src/engine.js";
import { bytesToHex } from "../src/sha256.js";
import {
  parsePfq, renderPfq, parsePfr, renderPfr, decodeValue, WireError,
} from "../src/wire.js";
import { processRequest } from "../src/pipeline.js";

const here = dirname(fileURLToPath(import.meta.url));
const corpus = JSON.parse(readFileSync(join(here, "corpus.json"), "utf-8"));

// ---- Ed25519 via Node crypto through the injected verifier seam
const { createPublicKey, verify: cryptoVerify } = await import("node:crypto");
function ed25519Verify(pub32, sigRaw, canonical) {
  try {
    const spki = Buffer.concat([
      Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
                   0x03, 0x21, 0x00]),
      Buffer.from(pub32),
    ]);
    return cryptoVerify(null, canonical, createPublicKey({ key: spki, format: "der", type: "spki" }), sigRaw);
  } catch {
    return false;
  }
}
const verifySig = makeVerifier(ed25519Verify);
const hexToBuf = (h) => Buffer.from(h, "hex");

function eq(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null) return false;
  if (Array.isArray(a)) {
    if (!Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => eq(v, b[i]));
  }
  if (typeof a === "object") {
    const ka = Object.keys(a), kb = Object.keys(b);
    if (ka.length !== kb.length) return false;
    return ka.every(k => eq(a[k], b[k]));
  }
  return false;
}

let pass = 0, fail = 0;
const failures = [];

function call(fn) {
  // Execute fn; normalize thrown engine errors to oracle shapes.
  try {
    return { value: fn() };
  } catch (e) {
    if (e instanceof WireError) return { value: { wire_error: [e.code, e.detail] } };
    if (e instanceof PreflightError) return { value: { raise: e.message } };
    throw e;
  }
}

function run(section, id, fn, wantY) {
  let got;
  try {
    got = call(fn).value;
  } catch (e) {
    fail++; failures.push([section, id, `HARNESS THREW: ${e.message}`, wantY]);
    return;
  }
  if (eq(got, wantY)) pass++;
  else { fail++; failures.push([section, id, got, wantY]); }
}

for (const [section, cases] of Object.entries(corpus.sections)) {
  for (const c of cases) {
    const x = c.x ?? {};
    switch (section) {
      case "sweep":
        run(section, c.id, () => sweep(x.text), c.y);
        break;

      case "rooms":
        if ("classes_of" in x)
          run(section, c.id, () => roomClasses(x.classes_of), c.y);
        else
          run(section, c.id, () => { const v = validateRoom(x.name);
            return { ok: v.ok, code: v.code, detail: v.detail }; }, c.y);
        break;

      case "nonces":
        run(section, c.id, () => { const v = validateNonce(x.nonce, x.floor);
          return { ok: v.ok, code: v.code, detail: v.detail }; }, c.y);
        break;

      case "dids":
        if ("fingerprint" in x)
          run(section, c.id, () => fingerprint(x.fingerprint), c.y);
        else
          run(section, c.id, () => {
            try { return { pub32_hex: bytesToHex(parseDid(x.did)) }; }
            catch (e) {
              if (e instanceof PreflightError) return { raise: e.message };
              throw e;
            }
          }, c.y);
        break;

      case "canonical":
        run(section, c.id, () =>
          ("msg" in x
            ? bytesToHex(canonicalMsg(x.msg[0], x.msg[1], x.msg[2]))
            : bytesToHex(canonicalNote(x.note[0], x.note[1], x.note[2], x.note[3]))),
          c.y);
        break;

      case "signatures":
        run(section, c.id, () => { const v = verifySig(
            hexToBuf(x.verify[0]), x.verify[1], hexToBuf(x.verify[2]));
          return { ok: v.ok, code: v.code, detail: v.detail }; }, c.y);
        break;

      case "url":
        if ("segment" in x)
          run(section, c.id, () => { const [enc, len] = encodeSegment(x.segment);
            return { encoded: enc, length: len }; }, c.y);
        else
          run(section, c.id, () => {
            const [, ldid] = encodeSegment(x.estimate[2]);
            const [, ltxt] = encodeSegment(x.estimate[5]);
            const v = estimateRequestLine(...x.estimate);
            return { enc_did_len: ldid, enc_txt_len: ltxt,
                     ok: v.ok, code: v.code, detail: v.detail };
          }, c.y);
        break;

      case "audit":
        run(section, c.id, () =>
          auditNote(x.audit.placed_key_fp, x.audit.value,
                    x.audit.did ?? null, x.audit.placed_ns ?? ""),
          c.y);
        break;

      case "wire":
        if ("render_pfq" in x) run(section, c.id, () => renderPfq(x.render_pfq), c.y);
        else if ("parse_pfq" in x) run(section, c.id, () => parsePfq(x.parse_pfq), c.y);
        else if ("render_pfr" in x) run(section, c.id, () => renderPfr(x.render_pfr), c.y);
        else if ("parse_pfr" in x) run(section, c.id, () => parsePfr(x.parse_pfr), c.y);
        else if ("decode_value" in x) run(section, c.id, () => decodeValue(x.decode_value), c.y);
        else { fail++; failures.push([section, c.id, "no known op key", c.y]); }
        break;

      case "pipeline":
        run(section, c.id,
          () => processRequest(x.process[0], x.process[1], verifySig), c.y);
        break;

      default:
        fail++; failures.push([section, c.id, "UNKNOWN SECTION", null]);
    }
  }
}

for (const [s, id, got, want] of failures.slice(0, 12)) {
  console.log(`\nFAIL [${s}] ${id}`);
  console.log("  got :", JSON.stringify(got)?.slice(0, 300));
  console.log("  want:", JSON.stringify(want)?.slice(0, 300));
}
console.log(`\n${pass} agree, ${fail} differ, of ${pass + fail} cases`);
process.exit(fail === 0 ? 0 : 1);
