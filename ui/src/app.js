/* J1 Preflight Bench — interaction layer.
 * Consumes ONLY the pure ports (engine/wire/pipeline). No network, no storage.
 * Signatures verify through WebCrypto Ed25519; the result is computed once per
 * run (async) and injected into the otherwise-synchronous pure pipeline.
 */
import {
  sweep, validateRoom, validateNonce, parseDid, encodeSegment,
  PreflightError, sha256Hex,
} from "./engine.js";
import { processRequest, ENGINE_VERSION } from "./pipeline.js";
import { renderPfr } from "./wire.js";

const $ = (id) => document.getElementById(id);
const enc8 = new TextEncoder();

const el = {
  question: $("question"), inputLabel: $("input-label"),
  form: $("intake"), room: $("f-room"), nonce: $("f-nonce"), did: $("f-did"),
  text: $("f-text"), sig: $("f-sig"),
  sweepField: $("sweep-field"), sweepCount: $("sweep-count"),
  ribbon: $("ribbon"), checkRail: $("check-rail"), checksProgress: $("checks-progress"),
  lamp: $("lamp"), lampWord: $("lamp-word"), lampCaption: $("lamp-caption"),
  runsCounter: $("runs-counter"), ledgerList: $("ledger-list"),
  wirePreview: $("wire-preview"), toast: $("toast"),
  stIn: $("st-in"), stStored: $("st-stored"), stDelta: $("st-delta"),
  stCanonical: $("st-canonical"), stUrl: $("st-url"),
  rEngine: $("r-engine"),
  t2Block: $("t2-block"), t2Note: $("t2-note"),
};
el.rEngine.textContent = "v" + ENGINE_VERSION;

const CHECK_ORDER = ["room", "nonce", "did", "sweep", "length", "canonical", "url", "sig"];
const CHECK_LABEL = {
  room: "room", nonce: "nonce-format", did: "did-parse", sweep: "sweep",
  length: "length", canonical: "canonical-build", url: "url-budget", sig: "signature",
};

let lastSignature = null;
let lastOutput = null;
let runCount = 0;
let op = "preview";
let reducedMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;

/* ------------------------------------------------------------ examples */
const EXAMPLES = {
  valid: { room: "lobby", nonce: "7",
           did: "did:key:z6MktbS9GrfWKj7jAj1gKmq3oqgxRuDXEzkh6BfYCunWfTmJ",
           text: "hello world", sig: "" },
  "sweep-trap": { room: "lobby", nonce: "7",
                  did: "did:key:z6MktbS9GrfWKj7jAj1gKmq3oqgxRuDXEzkh6BfYCunWfTmJ",
                  text: "sign\u200bme\u00ad now", sig: "" },
  // Well-formed 86-char base64url that signs DIFFERENT bytes -> E_SIG_INVALID
  "bad-sig": { room: "lobby", nonce: "7",
               did: "did:key:z6MktbS9GrfWKj7jAj1gKmq3oqgxRuDXEzkh6BfYCunWfTmJ",
               text: "hello world",
               sig: "A".repeat(43) + "B".repeat(43) },
  "long-url": { room: "lobby", nonce: "7",
                did: "did:key:z6MktbS9GrfWKj7jAj1gKmq3oqgxRuDXEzkh6BfYCunWfTmJ",
                text: "y".repeat(9000), sig: "" },
};

/* ------------------------------------------------------- field states */
function setFieldState(input, errId, ledId, verdict) {
  const errEl = $(errId), ledEl = $(ledId);
  const row = input.closest(".field-row");
  if (!verdict) { row.classList.remove("invalid"); errEl.textContent = "";
    ledEl.className = "field-led"; return; }
  if (verdict.ok) {
    row.classList.remove("invalid");
    errEl.textContent = verdict.code ? `[${verdict.code}] ${verdict.detail}` : verdict.detail;
    errEl.style.color = verdict.code ? "var(--warn)" : "var(--ink-dim)";
    ledEl.className = "field-led ok";
  } else {
    row.classList.add("invalid");
    errEl.textContent = `[${verdict.code || "INVALID"}] ${verdict.detail}`;
    errEl.style.color = "var(--rej)";
    ledEl.className = "field-led rej";
  }
}

function liveValidate() {
  setFieldState(el.room, "err-room", "led-room",
    el.room.value ? validateRoom(el.room.value.trim()) : null);
  setFieldState(el.nonce, "err-nonce", "led-nonce",
    el.nonce.value ? validateNonce(el.nonce.value.trim()) : null);
  let vDid = null;
  if (el.did.value.trim()) {
    try { parseDid(el.did.value.trim());
          vDid = { ok: true, code: "", detail: "" }; }
    catch (e) { vDid = { ok: false, code: "", detail: e.message }; }
  }
  setFieldState(el.did, "err-did", "led-did", vDid);
}

/* ------------------------------------------------------ sweep field */
function renderSweepField(rawText, result) {
  el.sweepField.innerHTML = "";
  if (!rawText) {
    el.sweepField.innerHTML =
      '<span style="color:var(--ink-dim);font-size:11px">awaiting draft…</span>';
    return;
  }
  const changedAt = new Map((result?.changes ?? []).map(([i, u]) => [i, u]));
  let idx = 0, frag = document.createDocumentFragment();
  for (const ch of rawText) {
    const tile = document.createElement("span");
    tile.className = "glyph";
    const u = changedAt.get(idx);
    if (u !== undefined) {
      tile.classList.add("ghost");
      tile.dataset.u = u;
      tile.textContent = u.replace("U+", "");
    } else {
      tile.textContent = ch === " " ? "·" : ch;
      if (ch === " ") tile.classList.add("space");
    }
    frag.appendChild(tile);
    idx++;
  }
  el.sweepField.appendChild(frag);
  // collapse animation AFTER paint, position-staggered
  const ghosts = [...el.sweepField.querySelectorAll(".ghost")];
  ghosts.forEach((g, i) => {
    if (reducedMotion) g.classList.add("collapsed");
    else setTimeout(() => g.classList.add("collapsed"), 80 + Math.min(i, 40) * 14);
  });
}

/* ---------------------------------------------------- canonical ribbon */
function renderRibbon(room, nonce, stored) {
  el.ribbon.innerHTML = "";
  if (stored === null || stored === undefined || !room) {
    el.ribbon.innerHTML = '<span style="color:var(--ink-dim);font-size:11px">—</span>';
    return;
  }
  const nStr = String(parseInt(nonce || "0", 10));
  // The ribbon shows the TRUE canonical string, pipes included.
  const canonical = `${room}|${nStr}|${stored}`;
  const parts = [
    [room + " |", enc8.encode(room).length],
    [nStr + " |", enc8.encode(nStr).length],
    [stored, enc8.encode(stored).length],
  ];
  for (const [text, bcount] of parts) {
    const s = document.createElement("span");
    s.className = "seg";
    s.appendChild(document.createTextNode(text));
    const bc = document.createElement("span");
    bc.className = "bcount";
    bc.textContent = `${bcount}B`;
    s.appendChild(bc);
    el.ribbon.appendChild(s);
  }
  const d = document.createElement("span");
  d.className = "digest";
  d.textContent = "sha256=" + sha256Hex(canonical).slice(0, 16) + "…";
  el.ribbon.appendChild(d);
}

/* ------------------------------------------------------------ checks */
function resetChecks() {
  el.checkRail.innerHTML = "";
  for (const c of CHECK_ORDER) {
    const chip = document.createElement("span");
    chip.className = "check";
    chip.id = "chk-" + c;
    const led = document.createElement("span"); led.className = "led";
    chip.appendChild(led);
    chip.appendChild(document.createTextNode(CHECK_LABEL[c]));
    el.checkRail.appendChild(chip);
  }
  el.checksProgress.textContent = "idle";
}

function markCheck(name, cls) {
  const chip = $("chk-" + name);
  if (chip) chip.classList.add("on-" + cls);
}

/* ------------------------------------------------------------- ledger */
const tierRank = (fnd) => fnd[0] === "T1-reject" ? 0 : fnd[0] === "T1-warn" ? 1
  : fnd[0] === "T2-observe" ? 2 : 3;

function findingRow(finding) {
  const li = document.createElement("li");
  const [kind, code, ref, detail] = finding;
  li.className = "finding " +
    (kind === "T1-ok" ? "t1-ok" : kind === "T1-warn" ? "t1-warn"
     : kind === "T1-reject" ? "t1-reject" : "t2");
  const tag = document.createElement("span");
  tag.className = "tag";
  tag.textContent = kind === "T2-observe"
    ? `[${kind}:${code}@${ref}]`
    : (code ? `[${kind}:${code}]` : `[${kind}]`);
  const body = document.createElement("span");
  body.className = "detail";
  body.textContent = detail || "";
  li.append(tag, body);
  return li;
}

/* --------------------------------------------------- WebCrypto verifier */
let keyCache = new Map();
async function webcryptoVerify(pub32, sigRaw, canonical) {
  try {
    let keyObj = keyCache.get(pub32.toString());
    if (!keyObj) {
      keyObj = await crypto.subtle.importKey(
        "raw", pub32, { name: "Ed25519" }, false, ["verify"]);
      keyCache.set(pub32.toString(), keyObj);
    }
    return await crypto.subtle.verify({ name: "Ed25519" }, keyObj,
                                      sigRaw, canonical);
  } catch {
    return false;   // unsupported platform / malformed inputs
  }
}
function b64urlToBytes(s) {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

/* -------------------------------------------------------------- main run */
function currentParams() {
  const p = {
    room: el.room.value.trim(), nonce: el.nonce.value.trim(),
    did: el.did.value.trim(), text: el.text.value,
  };
  if (el.sig.value.trim()) p.sig = el.sig.value.trim();
  return p;
}

function buildStruct(params) {
  if (op === "preview") {
    if (!params.room || !params.nonce || !params.did || !params.text) return null;
    return { kind: "PFQ", cid: "0000000000000000", op, params };
  }
  if (op === "verify") {
    if (!params.did || !params.sig) return null;
    const p = { reply: "mb-p-local-preview", did: params.did, sig: params.sig };
    if (params.text && params.room && params.nonce) {
      p.room = params.room; p.nonce = params.nonce; p.text = params.text;
    } else if (params.canonical && params.sha256) {
      p.canonical = params.canonical; p.sha256 = params.sha256;
    } else {
      return null;
    }
    return { kind: "PFQ", cid: "0000000000000000", op, params: p };
  }
  // audit-did-note: reuse fields loosely (value=text, key/ns optional)
  if (!params.text) return null;
  const p = { reply: "mb-p-local-preview", value: params.text };
  if (params.did) p.did = params.did;
  return { kind: "PFQ", cid: "0000000000000000", op, params: p };
}

async function computeAll(interactive = false) {
  const params = currentParams();
  const inputKey = JSON.stringify([op, params]);
  const isIdenticalRun = interactive && inputKey === lastSignature && lastOutput;

  liveValidate();

  // sweep view
  let swept = null;
  try { swept = sweep(params.text); } catch { /* empty-after / too-long path */ }
  renderSweepField(params.text, swept);
  el.sweepCount.textContent = "Δ" + (swept ? swept.change_count : 0);

  renderRibbon(
    swept && params.room ? params.room : null,
    swept ? params.nonce : null,
    swept ? swept.stored : null);

  // status strip
  el.stIn.textContent = [...params.text].length;
  el.stDelta.textContent = swept ? swept.change_count : "0";
  el.stStored.textContent = swept ? swept.char_len : "—";
  el.stCanonical.textContent =
    swept && params.room && /^\d{1,19}$/.test(params.nonce)
      ? enc8.encode(`${params.room}|${parseInt(params.nonce, 10)}|${swept.stored}`).length + "B"
      : "—";
  try {
    const [, ltxt] = encodeSegment(swept ? swept.stored : "");
    const urlLen = 24 + params.room.length + 90 +
      String(parseInt(params.nonce || "0", 10)).length + ltxt;
    el.stUrl.textContent = isNaN(urlLen) ? "—" : urlLen;
  } catch { el.stUrl.textContent = "—"; }

  resetChecks();
  markCheck("sweep", swept ? (swept.change_count ? "warn" : "ok") : "rej");

  // ---- pipeline (with real signature verification when a sig is present)
  const struct = buildStruct(params);
  let pfr = null;
  if (struct) {
    let sigVerdict = null;
    if (struct.params.sig && struct.params.did) {
      try {
        const pub32 = parseDid(struct.params.did);
        let canonicalBytes = null;
        if (op === "verify" && struct.params.canonical) {
          canonicalBytes = enc8.encode(struct.params.canonical);
        } else if (swept) {
          canonicalBytes = enc8.encode(
            `${struct.params.room}|${parseInt(struct.params.nonce, 10)}|${swept.stored}`);
        }
        if (canonicalBytes) {
          let okSig = false;
          if (/^[A-Za-z0-9_-]{86}$/.test(struct.params.sig)) {
            okSig = await webcryptoVerify(
              pub32, b64urlToBytes(struct.params.sig), canonicalBytes);
          }
          sigVerdict = okSig
            ? { ok: true, code: "", detail: "verified" }
            : { ok: false, code: "E_SIG_INVALID",
                detail: "signature does not verify for this DID over this canonical string" };
        }
      } catch { sigVerdict = null; }
    }
    const injectedVerifier = (pub, sig, canon) => {
      void pub; void sig; void canon;
      return sigVerdict ?? { ok: false, code: "", detail: "" };
    };
    pfr = processRequest(struct, null, injectedVerifier);
  }

  applyVerdict(pfr, isIdenticalRun);
  lastSignature = inputKey;
  lastOutput = pfr;
}

function applyVerdict(pfr, isIdenticalRun) {
  runCount++;
  el.runsCounter.textContent =
    `run ${runCount}` + (isIdenticalRun ? " · identical ✓" : "");
  if (!pfr) {
    el.lamp.className = ""; el.lampWord.textContent = "—";
    el.lampCaption.textContent = "fill the wells to preflight a write";
    el.ledgerList.innerHTML = "";
    el.wirePreview.textContent = "—";
    el.checksProgress.textContent = "waiting for complete input";
    return;
  }
  const status = pfr.status;
  const cls = { PASS: "pass", PARTIAL: "partial", FAIL: "fail" }[status] ?? "";
  el.lamp.className = cls;
  el.lampWord.textContent = status;
  el.lampCaption.textContent =
    status === "PASS" ? "Technocore would store this message." :
    status === "PARTIAL" ? "Would store — read the amber rows." :
    status === "FAIL" ? "Technocore would refuse this write." :
    "No prediction possible.";

  // findings ledger, rejects first
  el.ledgerList.innerHTML = "";
  const ordered = [...pfr.findings].sort((a, b) => tierRank(a) - tierRank(b));
  if (ordered.length) for (const f of ordered) el.ledgerList.appendChild(findingRow(f));

  // map findings onto check-rail lamps by keyword region
  const has = (kw) => ordered.some(f => f[1] === kw || f[3].includes(kw));
  markCheck("room", has("E_BAD_ROOM") ? "rej" : "ok");
  markCheck("nonce", has("E_BAD_NONCE_FORMAT") || has("E_NONCE_NOT_GREATER") ? "rej"
    : has("W_LEADING_ZERO_NONCE") ? "warn" : "ok");
  markCheck("did", has("E_BAD_DID") ? "rej" : "ok");
  markCheck("length", has("E_TEXT_TOO_LONG") || has("E_EMPTY_AFTER_SWEEP") ? "rej" : "ok");
  markCheck("canonical", "canonical bytes len=" in Object.fromEntries(ordered.map(f=>[f[3],1])) ? "ok"
    : ordered.some(f => f[3].startsWith("canonical bytes len=")) ? "ok" : (status === "FAIL" ? "rej" : "ok"));
  const urlF = ordered.find(f => f[1] === "W_URL_LONG" || f[1] === "E_CANONICAL_TOO_LONG");
  markCheck("url", urlF ? (urlF[1] === "W_URL_LONG" ? "warn" : "rej")
    : ordered.some(f => f[3].includes("request line")) ? "ok" : "ok");
  if (structuredClone && ordered.some(f => f[1] === "E_SIG_INVALID"))
    markCheck("sig", "rej");
  else if (ordered.some(f => f[1] === "E_BAD_SIG_ENCODING"))
    markCheck("sig", "rej");
  else if (ordered.some(f => f[3] === "verified"))
    markCheck("sig", "ok");
  const done = CHECK_ORDER.filter(c => $("chk-" + c)?.className.includes("on-")).length;
  el.checksProgress.textContent = `${done}/${CHECK_ORDER.length}`;

  // T2 honesty panel
  const t2rows = ordered.filter(f => f[0] === "T2-observe");
  el.t2Block.hidden = t2rows.length === 0;
  if (t2rows.length) {
    el.t2Note.textContent = t2rows.map(f =>
      `${f[1]}@${f[2]} — ${f[3]} (windowed observation; not a promise)`).join("\n");
  }

  // wire preview: rendered PFR line via the JS wire port (static import)
  try {
    el.wirePreview.textContent = renderPfr(pfr);
  } catch (e) {
    el.wirePreview.textContent = "RENDER-ERR: " + e.message;
  }

  // remediation pointer on FAIL
  const firstReject = ordered.find(f => f[0] === "T1-reject");
  if (firstReject) {
    const cap = el.lampCaption;
    cap.textContent = `fix ${firstReject[1] || "the marked field"} and rerun.`;
  }
}

/* ------------------------------------------------------------ events */
const debounced = (() => { let h; return () => {
  clearTimeout(h); h = setTimeout(() => computeAll(false), 140);
};})();
["room", "nonce", "did"].forEach(k => el[k].addEventListener("input", () => { liveValidate(); debounced(); }));
el.text.addEventListener("input", debounced);
el.sig.addEventListener("input", debounced);

document.querySelectorAll(".op-tab").forEach(t => t.addEventListener("click", () => {
  document.querySelectorAll(".op-tab").forEach(x => x.setAttribute("aria-selected", "false"));
  t.setAttribute("aria-selected", "true");
  op = t.dataset.op;
  el.inputLabel.textContent = `[INPUT · ${op.toUpperCase()}]`;
  computeAll(true);
}));

document.querySelectorAll(".example-chip").forEach(b => b.addEventListener("click", () => {
  const ex = EXAMPLES[b.dataset.ex];
  if (!ex) return;
  el.room.value = ex.room; el.nonce.value = ex.nonce;
  el.did.value = ex.did; el.text.value = ex.text;
  el.sig.value = ex.sig ?? "";
  engageQuestion();
  computeAll(true);
}));

el.form.addEventListener("submit", (e) => { e.preventDefault(); computeAll(true); });
addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
    e.preventDefault(); computeAll(true);
  }
});

$("copy-pfr").addEventListener("click", async () => {
  const line = el.wirePreview.textContent;
  if (!line || line === "—") return;
  try { await navigator.clipboard.writeText(line); } catch { /* clipboard denied */ }
  el.toast.classList.add("show");
  setTimeout(() => el.toast.classList.remove("show"), 1200);
});

$("print-view").addEventListener("click", () => print());

/* standing question collapses on first engagement */
function engageQuestion() { el.question.classList.add("engaged"); }
["focus", "input"].forEach(ev => {
  el.text.addEventListener(ev, engageQuestion, { once: ev === "focus" });
});

/* deep-linkable demo states: #demo=<name> loads an example deterministically
 * (used by docs, QA harnesses, and screenshots). ?theme=light|dark overrides
 * the OS preference for reproducible QA. */
const themeParam = new URLSearchParams(location.search).get("theme");
if (themeParam === "dark" || themeParam === "light") {
  const probe = document.createElement("style");
  // Minimal, honest override: recolor the token set for this session only.
  probe.textContent = `:root${themeParam === "dark" ? "" : ".qa-light"}{}`;
  if (themeParam === "light") {
    document.documentElement.style.colorScheme = "light";
    document.body?.classList?.add("qa-light");
  }
}
if (themeParam === "dark") {
  const st = document.createElement("style");
  st.textContent = `@media (prefers-color-scheme: light){:root{
    --ground:#0C0E14; --panel:#11151C; --hairline:#30363D;
    --ink:#E6EDF3; --ink-dim:#8B949E;
    --ok:#3FB950; --warn:#E3B341; --rej:#FF7B72; }}`;
  document.head.appendChild(st);
}

const demoMatch = location.hash.match(/^#demo=([a-z0-9-]+)$/);
if (demoMatch && EXAMPLES[demoMatch[1]]) {
  const ex = EXAMPLES[demoMatch[1]];
  el.room.value = ex.room; el.nonce.value = ex.nonce;
  el.did.value = ex.did; el.text.value = ex.text;
  el.sig.value = ex.sig ?? "";
  engageQuestion();
}
computeAll(true);
