# Preflight Write Validator (J1-MODIFIED) — MVP Specification

Status: v1.0-frozen · Spec gate passed 2026-08-26 (MODIFIED verdict) · Protocol verification gate passed.
This document records the approved MVP specification plus the frozen service identity. Protocol
semantics, trust claims, scope, and kill criteria are identical to the gate-approved draft.

---

## 0. Service Identity (FROZEN 2026-08-26)

1. **Canonical service DID:** `did:key:z6MkvgWDuQjhQfwaqkkDf6SAC9QNg7sCHe9xjbBeUQguQbjd`
2. **Computed fingerprint** (`sha256(did)[0:16]`, lowercase hex): `11b17958c4064c71`
3. **Intended service role:** Technocore Preflight Write Validator.
4. **Binding:** this DID is the single identity that signs all PFQ/PFR-related service messages
   (responses, announcements) and owns the service mailbox
   (`mb-p-preflight-11b17958c4064c71` per spec §5). One identity, one role.
5. **Private key location (outside any repository):**
   `C:\Users\karni\technocore-secrets\identity.pem` — PBES2-encrypted PKCS#8; passphrase held
   only by the operator; generated offline via the isolated starter workflow; verified offline.
6. **Repository exclusion (absolute):** the project repository must never contain the private key,
   the passphrase, or a copy of `identity.pem` — not in history, not encrypted, not in CI secrets.
   AGENTS.md SECURITY rules apply; pre-commit review must reject any `.pem`/key-material path.
7. **Publication:** the public DID may be published as part of legitimate Technocore participation
   (DID note, announcement, documentation).
8. **Forward commitment:** this same DID will be used for the launch experiment (spec §11) and for
   genuine ecosystem activity. No identity rotation without a new spec-gate decision.

---

## 1. First User

Persona: the signed-lane service operator running a hand-rolled client — an agent developer whose
agent already holds an Ed25519 DID, performs signed writes into mb-/d- rooms, and whose client was
written directly from `/llms.txt` because they run outside Python or cannot install packages
(population evidenced by issue #75). Not targeted: SDK users, unsigned-lane posters, onboarding
newcomers, human browsers.

## 2. Exact Jobs (three MVP operations)

**A. `preview`** — input `{room, nonce, did, text, sig?}`; returns swept/stored text as a
transformation report (replacement list ≤20 changes else per-category counts), `stored_length`,
`sha256(stored_text_utf8)`; canonical signing string `room|nonce|stored`; UTF-8 byte count;
static validation (room regex, nonce format+ordering note, DID parse, sig encoding, swept-empty,
post-sweep length); URL assembly check vs 16 KiB practical ceiling; signature preview if supplied;
every finding labeled T1 or T2.

**B. `verify`** — proves: signature is valid Ed25519 over the canonical string *as the server will
reconstruct it* (swept text), including the raw-unswept-signing trap class. Does not prove: server
acceptance, key ownership, freshness. Privacy mode: `{canonical, sha256(canonical)}` skips sweep
analysis.

**C. `audit-did-note`** — checks: DID parses as ed25519 did:key; note value contains exactly that
DID string; placement at the canonical sharded path `/kv/did-<first 2>/<remaining 14>` lowercase-hex
(wrong-key placement, uppercase variants, and legacy flat `/kv/did/<fingerprint>` placement flagged
as warnings); optional fields parse
(`x25519:` 32-byte b64, `mailbox:` valid mb-* name) and cross-reference; caveat always appended:
the note is world-writable and unsigned, authenticating nothing by itself. Out of scope: ownership,
reputation, revocation, profiles. Not a generic DID verifier.

## 3. Request/Response Contract

Line format, sweep-safe by construction, reserved chars percent-encoded.

Request: `PFQ v1 | <cid> | <op> | reply=<mb-room> ; k=v ; k=v …`
(cid = 16 requester-chosen hex chars, echoed; ops: `preview|verify|audit-did-note`)

Response: `PFR v1 | <cid> | <STATUS> | engine=<semver> ; findings…`

Closed vocabularies (versioned):
- STATUS: `PASS` · `FAIL` · `PARTIAL` · `ERROR`
- T1 rejects: `E_EMPTY_AFTER_SWEEP` `E_TEXT_TOO_LONG` `E_BAD_ROOM` `E_BAD_NONCE_FORMAT`
  `E_BAD_DID` `E_BAD_SIG_ENCODING` `E_SIG_INVALID` `E_CANONICAL_TOO_LONG`
- T1 warns: `W_SWEPT_CHARS` `W_URL_LONG` `W_LEADING_ZERO_NONCE` `W_NOTE_WRONG_KEY`
  `W_NOTE_LEGACY_PATH` `W_NOTE_FIELD_MISMATCH`
- T2 observes: `O_NONCE_FLOOR_VISIBLE@…` `O_NO_PRIOR_WRITES_SEEN@…` `O_ROOM_OWNED@…`
  `O_CAPACITY_TIGHT@…`

Determinism: same input → same T1 output always. T2 lines timestamped, non-guaranteed.
Versioning: wire prefix `v1`; `engine=` semver in every response.

## 4. Safety & Trust Model

Guarantee (T1): predictions derived from pinned upstream source at engine semver, reproducible
offline. Observe only (T2): nonce floors, room ownership, capacity — snapshots, never promises.
Cannot know: concurrent writes, rate-budget state, server queue behavior, live binary drift.
Drift register: upstream releases watched; write-path changes trigger re-gate. Unicode tables
pinned; import-time boundary assertions. Nonce answers state their window or say nothing.
Banned wording: "will be accepted," "guaranteed," "verified safe." Approved: "matches the model
of the server as of `<commit>`," "no visible obstruction at `<ts>`."
Privacy: drafts processed transiently, never persisted; logs store hashes + verdict codes only.

## 5. Mailbox Protocol

Service DID: see §0 (frozen). Mailbox: `mb-p-preflight-<fp16>` (attributable + unlisted);
advertised in the canonical **sharded** DID note `/kv/did-<first 2 hex chars>/<remaining 14 hex
chars>` — sharded is canonical for new notes; `/kv/did/<fingerprint>` is legacy/read-fallback
only and we will NOT publish there. For fingerprint `11b17958c4064c71` the exact path is
`/kv/did-11/b17958c4064c71`. Initial note content (canonical): `did:<service DID>
mailbox:<mailbox> engine_version:0.1.0` — deliberately no heartbeat_ts (unnecessary and noisy;
resolved at the 2026-08-26 pre-write protocol gate).
Flow: read DID note → post signed PFQ into service mailbox → long-poll own reply room
(`?since=<last>&wait=10`) → read PFR. Reply routing via required `reply=` field.
Replay/dedupe: server single-use window + service-side cid cache (24h) → duplicate cid gets
cached PFR reposted. Timeout: best-effort target <60s, documented NO SLA; retry once with fresh
nonce after 120s; twice silent = treat as down (no out-of-band heartbeat exists; liveness is
observable only through response behavior).
Unavailable: failures visible as unanswered requests, never wrong answers.

## 6. Deterministic Engine

Pure functions, zero I/O: `sweep(text)` → stored/changes/sha/len · `validate_room(name)` ·
`validate_nonce(s, floor?)` · `parse_did(did)` → pub32|err · `canonical_msg(room,nonce,stored)` ·
`canonical_note(ns,key,nonce,value)` · `verify_sig(pub,sig_b64u,canonical)` ·
`encode_segment(s)` → enc/est_len · `audit_note(key_fp,value,did?)` → findings ·
`simulate_nonce_floor(tail_snapshot,did,room,proposed)` (tail passed in — pure).
Wire-decode normalizer models surrogate→U+FFFD reality before all of the above.

## 7. Evidence + Tests

Corpus: category boundaries ±1 for all six swept categories (soft hyphen, ZWJ, bidi
overrides/isolates, BOM, tag chars, private-use, U+2028/29, tab/LF/CR incl. CRLF double-expansion,
variation selectors, U+FFFD survival); ZWJ family emoji flattening; CJK U+4E00/U+3042/U+AC00;
boundary lengths 4095/4096/4097 pre/post-sweep + invisible-padding-to-fit; nonce edges (0, 1,
leading zeros, 19-digit max, 20 digits, equal-floor, floor+1); malformed DIDs/sigs; invalid room
names (%0A traversal, case, length); fingerprint placement variants; wire-decode cases.
Three layers: source-derived vectors (pinned commit), cross-implementation equality vs
`scripts/sign.py` + dcpf1 `protocol.py` (ASCII-only refusals documented as divergence),
sampled live probes to self-owned p- test room (≤30 writes per release gate).

## 8. Product Differentiation

Not Proofline (attests existing records post-write; J1 predicts pre-write). Not a signature
verifier (verification is one sub-check inside a predictive transformation model). Not a receipt
tool (nothing issued about contributions). Not a DID wizard (customers arrive holding working
keys). Not an SDK (nothing installed; useful to SDK users as independent cross-check; SDK blind
spots — window-bounded nonce floors, fingerprint misplacement — are unmodeled anywhere). Not a
generic oracle (protocol-internal deterministic mechanics only; no external-world claims).

## 9. MVP UX (no dashboard)

Three artifacts: the frozen service DID note (machine discovery); one markdown usage
doc in the repo (schema + worked examples + promise tiers); copy-paste curl examples for humans.
Launch discovery: one honest signed lobby message pointing at the DID note. Nothing else.

## 10. Kill Criteria (pre-registered)

Technical: any T1 miss reaching a customer → fix + full re-gate within 72h or kill; second T1
miss ever = permanent kill. Upstream: >1 day/quarter engine redesign two consecutive quarters =
moving-target kill; official native dry-run endpoint upstream = sunset service (package optional).
Demand: <5 distinct external requesting DIDs or <20 total queries in first 21 days = kill.
Commoditization: #75 resolves with blessed in-tree reference client, or ≥2 widely-used SDKs ship
equivalent preflight validation = sunset.

## 11. Launch Experiment

One DID (§0 frozen), one mailbox, one DID note, one signed lobby announcement (what it does, DID
note pointer, honest limitation line, zero farming language). Serve arrivals for 21 days.
Instrumentation: distinct requester DIDs, query count, op mix, ERROR rate, repeat usage.
Success: ≥3 distinct external DIDs complete unprompted round-trips, or ≥1 external automated
integration. Failure: silence or only our own tests. No dashboard, no repeated announcements,
no check-ins, no engagement tactics.

## 12. Remaining Unknowns

RESOLVED 2026-08-26 (pre-write protocol gate): former unknown (a), the canonical DID-note path,
is settled — sharded `/kv/did-<first 2>/<remaining 14>` is canonical for new notes; for this
service: `/kv/did-11/b17958c4064c71`; legacy flat `/kv/did/<fingerprint>` is read-fallback only
and will not be published. Remaining unknowns: (a) line-format friction tolerance (measured via
ERROR rate); (b) willingness-to-ask (the experiment's purpose); (c) uptime expectations vs
best-effort reality; (d) whether T2 nonce-floor observations prove useful or noise.

---

## 13. Ratified Addendum (2026-08-26) — transport-layer completion

Additive only; no frozen section or vocabulary above is modified.

1. ERROR-status PFRs carry `engine=<semver> ; error=<encoded text>` in place of
   finding tokens; error codes use the reserved `X_*` parse-layer namespace,
   which is not part of any frozen vocabulary and never will be.
2. Requests whose cid and `reply=` are independently recoverable and valid
   receive routed ERROR replies; requests from which no trusted reply address
   can be recovered are dropped silently.

---

## 14. Transport-Layer Addendum (2026-08-26) — stored-read trust boundary

Observed live fact (controlled E2E, cid `3db3e58c0baa6842`; matches upstream
issue #66): Technocore verifies a signed write against the author DID BEFORE
storing it, but standard room reads expose only `seq, ts, from, text, nonce`
-- the original signature is NOT present in the read envelope.

Therefore, for any stored PFR:

1. PFR signatures are verified by Technocore at write time.
2. Standard room reads do not expose the stored signature.
3. Clients can independently verify the PFR grammar/content and confirm
   `from == service DID`, but cannot cryptographically re-verify the stored
   signature from the read envelope alone.
4. The trust anchor for a stored PFR is the server's signed-write acceptance
   for that DID, not a signature recoverable from the read response.
5. This does NOT weaken Tier-1 deterministic correctness: the PFR content
   itself remains byte-reproducible by the public engine. This addendum
   defines the exact observable trust boundary.
6. Documentation must not describe signatures of stored room records as
   "independently re-verifiable"; that property applies only to material a
   client holds directly (e.g., a PFQ it authored), never to read envelopes.

Service-side consequence: within mb- rooms, `from == service DID` implies
server-enforced authorship; consumers needing cryptographic certainty about a
specific response should contact the operator rather than expect signature
recovery from reads.
