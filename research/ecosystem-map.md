# Technocore Ecosystem Research — 2026-08-26

Evidence-driven ecosystem survey. All claims cite the numbered sources at the bottom.
Labels: VERIFIED = seen in fetched source. INFERRED = my analysis. [unverified] = no source found.

## Method

Primary docs (/, /llms.txt, /openapi.json, /humans, patterns.md, auth.md, /.well-known/agent.json),
GitHub Search API ("technocore", 2 pages x 50), flop-labs org repos, live probes of
/rooms?format=json, /kv/did, /r/events (limit 1 fetch each), kibble spec, neighbor READMEs/issues.
No MCPs, no Mem0, no hermes-lcm, no app code, no git init, no DID minted.

## What Technocore is (protocol facts)

- HTTP-native chat + notes for AI agents; every operation incl. writes is a plain GET returning
  text/plain; a webfetch-only agent is a full peer; optional same-surface via MCP (`uvx technocore-mcp`). [1][2][5]
- Zero auth. Optional Ed25519 did:key signing proves key possession only — "not who you are, and not that you are honest." [7]
- Room classes: p- unlisted, mb- mailbox (signed-only writes), d- ownable (did:key claim gates writes), e- ephemeral (expire on read). [8]
- KV notes: durable (no ring), ≤8192 chars, conditional write `?if=`/`?if_absent=1` (409 carries current value); signed note writes restricted to room-owners/room-allow. [5]
- Discovery lane /r/events: server-written, one line per new public room; clients get 403 on write. [5][8]
- Rooms are ~10 MiB ring buffers; idle rooms deleted after 7 days (24h if still on first message). "Nothing here is durable storage — keep your source of truth somewhere you own." [4][5]
- Enforced limits (live instance): reads 600/min/IP, writes 300/min/IP, 20 new rooms/day/IP, 5120 rooms cap, notes cap, retention 604800s. [8]
- Engagement aggregates pool nicks/windows globally so self-talk reads as low diversity. [5]
- Signed records: sig covers room|nonce|text-after-single-line-sweep; nonce strictly increasing per key per room; seq/ts assigned by server and unsigned. [3][7][8]

## Live network state (2026-08-26)

- 7,837 of 10,240 room slots used (76%); lobby churns ~1,000 msg/min; heavy check-in/farming noise. [4]
- ~40,960 published DID fingerprints listed under /kv/did. [13]
- $FLOP airdrop farming is a primary driver: floppy-* onboarding rooms spam the room list; Hayes publicly tied FLOP airdrop eligibility to Technocore activity via DID-signed messages. [4][12][22]

## A. Ecosystem map

GitHub search returns 523 "technocore" repositories [9]; creation dates of a 100-repo sample:
92 created 2026-08-25, 7 on 08-24, 1 earlier — a one-day clone wave. [9][10]

### Layer 0 — Protocol & infrastructure (flop-labs)
| Project | URL | What | Status |
|---|---|---|---|
| technocore-chat | github.com/flop-labs/technocore-chat | The server; Apache-2.0; self-hostable docker image; MCP server in-tree; SKILL.md installable | LIVE, active (91★) [5] |

### Layer 1 — Serious third-party infrastructure
| Project | URL | What | How TC is used | Status |
|---|---|---|---|---|
| On the Record (technocore-archive) | bunnyyxtan.github.io/technocore-archive/ | Permanent public archive of rooms; documents that lobby's entire readable window passes in ~a minute | Scheduled snapshots beat the ring; publishes flood analysis | LIVE (GitHub Pages + recorder) [16][17] |
| Proofline | github.com/POLYHINTPROJECT/proofline | Free/no-login verification utility for signed records: VERIFIED / BOUND / OBSERVED ONLY taxonomy | Verifies Ed25519 over stored bytes; matches vs live server | LIVE/building [18] |
| Kibble | flop-kibble.onrender.com | Job board: JOB→CLAIM→RESULT→ATTEST lines in room #kibble; passports ranking | Uses signed lane + its own API wrapper; reputation as "IOU for future airdrop" | LIVE (board API 200) [11] |
| technocore-py | github.com/dcpf1/technocore-py | Tested Python client + MCP server + Claude skill; pip-installable | Correct sweep/canonical-string/nonce handling | LIVE on PyPI [20] |
| memory-mcp | github.com/muhtalip01/technocore-memory-mcp | Encrypted DID-signed cross-session agent memory checkpoints over TC | d-p-* owned rooms as encrypted checkpoint lane | building [19] |
| cameldick/technocore-pulse | repo + d-technocore-pulse room | Sybil/clone detection + originality leaderboard; pulse.json endpoint | Reads public metadata only | LIVE room, repo unclear [12] |
| d-room-shape / roomshape index | /kv/roomshape namespace | Hourly room measurements, published as KV notes with readme | Pure-KV public dataset | LIVE [4][12] |
| gc-postmortem | room | Forensics on vanished (deleted) rooms from record evidence | Read-only analysis lane | LIVE [12] |
| azuro-paper-league | github.com/ipmy5/azuro-paper-league | Paper-trading league refereed by TC server-assigned seq | seq as referee ordering | unclear [23] |

### Layer 2 — The clone wave (~500 repos, mostly Aug 24–25)
Categories observed across sampled descriptions [9][10]:
- DID starters/tools/guides (largest block): Makabeez/technocore-did-starter, UfukNode/technocore-did-tool (20★), eren-karakus0/technocore-keykit, BambooTuna/technocore-did, DEKOMPOZA/did-studio-technocore, many localized guides (ID/TR/JA/ZH/KO)...
- Farming agents/check-ins: ARR03/flop-airdrop-tool, dizcorvus/flop-airdrop-skill, spacerug dashboard w/ weekly auto-checkins, rixkiw/technocore-batch-farm...
- Explorers/dashboards: Tunahankoc1/technocore-explorer, Asadlee24/technocore-explorer + -console, rimurutempestxv monitoring-dashboard, Jay0xx monitor, cipherBT monitor...
- Verifiers/receipts/evidence: tulipoaaaaa/technocore-signed-evidence, bunnyyxtan/technocore-verify, aldiboncel49-lgtm/tcverify, POLYHINTPROJECT/proofline, Isaiah-54 contribution-vault, BigGids Flop-agent-passport...
- SDKs/clients: staceemillei sdk, stupeterwilliams-ui sdk+LangChain tools, noncesense67-spec technocore-ts, addnad technocore-ts, agalunov/dcpf1 technocore-py, nakcrypto CLI, ilhamdivel tcctl...
- Archivers/digests: bunnyyxtan/technocore-archive, fazlul667 archiver, 2TheMoom verify-then-archive watcher, hokestemtop digest, tensorflowyt-eng digest toolkit...
- Misc genuine experiments: vaibhav0xq/technocore-gauntlet (protocol conformance+chaos tests), mrchandu1462-ux/technocore-tester (conformance), itsabhishekgup doctor, Slobaka ops-report (nonce hygiene/KV pitfalls), Xelp66 safelens (read-only safety inspector), cameldick can-i-sell...

## B. Crowded categories (avoid)
1. DID onboarding/keygen/guides — hundreds of clones [9][10]
2. Check-in/farming agents — dominates live traffic [4][12]
3. Room explorers/dashboards/monitors [9][10][12]
4. did:key verifiers/receipts/evidence viewers (Proofline already occupies the quality slot) [18]
5. Python/TS SDKs & clients (several competent ones) [9][10][20]
6. Single-room archivers/digests [10]
7. Task boards (Kibble owns JOB→CLAIM→RESULT→ATTEST) [11]

## C. Underserved categories (thin or absent)
1. Coordination primitives: zero repos for lock/lease/election/mutual exclusion despite CAS notes existing [5][9] [9-search]
2. Public capability/service registry of live agents (what services exist, who runs them, how to call) [12] [9][12]
3. Multi-party durable digests (cross-room editorial layer; existing archivers are single-room capture) [10][16]
4. Human↔agent coordination surfaces beyond a raw HTML page [4] [4]
5. Spam/trust infrastructure at protocol level (one safety inspector repo; sybil detection is single-project) [9][12] [9][12]
6. e- ephemeral room applications (zero found) [8][9] [9-search]
7. Conformance/testing exists but young (gauntlet, tester) — quality infra is thin [9][10] [9][10]

## D. Underused primitives
1. KV compare-and-set (?if=/if_absent → 409): documented [5] but no coordination/lease product uses it [9]
2. e- rooms (expire-on-read TTL 900s) — documented [8], no application found
3. mb- mailboxes + DID-note publishing convention (patterns.md §2–3) — few real uses [6][9] [6]
4. d- ownership + room-allow allowlists for attributable moderated spaces [6] [6]
5. /r/events discovery lane as an event feed input [8] [8]
6. Engagement aggregates' global nick-diversity pooling (anti-self-play signal) [5]
7. Signed note lane for owner-authored authoritative records [5]

## E. User problems even in a small network
1. Lobby unreadable (~1000 msg/min vs 200-record window) — signal extraction impossible without tooling [16]
2. Nickname spoofing: unsigned ~nick is forgeable; humans cannot tell who is real [4][7] [7]
3. No service directory: agents can't discover what other agents offer [12] [12]
4. History loss by design; archives exist but are not verifiable end-to-end (#66: server drops sig after verify, replicas can't be re-verified offline) [14][16]
5. No JS reference client — every JS builder re-implements signing and hits the sweep/nonce traps (#75) [15]
6. Ring expiry makes "receipts" ephemeral unless someone archived them first [16]
7. Farmers drown real coordination traffic [4]

## F. Problems made MORE valuable by ephemerality/ring-buffering
1. Anything durable built on top (archives, digests, registries) gains scarcity value — the platform guarantees loss [5][16] [5][16]
2. Real-time coordination (locks/leases) fits: state must be re-established continuously anyway; CAS gives atomicity [5]
3. "Was this true?" — verification must happen close to write time, before evidence ages out of the ring (#66 makes later re-verification impossible today) [14]
4. Digests/summarization: value decays fast; a daily cross-room brief is consumed before it rots

## G. Human-agent coordination opportunities
- Humans reading agent space safely (/humans is minimal; spoofed nicks make it untrustworthy) [4][7]
- Humans posting tasks to agents with attributable results (Kibble exists but is farming-flavored) [11]
- Agent-to-agent service calls with human-auditable receipts

## H. Durable-memory/search/reputation/trust/spam/workflow gaps
- Memory: one encrypted-checkpoint project (muhtalip01) [19] [19]
- Search: none found (no room/message search product) [9][10]
- Reputation: Kibble passports (farming-coupled), cameldick leaderboard (single project) [11][12] [11][12]
- Trust: Proofline verification taxonomy [18]; auth.md explicitly disclaims identity meaning [7]
- Spam defense: safelens + cameldick only [9][12]
- Workflows: patterns.md choreographies (E2E, mailboxes) but no tooling [6]
- Community writeups frame the deeper prize as machine-verifiable public evidence trails and
  verifiable reputation for automated actors — none of the current tools deliver more than
  single-record verification. [21]

## I. Utility-first activity (side-effect activity, not farming)
Products whose normal use generates signed traffic naturally: registries updated when services change,
leases renewed while work runs, digests published on schedule, verification receipts issued when
someone verifies. Contrast: check-in bots generate traffic as the product itself.

## J. Do-not-copy list (explicit overlaps to avoid)
- On the Record (archive + recorder + measurement) [16][17]
- Proofline (verification utility) [18]
- Kibble (task board/passports) [11]
- cameldick technocore-pulse (sybil detection/leaderboard) + d-technocore-pulse (metadata pulse) [12]
- roomshape (hourly room metrics as KV) [4]
- muhtalip01 memory-mcp (encrypted checkpoints) [19]
- dcpf1/stupeterwilliams/noncesense67 SDKs [9][10][20]
- gauntlet/tester conformance suites [9][10]
- ALL DID starters, explorers, dashboards, receipt tools, farming agents [9][10]

## K. Opportunity candidates (pre-dedup)

1. **Room-level lock/lease service** — distributed mutex via CAS notes: acquire=if_absent, renew=refresh,
   release=delete-or-overwrite; fencing via nonce; crash-safe TTLs. No incumbent. [INFERRED from 5,9-search]
2. **Public capability registry** — signed self-registration of live agent services (endpoint, protocol,
   price: free), heartbeat liveness, human-readable directory page. Thin incumbents. [12]
3. **Cross-room daily digest** — editorial multi-room brief (not single-room archive), published signed;
   useful exactly because rings rot. [16]
4. **Verifiable archive bridge** — fix the #66 gap: capture-and-countersign stream so replicas stay
   offline-verifiable (needs care not to duplicate On the Record). [14][16]
5. **JS/TS reference client** — #75 asks for it; but out-of-tree lib ≠ original public product. [15]
6. **e-room ephemeral apps** — vanish-on-read Q&A/secrets handoff; novel primitive use. [8]
7. **Human trust lens** — browser extension/page marking verified vs spoofable identities in /humans view.
8. **Spam/signal filter feed** — quality-scored firehose reader (overlaps cameldick).
9. **Agent workflow bus** — request-for-help routing via mb- mailboxes (thin but diffuse).
10. **Conformance badging** — public test results per client impl (overlaps gauntlet).

## L. Top 3 candidates + kill reasons

### C1: Locksmith — room-level locks/leases/elections on CAS notes
- Why strong: fills the single clearest primitive gap (zero incumbents [9]); pure protocol use (CAS+signed
  notes); utility regardless of token; side-effect activity (lease renewals ARE work signals); tiny scope;
  free/public/no-login native. Useful to every multi-agent team even on a 50-agent network.
- Kill reasons: (a) network may be too small to need distributed locking yet — coordination demand may be
  imaginary until dozens of agents share rooms; (b) correctness burden high — a wrong lease service hands
  out conflicting grants silently (fencing is subtle); (c) CAS notes are world-writable: anyone can
  overwrite a lock ns; enforcement is social unless conventions harden; (d) if flop-labs ships server-side
  locks later, product evaporates; (e) hardest to explain quickly — adoption friction.

### C2: Switchboard — public capability registry + liveness for agent services
- Why strong: direct answer to "who offers what" (no incumbent does this well [12]); every serious agent
  benefits; registry entries are signed notes (durable, attributable); heartbeat model produces honest
  liveness data; naturally useful to humans AND agents; grows with ecosystem, survives small size (even
  20 services make a useful directory); aligns with patterns.md DID-note conventions rather than inventing new ones.
- Kill reasons: (a) self-reported claims — a registry of lies is worse than none; mitigated by
  verify-on-register probes but that's scope creep; (b) discovery may stay informal (rooms' topics +
  word-of-mouth may suffice at current scale); (c) maintenance treadmill — stale entries poison trust,
  needs aggressive TTL hygiene; (d) closest to "another directory/dashboard" pattern if executed as a UI
  instead of a protocol+thin page; (e) Kibble could bolt on a services tab.

### C3: Tidewatch — cross-room daily digest (editorial, signed)
- Why strong: guaranteed relevance while rings rotate (lobby window <1 min [16]); zero overlap with
  single-room archivers; consumption is human+agent; cheap to build; genuinely useful under any network
  size; publication is natural signed activity.
- Kill reasons: (a) curation quality is the whole product — a bad digest is invisible noise; (b) value
  decays if Technocore adds history/pagination later (operator roadmap risk); (c) On the Record's
  measurement layer could grow into this [17]; (d) LLM-summarized content of farmer spam has low floor —
  most rooms are garbage [4]; (e) daily cadence may be wrong for real-time coordination needs.

## M. Recommended direction

**C2: Switchboard — a public capability registry for Technocore agents**, executed as:
signed KV-based registration protocol (convention doc first, like patterns.md does) + minimal verifier
(read-back + liveness probe at registration) + one thin static directory page. Free, public, no login.

Rationale vs alternatives: C1 is correct engineering but premature coordination demand and silent-failure
risk make it a poor FIRST product; C3 is buildable but its moat is taste and its floor is spam.
C2 sits at the intersection of three verified gaps (discovery [12], attributable identity [7],
durability [5]) with bounded scope, clear kill criteria, and honest degradation: even a small honest
registry beats the current state (agents shouting into rooms).

Next phase gate: architecture document for Switchboard — protocol schema, note namespaces, liveness
semantics, anti-abuse limits, page design. NO implementation until spec review passes.

---
Generated 2026-08-26 during research phase. Sources follow.
## Sources

[1] https://technocore.chat
[2] https://technocore.chat/llms.txt
[3] https://technocore.chat/openapi.json
[4] https://technocore.chat/humans
[5] https://github.com/flop-labs/technocore-chat
[6] https://technocore.chat/patterns.md
[7] https://technocore.chat/auth.md
[8] https://technocore.chat/.well-known/agent.json
[9] https://api.github.com/search/repositories?q=technocore&sort=updated&order=desc&per_page=50
[10] https://api.github.com/search/repositories?q=technocore&sort=updated&order=desc&per_page=50&page=2
[11] https://flop-kibble.onrender.com/llms.txt
[12] https://technocore.chat/rooms?format=json
[13] https://technocore.chat/kv/did
[14] https://github.com/flop-labs/technocore-chat/issues/66
[15] https://github.com/flop-labs/technocore-chat/issues/75
[16] https://github.com/bunnyyxtan/technocore-archive
[17] https://bunnyyxtan.github.io/technocore-archive
[18] https://github.com/POLYHINTPROJECT/proofline
[19] https://github.com/muhtalip01/technocore-memory-mcp
[20] https://github.com/dcpf1/technocore-py
[21] https://dev.to/maragung/-technocore-and-dids-how-ai-agents-prove-identity-with-cryptographic-signatures-45n3
[22] https://x.com/CryptoHayes/status/2092209532600463598
[23] https://github.com/ipmy5/azuro-paper-league
