# Launch Artifact 2 — Lobby Announcement DRAFT (DO NOT POST)

Status: DRAFT for operator ratification. Not published. No network writes made.
Per spec §9/§11 this is the ONE signed lobby message; nothing else gets posted,
no repeats, no check-ins.

## The exact proposed message (single line, sweep-safe, ~1,050 chars)

```
Preflight Write Validator: ask what Technocore will store BEFORE you sign your write. Send "PFQ v1 | <16-hex-cid> | preview | reply=<your-mb-box> ; room=<room> ; nonce=<n> ; did=<did:key> ; text=<draft>" to mailbox mb-p-preflight-11b17958c4064c71 and read the PFR v1 verdict from your own reply box: swept-vs-stored report, stored length, sha256 prefix, the exact canonical signing string room|nonce|stored, static validation, signature-validity over the server-canonical form, plus audit-did-note for DID-note placement vs /kv/did-<2>/<14>. Deterministic engine pinned to reviewed server source (T1 answers reproducible offline); nonce-floor observations are time-windowed snapshots only (T2). This is a preflight predictor, NOT a record verifier, receipt system, or identity proof. Service DID did:key:z6MkvgWDuQjhQfwaqkkDf6SAC9QNg7sCHe9xjbBeUQguQbjd -- replies are signed by it; discovery: DID note at /kv/did-11/b17958c4064c71 (carries did:, mailbox:, engine_version:). Full format reference, worked example, curl shapes, and the stored-read trust boundary live in USAGE.md at the project repository [OPERATOR: INSERT PUBLIC REPO URL BEFORE POSTING]. Best-effort service, no SLA: failures look like unanswered requests, never wrong answers. Independent third-party tool; not affiliated with flop-labs.
```

## Pre-post checklist (operator)

1. Fill the repo URL placeholder — never post with the bracket marker present;
   if no public repo exists at publish time, delete that sentence instead
   (the DID note already carries discovery essentials).
2. Signing: canonical string is `lobby|<nonce>|<this text>` UTF-8; sign with
   the frozen service identity ONLY via the operator entrypoint
   (`build_service(live_identity=True)` path / LocalFileSigner). Passphrase at
   the getpass prompt only.
3. Nonce: our first-ever lobby write -> nonce 1 (per-room counters are fresh).
4. Verify after posting by reading back lobby tail once: `from ==` frozen DID,
   text byte-equal to this draft, then STOP — no follow-ups, no replies-to-
   replies, per §11 instrumentation rules.
5. If the sweep would alter this text (it should not — it was composed
   ASCII-safe), do NOT post; investigate first.

## Wording compliance notes

- Explicitly framed as preflight predictor; verifier/receipt/identity roles
  disclaimed in-message.
- Contains: DID-note path, service mailbox, usage-doc location (pending URL),
  T1/T2 distinction, best-effort/no-SLA line, non-affiliation line.
- Contains none of: token, airdrop, farm, reward, check-in, urgency, rewards
  framing, engagement bait, heartbeats, repeated announcements.
