# J1 Preflight Bench — human-facing UI

A static, dependency-free client over the pure engine layers. No backend, no
accounts, no storage, no telemetry. All verdicts are computed locally by the
JavaScript port of `engine/preflight.py` + `engine/wire.py` +
`adapter/pipeline.py`, which is kept byte-exact with the Python engine by a
differential test gate.

## Run

```bash
# from this directory (any static file server works):
npx serve -l 9317 .
# then open http://localhost:9317/
```

Deterministic demo/QA states:

- `/#demo=valid` — clean PASS
- `/#demo=sweep-trap` — invisible characters swept (PARTIAL + ghost tiles)
- `/#demo=bad-sig` — well-formed signature over different bytes (FAIL)
- `/#demo=long-url` — URL budget warning
- `?theme=dark|light` — override OS color scheme (used by screenshot QA)

## Layout

```
ui/
├── index.html              bench markup (three zones + status strip)
├── src/
│   ├── styles.css          Signal/Machine Console visual system
│   ├── app.js              interaction choreography (no framework)
│   ├── engine.js           port of engine/preflight.py
│   ├── wire.js             port of engine/wire.py (PFQ/PFR parse+render)
│   ├── pipeline.js         port of adapter/pipeline.py
│   ├── sha256.js           pure-JS FIPS 180-4 SHA-256
│   ├── unicode-categories.js   GENERATED Unicode category ranges (do not edit)
│   └── unicode-categories.json twin of the above (Node/debug use)
├── tools/
│   ├── gen_unicode_tables.py   regenerates the tables from CPython unicodedata
│   └── gen_corpus.py           regenerates tests/corpus.json (Python oracle)
└── tests/
    ├── diff-harness.mjs    replays every corpus case through the JS ports
    └── corpus.json         GENERATED shared oracle vectors
```

## Correctness gate

The JS engine is not allowed to drift from the frozen Python semantics:

```bash
./.venv/Scripts/python.exe ui/tools/gen_corpus.py   # oracle outputs (Python)
node ui/tests/diff-harness.mjs                      # JS must agree 153/153
```

Any change to `engine/preflight.py`, `engine/wire.py`, or
`adapter/pipeline.py` requires regenerating the corpus and passing the
harness before the UI ships.

## Visual system

Signal/Machine Console per the Phase 2b contract: machined near-black
faceplate, hairline borders, bracket labels (`[SWEEP]`, `[CANONICAL STRING]`),
semantic green/amber/red reserved exclusively for verdict tiers, Sweep Field
ghost tiles as the signature device, Verdict Lamp as the single dominant state
object. No gradients, no shadows, no rounded card grids, no decorative motion;
identical reruns produce zero animation by design.
