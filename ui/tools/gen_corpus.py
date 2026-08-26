"""Generate ui/tests/corpus.json by executing the PYTHON engine as oracle.

Uniform case shape: {"x": <input>, "y": <oracle output>} where y is either a
value or one of {"raise": str} / {"wire_error": [code, detail]}. Bytes are
hex-encoded with keys ending in _hex. The Node harness (diff-harness.mjs)
replays every x through the JS ports and demands deep equality on y.

Regenerate after any intentional semantic change:
    .venv/Scripts/python.exe ui/tools/gen_corpus.py
"""
import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from engine import preflight as pf          # noqa: E402
from engine import wire as w                # noqa: E402
from adapter import pipeline as pl          # noqa: E402
import vectors as V                          # noqa: E402

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization

OUT = Path(__file__).resolve().parent.parent / "tests" / "corpus.json"
corpus = {"generator": "gen_corpus.py", "sections": {}}


def run(fn):
    try:
        return fn()
    except pf.PreflightError as exc:
        return {"raise": str(exc)}
    except w.WireError as exc:
        return {"wire_error": [exc.code, exc.detail]}


def sweep_out(text):
    s = pf.sweep(text)
    return {"stored": s.stored,
            "changes": [[i, u, c] for i, u, c in s.changes],
            "change_count": s.change_count,
            "truncated_change_list": s.truncated_change_list,
            "sha256_hex": s.sha256_hex,
            "char_len": s.char_len}


def verdict_out(v):
    return {"ok": v.ok, "code": v.code, "detail": v.detail}


# ------------------------------------------------------------------ sweep
sec = []
for label, raw, _want in V.SWEEP_IDENTITY + V.SWEEP_REPLACE_SINGLE:
    sec.append({"id": label, "x": {"text": raw}, "y": run(lambda r=raw: sweep_out(r))})
for label, rawb, _want in V.WIRE_CASES:
    decoded = pf.wire_decode(rawb)
    sec.append({"id": f"wire:{label}", "x": {"text": decoded},
                "y": run(lambda d=decoded: sweep_out(d))})
for label, raw, _outcome in V.length_boundary_cases():
    sec.append({"id": f"len:{label}", "x": {"text": raw},
                "y": run(lambda r=raw: sweep_out(r))})
for label, raw in V.SWEEP_EMPTY_AFTER:
    sec.append({"id": f"empty:{label}", "x": {"text": raw},
                "y": run(lambda r=raw: sweep_out(r))})
corpus["sections"]["sweep"] = sec

# ------------------------------------------------------------------ rooms
sec = []
for name in V.ROOMS_VALID + [n for n, _ in V.ROOMS_INVALID]:
    v = pf.validate_room(name)
    sec.append({"id": f"room:{name}", "x": {"name": name}, "y": verdict_out(v)})
for name, _note in V.ROOM_CLASS_TRAPS:
    sec.append({"id": f"class:{name}", "x": {"classes_of": name},
                "y": list(pf._room_classes(name))})
corpus["sections"]["rooms"] = sec

# ----------------------------------------------------------------- nonces
sec = []
cases = [(n, None) for n in V.NONCE_VALID] + \
        [(n, None) for n in V.NONCE_FORMAT_INVALID] + \
        [(n, None) for n in V.NONCE_LEADING_ZERO_WARN]
for floor, proposed, _ok_flag in V.NONCE_FLOOR_CASES:
    cases.append((proposed, floor))
for nonce, floor in cases:
    v = pf.validate_nonce(nonce, floor=floor)
    # floor serialized as string: 19-digit values lose precision as JSON numbers
    sec.append({"id": f"nonce:{nonce}:floor={floor}",
                "x": {"nonce": nonce,
                      "floor": None if floor is None else str(floor)},
                "y": verdict_out(v)})
corpus["sections"]["nonces"] = sec

# ------------------------------------------------------------------- DIDs
sec = []
for did in [V.REFERENCE_DID, V.SERVICE_DID] + [d for d, _ in V.DID_MALFORMED]:
    try:
        pub = pf.parse_did(did)
        y = {"pub32_hex": pub.hex()}
    except pf.PreflightError as exc:
        y = {"raise": str(exc)}
    sec.append({"id": f"did:{did}", "x": {"did": did}, "y": y})
sec.append({"id": "fp:service", "x": {"fingerprint": V.SERVICE_DID},
            "y": pf.fingerprint(V.SERVICE_DID)})
sec.append({"id": "fp:reference", "x": {"fingerprint": V.REFERENCE_DID},
            "y": pf.fingerprint(V.REFERENCE_DID)})
corpus["sections"]["dids"] = sec

# ------------------------------------------------------------- canonicals
sec = [
    {"id": "msg1", "x": {"msg": ["lobby", 7, "hello world"]},
     "y": pf.canonical_msg("lobby", 7, "hello world").hex()},
    {"id": "msg2", "x": {"msg": ["mb-p-x", "0012", "日本語 🚀"]},
     "y": pf.canonical_msg("mb-p-x", "0012", "日本語 🚀").hex()},
    {"id": "genesis", "x": {"msg": ["mb-p-preflight-11b17958c4064c71", 1,
                                    "PFS v1 | preflight | status=initializing ; engine_version:0.1.0"]},
     "y": V.GENESIS_CANONICAL.encode("utf-8").hex()},
    {"id": "note1", "x": {"note": ["did-11", "b17958c4064c71", 3,
                                   "did:key:z6Mk mailbox:mb-x"]},
     "y": pf.canonical_note("did-11", "b17958c4064c71", 3,
                            "did:key:z6Mk mailbox:mb-x").hex()},
]
corpus["sections"]["canonical"] = sec

# ------------------------------------------------------------ signatures
signer = Ed25519PrivateKey.generate()
pub32 = signer.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
sig_b64 = base64.urlsafe_b64encode(
    signer.sign(b"lobby|7|hello world")).decode().rstrip("=")
other = Ed25519PrivateKey.generate()
bad_sig = base64.urlsafe_b64encode(
    other.sign(b"lobby|7|hello world")).decode().rstrip("=")

sec = []
sig_cases = [
    ("valid", pub32.hex(), sig_b64, b"lobby|7|hello world".hex()),
    ("wrong-signer", pub32.hex(), bad_sig, b"lobby|7|hello world".hex()),
    ("wrong-bytes", pub32.hex(), sig_b64, b"lobby|7|tampered".hex()),
] + [(f"encoding:{s}", pub32.hex(), s, b"lobby|7|hello world".hex())
     for s in V.SIG_MALFORMED]
for label, pub_hex, sig, canon_hex in sig_cases:
    v = pf.verify_sig_b64u(bytes.fromhex(pub_hex), sig, bytes.fromhex(canon_hex))
    sec.append({"id": label,
                "x": {"verify": [pub_hex, sig, canon_hex]},
                "y": verdict_out(v)})
corpus["sections"]["signatures"] = sec

# ------------------------------------------------------------- URL budget
sec = []
url_cases = [
    ("small", ("https://technocore.chat", "mb-x", V.SERVICE_DID, sig_b64, 7, "hello world")),
    ("emoji", ("https://technocore.chat", "mb-x", V.SERVICE_DID, sig_b64, 7, "🚀 fire 日本語")),
    ("huge", ("https://technocore.chat", "mb-x", V.SERVICE_DID, sig_b64, 7, "y" * 9000)),
]
for label, args in url_cases:
    enc_did, l_did = pf.encode_segment(args[2])
    enc_txt, l_txt = pf.encode_segment(args[5])
    v = pf.estimate_request_line(*args)
    sec.append({"id": label,
                "x": {"estimate": list(args)},
                "y": {"enc_did_len": l_did, "enc_txt_len": l_txt,
                      **verdict_out(v)}})
seg_in = "a b|c;d=e~f.g-h_i:j?/"
seg = pf.encode_segment(seg_in)
sec.append({"id": "segment", "x": {"segment": seg_in},
            "y": {"encoded": seg[0], "length": seg[1]}})
corpus["sections"]["url"] = sec

# ------------------------------------------------------------- note audit
sec = []
audit_cases = [
    ("ok-canonical", dict(placed_key_fp=V.FP_CORRECT, value=V.NOTE_OK_VALUE)),
    ("legacy-path", dict(placed_key_fp="11b17958c4064c71",
                         value=(f"{V.SERVICE_DID} "
                                "mailbox:mb-p-preflight-11b17958c4064c71"),
                         placed_ns="did")),
    ("wrong-key", dict(placed_key_fp="0000000000000000",
                       value=(f"{V.SERVICE_DID} "
                              "mailbox:mb-p-preflight-11b17958c4064c71"),
                       placed_ns="did-11", did=V.SERVICE_DID)),
]
for label, kw in audit_cases:
    rows = pf.audit_note(**kw)
    sec.append({"id": label, "x": {"audit": kw}, "y": [[c, d] for c, d in rows]})
corpus["sections"]["audit"] = sec

# ------------------------------------------------------------------- wire
CID = "0123456789abcdef"
REPLY = "mb-p-consumer-0000000000000000"
PREVIEW_STRUCT = {"kind": "PFQ", "cid": CID, "op": "preview",
                  "params": {"reply": REPLY, "room": "lobby", "nonce": "1",
                             "did": V.SERVICE_DID, "text": "hello world"}}
PFR_STRUCT = {"kind": "PFR", "cid": CID, "status": "PASS", "engine": "0.1.0",
              "findings": [["T1-ok", "", "", "all static checks passed"]]}
ERROR_PFR_STRUCT = {"kind": "PFR", "cid": CID, "status": "ERROR",
                    "engine": "0.1.0", "findings": [],
                    "error": "X_BAD_OP: unknown op 'vanish'"}


def pfr_json(p):
    out = {"kind": p["kind"], "cid": p["cid"], "status": p["status"],
           "engine": p["engine"]}
    if "error" in p:
        out["error"] = p["error"]
    out["findings"] = [list(x) for x in p.get("findings", [])]
    return out


def werr(fn):
    try:
        fn()
        return None
    except w.WireError as exc:
        return [exc.code, exc.detail]


preview_line = w.render_pfq(PREVIEW_STRUCT)
esc_struct = {"kind": "PFQ", "cid": CID, "op": "preview",
              "params": dict(PREVIEW_STRUCT["params"], text="pipe|and;semicolon%here")}
esc_line = w.render_pfq(esc_struct)
dup_line = f"PFQ v1 | {CID} | preview | reply={REPLY} ; reply={REPLY}"
nonmb_line = f"PFQ v1 | {CID} | preview | reply=d-consumer-{CID} ; room=lobby"
pfr_pass_line = w.render_pfr(PFR_STRUCT)
pfr_err_line = w.render_pfr(ERROR_PFR_STRUCT)

sec = [
    {"id": "render.pfq.preview", "x": {"render_pfq": PREVIEW_STRUCT},
     "y": preview_line},
    {"id": "parse.pfq.roundtrip", "x": {"parse_pfq": preview_line},
     "y": PREVIEW_STRUCT},
    {"id": "parse.sloppy", "x": {"parse_pfq":
        f"PFQ v1|  {CID}  |preview| reply={REPLY} ;  room=lobby ; "
        f"nonce=1; did={V.SERVICE_DID} ;text=hello world"},
     "y": {"kind": "PFQ", "cid": CID, "op": "preview",
           "params": PREVIEW_STRUCT["params"]}},
    {"id": "escape.render", "x": {"render_pfq": esc_struct}, "y": esc_line},
    {"id": "escape.parse", "x": {"parse_pfq": esc_line}, "y": esc_struct},
    {"id": "badcid.empty", "x": {"parse_pfq": preview_line.replace(CID, "", 1)},
     "y": {"wire_error": werr(lambda: w.parse_pfq(preview_line.replace(CID, "", 1)))}},
    {"id": "badcid.upper", "x": {"parse_pfq": preview_line.replace(CID, "0123456789ABCDEF", 1)},
     "y": {"wire_error": werr(lambda: w.parse_pfq(preview_line.replace(CID, "0123456789ABCDEF", 1)))}},
    {"id": "badcid.g", "x": {"parse_pfq": preview_line.replace(CID, "0123456789abcdeg", 1)},
     "y": {"wire_error": werr(lambda: w.parse_pfq(preview_line.replace(CID, "0123456789abcdeg", 1)))}},
    {"id": "unknown-op", "x": {"parse_pfq": preview_line.replace("| preview |", "| transmogrify |", 1)},
     "y": {"wire_error": werr(lambda: w.parse_pfq(preview_line.replace("| preview |", "| transmogrify |", 1)))}},
    {"id": "wrong-prefix", "x": {"parse_pfq": preview_line.replace("PFQ v1", "PFR v1", 1)},
     "y": {"wire_error": werr(lambda: w.parse_pfq(preview_line.replace("PFQ v1", "PFR v1", 1)))}},
    {"id": "version-mismatch", "x": {"parse_pfq": preview_line.replace("PFQ v1", "PFQ v2", 1)},
     "y": {"wire_error": werr(lambda: w.parse_pfq(preview_line.replace("PFQ v1", "PFQ v2", 1)))}},
    {"id": "duplicate-key", "x": {"parse_pfq": dup_line},
     "y": {"wire_error": werr(lambda: w.parse_pfq(dup_line))}},
    {"id": "empty-param", "x": {"parse_pfq": f"PFQ v1 | {CID} | preview | reply={REPLY} ;; room=x"},
     "y": {"wire_error": werr(lambda: w.parse_pfq(f"PFQ v1 | {CID} | preview | reply={REPLY} ;; room=x"))}},
    {"id": "missing-reply", "x": {"parse_pfq": f"PFQ v1 | {CID} | preview | room=lobby"},
     "y": {"wire_error": werr(lambda: w.parse_pfq(f"PFQ v1 | {CID} | preview | room=lobby"))}},
    {"id": "reply-not-mb", "x": {"parse_pfq": nonmb_line},
     "y": {"wire_error": werr(lambda: w.parse_pfq(nonmb_line))}},
    {"id": "decode.lowercase-escape", "x": {"decode_value": "%7c"},
     "y": {"wire_error": werr(lambda: w.decode_value("%7c"))}},
    {"id": "decode.basic", "x": {"decode_value": "a%7Cb%3Bc%25d"},
     "y": w.decode_value("a%7Cb%3Bc%25d")},
    {"id": "render.pfr.pass", "x": {"render_pfr": PFR_STRUCT}, "y": pfr_pass_line},
    {"id": "parse.pfr.pass", "x": {"parse_pfr": pfr_pass_line}, "y": PFR_STRUCT},
    {"id": "render.pfr.error", "x": {"render_pfr": ERROR_PFR_STRUCT}, "y": pfr_err_line},
    {"id": "parse.pfr.error", "x": {"parse_pfr": pfr_err_line}, "y": ERROR_PFR_STRUCT},
    {"id": "pfr.unknown-code",
     "x": {"parse_pfr": f"PFR v1 | {CID} | FAIL | engine=0.1.0 ; T1-reject:E_MADE_UP detail"},
     "y": {"wire_error": werr(lambda: w.parse_pfr(
         f"PFR v1 | {CID} | FAIL | engine=0.1.0 ; T1-reject:E_MADE_UP detail"))}},
    {"id": "pfr.bad-t2-ref",
     "x": {"parse_pfr": f"PFR v1 | {CID} | PARTIAL | engine=0.1.0 ; T2-observe:O_ROOM_OWNED@bad ref"},
     "y": w.parse_pfr(f"PFR v1 | {CID} | PARTIAL | engine=0.1.0 ; T2-observe:O_ROOM_OWNED@bad ref")},
    {"id": "pfr.t2-ok",
     "x": {"parse_pfr": f"PFR v1 | {CID} | PARTIAL | engine=0.1.0 ; T2-observe:O_ROOM_OWNED@s1 detail"},
     "y": w.parse_pfr(f"PFR v1 | {CID} | PARTIAL | engine=0.1.0 ; T2-observe:O_ROOM_OWNED@s1 detail")},
    {"id": "pfr.empty-findings",
     "x": {"parse_pfr": f"PFR v1 | {CID} | PASS | engine=0.1.0"},
     "y": {"wire_error": werr(lambda: w.parse_pfr(f"PFR v1 | {CID} | PASS | engine=0.1.0"))}},
    {"id": "pfr.no-error-text",
     "x": {"render_pfr": {"kind": "PFR", "cid": CID, "status": "ERROR",
                          "engine": "0.1.0", "findings": []}},
     "y": {"wire_error": werr(lambda: w.render_pfr(
         {"kind": "PFR", "cid": CID, "status": "ERROR", "engine": "0.1.0", "findings": []}))}},
]
corpus["sections"]["wire"] = sec

# --------------------------------------------------------------- pipeline
verifier = lambda pub, sig, canon: pf.verify_sig_b64u(pub, sig, canon)


def proc(parsed, err):
    return pfr_json(pl.process_request(parsed, err))


parsed_preview = w.parse_pfq(preview_line)
sec = [
    {"id": "preview.happy", "x": {"process": [parsed_preview, None]},
     "y": proc(parsed_preview, None)},
    {"id": "preview.unknown-did",
     "x": {"process": [w.parse_pfq(w.render_pfq(
         {"kind": "PFQ", "cid": CID, "op": "preview",
          "params": {"reply": REPLY, "room": "lobby", "nonce": "1",
                     "did": "did:key:zed01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                     "text": "hi"}})), None],
      },
     "y": proc(w.parse_pfq(w.render_pfq(
         {"kind": "PFQ", "cid": CID, "op": "preview",
          "params": {"reply": REPLY, "room": "lobby", "nonce": "1",
                     "did": "did:key:zed01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                     "text": "hi"}})), None)},
    {"id": "preview.sweep-warn",
     # NB: constructed programmatically -- a real PFQ LINE can never carry
     # invisible chars (wire layer rejects non-sweep-safe lines), but the
     # pipeline accepts parsed structs from any producer.
     "x": {"process": [{"kind": "PFQ", "cid": CID, "op": "preview",
                        "params": {"reply": REPLY, "room": "lobby",
                                   "nonce": "1", "did": V.SERVICE_DID,
                                   "text": "a\u200db\u00adc"}}, None]},
     "y": proc({"kind": "PFQ", "cid": CID, "op": "preview",
                "params": {"reply": REPLY, "room": "lobby", "nonce": "1",
                           "did": V.SERVICE_DID,
                           "text": "a\u200db\u00adc"}}, None)},
    {"id": "verify.sha-mismatch",
     "x": {"process": [{"kind": "PFQ", "cid": CID, "op": "verify",
                        "params": {"reply": REPLY, "did": V.REFERENCE_DID,
                                   "canonical": "lobby|1|hi",
                                   "sha256": "a" * 64}}, None]},
     "y": proc({"kind": "PFQ", "cid": CID, "op": "verify",
                "params": {"reply": REPLY, "did": V.REFERENCE_DID,
                           "canonical": "lobby|1|hi",
                           "sha256": "a" * 64}}, None)},
    {"id": "audit.legacy",
     "x": {"process": [{"kind": "PFQ", "cid": CID, "op": "audit-did-note",
                        "params": {"reply": REPLY,
                                   "value": f"{V.SERVICE_DID} mailbox:mb-x",
                                   "did": V.SERVICE_DID, "ns": "did"}}, None]},
     "y": proc({"kind": "PFQ", "cid": CID, "op": "audit-did-note",
                "params": {"reply": REPLY, "value": f"{V.SERVICE_DID} mailbox:mb-x",
                           "did": V.SERVICE_DID, "ns": "did"}}, None)},
    {"id": "parse-error.path", "x": {"process": [None, "X_MISSING_KEY: missing"]},
     "y": proc(None, "X_MISSING_KEY: missing")},
]
corpus["sections"]["pipeline"] = sec

OUT.write_text(json.dumps(corpus, ensure_ascii=False, indent=1), encoding="utf-8")
n = sum(len(v) for v in corpus["sections"].values())
print(f"wrote {OUT} ({n} cases across {len(corpus['sections'])} sections)")
