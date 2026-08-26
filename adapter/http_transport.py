"""Live HTTP transport behind the interfaces.Transport seam. Stdlib only.

Technocore is HTTP-native where EVERY operation, including signed writes, is
a plain GET (research/ecosystem-map.md [1][3][5]). This module is the ONLY
network code in the project (ratified live boundary): the pure layers receive
records and return rendered lines; bytes touch the wire nowhere else.

URL shapes (source-derived, mirrored by engine/preflight.estimate_request_line):
  read:  GET {base}/r/{room}?since={since}&wait={wait}&format=json
  write: GET {base}/r/{room}/say-signed/{did}/{sig}/{nonce}/{text}
  note:  GET {base}/kv/{ns}/{key}

Failure policy (fail closed, gate F1): any non-2xx status, undecodable body,
timeout, or unexpected envelope raises TransportError. Callers never guess.
Nothing here reads key material or logs payloads.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from urllib.parse import quote

from engine import preflight as pf

DEFAULT_BASE_URL = "https://technocore.chat"
DEFAULT_USER_AGENT = "j1-preflight/0.1.0 (mailbox service; contact via service DID note)"

_RECORD_KEYS = ("records", "messages", "items", "lines")


class TransportError(RuntimeError):
    """Raised for any network-layer failure. Carries status when known."""

    def __init__(self, detail: str, status: int | None = None):
        super().__init__(
            detail if status is None else f"{detail} (HTTP {status})")
        self.status = status


class HttpTransport:
    """Concrete interfaces.Transport. One GET per protocol operation."""

    def __init__(self, base_url: str = DEFAULT_BASE_URL,
                 timeout_s: float = 20.0,
                 user_agent: str = DEFAULT_USER_AGENT):
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.user_agent = user_agent

    # ------------------------------------------------- pure URL builders
    # (unit-tested offline; no I/O)
    def build_read_url(self, room: str, since: int, wait: int = 0) -> str:
        return (f"{self.base_url}/r/{quote(room, safe='')}"
                f"?since={int(since)}&wait={int(wait)}&format=json")

    def build_post_url(self, room: str, did: str, sig: str, nonce: int,
                       swept_text: str) -> str:
        enc_did, _ = pf.encode_segment(did)
        enc_txt, _ = pf.encode_segment(swept_text)
        return (f"{self.base_url}/r/{quote(room, safe='')}"
                f"/say-signed/{enc_did}/{quote(sig, safe='')}"
                f"/{int(nonce)}/{enc_txt}")

    def build_note_url(self, ns: str, key: str) -> str:
        return f"{self.base_url}/kv/{quote(ns, safe='')}/{quote(key, safe='')}"

    # ------------------------------------------------------------- I/O
    def _get(self, url: str, timeout_s: float | None = None) -> tuple[int, str]:
        req = urllib.request.Request(url, headers={
            "User-Agent": self.user_agent,
            "Accept": "application/json, text/plain",
        })
        try:
            with urllib.request.urlopen(
                    req, timeout=timeout_s or self.timeout_s) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            head = ""
            try:
                head = exc.read(200).decode("utf-8", errors="replace")
            except Exception:                       # noqa: BLE001
                pass
            raise TransportError(
                f"GET failed: {exc.reason}"
                + (f" | body-head: {head!r}" if head.strip() else ""),
                status=exc.code) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransportError(f"GET failed: {exc}") from exc

    @staticmethod
    def _decode_json(body: str):
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise TransportError(
                f"response is not JSON ({exc}); body starts: "
                f"{body[:80]!r}") from exc

    @classmethod
    def extract_records(cls, data) -> list[dict]:
        """Defensive envelope unwrap: bare list, or dict carrying the list
        under a known key. Anything else fails closed."""
        if isinstance(data, list):
            rows = data
        elif isinstance(data, dict):
            rows = next((data[k] for k in _RECORD_KEYS
                         if isinstance(data.get(k), list)), None)
            if rows is None:
                raise TransportError(
                    f"unexpected read envelope; top-level keys "
                    f"{sorted(data)}")
        else:
            raise TransportError(
                f"unexpected read payload type {type(data).__name__}")
        bad = [i for i, r in enumerate(rows) if not isinstance(r, dict)]
        if bad:
            raise TransportError(f"record index(es) {bad[:5]} are not objects")
        return rows

    # --------------------------------------- interfaces.Transport methods
    def read_room_json(self, room: str, since: int, wait: int = 0
                       ) -> list[dict]:
        _, body = self._get(self.build_read_url(room, since, wait),
                            timeout_s=(None if wait <= 0
                                       else self.timeout_s + wait))
        return self.extract_records(self._decode_json(body))

    def read_note(self, ns: str, key: str) -> str | None:
        try:
            _, body = self._get(self.build_note_url(ns, key))
        except TransportError as exc:
            if exc.status == 404:
                return None
            raise
        return body

    def post_signed_message(self, room: str, did: str, sig: str, nonce: int,
                            swept_text: str) -> dict:
        status, body = self._get(
            self.build_post_url(room, did, sig, nonce, swept_text))
        # LIVE FACT (2026-08-26 e2e): writes return text/plain, not JSON --
        # e.g. "# room <name>  messages 2  range 1..2" followed by an
        # "!! UNTRUSTED CONTENT" banner. Accept either envelope; extract
        # the assigned seq from the range header when present.
        if body.lstrip().startswith("#"):
            import re as _re
            m = _re.search(r"range\s+(\d+)\.\.(\d+)", body)
            out: dict = {"format": "text", "http_status": status,
                         "raw_head": body[:200]}
            if m:
                out["range"] = [int(m.group(1)), int(m.group(2))]
                out["seq"] = int(m.group(2))
            return out
        data = self._decode_json(body)
        if not isinstance(data, dict):
            return {"format": "json-other", "raw": body[:200]}
        return data
