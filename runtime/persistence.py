"""Durable state for the live service: cursor, nonce counters, cid cache.

JSON-file persistence under runtime/state/. Crash-safe by write discipline
(temp file + os.replace, atomic on Windows and POSIX). Every store is a
plain class implementing an interfaces.* Protocol; the pure dispatcher
knows nothing about files.

Models (ratified live-boundary constraints):
- cursor:      persisted AFTER each batch completes (at-least-once). A crash
               between processing and persisting replays that batch; duplicate
               cids convert replays into byte-identical cached answers.
- nonces:      per-(key,room) counter, persisted immediately AFTER observe;
               restart seeds max(persisted+1) so we never collide with our
               own history (server floor is window-bounded; ours is absolute).
- CidCache:    24h TTL per entry (spec §5). lookup() returns None for expired
               entries and prunes them lazily. Stores (reply_room, pfr_line).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

STATE_DIR = Path(__file__).resolve().parent / "state"

CURSOR_FILE = STATE_DIR / "cursor.json"
NONCE_FILE = STATE_DIR / "nonces.json"
CACHE_FILE = STATE_DIR / "cid-cache.json"

CACHE_TTL_S = 24 * 3600          # spec §5: 24h replay window


class FileCursor:
    """Long-poll seq cursor. save() after successful batch processing."""

    def __init__(self, path: Path = CURSOR_FILE):
        self.path = path
        self.seq = self._load()

    def _load(self) -> int:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return int(data.get("seq", 0))
        except (FileNotFoundError, json.JSONDecodeError, ValueError, OSError):
            return 0

    def save(self) -> None:
        _atomic_write_json(self.path, {"seq": self.seq,
                                       "saved_at": int(time.time())})


class FileNonces:
    """interfaces.NonceSource. Strictly rising per (did-key, room)."""

    def __init__(self, path: Path = NONCE_FILE):
        self.path = path
        self.last: dict[str, int] = {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self.last = {str(k): int(v) for k, v in data.items()}
        except (FileNotFoundError, json.JSONDecodeError, ValueError, OSError):
            pass

    @staticmethod
    def _key(room: str) -> str:
        return room                       # single service identity: key=room

    def next_nonce(self, room: str) -> int:
        return self.last.get(self._key(room), 0) + 1

    def observe_written(self, room: str, nonce: int) -> None:
        k = self._key(room)
        if nonce > self.last.get(k, 0):
            self.last[k] = nonce
        _atomic_write_json(self.path, self.last)


class FileCidCache:
    """interfaces.CidCache with 24h TTL. Stores (reply_room, pfr_line)."""

    def __init__(self, path: Path = CACHE_FILE, ttl_s: int = CACHE_TTL_S,
                 now=time.time):
        self.path = path
        self.ttl_s = ttl_s
        self._now = now
        self.store: dict[str, tuple[int, str, str]] = {}   # cid->(ts,room,line)
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            cutoff = self._now() - ttl_s
            for cid, ent in raw.items():
                try:
                    ts, room, line = ent
                    if ts >= cutoff:
                        self.store[str(cid)] = (int(ts), str(room), str(line))
                except (TypeError, ValueError):
                    continue
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            pass

    def lookup(self, cid: str) -> tuple[str, str] | None:
        ent = self.store.get(cid)
        if ent is None:
            return None
        ts, room, line = ent
        if ts < self._now() - self.ttl_s:
            del self.store[cid]
            return None
        return room, line

    def remember(self, cid: str, reply_room: str, pfr_line: str) -> None:
        self.store[cid] = (int(self._now()), reply_room, pfr_line)
        self._flush()

    def prune(self) -> int:
        cutoff = self._now() - self.ttl_s
        stale = [c for c, (ts, _, _) in self.store.items() if ts < cutoff]
        for c in stale:
            del self.store[c]
        if stale:
            self._flush()
        return len(stale)

    def _flush(self) -> None:
        _atomic_write_json(self.path, {c: list(e)
                                       for c, e in self.store.items()})


def _atomic_write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    os.replace(tmp, path)             # atomic on POSIX and NTFS
