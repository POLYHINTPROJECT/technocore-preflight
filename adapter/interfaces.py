"""Boundary protocols for the mailbox adapter (structural interfaces).

Every side effect the service can perform is expressed here and NOWHERE else:
reading a room, posting a signed message, remembering a cid, obtaining a
nonce, producing a signature. Concrete implementations are injected; the pure
layers accept these Protocols and never import concrete adapters.

PRIVATE-KEY RULE (spec §4 / checkpoint scope): the only code permitted to
touch signing-key material is a Signer implementation. Everything above the
Signer seam sees signatures, never keys. Test suites use EphemeralSigner;
LocalFileSigner is constructed lazily by the operator entrypoint and is
forbidden in tests.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Signer(Protocol):
    """Produces signatures for the service DID. Key material never escapes."""

    @property
    def did(self) -> str: ...

    def sign_canonical(self, canonical: bytes) -> str:
        """Return the 86-char unpadded base64url Ed25519 signature."""
        ...


@runtime_checkable
class Transport(Protocol):
    """The ONLY place network operations may live."""

    def read_room_json(self, room: str, since: int, wait: int = 0) -> list[dict]:
        """GET /r/<room>?since=<since>&wait=<wait>&format=json -> records."""
        ...

    def read_note(self, ns: str, key: str) -> str | None:
        """GET /kv/<ns>/<key> -> value or None if absent."""
        ...

    def post_signed_message(self, room: str, did: str, sig: str,
                            nonce: int, swept_text: str) -> dict:
        """Signed-lane write; returns the stored record {seq, ts, from, text, nonce}."""
        ...


@runtime_checkable
class CidCache(Protocol):
    """Correlation-memory seam. The persistent 24h store plugs in here later;
    tests use the in-memory implementation. Stores the reply room WITH the
    rendered response so duplicate replays go to the original requester."""

    def lookup(self, cid: str) -> tuple[str, str] | None:
        """(reply_room, pfr_line) if this cid was answered before."""
        ...

    def remember(self, cid: str, reply_room: str, pfr_line: str) -> None: ...


@runtime_checkable
class NonceSource(Protocol):
    """Per-(key,room) strictly-increasing nonce state. Server floors are
    window-bounded; our counter must simply always rise."""

    def next_nonce(self, room: str) -> int: ...

    def observe_written(self, room: str, nonce: int) -> None:
        """Confirm a write landed so future nonces stay above it."""
        ...
