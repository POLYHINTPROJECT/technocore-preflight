"""Signer implementations. The private-key boundary lives here and ONLY here.

- EphemeralSigner: fresh Ed25519 keypair per instance. For tests and local
  dry-runs. Never touches disk.
- LocalFileSigner: decrypts C:\\Users\\karni\\technocore-secrets\\identity.pem
  via the isolated starter tooling. Constructed ONLY by the operator
  entrypoint at live-service start; passphrase arrives via getpass inside its
  constructor. Tests MUST NOT instantiate it.
"""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


def _pubkey_to_did(pub32: bytes) -> str:
    """Ed25519 public key -> did:key (multicodec 0xed01 + base58btc + z tag)."""
    prefixed = b"\xed\x01" + pub32
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(prefixed, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = alphabet[rem] + out
    zeros = len(prefixed) - len(prefixed.lstrip(b"\x00"))
    return "did:key:z" + "1" * zeros + out


def sign_b64u(key: Ed25519PrivateKey, canonical: bytes) -> str:
    return base64.urlsafe_b64encode(key.sign(canonical)).decode("ascii").rstrip("=")


class EphemeralSigner:
    """Fresh keypair per instance; DID derived on construction."""

    def __init__(self):
        self._key = Ed25519PrivateKey.generate()
        pub = self._key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        self._did = _pubkey_to_did(pub)

    @property
    def did(self) -> str:
        return self._did

    def sign_canonical(self, canonical: bytes) -> str:
        return sign_b64u(self._key, canonical)


class LocalFileSigner:
    """Operator-only. Decrypts the frozen service identity on demand.

    NOT for tests. The passphrase never appears in code, logs, argv, or this
    module's return values; it exists only inside getpass inside __init__."""

    def __init__(self, pem_path: str):
        import getpass
        import sys
        sys.path.insert(0, str(__import__("pathlib").Path(pem_path).parent))
        try:
            import technocore_agent as t   # isolated copy in technocore-secrets
        finally:
            sys.path.pop(0)
        passphrase = getpass.getpass(
            "Technocore service identity passphrase: ").encode("utf-8")
        key = t.load_identity(__import__("pathlib").Path(pem_path),
                              passphrase=passphrase, allow_prompt=False)
        self._key = key
        self._did = t.did_from_private_key(key)

    @property
    def did(self) -> str:
        return self._did

    def sign_canonical(self, canonical: bytes) -> str:
        return sign_b64u(self._key, canonical)
