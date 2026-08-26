"""Mailbox transport adapter — explicit boundaries around the pure engine.

Layers (dependencies point strictly downward; nothing here imports network
libraries):

    adapter/interfaces.py  Protocol definitions (Signer, Transport,
                           CidCache, NonceSource) -- the seams.
    adapter/pipeline.py    PURE: parsed-PFQ -> PFR struct via engine/wire.
    adapter/dispatcher.py  PURE decisions from raw lines + an EXECUTOR that
                           applies decisions through the injected seams.
    adapter/signing.py     Signer implementations: ephemeral test signer and
                           a lazy local-file signer (never touched by tests).

Network I/O may exist ONLY behind Transport. The live long-poll loop is NOT
part of this checkpoint.
"""
