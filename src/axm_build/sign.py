from __future__ import annotations

from nacl.signing import SigningKey


def signing_key_from_private_key_bytes(private_key_32: bytes) -> SigningKey:
    if len(private_key_32) != 32:
        raise ValueError("Ed25519 private key must be 32 bytes")
    return SigningKey(private_key_32)
