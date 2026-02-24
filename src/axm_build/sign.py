"""
AXM Genesis — Signing Module

Supports two suites:
  - "ed25519"              : Legacy Ed25519 (nacl). 32-byte keys, 64-byte sigs.
  - "axm-blake3-mldsa44"   : Post-quantum ML-DSA-44 (FIPS 204 / Dilithium2).
                              Deterministic. 2528-byte sk, 1312-byte pk, 2420-byte sig.

The compiler decides which suite to use. sign.py just signs and returns bytes.
"""
from __future__ import annotations

from dataclasses import dataclass

# ── Ed25519 (legacy) ─────────────────────────────────────────────────────────

from nacl.signing import SigningKey as _Ed25519SigningKey


def signing_key_from_private_key_bytes(private_key_32: bytes) -> _Ed25519SigningKey:
    """Legacy Ed25519 helper (backward-compatible API)."""
    if len(private_key_32) != 32:
        raise ValueError("Ed25519 private key must be 32 bytes")
    return _Ed25519SigningKey(private_key_32)


# ── ML-DSA-44 (post-quantum) ────────────────────────────────────────────────

try:
    from dilithium_py.dilithium import Dilithium2 as _Dilithium2
    _HAS_MLDSA = True
except ImportError:
    _HAS_MLDSA = False


@dataclass(frozen=True)
class MLDSAKeyPair:
    """ML-DSA-44 key pair. pk=1312 bytes, sk=2528 bytes."""
    public_key: bytes
    secret_key: bytes

    def sign(self, message: bytes) -> bytes:
        """Deterministic sign. Same key + same message = same signature, always."""
        if not _HAS_MLDSA:
            raise RuntimeError("dilithium-py not installed")
        return _Dilithium2.sign(self.secret_key, message)

    @property
    def verify_key_bytes(self) -> bytes:
        return self.public_key


def mldsa44_keygen() -> MLDSAKeyPair:
    """Generate a fresh ML-DSA-44 key pair."""
    if not _HAS_MLDSA:
        raise RuntimeError("dilithium-py not installed — pip install dilithium-py")
    pk, sk = _Dilithium2.keygen()
    return MLDSAKeyPair(public_key=pk, secret_key=sk)


def mldsa44_sign(secret_key: bytes, message: bytes) -> bytes:
    """Sign with ML-DSA-44. Returns 2420-byte signature."""
    if not _HAS_MLDSA:
        raise RuntimeError("dilithium-py not installed")
    return _Dilithium2.sign(secret_key, message)


def mldsa44_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify ML-DSA-44 signature. Returns True/False."""
    if not _HAS_MLDSA:
        raise RuntimeError("dilithium-py not installed")
    return _Dilithium2.verify(public_key, message, signature)


# ── Suite constants ──────────────────────────────────────────────────────────

SUITE_ED25519 = "ed25519"
SUITE_MLDSA44 = "axm-blake3-mldsa44"
KNOWN_SUITES = {SUITE_ED25519, SUITE_MLDSA44}

SUITE_SIZES = {
    SUITE_ED25519: {"pk": 32, "sig": 64},
    SUITE_MLDSA44: {"pk": 1312, "sig": 2420},
}
