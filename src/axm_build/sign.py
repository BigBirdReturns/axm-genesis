"""
AXM Genesis — Signing Module

Supports two suites:
  - "ed25519"              : Legacy Ed25519 (nacl). 32-byte keys, 64-byte sigs.
  - "axm-blake3-mldsa44"   : Post-quantum ML-DSA-44 (FIPS 204 / Dilithium2).
                              Deterministic. 2528-byte sk, 1312-byte pk, 2420-byte sig.

ML-DSA-44 backend selection (in preference order):
  1. liboqs-python (import oqs) — production C bindings, FIPS 140-3 validated.
     Install: pip install liboqs-python  (requires liboqs shared library)
  2. dilithium-py — pure-Python reference implementation, unaudited.
     Install: pip install dilithium-py
  Raises RuntimeError at call time if neither is present.
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


# ── ML-DSA-44 backend selection ──────────────────────────────────────────────
# Prefer liboqs (production C library) over pure-Python dilithium-py.

try:
    import oqs as _oqs
    _HAS_MLDSA = True

    def _mldsa44_keygen_raw() -> tuple[bytes, bytes]:
        with _oqs.Signature("ML-DSA-44") as _s:
            pk = _s.generate_keypair()
            sk = _s.export_secret_key()
        return pk, sk

    def _mldsa44_sign_raw(sk: bytes, msg: bytes) -> bytes:
        with _oqs.Signature("ML-DSA-44", secret_key=sk) as _s:
            return bytes(_s.sign(msg))

    def _mldsa44_verify_raw(pk: bytes, msg: bytes, sig: bytes) -> bool:
        with _oqs.Signature("ML-DSA-44") as _v:
            return bool(_v.verify(msg, sig, pk))

except (ImportError, SystemExit):
    try:
        from dilithium_py.dilithium import Dilithium2 as _Dilithium2
        _HAS_MLDSA = True

        def _mldsa44_keygen_raw() -> tuple[bytes, bytes]:
            pk, sk = _Dilithium2.keygen()
            return pk, sk

        def _mldsa44_sign_raw(sk: bytes, msg: bytes) -> bytes:
            return _Dilithium2.sign(sk, msg)

        def _mldsa44_verify_raw(pk: bytes, msg: bytes, sig: bytes) -> bool:
            return _Dilithium2.verify(pk, msg, sig)

    except ImportError:
        _HAS_MLDSA = False

        def _mldsa44_keygen_raw() -> tuple[bytes, bytes]:  # type: ignore[misc]
            raise RuntimeError(
                "No ML-DSA-44 backend installed. "
                "Run: pip install liboqs-python  (preferred, requires liboqs) "
                "or: pip install dilithium-py  (pure-Python fallback)"
            )

        def _mldsa44_sign_raw(sk: bytes, msg: bytes) -> bytes:  # type: ignore[misc]
            raise RuntimeError("No ML-DSA-44 backend installed.")

        def _mldsa44_verify_raw(pk: bytes, msg: bytes, sig: bytes) -> bool:  # type: ignore[misc]
            raise RuntimeError("No ML-DSA-44 backend installed.")


# ── Public ML-DSA-44 API ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class MLDSAKeyPair:
    """ML-DSA-44 key pair. pk=1312 bytes, sk=2528 bytes."""
    public_key: bytes
    secret_key: bytes

    def sign(self, message: bytes) -> bytes:
        """Deterministic sign. Same key + same message = same signature, always."""
        return _mldsa44_sign_raw(self.secret_key, message)

    @property
    def verify_key_bytes(self) -> bytes:
        return self.public_key


def mldsa44_keygen() -> MLDSAKeyPair:
    """Generate a fresh ML-DSA-44 key pair."""
    pk, sk = _mldsa44_keygen_raw()
    return MLDSAKeyPair(public_key=pk, secret_key=sk)


def mldsa44_sign(secret_key: bytes, message: bytes) -> bytes:
    """Sign with ML-DSA-44. Returns 2420-byte signature."""
    return _mldsa44_sign_raw(secret_key, message)


def mldsa44_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify ML-DSA-44 signature. Returns True/False."""
    return _mldsa44_verify_raw(public_key, message, signature)


# ── Suite constants ──────────────────────────────────────────────────────────

SUITE_ED25519 = "ed25519"
SUITE_MLDSA44 = "axm-blake3-mldsa44"
KNOWN_SUITES = {SUITE_ED25519, SUITE_MLDSA44}

SUITE_SIZES = {
    SUITE_ED25519: {"pk": 32, "sig": 64},
    SUITE_MLDSA44: {"pk": 1312, "sig": 2420},
}
