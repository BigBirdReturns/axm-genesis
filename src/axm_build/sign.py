"""AXM Genesis v1 — axm-hybrid1 signing (spec section 7).

There is exactly one suite:

    publisher.pub = pk_ed25519 (32) || pk_mldsa44 (1312)   = 1344 bytes
    manifest.sig  = sig_ed25519 (64) || sig_mldsa44 (2420) = 2484 bytes

Verification succeeds iff BOTH components verify.

Secret key blob layout (implementation-defined; the spec freezes only the
public wire format). Defined so signing needs no external state:

    sk = sk_ed25519_seed (32) || sk_mldsa44 (2560) || pk_mldsa44 (1312)
       = 3904 bytes

- bytes 0..31: the Ed25519 seed (RFC 8032). The Ed25519 public key is
  re-derived from it at signing time.
- bytes 32..2591: the FIPS 204 ML-DSA-44 secret key (2560 bytes).
- bytes 2592..3903: the ML-DSA-44 public key (1312 bytes). ML-DSA public
  keys are not cheaply derivable from the secret key, so the blob carries
  it.

ML-DSA-44 backend selection (in preference order):
  1. liboqs-python (import oqs) — production C bindings.
     Install: pip install liboqs-python  (requires the liboqs shared library)
  2. dilithium-py — pure-Python reference implementation, unaudited.
     Install: pip install dilithium-py
  Raises RuntimeError at call time if neither is present.
"""
from __future__ import annotations

from nacl.signing import SigningKey as _Ed25519SigningKey

SUITE_HYBRID1 = "axm-hybrid1"

ED25519_SEED_LEN = 32
ED25519_PK_LEN = 32
ED25519_SIG_LEN = 64
MLDSA44_SK_LEN = 2560
MLDSA44_PK_LEN = 1312
MLDSA44_SIG_LEN = 2420

HYBRID1_SK_LEN = ED25519_SEED_LEN + MLDSA44_SK_LEN + MLDSA44_PK_LEN  # 3904
HYBRID1_PK_LEN = ED25519_PK_LEN + MLDSA44_PK_LEN                     # 1344
HYBRID1_SIG_LEN = ED25519_SIG_LEN + MLDSA44_SIG_LEN                  # 2484

# Signature message domain prefix (spec section 7.2)
MANIFEST_SIG_DOMAIN = b"axm-genesis/v1/manifest\x00"


# ── ML-DSA-44 backend selection ──────────────────────────────────────────────

_NO_BACKEND_MSG = (
    "No ML-DSA-44 backend installed. "
    "Run: pip install liboqs-python  (preferred, requires liboqs) "
    "or: pip install dilithium-py  (pure-Python fallback)"
)

try:
    import oqs as _oqs

    def _mldsa44_keygen() -> tuple[bytes, bytes]:
        with _oqs.Signature("ML-DSA-44") as _s:
            pk = _s.generate_keypair()
            sk = _s.export_secret_key()
        return bytes(pk), bytes(sk)

    def _mldsa44_sign(sk: bytes, msg: bytes) -> bytes:
        with _oqs.Signature("ML-DSA-44", secret_key=sk) as _s:
            return bytes(_s.sign(msg))

    def _mldsa44_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        with _oqs.Signature("ML-DSA-44") as _v:
            return bool(_v.verify(msg, sig, pk))

except (ImportError, SystemExit):
    try:
        from dilithium_py.ml_dsa import ML_DSA_44 as _ML_DSA_44

        def _mldsa44_keygen() -> tuple[bytes, bytes]:
            return _ML_DSA_44.keygen()

        def _mldsa44_sign(sk: bytes, msg: bytes) -> bytes:
            # Deterministic signing keeps rebuilds byte-identical; verifiers
            # must accept both the hedged and deterministic variants.
            return _ML_DSA_44.sign(sk, msg, deterministic=True)

        def _mldsa44_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
            return bool(_ML_DSA_44.verify(pk, msg, sig))

    except ImportError:

        def _mldsa44_keygen() -> tuple[bytes, bytes]:  # type: ignore[misc]
            raise RuntimeError(_NO_BACKEND_MSG)

        def _mldsa44_sign(sk: bytes, msg: bytes) -> bytes:  # type: ignore[misc]
            raise RuntimeError(_NO_BACKEND_MSG)

        def _mldsa44_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:  # type: ignore[misc]
            raise RuntimeError(_NO_BACKEND_MSG)


# ── Public hybrid API ────────────────────────────────────────────────────────

def hybrid1_keygen() -> tuple[bytes, bytes]:
    """Generate an axm-hybrid1 keypair.

    Returns (public_key, secret_key):
      public_key = pk_ed25519 || pk_mldsa44                (1344 bytes)
      secret_key = ed25519_seed || sk_mldsa44 || pk_mldsa44 (3904 bytes)
    """
    ed_sk = _Ed25519SigningKey.generate()
    ml_pk, ml_sk = _mldsa44_keygen()
    if len(ml_pk) != MLDSA44_PK_LEN or len(ml_sk) != MLDSA44_SK_LEN:
        raise RuntimeError(
            f"ML-DSA-44 backend returned unexpected key sizes: "
            f"pk={len(ml_pk)} (want {MLDSA44_PK_LEN}), sk={len(ml_sk)} (want {MLDSA44_SK_LEN})"
        )
    public_key = bytes(ed_sk.verify_key) + ml_pk
    secret_key = bytes(ed_sk) + ml_sk + ml_pk
    return public_key, secret_key


def hybrid1_public_key(secret_key: bytes) -> bytes:
    """Derive the 1344-byte hybrid public key from the secret key blob."""
    if len(secret_key) != HYBRID1_SK_LEN:
        raise ValueError(
            f"hybrid1 secret key must be {HYBRID1_SK_LEN} bytes, got {len(secret_key)}"
        )
    ed_seed = secret_key[:ED25519_SEED_LEN]
    ml_pk = secret_key[ED25519_SEED_LEN + MLDSA44_SK_LEN:]
    return bytes(_Ed25519SigningKey(ed_seed).verify_key) + ml_pk


def hybrid1_sign(secret_key: bytes, message: bytes) -> bytes:
    """Sign with both components. Returns the 2484-byte hybrid signature."""
    if len(secret_key) != HYBRID1_SK_LEN:
        raise ValueError(
            f"hybrid1 secret key must be {HYBRID1_SK_LEN} bytes, got {len(secret_key)}"
        )
    ed_seed = secret_key[:ED25519_SEED_LEN]
    ml_sk = secret_key[ED25519_SEED_LEN:ED25519_SEED_LEN + MLDSA44_SK_LEN]
    sig_ed = _Ed25519SigningKey(ed_seed).sign(message).signature
    sig_ml = _mldsa44_sign(ml_sk, message)
    if len(sig_ml) != MLDSA44_SIG_LEN:
        raise RuntimeError(
            f"ML-DSA-44 backend returned a {len(sig_ml)}-byte signature "
            f"(want {MLDSA44_SIG_LEN})"
        )
    return sig_ed + sig_ml


def hybrid1_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an axm-hybrid1 signature. Valid iff BOTH components verify."""
    if len(public_key) != HYBRID1_PK_LEN or len(signature) != HYBRID1_SIG_LEN:
        return False
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey
    pk_ed, pk_ml = public_key[:ED25519_PK_LEN], public_key[ED25519_PK_LEN:]
    sig_ed, sig_ml = signature[:ED25519_SIG_LEN], signature[ED25519_SIG_LEN:]
    try:
        VerifyKey(pk_ed).verify(message, sig_ed)
    except (BadSignatureError, ValueError):
        return False
    try:
        return bool(_mldsa44_verify(pk_ml, message, sig_ml))
    except RuntimeError:
        raise
    except Exception:
        return False


def manifest_signing_message(manifest_bytes: bytes) -> bytes:
    """Domain-separated signature message (spec section 7.2)."""
    return MANIFEST_SIG_DOMAIN + manifest_bytes
