"""Test signing module for both suites."""
import pytest
from nacl.signing import SigningKey

from axm_build.sign import signing_key_from_private_key_bytes


def test_ed25519_roundtrip():
    """Ed25519 sign and verify."""
    sk = SigningKey.generate()
    msg = b"test message for signing"
    signed = sk.sign(msg)

    # Verify
    vk = sk.verify_key
    result = vk.verify(signed)
    assert result == msg


def test_ed25519_from_bytes():
    """Ed25519 key from raw bytes."""
    raw = bytes.fromhex("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3")
    sk = signing_key_from_private_key_bytes(raw)
    assert len(bytes(sk.verify_key)) == 32


def test_ed25519_wrong_size():
    """Ed25519 rejects wrong-size keys."""
    with pytest.raises(ValueError):
        signing_key_from_private_key_bytes(b"\x00" * 16)


try:
    from axm_build.sign import mldsa44_keygen, mldsa44_sign, mldsa44_verify, MLDSAKeyPair

    def test_mldsa44_keygen():
        """ML-DSA-44 key generation produces correct sizes."""
        kp = mldsa44_keygen()
        assert len(kp.public_key) == 1312
        assert len(kp.secret_key) == 2528

    def test_mldsa44_roundtrip():
        """ML-DSA-44 sign and verify roundtrip."""
        kp = mldsa44_keygen()
        msg = b"test message for ML-DSA-44"
        sig = kp.sign(msg)
        assert len(sig) == 2420
        assert mldsa44_verify(kp.public_key, msg, sig)

    def test_mldsa44_deterministic():
        """ML-DSA-44 deterministic: same key+msg = same sig."""
        kp = mldsa44_keygen()
        msg = b"deterministic test"
        sig1 = mldsa44_sign(kp.secret_key, msg)
        sig2 = mldsa44_sign(kp.secret_key, msg)
        assert sig1 == sig2, "ML-DSA-44 must be deterministic"

    def test_mldsa44_wrong_key_rejects():
        """ML-DSA-44 rejects wrong key."""
        kp1 = mldsa44_keygen()
        kp2 = mldsa44_keygen()
        msg = b"wrong key test"
        sig = mldsa44_sign(kp1.secret_key, msg)
        assert not mldsa44_verify(kp2.public_key, msg, sig)

except ImportError:
    @pytest.mark.skip(reason="dilithium-py not installed")
    def test_mldsa44_skip():
        pass
