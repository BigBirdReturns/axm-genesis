"""axm-hybrid1 signing (spec section 7): Ed25519 || ML-DSA-44, both must verify.

Covers keygen/sign/verify roundtrips, the both-halves-must-verify rule,
size enforcement, domain separation, and the no-backend failure mode.

The reload-based backend tests re-execute axm_build.sign / axm_verify.crypto
under gated imports; the autouse fixture below restores backend reality
afterwards so the reloaded module state can never leak a fake or missing
backend into later tests (the historical DURABILITY.md section 1.1 bug).
"""
from __future__ import annotations

import builtins
import importlib
import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey

import axm_build.sign as sign_mod
import axm_verify.crypto as crypto_mod
from axm_verify import const as verify_const
from helpers import (
    CI_KEY_PATH,
    CI_PUB_PATH,
    MISSING_BACKEND_FRAGMENT,
    requires_mldsa_backend,
)

_BACKEND_MODULE_NAMES = ("oqs", "dilithium_py", "dilithium_py.ml_dsa")
_MISSING = object()


@pytest.fixture(autouse=True)
def _restore_mldsa_backend_reality():
    """Undo backend-import pollution after every test in this module.

    Tests here reload ``axm_build.sign`` / ``axm_verify.crypto`` under a
    gated ``builtins.__import__``. pytest's ``monkeypatch`` restores the
    import hook and ``sys.modules`` entries, but the *reloaded module
    state* would otherwise stay bound to the gated backend selection and
    poison every ML-DSA test that runs later in the session. Snapshot
    reality before the test; afterwards restore ``builtins.__import__``
    and the backend ``sys.modules`` entries explicitly, then reload both
    modules so their module-level backend bindings are re-resolved
    against the real environment.
    """
    real_import = builtins.__import__
    saved_modules = {name: sys.modules.get(name, _MISSING) for name in _BACKEND_MODULE_NAMES}
    try:
        yield
    finally:
        builtins.__import__ = real_import
        for name, mod in saved_modules.items():
            if mod is _MISSING:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod
        importlib.reload(sign_mod)
        importlib.reload(crypto_mod)


def _reload_without_backends(monkeypatch, module):
    """Reload a module with every ML-DSA-44 backend import forced to fail."""
    real_import = builtins.__import__

    def gated_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "oqs" or name.startswith("dilithium_py"):
            raise ImportError(f"forced missing backend: {name}")
        return real_import(name, globals, locals, fromlist, level)

    for name in _BACKEND_MODULE_NAMES:
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setattr(builtins, "__import__", gated_import)
    return importlib.reload(module)


# ── Wire-format constants ────────────────────────────────────────────────────

def test_hybrid_sizes_are_frozen_and_single_sourced() -> None:
    assert sign_mod.HYBRID1_PK_LEN == verify_const.HYBRID1_PK_LEN == 32 + 1312 == 1344
    assert sign_mod.HYBRID1_SIG_LEN == verify_const.HYBRID1_SIG_LEN == 64 + 2420 == 2484
    assert sign_mod.HYBRID1_SK_LEN == 32 + 2560 + 1312 == 3904
    assert sign_mod.SUITE_HYBRID1 == verify_const.SUITE_HYBRID1 == "axm-hybrid1"


def test_domain_prefix_is_frozen() -> None:
    domain = b"axm-genesis/v1/manifest\x00"
    assert sign_mod.MANIFEST_SIG_DOMAIN == domain
    assert verify_const.MANIFEST_SIG_DOMAIN == domain
    assert sign_mod.manifest_signing_message(b"{}") == domain + b"{}"
    assert crypto_mod.manifest_signing_message(b"{}") == domain + b"{}"


# ── Keygen / sign / verify ───────────────────────────────────────────────────

@requires_mldsa_backend
def test_keygen_produces_frozen_sizes() -> None:
    pk, sk = sign_mod.hybrid1_keygen()
    assert len(pk) == 1344
    assert len(sk) == 3904
    assert sign_mod.hybrid1_public_key(sk) == pk


@requires_mldsa_backend
def test_sign_verify_roundtrip_across_both_implementations() -> None:
    pk, sk = sign_mod.hybrid1_keygen()
    msg = sign_mod.manifest_signing_message(b'{"spec_version":"1.0.0"}')
    sig = sign_mod.hybrid1_sign(sk, msg)
    assert len(sig) == 2484
    assert sign_mod.hybrid1_verify(pk, msg, sig)
    assert crypto_mod.hybrid1_verify(pk, msg, sig)  # independent verify path
    assert not sign_mod.hybrid1_verify(pk, msg + b"x", sig)
    assert not crypto_mod.hybrid1_verify(pk, msg + b"x", sig)


@requires_mldsa_backend
def test_ci_test_keypair_is_consistent() -> None:
    sk = CI_KEY_PATH.read_bytes()
    pub = CI_PUB_PATH.read_bytes()
    assert len(pub) == 1344
    assert sign_mod.hybrid1_public_key(sk) == pub
    sig = sign_mod.hybrid1_sign(sk, b"pipeline check")
    assert crypto_mod.hybrid1_verify(pub, b"pipeline check", sig)


# ── Both halves must verify ──────────────────────────────────────────────────

def _flip(data: bytes, index: int) -> bytes:
    return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1:]


@requires_mldsa_backend
@pytest.mark.parametrize(
    "sig_index, half",
    [(0, "ed25519"), (63, "ed25519"), (64, "mldsa44"), (2483, "mldsa44")],
)
def test_corrupting_either_signature_half_fails(sig_index: int, half: str) -> None:
    pk, sk = sign_mod.hybrid1_keygen()
    msg = b"both halves must verify"
    sig = sign_mod.hybrid1_sign(sk, msg)
    bad = _flip(sig, sig_index)
    assert not sign_mod.hybrid1_verify(pk, msg, bad), half
    assert not crypto_mod.hybrid1_verify(pk, msg, bad), half


@requires_mldsa_backend
@pytest.mark.parametrize("pk_index, half", [(0, "ed25519"), (32, "mldsa44")])
def test_corrupting_either_public_key_half_fails(pk_index: int, half: str) -> None:
    pk, sk = sign_mod.hybrid1_keygen()
    msg = b"key halves are bound"
    sig = sign_mod.hybrid1_sign(sk, msg)
    bad_pk = _flip(pk, pk_index)
    assert not sign_mod.hybrid1_verify(bad_pk, msg, sig), half
    assert not crypto_mod.hybrid1_verify(bad_pk, msg, sig), half


@requires_mldsa_backend
def test_mixed_keypairs_fail_even_with_one_valid_half() -> None:
    """pk from A, sig ed25519-half from A but mldsa-half from B -> invalid."""
    pk_a, sk_a = sign_mod.hybrid1_keygen()
    _, sk_b = sign_mod.hybrid1_keygen()
    msg = b"no partial credit"
    sig_a = sign_mod.hybrid1_sign(sk_a, msg)
    sig_b = sign_mod.hybrid1_sign(sk_b, msg)
    frankensig = sig_a[:64] + sig_b[64:]
    assert not sign_mod.hybrid1_verify(pk_a, msg, frankensig)
    assert not crypto_mod.hybrid1_verify(pk_a, msg, frankensig)


# ── Size enforcement ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("pk_len", [0, 32, 1312, 1343, 1345])
def test_wrong_public_key_size_returns_false(pk_len: int) -> None:
    assert sign_mod.hybrid1_verify(b"\x00" * pk_len, b"m", b"\x00" * 2484) is False
    assert crypto_mod.hybrid1_verify(b"\x00" * pk_len, b"m", b"\x00" * 2484) is False


@pytest.mark.parametrize("sig_len", [0, 64, 2420, 2483, 2485])
def test_wrong_signature_size_returns_false(sig_len: int) -> None:
    assert sign_mod.hybrid1_verify(b"\x00" * 1344, b"m", b"\x00" * sig_len) is False
    assert crypto_mod.hybrid1_verify(b"\x00" * 1344, b"m", b"\x00" * sig_len) is False


@pytest.mark.parametrize("sk_len", [0, 32, 2560, 3903, 3905])
def test_wrong_secret_key_size_raises(sk_len: int) -> None:
    with pytest.raises(ValueError, match="3904"):
        sign_mod.hybrid1_sign(b"\x00" * sk_len, b"m")
    with pytest.raises(ValueError, match="3904"):
        sign_mod.hybrid1_public_key(b"\x00" * sk_len)


# ── Domain separation (spec section 7.2) ─────────────────────────────────────

@requires_mldsa_backend
def test_domain_separation_prevents_cross_protocol_replay() -> None:
    pk, sk = sign_mod.hybrid1_keygen()
    manifest_bytes = b'{"spec_version":"1.0.0"}'
    # A signature over the raw manifest bytes must NOT verify as a manifest
    # signature, and vice versa.
    raw_sig = sign_mod.hybrid1_sign(sk, manifest_bytes)
    domain_sig = sign_mod.hybrid1_sign(sk, sign_mod.manifest_signing_message(manifest_bytes))
    msg = sign_mod.manifest_signing_message(manifest_bytes)
    assert sign_mod.hybrid1_verify(pk, msg, domain_sig)
    assert not sign_mod.hybrid1_verify(pk, msg, raw_sig)
    assert not sign_mod.hybrid1_verify(pk, manifest_bytes, domain_sig)


@requires_mldsa_backend
def test_verify_manifest_signature_file_based(tmp_path: Path) -> None:
    pk, sk = sign_mod.hybrid1_keygen()
    manifest_bytes = b'{"suite":"axm-hybrid1"}'
    sig = sign_mod.hybrid1_sign(sk, sign_mod.manifest_signing_message(manifest_bytes))
    sig_path = tmp_path / "manifest.sig"
    pub_path = tmp_path / "publisher.pub"
    sig_path.write_bytes(sig)
    pub_path.write_bytes(pk)
    assert crypto_mod.verify_manifest_signature(manifest_bytes, sig_path, pub_path)
    assert not crypto_mod.verify_manifest_signature(manifest_bytes + b" ", sig_path, pub_path)
    # Wrong trusted key -> False.
    other_pk, _ = sign_mod.hybrid1_keygen()
    pub_path.write_bytes(other_pk)
    assert not crypto_mod.verify_manifest_signature(manifest_bytes, sig_path, pub_path)


# ── Backend-missing behavior (no-backend CI leg) ─────────────────────────────

def test_sign_module_raises_clean_error_without_backend(monkeypatch) -> None:
    mod = _reload_without_backends(monkeypatch, sign_mod)
    with pytest.raises(RuntimeError, match=MISSING_BACKEND_FRAGMENT):
        mod.hybrid1_keygen()
    with pytest.raises(RuntimeError) as e:
        mod.hybrid1_sign(b"\x00" * 3904, b"msg")
    assert MISSING_BACKEND_FRAGMENT in str(e.value)
    assert "pip install liboqs-python" in str(e.value)
    assert "pip install dilithium-py" in str(e.value)


def test_verify_module_raises_clean_error_without_backend(monkeypatch) -> None:
    """The RuntimeError must surface — never be mislabeled a bad signature."""
    mod = _reload_without_backends(monkeypatch, crypto_mod)
    # Build a hybrid blob whose Ed25519 half genuinely verifies so the
    # verify path reaches the ML-DSA-44 component.
    ed = SigningKey.generate()
    msg = b"reaches the mldsa component"
    pk = bytes(ed.verify_key) + b"\x00" * 1312
    sig = ed.sign(msg).signature + b"\x00" * 2420
    with pytest.raises(RuntimeError) as e:
        mod.hybrid1_verify(pk, msg, sig)
    assert MISSING_BACKEND_FRAGMENT in str(e.value)
    assert "pip install liboqs-python" in str(e.value)
    assert "pip install dilithium-py" in str(e.value)


def test_backend_failure_on_ed25519_half_is_still_false(monkeypatch) -> None:
    """A bad Ed25519 half fails fast (False) even with no backend installed."""
    mod = _reload_without_backends(monkeypatch, crypto_mod)
    assert mod.hybrid1_verify(b"\x00" * 1344, b"m", b"\x00" * 2484) is False


def test_backend_reality_is_restored_between_tests() -> None:
    """Guard for the restore fixture itself: bindings match the environment."""
    from helpers import mldsa_backend_available

    if not mldsa_backend_available():
        with pytest.raises(RuntimeError, match=MISSING_BACKEND_FRAGMENT):
            sign_mod.hybrid1_keygen()
    else:
        pk, sk = sign_mod.hybrid1_keygen()
        sig = sign_mod.hybrid1_sign(sk, b"real backend")
        assert crypto_mod.hybrid1_verify(pk, b"real backend", sig)
