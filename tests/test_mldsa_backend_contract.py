from __future__ import annotations

import builtins
import importlib
import sys
import types
from pathlib import Path

import pytest

MISSING_BACKEND_FRAGMENT = "No ML-DSA-44 backend installed"


def _reload_sign_module_with_import_policy(monkeypatch, *, block_oqs: bool, block_dilithium: bool):
    """Reload axm_build.sign under controlled backend import failures."""
    real_import = builtins.__import__

    def gated_import(name, globals=None, locals=None, fromlist=(), level=0):
        if block_oqs and name == "oqs":
            raise ImportError("forced oqs missing")
        if block_dilithium and name == "dilithium_py.dilithium":
            raise ImportError("forced dilithium missing")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", gated_import)
    mod = importlib.import_module("axm_build.sign")
    return importlib.reload(mod)


def test_sign_and_verify_raise_clear_error_when_no_backend(monkeypatch):
    """No-backend mode should be reachable via import path and fail loudly."""
    sign_mod = _reload_sign_module_with_import_policy(
        monkeypatch, block_oqs=True, block_dilithium=True
    )

    with pytest.raises(RuntimeError) as e1:
        sign_mod.mldsa44_sign(b"x" * 2528, b"msg")
    assert MISSING_BACKEND_FRAGMENT in str(e1.value)
    assert "pip install liboqs-python" in str(e1.value)
    assert "pip install dilithium-py" in str(e1.value)

    with pytest.raises(RuntimeError) as e2:
        sign_mod.mldsa44_verify(b"x" * 1312, b"msg", b"x" * 2420)
    assert MISSING_BACKEND_FRAGMENT in str(e2.value)
    assert "pip install liboqs-python" in str(e2.value)
    assert "pip install dilithium-py" in str(e2.value)


def test_falls_back_to_dilithium_when_oqs_missing(monkeypatch):
    """When oqs import fails, dilithium fallback backend should still work."""
    fake_mod = types.SimpleNamespace(
        Dilithium2=types.SimpleNamespace(
            keygen=lambda: (b"p" * 1312, b"s" * 2528),
            sign=lambda _sk, _msg: b"z" * 2420,
            verify=lambda _pk, _msg, _sig: True,
        )
    )
    monkeypatch.setitem(sys.modules, "dilithium_py.dilithium", fake_mod)

    sign_mod = _reload_sign_module_with_import_policy(
        monkeypatch, block_oqs=True, block_dilithium=False
    )

    kp = sign_mod.mldsa44_keygen()
    assert len(kp.public_key) == 1312
    assert len(kp.secret_key) == 2528
    sig = sign_mod.mldsa44_sign(kp.secret_key, b"msg")
    assert len(sig) == 2420
    assert sign_mod.mldsa44_verify(kp.public_key, b"msg", sig)


def test_compiler_rejects_invalid_mldsa_key_lengths(tmp_path):
    """ML-DSA compile path must reject malformed private key blobs loudly."""
    from axm_build.compiler_generic import CompilerConfig, compile_generic_shard

    source = tmp_path / "source.txt"
    source.write_text("Tourniquet treats severe hemorrhage.\n", encoding="utf-8")

    candidates = tmp_path / "candidates.jsonl"
    candidates.write_text(
        '{"subject":"tourniquet","predicate":"treats","object":"severe hemorrhage",'
        '"object_type":"literal:string","tier":0,"evidence":"Tourniquet treats severe hemorrhage."}\n',
        encoding="utf-8",
    )

    cfg = CompilerConfig(
        source_path=source,
        candidates_path=candidates,
        out_dir=tmp_path / "out",
        private_key=b"x" * 32,
        publisher_id="pub:test",
        publisher_name="Test Publisher",
        namespace="test:pq",
        created_at="2026-01-01T00:00:00Z",
        suite="axm-blake3-mldsa44",
    )

    with pytest.raises(ValueError, match="private_key length"):
        compile_generic_shard(cfg)


def test_compiler_requires_pubkey_for_sk_only_mldsa(tmp_path):
    """2528-byte ML-DSA secret key requires pre-placed publisher.pub."""
    from axm_build.compiler_generic import CompilerConfig, compile_generic_shard

    source = tmp_path / "source.txt"
    source.write_text("Tourniquet treats severe hemorrhage.\n", encoding="utf-8")

    candidates = tmp_path / "candidates.jsonl"
    candidates.write_text(
        '{"subject":"tourniquet","predicate":"treats","object":"severe hemorrhage",'
        '"object_type":"literal:string","tier":0,"evidence":"Tourniquet treats severe hemorrhage."}\n',
        encoding="utf-8",
    )

    cfg = CompilerConfig(
        source_path=source,
        candidates_path=candidates,
        out_dir=tmp_path / "out",
        private_key=b"x" * 2528,
        publisher_id="pub:test",
        publisher_name="Test Publisher",
        namespace="test:pq",
        created_at="2026-01-01T00:00:00Z",
        suite="axm-blake3-mldsa44",
    )

    with pytest.raises(ValueError, match="pre-place publisher.pub"):
        compile_generic_shard(cfg)


def test_verify_manifest_signature_surfaces_backend_missing_error(monkeypatch, tmp_path: Path):
    """Verifier should surface backend-missing errors (not mislabel as bad signature)."""
    from axm_verify import crypto as crypto_mod

    def _raise(*_args, **_kwargs):
        raise RuntimeError(
            "No ML-DSA-44 backend installed — cannot verify ML-DSA-44 signatures. "
            "Run: pip install liboqs-python  (preferred) or: pip install dilithium-py"
        )

    monkeypatch.setattr(crypto_mod, "_mldsa44_verify", _raise)

    manifest_bytes = b'{"spec_version":"1.0.0"}'
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(manifest_bytes)

    sig_path = tmp_path / "manifest.sig"
    pub_path = tmp_path / "publisher.pub"
    sig_path.write_bytes(b"x" * 2420)
    pub_path.write_bytes(b"x" * 1312)

    with pytest.raises(RuntimeError, match=MISSING_BACKEND_FRAGMENT):
        crypto_mod.verify_manifest_signature(
            manifest_data=manifest_path,
            sig_path=sig_path,
            pubkey_path=pub_path,
            suite="axm-blake3-mldsa44",
        )
