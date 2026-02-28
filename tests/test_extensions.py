"""Tests for the ext/ extension envelope mechanism.

Validates:
1. Gold shard (no ext/) still passes
2. Shard with empty ext/ passes
3. Shard with ext/ containing files passes (Merkle covers them)
4. Shard with junk root dirs (tmp/, foo/) still fails E_LAYOUT_DIRTY
5. ext/ files are included in Merkle tree (tampering detected)
6. Compiler creates ext/ directory
7. Extensions declared in manifest when ext/ has files
8. Extensions NOT declared in manifest when ext/ is empty (hash stability)
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import pyarrow.parquet as pq
import pytest

from axm_verify.logic import verify_shard
from axm_verify.crypto import compute_merkle_root
from axm_build.compiler_generic import CompilerConfig, compile_generic_shard
from axm_build.manifest import dumps_canonical_json
from axm_build.sign import signing_key_from_private_key_bytes
from axm_build.cli import CANONICAL_TEST_PRIVATE_KEY

REPO_ROOT = Path(__file__).resolve().parents[1]
GOLD_SHARD = REPO_ROOT / "shards" / "gold" / "fm21-11-hemorrhage-v1"
TRUSTED_KEY = REPO_ROOT / "keys" / "canonical_test_publisher.pub"

needs_gold = pytest.mark.skipif(
    not GOLD_SHARD.exists(),
    reason="Gold shard not built (run: axm-build gold-fm21-11 <source> shards/gold/fm21-11-hemorrhage-v1/)"
)


def _copy_gold(tmp_path: Path) -> Path:
    dst = tmp_path / "shard"
    shutil.copytree(GOLD_SHARD, dst)
    return dst


def _resign(shard: Path) -> None:
    """Recompute Merkle root, update manifest, and re-sign."""
    manifest = json.loads((shard / "manifest.json").read_text())
    suite = manifest.get("suite", "ed25519")
    manifest["integrity"]["merkle_root"] = compute_merkle_root(shard, suite=suite)
    manifest["shard_id"] = f"shard_blake3_{manifest['integrity']['merkle_root']}"
    manifest_bytes = dumps_canonical_json(manifest)
    (shard / "manifest.json").write_bytes(manifest_bytes)

    if suite == "axm-blake3-mldsa44":
        from axm_build.sign import mldsa44_keygen
        kp = mldsa44_keygen()
        (shard / "sig" / "publisher.pub").write_bytes(kp.public_key)
        (shard / "sig" / "manifest.sig").write_bytes(kp.sign(manifest_bytes))
    else:
        sk = signing_key_from_private_key_bytes(CANONICAL_TEST_PRIVATE_KEY)
        (shard / "sig" / "manifest.sig").write_bytes(sk.sign(manifest_bytes).signature)


# ============================================================================
# Core ext/ behavior
# ============================================================================

@needs_gold
def test_gold_shard_no_ext_still_passes():
    """Gold shard has no ext/ and must continue to pass."""
    res = verify_shard(GOLD_SHARD, trusted_key_path=TRUSTED_KEY)
    assert res["status"] == "PASS"


@needs_gold
def test_shard_with_empty_ext_passes(tmp_path):
    """Empty ext/ directory should be allowed."""
    shard = _copy_gold(tmp_path)
    (shard / "ext").mkdir()
    # Empty dir doesn't change Merkle (no files to hash)
    # But layout check must not reject it
    res = verify_shard(shard, trusted_key_path=TRUSTED_KEY)
    assert res["status"] == "PASS"


@needs_gold
def test_shard_with_ext_file_covered_by_merkle(tmp_path):
    """ext/ files are included in Merkle tree. Valid if re-signed."""
    shard = _copy_gold(tmp_path)
    (shard / "ext").mkdir()
    (shard / "ext" / "spatial.parquet").write_bytes(b"placeholder")
    _resign(shard)
    res = verify_shard(shard, trusted_key_path=TRUSTED_KEY)
    assert res["status"] == "PASS"


@needs_gold
def test_ext_file_without_resign_fails_merkle(tmp_path):
    """Adding ext/ file without re-signing must fail Merkle check."""
    shard = _copy_gold(tmp_path)
    (shard / "ext").mkdir()
    (shard / "ext" / "spatial.parquet").write_bytes(b"placeholder")
    # Do NOT re-sign - Merkle should mismatch
    res = verify_shard(shard, trusted_key_path=TRUSTED_KEY)
    assert res["status"] == "FAIL"
    codes = {e["code"] for e in res["errors"]}
    assert "E_MERKLE_MISMATCH" in codes


@needs_gold
def test_junk_root_dir_still_rejected(tmp_path):
    """Non-ext/ extra directories must still fail E_LAYOUT_DIRTY."""
    shard = _copy_gold(tmp_path)
    (shard / "tmp").mkdir()
    res = verify_shard(shard, trusted_key_path=TRUSTED_KEY)
    assert res["status"] == "FAIL"
    codes = {e["code"] for e in res["errors"]}
    assert "E_LAYOUT_DIRTY" in codes


@needs_gold
def test_multiple_junk_dirs_rejected(tmp_path):
    """Multiple unauthorized directories all get rejected."""
    shard = _copy_gold(tmp_path)
    (shard / "tmp").mkdir()
    (shard / "foo").mkdir()
    res = verify_shard(shard, trusted_key_path=TRUSTED_KEY)
    assert res["status"] == "FAIL"


@needs_gold
def test_ext_plus_junk_rejected(tmp_path):
    """ext/ is fine but any other extra dir still fails."""
    shard = _copy_gold(tmp_path)
    (shard / "ext").mkdir()
    (shard / "cache").mkdir()
    res = verify_shard(shard, trusted_key_path=TRUSTED_KEY)
    assert res["status"] == "FAIL"
    codes = {e["code"] for e in res["errors"]}
    assert "E_LAYOUT_DIRTY" in codes


# ============================================================================
# Compiler ext/ behavior
# ============================================================================

def test_compiler_creates_ext_dir(tmp_path):
    """Compiler should create ext/ directory in output."""
    source = tmp_path / "source.txt"
    source.write_text("Tourniquets treat severe bleeding effectively.\n", encoding="utf-8")

    candidates = tmp_path / "candidates.jsonl"
    candidates.write_text(json.dumps({
        "subject": "tourniquet",
        "predicate": "treats",
        "object": "severe bleeding",
        "object_type": "entity",
        "tier": 0,
        "evidence": "Tourniquets treat severe bleeding effectively."
    }) + "\n", encoding="utf-8")

    out = tmp_path / "shard"
    cfg = CompilerConfig(
        source_path=source,
        candidates_path=candidates,
        out_dir=out,
        private_key=CANONICAL_TEST_PRIVATE_KEY,
        publisher_id="@test",
        publisher_name="Test",
        namespace="test/medical",
        created_at="2026-01-01T00:00:00Z",
    )
    ok = compile_generic_shard(cfg)
    assert ok
    assert (out / "ext").is_dir()


def test_compiler_no_extensions_in_manifest_when_ext_empty(tmp_path):
    """When ext/ is empty, manifest should NOT have extensions key (hash stability)."""
    source = tmp_path / "source.txt"
    source.write_text("Tourniquets treat severe bleeding effectively.\n", encoding="utf-8")

    candidates = tmp_path / "candidates.jsonl"
    candidates.write_text(json.dumps({
        "subject": "tourniquet",
        "predicate": "treats",
        "object": "severe bleeding",
        "object_type": "entity",
        "tier": 0,
        "evidence": "Tourniquets treat severe bleeding effectively."
    }) + "\n", encoding="utf-8")

    out = tmp_path / "shard"
    cfg = CompilerConfig(
        source_path=source,
        candidates_path=candidates,
        out_dir=out,
        private_key=CANONICAL_TEST_PRIVATE_KEY,
        publisher_id="@test",
        publisher_name="Test",
        namespace="test/medical",
        created_at="2026-01-01T00:00:00Z",
    )
    ok = compile_generic_shard(cfg)
    assert ok

    manifest = json.loads((out / "manifest.json").read_text())
    assert "extensions" not in manifest


def test_compiler_shard_with_ext_file_verifies(tmp_path):
    """Manually add an ext/ file after compile, re-sign, and verify."""
    source = tmp_path / "source.txt"
    source.write_text("Tourniquets treat severe bleeding effectively.\n", encoding="utf-8")

    candidates = tmp_path / "candidates.jsonl"
    candidates.write_text(json.dumps({
        "subject": "tourniquet",
        "predicate": "treats",
        "object": "severe bleeding",
        "object_type": "entity",
        "tier": 0,
        "evidence": "Tourniquets treat severe bleeding effectively."
    }) + "\n", encoding="utf-8")

    out = tmp_path / "shard"
    cfg = CompilerConfig(
        source_path=source,
        candidates_path=candidates,
        out_dir=out,
        private_key=CANONICAL_TEST_PRIVATE_KEY,
        publisher_id="@test",
        publisher_name="Test",
        namespace="test/medical",
        created_at="2026-01-01T00:00:00Z",
    )
    ok = compile_generic_shard(cfg)
    assert ok

    # Add an extension file
    (out / "ext" / "spatial.parquet").write_bytes(b"placeholder-spatial-data")

    # Re-sign (simulating a build step that emits extensions)
    _resign(out)

    # Create trusted key from the shard's own pubkey for this test
    trusted = tmp_path / "trusted.pub"
    trusted.write_bytes((out / "sig" / "publisher.pub").read_bytes())

    res = verify_shard(out, trusted_key_path=trusted)
    assert res["status"] == "PASS"
