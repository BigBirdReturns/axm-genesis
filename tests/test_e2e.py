"""End-to-end pipeline: keygen -> compile -> verify -> tamper -> fail.

Exercises the real CLI entry points as subprocesses (the way a publisher
would run them), plus the committed gold shard v2 under its provisional
publisher key.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from axm_verify.logic import verify_shard
from helpers import (
    CI_PUB_PATH,
    GOLD_CHECKSUMS,
    GOLD_PUB,
    GOLD_SHARD,
    REPO_ROOT,
    error_codes,
    requires_mldsa_backend,
)

pytestmark = requires_mldsa_backend

DOC_TEXT = (
    "Field Manual Excerpt\n"
    "A tourniquet stops severe bleeding when direct pressure fails.\n"
    "Apply direct pressure to the wound first.\n"
)
_EV1 = "A tourniquet stops severe bleeding when direct pressure fails."
_EV2 = "Apply direct pressure to the wound first."


def _run(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", *argv], capture_output=True, text=True, cwd=REPO_ROOT
    )


def _evidence(needle: str) -> dict:
    data = DOC_TEXT.encode("utf-8")
    start = data.index(needle.encode("utf-8"))
    return {
        "source_file": "doc.txt",
        "byte_start": start,
        "byte_end": start + len(needle.encode("utf-8")),
        "text": needle,
    }


@pytest.fixture(scope="module")
def pipeline(tmp_path_factory) -> dict:
    """Run keygen + compile once; individual tests copy the outputs."""
    base = tmp_path_factory.mktemp("e2e")

    # 1) keygen
    keydir = base / "keys"
    proc = _run("axm_build.cli", "keygen", str(keydir), "--name", "pub")
    assert proc.returncode == 0, proc.stderr
    sk_path, pk_path = keydir / "pub.key", keydir / "pub.pub"
    assert sk_path.stat().st_size == 3904
    assert pk_path.stat().st_size == 1344

    # 2) compile
    content_dir = base / "content"
    content_dir.mkdir()
    (content_dir / "doc.txt").write_text(DOC_TEXT, encoding="utf-8")
    candidates = base / "candidates.jsonl"
    lines = [
        {"type": "entity", "label": "tourniquet", "entity_type": "concept"},
        {
            "type": "claim",
            "subject_label": "tourniquet",
            "predicate": "treats",
            "object_label": "severe bleeding",
            "object_type": "entity",
            "tier": 3,
            "evidence": _evidence(_EV1),
        },
        {
            "type": "claim",
            "subject_label": "direct pressure",
            "predicate": "treats",
            "object_label": "severe bleeding",
            "object_type": "entity",
            "tier": 2,
            "evidence": _evidence(_EV2),
        },
    ]
    candidates.write_text(
        "".join(json.dumps(x, ensure_ascii=False) + "\n" for x in lines), encoding="utf-8"
    )
    shard = base / "shard"
    proc = _run(
        "axm_build.cli", "compile", str(candidates), str(content_dir), str(shard),
        "--private-key", str(sk_path),
        "--namespace", "test/e2e",
        "--title", "E2E Shard",
        "--created-at", "2026-07-02T00:00:00Z",
        "--license-spdx", "CC0-1.0",
    )
    assert proc.returncode == 0, proc.stderr
    return {"shard": shard, "pub": pk_path, "key": sk_path}


def _verify_cli(shard: Path, pub: Path) -> subprocess.CompletedProcess:
    return _run("axm_verify.cli", "shard", str(shard), "--trusted-key", str(pub))


def _copy(pipeline: dict, tmp_path: Path) -> Path:
    import shutil

    dst = tmp_path / "shard"
    shutil.copytree(pipeline["shard"], dst)
    return dst


# ── Happy path ───────────────────────────────────────────────────────────────

def test_compiled_shard_verifies(pipeline: dict) -> None:
    proc = _verify_cli(pipeline["shard"], pipeline["pub"])
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.strip())
    assert result["status"] == "PASS"
    assert result["errors"] == []


def test_compiled_shard_is_pure_v1(pipeline: dict) -> None:
    shard = pipeline["shard"]
    files = {p.relative_to(shard).as_posix() for p in shard.rglob("*") if p.is_file()}
    assert files == {
        "manifest.json",
        "content/doc.txt",
        "graph/entities.jsonl",
        "graph/claims.jsonl",
        "graph/provenance.jsonl",
        "evidence/spans.jsonl",
        "sig/manifest.sig",
        "sig/publisher.pub",
    }
    manifest = json.loads((shard / "manifest.json").read_bytes())
    assert manifest["suite"] == "axm-hybrid1"
    assert manifest["spec_version"] == "1.0.0"
    assert "shard_id" not in manifest
    assert (shard / "sig" / "manifest.sig").stat().st_size == 2484
    assert (shard / "sig" / "publisher.pub").stat().st_size == 1344


# ── Tamper -> fail ───────────────────────────────────────────────────────────

def test_tampered_content_fails_with_merkle_mismatch(pipeline, tmp_path: Path) -> None:
    shard = _copy(pipeline, tmp_path)
    doc = shard / "content" / "doc.txt"
    doc.write_bytes(doc.read_bytes().replace(b"stops", b"stopped", 1))
    proc = _verify_cli(shard, pipeline["pub"])
    assert proc.returncode == 1
    assert "E_MERKLE_MISMATCH" in proc.stderr


def test_tampered_manifest_fails_with_bad_signature(pipeline, tmp_path: Path) -> None:
    shard = _copy(pipeline, tmp_path)
    mp = shard / "manifest.json"
    manifest = json.loads(mp.read_bytes())
    manifest["metadata"]["title"] = "Retitled Without Resigning"
    mp.write_bytes(
        json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    )
    proc = _verify_cli(shard, pipeline["pub"])
    assert proc.returncode == 1
    assert "E_SIG_INVALID" in proc.stderr


def test_tampered_signature_fails(pipeline, tmp_path: Path) -> None:
    shard = _copy(pipeline, tmp_path)
    sig = shard / "sig" / "manifest.sig"
    data = bytearray(sig.read_bytes())
    data[100] ^= 0xFF
    sig.write_bytes(bytes(data))
    proc = _verify_cli(shard, pipeline["pub"])
    assert proc.returncode == 1
    assert "E_SIG_INVALID" in proc.stderr


def test_wrong_publisher_key_fails(pipeline) -> None:
    proc = _verify_cli(pipeline["shard"], CI_PUB_PATH)
    assert proc.returncode == 1
    assert "E_SIG_INVALID" in proc.stderr


def test_missing_manifest_is_malformed_exit_2(pipeline, tmp_path: Path) -> None:
    shard = _copy(pipeline, tmp_path)
    (shard / "manifest.json").unlink()
    proc = _verify_cli(shard, pipeline["pub"])
    assert proc.returncode == 2
    assert "E_LAYOUT_MISSING" in proc.stderr


def test_keygen_refuses_to_overwrite(pipeline) -> None:
    keydir = pipeline["key"].parent
    proc = _run("axm_build.cli", "keygen", str(keydir), "--name", "pub")
    assert proc.returncode != 0
    assert "Refusing to overwrite" in proc.stderr


# ── Gold shard v2 ────────────────────────────────────────────────────────────

def test_gold_shard_v2_verifies() -> None:
    result = verify_shard(GOLD_SHARD, trusted_key_path=GOLD_PUB)
    assert result["status"] == "PASS", result["errors"]
    assert error_codes(result) == []


def test_gold_shard_v2_rejects_the_ci_key() -> None:
    result = verify_shard(GOLD_SHARD, trusted_key_path=CI_PUB_PATH)
    assert result["status"] == "FAIL"
    assert error_codes(result) == ["E_SIG_INVALID"]


def test_gold_shard_frozen_bytes_match_checksums() -> None:
    """In-suite twin of `make verify-frozen`: the committed gold bytes are
    pinned; any regeneration fails here before verification even runs."""
    listed = {}
    for line in GOLD_CHECKSUMS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, path = line.split(maxsplit=1)
        listed[path.lstrip("*")] = digest
    assert listed, "CHECKSUMS.sha256 is empty"

    for relpath, digest in listed.items():
        p = REPO_ROOT / relpath
        assert p.is_file(), f"checksummed file missing: {relpath}"
        assert hashlib.sha256(p.read_bytes()).hexdigest() == digest, relpath

    # Every gold-shard file is pinned — nothing can ride along unpinned.
    gold_rel = GOLD_SHARD.relative_to(REPO_ROOT).as_posix()
    on_disk = {
        f"{gold_rel}/{p.relative_to(GOLD_SHARD).as_posix()}"
        for p in GOLD_SHARD.rglob("*")
        if p.is_file()
    }
    assert on_disk == {k for k in listed if k.startswith(gold_rel)}
