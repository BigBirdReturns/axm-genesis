"""
tests/test_fleet_roundtrip.py

The conformance habit for the fleet spoke (docs/ADOPTING.md §5), plus the
two things this spoke exists to demonstrate:

  1. the sustainment loop — a patch is a NEW shard that supersedes the old
     one, with the lineage sealed by the kernel;
  2. artifact binding — the record's digests are the real digests of the
     external artifacts it describes.

Keys are throwaway, generated fresh per run — they prove the pipeline,
never authenticity.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

try:
    from axm_build.sign import HYBRID1_PK_LEN, HYBRID1_SK_LEN, hybrid1_keygen
    _keygen_error = None
    try:
        hybrid1_keygen()
        _BACKEND = True
    except Exception as exc:  # no ML-DSA-44 backend installed
        _BACKEND = False
        _keygen_error = str(exc)
except ImportError as exc:
    raise

from axm_verify.logic import verify_shard

requires_backend = pytest.mark.skipif(
    not _BACKEND,
    reason=f"requires an ML-DSA-44 backend (liboqs-python or dilithium-py): {_keygen_error}",
)

SPOKE_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = SPOKE_ROOT / "examples"
ARTIFACTS = EXAMPLES / "artifacts"
DEPLOY_RECORD = EXAMPLES / "node-0042.deploy.json"
PATCH_RECORD = EXAMPLES / "node-0042.patch.json"
SHARD_ID_RE = re.compile(r"^sh1_[0-9a-f]{64}$")


@pytest.fixture()
def keypair(tmp_path: Path) -> tuple[Path, Path]:
    """Throwaway keypair in tmp; proves the pipeline, never authenticity."""
    public_key, secret_key = hybrid1_keygen()
    assert len(secret_key) == HYBRID1_SK_LEN
    assert len(public_key) == HYBRID1_PK_LEN
    key_path = tmp_path / "test_publisher.key"
    pub_path = tmp_path / "test_publisher.pub"
    key_path.write_bytes(secret_key)
    pub_path.write_bytes(public_key)
    return key_path, pub_path


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def test_example_records_validate():
    from axm_fleet.record_schema import validate_node_record
    for record_path in (DEPLOY_RECORD, PATCH_RECORD):
        errors = validate_node_record(json.loads(record_path.read_text()))
        assert errors == [], f"{record_path.name}: {errors}"


def test_artifact_digests_bind():
    """The digests in the example records are the REAL digests of the
    committed sample artifacts — the shard seals the record, the record's
    digests bind the artifacts."""
    deploy = json.loads(DEPLOY_RECORD.read_text())
    patch = json.loads(PATCH_RECORD.read_text())

    expected = {
        deploy["image"]["image_digest"]: "image-2026.07.02-r1.bin",
        deploy["image"]["sbom_digest"]: "sbom-r1.spdx.json",
        deploy["image"]["provenance_digest"]: "provenance-r1.intoto.json",
        deploy["components"]["detect-model"]["digest"]: "detect-model-4.2.1.onnx.bin",
        deploy["components"]["autopilot-fw"]["digest"]: "autopilot-fw-1.9.3.bin",
        patch["image"]["image_digest"]: "image-2026.07.02-r2.bin",
        patch["image"]["sbom_digest"]: "sbom-r2.spdx.json",
        patch["image"]["provenance_digest"]: "provenance-r2.intoto.json",
        patch["components"]["detect-model"]["digest"]: "detect-model-4.2.2.onnx.bin",
    }
    for digest, filename in expected.items():
        assert digest == _sha256(ARTIFACTS / filename), filename


@requires_backend
def test_build_verify_tamper_roundtrip(tmp_path, keypair):
    """node_record.json → shard → verify PASS → tamper one byte → FAIL."""
    from axm_fleet import compile_record

    key_path, pub_path = keypair
    out = tmp_path / "record_shard"

    shard_id = compile_record(DEPLOY_RECORD, out, key_path)
    assert SHARD_ID_RE.match(shard_id), shard_id

    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["spec_version"] == "1.0.0"
    assert manifest["suite"] == "axm-hybrid1"
    assert "shard_id" not in manifest  # identity is derived, never stored
    assert manifest["statistics"]["claims"] > 0

    result = verify_shard(out, trusted_key_path=pub_path)
    assert result["status"] == "PASS", result["errors"]
    assert result["error_count"] == 0
    assert result["profiles_checked"] == []
    assert result["profiles_unchecked"] == []

    content = out / "content" / "source.txt"
    raw = bytearray(content.read_bytes())
    raw[0] ^= 0x01
    content.write_bytes(bytes(raw))

    tampered = verify_shard(out, trusted_key_path=pub_path)
    assert tampered["status"] == "FAIL"
    codes = {e["code"] for e in tampered["errors"]}
    assert "E_MERKLE_MISMATCH" in codes, codes


@requires_backend
def test_wrong_trusted_key_fails(tmp_path, keypair):
    """Trust is anchored out of band: a different key must be rejected."""
    from axm_fleet import compile_record

    key_path, _ = keypair
    out = tmp_path / "record_shard"
    compile_record(DEPLOY_RECORD, out, key_path)

    other_pub, _ = hybrid1_keygen()
    other_path = tmp_path / "other.pub"
    other_path.write_bytes(other_pub)

    result = verify_shard(out, trusted_key_path=other_path)
    assert result["status"] == "FAIL"
    assert {e["code"] for e in result["errors"]} == {"E_SIG_INVALID"}


@requires_backend
def test_patch_supersedes_deploy(tmp_path, keypair):
    """The sustainment loop: the patch record is a new shard that names
    the deploy record's derived id; the kernel seals the lineage."""
    from axm_fleet import compile_record

    key_path, pub_path = keypair
    deploy_out = tmp_path / "pool" / "deploy"
    patch_out = tmp_path / "pool" / "patch"

    deploy_id = compile_record(DEPLOY_RECORD, deploy_out, key_path,
                               created_at="2026-07-02T00:00:00Z")
    patch_id = compile_record(PATCH_RECORD, patch_out, key_path,
                              supersedes=(deploy_id,),
                              created_at="2026-07-02T10:00:00Z")
    assert patch_id != deploy_id

    manifest = json.loads((patch_out / "manifest.json").read_text())
    assert manifest["supersedes"] == [deploy_id]
    assert "lineage@1" in manifest["extensions"]

    lineage_rows = [
        json.loads(line)
        for line in (patch_out / "ext" / "lineage@1.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert len(lineage_rows) == 1
    row = lineage_rows[0]
    assert row["action"] == "supersede"
    assert row["supersedes_shard_id"] == deploy_id
    assert row["note"] == "patch 2026.07.02-r2"

    # Both records verify; the deploy record is superseded, not invalidated.
    for shard in (deploy_out, patch_out):
        result = verify_shard(shard, trusted_key_path=pub_path)
        assert result["status"] == "PASS", (shard, result["errors"])


@requires_backend
def test_no_key_refuses(tmp_path):
    """There is deliberately no default signing key."""
    from axm_fleet import compile_record

    with pytest.raises(ValueError, match="no default key"):
        compile_record(DEPLOY_RECORD, tmp_path / "shard")


@requires_backend
def test_bad_key_length_refuses(tmp_path):
    """Unexpected key material must raise, never be coerced or replaced."""
    from axm_fleet import compile_record

    bad_key = tmp_path / "bad.key"
    bad_key.write_bytes(b"\x00" * 64)
    with pytest.raises(ValueError, match="axm-hybrid1"):
        compile_record(DEPLOY_RECORD, tmp_path / "shard", bad_key)


@requires_backend
def test_reproducible_build(tmp_path, keypair):
    """Same record + same key + same created_at → byte-identical manifest."""
    from axm_fleet import compile_record

    key_path, _ = keypair
    ts = "2026-07-02T00:00:00Z"
    id_a = compile_record(DEPLOY_RECORD, tmp_path / "a", key_path, created_at=ts)
    id_b = compile_record(DEPLOY_RECORD, tmp_path / "b", key_path, created_at=ts)
    assert id_a == id_b
    assert (tmp_path / "a" / "manifest.json").read_bytes() == \
           (tmp_path / "b" / "manifest.json").read_bytes()


@requires_backend
@pytest.mark.skipif(shutil.which("go") is None, reason="requires a Go toolchain")
def test_independent_go_verifier_accepts(tmp_path, keypair):
    """The control test for the evidence layer: a second verifier, built
    from the spec and vectors alone, accepts the record shard. Remove the
    reference implementation and the record still proves out."""
    from axm_fleet import compile_record

    go_dir = SPOKE_ROOT.parents[1] / "verifiers" / "go"
    if not go_dir.is_dir():
        pytest.skip("in-repo Go verifier not present (spoke lifted out?)")

    key_path, pub_path = keypair
    out = tmp_path / "record_shard"
    compile_record(DEPLOY_RECORD, out, key_path)

    binary = tmp_path / "axm-verify-go"
    subprocess.run(
        ["go", "build", "-o", str(binary), "./cmd/axm-verify-go"],
        cwd=go_dir, check=True, capture_output=True,
    )
    proc = subprocess.run(
        [str(binary), "shard", str(out), "--trusted-key", str(pub_path)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    result = json.loads(proc.stdout)
    assert result["status"] == "PASS", result
