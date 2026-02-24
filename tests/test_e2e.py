"""End-to-end: compile a shard from candidates.jsonl and verify it."""
import json
import tempfile
from pathlib import Path

import pytest

from axm_build.cli import _compile_from_candidates
from axm_verify.logic import verify_shard


def _make_test_content(tmpdir: Path) -> Path:
    """Create a content directory with a source file."""
    content_dir = tmpdir / "content_input"
    content_dir.mkdir()
    source = content_dir / "source.txt"
    source.write_text(
        "California Family Code section 271 authorizes sanctions "
        "to advance the policy of promoting settlement of litigation. "
        "A tourniquet is used to control severe bleeding in the field.\n",
        encoding="utf-8",
    )
    return content_dir


def _make_test_candidates(tmpdir: Path) -> Path:
    """Create a candidates.jsonl for the test content."""
    candidates = tmpdir / "candidates.jsonl"
    lines = [
        {"type": "entity", "namespace": "law/ca-family", "label": "Family Code § 271", "entity_type": "statute"},
        {"type": "entity", "namespace": "law/ca-family", "label": "sanctions", "entity_type": "concept"},
        {"type": "entity", "namespace": "law/ca-family", "label": "settlement policy", "entity_type": "concept"},
        {
            "type": "claim",
            "subject_label": "Family Code § 271",
            "predicate": "authorizes",
            "object_label": "sanctions",
            "object_type": "entity",
            "tier": 0,
            "evidence": {
                "source_file": "source.txt",
                "byte_start": 0,
                "byte_end": 77,
                "text": "California Family Code section 271 authorizes sanctions to advance the policy",
            },
        },
        {
            "type": "claim",
            "subject_label": "Family Code § 271",
            "predicate": "promotes",
            "object_label": "settlement policy",
            "object_type": "entity",
            "tier": 0,
            "evidence": {
                "source_file": "source.txt",
                "byte_start": 59,
                "byte_end": 117,
                "text": "advance the policy of promoting settlement of litigation. ",
            },
        },
    ]
    with candidates.open("w") as f:
        for line in lines:
            f.write(json.dumps(line) + "\n")
    return candidates


def _write_ed25519_keys(tmpdir: Path):
    """Generate Ed25519 key pair for testing."""
    from nacl.signing import SigningKey
    sk = SigningKey.generate()
    sk_path = tmpdir / "test.sk"
    pk_path = tmpdir / "publisher.pub"
    sk_path.write_bytes(bytes(sk))
    pk_path.write_bytes(bytes(sk.verify_key))
    return sk_path, pk_path


@pytest.fixture
def workspace():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


def test_compile_and_verify_ed25519(workspace):
    """End-to-end: compile with Ed25519, then verify."""
    content_dir = _make_test_content(workspace)
    candidates = _make_test_candidates(workspace)
    sk_path, pk_path = _write_ed25519_keys(workspace)
    outdir = workspace / "shard_out"

    manifest = _compile_from_candidates(
        candidates_path=candidates,
        content_dir=content_dir,
        outdir=outdir,
        suite="ed25519",
        private_key_path=sk_path,
        namespace="law/ca-family",
        title="Test Legal Shard",
    )

    assert manifest["statistics"]["entities"] == 3
    assert manifest["statistics"]["claims"] == 2
    assert (outdir / "manifest.json").exists()
    assert (outdir / "sig" / "manifest.sig").exists()

    # Verify
    result = verify_shard(outdir, trusted_key_path=pk_path)
    assert result["status"] == "PASS", f"Verification failed: {result['errors']}"


try:
    from axm_build.sign import mldsa44_keygen

    def test_compile_and_verify_mldsa44(workspace):
        """End-to-end: compile with ML-DSA-44, then verify."""
        content_dir = _make_test_content(workspace)
        candidates = _make_test_candidates(workspace)
        outdir = workspace / "shard_pq"

        kp = mldsa44_keygen()
        sk_path = workspace / "test_mldsa.sk"
        pk_path = workspace / "publisher.pub"
        sk_path.write_bytes(kp.secret_key)
        pk_path.write_bytes(kp.public_key)

        manifest = _compile_from_candidates(
            candidates_path=candidates,
            content_dir=content_dir,
            outdir=outdir,
            suite="axm-blake3-mldsa44",
            private_key_path=sk_path,
            namespace="law/ca-family",
            title="Test Legal Shard (PQ)",
        )

        assert manifest["suite"] == "axm-blake3-mldsa44"
        assert manifest["spec_version"] == "1.1.0"

        result = verify_shard(outdir, trusted_key_path=pk_path)
        assert result["status"] == "PASS", f"PQ verification failed: {result['errors']}"

except ImportError:
    @pytest.mark.skip(reason="dilithium-py not installed")
    def test_compile_and_verify_mldsa44(workspace):
        pass
