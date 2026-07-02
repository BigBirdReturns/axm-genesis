"""The conformance habit in miniature: build → verify PASS → tamper → FAIL.

Every spoke should ship this shape of test and run it in CI. The keypair is
generated fresh in tmp on every run — throwaway keys for tests, real keys
offline, never both in one pool (one publisher identity per key pool).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from axm_build.sign import HYBRID1_PK_LEN, HYBRID1_SK_LEN, hybrid1_keygen
from axm_verify.logic import verify_shard

from axm_spoke_template import build_shard

FIXTURE = Path(__file__).parent / "fixtures" / "sample.txt"
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


def test_build_verify_tamper_roundtrip(tmp_path: Path, keypair: tuple[Path, Path]) -> None:
    key_path, pub_path = keypair
    shard_dir = tmp_path / "shard"

    # Build: returns the derived shard identity.
    shard_id = build_shard(FIXTURE, shard_dir, key_path, namespace="template/test")
    assert SHARD_ID_RE.match(shard_id), shard_id

    # Verify: the kernel verifier must PASS with the publisher key.
    result = verify_shard(shard_dir, trusted_key_path=pub_path)
    assert result["status"] == "PASS", result["errors"]
    assert result["error_count"] == 0
    # Unchecked is not passed — this shard declares no profiles, so both
    # arrays must be present and empty (spec section 13.3).
    assert result["profiles_checked"] == []
    assert result["profiles_unchecked"] == []

    # Tamper one byte of sealed content: verification must FAIL.
    content = shard_dir / "content" / "source.txt"
    raw = bytearray(content.read_bytes())
    raw[0] ^= 0x01
    content.write_bytes(bytes(raw))

    tampered = verify_shard(shard_dir, trusted_key_path=pub_path)
    assert tampered["status"] == "FAIL"
    assert tampered["error_count"] >= 1
    codes = {e["code"] for e in tampered["errors"]}
    assert "E_MERKLE_MISMATCH" in codes, codes


def test_wrong_trusted_key_fails(tmp_path: Path, keypair: tuple[Path, Path]) -> None:
    """Trust is anchored out of band: a different key must be rejected."""
    key_path, _ = keypair
    shard_dir = tmp_path / "shard"
    build_shard(FIXTURE, shard_dir, key_path, namespace="template/test")

    other_pub, _ = hybrid1_keygen()
    other_path = tmp_path / "other.pub"
    other_path.write_bytes(other_pub)

    result = verify_shard(shard_dir, trusted_key_path=other_path)
    assert result["status"] == "FAIL"
    assert {e["code"] for e in result["errors"]} == {"E_SIG_INVALID"}
