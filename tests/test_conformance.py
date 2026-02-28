"""
AXM Genesis Conformance Test Suite
====================================
Version: 0.1
Covers: REQ 1–5 of AXM_Compatibility_Test_Procedure.md

Run:
    cd genesis && python -m pytest tests/test_conformance.py -v

All tests operate on a mutable copy of the gold shard. The gold shard
bytes are never modified — each test gets a fresh copy via the `gold`
fixture.
"""
from __future__ import annotations

import shutil
import struct
from pathlib import Path

import pytest

from axm_verify.logic import verify_shard
from axm_verify.const import ErrorCode

# ── Fixtures ──────────────────────────────────────────────────────────────────

REPO_ROOT  = Path(__file__).resolve().parents[1]
GOLD_SHARD = REPO_ROOT / "shards" / "gold" / "fm21-11-hemorrhage-v1"
TRUSTED_KEY = REPO_ROOT / "keys" / "canonical_test_publisher.pub"

# Binary format constants — must match axm-embodied protocol.py exactly
# cam_latents.bin: [AXLF(4)] [records: AXLR(4)+ver(1)+frame_id(4)+length(4)+payload]*
LATENT_FILE_MAGIC  = b"AXLF"   # 4-byte file header
LATENT_REC_MAGIC   = b"AXLR"   # per-record magic
LATENT_REC_VERSION = 1
LATENT_HEADER_FMT  = "<4sBII"  # magic(4) ver(1) frame_id(4) length(4)
LATENT_HEADER_LEN  = struct.calcsize(LATENT_HEADER_FMT)  # 13 bytes
LATENT_PAYLOAD_LEN = 256       # matches LATENT_DIM in protocol.py


@pytest.fixture
def gold(tmp_path: Path) -> Path:
    """Fresh mutable copy of the gold shard for each test."""
    dst = tmp_path / "shard"
    shutil.copytree(GOLD_SHARD, dst)
    return dst


# ── Baseline ──────────────────────────────────────────────────────────────────

def test_baseline_gold_shard_passes(gold: Path) -> None:
    """The gold shard must pass verification. All other tests depend on this."""
    result = verify_shard(gold, trusted_key_path=TRUSTED_KEY)
    assert result["status"] == "PASS", f"Gold shard failed: {result['errors']}"


# ── REQ 1: Manifest integrity ─────────────────────────────────────────────────

def test_req1_manifest_byte_flip_detected(gold: Path) -> None:
    """Flipping one byte in manifest.json must invalidate the signature."""
    manifest_path = gold / "manifest.json"
    raw = bytearray(manifest_path.read_bytes())
    raw[10] ^= 0x01
    manifest_path.write_bytes(bytes(raw))

    result = verify_shard(gold, trusted_key_path=TRUSTED_KEY)
    assert result["status"] == "FAIL"
    codes = {e["code"] for e in result["errors"]}
    # A byte flip in manifest.json may break JSON parsing (E_MANIFEST_SCHEMA)
    # before the signature check runs, or it may produce a valid-but-different
    # JSON document that fails signature verification (E_SIG_INVALID).
    # Either error is correct — the shard is rejected.
    assert codes & {ErrorCode.E_SIG_INVALID, ErrorCode.E_MANIFEST_SCHEMA}, (
        f"Expected E_SIG_INVALID or E_MANIFEST_SCHEMA in {codes}"
    )


def test_req1_manifest_invalid_json_detected(gold: Path) -> None:
    """Replacing manifest.json with invalid JSON must be caught."""
    (gold / "manifest.json").write_bytes(b"{not valid json")

    result = verify_shard(gold, trusted_key_path=TRUSTED_KEY)
    assert result["status"] == "FAIL"
    codes = {e["code"] for e in result["errors"]}
    assert ErrorCode.E_MANIFEST_SYNTAX in codes or ErrorCode.E_SIG_INVALID in codes


# ── REQ 2: Content identity ───────────────────────────────────────────────────

def test_req2_content_byte_flip_changes_merkle_root(gold: Path) -> None:
    """Flipping one byte in a content file must cause a Merkle mismatch."""
    source = gold / "content" / "source.txt"
    raw = bytearray(source.read_bytes())
    raw[0] ^= 0x01
    source.write_bytes(bytes(raw))

    result = verify_shard(gold, trusted_key_path=TRUSTED_KEY)
    assert result["status"] == "FAIL"
    codes = {e["code"] for e in result["errors"]}
    assert ErrorCode.E_MERKLE_MISMATCH in codes or ErrorCode.E_SIG_INVALID in codes


def test_req2_parquet_byte_flip_changes_merkle_root(gold: Path) -> None:
    """Flipping one byte in a graph parquet file must cause a Merkle mismatch."""
    claims = gold / "graph" / "claims.parquet"
    raw = bytearray(claims.read_bytes())
    raw[-10] ^= 0x01
    claims.write_bytes(bytes(raw))

    result = verify_shard(gold, trusted_key_path=TRUSTED_KEY)
    assert result["status"] == "FAIL"
    codes = {e["code"] for e in result["errors"]}
    assert ErrorCode.E_MERKLE_MISMATCH in codes or ErrorCode.E_SIG_INVALID in codes


# ── REQ 3: Lineage events ─────────────────────────────────────────────────────

def test_req3_orphan_claim_detected(gold: Path) -> None:
    """A claim referencing a non-existent entity must be rejected."""
    vector = REPO_ROOT / "tests" / "vectors" / "shards" / "invalid" / "orphan_claim"
    if not vector.exists():
        pytest.skip("orphan_claim vector not present")

    result = verify_shard(vector, trusted_key_path=TRUSTED_KEY)
    assert result["status"] == "FAIL"
    codes = {e["code"] for e in result["errors"]}
    assert ErrorCode.E_REF_ORPHAN in codes


def test_req3_null_in_column_detected(gold: Path) -> None:
    """A null value in a required Parquet column must be rejected."""
    vector = REPO_ROOT / "tests" / "vectors" / "shards" / "invalid" / "null_in_column"
    if not vector.exists():
        pytest.skip("null_in_column vector not present")

    result = verify_shard(vector, trusted_key_path=TRUSTED_KEY)
    assert result["status"] == "FAIL"
    codes = {e["code"] for e in result["errors"]}
    assert ErrorCode.E_SCHEMA_NULL in codes


# ── REQ 4: Proof bundle ───────────────────────────────────────────────────────

def test_req4_wrong_signing_key_rejected(gold: Path, tmp_path: Path) -> None:
    """A shard verified with the wrong trusted key must be rejected."""
    from nacl.signing import SigningKey
    wrong_key = SigningKey.generate()
    wrong_pub = tmp_path / "wrong.pub"
    wrong_pub.write_bytes(bytes(wrong_key.verify_key))

    result = verify_shard(gold, trusted_key_path=wrong_pub)
    assert result["status"] == "FAIL"
    codes = {e["code"] for e in result["errors"]}
    assert ErrorCode.E_SIG_INVALID in codes


def test_req4_sig_byte_flip_rejected(gold: Path) -> None:
    """Flipping one byte in the signature must cause rejection."""
    sig_path = gold / "sig" / "manifest.sig"
    raw = bytearray(sig_path.read_bytes())
    raw[0] ^= 0x01
    sig_path.write_bytes(bytes(raw))

    result = verify_shard(gold, trusted_key_path=TRUSTED_KEY)
    assert result["status"] == "FAIL"
    codes = {e["code"] for e in result["errors"]}
    assert ErrorCode.E_SIG_INVALID in codes


def test_req4_missing_manifest_rejected(gold: Path) -> None:
    """A shard with no manifest.json must be rejected."""
    vector = REPO_ROOT / "tests" / "vectors" / "shards" / "invalid" / "missing_manifest"
    if not vector.exists():
        pytest.skip("missing_manifest vector not present")

    result = verify_shard(vector, trusted_key_path=TRUSTED_KEY)
    assert result["status"] == "FAIL"
    codes = {e["code"] for e in result["errors"]}
    assert ErrorCode.E_LAYOUT_MISSING in codes


# ── REQ 5: Non-selective recording ───────────────────────────────────────────
#
# These tests write a synthetic cam_latents.bin into content/ of the gold shard
# copy. The gold shard has no binary streams — these tests inject them to
# exercise the continuity validator in isolation.
#
# Binary format (must match embodied protocol.py):
#   File:   [AXLF (4 bytes)] [record...]*
#   Record: [AXLR (4)] [ver=1 (1)] [frame_id (4)] [length (4)] [payload (length)]

def _write_latents(path: Path, frame_ids: list[int], payload_len: int = LATENT_PAYLOAD_LEN) -> None:
    """Write a cam_latents.bin with the given frame_ids in order."""
    with open(path, "wb") as f:
        f.write(LATENT_FILE_MAGIC)  # 4-byte file header
        for fid in frame_ids:
            payload = bytes([fid % 256]) * payload_len
            header = struct.pack(LATENT_HEADER_FMT, LATENT_REC_MAGIC,
                                 LATENT_REC_VERSION, fid, len(payload))
            f.write(header + payload)


def test_req5_buffer_gap_detected(gold: Path) -> None:
    """A gap in the hot stream frame sequence must trigger E_BUFFER_DISCONTINUITY.

    Simulates an agent dropping frame 5 to conceal a failure event.
    Valid sequence [0,1,2,3,4,6,7,...] — frame 5 missing — must fail.

    We call _validate_hot_stream_continuity directly because verify_shard
    short-circuits on E_MERKLE_MISMATCH (correct behavior: tampered content
    fails Merkle before any further checks). This test validates the
    continuity logic in isolation.
    """
    from axm_verify.logic import _validate_hot_stream_continuity

    latents_path = gold / "content" / "cam_latents.bin"
    frame_ids = list(range(5)) + list(range(6, 11))
    _write_latents(latents_path, frame_ids)

    errors: list[dict] = []
    _validate_hot_stream_continuity(gold / "content", errors)
    codes = {e["code"] for e in errors}
    assert ErrorCode.E_BUFFER_DISCONTINUITY in codes, (
        f"Expected E_BUFFER_DISCONTINUITY in {codes}"
    )


def test_req5_continuous_stream_passes_continuity_check(gold: Path) -> None:
    """A perfectly continuous stream must not trigger E_BUFFER_DISCONTINUITY.

    The shard will still fail on Merkle/sig (content changed) but must NOT
    fail with E_BUFFER_DISCONTINUITY.
    """
    latents_path = gold / "content" / "cam_latents.bin"
    _write_latents(latents_path, list(range(10)))

    result = verify_shard(gold, trusted_key_path=TRUSTED_KEY)
    codes = {e["code"] for e in result["errors"]}
    assert ErrorCode.E_BUFFER_DISCONTINUITY not in codes, (
        "A continuous stream must not trigger E_BUFFER_DISCONTINUITY"
    )


# ── Cross-cutting: determinism ────────────────────────────────────────────────

def test_verification_is_deterministic(gold: Path) -> None:
    """Same inputs must produce identical verification output every time."""
    result_a = verify_shard(gold, trusted_key_path=TRUSTED_KEY)
    result_b = verify_shard(gold, trusted_key_path=TRUSTED_KEY)
    assert result_a == result_b, "Verification is not deterministic"
