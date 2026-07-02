"""Reference verifier vs. the frozen shard vectors.

Every row of tests/vectors/shards/EXPECTED.md is executed in-process and
must reproduce exactly: status, error-code set, profile reporting, and the
exit code implied by the frozen contract. Because the table itself is the
parametrization source, the vectors and this suite cannot drift apart.

A second block runs adversarial mutations that the static vectors do not
cover (junk items, dotfiles, wrong trusted key, truncated key material).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from axm_verify.const import MALFORMED_SHARD_CODES, ErrorCode
from axm_verify.logic import verify_shard
from helpers import (
    CI_PUB_PATH,
    GOLD_PUB,
    SHARD_VECTORS_DIR,
    error_codes,
    expected_exit_code,
    parse_expected_rows,
    requires_mldsa_backend,
)

pytestmark = requires_mldsa_backend

ROWS = parse_expected_rows()


@pytest.mark.parametrize("row", ROWS, ids=[r["vector"] for r in ROWS])
def test_vector_reproduces_expected_md(row: dict) -> None:
    result = verify_shard(SHARD_VECTORS_DIR / row["shard"], trusted_key_path=CI_PUB_PATH)

    assert result["status"] == row["status"]
    assert error_codes(result) == row["error_codes"]
    assert result["profiles_checked"] == row["profiles_checked"]
    assert result["profiles_unchecked"] == row["profiles_unchecked"]

    # Internal consistency of the result object.
    assert result["error_count"] == len(result["errors"])
    assert (result["status"] == "PASS") == (result["error_count"] == 0)

    # The frozen exit-code contract, derived from the reported codes.
    assert expected_exit_code(result) == row["exit_code"]


def test_expected_md_and_disk_vectors_cannot_drift() -> None:
    on_disk = {
        f"{kind}/{p.name}"
        for kind in ("valid", "invalid")
        for p in (SHARD_VECTORS_DIR / kind).iterdir()
        if p.is_dir()
    }
    in_table = {row["vector"] for row in ROWS}
    assert on_disk == in_table
    for row in ROWS:
        assert (SHARD_VECTORS_DIR / row["shard"]).is_dir(), row["shard"]
        assert (SHARD_VECTORS_DIR / row["vector"] / "README.md").is_file(), row["vector"]


def test_expected_md_covers_both_outcomes() -> None:
    exit_codes = {row["exit_code"] for row in ROWS}
    assert exit_codes == {0, 1, 2}, "vector set must exercise the full exit-code contract"


# ── Cases the static vectors cannot express ──────────────────────────────────

def test_nonexistent_path_is_layout_missing() -> None:
    result = verify_shard(Path("/nonexistent/shard"), trusted_key_path=CI_PUB_PATH)
    assert result["status"] == "FAIL"
    assert error_codes(result) == [ErrorCode.E_LAYOUT_MISSING.value]
    assert expected_exit_code(result) == 2


def test_wrong_trusted_key_is_sig_invalid(minimal_shard: Path) -> None:
    result = verify_shard(minimal_shard, trusted_key_path=GOLD_PUB)
    assert result["status"] == "FAIL"
    assert error_codes(result) == [ErrorCode.E_SIG_INVALID.value]
    assert expected_exit_code(result) == 1


def test_truncated_publisher_pub_is_sig_invalid(minimal_shard: Path) -> None:
    pub = minimal_shard / "sig" / "publisher.pub"
    pub.write_bytes(pub.read_bytes()[:32])  # a bare Ed25519 key is NOT a suite
    result = verify_shard(minimal_shard, trusted_key_path=CI_PUB_PATH)
    assert error_codes(result) == [ErrorCode.E_SIG_INVALID.value]


def test_parquet_in_graph_is_layout_dirty(minimal_shard: Path) -> None:
    # Parquet is GONE from the shard: any .parquet file is a foreign object.
    (minimal_shard / "graph" / "entities.parquet").write_bytes(b"PAR1")
    result = verify_shard(minimal_shard, trusted_key_path=CI_PUB_PATH)
    assert ErrorCode.E_LAYOUT_DIRTY.value in error_codes(result)


def test_junk_root_item_is_layout_dirty(minimal_shard: Path) -> None:
    (minimal_shard / "cache").mkdir()
    (minimal_shard / "cache" / "junk.bin").write_bytes(b"\x00")
    result = verify_shard(minimal_shard, trusted_key_path=CI_PUB_PATH)
    assert ErrorCode.E_LAYOUT_DIRTY.value in error_codes(result)


def test_dotfile_is_rejected(minimal_shard: Path) -> None:
    (minimal_shard / "content" / ".DS_Store").write_bytes(b"\x00")
    result = verify_shard(minimal_shard, trusted_key_path=CI_PUB_PATH)
    assert ErrorCode.E_DOTFILE.value in error_codes(result)


def test_extra_file_in_sig_is_layout_dirty(minimal_shard: Path) -> None:
    (minimal_shard / "sig" / "extra.sig").write_bytes(b"\x00")
    result = verify_shard(minimal_shard, trusted_key_path=CI_PUB_PATH)
    assert ErrorCode.E_LAYOUT_DIRTY.value in error_codes(result)


def test_tampered_content_is_merkle_mismatch(minimal_shard: Path) -> None:
    doc = minimal_shard / "content" / "doc.txt"
    data = bytearray(doc.read_bytes())
    data[0] ^= 0x01
    doc.write_bytes(bytes(data))
    result = verify_shard(minimal_shard, trusted_key_path=CI_PUB_PATH)
    # The manifest and signature are untouched and still verify; the Merkle
    # root is the layer that catches the tamper... unless sources hashing
    # catches it first — the spec's stage order says Merkle runs first.
    assert error_codes(result) == [ErrorCode.E_MERKLE_MISMATCH.value]


def test_ext_file_without_manifest_listing_is_rejected(minimal_shard: Path) -> None:
    # ext/ content must be declared via manifest.extensions; an undeclared
    # ext file also breaks the Merkle root. Manifest validation runs first.
    ext = minimal_shard / "ext"
    ext.mkdir()
    (ext / "lineage@1.jsonl").write_bytes(b"")
    result = verify_shard(minimal_shard, trusted_key_path=CI_PUB_PATH)
    assert ErrorCode.E_MANIFEST_SCHEMA.value in error_codes(result)


def test_malformed_shard_codes_are_frozen() -> None:
    assert MALFORMED_SHARD_CODES == frozenset(
        {"E_LAYOUT_MISSING", "E_SCHEMA_MISSING", "E_SIG_MISSING"}
    )
