from __future__ import annotations

import os
import shutil
import json
from pathlib import Path

import pytest
from nacl.signing import SigningKey

import pyarrow as pa
import pyarrow.parquet as pq

from axm_verify.logic import verify_shard, MAX_FILE_BYTES
from axm_verify.crypto import compute_merkle_root
from axm_build.manifest import canonical_manifest_json
from axm_build.cli import CANONICAL_TEST_PRIVATE_KEY


VECTORS = Path(__file__).parent / "vectors"
TRUSTED_KEY = (Path(__file__).parent.parent / "keys" / "canonical_test_public_key").resolve()


def _copy_vector(tmp_path: Path, name: str) -> Path:
    src = VECTORS / "shards" / "valid" / name
    dst = tmp_path / name
    shutil.copytree(src, dst)
    return dst


def _write_manifest_and_sig(shard: Path, manifest_obj: dict) -> None:
    manifest_bytes = canonical_manifest_json(manifest_obj)
    (shard / "manifest.json").write_bytes(manifest_bytes)

    sk = SigningKey(CANONICAL_TEST_PRIVATE_KEY)
    sig = sk.sign(manifest_bytes).signature
    (shard / "sig" / "manifest.sig").write_bytes(sig)


def test_rejects_symlink_in_shard(tmp_path: Path) -> None:
    shard = _copy_vector(tmp_path, "minimal")

    target = shard / "manifest.json"
    link = shard / "content" / "source.txt"
    if link.exists():
        link.unlink()

    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported in this environment")

    result = verify_shard(shard, trusted_key_path=TRUSTED_KEY)
    assert result["status"] == "FAIL"
    assert any(e["code"] == "E_LAYOUT_DIRTY" for e in result["errors"])


def test_rejects_oversize_file_before_hashing(tmp_path: Path) -> None:
    shard = _copy_vector(tmp_path, "minimal")

    big = shard / "content" / "big.bin"
    with big.open("wb") as f:
        f.truncate(MAX_FILE_BYTES + 1)

    result = verify_shard(shard, trusted_key_path=TRUSTED_KEY)
    assert result["status"] == "FAIL"
    assert any(e["code"] in ("E_LAYOUT_DIRTY", "E_REF_READ") for e in result["errors"])


def test_rejects_parquet_row_limit(tmp_path: Path) -> None:
    shard = _copy_vector(tmp_path, "minimal")

    entities_path = shard / "graph" / "entities.parquet"
    schema = pq.read_schema(entities_path)

    n = 1_000_001  # verifier limit is 1_000_000
    cols = []
    for field in schema:
        t = field.type
        if pa.types.is_string(t) or pa.types.is_large_string(t):
            cols.append(pa.array(["x"] * n, type=t))
        elif pa.types.is_int64(t) or pa.types.is_int32(t) or pa.types.is_uint32(t) or pa.types.is_uint64(t):
            cols.append(pa.array(range(n), type=t))
        else:
            cols.append(pa.array([0] * n, type=t))

    table = pa.Table.from_arrays(cols, schema=schema)
    pq.write_table(table, entities_path)

    manifest_obj = json.loads((shard / "manifest.json").read_text())
    manifest_obj["integrity"]["merkle_root"] = compute_merkle_root(shard)
    _write_manifest_and_sig(shard, manifest_obj)

    result = verify_shard(shard, trusted_key_path=TRUSTED_KEY)
    assert result["status"] == "FAIL"
    assert any(e["code"] == "E_SCHEMA_READ" and "exceeds row limit" in e["message"] for e in result["errors"])
