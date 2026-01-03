from __future__ import annotations

import json
from pathlib import Path

import pytest

from axm_verify.identity import canonicalize, recompute_entity_id, recompute_claim_id
from axm_verify.crypto import compute_merkle_root
from axm_verify.logic import verify_shard


REPO_ROOT = Path(__file__).resolve().parents[1]
VECTORS = REPO_ROOT / "tests" / "vectors"
TRUSTED_KEY = REPO_ROOT / "keys" / "canonical_test_publisher.pub"


def test_identity_vectors() -> None:
    data = json.loads((VECTORS / "identity.json").read_text(encoding="utf-8"))
    for case in data["canonicalization"]:
        if case.get("expected_error"):
            with pytest.raises(ValueError):
                canonicalize(case["input"])
        else:
            assert canonicalize(case["input"]) == case["expected"]

    for case in data["entity_ids"]:
        assert recompute_entity_id(case["namespace"], case["label"]) == case["expected_id"]

    for case in data["claim_ids"]:
        assert (
            recompute_claim_id(case["subject"], case["predicate"], case["object"], case["object_type"])
            == case["expected_id"]
        )


def test_merkle_vectors(tmp_path: Path) -> None:
    data = json.loads((VECTORS / "merkle.json").read_text(encoding="utf-8"))
    for case in data["cases"]:
        shard = tmp_path / case["name"]
        shard.mkdir()
        (shard / "sig").mkdir()  # excluded

        for rel, content in case["files"].items():
            p = shard / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, str):
                p.write_text(content, encoding="utf-8", newline="\n")
            else:
                raise AssertionError("Unexpected content type in merkle vectors")

        assert compute_merkle_root(shard) == case["expected_root"]


def test_gold_shard_passes() -> None:
    gold = REPO_ROOT / "shards" / "gold" / "fm21-11-hemorrhage-v1"
    res = verify_shard(gold, trusted_key_path=TRUSTED_KEY)
    assert res["status"] == "PASS"
    assert res["error_count"] == 0
    assert res["errors"] == []


@pytest.mark.parametrize(
    "name,expected_code",
    [
        ("missing_manifest", "E_LAYOUT_MISSING"),
        ("bad_signature", "E_SIG_INVALID"),
        ("merkle_mismatch", "E_MERKLE_MISMATCH"),
        ("null_in_column", "E_SCHEMA_NULL"),
        ("orphan_claim", "E_REF_ORPHAN"),
    ],
)
def test_invalid_shards_fail(name: str, expected_code: str) -> None:
    shard = VECTORS / "shards" / "invalid" / name
    res = verify_shard(shard, trusted_key_path=TRUSTED_KEY)
    assert res["status"] == "FAIL"
    assert res["error_count"] >= 1
    codes = {e["code"] for e in res["errors"]}
    assert expected_code in codes
