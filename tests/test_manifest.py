"""Full manifest enforcement (spec section 6, RFC 0002 D5) and derived
shard identity (D3).

Every case copies the valid/minimal vector shard, mutates the manifest,
RE-SIGNS it with the CI test key, and verifies. Because the signature is
always fresh, any failure is attributable to the manifest rule under test,
never to a stale signature.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict

import blake3
import pytest

from axm_build.jsonl import canonical_json_bytes
from axm_build.merkle import compute_merkle_root
from axm_verify.const import ErrorCode
from axm_verify.crypto import derive_shard_id
from axm_verify.logic import verify_shard
from helpers import (
    CI_KEY_PATH,
    CI_PUB_PATH,
    GOLD_SHARD,
    MINIMAL_SHARD,
    error_codes,
    load_manifest,
    mutate_and_verify,
    requires_mldsa_backend,
    reseal_shard,
    reseal_shard_bytes,
)

pytestmark = requires_mldsa_backend

_CI_KEY = CI_KEY_PATH.read_bytes()


def _verify(shard: Path) -> Dict[str, Any]:
    return verify_shard(shard, trusted_key_path=CI_PUB_PATH)


# ── Control: the harness itself must produce a passing shard ─────────────────

def test_reseal_without_mutation_passes(minimal_shard: Path) -> None:
    result = mutate_and_verify(minimal_shard, _CI_KEY, mutate=None)
    assert result["status"] == "PASS", result["errors"]


# ── Required fields: each violation must be caught ───────────────────────────

def _del(*path: str) -> Callable[[Dict[str, Any]], None]:
    def mutate(m: Dict[str, Any]) -> None:
        target = m
        for key in path[:-1]:
            target = target[key]
        del target[path[-1]]
    return mutate


def _set(value: Any, *path: str) -> Callable[[Dict[str, Any]], None]:
    def mutate(m: Dict[str, Any]) -> None:
        target = m
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    return mutate


INVALID_MANIFEST_CASES = [
    # (case id, mutator) — all must FAIL with E_MANIFEST_SCHEMA.
    ("missing_spec_version", _del("spec_version")),
    ("wrong_spec_version", _set("0.9.0", "spec_version")),
    ("v0_spec_version", _set("1.0", "spec_version")),
    ("missing_suite", _del("suite")),
    ("legacy_suite_ed25519", _set("ed25519", "suite")),
    ("legacy_suite_mldsa", _set("axm-blake3-mldsa44", "suite")),
    ("missing_metadata", _del("metadata")),
    ("missing_title", _del("metadata", "title")),
    ("empty_title", _set("", "metadata", "title")),
    ("missing_namespace", _del("metadata", "namespace")),
    ("missing_created_at", _del("metadata", "created_at")),
    ("created_at_numeric_offset", _set("2026-07-02T00:00:00+00:00", "metadata", "created_at")),
    ("created_at_no_designator", _set("2026-07-02T00:00:00", "metadata", "created_at")),
    ("created_at_space_separator", _set("2026-07-02 00:00:00Z", "metadata", "created_at")),
    ("created_at_date_only", _set("2026-07-02", "metadata", "created_at")),
    ("created_at_bad_month", _set("2026-13-01T00:00:00Z", "metadata", "created_at")),
    ("created_at_bad_day", _set("2026-02-30T00:00:00Z", "metadata", "created_at")),
    ("created_at_bad_hour", _set("2026-07-02T24:00:00Z", "metadata", "created_at")),
    ("created_at_lowercase_z", _set("2026-07-02T00:00:00z", "metadata", "created_at")),
    ("created_at_integer", _set(1751414400, "metadata", "created_at")),
    ("missing_publisher", _del("publisher")),
    ("missing_publisher_id", _del("publisher", "id")),
    ("missing_publisher_name", _del("publisher", "name")),
    ("empty_publisher_id", _set("", "publisher", "id")),
    ("missing_license", _del("license")),
    ("empty_license_spdx", _set("", "license", "spdx")),
    ("missing_sources", _del("sources")),
    ("empty_sources", _set([], "sources")),
    ("source_path_escapes_content", _set(
        [{"path": "../../etc/passwd", "hash": "0" * 64}], "sources")),
    ("source_path_traversal", _set(
        [{"path": "content/../sig/manifest.sig", "hash": "0" * 64}], "sources")),
    ("source_hash_uppercase", _set("A" * 64, "sources", 0, "hash")),
    ("source_hash_short", _set("ab", "sources", 0, "hash")),
    ("missing_integrity", _del("integrity")),
    ("wrong_algorithm", _set("sha256", "integrity", "algorithm")),
    ("merkle_root_not_hex64", _set("zz", "integrity", "merkle_root")),
    ("missing_statistics", _del("statistics")),
    ("statistics_negative", _set(-1, "statistics", "entities")),
    ("statistics_string", _set("3", "statistics", "claims")),
    ("statistics_float", _set(3.0, "statistics", "entities")),
    ("shard_id_present", _set("sh1_" + "0" * 64, "shard_id")),
    ("unknown_top_level_key", _set("nope", "compression")),
    ("profiles_empty_array", _set([], "profiles")),
    ("profiles_bad_grammar", _set(["Embodied@1"], "profiles")),
    ("profiles_unversioned", _set(["embodied"], "profiles")),
    ("profiles_duplicate", _set(["embodied@1", "embodied@1"], "profiles")),
    ("supersedes_not_sh1", _set(["shard-000"], "supersedes")),
    ("extensions_without_ext_dir", _set(["lineage@1"], "extensions")),
]


@pytest.mark.parametrize(
    "mutate", [c[1] for c in INVALID_MANIFEST_CASES], ids=[c[0] for c in INVALID_MANIFEST_CASES]
)
def test_manifest_violation_is_rejected(minimal_shard: Path, mutate) -> None:
    result = mutate_and_verify(minimal_shard, _CI_KEY, mutate)
    assert result["status"] == "FAIL"
    assert error_codes(result) == [ErrorCode.E_MANIFEST_SCHEMA.value], result["errors"]


def test_statistics_must_equal_actual_row_counts(minimal_shard: Path) -> None:
    # Structurally valid statistics that lie about the tables (checked in a
    # later stage than the schema, hence a separate test).
    manifest = load_manifest(minimal_shard)
    manifest["statistics"]["entities"] += 1
    reseal_shard(minimal_shard, manifest, _CI_KEY)
    result = _verify(minimal_shard)
    assert result["status"] == "FAIL"
    assert error_codes(result) == [ErrorCode.E_MANIFEST_SCHEMA.value]
    assert "statistics.entities" in result["errors"][0]["message"]


def test_manifest_not_valid_json_is_syntax_error(minimal_shard: Path) -> None:
    reseal_shard_bytes(minimal_shard, b'{"spec_version":', _CI_KEY)
    result = _verify(minimal_shard)
    assert error_codes(result) == [ErrorCode.E_MANIFEST_SYNTAX.value]


def test_non_canonical_manifest_encoding_rejected(minimal_shard: Path) -> None:
    # Same JSON value, pretty-printed — and signed over those exact bytes,
    # so only the canonical-encoding rule can reject it.
    manifest = load_manifest(minimal_shard)
    pretty = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False).encode()
    assert pretty != canonical_json_bytes(manifest)
    reseal_shard_bytes(minimal_shard, pretty, _CI_KEY)
    result = _verify(minimal_shard)
    assert result["status"] == "FAIL"
    assert error_codes(result) == [ErrorCode.E_MANIFEST_SCHEMA.value]


# ── Sources <-> content/ bijection (RFC 0002 D5) ─────────────────────────────

def test_unlisted_content_file_is_rejected(minimal_shard: Path) -> None:
    # Add a content file, keep the Merkle root honest, but do not list the
    # file in sources: only the bijection check can catch it.
    (minimal_shard / "content" / "smuggled.txt").write_text("hidden\n", encoding="utf-8")
    manifest = load_manifest(minimal_shard)
    manifest["integrity"]["merkle_root"] = compute_merkle_root(minimal_shard)
    reseal_shard(minimal_shard, manifest, _CI_KEY)
    result = _verify(minimal_shard)
    assert result["status"] == "FAIL"
    assert error_codes(result) == [ErrorCode.E_MANIFEST_SCHEMA.value]
    assert "not listed in sources" in result["errors"][0]["message"]


def test_source_listed_but_absent_is_rejected(minimal_shard: Path) -> None:
    manifest = load_manifest(minimal_shard)
    manifest["sources"].append({"path": "content/ghost.txt", "hash": "0" * 64})
    reseal_shard(minimal_shard, manifest, _CI_KEY)
    result = _verify(minimal_shard)
    assert result["status"] == "FAIL"
    assert ErrorCode.E_MANIFEST_SCHEMA.value in error_codes(result)
    assert any("no such file" in e["message"] for e in result["errors"])


def test_source_hash_mismatch_is_rejected(minimal_shard: Path) -> None:
    manifest = load_manifest(minimal_shard)
    good = manifest["sources"][0]["hash"]
    manifest["sources"][0]["hash"] = ("0" if good[0] != "0" else "1") + good[1:]
    reseal_shard(minimal_shard, manifest, _CI_KEY)
    result = _verify(minimal_shard)
    assert result["status"] == "FAIL"
    assert error_codes(result) == [ErrorCode.E_MANIFEST_SCHEMA.value]
    assert any("hash mismatch" in e["message"] for e in result["errors"])


# ── Valid edge cases must still pass ─────────────────────────────────────────

@pytest.mark.parametrize(
    "created_at",
    ["2026-12-31T23:59:60Z", "2026-07-02T00:00:00.123Z", "2028-02-29T12:00:00Z"],
    ids=["leap-second", "fractional-seconds", "leap-day"],
)
def test_valid_created_at_variants_pass(minimal_shard: Path, created_at: str) -> None:
    result = mutate_and_verify(
        minimal_shard, _CI_KEY, _set(created_at, "metadata", "created_at")
    )
    assert result["status"] == "PASS", result["errors"]


def test_valid_supersedes_passes(minimal_shard: Path) -> None:
    result = mutate_and_verify(
        minimal_shard, _CI_KEY, _set(["sh1_" + "ab" * 32], "supersedes")
    )
    assert result["status"] == "PASS", result["errors"]


# ── Derived shard identity (RFC 0002 D3) ─────────────────────────────────────

def test_shard_id_is_derived_from_manifest_bytes() -> None:
    manifest_bytes = (MINIMAL_SHARD / "manifest.json").read_bytes()
    sid = derive_shard_id(manifest_bytes)
    assert sid == "sh1_" + blake3.blake3(manifest_bytes).hexdigest()
    assert len(sid) == 4 + 64


def test_shard_id_commits_to_metadata_not_just_content() -> None:
    manifest = load_manifest(MINIMAL_SHARD)
    original = derive_shard_id(canonical_json_bytes(manifest))
    relicensed = dict(manifest, license={"spdx": "Apache-2.0"})
    assert derive_shard_id(canonical_json_bytes(relicensed)) != original


def test_no_manifest_in_repo_carries_a_shard_id_field() -> None:
    for shard in (MINIMAL_SHARD, GOLD_SHARD):
        manifest = load_manifest(shard)
        assert "shard_id" not in manifest, f"{shard} manifest stores its own identity"
