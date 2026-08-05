"""RFC 0009: AXM Aperture package extension registration and one-pass seal."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from axm_build.aperture_bundle import validate_aperture_bundle
from axm_build.aperture_ext_schemas import (
    APERTURE_EXTENSION_IDS,
    APERTURE_EXTENSION_REGISTRY,
    register_aperture_extensions,
)
from axm_build.aperture_rows import ApertureExtensionError
from axm_build.compiler_aperture import compile_aperture_shard
from axm_build.compiler_generic import CompilerConfig
from axm_build.ext_schemas import EXTENSION_REGISTRY
from axm_verify.logic import verify_shard
from helpers import requires_mldsa_backend

PACKAGE = "storypkg1_" + "1" * 64
MAP = "timemap1_" + "2" * 64
STORY_DIGEST = "3" * 64
SOURCE_DIGEST = "4" * 64


def _arr(*values: str) -> str:
    return json.dumps(list(values), ensure_ascii=False, separators=(",", ":"))


def _bundle() -> dict[str, list[dict]]:
    revision = {"package_id": PACKAGE, "revision": "1"}
    return {
        "aperture-package-revisions@1": [{
            **revision,
            "work_id": "work:fixture",
            "canonical_story_digest": STORY_DIGEST,
            "canonical_edition_id": "edition:canonical",
            "review_state": "reviewed",
            "supersedes": "",
            "edition_time_map_refs_json": _arr(MAP),
        }],
        "aperture-positions@1": [
            {
                **revision,
                "position_id": "position:entry",
                "canonical_start_us": "0",
                "canonical_end_us": "5000000",
                "kind": "scene",
                "parent_id": "",
                "label": "Entry",
            },
            {
                **revision,
                "position_id": "position:consequence",
                "canonical_start_us": "5000000",
                "canonical_end_us": "9000000",
                "kind": "scene",
                "parent_id": "",
                "label": "Consequence",
            },
        ],
        "aperture-facts@1": [
            {
                **revision,
                "fact_id": "fact:entry",
                "proposition": "The courier enters.",
                "first_reveal_position_id": "position:entry",
                "subject_ids_json": _arr("character:courier"),
                "provenance_refs_json": _arr("source:primary"),
            },
            {
                **revision,
                "fact_id": "fact:consequence",
                "proposition": "The map changes hands.",
                "first_reveal_position_id": "position:consequence",
                "subject_ids_json": _arr("character:courier"),
                "provenance_refs_json": _arr("source:primary"),
            },
        ],
        "aperture-causal-edges@1": [{
            **revision,
            "edge_id": "edge:entry-consequence",
            "cause_fact_ids_json": _arr("fact:entry"),
            "effect_fact_id": "fact:consequence",
            "strength": "necessary",
            "provenance_refs_json": _arr("source:primary"),
        }],
        "aperture-reveals@1": [
            {
                **revision,
                "reveal_id": "reveal:entry",
                "fact_id": "fact:entry",
                "position_id": "position:entry",
                "mode": "seen",
                "provenance_refs_json": _arr("source:primary"),
            },
            {
                **revision,
                "reveal_id": "reveal:consequence",
                "fact_id": "fact:consequence",
                "position_id": "position:consequence",
                "mode": "seen",
                "provenance_refs_json": _arr("source:primary"),
            },
        ],
        "aperture-edition-maps@1": [{
            "map_id": MAP,
            "work_id": "work:fixture",
            "provider_edition_id": "edition:provider",
            "canonical_edition_id": "edition:canonical",
            "segment_id": "segment:mapped",
            "kind": "mapped",
            "provider_start_us": "0",
            "provider_end_us": "9000000",
            "canonical_start_us": "0",
            "canonical_end_us": "9000000",
            "rate_numerator": "2",
            "rate_denominator": "2",
            "evidence_refs_json": _arr("evidence:alignment"),
            "source_digests_json": _arr(SOURCE_DIGEST),
            "confidence": "1.000",
            "review_state": "reviewed",
        }],
        "aperture-sources@1": [{
            **revision,
            "source_id": "source:primary",
            "sha256": SOURCE_DIGEST,
            "custody": "holder_controlled",
            "contains_redistributable_text": "false",
        }],
    }


def test_aperture_extensions_registered_idempotently():
    register_aperture_extensions()
    register_aperture_extensions()
    assert set(APERTURE_EXTENSION_IDS) <= set(EXTENSION_REGISTRY)
    for extension_id in APERTURE_EXTENSION_IDS:
        assert EXTENSION_REGISTRY[extension_id] == APERTURE_EXTENSION_REGISTRY[extension_id]
        assert EXTENSION_REGISTRY[extension_id]["file"] == extension_id + ".jsonl"
        assert EXTENSION_REGISTRY[extension_id]["unique"] is True


def test_bundle_normalizes_semantically_unordered_values():
    value = _bundle()
    value["aperture-facts@1"][0]["subject_ids_json"] = _arr("z", "a")
    value["aperture-edition-maps@1"][0]["rate_numerator"] = "2"
    value["aperture-edition-maps@1"][0]["rate_denominator"] = "2"
    value["aperture-edition-maps@1"][0]["confidence"] = "1.000"
    result = validate_aperture_bundle(value)
    assert result["aperture-facts@1"][0]["subject_ids_json"] == '["a","z"]'
    mapped = result["aperture-edition-maps@1"][0]
    assert (mapped["rate_numerator"], mapped["rate_denominator"]) == ("1", "1")
    assert mapped["confidence"] == "1"


@pytest.mark.parametrize("mutation,match", [
    (lambda b: b.pop("aperture-reveals@1"), "complete RFC 0009 bundle"),
    (lambda b: b["aperture-facts@1"][0].__setitem__("first_reveal_position_id", "position:missing"), "unknown first reveal position"),
    (lambda b: b["aperture-causal-edges@1"][0].__setitem__("effect_fact_id", "fact:entry"), "self-causal"),
    (lambda b: b["aperture-facts@1"][0].__setitem__("provenance_refs_json", _arr("source:missing")), "unknown package sources"),
    (lambda b: b["aperture-edition-maps@1"][0].__setitem__("canonical_start_us", ""), "incomplete canonical interval"),
    (lambda b: b["aperture-edition-maps@1"][0].update({"canonical_start_us": "", "canonical_end_us": ""}), "contradicts segment kind"),
    (lambda b: b["aperture-sources@1"][0].__setitem__("contains_redistributable_text", False), "JSON strings only"),
])
def test_bundle_refuses_domain_drift(mutation, match):
    value = _bundle()
    mutation(value)
    with pytest.raises(ApertureExtensionError, match=match):
        validate_aperture_bundle(value)


def _cfg(base: Path, secret_key: bytes) -> CompilerConfig:
    base.mkdir(parents=True, exist_ok=True)
    source = base / "source.txt"
    source.write_text(
        "Aperture package fixture\nThe courier enters and the map changes hands.\n",
        encoding="utf-8",
    )
    candidates = base / "candidates.jsonl"
    candidates.write_text(
        json.dumps({
            "subject": "package",
            "predicate": "contains",
            "object": "reviewed story evidence",
            "object_type": "literal:string",
            "tier": 1,
            "evidence": "The courier enters and the map changes hands.",
        }) + "\n",
        encoding="utf-8",
    )
    return CompilerConfig(
        source_path=source,
        candidates_path=candidates,
        out_dir=base / "shard",
        private_key=secret_key,
        publisher_id="@aperture_test",
        publisher_name="Aperture Test Publisher",
        namespace="test/aperture",
        created_at="2026-08-05T00:00:00Z",
        title="RFC 0009 Aperture Package",
        license_spdx="CC0-1.0",
    )


@requires_mldsa_backend
def test_aperture_package_compiles_once_and_verifies_out_of_band(
    tmp_path,
    ci_secret_key,
):
    from axm_build.sign import hybrid1_public_key

    cfg = _cfg(tmp_path / "first", ci_secret_key)
    assert compile_aperture_shard(cfg, _bundle())
    shard = cfg.out_dir
    manifest = json.loads((shard / "manifest.json").read_text(encoding="utf-8"))
    assert set(APERTURE_EXTENSION_IDS) <= set(manifest["extensions"])
    assert not list(shard.rglob("*.parquet"))
    for extension_id in APERTURE_EXTENSION_IDS:
        assert (shard / "ext" / f"{extension_id}.jsonl").is_file()

    trusted = tmp_path / "trusted-aperture-publisher.pub"
    trusted.write_bytes(hybrid1_public_key(ci_secret_key))
    assert not trusted.is_relative_to(shard)
    result = verify_shard(shard, trusted_key_path=trusted)
    assert result["status"] == "PASS", result["errors"]


@requires_mldsa_backend
def test_repeated_builds_have_identical_manifest_and_extension_bytes(
    tmp_path,
    ci_secret_key,
):
    first = _cfg(tmp_path / "first", ci_secret_key)
    second = _cfg(tmp_path / "second", ci_secret_key)
    first_bundle = _bundle()
    second_bundle = _bundle()
    second_bundle["aperture-facts@1"][0]["subject_ids_json"] = _arr("z", "a")
    first_bundle["aperture-facts@1"][0]["subject_ids_json"] = _arr("a", "z")

    assert compile_aperture_shard(first, first_bundle)
    assert compile_aperture_shard(second, second_bundle)
    assert (first.out_dir / "manifest.json").read_bytes() == (second.out_dir / "manifest.json").read_bytes()
    for extension_id in APERTURE_EXTENSION_IDS:
        left = first.out_dir / "ext" / f"{extension_id}.jsonl"
        right = second.out_dir / "ext" / f"{extension_id}.jsonl"
        assert left.read_bytes() == right.read_bytes()


def test_compiler_wrapper_refuses_competing_extra_ext(tmp_path):
    cfg = CompilerConfig(
        source_path=tmp_path / "source.txt",
        candidates_path=tmp_path / "candidates.jsonl",
        out_dir=tmp_path / "shard",
        private_key=b"x",
        publisher_id="@test",
        publisher_name="Test",
        namespace="test/aperture",
        created_at="2026-08-05T00:00:00Z",
        extra_ext={"episodes@1": []},
    )
    with pytest.raises(ValueError, match="extra_ext must be empty"):
        compile_aperture_shard(cfg, _bundle())
