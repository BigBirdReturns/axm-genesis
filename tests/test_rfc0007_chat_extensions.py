"""RFC 0007: chat extensions — episodes@1 and engineering@1.

Both are ordinary registered canonical-JSONL extension tables fed through the
one-pass compiler's extra_ext path — no reseal, no post-compile injection, no
Parquet. Canonical JSONL is scalar-only, so array-valued domain fields ride as
JSON-array strings and confidence rides as a decimal string; the kernel treats
all of it opaquely and chat parses it after verification. This is what lets
axm-chat stop reimplementing the Merkle/sign path in distill.py.
"""
from __future__ import annotations

import json
from pathlib import Path

from axm_build.compiler_generic import CompilerConfig, compile_generic_shard
from axm_build.ext_schemas import EXTENSION_REGISTRY
from axm_build.jsonl import read_table
from axm_verify.logic import verify_shard
from helpers import requires_mldsa_backend

pytestmark = requires_mldsa_backend

SOURCE_ID = "sh1_" + "cd" * 32  # a foreign source-conversation shard id

DOC_TEXT = (
    "Episodic distillation log\n"
    "episode ep-0001 resolved the leaking-tap repair\n"
    "episode ep-0002 chose a grid inverter after two failed attempts\n"
)


def _arr(*items: str) -> str:
    """A domain array field: a compact canonical JSON array carried in a string."""
    return json.dumps(list(items), separators=(",", ":"), ensure_ascii=False)


def _cfg(base: Path, ci_secret_key: bytes, **overrides) -> CompilerConfig:
    source = base / "source.txt"
    source.write_text(DOC_TEXT, encoding="utf-8")
    candidates = base / "candidates.jsonl"
    candidates.write_text(
        json.dumps({
            "subject": "session", "predicate": "distilled", "object": "ep-0001",
            "object_type": "entity", "tier": 1,
            "evidence": "episode ep-0001 resolved the leaking-tap repair",
        }) + "\n", encoding="utf-8")
    defaults = dict(
        source_path=source, candidates_path=candidates, out_dir=base / "shard",
        private_key=ci_secret_key, publisher_id="@ci_test",
        publisher_name="CI Test Publisher", namespace="test/chat",
        created_at="2026-07-03T00:00:00Z", title="RFC 0007 chat extensions test",
        license_spdx="CC0-1.0",
    )
    defaults.update(overrides)
    return CompilerConfig(**defaults)


def _episode_rows() -> list[dict]:
    return [
        {
            "episode_id": "ep-0001", "shard_id": SOURCE_ID, "batch_index": 0,
            "timestamp": "2026-07-03T00:00:00Z",
            "topic_tags": _arr("home", "plumbing"), "people": _arr("alex"),
            "animals": _arr(), "tools_places_services": _arr("wrench"),
            "projects": _arr("bathroom"), "question_text": "why does the tap drip?",
            "state": "resolved", "tone": "relieved",
            "summary": "Fixed a leaking tap by replacing the washer.",
            "lens_hints": _arr("engineering"),
        },
        {
            "episode_id": "ep-0002", "shard_id": SOURCE_ID, "batch_index": 0,
            "timestamp": "2026-07-03T00:05:00Z",
            "topic_tags": _arr("energy"), "people": _arr(), "animals": _arr(),
            "tools_places_services": _arr("inverter"), "projects": _arr("solar"),
            "question_text": "",  # no question — "" not null
            "state": "resolved", "tone": "neutral",
            "summary": "Selected a grid-tie inverter after two rejected options.",
            "lens_hints": _arr("engineering", "reflect"),
        },
    ]


def _engineering_rows() -> list[dict]:
    return [
        {
            "episode_id": "ep-0002", "shard_id": SOURCE_ID,
            "problem_statement": "Pick an inverter for a grid-tie solar array.",
            "core_technologies": _arr("grid-tie-inverter", "MPPT"),
            "failed_attempts": _arr("off-grid unit (no export)", "microinverters (cost)"),
            "solution_adopted": "Single string grid-tie inverter, 5 kW.",
            "architectural_rule": "Match inverter export mode to the interconnect agreement.",
            "confidence": "0.82",  # decimal string, not a float
        },
    ]


def test_chat_extensions_registered():
    for ext_id in ("episodes@1", "engineering@1"):
        reg = EXTENSION_REGISTRY[ext_id]
        assert reg["file"] == ext_id + ".jsonl"
        assert reg["sort_key"] == "episode_id"
        assert reg["unique"] is True


def test_chat_shard_compiles_and_verifies(tmp_path, ci_secret_key):
    cfg = _cfg(tmp_path, ci_secret_key,
               extra_ext={"episodes@1": _episode_rows(),
                          "engineering@1": _engineering_rows()})
    assert compile_generic_shard(cfg)

    shard = cfg.out_dir
    manifest = json.loads((shard / "manifest.json").read_bytes())
    assert {"episodes@1", "engineering@1"} <= set(manifest["extensions"])
    # No Parquet, no reseal: the ext tables are canonical JSONL Merkle leaves.
    assert (shard / "ext" / "episodes@1.jsonl").exists()
    assert not any(p.suffix == ".parquet" for p in shard.rglob("*"))

    result = verify_shard(shard, trusted_key_path=shard / "sig" / "publisher.pub")
    assert result["status"] == "PASS", result["errors"]


def test_chat_tables_roundtrip_and_encodings(tmp_path, ci_secret_key):
    cfg = _cfg(tmp_path, ci_secret_key,
               extra_ext={"episodes@1": _episode_rows(),
                          "engineering@1": _engineering_rows()})
    assert compile_generic_shard(cfg)

    ep = read_table(cfg.out_dir / "ext" / "episodes@1.jsonl",
                    EXTENSION_REGISTRY["episodes@1"]["schema"],
                    EXTENSION_REGISTRY["episodes@1"]["sort_key"])
    by_id = {r["episode_id"]: r for r in ep}
    # Array fields round-trip as parseable JSON arrays; empty is [].
    assert json.loads(by_id["ep-0001"]["topic_tags"]) == ["home", "plumbing"]
    assert json.loads(by_id["ep-0001"]["animals"]) == []
    # A missing question is "" (no nulls in canonical JSONL).
    assert by_id["ep-0002"]["question_text"] == ""
    # shard_id is a foreign source reference, never the containing shard's id.
    assert by_id["ep-0001"]["shard_id"] == SOURCE_ID

    eng = read_table(cfg.out_dir / "ext" / "engineering@1.jsonl",
                     EXTENSION_REGISTRY["engineering@1"]["schema"],
                     EXTENSION_REGISTRY["engineering@1"]["sort_key"])
    (row,) = eng
    assert row["episode_id"] == "ep-0002"                      # FK into episodes@1
    assert 0.0 <= float(row["confidence"]) <= 1.0             # decimal string in [0,1]
    assert json.loads(row["core_technologies"]) == ["grid-tie-inverter", "MPPT"]
