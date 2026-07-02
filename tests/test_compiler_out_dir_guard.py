"""Compiler out_dir wipe guard (data-loss footgun).

`compile_generic_shard` recreates its output directory from scratch. The
guard makes the preceding `rmtree` legal only when out_dir is (a) empty or
(b) a single previously-compiled shard (manifest.json at its root, no
nested manifest.json). Pointing out_dir at a directory holding OTHER
shards — e.g. a shard-pool root — must raise before any byte is deleted.
This is a compiler safety precondition, not a format change.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from axm_build.compiler_generic import CompilerConfig, compile_generic_shard
from helpers import requires_mldsa_backend

DOC_TEXT = (
    "Field Manual Excerpt\n"
    "A tourniquet stops severe bleeding when direct pressure fails.\n"
)
_EVIDENCE = "A tourniquet stops severe bleeding when direct pressure fails."


def _cfg(base: Path, out_dir: Path, ci_secret_key: bytes) -> CompilerConfig:
    """A minimal valid CompilerConfig writing inputs under `base`."""
    source = base / "source.txt"
    source.write_text(DOC_TEXT, encoding="utf-8")
    candidates = base / "candidates.jsonl"
    row = {
        "subject": "tourniquet",
        "predicate": "treats",
        "object": "severe bleeding",
        "object_type": "entity",
        "tier": 3,
        "evidence": _EVIDENCE,
    }
    candidates.write_text(json.dumps(row) + "\n", encoding="utf-8")
    return CompilerConfig(
        source_path=source,
        candidates_path=candidates,
        out_dir=out_dir,
        private_key=ci_secret_key,
        publisher_id="@ci_test",
        publisher_name="CI Test Publisher",
        namespace="test/guard",
        created_at="2026-07-02T00:00:00Z",
        title="Guard Test Shard",
        license_spdx="CC0-1.0",
    )


def _snapshot(root: Path) -> dict:
    """Every file under `root` as {relative posix path: bytes}."""
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def _fake_shard(dst: Path) -> None:
    """A stand-in for a previously compiled shard: manifest.json at root
    plus content — enough for the guard, no signing needed."""
    (dst / "content").mkdir(parents=True)
    (dst / "manifest.json").write_bytes(b'{"spec_version":"1.0.0"}')
    (dst / "content" / "source.txt").write_bytes(b"irreplaceable bytes\n")


# ── Legal wipes: semantics unchanged ─────────────────────────────────────────

@requires_mldsa_backend
def test_fresh_out_dir_compiles(tmp_path: Path, ci_secret_key: bytes) -> None:
    out = tmp_path / "shard"  # does not exist yet
    assert compile_generic_shard(_cfg(tmp_path, out, ci_secret_key)) is True
    assert (out / "manifest.json").is_file()


@requires_mldsa_backend
def test_empty_out_dir_compiles(tmp_path: Path, ci_secret_key: bytes) -> None:
    out = tmp_path / "shard"
    out.mkdir()
    assert compile_generic_shard(_cfg(tmp_path, out, ci_secret_key)) is True
    assert (out / "manifest.json").is_file()


@requires_mldsa_backend
def test_recompile_over_own_output(tmp_path: Path, ci_secret_key: bytes) -> None:
    """Recompiling into a directory holding exactly one prior shard still works."""
    out = tmp_path / "shard"
    cfg = _cfg(tmp_path, out, ci_secret_key)
    assert compile_generic_shard(cfg) is True
    first = _snapshot(out)
    assert compile_generic_shard(cfg) is True
    assert _snapshot(out).keys() == first.keys()
    assert (out / "manifest.json").is_file()


# ── Illegal wipes: raise, delete nothing ─────────────────────────────────────

def test_out_dir_holding_two_shards_raises_and_deletes_nothing(
    tmp_path: Path, ci_secret_key: bytes
) -> None:
    """The shard-pool footgun: out_dir pointed at a root containing OTHER
    shards must raise, and both shards must survive byte-identical."""
    pool = tmp_path / "pool"
    _fake_shard(pool / "shard-a")
    _fake_shard(pool / "shard-b")
    before = _snapshot(pool)
    assert before, "pool setup produced no files"

    with pytest.raises(ValueError, match="Refusing to delete"):
        compile_generic_shard(_cfg(tmp_path, pool, ci_secret_key))

    after = _snapshot(pool)
    assert after == before  # nothing deleted, nothing altered — byte-identical
    assert (pool / "shard-a" / "manifest.json").is_file()
    assert (pool / "shard-b" / "manifest.json").is_file()


def test_out_dir_with_non_shard_content_raises(
    tmp_path: Path, ci_secret_key: bytes
) -> None:
    out = tmp_path / "workdir"
    (out / "sub").mkdir(parents=True)
    (out / "notes.txt").write_bytes(b"do not lose me\n")
    (out / "sub" / "data.bin").write_bytes(b"\x00\x01\x02")
    before = _snapshot(out)

    with pytest.raises(ValueError, match="Refusing to delete"):
        compile_generic_shard(_cfg(tmp_path, out, ci_secret_key))

    assert _snapshot(out) == before


def test_out_dir_with_root_manifest_but_nested_shard_raises(
    tmp_path: Path, ci_secret_key: bytes
) -> None:
    """manifest.json at the root does not license the wipe if a nested
    directory carries its own manifest.json (a shard inside a shard-pool)."""
    out = tmp_path / "poolish"
    _fake_shard(out)
    _fake_shard(out / "nested-shard")
    before = _snapshot(out)

    with pytest.raises(ValueError, match="nested shard"):
        compile_generic_shard(_cfg(tmp_path, out, ci_secret_key))

    assert _snapshot(out) == before
