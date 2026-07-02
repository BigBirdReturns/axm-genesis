"""Compiler support for embodied spokes: extra content files + spoke ext tables.

`compile_generic_shard` accepts `extra_content` (files copied into
content/, listed in the manifest sources bijection, sealed as Merkle
leaves) and `extra_ext` (registered extension tables the spoke computed,
e.g. streams@1). These are additive compiler features: nothing frozen in
the spec changes, and a config that uses neither compiles byte-identically
to before.

The embodied@1 profile is the consumer: a shard carrying a gap-free
content/cam_latents.bin and declaring "embodied@1" must PASS with the
profile checked; a frame gap must FAIL with E_BUFFER_DISCONTINUITY.
"""
from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from axm_build.compiler_generic import CompilerConfig, compile_generic_shard
from axm_build.ext_schemas import EXTENSION_REGISTRY
from axm_verify.logic import verify_shard
from helpers import requires_mldsa_backend

pytestmark = requires_mldsa_backend

DOC_TEXT = (
    "Embodied run log\n"
    "frame 0 selected_action maintain_speed\n"
    "frame 1 selected_action emergency_stop\n"
)

_REC_HEADER_FMT = "<4sBII"


def _latents_bytes(frame_ids: list[int], dim: int = 256) -> bytes:
    out = bytearray(b"AXLF")
    for fid in frame_ids:
        payload = bytes((fid + i) % 256 for i in range(dim))
        out += struct.pack(_REC_HEADER_FMT, b"AXLR", 1, fid, dim) + payload
    return bytes(out)


def _write_inputs(base: Path) -> tuple[Path, Path]:
    source = base / "source.txt"
    source.write_text(DOC_TEXT, encoding="utf-8")
    candidates = base / "candidates.jsonl"
    rows = [
        {
            "subject": "robot-001",
            "predicate": "selected_action",
            "object": "maintain_speed",
            "object_type": "entity",
            "tier": 1,
            "evidence": "frame 0 selected_action maintain_speed",
        },
        {
            "subject": "robot-001",
            "predicate": "selected_action",
            "object": "emergency_stop",
            "object_type": "entity",
            "tier": 1,
            "evidence": "frame 1 selected_action emergency_stop",
        },
    ]
    candidates.write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8"
    )
    return source, candidates


def _streams_rows() -> list[dict]:
    return [
        {
            "frame_id": fid,
            "stream": "latents",
            "file": "cam_latents.bin",
            "offset": 4 + fid * 269,
            "length": 269,
            "status": "VERIFIED",
            "content_hash": "0" * 64,
        }
        for fid in (0, 1)
    ]


def _cfg(base: Path, ci_secret_key: bytes, **overrides) -> CompilerConfig:
    source, candidates = _write_inputs(base)
    defaults = dict(
        source_path=source,
        candidates_path=candidates,
        out_dir=base / "shard",
        private_key=ci_secret_key,
        publisher_id="@ci_test",
        publisher_name="CI Test Publisher",
        namespace="test/embodied",
        created_at="2026-07-02T00:00:00Z",
        title="Embodied Extra Content Test",
        license_spdx="CC0-1.0",
    )
    defaults.update(overrides)
    return CompilerConfig(**defaults)


def test_extra_content_and_streams_ext_pass(tmp_path, ci_secret_key):
    lat = tmp_path / "cam_latents.bin"
    lat.write_bytes(_latents_bytes([0, 1]))

    cfg = _cfg(
        tmp_path,
        ci_secret_key,
        profiles=("embodied@1",),
        extra_content=(("cam_latents.bin", lat),),
        extra_ext={"streams@1": _streams_rows()},
    )
    assert compile_generic_shard(cfg)

    shard = cfg.out_dir
    manifest = json.loads((shard / "manifest.json").read_bytes())

    # Sources bijection covers both files, sorted by path.
    assert manifest["sources"] == sorted(
        manifest["sources"], key=lambda s: s["path"]
    )
    assert {s["path"] for s in manifest["sources"]} == {
        "content/source.txt",
        "content/cam_latents.bin",
    }
    assert "streams@1" in manifest["extensions"]
    assert manifest["profiles"] == ["embodied@1"]
    assert (shard / "ext" / "streams@1.jsonl").exists()

    result = verify_shard(shard, trusted_key_path=shard / "sig" / "publisher.pub")
    assert result["status"] == "PASS", result["errors"]
    assert "embodied@1" in result["profiles_checked"]


def test_streams_rows_sort_by_composite_key(tmp_path, ci_secret_key):
    lat = tmp_path / "cam_latents.bin"
    lat.write_bytes(_latents_bytes([0, 1]))

    rows = list(reversed(_streams_rows()))  # deliberately out of order
    cfg = _cfg(
        tmp_path,
        ci_secret_key,
        extra_content=(("cam_latents.bin", lat),),
        extra_ext={"streams@1": rows},
    )
    assert compile_generic_shard(cfg)

    lines = (cfg.out_dir / "ext" / "streams@1.jsonl").read_bytes().splitlines()
    frame_ids = [json.loads(line)["frame_id"] for line in lines]
    assert frame_ids == sorted(frame_ids)


def test_frame_gap_fails_embodied_profile(tmp_path, ci_secret_key):
    lat = tmp_path / "cam_latents.bin"
    lat.write_bytes(_latents_bytes([0, 2]))  # gap: frame 1 missing

    cfg = _cfg(
        tmp_path,
        ci_secret_key,
        profiles=("embodied@1",),
        extra_content=(("cam_latents.bin", lat),),
    )
    # The compiler self-verifies and the profile check fails on the gap.
    assert compile_generic_shard(cfg) is False

    result = verify_shard(
        cfg.out_dir, trusted_key_path=cfg.out_dir / "sig" / "publisher.pub"
    )
    assert result["status"] == "FAIL"
    assert any(e["code"] == "E_BUFFER_DISCONTINUITY" for e in result["errors"])


def test_unlisted_content_file_fails_bijection(tmp_path, ci_secret_key):
    """A content file smuggled in after compilation must fail verification."""
    lat = tmp_path / "cam_latents.bin"
    lat.write_bytes(_latents_bytes([0, 1]))

    cfg = _cfg(tmp_path, ci_secret_key, extra_content=(("cam_latents.bin", lat),))
    assert compile_generic_shard(cfg)

    (cfg.out_dir / "content" / "smuggled.bin").write_bytes(b"tamper")
    result = verify_shard(
        cfg.out_dir, trusted_key_path=cfg.out_dir / "sig" / "publisher.pub"
    )
    assert result["status"] == "FAIL"


def test_extra_content_rejects_unsafe_names(tmp_path, ci_secret_key):
    lat = tmp_path / "cam_latents.bin"
    lat.write_bytes(_latents_bytes([0]))

    for bad in ("source.txt", "../escape.bin", ".hidden", "a//b", ""):
        cfg = _cfg(tmp_path, ci_secret_key, extra_content=((bad, lat),))
        with pytest.raises(ValueError):
            compile_generic_shard(cfg)


def test_extra_ext_rejects_kernel_and_unknown_ids(tmp_path, ci_secret_key):
    cfg = _cfg(tmp_path, ci_secret_key, extra_ext={"lineage@1": []})
    with pytest.raises(ValueError, match="kernel compiler"):
        compile_generic_shard(cfg)

    cfg = _cfg(tmp_path, ci_secret_key, extra_ext={"nonsense@1": []})
    with pytest.raises(ValueError, match="unknown extension id"):
        compile_generic_shard(cfg)


def test_registry_entries_all_declare_uniqueness():
    for ext_id, reg in EXTENSION_REGISTRY.items():
        assert isinstance(reg["unique"], bool), ext_id
        assert reg["file"] == ext_id + ".jsonl"


def test_attestation_shard_roundtrip(tmp_path, ci_secret_key):
    """RFC 0005: an attestation shard is an ordinary v1 shard — proof bytes
    in content/, one attestations@1 row, a references@1 citation."""
    target_id = "sh1_" + "ab" * 32
    proof = tmp_path / "manifest.tsr"
    proof.write_bytes(b"\x30\x03fake-proof")
    manifest_copy = tmp_path / "target-manifest.json"
    manifest_copy.write_bytes(b'{"fake":"manifest"}')

    source = tmp_path / "source.txt"
    source.write_text(
        "ATTESTATION RECORD\n"
        f"target: {target_id}\n"
        "kind: rfc3161 authority: https://tsa.example gen_time: 2026-07-02T22:56:49Z\n",
        encoding="utf-8",
    )
    candidates = tmp_path / "candidates.jsonl"
    candidates.write_text(json.dumps({
        "subject": f"anchor/{target_id}",
        "predicate": "target_shard_id",
        "object": target_id,
        "object_type": "literal:string",
        "tier": 1,
        "evidence": f"target: {target_id}",
        "references": [{
            "dst_shard_id": target_id,
            "relation_type": "cites",
            "dst_object_type": "shard",
        }],
    }) + "\n", encoding="utf-8")

    cfg = CompilerConfig(
        source_path=source,
        candidates_path=candidates,
        out_dir=tmp_path / "shard",
        private_key=ci_secret_key,
        publisher_id="@ci_test",
        publisher_name="CI Test Publisher",
        namespace="test/attestation",
        created_at="2026-07-02T00:00:00Z",
        extra_content=(
            ("target-manifest.json", manifest_copy),
            ("manifest.tsr", proof),
        ),
        extra_ext={"attestations@1": [{
            "target_shard_id": target_id,
            "kind": "rfc3161",
            "authority": "https://tsa.example",
            "digest_sha256": "0" * 64,
            "anchored_at": "2026-07-02T22:56:49Z",
            "proof_path": "content/manifest.tsr",
        }]},
    )
    assert compile_generic_shard(cfg)

    shard = cfg.out_dir
    manifest = json.loads((shard / "manifest.json").read_bytes())
    assert set(manifest["extensions"]) == {"attestations@1", "references@1"}
    assert (shard / "ext" / "attestations@1.jsonl").stat().st_size > 0

    result = verify_shard(shard, trusted_key_path=shard / "sig" / "publisher.pub")
    assert result["status"] == "PASS", result["errors"]
