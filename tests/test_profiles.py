"""Profiles (spec section 15, RFC 0002 D6).

The kernel knows no application domain. A profile is a named, versioned
check-set; the manifest's optional "profiles" array is signed; a verifier
runs the listed profiles it implements and reports everything else as
UNCHECKED — silence must never impersonate verification.

embodied@1 (the former REQ 5 hot-stream continuity check) is the first
profile; its unit tests run against synthetic AXLF streams.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterable, List, Optional


import axm_verify.logic as logic
from axm_verify.profiles import IMPLEMENTED_PROFILES, embodied_v1
from helpers import (
    CI_KEY_PATH,
    CI_PUB_PATH,
    EMBODIED_GAP_SHARD,
    EMBODIED_SHARD,
    error_codes,
    mutate_and_verify,
    requires_mldsa_backend,
)

_CI_KEY = CI_KEY_PATH.read_bytes()


def _verify(shard: Path) -> dict:
    return logic.verify_shard(shard, trusted_key_path=CI_PUB_PATH)


# ── Registry ─────────────────────────────────────────────────────────────────

def test_embodied_profile_is_registered() -> None:
    assert IMPLEMENTED_PROFILES.get("embodied@1") is embodied_v1.check
    assert embodied_v1.PROFILE_ID == "embodied@1"


def test_buffer_discontinuity_is_a_profile_code_not_a_kernel_code() -> None:
    from axm_verify.const import ErrorCode

    assert embodied_v1.E_BUFFER_DISCONTINUITY == "E_BUFFER_DISCONTINUITY"
    assert "E_BUFFER_DISCONTINUITY" not in {e.value for e in ErrorCode}


# ── Verifier-level behavior (vectors + resealed mutations) ───────────────────

@requires_mldsa_backend
def test_listed_and_implemented_profile_is_checked() -> None:
    result = _verify(EMBODIED_SHARD)
    assert result["status"] == "PASS", result["errors"]
    assert result["profiles_checked"] == ["embodied@1"]
    assert result["profiles_unchecked"] == []


@requires_mldsa_backend
def test_profile_violation_fails_the_shard() -> None:
    result = _verify(EMBODIED_GAP_SHARD)
    assert result["status"] == "FAIL"
    assert error_codes(result) == ["E_BUFFER_DISCONTINUITY"]
    assert result["profiles_checked"] == ["embodied@1"]
    assert result["profiles_unchecked"] == []


@requires_mldsa_backend
def test_unlisted_profile_is_not_run(embodied_gap_shard: Path) -> None:
    """A gapped stream in a shard that does NOT claim embodied@1 passes:
    profile checks bind only through the signed manifest listing."""
    def drop_profiles(manifest: dict) -> None:
        del manifest["profiles"]

    result = mutate_and_verify(embodied_gap_shard, _CI_KEY, drop_profiles)
    assert result["status"] == "PASS", result["errors"]
    assert result["profiles_checked"] == []
    assert result["profiles_unchecked"] == []


@requires_mldsa_backend
def test_unimplemented_profile_is_reported_unchecked(embodied_shard: Path) -> None:
    def add_unknown_profile(manifest: dict) -> None:
        manifest["profiles"] = ["embodied@1", "translated-captions@3"]

    result = mutate_and_verify(embodied_shard, _CI_KEY, add_unknown_profile)
    assert result["status"] == "PASS", result["errors"]
    assert result["profiles_checked"] == ["embodied@1"]
    assert result["profiles_unchecked"] == ["translated-captions@3"]


@requires_mldsa_backend
def test_unchecked_is_not_passed(monkeypatch) -> None:
    """A verifier WITHOUT embodied@1 must report it unchecked — even though
    the stream has a gap it could not see. The result object keeps the
    distinction visible so a caller can refuse to treat it as verified."""
    monkeypatch.setattr(logic, "IMPLEMENTED_PROFILES", {})
    result = _verify(EMBODIED_GAP_SHARD)
    # Kernel checks pass; the profile violation is invisible to this verifier.
    assert result["status"] == "PASS"
    assert result["profiles_checked"] == []
    assert result["profiles_unchecked"] == ["embodied@1"]


@requires_mldsa_backend
def test_result_always_carries_profile_report_keys(minimal_shard: Path) -> None:
    result = _verify(minimal_shard)
    assert result["profiles_checked"] == []
    assert result["profiles_unchecked"] == []


# ── embodied@1 unit tests against synthetic AXLF streams ─────────────────────

def _stream(frame_ids: Iterable[int], payload_len: int = 16,
            file_magic: bytes = b"AXLF", version: int = 1) -> bytes:
    out = bytearray(file_magic)
    for fid in frame_ids:
        payload = bytes((fid + i) % 256 for i in range(payload_len))
        out += struct.pack("<4sBII", b"AXLR", version, fid, payload_len)
        out += payload
    return bytes(out)


def _run_check(tmp_path: Path, stream: Optional[bytes]) -> List[dict]:
    shard = tmp_path / "shard"
    (shard / "content").mkdir(parents=True)
    if stream is not None:
        (shard / "content" / "cam_latents.bin").write_bytes(stream)
    errors: List[dict] = []
    embodied_v1.check(shard, errors)
    return errors


def test_continuous_stream_passes(tmp_path: Path) -> None:
    assert _run_check(tmp_path, _stream(range(10))) == []


def test_missing_stream_is_a_vacuous_pass(tmp_path: Path) -> None:
    assert _run_check(tmp_path, None) == []


def test_frame_gap_is_a_discontinuity(tmp_path: Path) -> None:
    errors = _run_check(tmp_path, _stream([0, 1, 3, 4]))
    assert [e["code"] for e in errors] == ["E_BUFFER_DISCONTINUITY"]
    assert "expected frame 2" in errors[0]["message"]


def test_stream_must_start_at_frame_zero(tmp_path: Path) -> None:
    errors = _run_check(tmp_path, _stream([1, 2, 3]))
    assert [e["code"] for e in errors] == ["E_BUFFER_DISCONTINUITY"]
    assert "expected frame 0" in errors[0]["message"]


def test_bad_file_magic_is_rejected(tmp_path: Path) -> None:
    errors = _run_check(tmp_path, _stream(range(3), file_magic=b"NOPE"))
    assert [e["code"] for e in errors] == ["E_BUFFER_DISCONTINUITY"]


def test_empty_file_is_rejected(tmp_path: Path) -> None:
    errors = _run_check(tmp_path, b"")
    assert [e["code"] for e in errors] == ["E_BUFFER_DISCONTINUITY"]


def test_wrong_record_version_is_rejected(tmp_path: Path) -> None:
    errors = _run_check(tmp_path, _stream(range(3), version=2))
    assert [e["code"] for e in errors] == ["E_BUFFER_DISCONTINUITY"]


def test_truncated_header_is_rejected(tmp_path: Path) -> None:
    stream = _stream(range(2)) + b"AXLR\x01"  # header cut short
    errors = _run_check(tmp_path, stream)
    assert [e["code"] for e in errors] == ["E_BUFFER_DISCONTINUITY"]
    assert "truncated header" in errors[0]["message"]


def test_truncated_payload_is_rejected(tmp_path: Path) -> None:
    full = _stream(range(3))
    errors = _run_check(tmp_path, full[:-4])  # last payload cut short
    assert [e["code"] for e in errors] == ["E_BUFFER_DISCONTINUITY"]
    assert "truncated payload" in errors[0]["message"]
