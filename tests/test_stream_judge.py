from __future__ import annotations

import json
import struct
from pathlib import Path

import pyarrow.parquet as pq
from click.testing import CliRunner

from axm_judge.cli import main as axm_judge_main


HEADER_STRUCT = "<4sBII"
HEADER_LEN = struct.calcsize(HEADER_STRUCT)

MAGIC_LAT = b"LATN"
MAGIC_RESID = b"RSID"
VERSION = 1

LATENT_PAYLOAD_LEN = 256
LATENT_REC_LEN = HEADER_LEN + LATENT_PAYLOAD_LEN  # 269


def _latent_payload(fid: int) -> bytes:
    b = bytes([fid % 256])
    return b * LATENT_PAYLOAD_LEN


def _write_latents(path: Path, n_frames: int) -> None:
    with open(path, "wb") as f:
        for fid in range(n_frames):
            payload = _latent_payload(fid)
            header = struct.pack(HEADER_STRUCT, MAGIC_LAT, VERSION, fid, len(payload))
            f.write(header + payload)


def _write_events(path: Path, n_frames: int, *, offset_override: dict[int, int] | None = None) -> None:
    offset_override = offset_override or {}
    with open(path, "wb") as f:
        for fid in range(n_frames):
            off = offset_override.get(fid, fid * LATENT_REC_LEN)
            evt = {
                "frame_id": fid,
                "stream_refs": {
                    "latents": {"file": "cam_latents.bin", "offset": off, "length": LATENT_REC_LEN}
                },
            }
            f.write((json.dumps(evt) + "\n").encode("utf-8"))


def _write_residuals(path: Path, frame_ids: list[int], *, payload_len: int = 64) -> None:
    with open(path, "wb") as f:
        for fid in frame_ids:
            payload = (bytes([0xAB]) + bytes([fid % 256])) * (payload_len // 2)
            payload = payload[:payload_len]
            header = struct.pack(HEADER_STRUCT, MAGIC_RESID, VERSION, fid, len(payload))
            f.write(header + payload)


def _truncate_file(path: Path, n_bytes: int) -> None:
    data = path.read_bytes()
    assert n_bytes < len(data)
    path.write_bytes(data[:-n_bytes])


def _run_judge(capsule: Path) -> tuple[int, str]:
    runner = CliRunner()
    result = runner.invoke(axm_judge_main, [str(capsule)])
    return result.exit_code, result.output


def _read_streams_parquet(capsule: Path):
    p = capsule / "evidence" / "streams.parquet"
    assert p.exists()
    return pq.read_table(p).to_pylist()


def test_safe_run_writes_latents_only(tmp_path: Path) -> None:
    capsule = tmp_path / "capsule"
    capsule.mkdir()

    _write_latents(capsule / "cam_latents.bin", n_frames=10)
    _write_events(capsule / "events.jsonl", n_frames=10)

    exit_code, _ = _run_judge(capsule)
    assert exit_code == 0

    rows = _read_streams_parquet(capsule)
    assert len(rows) == 10
    assert all(r["stream"] == "latents" for r in rows)


def test_crash_run_discovers_residuals_without_json_offsets(tmp_path: Path) -> None:
    capsule = tmp_path / "capsule"
    capsule.mkdir()

    _write_latents(capsule / "cam_latents.bin", n_frames=20)
    _write_events(capsule / "events.jsonl", n_frames=20)

    residual_fids = list(range(5, 11))
    _write_residuals(capsule / "cam_residuals.bin", residual_fids)

    exit_code, _ = _run_judge(capsule)
    assert exit_code == 0

    rows = _read_streams_parquet(capsule)
    lat = [r for r in rows if r["stream"] == "latents"]
    res = [r for r in rows if r["stream"] == "residuals"]

    assert len(lat) == 20
    assert len(res) == len(residual_fids)
    assert sorted(r["frame_id"] for r in res) == residual_fids


def test_torn_write_stops_scan_cleanly_and_keeps_prior_records(tmp_path: Path) -> None:
    capsule = tmp_path / "capsule"
    capsule.mkdir()

    _write_latents(capsule / "cam_latents.bin", n_frames=30)
    _write_events(capsule / "events.jsonl", n_frames=30)

    residual_fids = list(range(10, 16))
    res_path = capsule / "cam_residuals.bin"
    _write_residuals(res_path, residual_fids, payload_len=80)

    _truncate_file(res_path, n_bytes=7)

    exit_code, _ = _run_judge(capsule)
    assert exit_code == 0

    rows = _read_streams_parquet(capsule)
    res = [r for r in rows if r["stream"] == "residuals"]

    assert len(res) >= (len(residual_fids) - 1)
    assert all(r["status"] == "VERIFIED" for r in res)


def test_offset_drift_causes_hard_fail(tmp_path: Path) -> None:
    capsule = tmp_path / "capsule"
    capsule.mkdir()

    _write_latents(capsule / "cam_latents.bin", n_frames=12)
    _write_events(capsule / "events.jsonl", n_frames=12, offset_override={7: (7 * LATENT_REC_LEN) + 1})

    exit_code, _ = _run_judge(capsule)
    assert exit_code != 0

    assert not (capsule / "evidence" / "streams.parquet").exists()
