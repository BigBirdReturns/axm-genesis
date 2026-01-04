"""AXM Phase 2 Stream Judge (Pattern 2: Disk is the Truth).

Inputs (capsule dir):
- events.jsonl
- cam_latents.bin
- cam_residuals.bin (optional)

Output:
- evidence/streams.parquet

Core invariants:
- Judge scans cam_residuals.bin to discover residual records.
- Judge verifies cam_latents.bin using strict offset math and header checks.
- Judge hashes header + payload.
- Judge stops scanning residuals cleanly on torn write at EOF.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import click
import pyarrow as pa
import pyarrow.parquet as pq

HEADER_STRUCT = "<4sBII"  # Magic(4) | Ver(1) | FrameID(4) | Length(4)
HEADER_LEN = struct.calcsize(HEADER_STRUCT)

MAGIC_LAT = b"LATN"
MAGIC_RESID = b"RSID"
VERSION = 1

# v1 harness: fixed-size latent records (13 header + 256 payload)
LATENT_REC_LEN = 269

MAX_PAYLOAD_LEN = 32 * 1024 * 1024  # safety bound


class JudgeError(Exception):
    """Judge failure."""


STREAMS_SCHEMA = pa.schema(
    [
        ("frame_id", pa.int64()),
        ("stream", pa.string()),
        ("offset", pa.int64()),
        ("length", pa.int64()),
        ("content_hash", pa.string()),
        ("status", pa.string()),
    ]
)


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _write_parquet_deterministic(path: Path, rows: List[Dict[str, Any]]) -> None:
    """Write deterministically for byte-identical outputs."""
    rows_sorted = sorted(rows, key=lambda r: (r["stream"], int(r["frame_id"]), int(r["offset"])))
    table = pa.Table.from_pylist(rows_sorted, schema=STREAMS_SCHEMA)

    path.parent.mkdir(parents=True, exist_ok=True)
    writer = pq.ParquetWriter(
        where=str(path),
        schema=STREAMS_SCHEMA,
        compression="NONE",
        use_dictionary=False,
        write_statistics=False,
    )
    try:
        writer.write_table(table)
    finally:
        writer.close()


@dataclass
class ResidualRec:
    frame_id: int
    offset: int
    length: int
    content_hash: str
    status: str = "VERIFIED"

class JudgeError(Exception):
    pass


class StreamJudge:
    def __init__(self, capsule_path: Path):
        self.path = capsule_path
        self.residual_index: Dict[int, List[ResidualRec]] = {}

        self._scan_residuals()

        lat_path = capsule_path / "cam_latents.bin"
        if not lat_path.exists():
            raise JudgeError(f"Missing cam_latents.bin at {lat_path}")
        self.f_lat = open(lat_path, "rb")

    def close(self) -> None:
        try:
            self.f_lat.close()
        except Exception:
            pass

    def _scan_residuals(self) -> None:
        res_path = self.path / "cam_residuals.bin"
        if not res_path.exists():
            return

        with open(res_path, "rb") as f:
            while True:
                start_off = f.tell()
                header = f.read(HEADER_LEN)

                if len(header) == 0:
                    break
                if len(header) < HEADER_LEN:
                    break  # torn header at EOF

                try:
                    magic, ver, fid, dlen = struct.unpack(HEADER_STRUCT, header)
                except struct.error:
                    break

                if magic != MAGIC_RESID or ver != VERSION:
                    break
                if dlen > MAX_PAYLOAD_LEN:
                    break

                payload = f.read(dlen)
                if len(payload) < dlen:
                    break  # torn payload at EOF

                full_record = header + payload
                rec = ResidualRec(
                    frame_id=int(fid),
                    offset=int(start_off),
                    length=int(HEADER_LEN + dlen),
                    content_hash=_sha256_hex(full_record),
                )
                self.residual_index.setdefault(int(fid), []).append(rec)

    def verify_latent(self, claimed_offset: int, claimed_len: int, expected_fid: int) -> Tuple[str, Optional[str]]:
        math_offset = expected_fid * LATENT_REC_LEN
        if claimed_offset != math_offset:
            return f"OFFSET_DRIFT (Claimed {claimed_offset}, Math {math_offset})", None

        self.f_lat.seek(claimed_offset)
        header = self.f_lat.read(HEADER_LEN)
        if len(header) < HEADER_LEN:
            return "EOF", None

        magic, ver, fid, dlen = struct.unpack(HEADER_STRUCT, header)
        if magic != MAGIC_LAT or ver != VERSION:
            return "BAD_HEADER", None
        if int(fid) != int(expected_fid):
            return f"DRIFT (Found {fid}, Exp {expected_fid})", None

        expected_payload_len = claimed_len - HEADER_LEN
        if int(dlen) != int(expected_payload_len):
            return f"LENGTH_DRIFT (Hdr {dlen}, Claim {expected_payload_len})", None

        payload = self.f_lat.read(dlen)
        if len(payload) < dlen:
            return "EOF", None

        full_record = header + payload
        return "VERIFIED", _sha256_hex(full_record)

def _load_events(events_path: Path) -> List[Dict[str, Any]]:
    if not events_path.exists():
        raise JudgeError(f"Missing events.jsonl at {events_path}")

    events: List[Dict[str, Any]] = []
    with open(events_path, "rb") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            try:
                events.append(json.loads(raw.decode("utf-8")))
            except Exception as e:
                raise JudgeError(f"Bad JSONL line in {events_path}: {e}") from e
    return events


@click.command()
@click.argument("capsule", type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path))
@click.option("--out", "out_dir", type=click.Path(file_okay=False, dir_okay=True, path_type=Path), default=None)
def main(capsule: Path, out_dir: Optional[Path]) -> None:
    """Build evidence/streams.parquet by scanning residuals and verifying latents."""
    if out_dir is None:
        out_dir = capsule / "evidence"

    events_path = capsule / "events.jsonl"

    judge = StreamJudge(capsule)
    try:
        events = _load_events(events_path)
        rows: List[Dict[str, Any]] = []

        for evt in events:
            fid = int(evt["frame_id"])

            l_ref = evt["stream_refs"]["latents"]
            claimed_off = int(l_ref["offset"])
            claimed_len = int(l_ref["length"])

            stat, h = judge.verify_latent(claimed_off, claimed_len, fid)
            if stat != "VERIFIED":
                raise SystemExit(1)

            rows.append(
                {
                    "frame_id": fid,
                    "stream": "latents",
                    "offset": claimed_off,
                    "length": claimed_len,
                    "content_hash": h,
                    "status": "VERIFIED",
                }
            )

            if fid in judge.residual_index:
                for rec in judge.residual_index[fid]:
                    rows.append(
                        {
                            "frame_id": int(rec.frame_id),
                            "stream": "residuals",
                            "offset": int(rec.offset),
                            "length": int(rec.length),
                            "content_hash": rec.content_hash,
                            "status": rec.status,
                        }
                    )

        out_path = out_dir / "streams.parquet"
        _write_parquet_deterministic(out_path, rows)
        click.echo(f"Wrote evidence table: {out_path} (rows={len(rows)})")
    finally:
        judge.close()


if __name__ == "__main__":
    main()
