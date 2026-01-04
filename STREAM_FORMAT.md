# STREAM_FORMAT v1

## Purpose
Pattern 2 treats on-disk bytes as the source of truth.
- `events.jsonl` provides narrative plus claimed offsets for hot streams.
- Cold streams must be discoverable by scanning the binary file.

## Shared record header (little endian)
Struct `<4sBII` (13 bytes): `magic` (4), `ver` (1), `frame_id` (uint32), `payload_len` (uint32).
Record bytes are `header + payload`. Hashes cover `header + payload`.

## Streams

### Latents (hot)
File: `cam_latents.bin`, magic `LATN`, ver `1`, payload_len `256`, record_len `269`.
Offset math: `math_offset(fid) = fid * 269`.
Judge: hard fail on offset drift, header mismatch, frame_id mismatch, length drift, or premature EOF.

### Residuals (cold)
File: `cam_residuals.bin`, magic `RSID`, ver `1`.
Judge scans sequentially and indexes valid records. If EOF cuts a header or payload (torn write), the Judge stops scanning cleanly and does not crash.

## Evidence output
The Judge writes `evidence/streams.parquet` with columns: frame_id, stream, offset, length, content_hash, status.
Determinism: sort by `(stream, frame_id, offset)` and write with no compression, no dictionary encoding, and no statistics.
