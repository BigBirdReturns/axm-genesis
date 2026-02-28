# STREAM_FORMAT v1

## Purpose

Pattern 2 treats on-disk bytes as the source of truth.

- `events.jsonl` provides the narrative event stream and claimed byte offsets for hot stream records.
- Cold streams must be discoverable by scanning the binary file directly, not by trusting log offsets.

---

## Shared record header (little endian)

```
Struct: <4sBII  (13 bytes total)
  magic       [4 bytes]   — stream-type identifier (see below)
  ver         [1 byte]    — format version, currently 1
  frame_id    [4 bytes]   — uint32, zero-indexed, monotonically increasing
  payload_len [4 bytes]   — uint32, payload bytes following this header
```

Record bytes are `header + payload`. Hashes cover `header + payload`.

---

## Streams

### Latents (hot stream)

| Field | Value |
|-------|-------|
| File | `cam_latents.bin` |
| File header magic | `AXLF` — 4 bytes at offset 0, written once at file open |
| Record magic | `AXLR` |
| Version | `1` |
| Payload length | `256` (LATENT_DIM — constant) |
| Record length | `269` (13-byte header + 256-byte payload) |

**File layout:**
```
[AXLF (4 bytes)]          ← file-level header, skip before reading records
[record_0][record_1]...   ← sequential AXLR records, frame_id 0, 1, 2, ...
```

**Offset math:** `math_offset(fid) = FILE_HEADER_LEN + fid * LATENT_REC_LEN = 4 + fid * 269`

**Judge behavior:** Hard fail on bad file header magic, record magic mismatch, version mismatch, frame_id gap, length mismatch, or premature EOF. The genesis verifier (`axm_verify`) independently checks frame continuity and emits `E_BUFFER_DISCONTINUITY` on any gap.

### Residuals (cold stream)

| Field | Value |
|-------|-------|
| File | `cam_residuals.bin` |
| Record magic | `AXRR` |
| Version | `1` |
| Payload length | Variable (up to DEFAULT_MAX_RESIDUAL_SIZE) |

**Judge behavior:** StrictJudge scans sequentially and indexes valid records. On corrupt magic, it re-synchronizes forward within a bounded scan budget and records the re-sync event. If EOF cuts a header or payload (torn write), scanning stops cleanly — no crash.

---

## Evidence output

StrictJudge writes `ext/streams@1.parquet` with the following schema:

| Column | Type | Description |
|--------|------|-------------|
| `frame_id` | int32 | Frame index |
| `stream` | string | `"latents"` or `"residuals"` |
| `file` | string | `"cam_latents.bin"` or `"cam_residuals.bin"` |
| `offset` | int64 | Byte offset of this record in the file |
| `length` | int32 | Total record length (header + payload) |
| `status` | string | `"VERIFIED"` or failure reason |
| `content_hash` | string | SHA-256 hex of the payload bytes |

**Sort key:** `(stream, frame_id, offset)`

**Location:** `ext/streams@1.parquet` — this is a domain extension, not a core table. The genesis verifier ignores `ext/`. StrictJudge outputs belong here, not in `evidence/`.

---

## Constants (from `axm_embodied_core/protocol.py`)

```python
MAGIC_LATENT_FILE = b"AXLF"   # file-level header
MAGIC_LATENT_REC  = b"AXLR"   # per-record magic for latents
MAGIC_RESID_REC   = b"AXRR"   # per-record magic for residuals

VERSION           = 1
REC_HEADER_FMT    = "<4sBII"
REC_HEADER_LEN    = 13
LATENT_DIM        = 256
FILE_HEADER_LEN   = 4
LATENT_REC_LEN    = REC_HEADER_LEN + LATENT_DIM   # 269
```

These constants are frozen. The genesis verifier (`axm_verify/logic.py`) uses the same values. Any spoke implementing a binary hot stream must match them exactly or define its own with distinct magic bytes.
