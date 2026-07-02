# Profile `embodied@1` — Non-selective recording

Status: **Normative for shards declaring `"embodied@1"`. Frozen.**

This document defines the `embodied@1` profile per Section 15 of
`spec/v1/SPECIFICATION.md`. It is self-contained: every constant and byte
layout is restated normatively here. It carries forward, unchanged in
substance, the former kernel requirement REQ 5 ("non-selective recording")
and the former repository-level STREAM_FORMAT v1 document.

## 1. Purpose

Embodied spokes (e.g. robotics recorders) write binary sensor streams into
`content/`. The compliance claim of this profile is **non-selectivity**:
the hot stream is a gap-free, append-only sequence of frames. A missing or
out-of-sequence frame means either deliberate deletion (spoliation) or
unrecovered corruption; both are violations.

On-disk bytes are the source of truth. Any event log's claimed byte
offsets are advisory; streams are validated by scanning the binary files
directly.

## 2. Declaration and scope

- A publisher declares this profile by including `"embodied@1"` in the
  manifest `profiles` array. The declaration is covered by the shard
  signature.
- A verifier that implements `embodied@1` MUST run the checks of Section 6
  whenever the profile is listed, and report it in `profiles_checked`. A
  verifier that does not implement it MUST report it in
  `profiles_unchecked` (unchecked ≠ passed).
- The profile inspects files under `content/`. It defines no manifest
  fields and no core-table rules.

## 3. Error code

| Code | Meaning |
|---|---|
| `E_BUFFER_DISCONTINUITY` | Any violation detected by the Section 6 continuity check: bad file magic, bad record magic or version, frame-id gap or reorder, truncated header or payload, or an unreadable stream file |

`E_BUFFER_DISCONTINUITY` is a **profile** error code. It flows into the
verifier's `errors` array like a kernel code, makes `status` `FAIL`, and
exits 1 under the CLI contract.

## 4. Shared record header

All stream records in this profile use one little-endian header layout
(equivalent to Python struct format `<4sBII`), 13 bytes total:

| offset | size | field | type | meaning |
|---|---|---|---|---|
| 0 | 4 | `magic` | bytes | stream-type record identifier (Section 5) |
| 4 | 1 | `ver` | uint8 | format version; MUST be `1` |
| 5 | 4 | `frame_id` | uint32 LE | zero-indexed, monotonically increasing by exactly 1 |
| 9 | 4 | `payload_len` | uint32 LE | number of payload bytes following the header |

A record is `header ‖ payload` (13 + `payload_len` bytes). Wherever a
record is hashed, the hash covers `header ‖ payload`.

## 5. Streams

### 5.1 Frozen constants

```
MAGIC_LATENT_FILE = b"AXLF"    # latents file-level header, offset 0, written once
MAGIC_LATENT_REC  = b"AXLR"    # per-record magic, latents (hot stream)
MAGIC_RESID_REC   = b"AXRR"    # per-record magic, residuals (cold stream)

VERSION           = 1
REC_HEADER_LEN    = 13         # <4sBII little-endian
FILE_HEADER_LEN   = 4          # the AXLF file magic
LATENT_DIM        = 256        # latent payload bytes
LATENT_REC_LEN    = 269        # 13-byte header + 256-byte payload
```

These constants are frozen. Any producer implementing a different binary
hot stream MUST use distinct magic bytes and a different profile.

### 5.2 Latents — hot stream (`content/cam_latents.bin`)

File layout:

```
[AXLF (4 bytes)]                      ← file-level header, offset 0
[record_0][record_1][record_2]...     ← consecutive AXLR records
```

Producer requirements (MUST):

- Byte 0–3 of the file are exactly `AXLF`.
- Records follow back-to-back with no padding: record `fid` begins at byte
  offset `4 + fid × 269`.
- Each record header has `magic` = `AXLR`, `ver` = 1,
  `payload_len` = 256, and `frame_id` values 0, 1, 2, … with no gaps, no
  repeats, no reordering.
- The file ends exactly at a record boundary (no trailing partial record).

### 5.3 Residuals — cold stream (`content/cam_residuals.bin`)

Optional. Record magic `AXRR`, `ver` = 1, variable `payload_len`. Records
are appended sequentially; there is **no** file-level header (records start
at offset 0). Cold streams are discovered by scanning: a reader
encountering a corrupt record magic MAY re-synchronize forward within a
bounded scan budget, and MUST stop cleanly (not crash) if EOF cuts a header
or payload (torn write).

The residual stream is a producer-side format definition; it is **not
inspected** by the Section 6 verification (its bytes are still sealed by
the kernel Merkle root like every content file).

## 6. Verification — hot-stream continuity check

This is the entire normative check set of `embodied@1`. Input:
`content/cam_latents.bin`.

1. If `content/cam_latents.bin` does not exist, the profile passes
   vacuously (document shards and non-embodied spokes pass through).
2. Otherwise open the file and read the first 4 bytes. If they are not
   exactly `AXLF` (including the file being shorter than 4 bytes), report
   `E_BUFFER_DISCONTINUITY` and stop.
3. Set `expected_fid = 0`. Repeat:
   a. Read 13 bytes. If 0 bytes were available, the scan ends: **clean
      EOF, the check passes.** If 1–12 bytes were read, report
      `E_BUFFER_DISCONTINUITY` (truncated header) and stop.
   b. Decode the header per Section 4. If `magic` ≠ `AXLR` or `ver` ≠ 1,
      report `E_BUFFER_DISCONTINUITY` and stop.
   c. If `frame_id` ≠ `expected_fid`, report `E_BUFFER_DISCONTINUITY`
      (frame gap) and stop.
   d. Read `payload_len` bytes of payload. If fewer are available, report
      `E_BUFFER_DISCONTINUITY` (truncated payload) and stop.
   e. Increment `expected_fid` and continue at (a).
4. Any I/O error while reading the file is `E_BUFFER_DISCONTINUITY`.

Notes:

- The traversal advances by the `payload_len` **declared in each record
  header**. A record with `payload_len` ≠ 256 violates the producer rules
  of Section 5.2, but the continuity check does not itself enforce the
  payload length; the exact bytes are in any case pinned by the kernel
  Merkle root and signature.
- The check is single-pass and O(file size). A verifier MAY impose a
  resource-limit policy on the stream size; if the limit prevents
  completing the scan, the verifier MUST NOT report the profile as checked
  and passed — the reference implementation reports
  `E_BUFFER_DISCONTINUITY` ("cannot verify continuity").
- Exactly one error is required to fail the shard; implementations MAY
  stop at the first violation.

## 7. Evidence output convention (informative)

Embodied judges that index stream records are RECOMMENDED to publish their
findings as an extension table `ext/streams@1.jsonl` (canonical JSONL per
Spec §5; sorted by the composite key (`stream`, `frame_id`, `offset`)):

| key | type | meaning |
|---|---|---|
| `frame_id` | integer | frame index |
| `stream` | string | `"latents"` or `"residuals"` |
| `file` | string | `"cam_latents.bin"` or `"cam_residuals.bin"` |
| `offset` | integer | byte offset of the record in the file |
| `length` | integer | total record length (header + payload) |
| `status` | string | `"VERIFIED"` or a failure reason |
| `content_hash` | string | SHA-256 hex of the payload bytes |

Like all of `ext/`, this table is opaque to the kernel and is not inspected
by the `embodied@1` verification in Section 6.

## 8. Relationship to the kernel

The kernel verifier has no knowledge of `cam_latents.bin`, `AXLF`, `AXLR`,
or latent dimensions; to the kernel these are ordinary content bytes,
hashed into `sources` and the Merkle tree. This profile adds semantics on
top. Future stream formats (new magics, new dimensions, new checks) are new
profile versions (`embodied@2`, …) — the kernel and this document never
change.
