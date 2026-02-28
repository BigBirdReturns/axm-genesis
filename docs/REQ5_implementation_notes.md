# Adding REQ 5: Hot Stream Buffer Continuity Enforcement

**What this does:** Activates the `E_BUFFER_DISCONTINUITY` error code and makes
`axm-verify` mechanically reject any shard whose binary event buffer has a gap.
This is the enforcement mechanism for the non-selective recording requirement.

**Files to change:** Two files in `genesis/src/axm_verify/`.

---

## Step 1 — Add the error code to `const.py`

In `genesis/src/axm_verify/const.py`, add to the `ErrorCode` enum:

```python
class ErrorCode(str, Enum):
    # ... existing codes ...
    E_BUFFER_DISCONTINUITY = "E_BUFFER_DISCONTINUITY"
```

Place it after `E_REF_READ`. That is the only change to this file.

---

## Step 2 — Add the continuity check to `logic.py`

### Binary format reference

`cam_latents.bin` has a two-level structure. This must match `axm_embodied_core/protocol.py` exactly:

```
File layout:
  [AXLF (4 bytes)]          ← file-level header, written once at open
  [record] [record] ...     ← one record per captured frame

Record layout:
  [AXLR (4 bytes)]          ← per-record magic
  [ver   (1 byte)]          ← version, currently 1
  [frame_id (4 bytes)]      ← uint32, little-endian
  [length   (4 bytes)]      ← payload length in bytes, little-endian
  [payload  (length bytes)] ← LATENT_DIM = 256 bytes per record
```

The file header (`AXLF`) must be skipped before reading records. Attempting to
parse it as a record header will fail immediately because `AXLF != AXLR`.

### Add this function to `logic.py`

```python
import struct as _struct

# Must match axm_embodied_core/protocol.py
_FILE_MAGIC      = b"AXLF"        # File-level header written once at open
_REC_MAGIC       = b"AXLR"        # Per-record magic
_FILE_HEADER_LEN = 4              # AXLF file magic, must be skipped before records
_REC_HEADER_FMT  = "<4sBII"       # magic(4) ver(1) frame_id(4) length(4)
_REC_HEADER_LEN  = _struct.calcsize(_REC_HEADER_FMT)   # 13 bytes
_REC_VERSION     = 1


def _validate_hot_stream_continuity(
    content_dir: Path,
    errors: List[Dict[str, str]],
) -> None:
    """REQ 5: Verify that the hot stream buffer (cam_latents.bin) has no gaps.

    The hot stream must be append-only and gap-free. A missing frame means
    either deliberate deletion or unrecovered corruption. Both are compliance
    violations under the non-selective recording rule.

    This check only runs when cam_latents.bin is present in content/.
    Shards without binary streams (document shards, etc.) are unaffected.
    """
    latents_path = content_dir / "cam_latents.bin"
    if not latents_path.exists():
        return  # Not an embodied shard — skip silently

    if latents_path.stat().st_size > MAX_FILE_BYTES:
        _err(errors, ErrorCode.E_BUFFER_DISCONTINUITY,
             "cam_latents.bin exceeds size limit — cannot verify continuity")
        return

    expected_fid = 0

    try:
        with latents_path.open("rb") as f:
            # Skip the 4-byte file-level magic (AXLF)
            file_magic = f.read(_FILE_HEADER_LEN)
            if len(file_magic) < _FILE_HEADER_LEN or file_magic != _FILE_MAGIC:
                _err(errors, ErrorCode.E_BUFFER_DISCONTINUITY,
                     f"cam_latents.bin: bad file header magic (got {file_magic!r})")
                return

            offset = _FILE_HEADER_LEN

            while True:
                header_bytes = f.read(_REC_HEADER_LEN)
                if len(header_bytes) == 0:
                    break  # Clean EOF
                if len(header_bytes) < _REC_HEADER_LEN:
                    _err(errors, ErrorCode.E_BUFFER_DISCONTINUITY,
                         f"cam_latents.bin: truncated header at offset {offset}")
                    return

                magic, ver, fid, dlen = _struct.unpack(_REC_HEADER_FMT, header_bytes)

                if magic != _REC_MAGIC or ver != _REC_VERSION:
                    _err(errors, ErrorCode.E_BUFFER_DISCONTINUITY,
                         f"cam_latents.bin: bad record magic/version at offset {offset} "
                         f"(got magic={magic!r} ver={ver})")
                    return

                if int(fid) != expected_fid:
                    _err(errors, ErrorCode.E_BUFFER_DISCONTINUITY,
                         f"cam_latents.bin: frame gap at offset {offset} — "
                         f"expected frame {expected_fid}, found frame {fid}")
                    return

                payload = f.read(dlen)
                if len(payload) < dlen:
                    _err(errors, ErrorCode.E_BUFFER_DISCONTINUITY,
                         f"cam_latents.bin: truncated payload at offset {offset} "
                         f"(frame {fid})")
                    return

                offset += _REC_HEADER_LEN + dlen
                expected_fid += 1

    except Exception as e:
        _err(errors, ErrorCode.E_BUFFER_DISCONTINUITY,
             f"cam_latents.bin: read error during continuity check: {e}")
```

### Wire it into `verify_shard()`

Call it after the content hash validation (step 6) and before the final status determination:

```python
    # 7) Hot stream continuity (REQ 5 — non-selective recording)
    _validate_hot_stream_continuity(root / "content", errors)

    status = "FAIL" if errors else "PASS"
    return {"shard": str(shard_path), "status": status, "error_count": len(errors), "errors": errors}
```

---

## Step 3 — Activate the tests

In `test_conformance.py`, the REQ 5 tests write synthetic `cam_latents.bin` files
using the correct format: `AXLF` file header followed by `AXLR` records. They are
active by default once the check is wired — no `@pytest.mark.skip` to remove.

Run the full suite:

```bash
cd genesis && python -m pytest tests/test_conformance.py -v
```

Expected output:

```
test_conformance.py::test_baseline_gold_shard_passes                      PASSED
test_conformance.py::test_req1_manifest_byte_flip_detected                PASSED
test_conformance.py::test_req1_manifest_invalid_json_detected             PASSED
test_conformance.py::test_req2_content_byte_flip_changes_merkle_root      PASSED
test_conformance.py::test_req2_parquet_byte_flip_changes_merkle_root      PASSED
test_conformance.py::test_req3_orphan_claim_detected                      PASSED
test_conformance.py::test_req3_null_in_column_detected                    PASSED
test_conformance.py::test_req4_wrong_signing_key_rejected                 PASSED
test_conformance.py::test_req4_sig_byte_flip_rejected                     PASSED
test_conformance.py::test_req4_missing_manifest_rejected                  PASSED
test_conformance.py::test_req5_buffer_gap_detected                        PASSED
test_conformance.py::test_req5_continuous_stream_passes_continuity_check  PASSED
test_conformance.py::test_verification_is_deterministic                   PASSED
```

---

## What this does NOT change

- The Genesis shard spec (frozen)
- Existing error codes (no renames, no removals)
- Ed25519 or ML-DSA-44 verification paths
- Any existing tests

The check is additive. Shards without `cam_latents.bin` in `content/` pass through
silently. Document shards, knowledge shards, and any spoke that does not produce
binary stream evidence are completely unaffected.
