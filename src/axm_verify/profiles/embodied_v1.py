"""Profile embodied@1 — non-selective recording (spec/profiles/embodied@1.md).

Hot-stream continuity: content/cam_latents.bin, if present, must contain a
gap-free sequence of latent records with no dropped frames. A missing or
gapped frame means either deliberate deletion (spoliation) or unrecovered
corruption; both are violations.

Shards without cam_latents.bin pass vacuously — document shards and
non-embodied spokes pass through silently.

Binary format (frozen in the profile document):
    File layout:    [AXLF (4 bytes)] [records ...]
    Record layout:  [AXLR (4)] [ver=1 (1)] [frame_id (4)] [length (4)] [payload]
    Header format:  "<4sBII" little-endian, 13 bytes
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Dict, List

PROFILE_ID = "embodied@1"

# Profile-owned error code (flows into the verifier errors array like a
# kernel code; makes status FAIL and exit code 1).
E_BUFFER_DISCONTINUITY = "E_BUFFER_DISCONTINUITY"

_FILE_MAGIC = b"AXLF"          # file-level header, offset 0, written once
_REC_MAGIC = b"AXLR"           # per-record magic
_HEADER_FMT = "<4sBII"         # magic(4) ver(1) frame_id(4) payload_len(4)
_HEADER_LEN = struct.calcsize(_HEADER_FMT)
_VERSION = 1
_FILE_HEADER_LEN = 4

# Resource-limit policy: if the limit prevents completing the scan, the
# profile must NOT be reported as checked-and-passed, so we fail loudly.
MAX_STREAM_BYTES = 512 * 1024 * 1024  # 512 MiB


def _err(errors: List[Dict[str, str]], message: str) -> None:
    errors.append({"code": E_BUFFER_DISCONTINUITY, "message": message})


def check(shard_root: Path, errors: List[Dict[str, str]]) -> None:
    """Run the embodied@1 hot-stream continuity check."""
    latents_path = shard_root / "content" / "cam_latents.bin"
    if not latents_path.exists():
        return  # vacuous pass — not an embodied shard

    try:
        if latents_path.stat().st_size > MAX_STREAM_BYTES:
            _err(errors, "cam_latents.bin exceeds size limit — cannot verify continuity")
            return

        expected_fid = 0
        offset = 0
        with latents_path.open("rb") as f:
            file_magic = f.read(_FILE_HEADER_LEN)
            if file_magic != _FILE_MAGIC:
                _err(errors,
                     f"cam_latents.bin: invalid file magic {file_magic!r} "
                     f"(expected {_FILE_MAGIC!r})")
                return
            offset = _FILE_HEADER_LEN

            while True:
                header_bytes = f.read(_HEADER_LEN)
                if len(header_bytes) == 0:
                    break  # clean EOF — check passes
                if len(header_bytes) < _HEADER_LEN:
                    _err(errors,
                         f"cam_latents.bin: truncated header at offset {offset} "
                         f"(expected frame {expected_fid})")
                    return

                magic, ver, fid, dlen = struct.unpack(_HEADER_FMT, header_bytes)

                if magic != _REC_MAGIC or ver != _VERSION:
                    _err(errors,
                         f"cam_latents.bin: bad record magic/version at offset {offset} "
                         f"(magic={magic!r} expected={_REC_MAGIC!r} ver={ver})")
                    return

                if int(fid) != expected_fid:
                    _err(errors,
                         f"cam_latents.bin: frame gap at offset {offset} — "
                         f"expected frame {expected_fid}, found frame {fid}")
                    return

                payload = f.read(dlen)
                if len(payload) < dlen:
                    _err(errors,
                         f"cam_latents.bin: truncated payload at offset {offset} "
                         f"(frame {fid}, expected {dlen} bytes, got {len(payload)})")
                    return

                offset += _HEADER_LEN + dlen
                expected_fid += 1

    except Exception as exc:
        _err(errors, f"cam_latents.bin: read error during continuity check: {exc}")
