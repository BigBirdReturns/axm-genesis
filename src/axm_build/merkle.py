"""AXM Genesis v1 — Merkle tree builder (spec section 8).

Exactly one construction:

    leaf  = BLAKE3(0x00 || relpath_utf8 || 0x00 || file_bytes)
    node  = BLAKE3(0x01 || left || right)
    odd   = promote unchanged (RFC 6962 — never duplicated, CVE-2012-2459 safe)
    empty = BLAKE3(0x01)

The tree commits to every regular file under the shard root except
manifest.json and sig/**, sorted by the UTF-8 bytes of the POSIX relative
path. The 0x00/0x01 prefixes domain-separate leaves from interior nodes.
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

import blake3

# Frozen constant: BLAKE3(0x01) — the empty-tree root.
EMPTY_ROOT = "48fc721fbbc172e0925fa27af1671de225ba927134802998b10a1568a188652b"


def _collect_files(shard_root: Path) -> List[Tuple[str, Path]]:
    """Collect and sort covered files (everything except manifest.json, sig/**)."""
    files: List[Tuple[str, Path]] = []
    for p in shard_root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(shard_root).as_posix()
        if rel == "manifest.json" or rel.startswith("sig/"):
            continue
        files.append((rel, p))
    files.sort(key=lambda x: x[0].encode("utf-8"))
    return files


def _merkle_root(leaves: List[bytes]) -> bytes:
    if not leaves:
        return bytes.fromhex(EMPTY_ROOT)
    level = list(leaves)
    while len(level) > 1:
        nxt: List[bytes] = []
        i = 0
        while i + 1 < len(level):
            nxt.append(blake3.blake3(b"\x01" + level[i] + level[i + 1]).digest())
            i += 2
        if i < len(level):
            nxt.append(level[i])  # promote unchanged — no duplication
        level = nxt
    return level[0]


def compute_merkle_root(shard_root: Path) -> str:
    """Compute the shard Merkle root as 64 lowercase hex characters."""
    leaves: List[bytes] = []
    for rel, fp in _collect_files(shard_root):
        h = blake3.blake3()
        h.update(b"\x00")
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(fp.read_bytes())
        leaves.append(h.digest())
    return _merkle_root(leaves).hex()
