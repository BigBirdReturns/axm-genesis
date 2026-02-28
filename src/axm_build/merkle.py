"""
AXM Genesis — Merkle Tree Builder

Two algorithms selected by suite:

  "ed25519" (legacy, v1.0):
    Leaf  = BLAKE3(relpath_utf8 + 0x00 + file_bytes)
    Node  = BLAKE3(left + right)
    Odd   = duplicate last node (Bitcoin style)
    Empty = BLAKE3(b"")

  "axm-blake3-mldsa44" (post-quantum):
    Leaf  = BLAKE3(0x00 + relpath_utf8 + 0x00 + file_bytes)   ← domain prefix
    Node  = BLAKE3(0x01 + left + right)                        ← domain prefix
    Odd   = promote unchanged (RFC 6962, no duplication)       ← CVE-2012-2459 safe
    Empty = BLAKE3(0x01)                                       ← hardcoded constant

Domain separation prevents structural collision attacks where crafted file
content could be confused with internal tree nodes.
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

import blake3

EXCLUDE_PATHS = {"manifest.json"}

# Frozen constant: BLAKE3(0x01). Used as empty tree root for mldsa44 suite.
EMPTY_ROOT_MLDSA44 = "48fc721fbbc172e0925fa27af1671de225ba927134802998b10a1568a188652b"


def _collect_files(shard_root: Path) -> List[Tuple[str, Path]]:
    """Collect and sort shard files, excluding manifest.json and sig/."""
    files: List[Tuple[str, Path]] = []
    for p in shard_root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(shard_root).as_posix()
        if rel in EXCLUDE_PATHS or rel.startswith("sig/"):
            continue
        files.append((rel, p))
    files.sort(key=lambda x: x[0].encode("utf-8"))
    return files


def _merkle_tree_legacy(leaves: List[bytes]) -> bytes:
    """Legacy tree: duplicate odd leaf (Bitcoin style)."""
    if not leaves:
        return blake3.blake3(b"").digest()
    level = list(leaves)
    while len(level) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(blake3.blake3(left + right).digest())
        level = nxt
    return level[0]


def _merkle_tree_mldsa44(leaves: List[bytes]) -> bytes:
    """Post-quantum tree: domain-separated nodes, odd-leaf promotion (RFC 6962)."""
    if not leaves:
        return bytes.fromhex(EMPTY_ROOT_MLDSA44)
    if len(leaves) == 1:
        return leaves[0]
    level = list(leaves)
    while len(level) > 1:
        nxt: List[bytes] = []
        i = 0
        while i < len(level) - 1:
            nxt.append(blake3.blake3(b"\x01" + level[i] + level[i + 1]).digest())
            i += 2
        if i < len(level):
            nxt.append(level[i])  # promote unchanged — no duplication
        level = nxt
    return level[0]


def compute_merkle_root(shard_root: Path, suite: str = "ed25519") -> str:
    """Compute the shard Merkle root.

    Args:
        shard_root: Path to shard directory.
        suite: "ed25519" (legacy) or "axm-blake3-mldsa44" (post-quantum).

    Returns:
        64-hex-character Merkle root string.
    """
    files = _collect_files(shard_root)

    if suite == "axm-blake3-mldsa44":
        # Domain-separated leaves: BLAKE3(0x00 + relpath + 0x00 + content)
        leaves: List[bytes] = []
        for rel, fp in files:
            h = blake3.blake3()
            h.update(b"\x00")
            h.update(rel.encode("utf-8"))
            h.update(b"\x00")
            h.update(fp.read_bytes())
            leaves.append(h.digest())
        return _merkle_tree_mldsa44(leaves).hex()
    else:
        # Legacy leaves: BLAKE3(relpath + 0x00 + content)
        leaves = []
        for rel, fp in files:
            h = blake3.blake3()
            h.update(rel.encode("utf-8"))
            h.update(b"\x00")
            h.update(fp.read_bytes())
            leaves.append(h.digest())
        return _merkle_tree_legacy(leaves).hex()
