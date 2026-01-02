from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

import blake3

EXCLUDE_PATHS = {"manifest.json"}


def compute_merkle_root(shard_root: Path) -> str:
    """Compute the shard Merkle root.

    Algorithm matches axm_verify.crypto.compute_merkle_root.
    Leaves are Blake3( relpath_utf8 + 0x00 + file_bytes ).
    manifest.json and all files under sig/ are excluded.

    Returns a 64-hex-character string.
    """

    files: List[Tuple[str, Path]] = []
    for p in shard_root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(shard_root).as_posix()
        if rel in EXCLUDE_PATHS or rel.startswith("sig/"):
            continue
        files.append((rel, p))

    files.sort(key=lambda x: x[0].encode("utf-8"))

    leaves: List[bytes] = []
    for rel, fp in files:
        h = blake3.blake3()
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(fp.read_bytes())
        leaves.append(h.digest())

    if not leaves:
        return blake3.blake3(b"").hexdigest()

    while len(leaves) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(leaves), 2):
            left = leaves[i]
            right = leaves[i + 1] if i + 1 < len(leaves) else left
            nxt.append(blake3.blake3(left + right).digest())
        leaves = nxt

    return leaves[0].hex()
