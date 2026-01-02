from __future__ import annotations

from pathlib import Path
from typing import List, Tuple
import blake3
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

def compute_merkle_root(shard_root: Path) -> str:
    # Spec: exclude manifest.json and sig/*
    files: List[Tuple[str, Path]] = []
    for p in shard_root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(shard_root).as_posix()
        if rel == "manifest.json" or rel.startswith("sig/"):
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

def verify_manifest_signature(manifest_path: Path, sig_path: Path, pubkey_path: Path) -> bool:
    if not manifest_path.exists() or not sig_path.exists() or not pubkey_path.exists():
        return False

    manifest_bytes = manifest_path.read_bytes()
    sig = sig_path.read_bytes()
    pub = pubkey_path.read_bytes()

    if len(pub) != 32:
        return False
    if len(sig) != 64:
        return False

    try:
        VerifyKey(pub).verify(manifest_bytes, sig)
        return True
    except (BadSignatureError, ValueError):
        return False
