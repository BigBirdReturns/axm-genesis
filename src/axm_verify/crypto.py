from __future__ import annotations

import os
from pathlib import Path
from typing import List, Tuple, Union

import blake3
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError


# Policy limits (implementation hardening, not protocol)
# These bounds prevent verifier DoS via unreasonably large shard files.
MAX_MERKLE_FILE_BYTES = 512 * 1024 * 1024  # 512 MiB
MAX_FILE_BYTES = MAX_MERKLE_FILE_BYTES  # backward-compatible alias (policy)
MAX_MERKLE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB
MAX_MERKLE_FILES = 100_000
HASH_CHUNK_SIZE = 64 * 1024

def compute_merkle_root(shard_root: Path) -> str:
    """Compute the BLAKE3 Merkle root for the shard.

    Spec: exclude manifest.json and sig/*.
    Hardening: refuse symlinks and enforce file/total size limits.
    """
    files: List[Tuple[str, Path]] = []

    total_bytes = 0
    file_count = 0

    for root, dirs, filenames in os.walk(shard_root, followlinks=False):
        root_path = Path(root)

        # Prune symlinked directories defensively
        dirs[:] = [d for d in dirs if not (root_path / d).is_symlink()]

        for name in filenames:
            path = root_path / name

            if path.is_symlink():
                raise ValueError(f"Symlink not allowed in shard: {path}")

            if not path.is_file():
                continue

            rel = path.relative_to(shard_root).as_posix()
            if rel == "manifest.json" or rel.startswith("sig/"):
                continue

            st = path.stat()
            if st.st_size > MAX_MERKLE_FILE_BYTES:
                raise ValueError(f"File exceeds size limit: {rel} ({st.st_size} bytes)")

            total_bytes += st.st_size
            file_count += 1

            if file_count > MAX_MERKLE_FILES:
                raise ValueError(f"Shard exceeds file count limit: {file_count}")

            if total_bytes > MAX_MERKLE_TOTAL_BYTES:
                raise ValueError(f"Shard exceeds total size limit: {total_bytes} bytes")

            files.append((rel, path))

    files.sort(key=lambda x: x[0].encode("utf-8"))

    leaves: List[bytes] = []
    for rel, fp in files:
        h = blake3.blake3()
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        with fp.open("rb") as f:
            while True:
                chunk = f.read(HASH_CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
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

def verify_manifest_signature(manifest_data: Union[Path, bytes], sig_path: Path, pubkey_path: Path) -> bool:
    """Verify Ed25519 signature over manifest bytes.

    Accepts either:
    - manifest_data: Path (legacy)
    - manifest_data: bytes (preferred; prevents TOCTOU)

    Note: manifest size limits are enforced in logic.py.
    """
    if not sig_path.exists() or not pubkey_path.exists():
        return False

    if isinstance(manifest_data, Path):
        if not manifest_data.exists():
            return False
        manifest_bytes = manifest_data.read_bytes()
    else:
        manifest_bytes = manifest_data

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
