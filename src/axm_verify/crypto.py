"""
AXM Genesis — Cryptographic Verification

Suite-aware Merkle root computation and signature verification.

  "ed25519" (legacy):  Ed25519 sigs, no domain separation, duplicate-odd-leaf
  "axm-blake3-mldsa44": ML-DSA-44 sigs, domain-separated tree, RFC 6962 odd-leaf
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List, Tuple, Union

import blake3
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

# Attempt to import ML-DSA-44
try:
    from dilithium_py.dilithium import Dilithium2 as _Dilithium2
    _HAS_MLDSA = True
except ImportError:
    _HAS_MLDSA = False

# Policy limits (implementation hardening, not protocol)
MAX_MERKLE_FILE_BYTES = 512 * 1024 * 1024  # 512 MiB
MAX_FILE_BYTES = MAX_MERKLE_FILE_BYTES  # backward-compatible alias
MAX_MERKLE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB
MAX_MERKLE_FILES = 100_000
HASH_CHUNK_SIZE = 64 * 1024

# Frozen empty-tree constant for mldsa44 suite: BLAKE3(0x01)
EMPTY_ROOT_MLDSA44 = "48fc721fbbc172e0925fa27af1671de225ba927134802998b10a1568a188652b"

# Suite key/sig sizes for quick validation
SUITE_SIZES = {
    "ed25519": {"pk": 32, "sig": 64},
    "axm-blake3-mldsa44": {"pk": 1312, "sig": 2420},
}


def _collect_and_validate_files(shard_root: Path) -> List[Tuple[str, Path]]:
    """Collect shard files with size/count/symlink enforcement."""
    files: List[Tuple[str, Path]] = []
    total_bytes = 0
    file_count = 0

    for root, dirs, filenames in os.walk(shard_root, followlinks=False):
        root_path = Path(root)
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
    return files


def _merkle_tree_legacy(leaves: List[bytes]) -> bytes:
    """Legacy tree: duplicate odd leaf (Bitcoin style), no domain separation."""
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
    """Post-quantum tree: domain-separated, odd-leaf promotion (RFC 6962)."""
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
            nxt.append(level[i])  # promote unchanged
        level = nxt
    return level[0]


def compute_merkle_root(shard_root: Path, suite: str = "ed25519") -> str:
    """Compute the BLAKE3 Merkle root for the shard.

    Spec: exclude manifest.json and sig/*.
    Hardening: refuse symlinks and enforce file/total size limits.

    Args:
        shard_root: Shard directory path.
        suite: "ed25519" or "axm-blake3-mldsa44".

    Returns: 64-hex Merkle root.
    """
    files = _collect_and_validate_files(shard_root)

    if suite == "axm-blake3-mldsa44":
        leaves: List[bytes] = []
        for rel, fp in files:
            h = blake3.blake3()
            h.update(b"\x00")  # domain: leaf
            h.update(rel.encode("utf-8"))
            h.update(b"\x00")
            with fp.open("rb") as f:
                while True:
                    chunk = f.read(HASH_CHUNK_SIZE)
                    if not chunk:
                        break
                    h.update(chunk)
            leaves.append(h.digest())
        return _merkle_tree_mldsa44(leaves).hex()
    else:
        leaves = []
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
        return _merkle_tree_legacy(leaves).hex()


def verify_manifest_signature(
    manifest_data: Union[Path, bytes],
    sig_path: Path,
    pubkey_path: Path,
    suite: str = "ed25519",
) -> bool:
    """Verify signature over manifest bytes.

    Suite-aware: dispatches to Ed25519 or ML-DSA-44 based on suite field.
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

    expected = SUITE_SIZES.get(suite, SUITE_SIZES["ed25519"])
    if len(pub) != expected["pk"]:
        return False
    if len(sig) != expected["sig"]:
        return False

    if suite == "axm-blake3-mldsa44":
        if not _HAS_MLDSA:
            raise RuntimeError("dilithium-py not installed — cannot verify ML-DSA-44 signatures")
        return _Dilithium2.verify(pub, manifest_bytes, sig)
    else:
        try:
            VerifyKey(pub).verify(manifest_bytes, sig)
            return True
        except (BadSignatureError, ValueError):
            return False
