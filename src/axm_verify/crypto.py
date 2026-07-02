"""AXM Genesis v1 — cryptographic verification (spec sections 7-9).

One suite (axm-hybrid1: Ed25519 || ML-DSA-44, BOTH must verify) and one
Merkle construction (domain-separated BLAKE3, RFC 6962 odd-node promotion).

This module is intentionally independent of axm_build: an auditor can read
the verify path alone.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List, Tuple

import blake3
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .const import (
    ED25519_PK_LEN,
    ED25519_SIG_LEN,
    HYBRID1_PK_LEN,
    HYBRID1_SIG_LEN,
    MANIFEST_SIG_DOMAIN,
)

# ML-DSA-44 backend: prefer liboqs (C bindings) over pure-Python dilithium-py.
try:
    import oqs as _oqs

    def _mldsa44_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        with _oqs.Signature("ML-DSA-44") as _v:
            return bool(_v.verify(msg, sig, pk))

except (ImportError, SystemExit):
    try:
        from dilithium_py.ml_dsa import ML_DSA_44 as _ML_DSA_44

        def _mldsa44_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
            return bool(_ML_DSA_44.verify(pk, msg, sig))

    except ImportError:

        def _mldsa44_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:  # type: ignore[misc]
            raise RuntimeError(
                "No ML-DSA-44 backend installed — cannot verify axm-hybrid1 signatures. "
                "Run: pip install liboqs-python  (preferred, requires liboqs) "
                "or: pip install dilithium-py  (pure-Python fallback)"
            )

# Policy limits (implementation hardening, not protocol)
MAX_MERKLE_FILE_BYTES = 512 * 1024 * 1024  # 512 MiB
MAX_MERKLE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB
MAX_MERKLE_FILES = 100_000
HASH_CHUNK_SIZE = 64 * 1024

# Frozen empty-tree constant: BLAKE3(0x01)
EMPTY_ROOT = "48fc721fbbc172e0925fa27af1671de225ba927134802998b10a1568a188652b"


def manifest_signing_message(manifest_bytes: bytes) -> bytes:
    """Domain-separated signature message (spec section 7.2)."""
    return MANIFEST_SIG_DOMAIN + manifest_bytes


def hybrid1_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an axm-hybrid1 signature. Valid iff BOTH components verify.

    public_key = pk_ed25519(32) || pk_mldsa44(1312)   — 1344 bytes
    signature  = sig_ed25519(64) || sig_mldsa44(2420) — 2484 bytes
    """
    if len(public_key) != HYBRID1_PK_LEN or len(signature) != HYBRID1_SIG_LEN:
        return False
    pk_ed, pk_ml = public_key[:ED25519_PK_LEN], public_key[ED25519_PK_LEN:]
    sig_ed, sig_ml = signature[:ED25519_SIG_LEN], signature[ED25519_SIG_LEN:]
    try:
        VerifyKey(pk_ed).verify(message, sig_ed)
    except (BadSignatureError, ValueError):
        return False
    try:
        return bool(_mldsa44_verify(pk_ml, message, sig_ml))
    except RuntimeError:
        raise
    except Exception:
        return False


def verify_manifest_signature(manifest_bytes: bytes, sig_path: Path, pubkey_path: Path) -> bool:
    """Verify sig/manifest.sig over the domain-separated manifest message."""
    if not sig_path.exists() or not pubkey_path.exists():
        return False
    sig = sig_path.read_bytes()
    pub = pubkey_path.read_bytes()
    return hybrid1_verify(pub, manifest_signing_message(manifest_bytes), sig)


def _collect_and_validate_files(shard_root: Path) -> List[Tuple[str, Path]]:
    """Collect Merkle-covered files with size/count/symlink enforcement.

    Covers every regular file except manifest.json and sig/** , sorted by
    the UTF-8 bytes of the POSIX relative path.
    """
    files: List[Tuple[str, Path]] = []
    total_bytes = 0

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
            if len(files) + 1 > MAX_MERKLE_FILES:
                raise ValueError(f"Shard exceeds file count limit: {MAX_MERKLE_FILES}")
            if total_bytes > MAX_MERKLE_TOTAL_BYTES:
                raise ValueError(f"Shard exceeds total size limit: {total_bytes} bytes")

            files.append((rel, path))

    files.sort(key=lambda x: x[0].encode("utf-8"))
    return files


def _merkle_root(leaves: List[bytes]) -> bytes:
    """The single frozen tree: node = BLAKE3(0x01 || left || right); an odd
    node is promoted unchanged (RFC 6962 — never duplicated)."""
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
            nxt.append(level[i])  # promote unchanged
        level = nxt
    return level[0]


def compute_merkle_root(shard_root: Path) -> str:
    """Compute the shard Merkle root (spec section 8).

    leaf = BLAKE3(0x00 || relpath_utf8 || 0x00 || file_bytes)
    """
    files = _collect_and_validate_files(shard_root)
    leaves: List[bytes] = []
    for rel, fp in files:
        h = blake3.blake3()
        h.update(b"\x00")
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        with fp.open("rb") as f:
            while True:
                chunk = f.read(HASH_CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        leaves.append(h.digest())
    return _merkle_root(leaves).hex()


def derive_shard_id(manifest_bytes: bytes) -> str:
    """shard_id = "sh1_" + hex(BLAKE3(manifest_bytes)) — derived, never stored."""
    return "sh1_" + blake3.blake3(manifest_bytes).hexdigest()
