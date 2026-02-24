"""Test Merkle root computation."""
import tempfile
from pathlib import Path

import blake3

from axm_verify.crypto import compute_merkle_root, EMPTY_ROOT_MLDSA44


def _make_shard(files: dict[str, str]) -> Path:
    """Create a minimal shard directory with given files."""
    tmp = Path(tempfile.mkdtemp())
    (tmp / "sig").mkdir()
    for rel, content in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    # Minimal manifest and sig
    (tmp / "manifest.json").write_text("{}")
    (tmp / "sig" / "manifest.sig").write_bytes(b"\x00" * 64)
    (tmp / "sig" / "publisher.pub").write_bytes(b"\x00" * 32)
    return tmp


def test_empty_tree_legacy():
    """Legacy empty tree = BLAKE3(b"")"""
    shard = _make_shard({})
    root = compute_merkle_root(shard, suite="ed25519")
    expected = blake3.blake3(b"").hexdigest()
    assert root == expected


def test_empty_tree_mldsa44():
    """PQ empty tree = BLAKE3(0x01) frozen constant."""
    shard = _make_shard({})
    root = compute_merkle_root(shard, suite="axm-blake3-mldsa44")
    assert root == EMPTY_ROOT_MLDSA44


def test_single_file_both_suites():
    """Same content produces DIFFERENT roots under different suites (domain separation)."""
    files = {"content/test.txt": "hello world\n"}
    shard = _make_shard(files)

    root_legacy = compute_merkle_root(shard, suite="ed25519")
    root_pq = compute_merkle_root(shard, suite="axm-blake3-mldsa44")

    assert root_legacy != root_pq, "Domain separation must produce different roots"
    assert len(root_legacy) == 64
    assert len(root_pq) == 64


def test_deterministic():
    """Same shard always produces same root."""
    files = {"content/a.txt": "aaa\n", "content/b.txt": "bbb\n"}
    shard = _make_shard(files)

    r1 = compute_merkle_root(shard, suite="axm-blake3-mldsa44")
    r2 = compute_merkle_root(shard, suite="axm-blake3-mldsa44")
    assert r1 == r2


def test_odd_leaf_differs():
    """Odd-leaf handling: legacy duplicates, PQ promotes. With 3 files, they must differ."""
    files = {"content/a.txt": "a", "content/b.txt": "b", "content/c.txt": "c"}
    shard = _make_shard(files)

    root_legacy = compute_merkle_root(shard, suite="ed25519")
    root_pq = compute_merkle_root(shard, suite="axm-blake3-mldsa44")
    assert root_legacy != root_pq
