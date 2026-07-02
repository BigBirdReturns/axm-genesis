"""Merkle construction (spec section 8): the single frozen tree.

leaf  = BLAKE3(0x00 || relpath_utf8 || 0x00 || file_bytes)
node  = BLAKE3(0x01 || left || right)
odd   = promoted unchanged (RFC 6962 — never duplicated)
empty = BLAKE3(0x01)

Vectors come from tests/vectors/merkle.json; both the builder and the
verifier implementation must agree with them and with each other. The
legacy duplicate-odd-leaf construction is deleted and asserted absent.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict

import blake3
import pytest

import axm_build.merkle as build_merkle
import axm_verify.crypto as verify_crypto
from helpers import VECTORS_DIR

VECTORS = json.loads((VECTORS_DIR / "merkle.json").read_text(encoding="utf-8"))


def _leaf(relpath: str, content: bytes) -> bytes:
    return blake3.blake3(b"\x00" + relpath.encode("utf-8") + b"\x00" + content).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return blake3.blake3(b"\x01" + left + right).digest()


def _materialize(root: Path, files: Dict[str, str]) -> Path:
    for relpath, content in files.items():
        p = root / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return root


def _both_roots(shard_root: Path) -> str:
    """Compute the root with both implementations; they must agree."""
    built = build_merkle.compute_merkle_root(shard_root)
    verified = verify_crypto.compute_merkle_root(shard_root)
    assert built == verified, "builder and verifier Merkle implementations disagree"
    return built


# ── Frozen constants ─────────────────────────────────────────────────────────

def test_empty_root_is_blake3_of_0x01() -> None:
    expected = blake3.blake3(b"\x01").hexdigest()
    assert expected == VECTORS["empty_root"]
    assert build_merkle.EMPTY_ROOT == expected
    assert verify_crypto.EMPTY_ROOT == expected
    assert expected == "48fc721fbbc172e0925fa27af1671de225ba927134802998b10a1568a188652b"


def test_empty_tree_root(tmp_path: Path) -> None:
    # Only excluded files present -> the tree is empty -> BLAKE3(0x01).
    _materialize(tmp_path, {"manifest.json": "{}", "sig/manifest.sig": "s", "sig/publisher.pub": "p"})
    assert _both_roots(tmp_path) == VECTORS["empty_root"]


# ── Vector reproduction ──────────────────────────────────────────────────────

@pytest.mark.parametrize("case", VECTORS["leaves"], ids=lambda c: c["relpath"])
def test_leaf_vectors(case: dict) -> None:
    got = _leaf(case["relpath"], case["content_utf8"].encode("utf-8"))
    assert got.hex() == case["expected_leaf"]


@pytest.mark.parametrize("case", VECTORS["nodes"], ids=lambda c: c["expected_node"][:12])
def test_node_vectors(case: dict) -> None:
    got = _node(bytes.fromhex(case["left"]), bytes.fromhex(case["right"]))
    assert got.hex() == case["expected_node"]


@pytest.mark.parametrize("case", VECTORS["trees"], ids=lambda c: c["name"])
def test_tree_vectors(case: dict, tmp_path: Path) -> None:
    _materialize(tmp_path, case["files"])
    assert _both_roots(tmp_path) == case["expected_root"]


# ── Structural properties ────────────────────────────────────────────────────

def test_single_leaf_is_promoted_to_root(tmp_path: Path) -> None:
    content = "hello world\n"
    _materialize(tmp_path, {"content/test.txt": content})
    assert _both_roots(tmp_path) == _leaf("content/test.txt", content.encode()).hex()


def test_odd_leaf_promoted_unchanged_never_duplicated(tmp_path: Path) -> None:
    files = {"content/a.txt": "aaa\n", "content/b.txt": "bbb\n", "content/c.txt": "ccc\n"}
    _materialize(tmp_path, files)
    la, lb, lc = (_leaf(rel, files[rel].encode()) for rel in sorted(files))
    promoted = _node(_node(la, lb), lc).hex()
    duplicated = _node(_node(la, lb), _node(lc, lc)).hex()  # the DELETED legacy rule
    computed = _both_roots(tmp_path)
    assert computed == promoted
    assert computed != duplicated


def test_manifest_and_sig_are_excluded(tmp_path: Path) -> None:
    _materialize(tmp_path, {"content/a.txt": "aaa\n", "content/b.txt": "bbb\n"})
    before = _both_roots(tmp_path)
    _materialize(tmp_path, {
        "manifest.json": '{"anything":"at all"}',
        "sig/manifest.sig": "not a real signature",
        "sig/publisher.pub": "not a real key",
    })
    assert _both_roots(tmp_path) == before
    # ...but everything else IS covered, ext/ included.
    _materialize(tmp_path, {"ext/lineage@1.jsonl": "{}\n"})
    assert _both_roots(tmp_path) != before


def test_leaf_commits_to_the_path(tmp_path: Path) -> None:
    a = _materialize(tmp_path / "a", {"content/x.txt": "same\n"})
    b = _materialize(tmp_path / "b", {"content/y.txt": "same\n"})
    assert _both_roots(a) != _both_roots(b)
    assert _leaf("content/x.txt", b"same\n") != _leaf("content/y.txt", b"same\n")


def test_leaf_domain_separated_from_node() -> None:
    # A 64-byte file content colliding with two child digests must not
    # produce an interior-node hash (0x00 vs 0x01 prefixes).
    payload = bytes(range(64))
    assert _leaf("p", payload) != blake3.blake3(b"\x01" + b"p" + b"\x00" + payload).digest()


def test_path_sort_is_bytewise_utf8(tmp_path: Path) -> None:
    # 'Z' (0x5A) < 'a' (0x61): bytewise, not locale or case-insensitive order.
    files = {"content/Z.txt": "z\n", "content/a.txt": "a\n"}
    _materialize(tmp_path, files)
    lz = _leaf("content/Z.txt", b"z\n")
    la = _leaf("content/a.txt", b"a\n")
    assert _both_roots(tmp_path) == _node(lz, la).hex()


def test_empty_file_still_produces_a_leaf(tmp_path: Path) -> None:
    _materialize(tmp_path, {"graph/entities.jsonl": ""})
    root = _both_roots(tmp_path)
    assert root == _leaf("graph/entities.jsonl", b"").hex()
    assert root != VECTORS["empty_root"]


def test_content_byte_flip_changes_root(tmp_path: Path) -> None:
    _materialize(tmp_path, {"content/a.txt": "aaa\n", "content/b.txt": "bbb\n"})
    before = _both_roots(tmp_path)
    (tmp_path / "content" / "a.txt").write_bytes(b"aab\n")
    assert _both_roots(tmp_path) != before


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="platform lacks symlinks")
def test_verifier_merkle_rejects_symlinks(tmp_path: Path) -> None:
    _materialize(tmp_path, {"content/a.txt": "aaa\n"})
    try:
        os.symlink(tmp_path / "content" / "a.txt", tmp_path / "content" / "link.txt")
    except OSError:
        pytest.skip("cannot create symlinks in this environment")
    with pytest.raises(ValueError, match="Symlink"):
        verify_crypto.compute_merkle_root(tmp_path)
