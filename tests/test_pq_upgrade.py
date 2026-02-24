"""
Tests for the post-quantum cryptographic upgrade.

Validates:
1. Gold shard (Ed25519) still verifies — backward compatible
2. New shards compile with ML-DSA-44 and self-verify
3. Domain-separated Merkle tree differs from legacy
4. Odd-leaf promotion (RFC 6962) differs from duplicate-odd (Bitcoin)
5. Empty tree constant matches spec
6. Deterministic ML-DSA-44 signing
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import blake3
import pytest

# ── Setup ────────────────────────────────────────────────────────────────────

TESTS_DIR = Path(__file__).parent
GOLD_SHARD = TESTS_DIR.parent / "shards" / "gold" / "fm21-11-hemorrhage-v1"
TRUSTED_KEY = TESTS_DIR.parent / "keys" / "canonical_test_publisher.pub"


# ── Merkle tree property tests ───────────────────────────────────────────────

class TestMerkleProperties:
    def test_empty_root_constant(self):
        """BLAKE3(0x01) must match the frozen constant."""
        computed = blake3.blake3(b"\x01").hexdigest()
        assert computed == "48fc721fbbc172e0925fa27af1671de225ba927134802998b10a1568a188652b"

    def test_empty_root_differs_from_legacy(self):
        """Legacy empty root differs from mldsa44 empty root."""
        legacy = blake3.blake3(b"").hexdigest()
        mldsa44 = blake3.blake3(b"\x01").hexdigest()
        assert legacy != mldsa44

    def test_domain_separation_leaf_vs_node(self):
        """Leaf prefix (0x00) and node prefix (0x01) produce different hashes for same data."""
        data = b"identical_data_block"
        leaf_h = blake3.blake3(b"\x00" + data).digest()
        node_h = blake3.blake3(b"\x01" + data).digest()
        assert leaf_h != node_h

    def test_odd_leaf_promotion_vs_duplication(self):
        """RFC 6962 (promote) must differ from Bitcoin (duplicate) for 3 leaves."""
        from axm_build.merkle import _merkle_tree_legacy, _merkle_tree_mldsa44

        a = blake3.blake3(b"\x00" + b"alpha").digest()
        b_leaf = blake3.blake3(b"\x00" + b"beta").digest()
        c = blake3.blake3(b"\x00" + b"gamma").digest()

        legacy_root = _merkle_tree_legacy([a, b_leaf, c])
        mldsa44_root = _merkle_tree_mldsa44([a, b_leaf, c])
        assert legacy_root != mldsa44_root, "Odd-leaf handling must differ between suites"

    def test_even_tree_both_suites(self):
        """4 leaves: both trees produce a root, but they differ due to domain separation."""
        from axm_build.merkle import _merkle_tree_legacy, _merkle_tree_mldsa44

        leaves = [blake3.blake3(f"leaf{i}".encode()).digest() for i in range(4)]
        legacy = _merkle_tree_legacy(leaves)
        mldsa44 = _merkle_tree_mldsa44(leaves)
        assert legacy != mldsa44

    def test_single_leaf_is_root_mldsa44(self):
        """Single leaf: root = leaf (no node hashing)."""
        from axm_build.merkle import _merkle_tree_mldsa44

        leaf = blake3.blake3(b"\x00" + b"only").digest()
        root = _merkle_tree_mldsa44([leaf])
        assert root == leaf


# ── ML-DSA-44 signing tests ─────────────────────────────────────────────────

class TestMLDSA44:
    def test_keygen_sizes(self):
        from axm_build.sign import mldsa44_keygen
        kp = mldsa44_keygen()
        assert len(kp.public_key) == 1312
        assert len(kp.secret_key) == 2528

    def test_sign_verify_roundtrip(self):
        from axm_build.sign import mldsa44_keygen, mldsa44_verify
        kp = mldsa44_keygen()
        msg = b"test message for AXM Genesis"
        sig = kp.sign(msg)
        assert len(sig) == 2420
        assert mldsa44_verify(kp.public_key, msg, sig)

    def test_deterministic_signing(self):
        from axm_build.sign import mldsa44_keygen
        kp = mldsa44_keygen()
        msg = b"determinism check"
        sig1 = kp.sign(msg)
        sig2 = kp.sign(msg)
        assert sig1 == sig2, "ML-DSA-44 must be deterministic"

    def test_wrong_message_rejected(self):
        from axm_build.sign import mldsa44_keygen, mldsa44_verify
        kp = mldsa44_keygen()
        msg = b"correct message"
        sig = kp.sign(msg)
        assert not mldsa44_verify(kp.public_key, b"wrong message", sig)

    def test_wrong_key_rejected(self):
        from axm_build.sign import mldsa44_keygen, mldsa44_verify
        kp1 = mldsa44_keygen()
        kp2 = mldsa44_keygen()
        msg = b"test"
        sig = kp1.sign(msg)
        assert not mldsa44_verify(kp2.public_key, msg, sig)


# ── Backward compatibility ───────────────────────────────────────────────────

class TestBackwardCompatibility:
    @pytest.mark.skipif(not GOLD_SHARD.exists(), reason="Gold shard not present")
    def test_gold_shard_still_verifies(self):
        """The Ed25519 gold shard must still pass verification after upgrade."""
        from axm_verify.logic import verify_shard
        result = verify_shard(GOLD_SHARD, TRUSTED_KEY)
        assert result["status"] == "PASS", f"Gold shard failed: {result.get('errors')}"

    @pytest.mark.skipif(not GOLD_SHARD.exists(), reason="Gold shard not present")
    def test_gold_shard_no_suite_field(self):
        """Gold shard manifest has no suite field — verifier defaults to ed25519."""
        manifest = json.loads((GOLD_SHARD / "manifest.json").read_bytes())
        assert "suite" not in manifest, "Gold shard should not have suite field"

    @pytest.mark.skipif(not GOLD_SHARD.exists(), reason="Gold shard not present")
    def test_gold_shard_ed25519_pubkey(self):
        """Gold shard's publisher.pub should be 32 bytes (Ed25519)."""
        pub = (GOLD_SHARD / "sig" / "publisher.pub").read_bytes()
        assert len(pub) == 32


# ── End-to-end: compile with ML-DSA-44 ──────────────────────────────────────

class TestMLDSA44Compilation:
    def _make_test_shard(self, suite="axm-blake3-mldsa44"):
        """Helper: compile a minimal test shard with given suite."""
        from axm_build.compiler_generic import CompilerConfig, compile_generic_shard

        workdir = Path(tempfile.mkdtemp(prefix="axm_pq_test_"))
        source = workdir / "source.txt"
        source.write_text("Tourniquet treats severe hemorrhage.\n", encoding="utf-8")

        candidates = workdir / "candidates.jsonl"
        candidates.write_text(json.dumps({
            "subject": "tourniquet",
            "predicate": "treats",
            "object": "severe hemorrhage",
            "object_type": "literal:string",
            "tier": 0,
            "confidence": 1.0,
            "evidence": "Tourniquet treats severe hemorrhage.",
        }) + "\n", encoding="utf-8")

        shard_dir = workdir / "shard"
        shard_dir.mkdir(parents=True)
        (shard_dir / "graph").mkdir()
        (shard_dir / "evidence").mkdir()
        (shard_dir / "content").mkdir()
        (shard_dir / "sig").mkdir()

        cfg = CompilerConfig(
            source_path=source,
            candidates_path=candidates,
            out_dir=shard_dir,
            private_key=secrets.token_bytes(32),  # ignored for mldsa44 — keygen happens inside
            publisher_id="pub:test",
            publisher_name="Test Publisher",
            namespace="test:pq",
            created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            suite=suite,
        )

        ok = compile_generic_shard(cfg)
        return ok, shard_dir, workdir

    def test_mldsa44_compile_and_verify(self):
        """Compile a shard with ML-DSA-44 and verify it passes."""
        ok, shard_dir, workdir = self._make_test_shard(suite="axm-blake3-mldsa44")
        try:
            assert ok, "ML-DSA-44 compilation failed"

            # Check manifest has suite field
            manifest = json.loads((shard_dir / "manifest.json").read_bytes())
            assert manifest["suite"] == "axm-blake3-mldsa44"

            # Check pubkey is 1312 bytes (ML-DSA-44)
            pub = (shard_dir / "sig" / "publisher.pub").read_bytes()
            assert len(pub) == 1312, f"Expected 1312, got {len(pub)}"

            # Check signature is 2420 bytes
            sig = (shard_dir / "sig" / "manifest.sig").read_bytes()
            assert len(sig) == 2420, f"Expected 2420, got {len(sig)}"

            # Independent verify
            from axm_verify.logic import verify_shard
            result = verify_shard(shard_dir, shard_dir / "sig" / "publisher.pub")
            assert result["status"] == "PASS", f"Verify failed: {result.get('errors')}"
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def test_ed25519_compile_still_works(self):
        """Legacy Ed25519 compilation still works."""
        ok, shard_dir, workdir = self._make_test_shard(suite="ed25519")
        try:
            assert ok, "Ed25519 compilation failed"

            manifest = json.loads((shard_dir / "manifest.json").read_bytes())
            assert manifest["suite"] == "ed25519"

            pub = (shard_dir / "sig" / "publisher.pub").read_bytes()
            assert len(pub) == 32

            sig = (shard_dir / "sig" / "manifest.sig").read_bytes()
            assert len(sig) == 64

            from axm_verify.logic import verify_shard
            result = verify_shard(shard_dir, shard_dir / "sig" / "publisher.pub")
            assert result["status"] == "PASS", f"Verify failed: {result.get('errors')}"
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def test_merkle_roots_differ_between_suites(self):
        """Same content compiled with different suites produces different Merkle roots."""
        ok1, shard1, wd1 = self._make_test_shard(suite="ed25519")
        ok2, shard2, wd2 = self._make_test_shard(suite="axm-blake3-mldsa44")
        try:
            assert ok1 and ok2
            m1 = json.loads((shard1 / "manifest.json").read_bytes())
            m2 = json.loads((shard2 / "manifest.json").read_bytes())
            root1 = m1["integrity"]["merkle_root"]
            root2 = m2["integrity"]["merkle_root"]
            assert root1 != root2, "Domain separation must produce different roots"
        finally:
            shutil.rmtree(wd1, ignore_errors=True)
            shutil.rmtree(wd2, ignore_errors=True)