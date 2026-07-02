"""Conformance requirements (spec/v1/CONFORMANCE.md, REQ 1-4) and the
reproducibility claim behind canonical JSONL (RFC 0002 D2).

REQ 1-4 are mapped onto the frozen shard vectors by parsing the REQ table
out of CONFORMANCE.md itself, so the requirement <-> error-code mapping in
the spec and the vectors cannot drift apart. REQ 5 must be gone from the
kernel (it is the embodied@1 profile).
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Set

import pytest

from axm_verify.const import ErrorCode
from axm_verify.crypto import derive_shard_id
from axm_verify.logic import verify_shard
from helpers import (
    CONFORMANCE_MD,
    GOLD_PUB,
    GOLD_SHARD,
    REPO_ROOT,
    parse_expected_rows,
    requires_mldsa_backend,
)

pytestmark = requires_mldsa_backend

ROWS = {row["vector"]: row for row in parse_expected_rows()}


def _req_codes_from_spec() -> Dict[int, Set[str]]:
    """Parse the REQ table in CONFORMANCE.md into {req_number: error codes}."""
    reqs: Dict[int, Set[str]] = {}
    for line in CONFORMANCE_MD.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\|\s*(?:~~)?REQ (\d)(?:~~)?\s*\|", line)
        if m:
            reqs[int(m.group(1))] = set(re.findall(r"E_[A-Z_]+", line))
    return reqs


REQ_CODES = _req_codes_from_spec()

# Which vectors demonstrate each kernel requirement being enforced.
REQ_VECTORS: Dict[int, List[str]] = {
    1: [
        "invalid/unknown_suite",
        "invalid/manifest_shard_id_present",
        "invalid/statistics_mismatch",
        "invalid/bad_signature_ed25519_half",
    ],
    2: [
        "invalid/merkle_mismatch",
        "invalid/sources_bijection_extra_file",
        "invalid/sources_bijection_missing_entry",
    ],
    3: [
        "invalid/missing_field",
        "invalid/orphan_claim",
        "invalid/dup_primary_key",
        "invalid/unsorted_rows",
    ],
    4: [
        "invalid/missing_manifest",
        "invalid/bad_signature_mldsa_half",
    ],
}


def test_spec_defines_req_1_through_4() -> None:
    assert set(REQ_CODES) >= {1, 2, 3, 4}, "CONFORMANCE.md must define REQ 1-4"
    for req, codes in REQ_CODES.items():
        if req != 5:
            assert codes, f"REQ {req} row in CONFORMANCE.md lists no error codes"


@pytest.mark.parametrize("req", [1, 2, 3, 4])
def test_every_kernel_requirement_has_enforcing_vectors(req: int) -> None:
    vectors = REQ_VECTORS[req]
    assert vectors, f"REQ {req} has no covering vectors"
    for vector in vectors:
        row = ROWS[vector]
        assert row["status"] == "FAIL"
        assert set(row["error_codes"]) & REQ_CODES[req], (
            f"{vector}: codes {row['error_codes']} do not evidence REQ {req}"
        )


def test_all_documented_kernel_codes_are_real() -> None:
    kernel_codes = {e.value for e in ErrorCode}
    for req in (1, 2, 3, 4):
        assert REQ_CODES[req] <= kernel_codes, f"REQ {req} cites unknown codes"


def test_req5_is_out_of_the_kernel() -> None:
    # The spec marks REQ 5 as moved to the embodied@1 profile...
    assert 5 in REQ_CODES
    assert REQ_CODES[5] == {"E_BUFFER_DISCONTINUITY"}
    # ...and the kernel no longer owns its code or any stream knowledge.
    assert "E_BUFFER_DISCONTINUITY" not in {e.value for e in ErrorCode}
    import axm_verify.logic as logic_mod

    logic_src = Path(logic_mod.__file__).read_text(encoding="utf-8")
    for token in ("cam_latents", "AXLF", "AXLR"):
        assert token not in logic_src, f"kernel verifier still knows about {token}"


# ── Determinism: same input -> byte-identical shard (RFC 0002 D2) ────────────

def _compile(workdir: Path, out_name: str) -> Path:
    candidates = workdir / "candidates.jsonl"
    content = workdir / "content"
    out = workdir / out_name
    proc = subprocess.run(
        [
            sys.executable, "-m", "axm_build.cli", "compile",
            str(candidates), str(content), str(out),
            "--private-key", str(workdir / "keys" / "pub.key"),
            "--namespace", "test/determinism",
            "--title", "Determinism Shard",
            "--created-at", "2026-07-02T00:00:00Z",
            "--license-spdx", "CC0-1.0",
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    return out


def _tree_bytes(root: Path) -> Dict[str, bytes]:
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in root.rglob("*")
        if p.is_file()
    }


def _signing_is_deterministic() -> bool:
    """Ed25519 (RFC 8032) is deterministic; ML-DSA-44 depends on the backend
    (dilithium-py signs deterministically here; liboqs uses hedged signing)."""
    from axm_build.sign import hybrid1_keygen, hybrid1_sign

    _, sk = hybrid1_keygen()
    return hybrid1_sign(sk, b"probe") == hybrid1_sign(sk, b"probe")


def test_compilation_is_reproducible(tmp_path: Path) -> None:
    from axm_build.sign import hybrid1_keygen

    # Fixed input material.
    (tmp_path / "content").mkdir()
    (tmp_path / "content" / "doc.txt").write_text(
        "Elevation supports hemorrhage control.\n", encoding="utf-8"
    )
    text = "Elevation supports hemorrhage control."
    candidate = {
        "type": "claim",
        "subject_label": "elevation",
        "predicate": "supports",
        "object_label": "hemorrhage control",
        "object_type": "entity",
        "tier": 2,
        "evidence": {
            "source_file": "doc.txt",
            "byte_start": 0,
            "byte_end": len(text.encode("utf-8")),
            "text": text,
        },
    }
    (tmp_path / "candidates.jsonl").write_text(
        json.dumps(candidate, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    keydir = tmp_path / "keys"
    keydir.mkdir()
    pk, sk = hybrid1_keygen()
    (keydir / "pub.key").write_bytes(sk)
    (keydir / "pub.pub").write_bytes(pk)

    out1 = _compile(tmp_path, "out1")
    out2 = _compile(tmp_path, "out2")

    tree1, tree2 = _tree_bytes(out1), _tree_bytes(out2)
    assert set(tree1) == set(tree2)

    deterministic_sig = _signing_is_deterministic()
    for relpath in sorted(tree1):
        if relpath == "sig/manifest.sig" and not deterministic_sig:
            # Hedged ML-DSA signing: bytes differ, but both must verify.
            continue
        assert tree1[relpath] == tree2[relpath], f"{relpath} is not reproducible"

    # Identity is the manifest hash: byte-identical manifests, one shard_id.
    assert derive_shard_id(tree1["manifest.json"]) == derive_shard_id(tree2["manifest.json"])

    # Regardless of signature determinism, both compilations verify.
    pub = keydir / "pub.pub"
    for out in (out1, out2):
        result = verify_shard(out, trusted_key_path=pub)
        assert result["status"] == "PASS", result["errors"]


def test_verification_is_deterministic(tmp_path: Path) -> None:
    shard = tmp_path / "gold"
    shutil.copytree(GOLD_SHARD, shard)
    first = verify_shard(shard, trusted_key_path=GOLD_PUB)
    second = verify_shard(shard, trusted_key_path=GOLD_PUB)
    assert first == second
    assert first["status"] == "PASS"


def test_gold_shard_id_is_stable() -> None:
    manifest_bytes = (GOLD_SHARD / "manifest.json").read_bytes()
    sid = derive_shard_id(manifest_bytes)
    assert re.fullmatch(r"sh1_[0-9a-f]{64}", sid)
    assert sid == derive_shard_id(manifest_bytes)
