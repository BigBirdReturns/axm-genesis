"""Shared helpers for the AXM Genesis v1 conformance suite.

Pure functions and path constants only — fixtures live in conftest.py.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import pytest

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent

VECTORS_DIR = TESTS_DIR / "vectors"
SHARD_VECTORS_DIR = VECTORS_DIR / "shards"
EXPECTED_MD = SHARD_VECTORS_DIR / "EXPECTED.md"

CI_KEY_PATH = TESTS_DIR / "keys" / "ci_test_publisher.key"
CI_PUB_PATH = TESTS_DIR / "keys" / "ci_test_publisher.pub"

GOLD_SHARD = REPO_ROOT / "shards" / "gold" / "fm21-11-hemorrhage-v2"
GOLD_PUB = REPO_ROOT / "keys" / "gold-v2-provisional.pub"
GOLD_CHECKSUMS = REPO_ROOT / "shards" / "gold" / "CHECKSUMS.sha256"

COMPATIBILITY_MD = REPO_ROOT / "COMPATIBILITY.md"
CONFORMANCE_MD = REPO_ROOT / "spec" / "v1" / "CONFORMANCE.md"
PYPROJECT_TOML = REPO_ROOT / "pyproject.toml"

MINIMAL_SHARD = SHARD_VECTORS_DIR / "valid" / "minimal" / "shard"
EMBODIED_SHARD = SHARD_VECTORS_DIR / "valid" / "valid_embodied" / "shard"
EMBODIED_GAP_SHARD = SHARD_VECTORS_DIR / "invalid" / "invalid_embodied_gap" / "shard"

MISSING_BACKEND_FRAGMENT = "No ML-DSA-44 backend installed"


def mldsa_backend_available() -> bool:
    """True when an ML-DSA-44 backend (liboqs or dilithium-py) is importable."""
    try:
        import oqs  # noqa: F401
        return True
    except Exception:
        pass
    try:
        from dilithium_py.ml_dsa import ML_DSA_44  # noqa: F401
        return True
    except Exception:
        return False


requires_mldsa_backend = pytest.mark.skipif(
    not mldsa_backend_available(),
    reason="requires an ML-DSA-44 backend (liboqs-python or dilithium-py)",
)


def parse_expected_rows() -> List[Dict[str, Any]]:
    """Parse tests/vectors/shards/EXPECTED.md into structured rows.

    EXPECTED.md is the machine-readable ground truth for every shard
    vector; parsing it directly means the vectors and the tests cannot
    drift apart.
    """
    rows: List[Dict[str, Any]] = []
    for line in EXPECTED_MD.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) != 7 or cells[0] == "vector" or set(cells[0]) <= {"-"}:
            continue
        vector, shard, exit_code, status, error_codes, checked, unchecked = cells
        rows.append(
            {
                "vector": vector,
                "shard": shard,
                "exit_code": int(exit_code),
                "status": status,
                "error_codes": [] if error_codes == "-" else sorted(error_codes.split(";")),
                "profiles_checked": [] if checked == "-" else checked.split(","),
                "profiles_unchecked": [] if unchecked == "-" else unchecked.split(","),
            }
        )
    assert rows, f"no vector rows parsed from {EXPECTED_MD}"
    return rows


def copy_shard(src: Path, dst: Path) -> Path:
    """Copy a shard directory tree for mutation."""
    shutil.copytree(src, dst)
    return dst


def load_manifest(shard_dir: Path) -> Dict[str, Any]:
    return json.loads((shard_dir / "manifest.json").read_bytes())


def reseal_shard_bytes(shard_dir: Path, manifest_bytes: bytes, secret_key: bytes) -> None:
    """Write exact manifest bytes and a fresh hybrid signature over them."""
    from axm_build.sign import hybrid1_public_key, hybrid1_sign, manifest_signing_message

    (shard_dir / "manifest.json").write_bytes(manifest_bytes)
    sig_dir = shard_dir / "sig"
    sig_dir.mkdir(exist_ok=True)
    (sig_dir / "publisher.pub").write_bytes(hybrid1_public_key(secret_key))
    (sig_dir / "manifest.sig").write_bytes(
        hybrid1_sign(secret_key, manifest_signing_message(manifest_bytes))
    )


def reseal_shard(shard_dir: Path, manifest: Dict[str, Any], secret_key: bytes) -> None:
    """Canonically encode the manifest, write it, and re-sign the shard."""
    from axm_build.jsonl import canonical_json_bytes

    reseal_shard_bytes(shard_dir, canonical_json_bytes(manifest), secret_key)


def mutate_and_verify(
    shard_dir: Path,
    secret_key: bytes,
    mutate: Optional[Callable[[Dict[str, Any]], Any]] = None,
) -> Dict[str, Any]:
    """Apply a manifest mutation, re-sign, and run the reference verifier.

    The mutator edits the manifest dict in place (or returns a replacement).
    The shard is re-signed after mutation, so any failure is attributable to
    the mutation itself, never to a stale signature.
    """
    from axm_verify.logic import verify_shard

    manifest = load_manifest(shard_dir)
    if mutate is not None:
        replaced = mutate(manifest)
        if replaced is not None:
            manifest = replaced
    reseal_shard(shard_dir, manifest, secret_key)
    return verify_shard(shard_dir, trusted_key_path=CI_PUB_PATH)


def error_codes(result: Dict[str, Any]) -> List[str]:
    """Sorted, de-duplicated error codes from a verifier result."""
    return sorted({e["code"] for e in result["errors"]})


def expected_exit_code(result: Dict[str, Any]) -> int:
    """Map a verifier result onto the frozen CLI exit-code contract."""
    from axm_verify.const import MALFORMED_SHARD_CODES

    if result["status"] == "PASS":
        return 0
    codes = {e["code"] for e in result["errors"]}
    return 2 if codes and codes <= MALFORMED_SHARD_CODES else 1
