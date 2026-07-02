"""
Executable contract for COMPATIBILITY.md
========================================

Every machine-checkable promise in COMPATIBILITY.md is asserted here, so the
document cannot silently drift from the code:

- Section 3: suite identifiers in the doc == axm_verify.const.KNOWN_SUITES
- Section 4: CLI exit codes (0 valid / 1 verification failed / 2 malformed),
  JSON on stdout, human-readable reasons on stderr
- Section 5: claim-schema field names in the doc == CLAIMS_SCHEMA columns
- Spec section 5.2: manifest field enforcement (E_MANIFEST_SCHEMA names the
  offending field)

The CLI is exercised via subprocess because the exit codes themselves are the
frozen contract.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from axm_verify.const import CLAIMS_SCHEMA, KNOWN_SUITES, MALFORMED_SHARD_CODES
from axm_verify.logic import verify_shard

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPATIBILITY_MD = REPO_ROOT / "COMPATIBILITY.md"
VECTORS = REPO_ROOT / "tests" / "vectors" / "shards"
VALID_MINIMAL = VECTORS / "valid" / "minimal"
TRUSTED_KEY = REPO_ROOT / "keys" / "canonical_test_publisher.pub"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run_cli(shard: Path, trusted_key: Path = TRUSTED_KEY) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "axm_verify.cli", "shard", str(shard), "--trusted-key", str(trusted_key)],
        capture_output=True,
        text=True,
    )


def _doc_section(number: int) -> str:
    """Return the body of '### <number>. ...' up to the next heading."""
    text = COMPATIBILITY_MD.read_text(encoding="utf-8")
    m = re.search(rf"^### {number}\..*?$(.*?)(?=^#{{2,3}} |\Z)", text, re.M | re.S)
    assert m, f"COMPATIBILITY.md section {number} not found"
    return m.group(1)


def _table_first_column_codes(section_body: str) -> list[str]:
    """Extract the backticked first cell of each data row in a markdown table."""
    out = []
    for line in section_body.splitlines():
        m = re.match(r"^\|\s*`([^`]+)`\s*\|", line)
        if m:
            out.append(m.group(1))
    return out


def _claims_schema_field_names() -> list[str]:
    try:
        return [f.name for f in CLAIMS_SCHEMA]  # pyarrow schema
    except AttributeError:
        return [name for name, _typ in CLAIMS_SCHEMA]  # duckdb fallback: list of tuples


# ── Section 4: exit-code contract ────────────────────────────────────────────

def test_exit_0_on_valid_shard() -> None:
    proc = _run_cli(VALID_MINIMAL)
    assert proc.returncode == 0, f"stdout={proc.stdout} stderr={proc.stderr}"
    result = json.loads(proc.stdout)
    assert result["status"] == "PASS"
    assert result["errors"] == []


def test_exit_0_with_vectors_own_publisher_key() -> None:
    proc = _run_cli(VALID_MINIMAL, trusted_key=VALID_MINIMAL / "sig" / "publisher.pub")
    assert proc.returncode == 0, f"stdout={proc.stdout} stderr={proc.stderr}"


@pytest.mark.parametrize("vector", ["bad_signature", "merkle_mismatch"])
def test_exit_1_on_verification_failure(vector: str) -> None:
    proc = _run_cli(VECTORS / "invalid" / vector)
    assert proc.returncode == 1, f"stdout={proc.stdout} stderr={proc.stderr}"
    result = json.loads(proc.stdout)
    assert result["status"] == "FAIL"
    # stderr carries one human-readable reason line per error
    stderr_lines = [ln for ln in proc.stderr.splitlines() if ln.strip()]
    assert len(stderr_lines) == len(result["errors"])
    for err, line in zip(result["errors"], stderr_lines):
        assert line.startswith(err["code"] + ":")


def test_exit_2_on_missing_manifest_vector() -> None:
    proc = _run_cli(VECTORS / "invalid" / "missing_manifest")
    assert proc.returncode == 2, f"stdout={proc.stdout} stderr={proc.stderr}"
    result = json.loads(proc.stdout)
    assert result["status"] == "FAIL"
    codes = {e["code"] for e in result["errors"]}
    assert codes and codes <= set(MALFORMED_SHARD_CODES)
    assert proc.stderr.strip(), "stderr must carry a human-readable reason"


def test_exit_2_on_empty_directory(tmp_path: Path) -> None:
    empty = tmp_path / "empty_shard"
    empty.mkdir()
    proc = _run_cli(empty)
    assert proc.returncode == 2, f"stdout={proc.stdout} stderr={proc.stderr}"


def test_exit_2_on_nonexistent_path(tmp_path: Path) -> None:
    # click's usage error for a missing PATH also exits 2, consistent with the contract
    proc = _run_cli(tmp_path / "does_not_exist")
    assert proc.returncode == 2


def test_stdout_is_json_even_on_failure() -> None:
    proc = _run_cli(VECTORS / "invalid" / "bad_signature")
    result = json.loads(proc.stdout)
    assert set(result) >= {"shard", "status", "error_count", "errors"}


# ── Section 3: suite identifiers must match KNOWN_SUITES ─────────────────────

def test_doc_suite_identifiers_match_code() -> None:
    doc_suites = _table_first_column_codes(_doc_section(3))
    assert set(doc_suites) == set(KNOWN_SUITES), (
        f"COMPATIBILITY.md section 3 lists {sorted(doc_suites)} "
        f"but KNOWN_SUITES is {sorted(KNOWN_SUITES)}"
    )


# ── Section 5: claim schema field names must match CLAIMS_SCHEMA ─────────────

def test_doc_claim_schema_fields_match_code() -> None:
    doc_fields = _table_first_column_codes(_doc_section(5))
    code_fields = _claims_schema_field_names()
    assert doc_fields == code_fields, (
        f"COMPATIBILITY.md section 5 lists {doc_fields} "
        f"but CLAIMS_SCHEMA is {code_fields}"
    )


# ── Section 2: frozen Merkle empty-root constant appears in the doc ──────────

def test_doc_states_frozen_mldsa44_empty_root() -> None:
    from axm_build.merkle import EMPTY_ROOT_MLDSA44

    assert EMPTY_ROOT_MLDSA44 in _doc_section(2), (
        "COMPATIBILITY.md section 2 must state the frozen "
        "axm-blake3-mldsa44 empty-root constant"
    )


# ── Section 4 doc text names the real invocation and exit codes ──────────────

def test_doc_section_4_states_real_invocation() -> None:
    body = _doc_section(4)
    assert "axm-verify shard" in body
    assert "--trusted-key" in body
    for code in sorted(MALFORMED_SHARD_CODES):
        assert code in body, f"section 4 must name malformed-shard code {code}"


# ── Spec 5.2: manifest schema enforcement (E_MANIFEST_SCHEMA names field) ────

def _mutated_copy(tmp_path: Path, drop_field: str) -> Path:
    shard = tmp_path / f"shard_no_{drop_field}"
    shutil.copytree(VALID_MINIMAL, shard)
    manifest_path = shard / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    del manifest[drop_field]
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    return shard


@pytest.mark.parametrize("field", ["spec_version", "sources"])
def test_manifest_missing_field_reports_manifest_schema(tmp_path: Path, field: str) -> None:
    shard = _mutated_copy(tmp_path, field)
    result = verify_shard(shard, trusted_key_path=TRUSTED_KEY)
    assert result["status"] == "FAIL"
    matching = [
        e for e in result["errors"]
        if e["code"] == "E_MANIFEST_SCHEMA" and field in e["message"]
    ]
    assert matching, (
        f"Expected an E_MANIFEST_SCHEMA error naming '{field}', got {result['errors']}"
    )
    # Manifest validation runs before signature verification: no sig error reported
    assert all(e["code"] != "E_SIG_INVALID" for e in result["errors"])


def test_manifest_schema_violation_exits_1_not_2(tmp_path: Path) -> None:
    shard = _mutated_copy(tmp_path, "spec_version")
    proc = _run_cli(shard)
    assert proc.returncode == 1, f"stdout={proc.stdout} stderr={proc.stderr}"
    assert "E_MANIFEST_SCHEMA" in proc.stderr
    assert "spec_version" in proc.stderr


def test_version_is_single_sourced() -> None:
    """axm_verify.__version__ must match the installed package version.

    RFC 0002 D8 flagged the drift (module said 1.1.0 while pyproject said
    1.2.0); this pins them together so a release can't ship disagreeing
    version strings again.
    """
    import importlib.metadata

    import axm_verify

    assert axm_verify.__version__ == importlib.metadata.version("axm-genesis")
