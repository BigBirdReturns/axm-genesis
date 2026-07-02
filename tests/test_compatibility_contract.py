"""The frozen compatibility contract (COMPATIBILITY.md).

Two halves:
1. The CLI exit-code contract, exercised end-to-end via subprocess against
   every shard vector in EXPECTED.md (0 pass / 1 fail / 2 malformed).
2. Drift checks that pin COMPATIBILITY.md and the packaging metadata to the
   code: exactly one suite identifier, the frozen claims schema, and the
   single-sourced version.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from typing import List

import pytest

import axm_verify
from axm_verify.const import CLAIMS_SCHEMA, SUITE_HYBRID1
from helpers import (
    CI_PUB_PATH,
    COMPATIBILITY_MD,
    PYPROJECT_TOML,
    REPO_ROOT,
    SHARD_VECTORS_DIR,
    parse_expected_rows,
    requires_mldsa_backend,
)

ROWS = parse_expected_rows()


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "axm_verify.cli", "shard", *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


# ── Exit codes 0/1/2, via subprocess, on the frozen vectors ──────────────────

@requires_mldsa_backend
@pytest.mark.parametrize("row", ROWS, ids=[r["vector"] for r in ROWS])
def test_cli_exit_code_matches_expected_md(row: dict) -> None:
    shard = SHARD_VECTORS_DIR / row["shard"]
    proc = _run_cli(str(shard), "--trusted-key", str(CI_PUB_PATH))

    assert proc.returncode == row["exit_code"], proc.stderr

    # stdout is exactly one machine-readable JSON line.
    stdout_lines = proc.stdout.strip().splitlines()
    assert len(stdout_lines) == 1
    result = json.loads(stdout_lines[0])
    assert result["status"] == row["status"]
    assert sorted({e["code"] for e in result["errors"]}) == row["error_codes"]
    assert result["profiles_checked"] == row["profiles_checked"]
    assert result["profiles_unchecked"] == row["profiles_unchecked"]

    # stderr carries one "<code>: <message>" line per error; silent on PASS.
    if row["exit_code"] == 0:
        assert proc.stderr == ""
    else:
        stderr_codes = {line.split(":", 1)[0] for line in proc.stderr.strip().splitlines()}
        assert stderr_codes == set(row["error_codes"])


@requires_mldsa_backend
def test_cli_nonexistent_path_exits_2() -> None:
    proc = _run_cli("/no/such/shard", "--trusted-key", str(CI_PUB_PATH))
    assert proc.returncode == 2


@requires_mldsa_backend
def test_cli_missing_trusted_key_option_exits_2() -> None:
    shard = SHARD_VECTORS_DIR / "valid" / "minimal" / "shard"
    proc = _run_cli(str(shard))
    assert proc.returncode == 2


# ── COMPATIBILITY.md drift checks ────────────────────────────────────────────

def _doc() -> str:
    return COMPATIBILITY_MD.read_text(encoding="utf-8")


# Tokens that share the axm- prefix but are packages/tools, not suites.
_NON_SUITE_TOKENS = {"axm-genesis", "axm-verify", "axm-build", "axm-core", "axm-chat"}


def test_doc_names_exactly_one_suite() -> None:
    doc = _doc()
    tokens = set(re.findall(r"\baxm-[a-z0-9][a-z0-9-]*\b", doc)) - _NON_SUITE_TOKENS
    assert tokens == {SUITE_HYBRID1}, (
        f"COMPATIBILITY.md must name exactly the {SUITE_HYBRID1!r} suite, found {sorted(tokens)}"
    )
    assert "axm-blake3-mldsa44" not in doc  # the deleted v0.x suite
    assert SUITE_HYBRID1 == "axm-hybrid1"


def _first_column_fields(table_lines: List[str]) -> List[str]:
    fields = []
    for line in table_lines:
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        m = re.fullmatch(r"`([A-Za-z_][A-Za-z0-9_]*)`", cells[0])
        if m:
            fields.append(m.group(1))
    return fields


def test_doc_claims_schema_matches_code() -> None:
    """The claims field table in COMPATIBILITY.md == axm_verify CLAIMS_SCHEMA."""
    doc = _doc()
    tables: List[List[str]] = []
    current: List[str] = []
    for line in doc.splitlines():
        if line.lstrip().startswith("|"):
            current.append(line)
        elif current:
            tables.append(current)
            current = []
    if current:
        tables.append(current)

    claims_tables = [t for t in tables if any("`claim_id`" in line for line in t)]
    assert claims_tables, "COMPATIBILITY.md must document the frozen claims schema"
    documented = {f for t in claims_tables for f in _first_column_fields(t)}
    assert documented == set(CLAIMS_SCHEMA)
    assert set(CLAIMS_SCHEMA) == {
        "claim_id", "subject", "predicate", "object", "object_type", "tier",
    }


def test_doc_core_tables_are_jsonl_not_parquet() -> None:
    doc = _doc()
    assert "claims.jsonl" in doc
    for legacy in ("claims.parquet", "entities.parquet", "provenance.parquet",
                   "spans.parquet"):
        assert legacy not in doc, f"COMPATIBILITY.md still references {legacy}"


def test_doc_pins_the_frozen_cli_contract() -> None:
    doc = _doc()
    assert "axm-verify shard" in doc
    for code in ("E_LAYOUT_MISSING", "E_SCHEMA_MISSING", "E_SIG_MISSING"):
        assert code in doc, f"COMPATIBILITY.md must define the exit-2 code set ({code})"


# ── Version single-sourcing ──────────────────────────────────────────────────

def test_version_is_single_sourced() -> None:
    assert axm_verify.__version__ == "1.0.0rc1"

    pyproject = tomllib.loads(PYPROJECT_TOML.read_text(encoding="utf-8"))
    project = pyproject["project"]
    if "version" in project:
        assert project["version"] == axm_verify.__version__
    else:
        assert "version" in project.get("dynamic", [])
        attr = pyproject["tool"]["setuptools"]["dynamic"]["version"]["attr"]
        assert attr == "axm_verify.__version__"


def test_installed_package_version_matches() -> None:
    from importlib import metadata

    try:
        installed = metadata.version("axm-genesis")
    except metadata.PackageNotFoundError:
        pytest.skip("axm-genesis is not installed in this environment")
    assert installed == axm_verify.__version__
