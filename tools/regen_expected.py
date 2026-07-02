#!/usr/bin/env python3
"""Regenerate tests/vectors/shards/EXPECTED.md from the vectors on disk.

EXPECTED.md is the machine-readable ground truth that the conformance
suite (tests/test_verifier.py) parametrizes off. This tool walks every
vector under tests/vectors/shards/{valid,invalid}/, runs the axm-verify
CLI on each exactly as the suite documents (``axm-verify shard <shard>
--trusted-key tests/keys/ci_test_publisher.pub``), and rewrites the
table from the observed results — so the committed file can always be
re-derived from the vectors themselves.

Usage:
  python tools/regen_expected.py            # rewrite EXPECTED.md in place
  python tools/regen_expected.py --check    # drift gate: regenerate to a
                                            # temp file, diff against the
                                            # committed file, exit nonzero
                                            # (printing the diff) on drift
"""
from __future__ import annotations

import argparse
import difflib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SHARD_VECTORS_DIR = REPO_ROOT / "tests" / "vectors" / "shards"
EXPECTED_MD = SHARD_VECTORS_DIR / "EXPECTED.md"
TRUSTED_KEY = REPO_ROOT / "tests" / "keys" / "ci_test_publisher.pub"

# Header prose is part of the frozen file format: reproduced byte-for-byte.
HEADER = """\
# Shard vector expectations (v1)

Machine-readable ground truth for every shard vector in this directory.
Each row records the outcome OBSERVED by running the reference verifier on
the vector at generation time; the conformance suite consumes this table
and must reproduce it exactly.

- Verifier invocation: `axm-verify shard <shard> --trusted-key tests/keys/ci_test_publisher.pub`
- `shard` paths are relative to `tests/vectors/shards/`.
- `error_codes` is `;`-separated and sorted; `-` means none.
- Exit codes (frozen contract): 0 = PASS; 2 = FAIL where every error code is in
  {E_LAYOUT_MISSING, E_SCHEMA_MISSING, E_SIG_MISSING} (or the path is missing);
  1 = any other FAIL.
- Each vector directory has a README.md documenting the exact mutation.
- `invalid/invalid_embodied_gap` is binding only for verifiers implementing
  the `embodied@1` profile; a verifier without it must report the profile
  under `profiles_unchecked` (and would PASS that shard).

| vector | shard | exit_code | status | error_codes | profiles_checked | profiles_unchecked |
|--------|-------|-----------|--------|-------------|------------------|--------------------|
"""


def verifier_command() -> list[str]:
    """The axm-verify CLI, as installed; fall back to the module form."""
    exe = shutil.which("axm-verify")
    if exe:
        return [exe]
    return [sys.executable, "-m", "axm_verify.cli"]


def run_vector(shard_rel: str) -> dict:
    """Run the CLI on one shard and return its parsed row fields."""
    cmd = verifier_command() + [
        "shard",
        str(SHARD_VECTORS_DIR / shard_rel),
        "--trusted-key",
        str(TRUSTED_KEY),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"axm-verify produced no JSON for {shard_rel} "
            f"(exit {proc.returncode}): {proc.stdout!r} {proc.stderr!r}"
        ) from exc
    codes = sorted({e["code"] for e in result["errors"]})
    return {
        "exit_code": proc.returncode,
        "status": result["status"],
        "error_codes": ";".join(codes) if codes else "-",
        "profiles_checked": ",".join(result["profiles_checked"]) or "-",
        "profiles_unchecked": ",".join(result["profiles_unchecked"]) or "-",
    }


def generate() -> str:
    lines = [HEADER]
    for kind in ("valid", "invalid"):
        kind_dir = SHARD_VECTORS_DIR / kind
        for vector_dir in sorted(p for p in kind_dir.iterdir() if p.is_dir()):
            vector = f"{kind}/{vector_dir.name}"
            shard = f"{vector}/shard"
            row = run_vector(shard)
            lines.append(
                "| {vector} | {shard} | {exit_code} | {status} | {error_codes} "
                "| {profiles_checked} | {profiles_unchecked} |\n".format(
                    vector=vector, shard=shard, **row
                )
            )
    return "".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; diff regenerated output against the committed "
        "EXPECTED.md and exit nonzero on drift",
    )
    args = parser.parse_args()

    regenerated = generate()

    if not args.check:
        EXPECTED_MD.write_text(regenerated, encoding="utf-8")
        print(f"wrote {EXPECTED_MD.relative_to(REPO_ROOT)}")
        return 0

    # Regenerate to a temp file, then diff it against the committed file.
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", suffix=".EXPECTED.md", delete=False
    ) as tmp:
        tmp.write(regenerated)
        tmp_path = Path(tmp.name)
    try:
        committed = EXPECTED_MD.read_text(encoding="utf-8")
        regenerated = tmp_path.read_text(encoding="utf-8")
        if regenerated == committed:
            print("EXPECTED.md is up to date (byte-identical to regenerated output)")
            return 0

        diff = difflib.unified_diff(
            committed.splitlines(keepends=True),
            regenerated.splitlines(keepends=True),
            fromfile="tests/vectors/shards/EXPECTED.md (committed)",
            tofile=f"{tmp_path} (regenerated)",
        )
        sys.stdout.writelines(diff)
        print("\nEXPECTED.md has drifted from the vectors on disk.", file=sys.stderr)
        print("Regenerate it with: python tools/regen_expected.py", file=sys.stderr)
        return 1
    finally:
        tmp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
