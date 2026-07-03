#!/usr/bin/env bash
# Bring ONE repo under the kernel contract — the unit of work behind ALIGNMENT.md.
#
# It answers the four ledger questions for a repo — Site, CI, Genesis
# relationship, Drift — and, with --fix, scaffolds a missing guarded pages.yml or
# self-verifying CI from the template. It never edits code, never commits, never
# guesses violations away: --fix only adds the two workflow files a spoke should
# have. You review the diff, fix the violations that matter, and merge.
#
# Read-only by default. Run from an axm-genesis checkout:
#   tools/align-spoke.sh <repo-dir> [--type spoke|kernel|runtime|demo|archive] [--fix]
set -uo pipefail

GENESIS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="$GENESIS_DIR/templates/spoke-template/.github/workflows"
DRIFT="$GENESIS_DIR/tools/drift-check.sh"

REPO="" TYPE="spoke" FIX=""
while [ $# -gt 0 ]; do
  case "$1" in
    --type) TYPE="${2:?}"; shift 2 ;;
    --fix)  FIX=1; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) REPO="$1"; shift ;;
  esac
done
[ -n "$REPO" ] && [ -d "$REPO" ] || { echo "usage: align-spoke.sh <repo-dir> [--type ...] [--fix]"; exit 2; }
REPO="${REPO%/}"

f() { printf "  %-9s %s\n" "$1" "$2"; }
echo "== align: $(basename "$REPO")  [type: $TYPE${FIX:+, --fix}] =="

# 1. Site — a Pages deploy workflow. Kernels/runtimes/demos publish too; only
#    an archive is expected to have none.
if [ -f "$REPO/.github/workflows/pages.yml" ]; then
  f site "pages.yml present"
elif [ -n "$FIX" ] && [ "$TYPE" != archive ]; then
  mkdir -p "$REPO/.github/workflows"; cp "$TEMPLATE/pages.yml" "$REPO/.github/workflows/pages.yml"
  f site "pages.yml SCAFFOLDED (guarded — publishes once index.html exists)"
elif [ "$TYPE" = archive ]; then
  f site "none (archive — expected)"
else
  f site "MISSING (re-run with --fix)"
fi

# 2. CI — a workflow of any kind. A spoke should run tests + the drift check;
#    scaffold the template CI when a spoke has none.
if [ -f "$REPO/.github/workflows/ci.yml" ]; then
  if [ "$TYPE" = spoke ] && ! grep -q 'drift-check.sh' "$REPO/.github/workflows/ci.yml"; then
    f ci "ci.yml present (spoke: add the drift-check step)"
  else
    f ci "ci.yml present"
  fi
elif [ -n "$FIX" ] && [ "$TYPE" = spoke ]; then
  cp "$TEMPLATE/ci.yml" "$REPO/.github/workflows/ci.yml"
  f ci "ci.yml SCAFFOLDED (set the spoke path + confirm the kernel ref)"
else
  f ci "MISSING${FIX:+ (only auto-scaffolded for --type spoke)}"
fi

# 3. Genesis relationship — report the actual dependency line + the CI kernel ref.
if [ "$TYPE" = kernel ]; then
  f genesis "IS the kernel (no dependency expected)"
else
  pin="$(grep -rhE 'axm-genesis' "$REPO" --include=*.toml 2>/dev/null \
          | sed 's/^[[:space:]]*//' \
          | grep -vE '^#|github\.io' \
          | grep -E 'git\+|[<>=]|axm-genesis[^ ]*@' \
          | head -1 \
          | sed 's/[[:space:]]*$//; s/^"//; s/",\{0,1\}$//')"
  ref="$(grep -rhoE 'ref:[[:space:]]*[0-9a-f]{7,40}' "$REPO"/.github/workflows/*.yml 2>/dev/null | head -1 | tr -s ' ')"
  if [ -n "$pin" ]; then
    f genesis "$pin${ref:+   ($ref)}"
  elif [ "$TYPE" = runtime ]; then
    f genesis "hub — expect axm-genesis + spoke-host contract${ref:+   ($ref)}"
  else
    f genesis "NONE FOUND — a spoke must pin/resolve axm-genesis"
  fi
fi

# 4. Drift — the kernel-boundary lint (skip for the kernel itself).
if [ "$TYPE" = kernel ]; then
  f drift "n/a (this repo defines the boundary)"
else
  out="$(bash "$DRIFT" "$REPO" 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ]; then f drift "clean"; else f drift "VIOLATIONS:"; echo "$out" | sed 's/^/      /'; fi
fi
