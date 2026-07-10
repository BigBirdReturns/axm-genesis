#!/usr/bin/env bash
# AXM doc-truth sweep — verifies that cross-repo doc pointers actually resolve.
#
# The family's CLAUDE.md / RFC / ADR files constantly point at files in a
# *sibling* repo ("axm-genesis `docs/CONTINUITY.md`", "world's
# `tests/world/constitution.test.ts`", ...). Nothing ever checked those
# pointers mechanically — docs/RFC_FAMILY_DOCTRINE.md PR 083 exists because one
# of them (axm-genesis docs/CONTINUITY.md, cited by both game clients'
# CLAUDE.md) turned out not to exist anywhere. This script is the mechanical
# check so that can't happen silently again.
#
# It lives in axm-genesis (root of the family, like drift-check.sh) and is
# re-runnable against the three repo checkouts (genesis itself + the two game
# clients, arc and world) any time — including as the doctrine lane's own
# capstone receipt (RFC PR 090).
#
# Usage:
#   bash tools/doc-truth-sweep.sh [GENESIS_DIR ARC_DIR WORLD_DIR] [--list]
#   env overrides: GENESIS_REPO / ARC_REPO / WORLD_REPO
#   Positional args, if given, override the env vars; both are optional and
#   default to genesis's own checkout (this script's repo) and its siblings
#   ../axm-arc, ../axm-world.
#
# Modes:
#   default   — print FINDING lines only (missing/unresolvable pointers).
#   --list    — print every checked pointer with its status (the receipt).
#
# Exit: 0 if every pointer resolved, 1 if any finding (missing source repo,
# missing hard-list target, or any extracted pointer that doesn't resolve). A
# pointer this script cannot resolve — e.g. because the target repo checkout
# isn't even present — is reported as a FINDING, never silently skipped.
set -uo pipefail

# ---------------------------------------------------------------------------
# 0. Resolve the three repo roots.
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GENESIS_SELF="$(cd "$SCRIPT_DIR/.." && pwd)"
SIBLING_DIR="$(dirname "$GENESIS_SELF")"

LIST_MODE=0
POSITIONAL=()
for arg in "$@"; do
  case "$arg" in
    --list) LIST_MODE=1 ;;
    *) POSITIONAL+=("$arg") ;;
  esac
done

GENESIS_DIR="${POSITIONAL[0]:-${GENESIS_REPO:-$GENESIS_SELF}}"
ARC_DIR="${POSITIONAL[1]:-${ARC_REPO:-$SIBLING_DIR/axm-arc}}"
WORLD_DIR="${POSITIONAL[2]:-${WORLD_REPO:-$SIBLING_DIR/axm-world}}"

# Normalize to absolute paths where possible (without requiring existence —
# a missing dir must still produce a FINDING for anything that points at it,
# never be swallowed by a `cd` failure).
abspath() { local p="$1"; if [ -d "$p" ]; then (cd "$p" && pwd); else echo "$p"; fi; }
GENESIS_DIR="$(abspath "$GENESIS_DIR")"
ARC_DIR="$(abspath "$ARC_DIR")"
WORLD_DIR="$(abspath "$WORLD_DIR")"

status=0
checked=0
findings=0

dir_for() {  # dir_for <repo-name: genesis|arc|world>
  case "$1" in
    genesis) echo "$GENESIS_DIR" ;;
    arc) echo "$ARC_DIR" ;;
    world) echo "$WORLD_DIR" ;;
  esac
}

# ---------------------------------------------------------------------------
# 1. Resolver — does a claimed path exist in a target repo?
# ---------------------------------------------------------------------------
# A path containing "/" is checked at its exact location relative to the
# target repo root (files and directories both count — trailing slash is
# stripped first). A bare filename (no "/") is checked by basename search
# anywhere in the repo, skipping vendor/build noise — doc prose regularly
# names a file without its full path (e.g. "genesis's `drift-check.sh`").
resolve() {  # resolve <target-repo-name> <path> -> 0 found, 1 missing
  local target="$1" path="$2" dir
  dir="$(dir_for "$target")"
  path="${path%/}"
  [ -n "$path" ] || return 1
  if [ ! -d "$dir" ]; then
    return 1
  fi
  if [[ "$path" == */* ]]; then
    [ -e "$dir/$path" ]
    return $?
  fi
  find "$dir" \
    \( -path '*/.git' -o -path '*/node_modules' -o -path '*/dist' -o -path '*/build' -o -path '*/__pycache__' -o -path '*/.venv' -o -path '*/venv' \) -prune -o \
    -name "$path" -print -quit 2>/dev/null | grep -q .
}

# ---------------------------------------------------------------------------
# 2. Path-like filter — a backtick/bare capture only counts as a real
#    cross-repo file claim, not incidental prose, if it looks like a path:
#    no whitespace/parens (excludes shell snippets, function calls, prose
#    fragments swallowed between two unrelated backticks), and either
#    contains a "/" or ends in a whitelisted file extension (excludes
#    version strings like "1.0.0", storage keys like "axm-arc:save:v1",
#    bare words like "main" or a cartridge codename like "severed-march").
#    Conservative on purpose: false negatives here are fine, false positives
#    are not (RFC_FAMILY_DOCTRINE.md PR 083 hard wall).
EXT_RE='\.(md|ts|tsx|mts|cts|js|jsx|mjs|cjs|json|sh|py|toml|ya?ml|txt|html?|css|arc\.json)$'
path_like() {
  local p="$1"
  [[ "$p" == *' '* || "$p" == *'('* || "$p" == *')'* || "$p" == *'|'* || "$p" == *'"'* ]] && return 1
  [[ -z "$p" ]] && return 1
  if [[ "$p" == */* ]] || [[ "$p" =~ $EXT_RE ]]; then
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# 3. Extraction — a small, explicit, documented pattern set. Two forms, run
#    once per known repo token (arc/world/genesis) so we always know which
#    repo a hit targets:
#
#    Pattern A: `axm-<repo>` mentioned in prose, immediately (optionally via
#    "'s", " at ", " in ", or " holds ") followed by a backtick-quoted path —
#    e.g. "axm-genesis `docs/CONTINUITY.md`", "axm-world's
#    `RECONCILIATION.md`", "axm-arc at `src/engine/strategy-board/`". Uses
#    \K + lookahead so the capture is exactly the backtick content.
#
#    Pattern B: `axm-<repo> <path.ext>` with no backticks at all, or both
#    wrapped in one shared backtick pair — e.g. "axm-world
#    docs/adr/0002-platform-constitution.md". Requires a real extension so it
#    doesn't fire on version strings.
#
# Both patterns are deliberately narrow: they require the literal `axm-`
# prefix, so generic prose about "the world" (this is a game about worlds)
# never matches. That is an intentional false-negative: a bare "world's
# `path`" possessive without the axm- prefix is NOT extracted, because
# "world" alone is highly ambiguous in these codebases' own prose. Anything
# that slips through as a false negative here is still covered by the hard
# list in section 4 for the load-bearing pointers named in CONTINUITY.md.
DOC_GLOB='*.md'
PRUNE_RE='/(\.git|node_modules|dist|build|__pycache__|\.venv|venv)/'

extract_for_repo() {  # extract_for_repo <source-dir> <repo-token>
  local src="$1" repo="$2"
  [ -d "$src" ] || return 0
  # Pattern A
  grep -rnoP "axm-${repo}(?:'s)?(?:\s+(?:at|in|holds))?\s*\`\K[^\`\n]{1,200}(?=\`)" \
    --include="$DOC_GLOB" "$src" 2>/dev/null | grep -vE "$PRUNE_RE"
  # Pattern B
  grep -rnoP "axm-${repo}\s+\K[A-Za-z0-9_][A-Za-z0-9_./-]*\.[A-Za-z0-9]+" \
    --include="$DOC_GLOB" "$src" 2>/dev/null | grep -vE "$PRUNE_RE"
}

report_line() {  # report_line <status: OK|MISS> <where> <target> <path>
  local st="$1" where="$2" target="$3" path="$4"
  checked=$((checked + 1))
  if [ "$st" = OK ]; then
    [ "$LIST_MODE" -eq 1 ] && echo "[OK]   $where -> axm-${target} \`${path}\`"
  else
    findings=$((findings + 1))
    status=1
    echo "FINDING: $where -> claimed axm-${target} \`${path}\` (not found in axm-${target} checkout)"
  fi
}

# ---------------------------------------------------------------------------
# 4. Hard list — the load-bearing pointers CONTINUITY.md states by name.
#    Encoded explicitly (not discovered) so this sweep still catches their
#    loss even if every prose mention of them were reworded or deleted.
# ---------------------------------------------------------------------------
# repo:path  (one per required pointer)
HARD_LIST=(
  "world:docs/adr/0002-platform-constitution.md"
  "world:tests/world/constitution.test.ts"
  "genesis:docs/ECOSYSTEM-WIRING.md"
  "genesis:tools/drift-check.sh"
  "arc:docs/COMPATIBILITY_ATLAS.md"
  "arc:docs/drills/README.md"
  # Lane RFCs named in CONTINUITY.md's record table:
  "arc:docs/RFC_GUILD_HALL.md"
  "arc:docs/RFC_EXPANSION_ARCHIVE.md"
  "arc:docs/RFC_WORKSHOP.md"
  "arc:docs/RFC_CARTRIDGE_LIBRARY.md"
  "world:docs/design/RFC_APPLIANCE_EXPANSION.md"
  "genesis:docs/RFC_FAMILY_DOCTRINE.md"
)

for entry in "${HARD_LIST[@]}"; do
  target="${entry%%:*}"
  path="${entry#*:}"
  if resolve "$target" "$path"; then
    report_line OK "HARDLIST" "$target" "$path"
  else
    report_line MISS "HARDLIST" "$target" "$path"
  fi
done

# ---------------------------------------------------------------------------
# 5. Cross-repo pointer sweep — every repo's docs, checked against every repo.
# ---------------------------------------------------------------------------
for source_name in genesis arc world; do
  source_dir="$(dir_for "$source_name")"
  if [ ! -d "$source_dir" ]; then
    echo "FINDING: source repo axm-${source_name} not found at expected path (cannot sweep its docs)"
    findings=$((findings + 1))
    status=1
    continue
  fi
  for target_name in genesis arc world; do
    while IFS=: read -r file line path; do
      [ -n "${file:-}" ] || continue
      # Path-like filter (post-extraction, applies to both patterns A and B).
      path_like "$path" || continue
      rel="${file#"$source_dir"/}"
      where="axm-${source_name}/${rel}:${line}"
      if resolve "$target_name" "$path"; then
        report_line OK "$where" "$target_name" "$path"
      else
        report_line MISS "$where" "$target_name" "$path"
      fi
    done < <(extract_for_repo "$source_dir" "$target_name" | sort -u)
  done
done

# ---------------------------------------------------------------------------
# 6. Summary.
# ---------------------------------------------------------------------------
if [ "$status" -eq 0 ]; then
  echo "✓ doc-truth-sweep: clean — ${checked} cross-repo pointer(s) verified, 0 findings"
else
  echo "✗ doc-truth-sweep: ${findings} finding(s) out of ${checked} pointer(s) checked"
fi

exit $status
