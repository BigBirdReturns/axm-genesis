#!/usr/bin/env bash
# Flip a repo's GitHub Pages source to GitHub Actions (build_type=workflow).
#
# There is no account-wide "default all new repos to Actions Pages" switch —
# GitHub only exposes this per repo. This wraps the one API that does it:
#   POST /repos/{owner}/{repo}/pages   (create a site in workflow mode)
#   PUT  /repos/{owner}/{repo}/pages   (update an existing site to workflow mode)
# https://docs.github.com/en/rest/pages/pages
#
# Requires: `gh` authenticated with a token that has BOTH Pages: write and
# Administration: write on the repo (repo admin / maintainer, or a fine-grained
# token with those two scopes). Run it wherever those creds live — a repo
# bootstrap step, CI with a PAT, or your laptop. It is a settings flip, not a
# code change; pair it with the pages.yml workflow (which does the publishing).
#
# Usage:   OWNER=BigBirdReturns tools/bootstrap-pages.sh <repo> [--dry-run]
set -euo pipefail

OWNER="${OWNER:-BigBirdReturns}"
REPO="${1:?usage: bootstrap-pages.sh <repo> [--dry-run]}"
DRY=""; [ "${2:-}" = "--dry-run" ] && DRY=1
API="/repos/${OWNER}/${REPO}/pages"

# --dry-run needs no gh and no network: just show what would run.
if [ -n "$DRY" ]; then
  echo "== ${OWNER}/${REPO}: dry-run — set Pages build_type=workflow =="
  echo "  if no site exists yet:  gh api --method POST -H 'Accept: application/vnd.github+json' ${API} -f build_type=workflow"
  echo "  if a site exists:       gh api --method PUT  -H 'Accept: application/vnd.github+json' ${API} -f build_type=workflow"
  echo "  (the live run picks POST vs PUT automatically, then verifies)"
  exit 0
fi

command -v gh >/dev/null 2>&1 || { echo "error: gh CLI not found (needs gh + a token with Pages+Administration write)"; exit 2; }

# Choose create vs update by whether a Pages site already exists.
if gh api "$API" >/dev/null 2>&1; then
  method=PUT; verb="update existing Pages to workflow mode"
else
  method=POST; verb="create Pages in workflow mode"
fi

echo "== ${OWNER}/${REPO}: ${verb} =="
if ! gh api --method "$method" -H "Accept: application/vnd.github+json" "$API" -f build_type=workflow; then
  # POST can 409 if a site raced into existence; fall back to PUT.
  [ "$method" = POST ] || exit 1
  echo "  POST failed (site may already exist) — retrying as PUT"
  gh api --method PUT -H "Accept: application/vnd.github+json" "$API" -f build_type=workflow
fi

gh api "$API" -q '"  -> build_type=" + (.build_type // "?") + "  status=" + (.status // "null") + "  url=" + (.html_url // "?")'
echo "  Pages source is now GitHub Actions. The pages.yml workflow publishes on the next push to the default branch."
