# Agent operating protocol

## Driver / hands separation

The most capable model in a session is the DRIVER. The driver designs,
adjudicates divergences, reviews summaries and diffs, and decides what
ships. The driver does not execute: no file edits, no shell runs, no
web fetches, no commits. All execution is delegated to smaller models
(hands), sized to the task's risk:

- mechanical work (greps, sweeps, format checks, archive lookups): smallest
- scoped implementation and research against a written spec: mid-tier
- crypto-critical, canonical-data, or validator-touching changes: largest
  available hand, never the driver, always with a written derivation or
  acceptance spec from the driver, always reviewed before commit.

Rationale: driver tokens are the scarcest resource in the project; an
hour of driver execution is a day of driver adjudication lost. This is
also the BUILD-INSTRUCTIONS anti-goal made operational: every pipeline
must remain executable by a human with a text editor - agents
accelerate, they never become load-bearing.

## Standing rules for any agent in this repo

- Read BUILD-INSTRUCTIONS.md (clifford-number) or COMPATIBILITY.md +
  RELEASE.md (axm-genesis) before changing anything; Section 1 of
  BUILD-INSTRUCTIONS is non-negotiable.
- Push early: pushed remotes are the only durable state; local working
  trees have been destroyed mid-session before and will be again.
- Canonical data changes (ledgers, registries, vectors) require
  driver-verified receipts; agents propose, the driver gates.
- Every commit runs the repo's full check first (npm run check /
  make test). A red check never ships.
