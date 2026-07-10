# CONTINUITY — the family's laws, operating doctrine, and record

This is the file every AXM session is told to read before designing anything
(axm-arc and axm-world `CLAUDE.md`s both point here). It consolidates and
points; it does not legislate. Every claim below is citable to an artifact —
an ADR, an RFC, a merged PR — and the owner ratifies or overrules anything
recorded here under delegation. Created by the release train's doctrine lane
(`docs/RFC_FAMILY_DOCTRINE.md`, PR 082).

## The laws

**The kernel invariant** (this repo): *Genesis compiles and signs; everything
else only reads.* No perimeter repo re-signs a manifest, mutates a Merkle
root, adds a core-table field, or reimplements the kernel's constructions.
(Canon: `README.md`, `PERIMETER-SWEEP.md`, enforced by `tools/drift-check.sh`
in every spoke's CI.)

**The platform constitution** (games line): six durable, guard-enforced
articles. Canon: `axm-world docs/adr/0002-platform-constitution.md`, guarded
by `tests/world/constitution.test.ts`. Short form:

1. The cartridge belongs to its holder — playing never requires a server.
2. Identity is computed, not claimed — trust is a layer, never a gate.
3. Memory belongs to the run — the ledger exports with it; old records migrate.
4. The dev kit is free and the dev kit is the product.
5. Old cartridges always boot.
6. The runtime may not claim what it cannot prove.

A PR that weakens an article amends the ADR explicitly. Deleting a guard is
amending the constitution.

**The grammar rule** (both clients): chrome is the app's to translate;
cartridge data flows verbatim and is never catalogued. Cartridges are data,
imported through one validator per client — never a second one.

## Operating doctrine

How work ships in this family — practiced across the 2026-07 release train
(~40 merged PRs across three repos) and codified here:

- **RFC-first lanes.** A program of work opens with an RFC stating its one
  rule, shape, non-goals, and walls. The owner ratifies scope; under an
  explicit owner delegation, the orchestrator may rule on open calls, and
  every **delegated ruling is recorded in the RFC for the owner's audit** —
  visible, dated, overrulable.
- **Driver-model orchestration.** The strongest available model is the
  driver: it scouts the terrain, writes the RFC, specs each PR with the walls
  baked in, **reviews every diff, runs every gate itself, and merges**.
  Implementation is delegated to smaller, faster models working one scoped PR
  at a time. Subagents are told to *stop and report* rather than improvise
  when a wall is near; their honest deviations and findings are reviewed by
  the driver, not rubber-stamped.
- **Verification bars, per repo.** Tests passing is not shipping.
  - *arc*: purge stale emits → `tsc --noEmit` → `vitest` → build → headless
    drills through the real player paths (`docs/drills/`). No CI gate — the
    driver's local gate IS the gate, run before every merge.
  - *world*: `npm run check` → Playwright receipts, desktop AND mobile →
    preview screenshots for anything visual → CI green on the merge commit.
  - *genesis*: `make test`; `tools/drift-check.sh` guards the kernel boundary
    in every spoke.
- **Honest layers.** Make the current truth readable → make it embodied →
  only then record richer truth. Never render a fact the engine or a stored
  record can't back: no invented rewards, no fabricated verdicts for
  artifacts not in hand, no wall-clock where the schema stores none, honest
  empty states instead of fabricated ones.
- **One pure helper, two surfaces.** Any fact shown in two places derives
  from one shared function, so surfaces can never disagree.
- **Scope walls.** Display PRs never touch schema/resolver/save; engine
  changes land in arc first (the vendored surface, drift-checked); clients
  never hand-edit it. A gap becomes an RFC, never a hack.
- **Verdict-recorded no-ops.** When a planned step turns out to be already
  satisfied, the audit is recorded in the RFC instead of churn being
  manufactured (precedent: train PRs 059/069/079).
- **The stop/ask box.** Proceed without asking when work is read-only or
  additive display, existing facts suffice, unknowns can be labeled honestly,
  missing artifacts degrade safely, and tests can prove the behavior. Stop
  for: schema/engine/save changes, data mutation or deletion, guessed
  semantic mappings, new product lanes, crossed repo boundaries, or any UI
  claim the data cannot back.

## The family

Genesis roots two product lines (`docs/ECOSYSTEM-WIRING.md` is the wiring
map; `axm-tools` holds identity/house style):

- **The games line** — axm-arc (management/text client) and axm-world
  (embodied/appliance client). Mission: *make games fun again* — consequence
  and memory, a world that honestly remembers what you did. One cartridge,
  two honest expressions, same content digest on both ends.
- **The ops line** — axm-core, GhostBox, axm-console, ScreenGhost,
  axm-embodied, axm-aide, axm-chat. Separate surfaces, same kernel.

The engine is dual-use by construction — an organizational simulation runs
guilds or operations alike — but **each line states its own mission in its
own docs and neither wears the other's clothes**: game-client docs don't
carry ops surface, and ops repos are not in a game session's scope.

## The record (the 2026-07 release train)

One-PR-per-item, RFC-first, driver-gated. As shipped:

| Lane | Items | Where | RFC |
|---|---|---|---|
| Guild Hall | 032–040 | arc | `docs/RFC_GUILD_HALL.md` |
| Expansion Archive | 041–050 | arc | `docs/RFC_EXPANSION_ARCHIVE.md` |
| Appliance expansion | 051–060 | world | `docs/design/RFC_APPLIANCE_EXPANSION.md` |
| Workshop conformance | 061–070 | arc | `docs/RFC_WORKSHOP.md` |
| Cartridge Library custody | 071–080 | arc | `docs/RFC_CARTRIDGE_LIBRARY.md` |
| Family doctrine & doc-truth | 081–090 | genesis + clients | `docs/RFC_FAMILY_DOCTRINE.md` |
| Quality / governance / release | 091–100 | all | `docs/RFC_TRAIN_RELEASE.md` |

The full report: `docs/TRAIN-2026-07.md` (train PR 100).

## Amendment

The owner amends this file directly or by ratifying/overruling a recorded
delegated ruling. Sessions treat it as read-before-design; the guard test
(`tests/`, train PR 084) keeps it from ever going phantom again.
