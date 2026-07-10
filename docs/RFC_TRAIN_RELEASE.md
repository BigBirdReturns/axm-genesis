# RFC: Quality, governance, release — closing the train

Status: **accepted** (2026-07-10, under the owner's drive-to-100 delegation;
rulings recorded for audit). Implementation lands as the release train's PR
091–100, its final lane.

## The one rule

> **The train ends the way every car on it shipped: receipts, not claims.**

## Verified starting facts

- **arc has no test CI.** `.github/workflows/` holds only `deploy.yml` — every
  train merge was gated solely by the driver's local runs (purge → tsc →
  vitest → build → drills). That was the doctrine's answer for this session;
  it is not a governance floor for future sessions.
- world has real CI (`test.yml`, confirmed green per-merge during the lane);
  genesis has `ci.yml` + `make test` (302) + `drift-check` + the new
  doc-truth sweep.
- The train's record lives in `docs/CONTINUITY.md`; the owner's audit
  deliverable ("then we'll see what happened") does not exist yet.

## Shape

| PR  | Step | Repo |
|-----|------|------|
| 091 | **This RFC.** | genesis |
| 092 | **arc CI floor** — a minimal `test.yml` (checkout → npm ci → `tsc --noEmit` → `vitest run`) so future arc merges have a mechanical gate; the drills stay receipts-not-CI per arc's own doctrine. Verified by its first green run on main. | arc |
| 093–098 | **Full-receipt sweep + fixes** — the driver re-runs every gate on every repo's latest main (arc: tsc/vitest/build + all drills; world: `npm run check` + all e2e specs, both projects; genesis: `make test` + drift-check + doc-truth sweep). Anything red becomes a numbered fix PR here; anything green compresses into the verdict (059/069/079 precedent). | all |
| 099 | **Lane verdict** — what the sweep found, what compressed, recorded. | genesis |
| 100 | **The train report** — `docs/TRAIN-2026-07.md`: every lane, every PR, every recorded delegated ruling, every receipt, the open items left deliberately for the owner (genesis PR #23; arc PR #78's cosmetic branch; the FIRST_CHARTER 6→8 pacing ruling; the drama-card engine observation). Linked from CONTINUITY's record. The audit the owner reads. | genesis |

## Non-goals

- No version bumps, no kernel release mechanics (`RELEASE.md` is the kernel's
  own process — untouched). No new product surface. No re-opening shipped
  lanes. PR #23 remains the owner's.

## Delegated rulings (2026-07-10)

1. **arc gets a CI floor now** (092): the drive proved local gating works when
   the driver holds the bar; unattended futures need the mechanical minimum.
   Drills deliberately stay out of CI (arc's own doctrine: receipts, not CI).
2. **Receipts before report**: 100 is written only after 093–098's sweep, so
   the report states what IS, not what was intended.
