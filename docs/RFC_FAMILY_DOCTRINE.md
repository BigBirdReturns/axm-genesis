# RFC: Family doctrine & doc-truth — the law book made real

Status: **accepted** (2026-07-10, under the owner's drive-to-100 delegation; the
rulings below were made by the orchestrator under the standing stop/ask policy
and are recorded for the owner's audit). Implementation lands as the release
train's PR 081–090, across the three in-session repos (genesis, arc, world).

## The one rule

> **A doc that other repos point to must exist, and a posture the family holds
> must be stated in exactly one place.**

## Why it exists (all verified, none guessed)

- **The law book is a phantom.** Both game clients' `CLAUDE.md`s instruct every
  session: *"read axm-genesis `docs/CONTINUITY.md` before designing anything."*
  **That file does not exist** — in this repo or anywhere in the family. Every
  session since that instruction landed has been pointed at a void.
- **The operating doctrine is oral tradition.** The owner's first question of
  this session — *does genesis hold the instruction that the top model drives
  and delegates implementation to smaller models?* — had the answer "no, it is
  written nowhere." It has now been *practiced* across ~30 train PRs (spec →
  delegate → gate → merge, with recorded delegated rulings); it should be law,
  not lore.
- **"Dual-use" is real but unstated.** The train slot 081–090 was labeled
  "dual-use pruning." The verified reality: the word appears in ONE prototype
  doc across all three repos, yet `docs/ECOSYSTEM-WIRING.md` shows genesis
  rooting two product families — the **games line** (arc, world) and an **ops
  line** (core, GhostBox, console, …; outside this session's scope). The games
  clients' own mission docs say "make games fun again." The pruning that is
  honestly in scope: state the posture once, here, and verify the game repos'
  docs don't bleed ops-lane surface.

## Shape

| PR  | Step | Repo |
|-----|------|------|
| 081 | **This RFC.** | genesis |
| 082 | **`docs/CONTINUITY.md` created** — the law book the family already cites: the six constitutional articles (cited from world's ADR 0002, the existing canon — no new law invented), the operating doctrine (RFC-first lanes; driver-model orchestration: the strongest model specs/reviews/gates/merges, delegates implementation; delegated rulings recorded for audit; verification bars per repo), the family posture (games line vs ops line, one paragraph, pointing at ECOSYSTEM-WIRING), and the train record (what 001–100 shipped, as fact). | genesis |
| 083 | **Doc-truth sweep** — an executable check (script) that greps the three in-scope repos for cross-repo doc pointers and verifies each target exists; run it, fix what it finds (each fix lands in the owning repo), record the receipt. | all three |
| 084 | **Law-book guard** — a genesis test asserting `docs/CONTINUITY.md` exists and carries its required sections, so the pointer can never go phantom again. | genesis |
| 085–087 | **Sweep findings** — whatever 083 surfaces, fixed in the owning repos. Expected small; the lane compresses honestly (verdict-recorded, 059/069/079 precedent) if the sweep comes back clean. | as found |
| 088 | **CHANGELOG/ERRATA record** — genesis's own conventions updated to record the doctrine additions. | genesis |
| 089 | **Cohesion/verdict** — the lane audited; recorded either way. | genesis |
| 090 | **Capstone** — the 083 sweep re-run as the lane's receipt: zero phantom pointers across the three repos, CONTINUITY guarded, doctrine stated once. | genesis |

## Non-goals (guard-enforced)

- **No new law.** 082 cites the existing constitution (world ADR 0002) as the
  canon it is; CONTINUITY consolidates and points, it does not legislate.
- **No kernel/spec/digest changes.** Genesis's frozen surfaces are untouched;
  this is `docs/`, `tests/` (one guard), and `tools/` (one sweep script) only.
- **No ops-lane repos touched.** GhostBox/core/console/etc. are outside this
  session's scope; the posture paragraph *names* the split, nothing more.
- **PR #23 stays the owner's.** The open family-doctrine PR (localization +
  cartridge lifecycle) predates this train and was explicitly parked for the
  owner's review — it is referenced, not merged, by this lane.

## Delegated rulings (2026-07-10)

1. **The lane's label resolves to doc-truth.** "Dual-use pruning" as literal
   deletion has nothing verified to delete in-scope; the honest work is the
   posture stated once + the phantom-pointer sweep. Recorded so the owner can
   overrule with a broader mandate if the original intent was the ops line.
2. **CONTINUITY.md is written by the orchestrator, not delegated** — law-book
   prose is reviewer-grade work, and every claim in it must be citable to an
   existing artifact (ADR, RFC, merged PR).
3. **Numbering kept**: 081–090; the quality/release lane (091–100) follows.

## Lane verdict (PRs 086–087 compressed; 089 — audited 2026-07-10)

The sweep's first run (083) found exactly two phantoms, both in one arc README
section, both fixed by one PR (085). PRs 086–087 therefore compress into this
recorded verdict rather than manufactured churn (the 059/069/079 precedent):
**no further findings existed to fix.** Cohesion: the lane added docs, one
test, and one tool — all in genesis's own registers (ADOPTING/ERRATA prose
style, pytest conventions, drift-check's script register); nothing frozen
touched; PR #23 untouched and still the owner's.

## Capstone receipt (090 — run 2026-07-10)

- `tools/doc-truth-sweep.sh` across all three checkouts: **clean — 34
  cross-repo pointers verified, 0 findings** (exit 0).
- `make test`: **302 passed** (299 baseline + the 3 law-book guards).
- CONTINUITY.md exists, guarded, and every load-bearing pointer it names
  resolves. The lane's one rule — *a doc other repos point to must exist,
  and a posture is stated in exactly one place* — holds mechanically.
