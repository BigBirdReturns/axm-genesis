# Continuity — how to keep building this, for any model, any decade

Written 2026-07-07 by the session that shipped clones #2–#5, the Cartridge
Workshop, and the lifecycle doctrine. Its premise: **every model, tool, and
stack in this project will be replaced many times over; the laws and the
artifact chain must survive all of it.** If you are a model reading this
cold, this document plus the docs it points to are sufficient to continue.
Nothing here requires memory of any prior session — `git log` on each
repo's `main` is the authoritative history.

## 1. The map

| Repo | Role | Load-bearing artifacts |
|---|---|---|
| **axm-genesis** | Frozen kernel + family doctrine | `docs/LOCALIZATION.md`, `docs/CARTRIDGE_LIFECYCLE.md`, this file, `ADOPTING.md`, `DURABILITY.md` |
| **axm-arc** | Simulation engine + management/text play client + the cartridges | `src/engine/schema.ts` (the law), `src/sim/cartridge-conformance.ts` (the harness), `cartridges/*.arc.json` + `tests/cartridges/`, `docs/COMPATIBILITY_ATLAS.md`, `docs/CLONE_PORTING.md`, `docs/TIER_B_ENCOUNTER_SEAM.md`, `docs/RFC_TIER_C_REALTIME.md`, the Workshop (`src/game/components/WorkshopScreen.tsx`), `docs/drills/` (verification scripts) |
| **axm-world** | Embodied/appliance play client; vendors arc's engine | `RECONCILIATION.md` (the vendor contract), `src/engine/VENDORED_FROM` (the pin), `src/world/i18n/` (localization reference implementation), boot importer (`src/world/cartridge-bay.ts`) |

Both arc and world *play* the cartridge (see `CARTRIDGE_LIFECYCLE.md` §6):
arc plays the full text/management story and runs every encounter start to
finish; world takes the same cartridge and embodies it as a world you walk.
arc is not "authoring, and world is playing" — it is two honest surfaces on
one artifact, with deliberately different save models and visual languages.
| **axm-tools** | Unrelated product line: static, stdlib-only civic tools | its own `CLAUDE.md` + root `README.md` — different laws, do not import the game family's habits there |

Other spokes (core, chat, show, embodied) exist per arc's README family
table; they were not touched by the cartridge work.

## 2. The laws

Each law lives in a home doc; this list is the index, not the source.
Violating one "temporarily" is how 30-year projects die at year 3.

1. **One artifact, one seam.** A cartridge is one JSON file; every stage
   acts on it through the same validation path; never a second validator.
   (`CARTRIDGE_LIFECYCLE.md`)
2. **A clone may never change the engine.** Gaps become RFCs; the tier
   ladder prices them honestly. (arc `COMPATIBILITY_ATLAS.md`, rule #1)
3. **Determinism.** Seeded PRNG; codepoint compare, never `localeCompare`;
   no locale-sensitive behavior in any engine path; the run record replays
   exactly. (`CARTRIDGE_LIFECYCLE.md` §5, arc engine)
4. **The grammar rule.** Chrome is the app's to translate; cartridge/arc
   data flows verbatim — a cartridge's own vocabulary always wins.
   (`LOCALIZATION.md`)
5. **Trust is assigned by the receiving client.** Export strips it; a file
   never claims its own trust level. (`CARTRIDGE_LIFECYCLE.md` §4)
6. **A cartridge without its conformance test is content, not a clone.**
   (arc `CLONE_PORTING.md` §4)
7. **Engine changes land in arc first.** world re-vendors via
   `scripts/sync-engine.sh`; `engine-drift` CI fails on silent divergence;
   never edit vendored files in place. (world `RECONCILIATION.md`)
8. **Original vocabulary always — clean-room, no exceptions.** Lineage
   mechanics are portable; expression (names, story, art, text, data
   files) is not. Never ingest ROMs, rips, or franchise assets, even
   owner-provided; the owner's role with source games is to play them and
   report feel, nothing else. (arc `COMPATIBILITY_ATLAS.md`)
9. **Positional/skill leverage is bounded.** ±15% of a check's
   `difficultyThreshold`, additive, recorded on the decision — one law
   shared by Tier B placement and Tier C outcome mapping. (arc
   `TIER_B_ENCOUNTER_SEAM.md`)
10. **axm-tools is a different country.** Python stdlib-only, no build
    step, `main` is production, machine-owned data files. Its own
    `CLAUDE.md` governs.

## 3. How to amend a law

Laws are amendable — silently breaking them is not. The pattern, with two
worked examples already in the tree (arc `TIER_B_ENCOUNTER_SEAM.md`
unlocked positioning; arc `RFC_TIER_C_REALTIME.md` prices real-time input):

1. Write the RFC/contract **in the repo that owns the law**, stating the
   options and their costs honestly — including the option of not doing it.
2. Get the owner's explicit acceptance before code.
3. Update the law's home doc and this index in the same PR as the change.
4. Leave the reasoning in the doc, not just the decision — the next model
   needs to know *why*, or it will relitigate or, worse, quietly undo it.

Stacks are not laws. React, Vite, Zod, Playwright, GitHub — all
replaceable. What must survive a stack migration: the JSON schema
semantics, the digest algorithm (`cart1_<sha256>` over canonicalized
content), the single-seam property, the conformance suite behaviors, and
the doctrine docs. A future client in a future framework joins the family
by reading `CARTRIDGE_LIFECYCLE.md` and honoring the eight stages, not by
resembling the current code.

## 4. The operating doctrine (how the work gets done)

**Driver and hands.** The strongest available model designs, specs,
reviews, and verifies; cheaper models execute to spec. What makes a hand
spec good (this is where the token economy lives): name the exact files to
read and forbid exploration beyond them; point at one worked example
(severed-march + its test was the template for three clones, all
first-pass clean); embed the mapping table / outline so the hand executes
rather than designs; state the verification commands and their required
results; demand a raw-data report including judgment calls. Review every
hand's output against the laws before integrating — hands drift, drivers
catch.

**Use all of the buffalo.** Every port, feature, or fix must bank its
byproducts as durable artifacts: harnesses generalized (the karazhan sim
became `cartridge-conformance.ts`), gotchas written down (see §6), gaps
filed as RFCs, drills committed (arc `docs/drills/`). The test: the next
task of the same shape must be strictly cheaper.

**The verification bar.** Nothing ships on "tests pass" alone. The bar:
typecheck + full suite green; the real seam exercised (actual import
functions, not hand-rolled validators); headless-browser drills through
the actual player paths in **both** clients; digests pinned and compared.
When a UI drill fails where a test passed, the seam is what's broken —
fix that, it protects every future cartridge.

**PR discipline.** PR bodies carry the mapping tables and verification
evidence (they are the porting protocol's durable record). Babysit open
PRs to merged/closed — re-check state, CI, and mergeability on a timer;
resolve conflicts by merging main in, re-verifying everything, pushing.
One PR is one reviewable unit: a change that spans an engine seam, a
schema/persistence layer, and a UI is three PRs, not one — split it into
a stack (engine/data first, then the layers that consume it) so each
diff can be judged on its own and the load-bearing seam lands before its
dependents. An engine or vendored-surface change is always its own PR,
merged first, because downstream repos sync from it. Squash a surface's
build-history churn (the intermediate passes) into the final state before
review — reviewers judge the result, not the archaeology. A diff too
large to review as one unit is a packaging failure, not a size to excuse.

**The owner's role.** Plays the games and gives feel-notes (mechanics
tuning has no other ground truth); proofreads model-drafted locales
(fluent proofread is the bar for "final" — `LOCALIZATION.md`); merges;
decides RFCs. Do not block on the owner for anything else; do not ask the
owner to do model work.

## 5. Roadmap (direction, not binding)

- **Near:** merge what's open; native-speaker proofread of zh-Hant/ko/es
  catalogs; owner feel-notes on the five clones; owner decision on the
  Tier C RFC (Option 3, outcome mapping, is the standing recommendation).
- **Mid:** Tier B seam implementation in world per the contract (unlocks
  grid tactics / isometric tactics / campaign wargame / mech tactics);
  cartridge signing (genesis roadmap: signed arcs, Merkle roots,
  `axm-verify`) — extends trust without changing the seam; more Tier A
  cartridges authored through the Workshop.
- **Long:** new clients (mobile shell, TUI, whatever the decade offers)
  enter through the same import seam and the lifecycle's eight stages;
  the Workshop grows toward structured editing atop the same
  `validateArcJson`; competitive Tier C waits for input-trace replay
  (Option 2) and not before.
- **Named non-goals:** Tier D lineages; engine hacks to promote a tier;
  cheat-sensitive competitive play on self-reported results; on-page edit
  buttons in pta-tracker; re-adding EdSource to its feeds.

## 6. Perishable tooling notes (true in 2026 — verify, then replace)

These rot. When one dies, fix it and update this section.

- **vitest/tsc shadowing:** `tsc -b` emits `.js` beside sources that
  silently shadow `.ts` under vitest. Purge before every run:
  `find src tests \( -name "*.js" -o -name "*.js.map" -o -name "*.d.ts" \) -delete && rm -f tsconfig.tsbuildinfo`.
- **Headless drills:** playwright-core + system Chromium; scripts and
  solved gotchas (base-path serving, MouseEvent dispatch, overlay closing,
  uppercase text-transform, download capture) live in arc `docs/drills/`.
- **Sandboxed sessions:** proxy CA at `/root/.ccr/ca-bundle.crt`
  (`SSL_CERT_FILE` for Python/urllib); GitHub via MCP tools, not `gh`.
- **Locale storage keys:** `axm-arc:locale:v1`, workshop draft
  `axm-arc:workshop-draft:v1` — versioned keys; bump, don't mutate.
- **Vite bases:** `/axm-arc/game/`, `/axm-world/game/`; builds emit to
  `docs/game` (arc's is gitignored; world's deploys).

## 7. State snapshot (2026-07-07 — stale the moment it was written)

Five Tier A clones proven (Karazhan, The Severed March, Deepway Rescue
Guild, The Wandering Court, The Palisade War), each with a 12-test
conformance suite and dual-client UI verification. Workshop shipped. The
full lifecycle demonstrated live: Workshop-authored skeleton → validate →
play in arc → export → the exported file imported into world → identical
64-hex digest both ends. Tier B contract and Tier C RFC written, awaiting
owner decision. Localization: en + zh-Hant in arc/world chrome; four
locales in pta-tracker; model-drafted catalogs awaiting fluent proofread.
Everything above merged or riding then-open PRs — `git log` knows which.
