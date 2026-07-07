# The cartridge lifecycle — one cartridge, authorship to play

Status: adopted family-wide (axm-arc, axm-world). This document is the
normative statement of the pipeline so new stages and new clients extend it
instead of rediscovering it. It does not replace the atlas or the porting
protocol — see arc: `docs/COMPATIBILITY_ATLAS.md` and arc:
`docs/CLONE_PORTING.md` for the tier ladder and the six-step recipe; this
document is the doctrine those two implement.

## The one rule

> **A cartridge is one artifact. Every stage acts on the same JSON, through
> the same seams, or it doesn't count.**

No stage forks the format, adds a second validator, or gives a client a
private notion of what a cartridge is. Eight stages, eight laws:

## 1. Author

A cartridge is plain JSON. The schema is law — the single Zod schema in
arc's `src/engine/schema.ts`; world vendors the identical file (stage 6).
Authoring surfaces: arc's Cartridge Workshop (skeleton, duplicate-from-
library, live validation, export, in-app) or any text editor. There is no
compile step and no build artifact — the JSON file *is* the cartridge.

## 2. Validate — one seam, everywhere

Validation is a single shared path: `validateArcJson` (parse +
`validateArc`), which `importArcFromJson` delegates to. The Workshop's
Validate button, arc's Library paste-import, and world's boot file-import
all run this same path. Law: never a second validator. A cartridge that
passes the seam in one client passes it in all clients; a malformed
cartridge fails at import, never at first contact in play.

## 3. Identity

`cartridgeDigest(arc)` → `cart1_<sha256>` — content-addressed identity,
deterministic across clients and across export/import round-trips. Uses:
conformance tests pin it (a content change is a visible diff in the pin);
world keys its per-cartridge save ledger by digest; a future signing scheme
signs it. The digest identifies content, not trust.

## 4. Trust

Two levels today: `bundled` (ships with a client) and `imported-unsigned`
(anything through the import seam). Law: export strips trust — a file can
never claim its own trust level; trust is assigned by the receiving client
at import. Signing (genesis roadmap: signed arcs, Merkle roots,
axm-verify) will extend this without changing the seam.

## 5. Conform

Every cartridge meant to be played ships with a conformance test against
arc's cartridge-agnostic harness (`src/sim/cartridge-conformance.ts`): real-
seam import, digest pin, determinism (same seed → identical run), gate
honesty (structural — every assignment re-validated against access rules),
reachability (seeded sweeps must reach the finale). "A cartridge without
its sim test is content, not a clone" (arc: `docs/CLONE_PORTING.md`).
Determinism is a family-wide law, not a per-cartridge choice: seeded PRNG,
codepoint compare never `localeCompare`, no locale-sensitive behavior
anywhere in an engine path.

## 6. Play — one cartridge, two clients

Both clients *play* the cartridge — this is not an author-here, play-there
split. arc is the management/text client: it plays the full story start to
finish and runs every encounter, through a management UI (assign / roster /
drama / reports) over a single global save slot. world is the appliance
client: it takes the *same* cartridge and embodies it as a world you walk —
boot-screen file import, per-cartridge ledger keyed by digest (a different
save model, deliberately). Same content, two honest surfaces: read-and-run
the whole arc in arc; inhabit it in world. Both vendor the *same* engine:
world vendors `src/engine`,
`src/arcs`, `tests/engine`, `tests/fixtures` from arc, pinned in world's
`src/engine/VENDORED_FROM`, synced only via `scripts/sync-engine.sh`, drift
enforced by world's `engine-drift` CI. Engine changes land in arc first —
always.

## 7. Localize — the grammar rule

Chrome belongs to the client and is translated; cartridge vocabulary flows
verbatim — a cartridge's own nouns (economy names, challenge names, role
names) always win and are never machine-translated. This is the same
distinction the presentation layer draws everywhere else in the family;
full doctrine: `docs/LOCALIZATION.md` (this repo).

## 8. Port

New game loops enter as cartridges, not as engine changes. Which lineages
qualify, at what cost, is the atlas's job — arc: `docs/COMPATIBILITY_ATLAS.md`
lays out four tiers with honest price tags. How a qualifying lineage
actually becomes a cartridge is the protocol's job — arc:
`docs/CLONE_PORTING.md`'s six steps. Rule #1 of both: a clone may never
change the engine; a gap becomes an engine RFC instead (worked examples:
arc `docs/TIER_B_ENCOUNTER_SEAM.md`, arc `docs/RFC_TIER_C_REALTIME.md`).

## Why this shape lasts

Every stage is one seam, one law, one artifact. Authoring needs a text
editor. Validating needs a function call. Identity needs a hash. Trust
needs a receiving client, not a certificate authority. Conformance needs a
seeded simulation, not a QA team. Play needs two clients agreeing to vendor
the same files, not a shared server. Porting needs a mapping table, not a
rewrite. Nothing in this pipeline depends on a service staying up, a build
farm, or a database — a cartridge authored today imports, digests, and
plays the same way a decade from now, on whatever reads the schema.
