# Ecosystem wiring — where everything lives

*The single source of truth for cross-repo wiring, so a move is one edit here and
one grep, not reality held in someone's head. This lives in axm-genesis — the one
shared root every spoke already depends on — next to the `drift-check` that
enforces part of it.*

Separate concern from **page flavor** (which property uses which accent): that's
`axm-tools/identity/axm/PROPERTY-FLAVORS.md`. This file is about *where code
lives and how repos find each other*.

## The map

| Repo | Provides (importable) | Console env var | Pages | Depends on |
|---|---|---|---|---|
| **axm-genesis** | the kernel: `axm_build`, `axm_verify` (`axm-build`/`axm-verify` on PATH) | — | — | nothing (the root) |
| **axm-core** | `axm_core` (CLI), `axm_forge`, **`axiom_runtime`** (Spectra) | `AXM_CORE_REPO` *(for `axm ask` / Spectra only)* | `axm-core/` | genesis |
| **GhostBox** | `ghostbox`, `axiom`, `screen_ghost`, **`foundry_exit`** (the Palantir exit engine) | `GHOSTBOX_REPO` *(foundry surfaces)* | `GhostBox/` | genesis; core (Spectra, for the exit's query proof) |
| **axm-console** | `axm_console` (the `axm` operator CLI) | — | `axm-console/` | genesis; drives the spokes as subprocesses via their env vars |
| **ScreenGhost** | `screen_ghost` core, interface procedures | `AXM_SCREENGHOST_REPO` | (repo) | genesis |
| **axm-embodied** | physical capture | `AXM_EMBODIED_REPO` | (repo) | genesis |
| **axm-aide** | `axm_aide` (personal assistant spoke) | — | `axm-aide/` | genesis |
| **axm-chat** | chat→shard | — | `axm-chat/` | genesis |
| **axm-tools** | identity system, house style, pta-tracker | — | `axm-tools/` | — (reference area) |

**Key fact the 2026-07 move established:** `foundry_exit` (the Palantir exit
engine) lives in **GhostBox**, not axm-core. The console's foundry surfaces
resolve **`GHOSTBOX_REPO`**; only `axm ask` (Spectra) resolves `AXM_CORE_REPO`.
GhostBox depends on core for the Spectra query proof — the correct spoke → hub
direction.

## When you move a package between repos

Do all four, in order — the drift-check catches you if you skip the last:

1. **Move the code + its tests + its samples**, update the destination repo's
   `pyproject` (packages + console scripts) and CI.
2. **Update this table** (Provides / env var / depends-on).
3. **Grep every repo** for the old home: `grep -rn '<OLD_ENV_VAR>\|<old/path>' <repo>`
   — docs, HTML links, env-var resolvers, tests.
4. **Add a `drift-check` rule** (`axm-genesis/tools/drift-check.sh`, section F)
   pairing the package with its OLD home, so a reintroduced stale reference fails
   CI in every spoke instead of skipping a test silently.

## What drift-check enforces (section F)

`drift-check.sh` runs in every spoke's CI against that spoke's own tree. Beyond
the kernel-boundary rules (A–E), section **F** flags **stale cross-repo
references**: a package resolved from the *wrong* repo's env var. Each future
move adds one line to that rule. The seeded case:

> a reference resolving `foundry_exit` from `AXM_CORE_REPO` is stale — it is `GHOSTBOX_REPO` now. <!-- drift-ok: this line names the pattern to document it -->

Keyed on the env var (a code construct), so prose that merely says "axm-core"
does not trip it.
