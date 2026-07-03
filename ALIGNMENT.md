# ALIGNMENT.md — bringing every repo under the kernel contract

`axm-genesis` is the **kernel**: it owns the format/crypto contract (the frozen
`spec/v1`, the vectors, the `EXTENSION_REGISTRY`, the spoke template, and the
drift lint). `axm-core` is the separate **runtime** hub. Every other repo is a
**spoke**, **demo**, or **archive** that reads the kernel and never
reimplements it.

This ledger is the control object — a small, auditable table, not a big
migration. For each repo it tracks four fields: **Site**, **CI**, **Genesis
relationship**, **Drift**. The question is not "does this repo look modern?" It
is: *does the repo know where the kernel boundary is, and can it publish its own
public surface without hand work?*

**Operating rule: new repos come from the template; old repos get aligned by
ledger — one at a time.** Do not fleet-edit blind.

## The unit of work (per repo)

1. **Classify** — kernel | runtime | spoke | demo | archive.
2. **Report** — `tools/align-spoke.sh <repo-dir> --type <class>` prints the four
   fields. Add `--fix` to scaffold a missing guarded `pages.yml` or spoke CI
   from `templates/spoke-template/` (it never edits code or commits).
3. **Pin** — normalize the `axm-genesis` dependency: a git-commit pin pre-PyPI
   (the CI `ref:` must point at a commit that contains `tools/drift-check.sh`),
   the `axm-genesis[mldsa-compat]>=1.0.0,<2` range after the v1.0.0 PyPI release.
4. **Drift** — run the lint; fix only the violations that matter.
5. **Pages** — if the repo's Pages *source* isn't already "GitHub Actions",
   flip it: `OWNER=BigBirdReturns tools/bootstrap-pages.sh <repo>` (needs a token
   with Pages + Administration write — the template and the connector cannot flip
   a repo setting; GitHub exposes it per repo only, `build_type=workflow`).
6. **Merge.** `pages.yml` publishes on the next push to the default branch.

## Ledger

Class: **K** kernel · **R** runtime · **S** spoke · **D** demo · **A** archive.
Alignment work landed on branch `claude/genesis-docs-rfc-sync-t5eywu` per repo;
"merged" = that branch reached `main`, so the CI + Pages workflows are live.

| Repo | Class | Site | CI | Genesis relationship | Drift | Status |
|------|:---:|---|---|---|---|---|
| axm-genesis | K | `pages.yml` ✓ | own CI (conformance, gold, lint) | is the kernel | n/a | aligned · merged |
| axm-core | R | `pages.yml` ✓ | tests (kernel mount + pipelines) + drift | git-pin `@fffe7cf` — runtime hub, mounts/hosts the kernel | clean | aligned · merged |
| axm-chat | S | `pages.yml` ✓ | tests + drift | git-pin `@8d211ca` (RFC 0007) | clean | aligned · merged |
| axm-show | S | `pages.yml` ✓ | tests + compile→verify + drift | range `>=1.0.0rc1,<2`, CI ref `fffe7cf` | clean | aligned · merged |
| axm-embodied | S | `pages.yml` ✓ | tests (compile→verify + embodied@1) + drift | git-pin `@fffe7cf` | clean | aligned · merged |
| axm-fleet | S | `pages.yml` ✓ | tests + four-beat demo + drift | range `>=1.0.0rc1,<2`, CI ref `fffe7cf` | clean | aligned · merged |
| axm-sfn | S | `pages.yml` ✓ | Py tests + Go build/vet + drift | git-pin `@fffe7cf` | clean | aligned · merged |
| templates/spoke-template | K asset | `pages.yml` ✓ (guarded) | tests + drift | ref `fffe7cf` | clean | canonical source new spokes inherit |

## Kernel commit policy

Pre-release repos may pin different genesis commits when their required kernel surface differs.

- `fffe7cf` is the v1 alignment floor used by repos that need the anti-drift tooling, v1 compiler surface, `streams@1`, and the embodied/profile support already present there.
- `8d211ca` is the RFC 0007 floor used by `axm-chat`, because chat depends on `episodes@1` and `engineering@1`.
- These are temporary pre-tag pins, not divergent kernel lines.

At the v1.0.0 release ceremony, all spokes should move from commit pins to the release range:

`axm-genesis[mldsa-compat]>=1.0.0,<2`

After that, 1.x compatibility is governed by the release contract rather than per-repo SHA uniformity. Do not repin a spoke merely for cosmetic consistency before the tag; repin only when the repo needs a kernel surface introduced after its current floor.

## Notes

- **Pages source is a repo SETTING, separate from `pages.yml`.** The workflow
  publishes; the setting (`build_type=workflow`) tells GitHub to use it. You
  reported flipping all current repos to GitHub Actions, so `bootstrap-pages.sh`
  is for *future* repos (or any not yet flipped).
- **Every repo is aligned and merged.** The sweep is complete: the kernel, the
  runtime hub (`axm-core`), and all five spokes (`chat`, `show`, `embodied`,
  `fleet`, `sfn`) pin a v1 kernel commit, ship self-verifying CI + the boundary
  drift-check, and publish through a `pages.yml`. A newly reconciled repo turns
  green here only after it passes the boundary check on its own branch and that
  branch merges — no "almost-aligned" rows.
- **Range of drift the sweep resolved.** `axm-chat` carried the worst of it (a
  post-compile reseal + Parquet ext tables) and was rebuilt onto the one-pass
  kernel path under RFC 0007 — the worked example of aligning a pre-reset spoke.
  `axm-embodied` was already on the one-pass path (extra_content + JSONL
  streams@1 + the embodied@1 profile) and needed only a repin off its provisional
  feature-branch pin plus doc/CI polish. `axm-core` is the runtime hub: it mounts
  and hosts the kernel (its `test_v1_mount` asserts the kernel exposes exactly the
  SPOKE_API surface) and never compiles shards itself, so it needed a repin, CI,
  and identity-doc truth. Historical/backward-compat references (embodied's
  spoke-era SPECIFICATION, clarion's v0.x Parquet fallback readers) are marked
  `drift-ok` in place rather than rewritten.
- **Post-PyPI**, spokes float on the semver range and a 1.x kernel bump can't
  break them (COMPATIBILITY.md) — so the pin-bump step disappears for minor/patch
  kernel work. Keep the drift-check step (fetch the script from a pinned kernel
  tag) as cheap insurance.
- Tools: [`tools/align-spoke.sh`](tools/align-spoke.sh),
  [`tools/bootstrap-pages.sh`](tools/bootstrap-pages.sh),
  [`tools/drift-check.sh`](tools/drift-check.sh).
