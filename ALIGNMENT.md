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
| axm-core | R | ? | ? | runtime hub — pins/hosts the kernel | ? | **not yet aligned** |
| axm-chat | S | `pages.yml` ✓ | tests + drift | git-pin `@8d211ca` (RFC 0007) | clean | aligned · merged |
| axm-show | S | `pages.yml` ✓ | tests + compile→verify + drift | range `>=1.0.0rc1,<2`, CI ref `fffe7cf` | clean | aligned · merged |
| axm-embodied | S | ? | ? | ? | ? | **not yet aligned** |
| axm-fleet | S | `pages.yml` ✓ | tests + four-beat demo + drift | range `>=1.0.0rc1,<2`, CI ref `fffe7cf` | clean | aligned · merged |
| axm-sfn | S | `pages.yml` ✓ | Py tests + Go build/vet + drift | git-pin `@fffe7cf` | clean | aligned · merged |
| templates/spoke-template | K asset | `pages.yml` ✓ (guarded) | tests + drift | ref `fffe7cf` | clean | canonical source new spokes inherit |

## Notes

- **Pages source is a repo SETTING, separate from `pages.yml`.** The workflow
  publishes; the setting (`build_type=workflow`) tells GitHub to use it. You
  reported flipping all current repos to GitHub Actions, so `bootstrap-pages.sh`
  is for *future* repos (or any not yet flipped).
- **The two "not yet aligned" repos (axm-core, axm-embodied) are outside this
  session's checkout scope.** Run `align-spoke.sh` against each to fill its row.
  `axm-chat` did carry the expected pre-reset drift (Parquet ext tables, a
  post-compile reseal, stale suite labels); it was reconciled onto the one-pass
  kernel path under RFC 0007 (episodes@1/engineering@1 as canonical JSONL via
  `extra_ext`, no reseal) and merged — so it is now the worked example of what
  aligning a pre-reset spoke looks like.
- **Post-PyPI**, spokes float on the semver range and a 1.x kernel bump can't
  break them (COMPATIBILITY.md) — so the pin-bump step disappears for minor/patch
  kernel work. Keep the drift-check step (fetch the script from a pinned kernel
  tag) as cheap insurance.
- Tools: [`tools/align-spoke.sh`](tools/align-spoke.sh),
  [`tools/bootstrap-pages.sh`](tools/bootstrap-pages.sh),
  [`tools/drift-check.sh`](tools/drift-check.sh).
