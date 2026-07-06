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
| axm-core | R | `pages.yml` ✓ | tests (kernel mount + pipelines) + drift | git-pin `@9074e7f` (v1.0.0 release) — runtime hub, mounts/hosts the kernel | clean | aligned · merged |
| axm-chat | S | `pages.yml` ✓ | tests + drift | git-pin `@9074e7f` (v1.0.0 release) | clean | aligned · merged |
| axm-show | S | `pages.yml` ✓ | tests + compile→verify + drift | range `>=1.0.0rc1,<2`, CI ref `fffe7cf` | clean | aligned · merged |
| axm-embodied | S | `pages.yml` ✓ | tests (compile→verify + embodied@1) + drift | git-pin `@9074e7f` (v1.0.0 release) | clean | aligned · merged |
| axm-fleet | S | `pages.yml` ✓ | tests + four-beat demo + drift | range `>=1.0.0rc1,<2`, CI ref `fffe7cf` | clean | aligned · merged |
| axm-sfn | S | `pages.yml` ✓ | Py tests + Go build/vet + drift | git-pin `@fffe7cf` | clean | aligned · merged |
| templates/spoke-template | K asset | `pages.yml` ✓ (guarded) | tests + drift | ref `fffe7cf` | clean | canonical source new spokes inherit |

## Kernel release policy (v1.0.0)

**The v1.0.0 release anchor is the commit, not a tag:**

`9074e7fb2e9cedde692b248cdd0c6a805e77d8ac` — the release merge on `main`
(canonical publisher key installed, gold v2 ceremony-signed and
byte-deterministic, `__version__ = "1.0.0"`, full CI green). Consumers pin
`axm-genesis @ git+…@9074e7f…` and CI checks out the same ref. A commit SHA
is content-addressed and immutable; it cannot be moved or reused — which is
exactly the property a release anchor needs.

- **Tags are cosmetic here, and currently hazardous:** the repository still
  carries pre-reset prototype tags (`v1.0.0`, `v1.0.2`, `v1.1.0`, `v1.2.0`)
  pointing at v0.x commits — the old lightweight `v1.0.0` is six months
  older than the release. **Do not install by tag** until the maintainer
  renames them (`RELEASE.md` step 0) and, optionally, cuts a signed
  `v1.0.0` at the release commit. If that signed tag lands, pins may move
  from the SHA to `refs/tags/v1.0.0` — a cosmetic upgrade, not a semantic
  one.
- **pip does not verify tag or commit signatures during installation.**
  Authenticity is anchored by this repository's history, CI, the
  gold-shard checksums, and the independent timestamp attestations
  (`attestations/`) — which remain valid across the ceremony because the
  re-mint reproduced the attested manifest byte-identically.
- **Custody grade is recorded honestly in `keys/README.md`:** cloud-session
  ceremony, maintainer-authorized; the publisher secret key was
  deliberately destroyed at the end of the ceremony session, making this a
  **single-use publisher identity** — nothing can ever be re-signed under
  it, and verification (public key only) is unaffected forever. Future
  signing requires a new key by RFC'd rotation.
- The pre-release floors this section used to define (`fffe7cf` alignment
  floor, `8d211ca` RFC 0007 floor for chat) are superseded: `axm-core`,
  `axm-chat`, and `axm-embodied` now pin the release commit. `axm-show`,
  `axm-fleet`, and `axm-sfn` still carry `fffe7cf` CI refs (compatible;
  update opportunistically — do not fleet-edit for cosmetics).

**Post-PyPI (still future):** if/when the kernel is published to an index,
spokes move to the range `axm-genesis[mldsa-compat]>=1.0.0,<2` and 1.x
compatibility is governed by the release contract rather than SHA pins.
Publishing is a separate, deliberate distribution contract — not implied
by this release.

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
