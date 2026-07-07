# Localization doctrine — chrome vs. cartridge data

Status: adopted family-wide (axm-world, axm-arc, axm-tools/pta-tracker).
This document is the normative statement of the pattern so new surfaces
replicate it instead of rediscovering it. It is presentation-layer law;
it changes nothing about shards, digests, or the kernel.

## The one rule

> **Chrome is the app's to translate. Data flows verbatim.**

*Chrome* is every string the application authors: navigation, buttons,
help prose, section headings, empty states, generated summary sentences.
*Data* is everything a cartridge/arc/shard/feed brings with it: names,
descriptions, narrative text, resource vocabulary, curated content.
Data is never catalogued, never machine-translated, never rewritten by
the presentation layer — a second cartridge's own vocabulary always
wins. This is the presentation-layer sibling of the ecosystem invariant
("Genesis compiles and signs; everything else reads"): the surface
renders what it was handed.

## Adherence requirements (what "conformant" means)

1. **Typed catalog, English fallback.** Every chrome string lives in a
   message catalog keyed by id. A missing translation falls back to
   English; a missing id renders the id itself. Never a blank, never a
   crash.
2. **Honest coverage, guarded by test.** Untranslated ids are listed in
   an explicit `EN_ONLY` set. A coverage-guard test asserts every
   English id is either translated or documented there — silence is not
   allowed to look like coverage.
3. **Engine strings are data.** Text emitted by a deterministic engine
   (projection hints, event predictions, enum values) is displayed
   verbatim, or mapped to localized copy at *display time only* with a
   raw fallback for unknown values. Localization must never reach into
   engine internals.
4. **Determinism boundary.** The engine must not use locale-sensitive
   platform behavior: no `localeCompare` for canonical ordering
   (codepoint compare only), no unseeded randomness, no host-dependent
   formatting inside the sim. Same seed, same run, on every machine in
   every locale. (Locale-sensitive collation in engine ordering was a
   real bug found and fixed in world and arc.)
5. **Locale preference** is per-player: one storage key, browser-default
   detection, try/catch-guarded for headless environments.

## Adaptation by stack

- **React/TS apps** (world, arc): the reference shape is three modules —
  `locale.ts` (preference + detection), `messages.ts` (typed catalog,
  values are strings or param functions; no template parsing),
  `index.ts` (module-level `t()` + a `useSyncExternalStore`-backed
  `useLocale()`; no context provider). Reference implementation:
  `axm-world/src/world/i18n/`, full-app example: `axm-arc/src/i18n/`.
- **No-build static pages** (tools): the same design inlined as vanilla
  JS — a plain object catalog, `data-i18n` attributes for static nodes,
  re-render functions for data-driven views. Reference:
  `axm-tools/pta-tracker/index.html`.
- **Content you don't own** (external feeds, user cartridges): do not
  translate it. Give readers the bridge instead — the browser's built-in
  translate-page covers 100+ languages; state the boundary in the UI
  (pta-tracker shows a hint saying chrome is curated, content is
  original-language, use browser translate for the rest).

## Platform-included features (use, don't reinvent — outside the engine)

Browsers now include most of what game/tool surfaces used to hand-roll:
`Intl.*` (plurals, dates, numbers, lists), native `<dialog>`,
`light-dark()` CSS theming, View Transitions, `structuredClone`,
`crypto.randomUUID`, `CompressionStream`, Web Share, Web Crypto
(SHA-256, Ed25519 verify — async only; a sync deterministic path may
justify a self-contained hash, as arc's cartridge digest does).
For **offline play**: a PWA manifest + service-worker precache makes a
surface installable and offline-runnable (self-host fonts first);
`navigator.storage.persist()` + IndexedDB over bare localStorage for
save durability (installed PWAs are exempt from Safari's 7-day storage
eviction); file export remains the user-owned backstop no browser
policy can evict. None of these are implemented family-wide yet — this
paragraph is the shopping list, not a claim.

## Translation quality

Machine- or model-drafted catalogs (the current zh-Hant/ko/es) must be
proofread by a fluent speaker before being treated as final. "Renders
correctly" and "reads natively" are different claims; only the first is
machine-verifiable.
