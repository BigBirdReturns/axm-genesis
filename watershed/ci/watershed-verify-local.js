#!/usr/bin/env node
// watershed-verify-local: the receipt check. Declared edges in a watershed
// manifest are self-reported until something reads what a repo *actually*
// imports and fails on divergence. This is that something - for whatever
// repos are checked out locally.
//
// Usage:
//   node ci/watershed-verify-local.js path/to/watershed.json --repo <id>=<localPath> [--repo <id>=<localPath> ...]
//
// For each --repo pair, this reads <localPath>/package.json (dependencies,
// not devDependencies) and <localPath>/pyproject.toml ([project].dependencies)
// and extracts the first-party dependency ids that match other repo ids in
// the manifest. It then diffs that set against the manifest's depends_on
// entry for that repo id.
//
// Note on scope: this only ever reads package manifests (package.json,
// pyproject.toml). Vendored conformance - e.g. clifford-number vendoring
// axm-genesis's identity vectors as test fixtures - is not a package
// dependency and will never show up here, so it can never produce a false
// UNDECLARED. That is a feature of reading manifests instead of source
// trees, not an oversight; it also means this check cannot see a real
// dependency smuggled in without a manifest entry (e.g. a git submodule,
// a copy-pasted file, a runtime HTTP call). It verifies declared package
// dependencies against actual package dependencies, nothing more.
//
// Exit 0: no divergence found among locally-verified repos. Exit 1: violations,
// listed flat, same style as watershed-check.js.

const fs = require("fs");
const path = require("path");

const args = process.argv.slice(2);
const manifestPath = args[0];
if (!manifestPath) {
  console.error("usage: node ci/watershed-verify-local.js <manifest.json> --repo <id>=<localPath> [--repo <id>=<localPath> ...]");
  process.exit(1);
}

const repoPaths = new Map(); // manifest repo id -> local checkout path
for (let i = 1; i < args.length; i++) {
  if (args[i] === "--repo") {
    const pair = args[++i] || "";
    const eq = pair.indexOf("=");
    if (eq === -1) {
      console.error(`--repo argument must be <id>=<localPath>, got: ${pair}`);
      process.exit(1);
    }
    repoPaths.set(pair.slice(0, eq), pair.slice(eq + 1));
  }
}

const m = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const repoById = new Map(m.repos.map(r => [r.id, r]));
const allRepoIds = new Set(m.repos.map(r => r.id));
// depends_on entries are strings or { repo, target: true } (declared, not yet actual)
const depsOf = r => r.depends_on.map(d => typeof d === "string" ? { repo: d, target: false } : { repo: d.repo, target: d.target === true });

// --- normalization -----------------------------------------------------

// npm package name -> candidate manifest repo id: strip scope, kebab-case.
function normalizeNpmName(name) {
  const unscoped = name.replace(/^@[^/]+\//, "");
  return unscoped.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}

// pyproject dependency spec ("foo[extra]>=1.0; python_version>='3.8'") ->
// candidate manifest repo id: strip environment markers, extras, version
// specifiers, then underscores/dots -> hyphens.
function normalizePyName(spec) {
  const noMarker = spec.split(";")[0];
  const bareName = noMarker.split(/[\[<>=!~ ,]/)[0];
  return bareName.trim().toLowerCase().replace(/[_.]+/g, "-");
}

// Pull the quoted string literals out of a pyproject.toml [project].dependencies
// array without a TOML parser. Assumes simple quoted entries, which is what
// PEP 621 dependency lists are. Deliberately scoped to the [project] table so
// it does not pick up [project.optional-dependencies] sub-arrays (those are
// extras, not first-party runtime deps, and have different key names).
function extractPyProjectDependencies(text) {
  const projectMatch = text.match(/\n\[project\]([\s\S]*?)(?=\n\[[^\[\n]|\n\[\[|$)/);
  const body = projectMatch ? projectMatch[1] : (text.startsWith("[project]") ? text : "");
  const depsMatch = body.match(/\bdependencies\s*=\s*\[([\s\S]*?)\]/);
  if (!depsMatch) return [];
  const items = [];
  const itemRe = /["']([^"']+)["']/g;
  let mm;
  while ((mm = itemRe.exec(depsMatch[1]))) items.push(mm[1]);
  return items;
}

// Actual first-party manifest-repo dependencies found in a local checkout.
function actualDepsFor(localPath) {
  const found = new Set();

  const pkgPath = path.join(localPath, "package.json");
  if (fs.existsSync(pkgPath)) {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
    for (const name of Object.keys(pkg.dependencies || {})) {
      const norm = normalizeNpmName(name);
      if (allRepoIds.has(norm)) found.add(norm);
    }
  }

  const pyPath = path.join(localPath, "pyproject.toml");
  if (fs.existsSync(pyPath)) {
    const text = fs.readFileSync(pyPath, "utf8");
    for (const spec of extractPyProjectDependencies(text)) {
      const norm = normalizePyName(spec);
      if (allRepoIds.has(norm)) found.add(norm);
    }
  }

  return found;
}

// --- verification --------------------------------------------------------

const errors = [];
let checked = 0;

for (const r of m.repos) {
  const localPath = repoPaths.get(r.id);
  if (localPath === undefined) {
    console.log(`watershed-verify-local: skipping ${r.id} (not passed via --repo; local verification only covers what is locally present)`);
    continue;
  }
  if (!fs.existsSync(localPath)) {
    console.error(`watershed-verify-local: --repo ${r.id}=${localPath} does not exist`);
    process.exit(1);
  }

  checked++;
  const declared = depsOf(r);
  const declaredNonTarget = new Set(declared.filter(d => !d.target).map(d => d.repo));
  const declaredTarget = declared.filter(d => d.target).map(d => d.repo);
  const declaredAll = new Set(declared.map(d => d.repo));
  const actual = actualDepsFor(localPath);

  for (const dep of declaredNonTarget) {
    if (!actual.has(dep)) {
      errors.push(`DECLARED-NOT-ACTUAL: ${r.id} declares ${dep} but no package/pyproject dependency found - either make it real or mark it target: true`);
    }
  }
  for (const dep of actual) {
    if (!declaredAll.has(dep)) {
      errors.push(`UNDECLARED: ${r.id} actually depends on ${dep} but the manifest does not declare it`);
    }
  }
  for (const dep of declaredTarget) {
    if (actual.has(dep)) {
      errors.push(`STALE-TARGET: ${r.id} -> ${dep} is real now; remove the target flag`);
    }
  }
}

if (errors.length) {
  console.error(`watershed-verify-local: ${errors.length} violation(s)\n`);
  for (const e of errors) console.error("  " + e);
  process.exit(1);
}
console.log(`watershed-verify-local: ${checked} repo(s) verified locally, 0 violations.`);
process.exit(0);
