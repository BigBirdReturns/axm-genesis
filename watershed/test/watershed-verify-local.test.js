#!/usr/bin/env node
// Tests for watershed-verify-local: the receipt check that reads actual
// package.json / pyproject.toml dependencies and diffs them against a
// watershed manifest. Node, no dependencies, same plain style as
// watershed-check.test.js.

const { execFileSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const VERIFY = path.join(__dirname, "..", "ci", "watershed-verify-local.js");
const EXAMPLE = path.join(__dirname, "..", "example", "axm.watershed.json");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "watershed-verify-test-"));

function writeJSON(file, obj) {
  fs.writeFileSync(file, JSON.stringify(obj, null, 2));
}

function baseManifest(overrides) {
  const m = {
    watershed: { name: "t", version: "0.0.1", basin: "kernel" },
    layers: [
      { index: 0, name: "protocol", rule: "defines" },
      { index: 1, name: "instruments", rule: "produce" },
    ],
    extensions: [],
    repos: [
      { id: "kernel", url: "x", layer: 0, depends_on: [], consumes_extensions: [], status: "frozen" },
      { id: "widget", url: "x", layer: 1, depends_on: ["kernel"], consumes_extensions: [], status: "active" },
    ],
  };
  return Object.assign(m, overrides);
}

function run(args) {
  try {
    const out = execFileSync("node", [VERIFY, ...args], { encoding: "utf8" });
    return { code: 0, out };
  } catch (e) {
    return { code: e.status, out: (e.stdout ?? "") + (e.stderr ?? "") };
  }
}

function assert(cond, label, got) {
  if (!cond) { console.error(`FAIL: ${label}\n${got}`); process.exit(1); }
  console.log(`  ok: ${label}`);
}

function mkRepoDir(name) {
  const d = path.join(tmp, name + "-" + Math.floor(Math.random() * 1e9));
  fs.mkdirSync(d, { recursive: true });
  return d;
}

// 1. DECLARED-NOT-ACTUAL: manifest says widget depends on kernel, but
// widget's package.json has no such dependency.
{
  const manifestFile = path.join(tmp, "m1.json");
  writeJSON(manifestFile, baseManifest());

  const kernelDir = mkRepoDir("kernel");
  const widgetDir = mkRepoDir("widget");
  writeJSON(path.join(widgetDir, "package.json"), { name: "widget", dependencies: {} });

  const r = run([manifestFile, "--repo", `kernel=${kernelDir}`, "--repo", `widget=${widgetDir}`]);
  assert(r.code === 1 && r.out.includes("DECLARED-NOT-ACTUAL: widget declares kernel"), "declared-not-actual fails", r.out);
}

// 2. UNDECLARED: widget's package.json actually depends on kernel via npm,
// but the manifest doesn't declare it.
{
  const manifestFile = path.join(tmp, "m2.json");
  const m = baseManifest();
  m.repos.find(x => x.id === "widget").depends_on = [];
  writeJSON(manifestFile, m);

  const kernelDir = mkRepoDir("kernel");
  const widgetDir = mkRepoDir("widget");
  writeJSON(path.join(widgetDir, "package.json"), { name: "widget", dependencies: { "@scope/kernel": "^1.0.0" } });

  const r = run([manifestFile, "--repo", `kernel=${kernelDir}`, "--repo", `widget=${widgetDir}`]);
  assert(r.code === 1 && r.out.includes("UNDECLARED: widget actually depends on kernel"), "undeclared fails", r.out);
}

// 3. STALE-TARGET: manifest marks widget -> kernel as target: true, but
// widget's pyproject.toml already lists it as a real dependency.
{
  const manifestFile = path.join(tmp, "m3.json");
  const m = baseManifest();
  m.repos.find(x => x.id === "widget").depends_on = [{ repo: "kernel", target: true }];
  writeJSON(manifestFile, m);

  const kernelDir = mkRepoDir("kernel");
  const widgetDir = mkRepoDir("widget");
  fs.writeFileSync(path.join(widgetDir, "pyproject.toml"), [
    "[project]",
    'name = "widget"',
    "dependencies = [",
    '  "kernel>=1.0.0",',
    '  "requests>=2.0",',
    "]",
    "",
  ].join("\n"));

  const r = run([manifestFile, "--repo", `kernel=${kernelDir}`, "--repo", `widget=${widgetDir}`]);
  assert(r.code === 1 && r.out.includes("STALE-TARGET: widget -> kernel is real now"), "stale-target fails", r.out);
}

// 4. Clean repo passes: declared dep matches actual npm dep exactly, no
// undeclared extras, no stale targets. Unrelated deps (not other manifest
// repo ids) and devDependencies are ignored.
{
  const manifestFile = path.join(tmp, "m4.json");
  writeJSON(manifestFile, baseManifest());

  const kernelDir = mkRepoDir("kernel");
  const widgetDir = mkRepoDir("widget");
  writeJSON(path.join(widgetDir, "package.json"), {
    name: "widget",
    dependencies: { kernel: "^1.0.0", lodash: "^4.0.0" },
    devDependencies: { jest: "^29.0.0" },
  });

  const r = run([manifestFile, "--repo", `kernel=${kernelDir}`, "--repo", `widget=${widgetDir}`]);
  assert(r.code === 0 && r.out.includes("0 violations"), "clean repo passes", r.out);
}

// 5. Vendored conformance is not a package dependency: a repo can vendor
// another repo's fixtures/vectors as files (not through package.json /
// pyproject.toml) without tripping UNDECLARED, because this checker only
// ever reads package manifests.
{
  const manifestFile = path.join(tmp, "m5.json");
  const m = baseManifest();
  m.repos.find(x => x.id === "widget").depends_on = [];
  writeJSON(manifestFile, m);

  const kernelDir = mkRepoDir("kernel");
  const widgetDir = mkRepoDir("widget");
  fs.mkdirSync(path.join(widgetDir, "vendor", "kernel-vectors"), { recursive: true });
  fs.writeFileSync(path.join(widgetDir, "vendor", "kernel-vectors", "vectors.json"), "[]");
  writeJSON(path.join(widgetDir, "package.json"), { name: "widget", dependencies: {} });

  const r = run([manifestFile, "--repo", `kernel=${kernelDir}`, "--repo", `widget=${widgetDir}`]);
  assert(r.code === 0 && r.out.includes("0 violations"), "vendored conformance does not trigger undeclared", r.out);
}

// 6. Skipped repo: a manifest repo not passed via --repo is noted, not
// treated as a violation, and does not affect the exit code.
{
  const manifestFile = path.join(tmp, "m6.json");
  writeJSON(manifestFile, baseManifest());

  const kernelDir = mkRepoDir("kernel");
  const r = run([manifestFile, "--repo", `kernel=${kernelDir}`]);
  assert(r.code === 0, "repo not passed via --repo is skipped, not a violation", r.out);
  assert(r.out.includes("skipping widget"), "skip note printed for repo not covered locally", r.out);
}

// 7. The shipped example manifest, checked against axm-genesis itself (no
// package.json, pyproject.toml declares no first-party manifest deps),
// passes clean for the one repo present.
{
  const genesisRoot = path.join(__dirname, "..", "..");
  const r = run([EXAMPLE, "--repo", `axm-genesis=${genesisRoot}`]);
  assert(r.code === 0 && r.out.includes("1 repo(s) verified locally, 0 violations"), "example manifest verifies clean against real axm-genesis checkout", r.out);
}

fs.rmSync(tmp, { recursive: true, force: true });
console.log("watershed-verify-local.test: OK");
