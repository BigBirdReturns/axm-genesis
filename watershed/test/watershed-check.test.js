#!/usr/bin/env node
// Negative tests for watershed-check. Node, no dependencies.
// Each fixture is a minimal manifest; we assert exit code and message substring.

const { execFileSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const CHECK = path.join(__dirname, "..", "ci", "watershed-check.js");
const EXAMPLE = path.join(__dirname, "..", "example", "axm.watershed.json");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "watershed-test-"));

function base() {
  return {
    watershed: { name: "t", version: "0.0.1", basin: "kernel" },
    layers: [
      { index: 0, name: "protocol", rule: "defines" },
      { index: 1, name: "attention", rule: "observes via ledgers", dependable: false },
      { index: 2, name: "instruments", rule: "produce" },
    ],
    extensions: [],
    repos: [
      { id: "kernel", url: "x", layer: 0, depends_on: [], consumes_extensions: [], status: "frozen" },
      { id: "watcher", url: "x", layer: 1, depends_on: ["kernel"], consumes_extensions: [], status: "active" },
      { id: "tool", url: "x", layer: 2, depends_on: ["kernel"], consumes_extensions: [], status: "active" },
    ],
  };
}

function run(manifest) {
  const f = path.join(tmp, `m${Math.floor(Math.random() * 1e9)}.json`);
  fs.writeFileSync(f, JSON.stringify(manifest));
  try {
    const out = execFileSync("node", [CHECK, f], { encoding: "utf8" });
    return { code: 0, out };
  } catch (e) {
    return { code: e.status, out: (e.stdout ?? "") + (e.stderr ?? "") };
  }
}

function assert(cond, label, got) {
  if (!cond) { console.error(`FAIL: ${label}\n${got}`); process.exit(1); }
  console.log(`  ok: ${label}`);
}

// 1. clean manifest passes
let r = run(base());
assert(r.code === 0, "clean manifest passes", r.out);

// 2. edge into a non-dependable layer fails, even downhill-adjacent
let m = base();
m.repos.find(x => x.id === "tool").depends_on = ["kernel", "watcher"];
r = run(m);
assert(r.code === 1 && r.out.includes("NON-DEPENDABLE"), "edge into non-dependable layer fails", r.out);

// 3. target edge must still flow downhill: uphill target fails
m = base();
m.repos.find(x => x.id === "watcher").depends_on = [{ repo: "tool", target: true }];
r = run(m);
assert(r.code === 1 && r.out.includes("UPHILL"), "uphill target edge fails", r.out);

// 4. legal target edge passes and is labeled FORECAST
m = base();
m.repos.find(x => x.id === "tool").depends_on = [{ repo: "kernel", target: true }];
r = run(m);
assert(r.code === 0 && r.out.includes("FORECAST: 1 target edge"), "downhill target edge passes as FORECAST", r.out);

// 5. frozen repos depend on nothing, target or not
m = base();
m.repos.find(x => x.id === "kernel").depends_on = [{ repo: "tool", target: true }];
r = run(m);
assert(r.code === 1 && r.out.includes("frozen repos depend on nothing"), "frozen repo with target dep fails", r.out);

// 6. layer 0 may not be non-dependable
m = base();
m.layers.find(l => l.index === 0).dependable = false;
r = run(m);
assert(r.code === 1 && r.out.includes("layer 0 must be dependable"), "non-dependable layer 0 fails", r.out);

// 7. sideways target edge fails (aspiration to violate is a violation)
m = base();
m.repos.push({ id: "tool2", url: "x", layer: 2, depends_on: [{ repo: "tool", target: true }], consumes_extensions: [], status: "active" });
r = run(m);
assert(r.code === 1 && r.out.includes("SIDEWAYS"), "sideways target edge fails", r.out);

// 8. the shipped example manifest passes
try {
  const out = execFileSync("node", [CHECK, EXAMPLE], { encoding: "utf8" });
  assert(out.includes("all flows downhill"), "example manifest passes", out);
} catch (e) {
  assert(false, "example manifest passes", (e.stdout ?? "") + (e.stderr ?? ""));
}

fs.rmSync(tmp, { recursive: true, force: true });
console.log("watershed-check.test: OK");
