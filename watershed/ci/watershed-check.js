#!/usr/bin/env node
// watershed-check: fails CI if any dependency flows sideways or uphill.
// Usage: node ci/watershed-check.js path/to/watershed.json
// Exit 0: all flows downhill. Exit 1: violations, listed flat.

const fs = require("fs");

const path = process.argv[2] || "watershed.json";
const m = JSON.parse(fs.readFileSync(path, "utf8"));

const errors = [];
const repoById = new Map(m.repos.map(r => [r.id, r]));
const layerIndices = m.layers.map(l => l.index).sort((a, b) => a - b);
const layerByIndex = new Map(m.layers.map(l => [l.index, l]));
// depends_on entries are strings or { repo, target: true } (declared, not yet actual)
const depsOf = r => r.depends_on.map(d => typeof d === "string" ? { repo: d, target: false } : { repo: d.repo, target: d.target === true });
let targetEdges = 0;

// Structural invariants
layerIndices.forEach((v, i) => {
  if (v !== i) errors.push(`layers: indices must be contiguous from 0, found ${JSON.stringify(layerIndices)}`);
});
const basin = repoById.get(m.watershed.basin);
if (!basin) errors.push(`basin: ${m.watershed.basin} not present in repos`);
else {
  if (basin.layer !== 0) errors.push(`basin: ${basin.id} must sit at layer 0, found ${basin.layer}`);
  if (basin.status !== "frozen") errors.push(`basin: ${basin.id} must be frozen, found ${basin.status}`);
}
if (layerByIndex.get(0)?.dependable === false) errors.push(`layers: layer 0 must be dependable; the basin layer is what everything drains toward`);

// Extension invariants
const extIds = new Set();
for (const e of m.extensions || []) {
  if (extIds.has(e.id)) errors.push(`extension ${e.id}: duplicate id (extensions are immutable; new version = new id)`);
  extIds.add(e.id);
  if (e.layer !== 0) errors.push(`extension ${e.id}: defined at layer ${e.layer}; extensions live at layer 0 only`);
  const home = repoById.get(e.defined_in);
  if (!home) errors.push(`extension ${e.id}: defined_in ${e.defined_in} not present in repos`);
  else if (home.layer !== 0) errors.push(`extension ${e.id}: canonical repo ${home.id} is at layer ${home.layer}, must be 0`);
}

// Flow direction: the one rule
for (const r of m.repos) {
  const seen = new Set();
  for (const { repo: depId, target } of depsOf(r)) {
    if (target) targetEdges++;
    if (seen.has(depId)) errors.push(`${r.id}: duplicate dependency ${depId}`);
    seen.add(depId);
    if (depId === r.id) { errors.push(`${r.id}: depends on itself`); continue; }
    const dep = repoById.get(depId);
    if (!dep) { errors.push(`${r.id}: depends on ${depId}, which is not in the manifest`); continue; }
    // Target edges are declared-not-actual, but must still be legal: an illegal
    // aspiration is a plan to violate the invariant, and fails now.
    if (dep.layer === r.layer && r.layer !== 0) errors.push(`${r.id} -> ${depId}: SIDEWAYS. Both at layer ${r.layer}. Shared need goes down into layer 0 as an extension, never sideways.`);
    // Layer 0 is internally stratified (kernel < format < verification); intra-layer deps are
    // legal there. Cycle detection below still guards acyclicity, and the frozen basin still
    // depends on nothing, so the stratigraphy bottoms out.
    if (dep.layer > r.layer) errors.push(`${r.id} -> ${depId}: UPHILL. Layer ${r.layer} depending on layer ${dep.layer}. Water does not flow uphill.`);
    if (layerByIndex.get(dep.layer)?.dependable === false) errors.push(`${r.id} -> ${depId}: NON-DEPENDABLE. Layer ${dep.layer} (${layerByIndex.get(dep.layer).name}) interacts through ledgers at runtime; no code dependency may point into it.`);
    if (dep.status === "archived") errors.push(`${r.id} -> ${depId}: target is archived; nothing may depend on it`);
    if (dep.status === "incubating") errors.push(`${r.id} -> ${depId}: target is incubating; layer assignment provisional, not yet a legal dependency`);
  }
  for (const extId of r.consumes_extensions) {
    if (!extIds.has(extId)) errors.push(`${r.id}: consumes ${extId}, not registered in extensions`);
  }
  if (r.status === "frozen" && r.depends_on.length > 0)
    errors.push(`${r.id}: frozen repos depend on nothing (found ${r.depends_on.length} dependencies)`);
  if (r.status === "legacy") {
    // legacy repos may keep existing deps; enforcement of "may not add" requires manifest history, flagged as advisory
  }
}

// Cycle detection (belt and suspenders; direction rule already prevents cycles across layers,
// but a corrupt manifest with equal-layer errors could still hide one)
const visiting = new Set(), done = new Set();
function walk(id, trail) {
  if (done.has(id)) return;
  if (visiting.has(id)) { errors.push(`cycle: ${[...trail, id].join(" -> ")}`); return; }
  visiting.add(id);
  const r = repoById.get(id);
  if (r) for (const d of depsOf(r)) walk(d.repo, [...trail, id]);
  visiting.delete(id);
  done.add(id);
}
for (const r of m.repos) walk(r.id, []);

if (errors.length) {
  console.error(`watershed-check: ${errors.length} violation(s)\n`);
  for (const e of errors) console.error("  " + e);
  process.exit(1);
}
const forecast = targetEdges > 0 ? ` FORECAST: ${targetEdges} target edge(s) declared, not yet actual.` : "";
console.log(`watershed-check: ${m.repos.length} repos, all flows downhill. Basin: ${m.watershed.basin}.${forecast}`);
process.exit(0);
