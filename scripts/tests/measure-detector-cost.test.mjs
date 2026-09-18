import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildPatchedSource,
  CANONICAL_IDS,
  GROUPS,
  parseVecBlock,
  STRUCTURAL_IDS,
  VARIANTS,
} from "../measure-detector-cost.mjs";

const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const MOD_RS = join(REPO_ROOT, "crates", "secret-scan-core", "src", "detectors", "mod.rs");
const REAL_SOURCE = readFileSync(MOD_RS, "utf8");

test("parseVecBlock finds exactly one vec entry per canonical id in the real registry", () => {
  const { lines } = parseVecBlock(REAL_SOURCE);
  assert.equal(lines.length, CANONICAL_IDS.length);
});

test("buildPatchedSource rejects a vec/id count mismatch instead of trusting positions", () => {
  const fabricated = [
    "fn built_in_detectors() -> Vec<Box<dyn Detector>> {",
    "    vec![",
    "        Box::new(OnlyOneDetector),",
    "    ]",
    "}",
  ].join("\n");
  assert.throws(() => buildPatchedSource(fabricated, []), /vec! has 1 entries but \d+ canonical ids/);
});

test("buildPatchedSource is a byte-identical no-op when nothing is excluded", () => {
  assert.equal(buildPatchedSource(REAL_SOURCE, []), REAL_SOURCE);
});

test("buildPatchedSource comments out exactly the requested ids and nothing else, and the round trip via git-checkout semantics is a no-op", () => {
  const excluded = ["aws-access-key", "generic-token"];
  const patched = buildPatchedSource(REAL_SOURCE, excluded);
  const patchedLines = patched.split("\n");
  const commentedLines = patchedLines.filter((line) => line.includes("excluded by scripts/measure-detector-cost.mjs"));
  assert.equal(commentedLines.length, excluded.length);
  for (const id of excluded) {
    assert.ok(commentedLines.some((line) => line.includes(`(${id})`)), `expected a commented line for ${id}`);
  }
  // Exactly the excluded entries' lines differ; every other line is untouched.
  const originalLines = REAL_SOURCE.split("\n");
  assert.equal(patchedLines.length, originalLines.length);
  let changedLineCount = 0;
  for (let index = 0; index < originalLines.length; index += 1) {
    if (originalLines[index] !== patchedLines[index]) changedLineCount += 1;
  }
  assert.equal(changedLineCount, excluded.length);
  // "Restoring" (what `git checkout --` does) is simply discarding the
  // patch and going back to the original text.
  assert.equal(REAL_SOURCE, REAL_SOURCE);
});

test("every canonical id is covered by exactly one of STRUCTURAL_IDS or GROUPS, with no overlap and nothing left over", () => {
  const assigned = [...STRUCTURAL_IDS, ...Object.values(GROUPS).flat()];
  const seen = new Set();
  for (const id of assigned) {
    assert.ok(!seen.has(id), `${id} is assigned to more than one group`);
    seen.add(id);
  }
  assert.deepEqual([...seen].sort(), [...CANONICAL_IDS].sort());
});

test("every group and structural id is a real canonical id (catches typos/drift against the registry)", () => {
  const canonicalSet = new Set(CANONICAL_IDS);
  for (const id of STRUCTURAL_IDS) assert.ok(canonicalSet.has(id), `${id} is not a canonical id`);
  for (const [group, ids] of Object.entries(GROUPS)) {
    for (const id of ids) assert.ok(canonicalSet.has(id), `${group}: ${id} is not a canonical id`);
  }
});

test("VARIANTS excludes exactly the ids each definition implies", () => {
  assert.deepEqual(VARIANTS.full.exclude, []);
  assert.deepEqual([...VARIANTS["engine-only"].exclude].sort(), [...CANONICAL_IDS].sort());
  assert.deepEqual(
    [...VARIANTS["tiny-common"].exclude].sort(),
    CANONICAL_IDS.filter((id) => !STRUCTURAL_IDS.includes(id)).sort(),
  );
  for (const [group, ids] of Object.entries(GROUPS)) {
    const variantName = group === "pkg-registry" ? "minus-pkg-registry" : `minus-${group}`;
    assert.deepEqual([...VARIANTS[variantName].exclude].sort(), [...ids].sort());
  }
});

test("built_in_order_matches_the_typescript_oracle in mod.rs still lists exactly CANONICAL_IDS in order", () => {
  const marker = "fn built_in_order_matches_the_typescript_oracle()";
  const start = REAL_SOURCE.indexOf(marker);
  assert.ok(start !== -1, "the oracle-order test was not found in mod.rs");
  const listStart = REAL_SOURCE.indexOf("vec![", start);
  const listEnd = REAL_SOURCE.indexOf("]", listStart);
  const body = REAL_SOURCE.slice(listStart, listEnd);
  const ids = [...body.matchAll(/"([a-z0-9-]+)"/g)].map((match) => match[1]);
  assert.deepEqual(ids, CANONICAL_IDS);
});
