// Tests of the scoped local checks (issue #896): every gate in `npm run ci`
// belongs to at least one `check:<scope>` script, and scripts/check-scope.mjs
// maps changed paths to those scopes deterministically.
import assert from "node:assert/strict";
import test from "node:test";

import { commands, loadScripts, npmRunTargets, recommend, SCOPES } from "../check-scope.mjs";

const scripts = loadScripts();
const ciGates = npmRunTargets(scripts.ci);
// Gates a scope may run beyond `npm run ci`: CI runs them in its Rust job.
const NON_CI_SCOPE_GATES = new Set(["rust:check"]);

function scopeGates(scope) {
  return npmRunTargets(scripts[`check:${scope}`]);
}

test("npm run ci chains gates and every gate is a defined script", () => {
  assert.ok(ciGates.length >= 40, `expected the full suite, found ${ciGates.length} gates`);
  for (const gate of ciGates) assert.ok(scripts[gate], `ci runs undefined script ${gate}`);
  assert.ok(ciGates.includes("check-scopes:test"), "ci must run this drift test");
});

test("every scope has a check:<scope> script and no other check:<scope> exists", () => {
  const defined = Object.keys(scripts)
    .filter((name) => name.startsWith("check:") && name !== "check:changed")
    .map((name) => name.slice("check:".length));
  assert.deepEqual([...defined].sort(), [...SCOPES].sort());
});

test("every gate in npm run ci belongs to at least one scope", () => {
  const covered = new Set(SCOPES.flatMap(scopeGates));
  const uncovered = ciGates.filter((gate) => !covered.has(gate));
  assert.deepEqual(uncovered, [], `add each to a check:<scope> script in package.json`);
});

test("a scope runs only suite gates, never the whole suite", () => {
  for (const scope of SCOPES) {
    const gates = scopeGates(scope);
    assert.ok(gates.length > 0, `check:${scope} runs no gate`);
    for (const gate of gates) {
      assert.notEqual(gate, "ci", `check:${scope} must not run the full suite`);
      assert.ok(
        ciGates.includes(gate) || NON_CI_SCOPE_GATES.has(gate),
        `check:${scope} runs ${gate}, which is not a CI gate`,
      );
    }
  }
});

test("maps each change type to its scopes", () => {
  const cases = [
    [["docs/guides/reporting-detection-issues.md"], ["docs"]],
    [["CONTRIBUTION.md"], ["docs"]],
    [["docs/decisions/DECISIONS.md", "docs/specs/engine.md"], ["docs"]],
    [["docs/coverage/detector-inventory.json"], ["docs", "detector"]],
    [["crates/secret-scan-core/src/detectors/mod.rs"], ["detector", "rust"]],
    [["crates/secret-scan-cli/src/main.rs"], ["rust"]],
    [["conformance/fixtures/synchronous-corpus.json"], ["detector", "js", "rust"]],
    [["packages/javascript/src/index.ts"], ["js"]],
    [["bindings/wasm/src/lib.rs"], ["js", "rust"]],
    [["bindings/python/pyproject.toml"], ["rust", "release"]],
    [[".github/workflows/release.yml"], ["release"]],
  ];
  for (const [paths, scopes] of cases) {
    const result = recommend(paths, scripts);
    assert.equal(result.full, false, paths.join(", "));
    assert.deepEqual(result.scopes, scopes, paths.join(", "));
  }
});

test("a changed gate script or its test selects that gate first", () => {
  const checker = recommend(["scripts/check-doc-links.py"], scripts);
  assert.deepEqual(checker.gates, ["doc-links:check"]);
  assert.deepEqual(commands(checker), ["doc-links:check", "check:release"]);
  const unit = recommend(["scripts/tests/test_check_doc_links.py"], scripts);
  assert.deepEqual(unit.gates, ["doc-links:check"]);
});

test("an unscoped path falls back to the full suite", () => {
  const result = recommend(["docs/a.md", ".gitignore"], scripts);
  assert.equal(result.full, true);
  assert.deepEqual(result.unmatched, [".gitignore"]);
  assert.deepEqual(commands(result), ["ci"]);
});
