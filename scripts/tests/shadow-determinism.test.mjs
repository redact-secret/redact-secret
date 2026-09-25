// Tests of scripts/shadow-determinism.mjs (issue #772). Every value is
// synthetic.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  MAX_CONTEXT_VALUE_BYTES,
  deBruijnPairs,
  firstDifference,
  hostileBattery,
  hostileValues,
  lcgValue,
  qualificationInputs,
  summarize,
} from "../shadow-determinism.mjs";

const SCRIPT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "shadow-determinism.mjs");

test("the generators match the Rust qualification tests", () => {
  // crates/secret-scan-core/src/evidence/qualification_tests.rs pins the same prefixes.
  assert.equal(lcgValue(0x772, 24), "MFtPoopPWwgzkd6zUjyF86fh");
  const pairs = deBruijnPairs(62);
  assert.equal(pairs.length, 62 * 62);
  assert.equal(pairs.slice(0, 12), "001020304050");
  const bigrams = new Set();
  for (let i = 0; i + 1 < pairs.length; i += 1) bigrams.add(pairs.slice(i, i + 2));
  assert.equal(bigrams.size, pairs.length - 1, "no bigram repeats");
});

test("hostile values stay within one contextual value except the over-length case", () => {
  for (const [name, value] of hostileValues()) {
    const bytes = Buffer.byteLength(value, "utf8");
    if (name === "over-max-length") assert.equal(bytes, MAX_CONTEXT_VALUE_BYTES + 1, name);
    else assert.ok(bytes <= MAX_CONTEXT_VALUE_BYTES + 2048, `${name}: ${bytes}`);
  }
});

test("the input set is deterministic, uniquely named and covers every corpus", () => {
  const first = qualificationInputs();
  const second = qualificationInputs();
  assert.deepEqual(first, second);
  const ids = first.map(([id]) => id);
  assert.equal(new Set(ids).size, ids.length);
  for (const prefix of ["synchronous/", "incremental/", "unicode/", "hostile/"]) {
    assert.ok(ids.some((id) => id.startsWith(prefix)), prefix);
  }
  assert.equal(hostileBattery().length, hostileValues().length * 4 + 2);
});

const HEADER = '{"record":"shadow-evaluation","productVersion":"0","model":"m","featureSchema":"f","artifactRevision":1,"modelFingerprint":"x","profile":"full"}';
const STATISTICAL = '{"record":"shadow-comparison","authority":"statistical","band":"high","promotion":"preserve"}';
const DETERMINISTIC = '{"record":"shadow-comparison","authority":"deterministic","band":"high","promotion":"preserve"}';

test("summarize counts records and never needs one", () => {
  const summary = summarize(`${HEADER}\n${STATISTICAL}\n${DETERMINISTIC}\n{"record":"shadow-error","code":"E"}\n`);
  assert.equal(summary.lines, 4);
  assert.equal(summary.comparisons, 2);
  assert.equal(summary.statistical, 1);
  assert.equal(summary.deterministic, 1);
  assert.equal(summary.errors, 1);
  assert.deepEqual(summary.statisticalBands, { none: 0, low: 0, medium: 0, high: 1 });
  assert.equal(summary.header.profile, "full");
});

test("firstDifference names the first differing line", () => {
  assert.equal(firstDifference("a\nb\n", "a\nb\n"), 0);
  assert.equal(firstDifference("a\nb\n", "a\nc\n"), 2);
  assert.equal(firstDifference("a\n", "a\nb\n"), 2);
});

test("compare exits 0 on identical outputs and 1 on any difference", () => {
  const dir = mkdtempSync(join(tmpdir(), "shadow-determinism-"));
  const same = join(dir, "same.jsonl");
  const other = join(dir, "other.jsonl");
  writeFileSync(same, `${HEADER}\n${STATISTICAL}\n`);
  writeFileSync(other, `${HEADER}\n${DETERMINISTIC}\n`);
  const identical = spawnSync(process.execPath, [SCRIPT, "compare", `a=${same}`, `b=${same}`], { encoding: "utf8" });
  assert.equal(identical.status, 0, identical.stderr);
  assert.equal(JSON.parse(identical.stdout).crossRuntimeMismatches, 0);
  const different = spawnSync(process.execPath, [SCRIPT, "compare", `a=${same}`, `b=${same}`, `c=${other}`], {
    encoding: "utf8",
  });
  assert.equal(different.status, 1);
  const report = JSON.parse(different.stdout);
  assert.equal(report.crossRuntimeMismatches, 1);
  assert.deepEqual(report.mismatches, [{ reference: "a", label: "c", line: 2 }]);
  assert.ok(!different.stdout.includes('"authority"'), "the report holds no record");
});
