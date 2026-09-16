import assert from "node:assert/strict";
import test from "node:test";

import {
  CLI_ARGUMENT_BUDGET,
  batchArguments,
} from "../lib/cli-qualification-batches.mjs";

test("partitions an expanded corpus without losing or reordering paths", () => {
  const paths = Array.from(
    { length: 500 },
    (_, index) => `C:\\a\\redact-secret\\fixture-${String(index).padStart(4, "0")}-${"x".repeat(80)}.txt`,
  );
  const batches = batchArguments(paths);

  assert.ok(batches.length > 1);
  assert.deepEqual(batches.flat(), paths);
  for (const batch of batches) {
    const conservativeLength = batch.reduce((total, path) => total + path.length * 2 + 3, 0);
    assert.ok(conservativeLength <= CLI_ARGUMENT_BUDGET);
  }
});

test("rejects invalid budgets and an individually oversized path", () => {
  assert.throws(() => batchArguments(["fixture.txt"], 0), /positive safe integer/);
  assert.throws(() => batchArguments(["x".repeat(100)], 100), /exceeds/);
});

test("returns no empty batch for an empty corpus", () => {
  assert.deepEqual(batchArguments([]), []);
});
