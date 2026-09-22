import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const root = process.cwd();

describe("runner source guards", () => {
  it("verifies CLI redact-mode output before emitting an accuracy result", () => {
    const cliRunner = readFileSync(join(root, "scripts", "assessment-cli-run.mjs"), "utf8");
    const callIndex = cliRunner.indexOf("verifyRedactMode(invoke, fixtures, rawFindingsByFixture);");
    const emitIndex = cliRunner.indexOf("await buildAndEmitAccuracyResult(");
    expect(callIndex).toBeGreaterThan(-1);
    expect(emitIndex).toBeGreaterThan(-1);
    expect(callIndex).toBeLessThan(emitIndex);
  });

  it("checks whole-input and incremental output equality in the Python worker", () => {
    const pythonWorker = readFileSync(
      join(root, "scripts", "assessment-python-worker.py"),
      "utf8",
    );
    expect(pythonWorker).toContain("whole.text != incremental_text");
  });
});
