import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";

describe("cli assessment adapter", () => {
  it("passes tiny known-answer self-tests for Unicode, failures, and redaction", () => {
    const output = execFileSync(
      "node",
      ["scripts/assessment-cli-run.mjs", "--self-test"],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );

    expect(output).toBe("");
  }, 120_000);
});
