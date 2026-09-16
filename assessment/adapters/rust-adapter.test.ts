import { execFileSync, spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";

describe("rust assessment adapter", () => {
  it("rejects debug performance before executing a workload", () => {
    const result = spawnSync("cargo", ["run", "--locked", "-p", "redact-secret", "--example", "assessment_adapter", "--", "performance", "--profile", "scale-logs-small-whole", "--runs", "2"], { encoding: "utf8" });
    expect(result.status).not.toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("Performance assessment requires a release build");
  }, 30_000);
  it("passes tiny public API self-tests for Unicode, failures, and incomplete runs", () => {
    const output = execFileSync(
      "cargo",
      ["run", "-p", "redact-secret", "--example", "assessment_adapter", "--", "self-test"],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );

    expect(output).toBe("");
  }, 30_000);
});
