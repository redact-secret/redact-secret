import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  agreedResolvedArtifact,
  resolvedNodeArtifact,
} from "../../scripts/lib/assessment-provenance.mjs";

// benchmarks #405/#415: a node performance result must name the artifact
// `initialize()` loaded, because the loader can fall back from the N-API
// addon to WebAssembly.
describe("node performance resolved artifact", () => {
  it("maps artifact() to the provenance vocabulary and rejects anything else", () => {
    expect(resolvedNodeArtifact("addon")).toBe("node-addon");
    expect(resolvedNodeArtifact("wasm")).toBe("wasm");
    expect(() => resolvedNodeArtifact(undefined)).toThrow(/expected "addon" or "wasm"/);
    expect(() => resolvedNodeArtifact("node-addon")).toThrow(/expected "addon" or "wasm"/);
  });

  it("requires every sample of a run to agree on one artifact", () => {
    expect(agreedResolvedArtifact(["addon", "addon"])).toBe("node-addon");
    expect(() => agreedResolvedArtifact(["addon", "wasm"])).toThrow(/node-addon and wasm/);
    expect(() => agreedResolvedArtifact([])).toThrow(/no artifact/);
  });

  it("stamps the agreed artifact into the emitted provenance", () => {
    const runner = readFileSync(join(process.cwd(), "scripts", "assessment-node-performance.mjs"), "utf8");
    expect(runner).toContain("const artifact = api.artifact();");
    expect(runner).toContain("agreedResolvedArtifact(samples.map((sample) => sample.artifact))");
    const stamp = runner.indexOf("      resolvedArtifact,\n    },");
    expect(stamp).toBeGreaterThan(runner.indexOf("await buildAndEmitPerformanceResult("));
  });
});
