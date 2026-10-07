/**
 * `compareConfigurations` (issue #1254, `configuration-comparison/v1`): the
 * runtime-neutral correspondence of independent passes, and how a result is
 * shaped. Detection, the per-side registries and the Rust core's own
 * `compare_configurations` run against the real artifacts in
 * `real-binding-config.test.ts` from the shared fixture; this file pins the
 * relation itself, edge by edge, without a binding.
 */

import { describe, expect, it } from "vitest";

import { relateFindings, statusOfFailure, toConfigurationComparison } from "../src/configuration-compare.js";
import type { NativeActionComparison } from "../src/native.js";
import type { ComparedConfigurationSummary, ConfigurationFinding } from "../src/types.js";

function finding(start: number, end: number, extra: Partial<ConfigurationFinding> = {}): ConfigurationFinding {
  return {
    type: "jwt",
    detector: "jwt",
    confidence: "high",
    obfuscation: "none",
    start,
    end,
    action: "redact",
    reason: { basis: "default-policy", ruleId: null, ruleIndex: null },
    ...extra,
  };
}

describe("relateFindings", () => {
  it("counts identical pairs and lists nothing for them", () => {
    const side = [finding(0, 10), finding(20, 30)];
    expect(relateFindings(side, side)).toEqual({ entries: [], unchanged: 2 });
  });

  it("names added and removed findings one per entry, in input order", () => {
    const result = relateFindings([finding(0, 10), finding(40, 50)], [finding(20, 30)]);
    expect(result.entries.map((entry) => [entry.kind, entry.base, entry.other, entry.correspondence])).toEqual([
      ["removed", [0], [], null],
      ["added", [], [0], null],
      ["removed", [1], [], null],
    ]);
  });

  it("reports a provider-versus-contextual swap as a change on the same span, not a removal", () => {
    const base = [finding(8, 48, { type: "github_token", detector: "github-token" })];
    const other = [
      finding(8, 48, { type: "contextual_secret", detector: "generic-token", confidence: "medium", action: "warn" }),
    ];
    const { entries } = relateFindings(base, other);
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({ kind: "changed", correspondence: "exact", base: [0], other: [0] });
    expect(entries[0]?.changes).toEqual(["type", "detector", "confidence", "action"]);
  });

  it("separates an action change from a reason-only change", () => {
    const rule = (ruleId: string) => ({ basis: "rule" as const, ruleId, ruleIndex: 0 });
    const reasonOnly = relateFindings([finding(0, 5, { reason: rule("a") })], [finding(0, 5, { reason: rule("b") })]);
    expect(reasonOnly.entries[0]?.changes).toEqual(["reason"]);
    const both = relateFindings(
      [finding(0, 5, { reason: rule("a") })],
      [finding(0, 5, { action: "allow", reason: rule("b") })],
    );
    expect(both.entries[0]?.changes).toEqual(["action", "reason"]);
  });

  it("pairs one finding each over different ranges as an overlap that names the range", () => {
    const { entries } = relateFindings([finding(0, 10)], [finding(2, 14)]);
    expect(entries[0]).toMatchObject({ kind: "changed", correspondence: "overlap", changes: ["range"] });
  });

  it("does not join adjacent findings that do not overlap", () => {
    const result = relateFindings([finding(0, 10)], [finding(10, 20)]);
    expect(result.entries.map((entry) => entry.kind)).toEqual(["removed", "added"]);
  });

  it("lists a split, a merge and a regrouping together and pairs none of them", () => {
    const split = relateFindings([finding(0, 30)], [finding(0, 10), finding(10, 30)]);
    expect(split.entries).toHaveLength(1);
    expect(split.entries[0]).toMatchObject({ kind: "split", correspondence: "ambiguous", base: [0], other: [0, 1] });
    expect(split.entries[0]?.changes).toEqual([]);

    const merged = relateFindings([finding(0, 10), finding(10, 30)], [finding(0, 30)]);
    expect(merged.entries[0]).toMatchObject({ kind: "merged", base: [0, 1], other: [0] });

    const regrouped = relateFindings([finding(0, 10), finding(8, 20)], [finding(0, 6), finding(6, 20)]);
    expect(regrouped.entries[0]).toMatchObject({ kind: "regrouped", base: [0, 1], other: [0, 1] });
    expect(regrouped.unchanged).toBe(0);
  });

  it("is a function of the ranges alone: the unit never changes which findings correspond", () => {
    // UTF-16 ranges over text with an astral character: the same relation as
    // the byte ranges would give, because conversion keeps order and overlap.
    const base = [finding(5, 76)];
    const other = [finding(5, 40), finding(40, 76)];
    expect(relateFindings(base, other).entries[0]?.kind).toBe("split");
  });
});

describe("statusOfFailure", () => {
  it("separates a limit, an unsupported request and an error from a scan", () => {
    expect(statusOfFailure(null)).toBe("scanned");
    expect(statusOfFailure("INPUT_LIMIT_EXCEEDED")).toBe("limited");
    expect(statusOfFailure("FINDING_LIMIT_EXCEEDED")).toBe("limited");
    expect(statusOfFailure("PII_SELECTOR_UNAVAILABLE")).toBe("unsupported");
    expect(statusOfFailure("DETECTION_SELECTION_UNSUPPORTED")).toBe("unsupported");
    expect(statusOfFailure("UNKNOWN_DETECTOR_ID")).toBe("error");
    expect(statusOfFailure("EMPTY_DETECTION_SET")).toBe("error");
  });
});

describe("toConfigurationComparison", () => {
  const summary = (label: string, kind: "default" | "callback" = "default"): ComparedConfigurationSummary => ({
    label,
    digest: "sha256:" + "a".repeat(64),
    detectionDigest: "sha256:" + "b".repeat(64),
    origins: null,
    diagnostics: [],
    policy: { kind, documentSha256: null },
  });
  const native = (starts: readonly number[]): NativeActionComparison => ({
    detection: { activationIdentity: "x", profile: "full", detectorCount: 1 },
    sides: [{ kind: "default", redact: starts.length, block: 0, warn: 0, allow: 0 }],
    changedCount: 0,
    findings: starts.map((start) => ({
      id: `finding-${start}`,
      type: "jwt",
      detector: "jwt",
      confidence: "high",
      obfuscation: "none",
      start,
      end: start + 5,
      differs: false,
      decisions: [{ action: "redact", basis: "default-policy" }],
    })),
  });

  it("is a frozen, non-enforcing, input-scoped preview with no per-scan id", () => {
    const comparison = toConfigurationComparison([
      { summary: summary("baseline"), failure: null, native: native([0]) },
      { summary: summary("candidate-1"), failure: null, native: native([0, 10]) },
    ]);
    expect(comparison).toMatchObject({
      schema: "configuration-comparison/v1",
      scope: "input",
      mode: "preview",
      enforced: false,
      rangeUnit: "utf16-code-units",
    });
    expect(Object.isFrozen(comparison)).toBe(true);
    expect(Object.isFrozen(comparison.results[1])).toBe(true);
    expect(comparison.differences[0]).toBeNull();
    expect(comparison.differences[1]?.entries.map((entry) => entry.kind)).toEqual(["added"]);
    expect(JSON.stringify(comparison)).not.toContain("finding-");
  });

  it("reports no difference against, or for, a side that did not scan", () => {
    const failed = { summary: summary("candidate-1"), failure: "INPUT_LIMIT_EXCEEDED", native: null };
    const scanned = { summary: summary("baseline"), failure: null, native: native([0]) };

    const failedCandidate = toConfigurationComparison([scanned, failed]);
    expect(failedCandidate.results[1]).toMatchObject({
      status: "limited",
      failure: "INPUT_LIMIT_EXCEEDED",
      findings: [],
    });
    expect(failedCandidate.differences).toEqual([null, null]);

    const failedBaseline = toConfigurationComparison([{ ...failed, summary: summary("baseline") }, scanned]);
    expect(failedBaseline.results[0]?.status).toBe("limited");
    expect(failedBaseline.differences).toEqual([null, null]);
  });

  it("never claims the absence of risk: a side with no finding is scanned with no finding, nothing more", () => {
    const comparison = toConfigurationComparison([
      { summary: summary("baseline"), failure: null, native: native([]) },
      { summary: summary("candidate-1"), failure: null, native: native([]) },
    ]);
    expect(comparison.results.map((result) => result.status)).toEqual(["scanned", "scanned"]);
    expect(comparison.differences[1]).toEqual({ entries: [], unchanged: 0 });
    expect(Object.keys(comparison).sort()).toEqual([
      "callbackSides",
      "configs",
      "differences",
      "enforced",
      "mode",
      "rangeUnit",
      "results",
      "schema",
      "scope",
      "version",
    ]);
  });

  it("names the callback sides, which have no identity", () => {
    const comparison = toConfigurationComparison([
      { summary: summary("baseline", "callback"), failure: null, native: native([]) },
      { summary: summary("candidate-1"), failure: null, native: native([]) },
      { summary: summary("candidate-2", "callback"), failure: null, native: native([]) },
    ]);
    expect(comparison.callbackSides).toEqual([0, 2]);
  });
});
