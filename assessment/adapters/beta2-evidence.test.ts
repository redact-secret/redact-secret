import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { validateAssessmentFixtures, validateAssessmentResults } from "../schema.js";

const root = process.cwd();
const evidenceDirectory = join(root, "assessment", "results", "beta.2");

function readJson(relative: string): unknown {
  return JSON.parse(readFileSync(join(evidenceDirectory, relative), "utf8"));
}

describe("beta.2 detection assessment evidence", () => {
  it("reconciles the reported denominators with the fixed corpus", () => {
    const corpusBytes = readFileSync(
      join(root, "assessment", "fixtures", "accuracy-corpus.json"),
    );
    const corpus = JSON.parse(corpusBytes.toString("utf8"));
    const fixtures = validateAssessmentFixtures(corpus.fixtures);
    const summary = readJson("summary.json") as {
      scope: {
        fixtureCount: number;
        categories: Record<string, number>;
        expectedFindingCount: number;
        negativeFixtureCount: number;
      };
    };

    const categories = Object.fromEntries(
      ["logs", "code", "chat", "negative-text"].map((category) => [
        category,
        fixtures.filter((fixture) => fixture.category === category).length,
      ]),
    );
    expect(summary.scope).toEqual({
      fixtureCount: fixtures.length,
      categories,
      expectedFindingCount: fixtures.reduce((total, fixture) => total + fixture.expected.length, 0),
      negativeFixtureCount: fixtures.filter((fixture) => fixture.expected.length === 0).length,
      corpusVersion: corpus.corpusVersion,
      corpusSha256: createHash("sha256").update(corpusBytes).digest("hex"),
    });
  });

  it("pins conforming, cross-surface results and safe range-mismatch evidence", () => {
    const summary = readJson("summary.json") as {
      runs: Array<Record<string, unknown> & { result: string }>;
      confirmedDetectorDefects: number;
    };
    expect(summary.confirmedDetectorDefects).toBe(0);
    expect(summary.runs).toHaveLength(4);

    for (const run of summary.runs) {
      const [result] = validateAssessmentResults([readJson(run.result) as never]);
      expect(result.accuracy).toEqual({
        truePositives: 1,
        falsePositives: 1,
        falseNegatives: 5,
        policyMismatches: 0,
      });
      expect(run).toMatchObject({
        truePositives: 1,
        falsePositives: 1,
        falseNegatives: 5,
        incorrectRanges: 1,
        policyCorrect: 1,
        policyEvaluable: 1,
        negativeFixturesWithFindings: 0,
      });

      const mismatches = readJson(run.result.replace(".json", "-mismatches.json")) as Array<{
        fixtureId: string;
        kind: string;
        detector: string;
        type: string;
      }>;
      expect(mismatches).toHaveLength(6);
      expect(mismatches.filter((mismatch) => mismatch.kind === "missing")).toHaveLength(5);
      expect(mismatches.filter((mismatch) => mismatch.kind === "extra")).toHaveLength(1);
      expect(mismatches.filter((mismatch) => mismatch.kind === "policy-mismatch")).toHaveLength(0);
      expect(mismatches.filter((mismatch) =>
        mismatch.fixtureId === "chat-bearer-token" &&
        mismatch.detector === "bearer-token" &&
        mismatch.type === "bearer_token"
      )).toHaveLength(2);
      expect(JSON.stringify(mismatches)).not.toContain("input");
    }
  });

  it("binds every run to the recorded source and candidate package digests", () => {
    const summary = readJson("summary.json") as {
      sourceCommit: string;
      artifacts: Array<{ name: string; manifestVersion: string; sha256: string }>;
      runs: Array<{ result: string }>;
    };
    const expectedArtifacts = summary.artifacts.map((artifact) => ({
      name: artifact.name,
      version: artifact.manifestVersion,
      sha256: artifact.sha256,
    }));

    for (const run of summary.runs) {
      const result = readJson(run.result) as { provenance: { commit: string } };
      expect(result.provenance.commit).toBe(summary.sourceCommit);
    }

    for (const reportName of [
      "package-node-qualification.json",
      "package-browser-chromium-qualification.json",
      "package-browser-firefox-qualification.json",
      "package-browser-webkit-qualification.json",
    ]) {
      const report = readJson(reportName) as {
        sourceCommit: string;
        packageArtifacts: Array<{ name: string; version: string; sha256: string }>;
        results: Record<string, string>;
      };
      expect(report.sourceCommit).toBe(summary.sourceCommit);
      expect(report.packageArtifacts.map(({ name, version, sha256 }) => ({
        name,
        version,
        sha256,
      }))).toEqual(expectedArtifacts);
      expect(report.results).toMatchObject({
        initialize: "passed",
        scan: "passed",
        incremental: "passed",
        stream: "passed",
      });
    }
  });
});
