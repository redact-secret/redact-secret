import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { validateAssessmentResults } from "../schema.js";

const root = process.cwd();
const evidenceDirectory = join(root, "assessment", "results", "beta.2");

function readJson(relative: string): unknown {
  return JSON.parse(readFileSync(join(evidenceDirectory, relative), "utf8"));
}

/**
 * `accuracy-corpus.json`'s scope as it existed when this evidence was
 * generated (`./README.md`'s "Dataset scope" section): version "1", 9
 * fixtures. Pinned here rather than re-derived from the live corpus file,
 * which issue #248 grows past this snapshot; this report describes only
 * those original 9 fixtures, not however many the corpus holds today.
 */
const FROZEN_CORPUS_SCOPE = {
  fixtureCount: 9,
  categories: { logs: 3, code: 2, chat: 2, "negative-text": 2 },
  expectedFindingCount: 6,
  negativeFixtureCount: 3,
  corpusVersion: "1",
  corpusSha256: "9c72ab77bb1ee54c6912592c2ce3de72c0c152356283d620498aac5fe08c26d9",
};

describe("beta.2 detection assessment evidence", () => {
  it("reconciles the reported denominators with the fixed corpus", () => {
    const summary = readJson("summary.json") as { scope: typeof FROZEN_CORPUS_SCOPE };
    expect(summary.scope).toEqual(FROZEN_CORPUS_SCOPE);
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
