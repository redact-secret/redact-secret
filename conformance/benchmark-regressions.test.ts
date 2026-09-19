import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import {
  validateBenchmarkRegressionManifest,
  type BenchmarkRegressionManifest,
} from "./benchmark-regressions.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const readJson = <T>(...segments: readonly string[]): T =>
  JSON.parse(readFileSync(path.join(HERE, ...segments), "utf8")) as T;

const synchronous = readJson<{ fixtures: { id: string }[] }>("fixtures", "synchronous-corpus.json");
const incremental = readJson<{ fixtures: { id: string }[] }>("fixtures", "incremental-corpus.json");
const manifest = readJson<BenchmarkRegressionManifest>("benchmark-regressions.json");
const index = {
  synchronous: new Set(synchronous.fixtures.map(({ id }) => id)),
  incremental: new Set(incremental.fixtures.map(({ id }) => id)),
};

const clone = (): BenchmarkRegressionManifest => structuredClone(manifest);

describe("benchmark regression provenance", () => {
  test("the checked-in manifest validates against canonical fixture identities", () => {
    expect(validateBenchmarkRegressionManifest(manifest, index)).toBe(manifest);
  });

  test("rejects an unknown canonical fixture reference", () => {
    const candidate = clone();
    (candidate.records[1].canonicalFixtures.synchronous as string[])[0] = "unknown-fixture";
    expect(() => validateBenchmarkRegressionManifest(candidate, index))
      .toThrow(/unknown-synchronous-fixture/);
  });

  test("rejects a passed product gate without a canonical fixture and evidence", () => {
    const candidate = clone();
    (candidate.records[0].gates.productConformance as { status: string; evidence: string[] }).status = "passed";
    expect(() => validateBenchmarkRegressionManifest(candidate, index))
      .toThrow(/invalid-product-gate/);
  });

  test("rejects extra fields that could carry benchmark payloads", () => {
    const candidate = clone() as BenchmarkRegressionManifest & { input?: string };
    candidate.input = "forbidden";
    expect(() => validateBenchmarkRegressionManifest(candidate, index))
      .toThrow(/invalid-metadata/);
  });

  test("rejects a non-40-hex benchmarkCommit", () => {
    const candidate = clone() as BenchmarkRegressionManifest & {
      records: (BenchmarkRegressionManifest["records"][number] & { benchmarkCommit?: string })[];
    };
    candidate.records[0].benchmarkCommit = "not-a-commit";
    expect(() => validateBenchmarkRegressionManifest(candidate, index))
      .toThrow(/invalid-metadata/);
  });

  test("rejects an unknown key alongside benchmarkCommit", () => {
    const candidate = clone() as BenchmarkRegressionManifest & {
      records: (BenchmarkRegressionManifest["records"][number] & { benchmarkRevision?: string })[];
    };
    candidate.records[0].benchmarkRevision = "8d8d5b4e8dae8de1b42e174d8d21dc0075147fc6";
    expect(() => validateBenchmarkRegressionManifest(candidate, index))
      .toThrow(/invalid-metadata/);
  });

  test("rejects a passed benchmark revalidation gate without benchmarkCommit", () => {
    const candidate = clone();
    (candidate.records[0].gates.benchmarkRevalidation as { status: string; evidence: string[] }).status = "passed";
    (candidate.records[0].gates.benchmarkRevalidation as { status: string; evidence: string[] }).evidence = [
      "https://example.invalid/evidence",
    ];
    expect(() => validateBenchmarkRegressionManifest(candidate, index))
      .toThrow(/passed-without-benchmark-commit/);
  });
});
