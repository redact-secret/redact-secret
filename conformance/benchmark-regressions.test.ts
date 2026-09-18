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
});
