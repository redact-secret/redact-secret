import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { parseArguments, stageWorkerProject } from "../qualify-workerd-artifact.mjs";

test("edge qualifier rejects ambiguous inputs, missing values, and unsupported profiles", () => {
  for (const args of [
    [],
    ["--candidate-dir"],
    ["--wasm-dir", "a", "--candidate-dir", "b"],
    ["--candidate-dir", "a", "--detector-profile", "custom"],
  ]) {
    assert.throws(() => parseArguments(args));
  }
});

test("edge staging rejects a directory without immutable core tarball", async () => {
  const directory = await mkdtemp(join(tmpdir(), "redact-secret-edge-invalid-"));
  try {
    await writeFile(join(directory, "unpacked.js"), "synthetic");
    await assert.rejects(
      stageWorkerProject("full", { input: "synthetic", expected: [] }, "0.1.0-beta.14", undefined, directory),
      /holds no @redact-secret\/core tarball/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
