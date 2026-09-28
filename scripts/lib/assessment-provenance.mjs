/**
 * Reproducibility provenance shared by every surface's accuracy-assessment
 * runner (`scripts/assessment-run.mjs` for Node,
 * `scripts/assessment-browser-run.mjs` for the browser WebAssembly
 * artifact): the exact commit, corpus revision, host, and command that
 * produced a result, on the terms `assessment/schema.ts`'s
 * `AssessmentProvenance` documents. Neither runner embeds a corpus fixture
 * or a matched value; both read `assessment/fixtures/accuracy-corpus.json`
 * through this one path.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { release } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const ACCURACY_CORPUS_PATH = join(
  REPO_ROOT,
  "assessment",
  "fixtures",
  "accuracy-corpus.json",
);
export const WORKLOAD_PROFILES_PATH = join(
  REPO_ROOT,
  "assessment",
  "fixtures",
  "workload-profiles.json",
);

export function gitCommit() {
  return execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  }).trim();
}

export function loadAccuracyCorpus() {
  return JSON.parse(readFileSync(ACCURACY_CORPUS_PATH, "utf8"));
}

export function accuracyCorpusHash() {
  return createHash("sha256").update(readFileSync(ACCURACY_CORPUS_PATH)).digest("hex");
}

export function loadWorkloadProfiles() {
  return JSON.parse(readFileSync(WORKLOAD_PROFILES_PATH, "utf8"));
}

export function workloadProfilesHash() {
  return createHash("sha256").update(readFileSync(WORKLOAD_PROFILES_PATH)).digest("hex");
}

/** `<platform>-<release>`, e.g. `darwin-24.6`, matching the contract's example. */
export function hostOs() {
  return `${process.platform}-${release()}`;
}

export function hostCpu() {
  return process.arch;
}

export function readPackageVersion(packageJsonPath) {
  return JSON.parse(readFileSync(packageJsonPath, "utf8")).version;
}

/**
 * Maps the JavaScript package's `artifact()` ("addon" | "wasm") to the
 * assessment provenance's `resolvedArtifact` ("node-addon" | "wasm"). Throws on
 * anything else, so a node performance result never goes out unattributed.
 */
export function resolvedNodeArtifact(kind) {
  if (kind === "addon") return "node-addon";
  if (kind === "wasm") return "wasm";
  throw new Error(`artifact() returned ${JSON.stringify(kind)}; expected "addon" or "wasm"`);
}

/** The one resolved artifact every sample of a run agrees on; throws when samples differ or none exist. */
export function agreedResolvedArtifact(kinds) {
  const resolved = new Set(kinds.map(resolvedNodeArtifact));
  if (resolved.size !== 1) throw new Error(`samples resolved ${resolved.size === 0 ? "no" : [...resolved].join(" and ")} artifact(s); expected exactly one`);
  return [...resolved][0];
}
