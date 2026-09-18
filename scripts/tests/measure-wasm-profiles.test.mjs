import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { DETECTOR_PROFILES } from "../build-browser-artifact.mjs";
import {
  classifyModules,
  COMMON_PACK_MODULES,
  detectorModules,
  guardFailures,
  percentChange,
  PROFILES,
  SHARED_ENGINE_MODULES,
} from "../measure-wasm-profiles.mjs";

const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const DETECTORS_DIR = join(REPO_ROOT, "crates", "secret-scan-core", "src", "detectors");

function packTable() {
  const source = readFileSync(join(DETECTORS_DIR, "mod.rs"), "utf8");
  const table = source.match(/BUILT_IN_PACKS: &\[\(&str, Pack\)\] = &\[([\s\S]*?)\n\];/);
  assert.ok(table, "BUILT_IN_PACKS not found");
  return [...table[1].matchAll(/\("([a-z0-9-]+)", Pack::(Common|Provider)\)/g)].map(
    ([, id, pack]) => ({ id, pack }),
  );
}

test("COMMON_PACK_MODULES covers exactly the Pack::Common ids, in canonical order", () => {
  const commonIds = packTable()
    .filter(({ pack }) => pack === "Common")
    .map(({ id }) => id);
  assert.deepEqual(Object.keys(COMMON_PACK_MODULES), commonIds);
});

test("every common pack and shared engine module is a real detector source file", () => {
  for (const module of [...Object.values(COMMON_PACK_MODULES), ...SHARED_ENGINE_MODULES]) {
    assert.ok(existsSync(join(DETECTORS_DIR, `${module}.rs`)), module);
  }
});

test("both profiles have a build configuration", () => {
  assert.deepEqual(Object.keys(DETECTOR_PROFILES), PROFILES);
  assert.deepEqual(DETECTOR_PROFILES.full.cargoArgs, []);
  assert.deepEqual(DETECTOR_PROFILES.common.cargoArgs, ["--no-default-features"]);
  assert.notEqual(DETECTOR_PROFILES.full.outName, DETECTOR_PROFILES.common.outName);
});

test("detectorModules reads module names from mangled name-section symbols", () => {
  const section = [
    "<redact_secret[7f632526a786e8f3]::detectors::jwt::JwtDetector as redact_secret[7f632526a786e8f3]::types::Detector>::detect",
    "Vredact_secret[7f632526a786e8f3]::detectors::text::matches_placeholder_vocabulary",
    "Iredact_secret[7f632526a786e8f3]::detectors::datadog::detect_context_gated",
    "redact_secret[7f632526a786e8f3]::pipeline::run_detector_pipeline",
    "Iredact_secret[7f632526a786e8f3]::detectors::jwt::parse",
  ].join(String.fromCharCode(0));
  assert.deepEqual(detectorModules(section), ["datadog", "jwt", "text"]);
});

test("classifyModules separates common, shared engine, and provider code", () => {
  assert.deepEqual(classifyModules(["datadog", "jwt", "pattern", "text"]), {
    common: ["jwt"],
    sharedEngine: ["text"],
    provider: ["datadog", "pattern"],
  });
});

test("percentChange rounds to two places", () => {
  assert.equal(percentChange(80, 100), -20);
  assert.equal(percentChange(224_879, 281_346), -20.07);
});

const COMMON_MODULES = [...Object.values(COMMON_PACK_MODULES), "text"];

function artifact(raw, modules, exports = ["initialize", "profile", "scan"]) {
  return { sizes: { wasmRawBytes: raw }, exports, classification: classifyModules(modules) };
}

test("guardFailures accepts a smaller common artifact with only common modules", () => {
  const full = artifact(280_000, [...COMMON_MODULES, "aws", "github", "pattern"]);
  const common = artifact(220_000, COMMON_MODULES);
  assert.deepEqual(guardFailures(full, common), []);
});

test("guardFailures rejects a common artifact that links provider code or is not smaller", () => {
  const full = artifact(280_000, [...COMMON_MODULES, "aws"]);
  const regressed = artifact(281_000, [...COMMON_MODULES, "aws"]);
  const failures = guardFailures(full, regressed);
  assert.equal(failures.length, 2);
  assert.match(failures[0], /not smaller/);
  assert.match(failures[1], /aws/);
});

test("guardFailures rejects a different export surface", () => {
  const full = artifact(280_000, [...COMMON_MODULES, "aws"]);
  const common = artifact(220_000, COMMON_MODULES, ["initialize", "scan"]);
  assert.deepEqual(guardFailures(full, common), ["full and common export different surfaces"]);
});
