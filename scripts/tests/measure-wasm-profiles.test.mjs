import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { DETECTOR_PROFILES } from "../build-browser-artifact.mjs";
import {
  ARTIFACTS,
  artifactBuild,
  COMMON_PROVIDER_HELPER_MODULES,
  classifyModules,
  detectorImplementations,
  detectorModules,
  guardFailures,
  loadModulePacks,
  modulePacks,
  PROFILES,
  percentChange,
  piiGuardFailures,
  piiRuntime,
} from "../measure-wasm-profiles.mjs";

const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const DETECTORS_DIR = join(REPO_ROOT, "crates", "secret-scan-core", "src", "detectors");

function packTable() {
  const source = readFileSync(join(DETECTORS_DIR, "mod.rs"), "utf8");
  const table = source.match(/BUILT_IN_PACKS: &\[\(&str, Pack\)\] = &\[([\s\S]*?)\n\];/);
  assert.ok(table, "BUILT_IN_PACKS not found");
  return [...table[1].matchAll(/\("([a-z0-9-]+)", Pack::(Common|Provider)\)/g)].map(([, id, pack]) => ({ id, pack }));
}

test("module packs follow BUILT_IN_PACKS and built_in_detectors() in the core source", () => {
  const packs = loadModulePacks();
  assert.deepEqual(packs.common, [
    "bearer_token",
    "connection_string",
    "generic_token",
    "jwt",
    "otpauth",
    "private_key",
  ]);
  const commonIds = packTable()
    .filter(({ pack }) => pack === "Common")
    .map(({ id }) => id);
  assert.equal(commonIds.length, 6);
  for (const module of ["pattern", "ruleset_adapter", "text"]) assert.ok(packs.sharedEngine.includes(module), module);
  for (const module of ["aws", "heroku", "sentry", "ai_inference"]) assert.ok(packs.provider.includes(module), module);
  for (const module of [...packs.common, ...packs.provider, ...packs.sharedEngine]) {
    assert.ok(existsSync(join(DETECTORS_DIR, `${module}.rs`)), module);
  }
  const all = [...packs.common, ...packs.provider, ...packs.sharedEngine];
  assert.equal(new Set(all).size, all.length, "a module has exactly one role");
});

const SYNTHETIC_MOD_RS = `mod acme;
mod jwt;
mod pattern;
mod private_key;
mod zeta;

use crate::types::Detector;
use private_key::PrivateKeyDetector;

#[must_use]
pub(crate) fn built_in_detectors() -> &'static [BuiltInRow] {
    #[rustfmt::skip]
    static DETECTORS: &[BuiltInRow] = &[
        row("private-key", &PrivateKeyDetector),
        row("acme-token", &acme::AcmeTokenDetector),
        row("zeta-key", &zeta::ZetaKeyDetector),
        row("acme-legacy", &acme::ACME_LEGACY),
        row("jwt", &jwt::JwtDetector),
    ];
    DETECTORS
}

pub(crate) const BUILT_IN_PACKS: &[(&str, Pack)] = &[
    ("private-key", Pack::Common),
    ("acme-token", Pack::Provider),
    ("zeta-key", Pack::Provider),
    ("acme-legacy", Pack::Provider),
    ("jwt", Pack::Common),
];
`;

test("modulePacks classifies a new provider module without a script change", () => {
  assert.deepEqual(modulePacks(SYNTHETIC_MOD_RS), {
    common: ["jwt", "private_key"],
    provider: ["acme", "zeta"],
    sharedEngine: ["pattern"],
  });
});

test("modulePacks rejects a list/table mismatch and a mixed-pack module", () => {
  assert.throws(() => modulePacks(SYNTHETIC_MOD_RS.replace('    ("jwt", Pack::Common),\n', "")), /BUILT_IN_PACKS rows/);
  assert.throws(
    () => modulePacks(SYNTHETIC_MOD_RS.replace('("acme-legacy", Pack::Provider)', '("acme-legacy", Pack::Common)')),
    /both common and provider/,
  );
});

test("CI runs the real build-and-guard in the rust-wasm job (#929)", () => {
  const ci = readFileSync(join(REPO_ROOT, ".github", "workflows", "ci.yml"), "utf8");
  const start = ci.indexOf("\n  rust-wasm:\n");
  assert.ok(start >= 0, "rust-wasm job not found");
  const next = ci.slice(start + 1).search(/\n {2}[a-z0-9-]+:\n/);
  const job = next < 0 ? ci.slice(start) : ci.slice(start, start + 1 + next);
  assert.match(job, /node scripts\/measure-wasm-profiles\.mjs --guard-only/);
});

test("both profiles have a build configuration", () => {
  assert.deepEqual(Object.keys(DETECTOR_PROFILES), PROFILES);
  assert.deepEqual(DETECTOR_PROFILES.full.cargoArgs, []);
  assert.deepEqual(DETECTOR_PROFILES.common.cargoArgs, ["--no-default-features"]);
  assert.notEqual(DETECTOR_PROFILES.full.outName, DETECTOR_PROFILES.common.outName);
});

test("each profile has a pii variant built with the pii feature under its own names (#937)", () => {
  assert.deepEqual(DETECTOR_PROFILES.full.pii.cargoArgs, ["--features", "pii"]);
  assert.deepEqual(DETECTOR_PROFILES.common.pii.cargoArgs, ["--no-default-features", "--features", "pii"]);
  assert.equal(DETECTOR_PROFILES.full.pii.outName, "redact_secret_wasm_pii");
  assert.equal(DETECTOR_PROFILES.common.pii.outName, "redact_secret_wasm_common_pii");
  const names = ARTIFACTS.map((name) => artifactBuild(name).outName);
  assert.equal(new Set(names).size, 4, "four distinct wasm-bindgen out names");
  assert.throws(() => artifactBuild("full-tiny"), /unknown artifact/);
  const manifest = JSON.parse(readFileSync(join(REPO_ROOT, "bindings", "wasm", "npm", "package.json"), "utf8"));
  for (const name of ARTIFACTS) {
    for (const file of artifactBuild(name).files) assert.ok(manifest.files.includes(file), `${file} is published`);
  }
});

test("the usage text and defaults never name the audit archive", () => {
  const source = readFileSync(join(REPO_ROOT, "scripts", "measure-wasm-profiles.mjs"), "utf8");
  assert.ok(!source.includes("docs/audits"), "no example or default may name docs/audits");
  assert.ok(!source.includes('"audits"'), "no path may be assembled from an audits segment");
  assert.ok(source.includes("redact-secret-benchmarks"));
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

test("detectorImplementations reads Detector impls only", () => {
  const section = [
    "<redact_secret[7f632526a786e8f3]::detectors::jwt::JwtDetector as redact_secret[7f632526a786e8f3]::types::Detector>::detect",
    "<redact_secret[7f632526a786e8f3]::detectors::pattern::PrefixDetector<4> as redact_secret[7f632526a786e8f3]::types::Detector>::id",
    "Iredact_secret[7f632526a786e8f3]::detectors::sentry::is_lower_hex",
  ].join(String.fromCharCode(0));
  assert.deepEqual(detectorImplementations(section), ["jwt", "pattern"]);
});

const PACKS = {
  common: ["jwt", "private_key"],
  provider: ["datadog", "github", ...COMMON_PROVIDER_HELPER_MODULES],
  sharedEngine: ["pattern", "text"],
};

test("classifyModules separates common, shared engine, provider and undeclared code", () => {
  assert.deepEqual(classifyModules(["datadog", "jwt", "mystery", "pattern", "text"], PACKS), {
    common: ["jwt"],
    sharedEngine: ["pattern", "text"],
    provider: ["datadog"],
    undeclared: ["mystery"],
  });
});

test("percentChange rounds to two places", () => {
  assert.equal(percentChange(80, 100), -20);
  assert.equal(percentChange(224_879, 281_346), -20.07);
});

const COMMON_MODULES = [...PACKS.common, "text"];

function artifact(raw, implementations, helpers = implementations, exports = ["initialize", "profile", "scan"]) {
  return {
    sizes: { wasmRawBytes: raw },
    exports,
    classification: classifyModules(helpers, PACKS),
    implementationClassification: classifyModules(implementations, PACKS),
  };
}

test("guardFailures accepts a smaller common artifact with only common detectors", () => {
  const full = artifact(280_000, [...COMMON_MODULES, "aws", "github", "pattern"]);
  const common = artifact(220_000, COMMON_MODULES);
  assert.deepEqual(guardFailures(full, common, PACKS), []);
});

test("guardFailures tolerates reviewed provider helper symbols without a provider detector", () => {
  const full = artifact(280_000, [...COMMON_MODULES, "aws", "datadog"]);
  const common = artifact(220_000, COMMON_MODULES, [...COMMON_MODULES, ...COMMON_PROVIDER_HELPER_MODULES]);
  assert.deepEqual(guardFailures(full, common, PACKS), []);
});

test("guardFailures rejects provider helper code outside the reviewed list (#1127)", () => {
  const full = artifact(280_000, [...COMMON_MODULES, "aws", "datadog"]);
  const common = artifact(220_000, COMMON_MODULES, [...COMMON_MODULES, "twilio", "datadog", "github"]);
  const failures = guardFailures(full, common, PACKS);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /outside the reviewed helper list/);
  assert.match(failures[0], /datadog, github/);
  assert.doesNotMatch(failures[0], /twilio/);
});

test("every reviewed provider helper module is a declared provider module (#1127)", () => {
  for (const module of COMMON_PROVIDER_HELPER_MODULES) {
    assert.ok(loadModulePacks().provider.includes(module), `${module} is not a provider module of the core`);
  }
  assert.deepEqual([...COMMON_PROVIDER_HELPER_MODULES].sort(), [...COMMON_PROVIDER_HELPER_MODULES]);
});

test("guardFailures rejects a common artifact that links a provider detector or is not smaller", () => {
  const full = artifact(280_000, [...COMMON_MODULES, "aws"]);
  const regressed = artifact(281_000, [...COMMON_MODULES, "aws"]);
  const failures = guardFailures(full, regressed, PACKS);
  assert.equal(failures.length, 2);
  assert.match(failures[0], /not smaller/);
  assert.match(failures[1], /provider detector implementations: aws/);
});

test("guardFailures rejects a missing common detector, an undeclared module and a different export surface", () => {
  const full = artifact(280_000, [...COMMON_MODULES, "aws"]);
  assert.match(guardFailures(full, artifact(220_000, ["jwt"]), PACKS).join(" "), /expected jwt, private_key/);
  assert.match(
    guardFailures(full, artifact(220_000, [...COMMON_MODULES, "mystery"]), PACKS).join(" "),
    /undeclared modules: mystery/,
  );
  assert.deepEqual(
    guardFailures(full, artifact(220_000, COMMON_MODULES, COMMON_MODULES, ["initialize", "scan"]), PACKS),
    ["full and common export different surfaces"],
  );
});

const NUL = String.fromCharCode(0);

test("piiRuntime reads the adapter, family implementations and unicode_normalization (#937)", () => {
  const section = [
    "<redact_secret[7f632526a786e8f3]::pii::PiiDomain as redact_secret[7f632526a786e8f3]::types::Detector>::detect",
    "<redact_secret[7f632526a786e8f3]::pii::pii_email::EmailFamily as redact_secret[7f632526a786e8f3]::pii::PiiFamily>::detect",
    "<redact_secret[7f632526a786e8f3]::pii::network_address::NetworkAddress as redact_secret[7f632526a786e8f3]::pii::PiiFamily>::id",
    "<unicode_normalization[0c9a1a7c1f3b1d2e]::recompose::Recompositions<I> as core[ed718c3d60ebd546]::iter::traits::iterator::Iterator>::next",
    "<redact_secret[7f632526a786e8f3]::pii::PiiSelection>::parse",
  ].join(NUL);
  assert.deepEqual(piiRuntime(section), ["EmailFamily", "NetworkAddress", "PiiDomain", "unicode_normalization"]);
  assert.deepEqual(
    piiRuntime(
      [
        "<redact_secret[7f632526a786e8f3]::pii::PiiSelection>::parse",
        "redact_secret[7f632526a786e8f3]::pii::valid_slug",
      ].join(NUL),
    ),
    [],
    "selector parsing is not the PII runtime",
  );
});

const PII_RUNTIME = ["EmailFamily", "PiiDomain", "unicode_normalization"];

function withPii(base, raw, parts) {
  return { ...base, sizes: { wasmRawBytes: raw }, piiRuntime: parts };
}

function fourArtifacts() {
  const full = { ...artifact(280_000, [...COMMON_MODULES, "aws"]), piiRuntime: [] };
  const common = { ...artifact(220_000, COMMON_MODULES), piiRuntime: [] };
  return {
    full,
    common,
    "full-pii": withPii(full, 400_000, PII_RUNTIME),
    "common-pii": withPii(common, 340_000, PII_RUNTIME),
  };
}

test("piiGuardFailures accepts PII-free defaults and PII-linking variants", () => {
  const artifacts = fourArtifacts();
  assert.deepEqual(piiGuardFailures(artifacts, PACKS), []);
  assert.deepEqual(guardFailures(artifacts.full, artifacts.common, PACKS), []);
});

test("piiGuardFailures rejects a default artifact that links the PII runtime", () => {
  const artifacts = fourArtifacts();
  artifacts.full = { ...artifacts.full, piiRuntime: ["PiiDomain", "unicode_normalization"] };
  artifacts.common = { ...artifacts.common, piiRuntime: ["unicode_normalization"] };
  assert.deepEqual(piiGuardFailures(artifacts, PACKS), [
    "full links the PII runtime: PiiDomain, unicode_normalization",
    "common links the PII runtime: unicode_normalization",
  ]);
});

test("piiGuardFailures rejects a pii variant without the runtime, a provider in common-pii, and a different surface", () => {
  const artifacts = fourArtifacts();
  artifacts["full-pii"] = { ...artifacts["full-pii"], piiRuntime: ["unicode_normalization"] };
  artifacts["common-pii"] = {
    ...withPii(artifact(410_000, [...COMMON_MODULES, "aws"], undefined, ["initialize"]), 410_000, PII_RUNTIME),
  };
  const failures = piiGuardFailures(artifacts, PACKS).join("\n");
  assert.match(failures, /full-pii does not link the PII runtime/);
  assert.match(failures, /common-pii \.wasm \(410000 B\) is not smaller than full-pii/);
  assert.match(failures, /common-pii links provider detector implementations: aws/);
  assert.match(failures, /full-pii and common-pii export different surfaces/);
  assert.match(failures, /common-pii exports a different surface than full/);
});

test("piiGuardFailures rejects a default build that is not smaller than its pii variant", () => {
  const artifacts = fourArtifacts();
  artifacts["common-pii"] = withPii(artifacts.common, 220_000, PII_RUNTIME);
  assert.deepEqual(piiGuardFailures(artifacts, PACKS), [
    "common .wasm (220000 B) is not smaller than common-pii (220000 B)",
  ]);
});
