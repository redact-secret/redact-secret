/**
 * Qualifies static custom WebAssembly artifacts against the `full` artifact
 * (issue #1253, the per-exact-artifact qualification of
 * `decision-define-the-configuration-capability-ceiling-runtime-ownership-and-surface-support`).
 *
 * It builds two different compositions with `scripts/build-custom-artifact.mjs`
 * and the `full` baseline with `scripts/build-browser-artifact.mjs`, imports each
 * emitted wrapper the way a consumer does, and checks:
 *
 * - the oracle: findings equal the `full` runtime artifact initialized with the
 *   same `include`, over the canonical synchronous corpus; equal per-detector
 *   candidates through the synthetic positive cases; partition-equivalent
 *   incremental output equal to the oracle's;
 * - the manifest, the registry and the self-report describe the same detectors,
 *   and the packaged manifest is the artifact's own;
 * - reachability: probe literals of excluded detectors are in `full` and not in
 *   the custom binary, probe literals of selected detectors are in both, and the
 *   raw export surface is the standard glue's plus the module start hook, and
 *   the wrapper has exactly the names of `@redact-secret/core/common`;
 * - an unsupported id, combination or target fails before anything is emitted;
 * - a runtime action policy changes actions without a rebuild, and a capability
 *   the artifact lacks cannot be silently restored;
 * - the measured sizes against the standard artifacts.
 *
 * It prints one JSON report on stdout and exits non-zero on the first failed
 * check. The report is evidence for a reviewer, not a published claim: the
 * numbers describe this revision and toolchain, and no size or speed guarantee
 * follows from them.
 *
 *     node scripts/qualify-custom-artifact.mjs [--out-dir <dir>] [--reuse]
 */

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  BuildError,
  buildCustomArtifact,
  CompositionError,
  OUT_NAME as CUSTOM_OUT_NAME,
} from "./build-custom-artifact.mjs";
import { containsLiteral, measureElimination, sizes, wasmExports } from "./lib/wasm-inspect.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DIST = join(REPO_ROOT, "packages", "javascript", "dist");

/** Two compositions that differ in detectors, so one cannot pass for the other. */
export const COMPOSITIONS = Object.freeze([
  {
    schema: "composition/v1",
    name: "edge-checks",
    include: ["github-token", "jwt", "generic-token"],
    pii: "none",
  },
  {
    schema: "composition/v1",
    name: "payments-chat",
    include: ["stripe-token", "slack-token", "bearer-token", "connection-string", "generic-token"],
    pii: "none",
  },
]);

/**
 * Literals that only one detector's grammar carries. Each is checked against the
 * `full` binary first, so a probe that is not a real detector literal fails the
 * qualification instead of passing it.
 */
export const PROBES = Object.freeze({
  "github-token": ["ghp_"],
  "stripe-token": ["sk_live_"],
  "slack-token": ["xoxb-"],
  "gitlab-token": ["glpat-"],
  "sendgrid-token": ["SG."],
  "google-api-key": ["AIza"],
  "digitalocean-token": ["dop_v1_"],
});

const LIMITS = {
  maxInputCodeUnits: 65_536,
  maxBufferedCodeUnits: 16_512,
  maxTokenCodeUnits: 8_192,
  maxMultilineCodeUnits: 16_384,
};

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    cwd: REPO_ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
    ...options,
  });
}

function shape(findings) {
  return findings.map((finding) => [finding.detector, finding.type, finding.start, finding.end, finding.action]);
}

function loadCorpus() {
  const corpus = JSON.parse(
    readFileSync(join(REPO_ROOT, "conformance", "fixtures", "synchronous-corpus.json"), "utf8"),
  );
  return corpus.fixtures.filter((fixture) => fixture.support !== "not-yet-evaluated");
}

/** A copy of an emitted artifact in its own directory: a fresh module instance. */
function fresh(dir, tag) {
  const copy = mkdtempSync(join(tmpdir(), `custom-${tag}-`));
  cpSync(dir, copy, { recursive: true });
  return copy;
}

async function importWrapper(dir, tag) {
  const copy = fresh(dir, tag);
  const wrapper = await import(pathToFileURL(join(copy, "index.js")).href);
  return { wrapper, copy };
}

/** A runtime over the `full` standard glue, one module instance per call. */
async function fullRuntime(fullDir, tag) {
  const { createRedactSecretRuntime } = await import(pathToFileURL(join(DIST, "runtime.js")).href);
  const { assertWasmModuleShape, createBindingFromWasmModule } = await import(
    pathToFileURL(join(DIST, "runtime", "wasm-binding.js")).href
  );
  const copy = fresh(fullDir, `full-${tag}`);
  const glue = pathToFileURL(join(copy, "redact_secret_wasm.js")).href;
  const bytes = readFileSync(join(copy, "redact_secret_wasm_bg.wasm"));
  return createRedactSecretRuntime(async () => {
    const module = await import(glue);
    assertWasmModuleShape(module);
    await module.default({ module_or_path: bytes });
    return createBindingFromWasmModule(module);
  }, "full");
}

function incrementalText(runtime, input, chunk) {
  const session = runtime.createIncrementalSanitizer({ limits: LIMITS });
  let out = "";
  for (let at = 0; at < input.length; ) {
    let end = Math.min(input.length, at + chunk);
    // Never split a surrogate pair: a lone surrogate is not valid input.
    if (end < input.length && input.charCodeAt(end - 1) >= 0xd800 && input.charCodeAt(end - 1) <= 0xdbff) end += 1;
    out += session.append(input.slice(at, end)).text;
    at = end;
  }
  return out + session.finalize().text;
}

async function expectRejection(promise, code) {
  let thrown;
  try {
    await promise;
  } catch (error) {
    thrown = error;
  }
  assert.ok(thrown !== undefined, `expected ${code}`);
  assert.equal(thrown.code, code);
}

async function qualifyComposition({ composition, outDir, fullDir, corpus, report }) {
  const built = await buildCustomArtifact({
    composition,
    outDir,
    baseline: join(fullDir, "redact_secret_wasm_bg.wasm"),
    log: (message) => console.error(`[${composition.name}] ${message}`),
  });
  const ids = built.resolved.ids;
  const entry = { name: composition.name, id: built.composition.id, detectors: ids.length, checks: {} };
  report.compositions.push(entry);

  // The manifest, the registry and the self-report agree (the build already
  // compared them natively; this reads the shipped files).
  const manifestText = readFileSync(join(outDir, "artifact-manifest.custom.json"), "utf8");
  const manifest = JSON.parse(manifestText);
  assert.deepEqual(
    manifest.detectors.map((detector) => detector.id),
    ids,
  );
  assert.equal(manifest.composition.id, built.composition.id);
  assert.equal(manifest.artifact.variant, "custom");

  // Executable consumer import.
  const { wrapper } = await importWrapper(outDir, `${composition.name}-run`);
  assert.equal(wrapper.PROFILE, "custom");
  await wrapper.initialize();
  assert.equal(wrapper.status().profile, "custom");
  assert.equal(wrapper.artifactManifest().composition.id, built.composition.id);
  assert.equal(JSON.stringify(wrapper.artifactManifest()), JSON.stringify(manifest));
  assert.deepEqual(wrapper.describeConfig().detection.enabled, ids);
  entry.checks.consumerImport = "ok";

  // The oracle: `full` initialized with the same include.
  const oracle = await fullRuntime(fullDir, `${composition.name}-oracle`);
  await oracle.initialize({ detection: { include: ids } });
  assert.deepEqual(oracle.describeConfig().detection.enabled, ids);

  const inputs = corpus.filter((fixture) => fixture.input.length <= 4_096).map((fixture) => fixture.input);
  let compared = 0;
  for (const input of inputs) {
    const got = shape(wrapper.scan(input));
    const expected = shape(oracle.scan(input));
    assert.deepEqual(got, expected, `${composition.name}: findings differ from the full oracle`);
    compared += 1;
  }
  entry.checks.oracleCorpusInputs = compared;

  // Synthetic selected, excluded and overlap cases.
  const positive = (id) =>
    corpus.find((fixture) => fixture.detector === id && fixture.kind === "positive" && fixture.support === "supported");
  let selectedCases = 0;
  for (const id of ids) {
    const fixture = positive(id);
    if (fixture === undefined) continue;
    const found = shape(wrapper.scan(fixture.input));
    assert.deepEqual(found, shape(oracle.scan(fixture.input)));
    selectedCases += 1;
  }
  let excludedCases = 0;
  for (const id of ["github-token", "stripe-token", "slack-token", "gitlab-token", "aws-access-key"]) {
    if (ids.includes(id)) continue;
    const fixture = positive(id);
    if (fixture === undefined) continue;
    const findings = wrapper.scan(fixture.input);
    assert.ok(
      findings.every((finding) => finding.detector !== id),
      `${id} is excluded and never reports`,
    );
    assert.deepEqual(shape(findings), shape(oracle.scan(fixture.input)));
    excludedCases += 1;
  }
  entry.checks.syntheticSelected = selectedCases;
  entry.checks.syntheticExcluded = excludedCases;
  assert.ok(
    selectedCases > 0 && excludedCases > 0,
    "the synthetic cases exercise both selected and excluded detectors",
  );

  // Incremental retention and partition equivalence, against the oracle.
  const oracleSession = await fullRuntime(fullDir, `${composition.name}-incremental`);
  await oracleSession.initialize({ detection: { include: ids } });
  let sessions = 0;
  for (const input of inputs.filter((value) => value.length <= 1_500).filter((_, index) => index % 7 === 0)) {
    const whole = wrapper.scanAndRedact(input).text;
    assert.equal(whole, oracleSession.scanAndRedact(input).text);
    for (const chunk of [1, 13, 200]) {
      const custom = incrementalText(wrapper, input, chunk);
      assert.equal(custom, whole, `${composition.name}: chunk ${chunk} differs from whole-input output`);
      assert.equal(custom, incrementalText(oracleSession, input, chunk));
    }
    sessions += 1;
  }
  entry.checks.incrementalInputs = sessions;

  // Runtime override of a supported action policy, no rebuild: the same
  // findings, one detector's action replaced.
  const sample = positive(ids.find((id) => positive(id) !== undefined)).input;
  const before = wrapper.scan(sample);
  assert.ok(before.length > 0);
  const chosen = before[0];
  const policy = {
    actionPolicyRevision: 1,
    base: "default",
    rules: [{ id: "override-one-detector", match: { detector: [chosen.detector] }, action: "warn" }],
  };
  const after = wrapper.scan(sample, { actionPolicy: policy });
  const positions = (list) => list.map(({ detector, type, start, end }) => [detector, type, start, end]);
  assert.deepEqual(positions(after), positions(before), "an action policy never adds or removes a finding");
  for (const [index, finding] of after.entries()) {
    assert.equal(finding.action, finding.detector === chosen.detector ? "warn" : before[index].action);
  }
  assert.notEqual(before[0].action, "warn", "the override changes an action the default would not choose");
  entry.checks.actionPolicyOverride = "ok";

  // A capability the artifact lacks cannot be silently restored.
  const excluded = built.resolved.notIncluded[0];
  const absent = await importWrapper(outDir, `${composition.name}-absent`);
  await expectRejection(absent.wrapper.initialize({ detection: { include: [excluded] } }), "INVALID_DETECTION_CONFIG");
  const resolution = wrapper.resolveConfig({ detection: { include: [excluded] } });
  assert.equal(resolution.ok, false);
  assert.ok(resolution.diagnostics.items.some((item) => item.code === "DETECTOR_NOT_INCLUDED"));
  const noPii = await importWrapper(outDir, `${composition.name}-pii`);
  await expectRejection(noPii.wrapper.initialize({ pii: ["pii:global"] }), "PII_SELECTOR_UNAVAILABLE");
  const narrowed = await importWrapper(outDir, `${composition.name}-narrow`);
  await narrowed.wrapper.initialize({ detection: { include: [ids[0]] } });
  assert.deepEqual(narrowed.wrapper.describeConfig().detection.enabled, [ids[0]]);
  await expectRejection(narrowed.wrapper.initialize({ detection: { include: ids } }), "DETECTION_CONFIG_CONFLICT");
  entry.checks.ceiling = "ok";

  // Reachability against the binaries.
  const customBytes = readFileSync(join(outDir, `${CUSTOM_OUT_NAME}_bg.wasm`));
  const fullBytes = readFileSync(join(fullDir, "redact_secret_wasm_bg.wasm"));
  const probes = Object.entries(PROBES).map(([id, literals]) => ({ id, literals, selected: ids.includes(id) }));
  const elimination = measureElimination(customBytes, fullBytes, { probes });
  for (const probe of elimination.probes) {
    assert.ok(probe.inFull, `probe ${probe.id} is not in the full binary: not a detector literal`);
    assert.equal(
      probe.inCustom,
      probe.selected,
      `probe ${probe.id}: selected=${probe.selected} but inCustom=${probe.inCustom}`,
    );
  }
  assert.ok(elimination.probes.some((probe) => !probe.selected) && elimination.probes.some((probe) => probe.selected));
  const standardGlue = join(fullDir, "redact_secret_wasm_bg.wasm");
  // The raw glue adds exactly the module start hook; the wrapper a consumer
  // imports has exactly the names of `@redact-secret/core/common`.
  const rawExports = wasmExports(customBytes);
  const standardExports = wasmExports(readFileSync(standardGlue));
  assert.deepEqual(
    rawExports.filter((name) => !standardExports.includes(name)),
    ["start"],
  );
  assert.deepEqual(
    standardExports.filter((name) => !rawExports.includes(name)),
    [],
  );
  const commonKeys = Object.keys(await import(pathToFileURL(join(DIST, "common.js")).href)).sort();
  assert.deepEqual(Object.keys(wrapper).sort(), commonKeys, "the wrapper has the function set of ./common");
  assert.ok(customBytes.length < fullBytes.length, "smaller than full");
  entry.checks.reachability = elimination;
  entry.packagedManifestDigest = manifest.digest;
  return built;
}

async function qualifyRefusals({ corpusCatalogWork }) {
  const refused = {};
  const attempt = async (label, options, code) => {
    const outDir = join(corpusCatalogWork, `refused-${label}`);
    rmSync(outDir, { recursive: true, force: true });
    let error;
    try {
      await buildCustomArtifact({ outDir, ...options });
    } catch (thrown) {
      error = thrown;
    }
    assert.ok(error instanceof CompositionError || error instanceof BuildError, `${label}: expected a build refusal`);
    assert.equal(error.code, code, `${label}: ${error.message}`);
    assert.equal(existsSync(outDir), false, `${label}: nothing was emitted`);
    assert.equal(existsSync(`${outDir}.work`), false, `${label}: no workspace was created`);
    refused[label] = error.code;
  };
  const base = { schema: "composition/v1", name: "refused", include: ["jwt"], pii: "none" };
  await attempt(
    "unknown-id",
    { composition: { ...base, include: ["jwt", "no-such-detector"] } },
    "UNKNOWN_DETECTOR_ID",
  );
  await attempt("duplicate-id", { composition: { ...base, include: ["jwt", "jwt"] } }, "DUPLICATE_DETECTOR_ID");
  await attempt("empty", { composition: { ...base, include: [] } }, "EMPTY_COMPOSITION");
  await attempt("pii-value", { composition: { ...base, pii: "email" } }, "UNSUPPORTED_PII");
  await attempt("unknown-field", { composition: { ...base, ruleset: "x" } }, "UNKNOWN_FIELD");
  await attempt("node-addon", { composition: base, target: "node-addon" }, "UNSUPPORTED_TARGET");
  await attempt("python-wheel", { composition: base, target: "python-wheel" }, "UNSUPPORTED_TARGET");
  return refused;
}

async function main() {
  const args = process.argv.slice(2);
  const outIndex = args.indexOf("--out-dir");
  const evidence = resolve(REPO_ROOT, outIndex >= 0 ? args[outIndex + 1] : join("target", "custom-qualification"));
  const reuse = args.includes("--reuse");
  if (!reuse) rmSync(evidence, { recursive: true, force: true });
  mkdirSync(evidence, { recursive: true });

  const fullDir = join(evidence, "standard-full");
  const commonDir = join(evidence, "standard-common");
  if (!(reuse && existsSync(join(fullDir, "redact_secret_wasm_bg.wasm")))) {
    run("node", ["scripts/build-browser-artifact.mjs", "--out-dir", fullDir], { stdio: "inherit" });
    run("node", ["scripts/build-browser-artifact.mjs", "--detector-profile", "common", "--out-dir", commonDir], {
      stdio: "inherit",
    });
  }

  const corpus = loadCorpus();
  const report = {
    schema: "custom-artifact-qualification/v1",
    compositions: [],
    refusals: {},
    standardSizes: {
      full: sizes(readFileSync(join(fullDir, "redact_secret_wasm_bg.wasm"))),
      common: sizes(readFileSync(join(commonDir, "redact_secret_wasm_common_bg.wasm"))),
    },
  };
  const builds = [];
  for (const composition of COMPOSITIONS) {
    builds.push(
      await qualifyComposition({ composition, outDir: join(evidence, composition.name), fullDir, corpus, report }),
    );
  }
  // Two different requested compositions produce different identities, registries and manifests.
  assert.notEqual(builds[0].composition.id, builds[1].composition.id);
  assert.notDeepEqual(builds[0].resolved.ids, builds[1].resolved.ids);
  assert.notEqual(builds[0].manifest.digest, builds[1].manifest.digest);

  report.refusals = await qualifyRefusals({ corpusCatalogWork: evidence });
  report.sizes = report.compositions.map((entry) => ({
    name: entry.name,
    detectors: entry.detectors,
    ...entry.checks.reachability.custom,
    ratioVsFullRaw: entry.checks.reachability.ratio.raw,
    ratioVsFullBrotli: entry.checks.reachability.ratio.brotli,
  }));
  writeFileSync(join(evidence, "qualification-report.json"), `${JSON.stringify(report, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

// Probe literals stay checkable by the unit tests without building anything.
export function probeLiteralsPresent(bytes, literals) {
  return literals.every((literal) => containsLiteral(bytes, literal));
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  await main();
}
