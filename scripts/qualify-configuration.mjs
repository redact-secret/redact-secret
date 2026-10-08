#!/usr/bin/env node
/**
 * Issue #1255 (child of epic #1246): qualifies the configuration journeys of the
 * artifacts a consumer installs, against the exact bytes, and records what is
 * unsupported as an assertion instead of a silent gap.
 *
 * What it qualifies is the artifacts the candidate directory holds -- the npm
 * tarballs `scripts/pack-npm-candidate.mjs` packed from the addon and WebAssembly
 * builds one `artifact-qualification.yml` run qualified -- installed into an empty
 * project outside the checkout from a local registry that serves only them, plus
 * a generated custom artifact (`--custom-dir`, or built here with `--build-custom`
 * from `scripts/build-custom-artifact.mjs`). Nothing is rebuilt from source for the
 * installed rows. Each row's own manifest is read from the loaded artifact,
 * its digest is recomputed outside the artifact, and the digest of the binary file
 * that was loaded is recorded beside it; for the custom row the packaged manifest
 * file, the build report's file digests and the artifact's self-report are compared
 * as well.
 *
 * Rows (a row exists only where the contract and the implementation do):
 *
 *   node-addon/full, node-addon/common   the installed `@redact-secret/core` addon
 *   wasm/full, wasm/common               the installed `@redact-secret/wasm` builds, through
 *                                        the package's own loader (the `pii` builds included)
 *   wasm/custom                          the generated custom composition
 *
 * and the unsupported rows, asserted rather than skipped: a custom Node addon and a
 * custom Python wheel (refused by the build tooling before anything is emitted), the
 * Python wheel (`--python`) and the CLI (`--cli-binary`), which report
 * `detectorSelection: false` and offer no configuration surface.
 *
 * Each journey of `scripts/lib/configuration-journeys.mjs` runs in its own worker
 * thread (a fresh initialization owner) and its result must carry no secret input
 * byte or hash. This driver compares what the journeys returned: build defaults
 * against runtime overrides, the allow-versus-disable controls, the sessions, and
 * so on. It also bundles the installed standard package and the custom artifact
 * with esbuild, runs both, and runs the documented quickstart
 * (`examples/configuration-quickstart/quickstart.mjs`) against the installed
 * package.
 *
 * Usage:
 *
 *     node scripts/qualify-configuration.mjs --candidate-dir <dir>
 *       (--custom-dir <dir> | --build-custom) [--cli-binary <path>] [--python <path>]
 *       [--require-unsupported] [--report <path>]
 *
 * It prints one summary line and writes the JSON report. The report is evidence for a
 * reviewer, not a published claim: no size or speed follows from it.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Worker } from "node:worker_threads";

import { build as esbuild } from "esbuild";

import { buildCustomArtifact, CompositionError } from "./build-custom-artifact.mjs";
import {
  cleanEnvironment,
  freshWorkspace,
  loadNpmCandidate,
  makeAssert,
  REPO_ROOT,
  runShell,
  sourceCommit,
  startCandidateRegistry,
  verifyNpmInstall,
} from "./lib/candidate-install.mjs";
import { canonicalDigest, EMAIL_INPUT, PII_ALL, PROBES, SYNTHETIC } from "./lib/configuration-journeys.mjs";
import { copyRedactWasm } from "./lib/esbuild-redact-wasm.mjs";

const LABEL = "configuration";
const fail = makeAssert(LABEL);
export const WORKER = fileURLToPath(new URL("./lib/configuration-worker.mjs", import.meta.url));
export const QUICKSTART = "examples/configuration-quickstart/quickstart.mjs";

/** The composition built when `--build-custom` is given: a provider, a structural and a contextual detector. */
export const CUSTOM_COMPOSITION = Object.freeze({
  schema: "composition/v1",
  name: "config-journeys",
  include: ["github-token", "jwt", "generic-token"],
  pii: "none",
});

function parseArgs(argv) {
  const options = { requireUnsupported: false, buildCustom: false };
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (key === "--require-unsupported") options.requireUnsupported = true;
    else if (key === "--build-custom") options.buildCustom = true;
    else if (["--candidate-dir", "--custom-dir", "--cli-binary", "--python", "--report"].includes(key)) {
      const value = argv[index + 1];
      if (value === undefined) throw new Error(`missing value for ${key}`);
      options[key.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = resolve(value);
      index += 1;
    } else throw new Error(`unknown argument ${key}`);
  }
  if (options.candidateDir === undefined || (options.customDir === undefined) === !options.buildCustom) {
    throw new Error(
      "usage: qualify-configuration.mjs --candidate-dir <dir> (--custom-dir <dir> | --build-custom) " +
        "[--cli-binary <path>] [--python <path>] [--require-unsupported] [--report <path>]",
    );
  }
  return options;
}

const sha256Hex = (bytes) => createHash("sha256").update(bytes).digest("hex");
const fileUrl = (path) => pathToFileURL(path).href;

// ---------------------------------------------------------------------------
// Running a journey.
// ---------------------------------------------------------------------------

function runJourney(row, journey, init) {
  return new Promise((resolveRun, reject) => {
    const worker = new Worker(WORKER, {
      workerData: { load: row.load, journey, row: publicRow(row), known: row.known ?? null, init },
    });
    worker.once("message", (message) => {
      void worker.terminate();
      if (message.ok) resolveRun(message.result);
      else reject(new Error(`${row.id}/${journey}: ${message.error}${message.code ? ` (${message.code})` : ""}`));
    });
    worker.once("error", reject);
  });
}

// Fresh workers prove the installed public factories share the initialized owner.
// WASM rows use the existing forced-WASM loader and report direct sessions only.
export async function installedIncrementalBoundary({ load, profile, probe }) {
  const { strict: assert } = await import("node:assert");
  const { pathToFileURL } = await import("node:url");
  const { join } = await import("node:path");
  let api;
  const factories = [];
  if (load.type === "package") {
    const suffix = profile === "common" ? "/common" : "";
    api = await import(`@redact-secret/core${suffix}`);
    const node = await import(`@redact-secret/core${suffix}/node-stream`);
    const web = await import(`@redact-secret/core${suffix}/web-stream`);
    factories.push(["node", node.createNodeStreamSanitizer], ["web", web.createWebStreamSanitizer]);
  } else {
    const { createRedactSecretRuntime } = await import(pathToFileURL(join(load.coreDist, "runtime.js")).href);
    const { loadWasmFallback } = await import(pathToFileURL(join(load.coreDist, "runtime", "node.js")).href);
    api = createRedactSecretRuntime(({ pii }) => loadWasmFallback(profile, Boolean(pii)), profile);
  }
  const limits = {
    maxInputCodeUnits: 65536,
    maxBufferedCodeUnits: 16512,
    maxTokenCodeUnits: 8192,
    maxMultilineCodeUnits: 16384,
  };
  let getterReads = 0,
    policyCalls = 0,
    formatterCalls = 0;
  const policy = {
    evaluate() {
      policyCalls += 1;
      return "redact";
    },
  };
  const formatter = () => {
    formatterCalls += 1;
    return "<SECRET_1>";
  };
  const inheritedGetter = Object.defineProperty({}, "ruleset", {
    get() {
      getterReads += 1;
      throw new Error("getter must not run");
    },
  });
  const options = [
    { limits, ruleset: "SYNTHETIC_REVOKED_RULESET" },
    { limits, ruleset: undefined },
    Object.assign(Object.create({ ruleset: "SYNTHETIC_REVOKED_RULESET" }), { limits }),
    Object.assign(Object.create({ ruleset: undefined }), { limits }),
    Object.assign(Object.create(inheritedGetter), { limits }),
  ].map((value) => Object.assign(value, { policy, placeholderFormatter: formatter }));
  const opens = [["session", (options) => api.createIncrementalSanitizer(options)], ...factories];
  const rejects = (open, option, code) => {
    let error;
    try {
      open(option);
    } catch (caught) {
      error = caught;
    }
    assert.equal(error?.name, "SecretScanError", "installed boundary must throw synchronously");
    assert.equal(error?.code, code, "installed boundary returned another code");
    assert.ok(!error.message.includes("SYNTHETIC_REVOKED"), "installed diagnostic contains input");
  };
  for (const [, open] of opens) for (const option of options) rejects(open, option, "NOT_INITIALIZED");
  await api.initialize();
  for (const [, open] of opens) for (const option of options) rejects(open, option, "INVALID_OPTIONS");
  assert.equal(getterReads, 0, "installed rejection read a getter");
  assert.equal(policyCalls, 0, "installed rejection called policy");
  assert.equal(formatterCalls, 0, "installed rejection called formatter");
  // Custom detection migrates to bounded whole-input processing, never per-chunk fallback.
  const migrationInput = `TOKEN=ACME_${"SYNTHETICREVOKED".repeat(2)}`;
  assert.ok(new TextEncoder().encode(migrationInput).byteLength <= 32768, "migration input exceeds bound");
  const ruleset =
    'ruleset-revision: 1\n\ndetector: acme-internal-token\nspecificity: contextual\nprefix: "ACME_"\nalphabet: alnum-dash\nrun: at-least 20\nvalidator: none\n';
  const migration = api.scanAndRedact(migrationInput, {
    ruleset,
    actionPolicy: JSON.stringify({
      actionPolicyRevision: 1,
      base: "default",
      rules: [{ id: "redact-acme", match: { type: ["acme-internal-token"] }, action: "redact" }],
    }),
  });
  assert.notEqual(migration.text, migrationInput, "whole-input migration did not redact");
  assert.ok(
    migration.findings.some((finding) => finding.detector === "acme-internal-token" && finding.action === "redact"),
    "whole-input migration lost custom detection",
  );
  const expected = api.scanAndRedact(probe).text;
  assert.notEqual(expected, probe, "installed absent-key control did not redact");
  const session = api.createIncrementalSanitizer({ limits });
  assert.equal(session.append(probe).text + session.finalize().text, expected, "installed direct session differs");
  const result = {
    host: "node",
    artifact: api.artifact(),
    profile,
    directSession: { rejectedKeys: options.length, validControl: true },
    boundedWholeInputMigration: "custom ruleset with explicit redaction",
    factories: {},
  };
  for (const [kind, open] of factories) {
    const sanitizer = open({ limits });
    const output = [];
    if (kind === "node") {
      const { Readable, Writable } = await import("node:stream");
      const { pipeline } = await import("node:stream/promises");
      await pipeline(
        Readable.from([Buffer.from(probe)]),
        sanitizer,
        new Writable({
          write(chunk, _encoding, done) {
            output.push(chunk.toString());
            done();
          },
        }),
      );
      const failure = new Error("synthetic source failure");
      const failed = open({ limits });
      await assert.rejects(
        pipeline(
          Readable.from(
            (async function* () {
              yield Buffer.from("synthetic pending input");
              throw failure;
            })(),
          ),
          failed,
          new Writable({
            write(_chunk, _encoding, done) {
              done();
            },
          }),
        ),
        (error) => error === failure,
      );
      assert.deepEqual(failed.findings, [], "failed stream retained findings");
    } else {
      await new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(probe));
          controller.close();
        },
      })
        .pipeThrough(sanitizer)
        .pipeTo(
          new WritableStream({
            write(chunk) {
              output.push(chunk);
            },
          }),
        );
      const failure = new Error("synthetic source failure");
      const failed = open({ limits });
      await assert.rejects(
        new ReadableStream({
          pull(controller) {
            controller.error(failure);
          },
        })
          .pipeThrough(failed)
          .pipeTo(new WritableStream()),
        (error) => error === failure,
      );
      assert.deepEqual(failed.findings, [], "failed stream retained findings");
    }
    assert.equal(output.join(""), expected, "installed public factory differs from whole input");
    result.factories[kind] = {
      rejectedKeys: options.length,
      validControl: true,
      sourceFailurePropagated: true,
      host: kind === "web" ? "node-web-streams" : "node-streams",
    };
  }
  return result;
}

export function runInstalledIncrementalBoundary(row) {
  return new Promise((resolveRun, reject) => {
    const source = `import {parentPort,workerData} from "node:worker_threads";\n(${installedIncrementalBoundary.toString()})(workerData).then(result=>parentPort.postMessage({ok:true,result})).catch(error=>parentPort.postMessage({ok:false,code:error?.code??null}));`;
    const coreDist = row.load.coreDist ?? fileURLToPath(new URL(".", row.load.url));
    const project = resolve(coreDist, "../../../..");
    const workerFile = join(project, `.incremental-boundary-${row.id.replaceAll("/", "-")}.mjs`);
    writeFileSync(workerFile, source);
    const worker = new Worker(workerFile, {
      workerData: { load: row.load, profile: row.profile, probe: PROBES.structural },
    });
    let received = false;
    worker.once("message", (message) => {
      received = true;
      void worker.terminate();
      if (message.ok) resolveRun(message.result);
      else reject(new Error(`${row.id}: installed incremental key boundary failed (${message.code ?? "assertion"})`));
    });
    worker.once("error", () => reject(new Error(`${row.id}: installed incremental boundary worker failed`)));
    worker.once("exit", () => {
      if (!received) reject(new Error(`${row.id}: installed incremental boundary worker exited without a result`));
    });
  });
}

const publicRow = ({ id, profile, manifestKind, piiAvailable, piiInProcess }) => ({
  id,
  profile,
  manifestKind,
  piiAvailable,
  piiInProcess,
});

// ---------------------------------------------------------------------------
// Checks over what journeys returned. Each throws on the first disagreement.
// ---------------------------------------------------------------------------

const equal = assert.deepStrictEqual;

export function checkEffectiveEquivalence(row, runs) {
  const [defaults, ...overrides] = runs;
  assert.equal(defaults.origin, "artifact-default", `${row.id}: defaults are not build defaults`);
  assert.equal(defaults.disabled.length, 0);
  assert.equal(defaults.unavailableCount, row.known.notIncluded.length);
  for (const [name, override] of overrides) {
    equal(override.enabled, defaults.enabled, `${row.id}: ${name} enables a different set`);
    equal(override.detectionDigest, defaults.detectionDigest, `${row.id}: ${name} has another detection identity`);
    equal(override.scans, defaults.scans, `${row.id}: ${name} scans differently from the build defaults`);
    assert.notEqual(override.origin, "artifact-default", `${row.id}: ${name} does not report a runtime origin`);
  }
}

export function checkSelectionBeforeOverlap(row, overlap, defaultScans) {
  assert.ok(overlap.disabled.includes(overlap.id), `${row.id}: ${overlap.id} is not disabled`);
  assert.ok(!overlap.detectorsReported.includes(overlap.id), `${row.id}: a disabled detector reported`);
  assert.equal(overlap.overlapOutcomesMayChange, true, `${row.id}: the snapshot does not warn about overlap`);
  if (overlap.id === "github-token") {
    // Provider-to-contextual: the weaker contextual detector now owns the span, with its own type and action.
    equal(overlap.detectorsReported, ["generic-token"], `${row.id}: expected the contextual fallback`);
    assert.equal(overlap.findings[0][1], "contextual_secret");
    assert.equal(overlap.findings[0][4], "warn");
    assert.equal(overlap.textKeepsSecret, true, "a warn keeps the text, a redact would not");
    assert.equal(defaultScans.provider[0][0], "github-token");
    assert.equal(defaultScans.provider[0][4], "redact");
  }
}

export function checkRejections(row, result) {
  const { attempts, resolved } = result;
  for (const name of ["unknownId", "pastedAsIdentifier", "both", "unknownDetectionMember"]) {
    assert.equal(attempts[name].code, "INVALID_DETECTION_CONFIG", `${row.id}: ${name}`);
  }
  if (row.known.notIncluded.length > 0) {
    assert.equal(attempts.notIncluded.code, "INVALID_DETECTION_CONFIG", `${row.id}: excluded capability`);
  } else assert.equal(attempts.notIncluded, undefined);
  assert.equal(attempts.nothingEnabled.code, "EMPTY_DETECTION_SET");
  assert.equal(attempts.piiSelector.code, row.piiAvailable ? "PII_SELECTOR_INVALID" : "PII_SELECTOR_UNAVAILABLE");
  for (const name of ["detectionOnScan", "detectionOnSession", "callbackAndPolicy"]) {
    assert.equal(attempts[name].code, "INVALID_OPTIONS", `${row.id}: ${name}`);
  }
  assert.equal(result.afterRejections, false, `${row.id}: a rejected request initialized the owner`);
  equal(result.enabled, row.known.included, `${row.id}: a rejected request changed the defaults`);

  const has = (name, code, severity = "error") =>
    assert.ok(
      resolved[name].codes.some(([found, level]) => found === code && level === severity),
      `${row.id}: ${name} does not report ${code}`,
    );
  for (const name of ["unknownId", "pastedAsIdentifier", "both", "unknownMember", "pii", "reservedRulesetId"]) {
    assert.equal(resolved[name].ok, false, `${row.id}: ${name} resolved`);
    assert.equal(resolved[name].snapshot, true, `${row.id}: ${name} returned a snapshot`);
  }
  has("unknownId", "UNKNOWN_DETECTOR_ID");
  if (row.known.notIncluded.length > 0) has("notIncluded", "DETECTOR_NOT_INCLUDED");
  has("pastedAsIdentifier", "INVALID_IDENTIFIER");
  has("both", "DETECTION_SELECTOR_CONFLICT");
  has("unknownMember", "UNKNOWN_FIELD");
  has("pii", row.piiAvailable ? "PII_SELECTOR_INVALID" : "PII_SELECTOR_UNAVAILABLE");
  has("reservedRulesetId", "INVALID_RULESET");
  has("rulesetIdNotSelectable", "UNKNOWN_DETECTOR_ID");
  // A selection that leaves nothing is described (inert), never silently widened.
  assert.equal(resolved.nothingEnabled.ok, true);
  has("nothingEnabled", "NO_BUILT_IN_DETECTORS", "warning");
}

export function checkOwnership(row, result) {
  assert.equal(result.canonicalOrder, true, `${row.id}: the enabled set is not in canonical order`);
  assert.equal(result.equivalent, true, `${row.id}: an equivalent selection is not idempotent`);
  assert.equal(result.plain.code, "DETECTION_CONFIG_CONFLICT", `${row.id}: plain initialize after a narrowed one`);
  assert.equal(result.different.code, "DETECTION_CONFIG_CONFLICT");
  assert.equal(result.unchanged, true, `${row.id}: a conflicting request changed the configuration`);
}

export function checkSessions(row, result, { narrowed }) {
  for (const [name, runs] of Object.entries(result.partitions)) {
    for (const run of runs) {
      assert.equal(run.equalsWhole, true, `${row.id}: ${name} chunked by ${run.size} differs from the whole input`);
    }
  }
  assert.equal(result.reconfigure.code, "DETECTION_CONFIG_CONFLICT");
  assert.equal(result.earlyEqualsLate, true, `${row.id}: a session made before the refused change behaves differently`);
  assert.equal(result.appendAfterFinalize.code, "INVALID_STATE");
  assert.equal(result.finalizeTwice.code, "INVALID_STATE");
  assert.equal(result.rulesetOnSession.code, "INVALID_OPTIONS", `${row.id}: a session accepted a ruleset`);
  assert.equal(result.detectionOnSession.code, "INVALID_OPTIONS");
  assert.equal(result.targetRedacted, result.sessionTargetRedacted, `${row.id}: session and whole input disagree`);
  if (!narrowed) assert.equal(result.targetRedacted, true);
}

export function checkComparison(row, result) {
  const { policyOnly, configChange, pii } = result;
  // Allowing a finding changes its action and nothing about detection.
  equal(policyOnly.statuses, [
    ["scanned", null],
    ["scanned", null],
  ]);
  assert.equal(policyOnly.detectionDigests[0], policyOnly.detectionDigests[1], `${row.id}: allow changed detection`);
  assert.notEqual(policyOnly.digests[0], policyOnly.digests[1], "the policy is part of the configuration identity");
  assert.equal(policyOnly.entries[1].length, 1);
  const [kind, correspondence, changes] = policyOnly.entries[1][0];
  equal([kind, correspondence], ["changed", "exact"]);
  assert.ok(
    changes.every((change) => ["action", "reason"].includes(change)),
    `${row.id}: allow changed ${changes}`,
  );
  assert.equal(policyOnly.counts[1].allow, 1);
  // Disabling the detector changes detection, whatever the action says.
  assert.notEqual(configChange.detectionDigests[0], configChange.detectionDigests[1], `${row.id}: no detection change`);
  assert.ok(configChange.entries[1].length >= 1, `${row.id}: disabling changed nothing`);
  const [first] = configChange.entries[1];
  if (result.id === "github-token") {
    assert.ok(first[2].includes("detector") && first[2].includes("type"), `${row.id}: provider-to-contextual`);
  }
  assert.equal(policyOnly.mode, "preview");
  assert.equal(policyOnly.enforced, false);
  // PII: where it is in this process it is compared; elsewhere the side is unsupported, never skipped.
  if (result.piiExpected) {
    equal(pii.statuses[1], ["scanned", null]);
    assert.equal(pii.entries[1][0][0], "added", `${row.id}: PII added nothing`);
  } else {
    equal(pii.statuses[1], ["unsupported", "PII_SELECTOR_UNAVAILABLE"]);
    assert.equal(pii.entries[1], null);
  }
}

export function checkPii(row, off, on) {
  equal(off.email, [], `${row.id}: PII is on by default`);
  equal(off.families, []);
  assert.match(off.activation, /selectors=off/);
  assert.equal(off.credentialsStillFound, true);
  assert.equal(on.credentialsStillFound, true);
  assert.equal(on.email.length, 1, `${row.id}: PII selection found no email`);
  assert.equal(on.email[0][1], "pii_global_email");
  equal(on.families, ["pii:global:email"]);
  assert.notEqual(on.detectionDigest, off.detectionDigest, "PII does not change the detection identity");
}

export function checkDiagnostics(row, result) {
  const typo = result.typo.codes;
  const code = (list, name) => list.filter(([found]) => found === name);
  assert.equal(code(typo, "ACTION_POLICY_UNKNOWN_DETECTOR").length, 1, `${row.id}: the typo`);
  // A secret pasted where a detector id belongs is a rejected document, named by code and path only.
  equal([result.pasted.ok, result.pasted.snapshot], [false, true]);
  assert.equal(code(result.pasted.codes, "INVALID_ACTION_POLICY").length, 1);
  const shadowed = code(typo, "ACTION_POLICY_SHADOWED_RULE");
  assert.equal(shadowed.length, 1);
  assert.equal(shadowed[0][3], "second");
  assert.ok(code(result.disabled.codes, "ACTION_POLICY_RULE_ON_UNENABLED_DETECTOR").length >= 1);
  equal([result.callbackAndPolicy.ok, result.callbackAndPolicy.snapshot], [false, true]);
  equal(result.callbackAndPolicy.codes[0].slice(0, 3), ["INVALID_OPTIONS", "error", "actionPolicy"]);
  equal([result.callback.ok, result.callback.source, result.callback.explainable], [true, "callback", false]);
}

export function checkRulesets(result) {
  assert.equal(result.withRuleset.length, 1);
  assert.equal(result.withRuleset[0][0], "acme-internal");
  assert.ok(result.without.every(([detector]) => detector !== "acme-internal"));
  assert.equal(result.reserved.code, "INVALID_RULESET");
  assert.equal(result.snapshotRuleset.disclosed, false);
  assert.equal(result.snapshotRuleset.detectorIds, null);
  equal(result.disclosedIds, ["acme-internal"]);
}

export function checkAdapterSurface(row, result) {
  assert.ok(Object.values(result.present).every(Boolean), `${row.id}: a name the adapters call is missing`);
  const [text, bytes, object] = result.actionPolicyForms;
  equal(bytes, text, `${row.id}: bytes and text actionPolicy differ`);
  equal(object, text, `${row.id}: an object and its text actionPolicy differ`);
  assert.equal(text[0], true, "a warn rule keeps the text");
  assert.equal(result.emptyProbe.code, null, "the adapters' empty-input option probe is rejected");
  assert.equal(result.both.code, "INVALID_OPTIONS");
  assert.equal(result.rejected.code, "INVALID_ACTION_POLICY");
  assert.equal(result.sessionKeepsWarned, true);
}

// ---------------------------------------------------------------------------
// Rows.
// ---------------------------------------------------------------------------

function installedRows(project) {
  const coreDist = join(project, "node_modules", "@redact-secret", "core", "dist");
  return [
    {
      id: "node-addon/full",
      target: "node-addon",
      profile: "full",
      manifestKind: "node-addon",
      load: { type: "package", url: fileUrl(join(coreDist, "index.js")) },
      piiAvailable: true,
      piiInProcess: true,
      loadedArtifact: "addon",
    },
    {
      id: "node-addon/common",
      target: "node-addon",
      profile: "common",
      manifestKind: "node-addon",
      load: { type: "package", url: fileUrl(join(coreDist, "common.js")) },
      piiAvailable: true,
      piiInProcess: true,
      loadedArtifact: "addon",
    },
    {
      id: "wasm/full",
      target: "wasm",
      profile: "full",
      manifestKind: "wasm",
      load: { type: "wasm", coreDist, profile: "full" },
      piiAvailable: true,
      piiInProcess: false,
      loadedArtifact: "wasm",
      binary: "redact_secret_wasm_bg.wasm",
    },
    {
      id: "wasm/common",
      target: "wasm",
      profile: "common",
      manifestKind: "wasm",
      load: { type: "wasm", coreDist, profile: "common" },
      piiAvailable: true,
      piiInProcess: false,
      loadedArtifact: "wasm",
      binary: "redact_secret_wasm_common_bg.wasm",
    },
  ];
}

function customRow(customDir) {
  return {
    id: "wasm/custom",
    target: "wasm",
    profile: "custom",
    manifestKind: "wasm",
    load: { type: "custom", url: fileUrl(join(customDir, "index.js")) },
    piiAvailable: false,
    piiInProcess: false,
    loadedArtifact: "wasm",
    binary: "redact_secret_wasm_custom_bg.wasm",
  };
}

const targetOf = (known) => (known.included.includes("github-token") ? "github-token" : "jwt");

async function qualifyRow(row, installed, report) {
  const entry = { id: row.id, target: row.target, profile: row.profile };
  report.rows.push(entry);

  const manifest = await runJourney(row, "manifest");
  row.known = { included: manifest.included, notIncluded: manifest.notIncluded };
  assert.equal(manifest.loaded, row.loadedArtifact, `${row.id}: loaded ${manifest.loaded}`);
  entry.manifestDigest = manifest.manifestDigest;
  entry.snapshotDigest = manifest.snapshotDigest;
  entry.detectors = manifest.included.length;
  entry.version = manifest.version;
  if (row.binary !== undefined && installed !== undefined) {
    const binary = installed.binaries.find(({ file }) => file === row.binary);
    assert.ok(binary, `${row.id}: ${row.binary} is not in the installed package`);
    entry.binary = { file: binary.file, sha256: binary.sha256 };
  }
  if (row.target === "node-addon" && installed !== undefined) {
    entry.binary = installed.binaries.find(({ file }) => file.endsWith(".node"));
  }
  row.manifest = manifest;

  // Build defaults and runtime overrides give the same effective behavior.
  const all = manifest.included;
  const runs = [await runJourney(row, "effective")];
  for (const [name, init] of [
    ["include=all", { detection: { include: all } }],
    ["include=all reversed", { detection: { include: [...all].reverse() } }],
    ["exclude=[]", { detection: { exclude: [] } }],
  ]) {
    runs.push([name, await runJourney(row, "effective", init)]);
  }
  checkEffectiveEquivalence(row, runs);
  row.defaults = runs[0];
  entry.checks = { effectiveEquivalence: runs.length };
  if (row.profile !== "custom") {
    entry.checks.incrementalKeyBoundary = await runInstalledIncrementalBoundary(row);
    assert.equal(
      entry.checks.incrementalKeyBoundary.artifact,
      row.loadedArtifact,
      `${row.id}: boundary loaded another artifact`,
    );
  }

  const target = targetOf(row.known);
  checkSelectionBeforeOverlap(row, await runJourney(row, "overlap"), runs[0].scans);
  checkRejections(row, await runJourney(row, "rejections"));
  checkOwnership(row, await runJourney(row, "ownership"));
  checkSessions(row, await runJourney(row, "sessions"), { narrowed: false });
  checkSessions(row, await runJourney(row, "sessions", { detection: { exclude: [target] } }), { narrowed: true });
  checkComparison(row, await runJourney(row, "comparison"));
  const off = await runJourney(row, "pii");
  if (row.profile !== "custom") {
    const on = await runJourney(row, "pii", { pii: [...PII_ALL] });
    checkPii(row, off, on);
    entry.checks.pii = "off/on";
  } else {
    equal(off.email, []);
    entry.checks.pii = "off; on is PII_SELECTOR_UNAVAILABLE (rejections)";
  }
  checkDiagnostics(row, await runJourney(row, "diagnostics"));
  checkRulesets(await runJourney(row, "rulesets"));
  checkAdapterSurface(row, await runJourney(row, "adapterSurface"));
  Object.assign(entry.checks, {
    selectionBeforeOverlap: "ok",
    rejections: "ok",
    ownership: "ok",
    sessions: "ok (default and narrowed)",
    allowVersusDisable: "ok",
    diagnostics: "ok",
    rulesets: "ok",
    adapterSurface: "ok",
    noSecretInOutputs: "ok (asserted in the worker on every result)",
  });
}

/** Cross-row facts: the artifacts relate as the contract says, and a custom artifact equals its oracle. */
function checkAcrossRows(rows, report) {
  const byId = Object.fromEntries(rows.map((row) => [row.id, row]));
  const full = byId["node-addon/full"];
  equal(byId["wasm/full"].known.included, full.known.included, "addon and wasm `full` include different detectors");
  const fullIds = new Set(full.known.included);
  for (const id of byId["wasm/common"].known.included) assert.ok(fullIds.has(id), `common holds ${id}, full lacks it`);
  equal(byId["node-addon/common"].known.included, byId["wasm/common"].known.included);
  assert.notEqual(full.manifest.manifestDigest, byId["wasm/full"].manifest.manifestDigest, "digest ignores the kind");
  assert.notEqual(byId["wasm/full"].manifest.manifestDigest, byId["wasm/common"].manifest.manifestDigest);
  const custom = byId["wasm/custom"];
  if (custom !== undefined) {
    for (const id of custom.known.included) assert.ok(fullIds.has(id));
    assert.ok(custom.known.included.length < full.known.included.length);
    report.crossRow = { fullDetectors: full.known.included.length, customDetectors: custom.known.included.length };
  }
}

// ---------------------------------------------------------------------------
// The custom artifact: exactly the bytes its manifest and build report describe.
// ---------------------------------------------------------------------------

function qualifyCustomFiles(customDir, row) {
  const text = readFileSync(join(customDir, "artifact-manifest.custom.json"), "utf8");
  const packaged = JSON.parse(text);
  assert.equal(packaged.digest, canonicalDigest(packaged), "the packaged manifest digest is not its own");
  assert.equal(packaged.digest, row.manifest.manifestDigest, "the loaded artifact reports another manifest");
  assert.equal(
    JSON.stringify(packaged),
    row.manifest.manifestJson,
    "the loaded manifest differs from the packaged file",
  );
  assert.equal(packaged.artifact.variant, "custom");
  equal(
    packaged.detectors.map((detector) => detector.id),
    row.known.included,
  );
  const buildReport = JSON.parse(readFileSync(join(customDir, "build-report.json"), "utf8"));
  assert.equal(buildReport.manifest.digest, packaged.digest, "the build report names another manifest");
  assert.equal(buildReport.composition.id, packaged.composition.id);
  const files = {};
  for (const [name, digest] of Object.entries(buildReport.files)) {
    assert.equal(sha256Hex(readFileSync(join(customDir, name))), digest, `${name} differs from the build report`);
    files[name] = digest;
  }
  const defaults = JSON.parse(readFileSync(join(customDir, "default-configuration.json"), "utf8"));
  assert.equal(
    defaults.artifact.manifestDigest,
    packaged.digest,
    "the recorded default snapshot is another artifact's",
  );
  return {
    packagedManifestDigest: packaged.digest,
    compositionId: packaged.composition.id,
    binary: { file: "redact_secret_wasm_custom_bg.wasm", sha256: files["redact_secret_wasm_custom_bg.wasm"] },
    buildReportFiles: Object.keys(files).length,
  };
}

async function qualifyCustomRefusals(parent) {
  const refused = {};
  for (const target of ["node-addon", "python-wheel"]) {
    const outDir = join(parent, `refused-${target}`);
    let error;
    try {
      await buildCustomArtifact({ composition: { ...CUSTOM_COMPOSITION }, outDir, target });
    } catch (thrown) {
      error = thrown;
    }
    assert.ok(error instanceof CompositionError, `a custom ${target} was not refused`);
    assert.equal(error.code, "UNSUPPORTED_TARGET");
    assert.equal(existsSync(outDir), false, `a custom ${target} emitted something`);
    refused[target] = error.code;
  }
  return refused;
}

// ---------------------------------------------------------------------------
// Unsupported surfaces, asserted.
// ---------------------------------------------------------------------------

function verifyForeignManifest(text, kindLabel) {
  const manifest = JSON.parse(text);
  assert.equal(manifest.schema, "artifact-manifest/v1");
  assert.equal(manifest.digest, canonicalDigest(manifest), `${kindLabel}: manifest digest`);
  assert.equal(manifest.capabilities.detectorSelection, false, `${kindLabel}: claims detector selection`);
  return manifest;
}

function qualifyCli(binary, fullDigest) {
  const printed = spawnSync(binary, ["--print-artifact-manifest"], { encoding: "utf8" });
  assert.equal(printed.status, 0, "the CLI does not print its manifest");
  const manifest = verifyForeignManifest(printed.stdout, "cli");
  assert.notEqual(manifest.digest, fullDigest, "the CLI manifest digest equals an addon's");
  const refused = spawnSync(binary, ["--detection-include", "jwt"], { encoding: "utf8", input: "" });
  assert.notEqual(refused.status, 0, "the CLI accepted a detector selection");
  assert.equal(refused.stdout, "", "the CLI wrote output for a refused selection");
  return { verified: true, kind: manifest.artifact.kind, manifestDigest: manifest.digest, selectionFlag: "refused" };
}

function qualifyPython(python) {
  const script = [
    "import json, redact_secret as r",
    "m = r.artifact_manifest()",
    "print(json.dumps({'manifest': m, 'configSurface': [n for n in ('resolve_config', 'describe_config', 'compare_configurations') if hasattr(r, n)]}))",
  ].join("\n");
  const run = spawnSync(python, ["-I", "-c", script], { encoding: "utf8" });
  assert.equal(run.status, 0, "the installed wheel did not run");
  const { manifest, configSurface } = JSON.parse(run.stdout);
  verifyForeignManifest(JSON.stringify(manifest), "python");
  assert.deepEqual(configSurface, [], "the Python wheel exposes a configuration function");
  return {
    verified: true,
    kind: manifest.artifact.kind,
    manifestDigest: manifest.digest,
    configurationFunctions: configSurface,
  };
}

// ---------------------------------------------------------------------------
// Bundlers and the quickstart.
// ---------------------------------------------------------------------------

async function runInProject(project, env, file) {
  const result = await runShell(`node ${file}`, project, env);
  if (result.code !== 0) process.stderr.write(result.stderr.slice(0, 2000));
  assert.equal(result.code, 0, `${file} exited ${result.code}`);
  return result.stdout;
}

async function qualifyBundlers({ project, env, customDir, customRow: row, standard }) {
  const out = {};
  const consumer = (entry, extra = "") =>
    `import { initialize, scanAndRedact, scan, artifactManifest, describeConfig } from ${JSON.stringify(entry)};\n` +
    `await initialize();\n${extra}\nconsole.log(JSON.stringify({ digest: artifactManifest().digest, ` +
    `profile: artifactManifest().artifact.variant, id: artifactManifest().composition.id, ` +
    `enabled: describeConfig().detection.enabledCount, redacted: !scanAndRedact(${JSON.stringify(PROBES.provider)}).text.includes(${JSON.stringify(SYNTHETIC.github)}), ` +
    `findings: scan(${JSON.stringify(PROBES.provider)}).length }));\n`;

  // 1. The standard package, bundled for Node: imports stay compatible.
  writeFileSync(join(project, "app-standard.mjs"), consumer("@redact-secret/core"));
  await esbuild({
    entryPoints: [join(project, "app-standard.mjs")],
    bundle: true,
    format: "esm",
    platform: "node",
    outfile: join(project, "bundled", "standard", "app.mjs"),
    absWorkingDir: project,
    logLevel: "error",
  });
  const standardRun = JSON.parse(await runInProject(project, env, "bundled/standard/app.mjs"));
  assert.equal(standardRun.digest, standard.manifestDigest, "the bundled standard package is another artifact");
  assert.equal(standardRun.redacted, true);
  out.standard = { bundler: "esbuild", platform: "node", digest: standardRun.digest, executed: true };

  // 2. The generated custom artifact, vendored into the project and bundled.
  cpSync(customDir, join(project, "vendor", "redact"), { recursive: true });
  writeFileSync(join(project, "app-custom.mjs"), consumer("./vendor/redact/index.js"));
  for (const platform of ["node", "browser"]) {
    const outfile = join(project, "bundled", `custom-${platform}`, "app.mjs");
    await esbuild({
      entryPoints: [join(project, "app-custom.mjs")],
      bundle: true,
      format: "esm",
      platform,
      outfile,
      absWorkingDir: project,
      plugins: [copyRedactWasm({ artifactDir: join(project, "vendor", "redact") })],
      logLevel: "error",
    });
    const bundle = readFileSync(outfile, "utf8");
    assert.ok(bundle.includes("redact_secret_wasm_custom_bg.wasm"), "the bundle does not reference its binary");
    assert.equal(
      sha256Hex(readFileSync(join(project, "bundled", `custom-${platform}`, "redact_secret_wasm_custom_bg.wasm"))),
      row.binarySha256,
      "the bundler recipe copied another binary",
    );
    out[`custom-${platform}`] = { bundler: "esbuild", platform, binaryCopied: true, executed: platform === "node" };
  }
  const customRun = JSON.parse(await runInProject(project, env, "bundled/custom-node/app.mjs"));
  assert.equal(customRun.profile, "custom");
  assert.equal(customRun.digest, row.manifest.manifestDigest, "the bundled custom artifact is another artifact");
  assert.equal(customRun.id, row.manifest.compositionId);
  assert.equal(customRun.redacted, true);
  out["custom-node"].digest = customRun.digest;
  return out;
}

async function qualifyQuickstart(project, env) {
  const source = readFileSync(join(REPO_ROOT, QUICKSTART));
  writeFileSync(join(project, "quickstart.mjs"), source);
  const stdout = await runInProject(project, env, "quickstart.mjs");
  const steps = Object.fromEntries(
    stdout
      .trim()
      .split("\n")
      .map((line) => {
        const [number, name, ...rest] = line.split(" ");
        return [`${number} ${name}`, JSON.parse(rest.join(" "))];
      }),
  );
  assert.equal(steps["1 manifest"].detectorSelection, true);
  assert.equal(steps["2 resolve"].ok, true);
  assert.equal(steps["2 describe"].origins, "artifact-default");
  const codes = steps["3 diagnose"].map(({ code }) => code);
  for (const code of ["ACTION_POLICY_UNKNOWN_DETECTOR", "ACTION_POLICY_SHADOWED_RULE"]) {
    assert.ok(codes.includes(code), `the quickstart does not show ${code}`);
  }
  equal(steps["4 compare"].statuses, ["scanned", "scanned"]);
  assert.equal(steps["4 compare"].mode, "preview");
  assert.equal(steps["4 compare"].sameDetection, false);
  equal(steps["5 apply"], { findings: [{ detector: "github-token", action: "redact" }], text: "API_KEY=<SECRET_1>" });
  equal(steps["5 warn"], { findings: [{ detector: "github-token", action: "warn" }], textKept: true });
  equal(steps["5 empty"], { findings: 0, unchanged: true });
  // The quickstart's own output holds findings by range and codes only: no input byte, no hash.
  for (const value of Object.values(SYNTHETIC)) assert.ok(!stdout.includes(value));
  assert.ok(!stdout.includes(EMAIL_INPUT));
  return { script: QUICKSTART, sha256: sha256Hex(source), steps: Object.keys(steps) };
}

// ---------------------------------------------------------------------------

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (process.platform === "win32") throw new Error(`${LABEL}: the driver runs POSIX shell commands`);
  const version = JSON.parse(readFileSync(join(REPO_ROOT, "packages/javascript/package.json"), "utf8")).version;
  const { parent, project } = await freshWorkspace("redact-secret-configuration-", LABEL);
  let registry;
  try {
    const candidate = await loadNpmCandidate(options.candidateDir, join(parent, "tarballs"), LABEL);
    for (const entry of candidate.values()) {
      fail(entry.manifest.version === version, `${entry.file} is ${entry.manifest.version}, not ${version}`);
    }
    registry = await startCandidateRegistry(candidate);
    const npmrc = join(parent, "npmrc");
    await writeFile(npmrc, `registry=${registry.url}\n@redact-secret:registry=${registry.url}\n`);
    const env = cleanEnvironment({
      npm_config_cache: join(parent, "npm-cache"),
      npm_config_update_notifier: "false",
      NPM_CONFIG_USERCONFIG: npmrc,
    });
    writeFileSync(
      join(project, "package.json"),
      `${JSON.stringify({ name: "configuration-candidate", private: true, type: "module", dependencies: { "@redact-secret/core": version } }, null, 2)}\n`,
    );
    const install = await runShell("npm install --no-audit --no-fund", project, env);
    if (install.code !== 0) process.stderr.write(install.stdout + install.stderr);
    fail(install.code === 0, `npm install exited ${install.code}`);
    const installed = await verifyNpmInstall(project, version, candidate, registry.url, { label: LABEL });

    let customDir = options.customDir;
    if (options.buildCustom) {
      customDir = join(parent, "custom");
      const wasm = join(project, "node_modules", "@redact-secret", "wasm", "redact_secret_wasm_bg.wasm");
      await buildCustomArtifact({
        composition: { ...CUSTOM_COMPOSITION },
        outDir: customDir,
        baseline: wasm,
        log: (message) => console.error(`[custom] ${message}`),
      });
    }

    const report = {
      schema: "configuration-qualification/v1",
      sourceCommit: sourceCommit(),
      published: false,
      productVersion: version,
      platform: `${process.platform}-${process.arch}`,
      node: process.version,
      packages: installed.packages,
      binaries: installed.binaries,
      rows: [],
      unsupported: {},
    };

    const rows = installedRows(project);
    for (const row of rows) await qualifyRow(row, installed, report);
    const custom = customRow(customDir);
    await qualifyRow(custom, undefined, report);
    rows.push(custom);
    checkAcrossRows(rows, report);

    const customFiles = qualifyCustomFiles(customDir, custom);
    custom.binarySha256 = customFiles.binary.sha256;
    Object.assign(
      report.rows.find((entry) => entry.id === custom.id),
      { exact: customFiles, binary: customFiles.binary },
    );

    // The oracle of the custom artifact is the standard `full` artifact narrowed to the same ids.
    const oracle = await runJourney(rows[2], "effective", { detection: { include: custom.known.included } });
    equal(oracle.enabled, custom.defaults.enabled);
    equal(oracle.scans, custom.defaults.scans, "the custom artifact disagrees with `full` narrowed to its detectors");
    report.customOracle = "wasm/full initialized with the custom artifact's ids: identical enabled set and scans";

    report.unsupported.customTargets = await qualifyCustomRefusals(parent);
    const fullAddon = rows[0].manifest.manifestDigest;
    if (options.cliBinary !== undefined) report.unsupported.cli = qualifyCli(options.cliBinary, fullAddon);
    else report.unsupported.cli = { verified: false, reason: "no --cli-binary given" };
    if (options.python !== undefined) report.unsupported.python = qualifyPython(options.python);
    else report.unsupported.python = { verified: false, reason: "no --python given" };
    if (options.requireUnsupported) {
      for (const name of ["cli", "python"]) {
        fail(report.unsupported[name].verified !== false, `the ${name} unsupported row was not run`);
      }
    }

    report.bundlers = await qualifyBundlers({
      project,
      env,
      customDir,
      customRow: custom,
      standard: rows[0].manifest,
    });
    report.quickstart = await qualifyQuickstart(project, env);

    if (options.report !== undefined) writeFileSync(options.report, `${JSON.stringify(report, null, 2)}\n`);
    const checked = report.rows.map((row) => row.id).join(", ");
    console.log(
      `Configuration qualification passed (${version}, ${report.platform}): ${checked}; custom composition ` +
        `${report.crossRow.customDetectors}/${report.crossRow.fullDetectors} detectors; bundlers and quickstart ran against the installed candidate.`,
    );
  } finally {
    await registry?.close();
    await rm(parent, { recursive: true, force: true });
  }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    await main();
  } catch (error) {
    // An assertion names the row and the check, never an input.
    console.error(
      String(error?.stack ?? error)
        .split("\n")
        .slice(0, 12)
        .join("\n"),
    );
    process.exitCode = 1;
  }
}
