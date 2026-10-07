// One configuration scenario against a real, built artifact, in a Worker.
//
// Each Worker is its own thread, so the native owner state (the registry, the
// PII activation and the detector selection are thread-local) starts fresh:
// that is exactly the recipe the ownership guide gives for independent
// configurations, and it lets one test file run many one-shot initializations.
//
// The Worker loads the compiled package (`dist`, built by `npm run js:build`)
// and one real binding: the N-API addon (`bindings/node`) or the WebAssembly
// artifact (`bindings/wasm/pkg*`). It reports plain observations; the test
// asserts on them.

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { parentPort, workerData } from "node:worker_threads";

import {
  casesFor as compareCasesFor,
  loadConfigurationCompareFixture,
  optionsFor,
  project,
} from "../../../../conformance/configuration-compare.mjs";
import {
  casesFor,
  checkCase,
  loadRuntimeConfigFixture,
  runtimeArguments,
} from "../../../../conformance/runtime-config.mjs";

const { artifact, profile, scenario, root } = workerData;
const dist = `${root}/packages/javascript/dist`;
const { createRedactSecretRuntime } = await import(`${dist}/runtime.js`);
const node = await import(`${dist}/runtime/node.js`);
const wasmBinding = await import(`${dist}/runtime/wasm-binding.js`);

async function loadBinding() {
  if (artifact === "addon") {
    const addon = createRequire(import.meta.url)(`${root}/bindings/node/index.js`);
    return profile === "common" ? node.createBindingFromCommonAddon(addon) : node.createBindingFromAddon(addon);
  }
  const directory = `${root}/bindings/wasm/${profile === "common" ? "pkg-common" : "pkg"}`;
  const name = profile === "common" ? "redact_secret_wasm_common" : "redact_secret_wasm";
  const module = await import(`${directory}/${name}.js`);
  await module.default({ module_or_path: readFileSync(`${directory}/${name}_bg.wasm`) });
  return wasmBinding.createBindingFromWasmModule(module);
}

const binding = await loadBinding();
const runtime = createRedactSecretRuntime(async () => binding, profile);

const TOKEN = "ghp_SYNTHETICREVOKED00000000000000000000";
const KEYED = `API_KEY=${TOKEN}`;
const LIMITS = { maxInputBytes: 1_000_000, maxBufferedBytes: 16_512, maxTokenBytes: 8_192, maxMultilineBytes: 16_384 };

async function settle(attempt) {
  try {
    await attempt();
    return "ok";
  } catch (error) {
    return error.code ?? `unexpected:${error.name}`;
  }
}

/** Compares by value, whatever order an object's members arrived in. */
function canonical(value) {
  const sort = (item) =>
    Array.isArray(item)
      ? item.map(sort)
      : item !== null && typeof item === "object"
        ? Object.fromEntries(
            Object.keys(item)
              .sort()
              .map((key) => [key, sort(item[key])]),
          )
        : item;
  return JSON.stringify(sort(value));
}

function detectors(findings) {
  return findings.map((finding) => finding.detector);
}

function sessionText(chunks) {
  const session = runtime.createIncrementalSanitizer({ limits: LIMITS });
  let text = "";
  for (const chunk of chunks) text += session.append(chunk).text;
  return text + session.finalize().text;
}

async function run() {
  if (scenario === "fixture") {
    const fixture = loadRuntimeConfigFixture();
    await runtime.initialize();
    const manifest = runtime.artifactManifest();
    const failures = [];
    let ran = 0;
    for (const fixtureCase of casesFor(fixture, profile)) {
      const inputs = runtimeArguments(fixtureCase);
      if (inputs === undefined) continue;
      const { config, options } = inputs;
      let resolution;
      try {
        resolution = runtime.resolveConfig(config, options);
      } catch (error) {
        failures.push(`${fixtureCase.name}: threw ${error.code}`);
        continue;
      }
      ran += 1;
      checkCase(fixtureCase, profile, resolution, manifest, (actual, expected, message) => {
        if (canonical(actual) !== canonical(expected)) {
          failures.push(`${message}: ${canonical(actual).slice(0, 200)} !== ${canonical(expected).slice(0, 200)}`);
        }
      });
    }
    return { ran, failures };
  }

  if (scenario === "compare") {
    // Every shared case, from the fixture: the Rust core runs the same file.
    const fixture = loadConfigurationCompareFixture();
    await runtime.initialize();
    const failures = [];
    let ran = 0;
    const leaks = [];
    for (const fixtureCase of compareCasesFor(fixture, profile)) {
      const options = optionsFor(fixtureCase);
      let comparison;
      try {
        comparison = runtime.compareConfigurations(fixtureCase.input, options);
      } catch (error) {
        failures.push(`${fixtureCase.name}: threw ${error.code ?? error.message}`);
        continue;
      }
      ran += 1;
      const actual = canonical(project(fixtureCase.input, comparison));
      const expected = canonical(fixtureCase.expect[profile]);
      if (actual !== expected)
        failures.push(`${fixtureCase.name}: ${actual.slice(0, 300)} !== ${expected.slice(0, 300)}`);
      // The serialized result holds no input, no per-scan id and no digest of
      // anything but a configuration or a policy document.
      const serialized = JSON.stringify(comparison);
      for (const word of fixtureCase.input.split(/\s+/).filter((word) => word.length >= 12)) {
        if (serialized.includes(word)) leaks.push(`${fixtureCase.name}: input word`);
      }
      if (/finding-\d/.test(serialized)) leaks.push(`${fixtureCase.name}: per-scan id`);
      const allowed = new Set();
      for (const config of comparison.configs) {
        for (const digest of [config.digest, config.detectionDigest]) {
          if (digest !== null) allowed.add(digest.replace("sha256:", ""));
        }
        if (config.policy.documentSha256 !== null) allowed.add(config.policy.documentSha256);
      }
      for (const run of serialized.match(/[0-9a-f]{64}/g) ?? []) {
        if (!allowed.has(run)) leaks.push(`${fixtureCase.name}: unexpected 64-hex run`);
      }
      if (!Object.isFrozen(comparison) || !Object.isFrozen(comparison.results[0])) leaks.push("not frozen");
    }
    return { ran, failures, leaks };
  }

  if (scenario === "compareContract") {
    const jwtInput = "token eyJhbGciOiJub25lIn0.eyJzdWIiOiJTWU5USEVUSUMifQ.SYNTHETIC_REVOKED_SIG_00 end";
    // The owner is fixed to a narrow selection; a comparison is independent of
    // it and leaves it, and every scan, unchanged.
    await runtime.initialize({ detection: { include: ["jwt"] } });
    const before = {
      status: runtime.status(),
      snapshot: runtime.describeConfig(),
      keyed: detectors(runtime.scan(KEYED)),
    };
    const observed = {};
    const wide = runtime.compareConfigurations(KEYED, { configs: [{}, { detection: { include: ["jwt"] } }] });
    observed.wideDetectors = wide.results[0].findings.map((finding) => finding.detector);
    observed.narrowDetectors = wide.results[1].findings.map((finding) => finding.detector);
    observed.ownerUnchanged =
      runtime.describeConfig() === before.snapshot &&
      runtime.status().configuration === before.status.configuration &&
      canonical(detectors(runtime.scan(KEYED))) === canonical(before.keyed);
    observed.preview = [wide.mode, wide.enforced, wide.scope, wide.schema, wide.rangeUnit];
    observed.noCallbacks = wide.callbackSides;

    // Callbacks: disclosed, once per finding of each scanned side, in order.
    const log = [];
    const policy = {
      evaluate(finding, context) {
        log.push(`${finding.detector}#${context.findingIndex}`);
        return "warn";
      },
    };
    const withCallback = runtime.compareConfigurations(jwtInput, {
      configs: [{}, {}, { detection: { include: [] } }],
      policy,
    });
    observed.callbackLog = log.slice();
    observed.callbackSides = withCallback.callbackSides;
    observed.callbackKinds = withCallback.configs.map((config) => [config.policy.kind, config.policy.documentSha256]);
    observed.callbackStatus = withCallback.results.map((result) => result.status);
    observed.callbackActions = withCallback.results.map((result) => result.findings.map((finding) => finding.action));

    // A failing callback fails the whole call; a bad document fails it before any callback.
    observed.throwing = await settle(async () =>
      runtime.compareConfigurations(jwtInput, {
        configs: [{}, {}],
        policy: {
          evaluate: () => {
            throw new Error("boom");
          },
        },
      }),
    );
    observed.badAction = await settle(async () =>
      runtime.compareConfigurations(jwtInput, { configs: [{}], policy: { evaluate: () => "mask" } }),
    );
    log.length = 0;
    observed.badDocument = await settle(async () =>
      runtime.compareConfigurations(jwtInput, { configs: [{}, { actionPolicy: "{}" }], policy: undefined }),
    );
    observed.badDocumentWithCallback = await settle(async () =>
      runtime.compareConfigurations(jwtInput, { configs: [{ actionPolicy: "{}" }], policy }),
    );
    observed.callbackCallsAfterRejection = log.length;

    // Malformed calls detect nothing.
    const bad = (options) => settle(async () => runtime.compareConfigurations(jwtInput, options));
    observed.zero = await bad({ configs: [] });
    observed.five = await bad({ configs: [{}, {}, {}, {}, {}] });
    observed.unknownKey = await bad({ configs: [{}], detection: {} });
    observed.notObject = await bad({ configs: ["x"] });
    observed.notArray = await bad({ configs: {} });
    observed.missing = await bad({});
    observed.notString = await settle(async () => runtime.compareConfigurations(["x"], { configs: [{}] }));

    // PII the artifact cannot build is a failed, unsupported side, not a silent fallback.
    const email = "email: fixture876-q7m9@x4z8v2n6.synthetic";
    const pii = runtime.compareConfigurations(email, { configs: [{}, { pii: ["pii:family:global:email"] }] });
    observed.pii = [
      pii.results[1].status,
      pii.results[1].failure,
      pii.differences[1] === null,
      pii.results[0].status,
      pii.results[1].findings.map((finding) => finding.detector),
      pii.differences[1]?.entries.map((entry) => entry.kind) ?? null,
      JSON.stringify(pii).includes("fixture876"),
    ];

    // Shared and per-side action policies.
    const allowJwt =
      '{"actionPolicyRevision":1,"base":"default","rules":[{"id":"allow-jwt","match":{"type":["jwt"]},"action":"allow"}]}';
    const noRules = '{"actionPolicyRevision":1,"base":"default","rules":[]}';
    const shared = runtime.compareConfigurations(jwtInput, {
      configs: [{}, { actionPolicy: noRules }],
      actionPolicy: allowJwt,
    });
    observed.shared = shared.results.map((result) => result.findings.map((finding) => finding.action));
    observed.sharedDigests = shared.configs.map((config) => config.policy.documentSha256 !== null);
    observed.sharedDigestsDiffer = shared.configs[0].policy.documentSha256 !== shared.configs[1].policy.documentSha256;
    return observed;
  }

  if (scenario === "legacy") {
    await runtime.initialize();
    const snapshot = runtime.describeConfig();
    return {
      mode: snapshot.detection.mode,
      enabledCount: snapshot.detection.enabledCount,
      compiledCount: snapshot.detection.compiledCount,
      manifestDetectors: runtime.artifactManifest().detectors.length,
      origins: snapshot.origins.detection,
      keyed: detectors(runtime.scan(KEYED)),
      status: runtime.status(),
      sessionText: sessionText([KEYED.slice(0, 10), KEYED.slice(10)]),
      digestIsStatus: runtime.status().configuration === snapshot.digest,
    };
  }

  if (scenario === "owner") {
    const detection = { include: ["jwt", "private-key"] };
    await runtime.initialize({ detection });
    detection.include.push("github-token");
    const snapshot = runtime.describeConfig();
    const keyed = detectors(runtime.scan(KEYED));
    const observed = {
      enabled: snapshot.detection.enabled,
      disabledCount: snapshot.detection.disabled.length,
      mode: snapshot.detection.mode,
      origin: snapshot.origins.detection,
      overlap: snapshot.effects.overlapOutcomesMayChange,
      keyed,
      scanWithRuleset: detectors(
        runtime.scan(KEYED, {
          ruleset:
            'ruleset-revision: 1\ndetector: acme-internal-token\nspecificity: contextual\nprefix: "ACME_"\nalphabet: alnum-dash\nrun: at-least 20\nvalidator: none\n',
        }),
      ),
      sessionText: sessionText([KEYED.slice(0, 10), KEYED.slice(10)]),
      status: runtime.status(),
      frozen: Object.isFrozen(snapshot),
    };
    // Idempotent: the same resolved selection in another spelling and order.
    observed.idempotent = await settle(() => runtime.initialize({ detection: { include: ["private-key", "jwt"] } }));
    // Conflicts change nothing.
    observed.conflicts = [
      await settle(() => runtime.initialize({ detection: { include: ["jwt"] } })),
      await settle(() => runtime.initialize({ detection: { exclude: ["jwt"] } })),
      await settle(() => runtime.initialize()),
      await settle(() => runtime.initialize({ detection: {} })),
    ];
    // Previews never touch the owner.
    const preview = runtime.resolveConfig({ detection: { exclude: ["private-key"] } });
    observed.previewMode = preview.snapshot?.detection.mode;
    observed.previewEnabledCount = preview.snapshot?.detection.enabledCount;
    observed.unchanged = runtime.describeConfig() === snapshot && runtime.status().configuration === snapshot.digest;
    observed.keyedAfter = detectors(runtime.scan(KEYED));
    observed.perCall = await settle(async () => runtime.scan(KEYED, { detection: { include: ["jwt"] } }));
    return observed;
  }

  if (scenario === "rejected") {
    const outcomes = {};
    const bad = {
      unknown: { include: ["jwt", "no-such-detector"] },
      duplicate: { include: ["jwt", "jwt"] },
      conflict: { include: ["jwt"], exclude: ["jwt"] },
      empty: { include: [] },
      family: { include: ["pii:global:email"] },
      adapter: { include: ["pii-domain"] },
    };
    if (profile === "common") bad.notIncluded = { include: ["github-token"] };
    for (const [name, detection] of Object.entries(bad)) {
      outcomes[name] = await settle(() => runtime.initialize({ detection }));
      outcomes[`${name}Initialized`] = runtime.status().initialized;
    }
    // Nothing was cached: a valid request still succeeds afterwards.
    outcomes.valid = await settle(() => runtime.initialize({ detection: { include: ["jwt"] } }));
    outcomes.enabled = runtime.describeConfig().detection.enabled;
    return outcomes;
  }

  throw new Error(`unknown scenario ${scenario}`);
}

try {
  parentPort.postMessage({ ok: true, result: await run() });
} catch (error) {
  parentPort.postMessage({ ok: false, error: `${error.name}: ${error.message}` });
}
