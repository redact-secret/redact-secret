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
