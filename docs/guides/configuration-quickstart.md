# Configuration quickstart: look before you enforce

[Documentation home](../README.md) · [Capability matrix](../reference/detector-capability-matrix.md) · [Configuration ownership](configuration-ownership.md) · [Custom composition](custom-composition.md)

Five steps, run locally on synthetic input: read what the artifact contains,
resolve a configuration, diagnose it, compare it on a sample, and apply it. The
script below is `examples/configuration-quickstart/quickstart.mjs`, shown
verbatim; nothing in it reads a file, the environment or the network, and its only
credential-shaped value is the repository's revoked synthetic example.

## Run it

```sh
npm install @redact-secret/core
curl -O https://raw.githubusercontent.com/redact-secret/redact-secret/main/examples/configuration-quickstart/quickstart.mjs
node quickstart.mjs
```

CI runs this exact file as a test: `npm run configuration:qualify` installs the
candidate npm packages (the addon and the WebAssembly builds one
[artifact qualification](../releasing.md) run built) into an empty project outside the
checkout and runs it there, next to the journeys listed [below](#what-is-qualified).
Offline, `npm run ci` checks that this page still shows the file verbatim.

```js
// Configuration quickstart: look before you enforce. Local only, synthetic input only.
import {
  artifactManifest,
  compareConfigurations,
  describeConfig,
  initialize,
  resolveConfig,
  scanAndRedact,
} from "@redact-secret/core";

await initialize(); // the artifact's own defaults; nothing is read from disk, the environment or the network
const sample = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000"; // revoked, obviously synthetic
const benign = "release notes: nothing to see here";
const say = (step, value) => console.log(`${step} ${JSON.stringify(value)}`);

// 1. What does this artifact contain? (no scan, no input)
const manifest = artifactManifest();
say("1 manifest", {
  variant: manifest.artifact.variant,
  kind: manifest.artifact.kind,
  detectors: manifest.detectors.length,
  detectorSelection: manifest.capabilities.detectorSelection,
});

// 2. What would this configuration be? Resolve a request, then describe what is in force.
const policy = {
  actionPolicyRevision: 1,
  base: "default",
  rules: [
    { id: "warn-github", match: { detector: ["github-token"] }, action: "warn" },
    { id: "warn-github-again", match: { detector: ["github-token"] }, action: "block" }, // shadowed by the rule above
    { id: "typo", match: { detector: ["github-tokn"] }, action: "warn" }, // not a detector id
  ],
};
const candidate = { detection: { exclude: ["github-token"] }, actionPolicy: policy };
const preview = resolveConfig(candidate);
say("2 resolve", {
  ok: preview.ok,
  enabled: preview.snapshot?.detection.enabledCount,
  digest: preview.snapshot?.digest,
});
say("2 describe", { enabled: describeConfig().detection.enabledCount, origins: describeConfig().origins.detection });

// 3. Diagnose it: the typo and the shadowed rule are named by code and path, never by value.
say(
  "3 diagnose",
  preview.diagnostics.items.map(({ code, severity, path }) => ({ code, severity, path })),
);

// 4. Compare on synthetic samples: what changes for the baseline and for the candidate, on this input only.
const comparison = compareConfigurations(sample, { configs: [{}, candidate] });
say("4 compare", {
  mode: comparison.mode,
  statuses: comparison.results.map((result) => result.status),
  changed: comparison.differences[1]?.entries.map(({ kind, changes }) => ({ kind, changes })),
  sameDetection: comparison.configs[0].detectionDigest === comparison.configs[1].detectionDigest,
});

// 5. Apply: a supported per-call policy changes the action, the built-in default redacts. Output is ranges and
// placeholders only; an empty result is not a clean bill of health.
const redacted = scanAndRedact(sample);
say("5 apply", {
  findings: redacted.findings.map(({ detector, action }) => ({ detector, action })),
  text: redacted.text,
});
const warned = scanAndRedact(sample, { actionPolicy: { ...policy, rules: policy.rules.slice(0, 1) } });
say("5 warn", {
  findings: warned.findings.map(({ detector, action }) => ({ detector, action })),
  textKept: warned.text === sample,
});
const empty = scanAndRedact(benign);
say("5 empty", { findings: empty.findings.length, unchanged: empty.text === benign });
```

## Reading the output

| Step | Prints | How to read it |
| --- | --- | --- |
| 1 `manifest` | the artifact variant, kind, detector count and whether detector selection is supported | what was **compiled in**. `detectorSelection: false` (Python, CLI) means no step below exists on that surface |
| 2 `resolve`, `describe` | `ok`, the enabled count and a digest of the *request*; then what the running owner is fixed to | `resolve` is a pure preview (nothing is scanned, no owner changes); `describe` is what is **in force**, here the build defaults (`origins: artifact-default`) |
| 3 `diagnose` | a code, a severity and a path per finding about the request | the typo (`ACTION_POLICY_UNKNOWN_DETECTOR`) and the shadowed rule (`ACTION_POLICY_SHADOWED_RULE`) are named by position, never by value; the two `ACTION_POLICY_RULE_ON_UNENABLED_DETECTOR` warnings say the candidate disables the detector those rules target |
| 4 `compare` | one preview pass per side over this one input, `sameDetection: false` | disabling `github-token` hands the span to the contextual `generic-token` (`type`, `detector`, `confidence`, `action` changed); the sides' detection digests differ because the detection changed, not only an action |
| 5 `apply`, `warn`, `empty` | the built-in default redacts; a per-call `warn` rule keeps the text; a benign input finds nothing | a supported per-call policy changes the action and nothing about detection |

A detector-selection change is applied once, when the owner is initialized
(`initialize({ detection })`, before any other call, in the process that will
enforce); the quickstart previews it with `resolveConfig` and `compareConfigurations`,
which do not need or change that choice. An action policy is per call and needs no
initialization.

## Supported targets

| Step | Node addon | WebAssembly (browser, Node fallback, Workers) | custom WebAssembly | Python | CLI | Rust |
| --- | --- | --- | --- | --- | --- | --- |
| manifest | `artifactManifest()` | `artifactManifest()` | `artifactManifest()` | `artifact_manifest()` | `--print-artifact-manifest` | `ArtifactManifest` |
| resolve, describe, diagnose | yes | yes | yes | unsupported | unsupported | yes |
| `initialize({ detection })` | yes | yes | narrows within the compiled set | unsupported | unsupported | the registry value |
| `compareConfigurations` | yes | yes | yes | unsupported | unsupported | yes (over registries you build) |
| per-call `actionPolicy` | yes | yes | yes | policy only | yes | yes |

Unsupported means the surface reports `detectorSelection: false` or exposes no such
function, and the qualification asserts that instead of skipping it. A request an
artifact cannot meet is rejected (`INVALID_DETECTION_CONFIG`, `PII_SELECTOR_UNAVAILABLE`,
an `unsupported` comparison side), never answered by loading or emulating another
artifact.

## Stable defaults

Without any configuration: every detector the artifact **includes** is enabled (a
detector added by a later release is on; an `include` allowlist is the way to pin a
set); PII is off; the action policy is the built-in default; limits are the
artifact's. An action, `allow` included, never enables or disables a detector.
Arrays and policy documents replace and are never merged across layers. The
[API contract](../reference/api-contract.md#detector-selection-and-effective-configuration)
has the truth table.

## Ownership constraints

`detection` and `pii` belong to the initialization owner and are one-shot per Node
thread or WebAssembly module instance: an equivalent request is idempotent, a different one is
`DETECTION_CONFIG_CONFLICT`, and a rejected request changes nothing. An action
policy, a ruleset and whole-input limits belong to the call. A streaming session
captures the owner's configuration once, when it is created, and accepts neither a
ruleset nor a `detection` key (`INVALID_OPTIONS`). Wrapping the singleton does not isolate
anything; independent configurations use Workers, module instances or processes
([ownership](configuration-ownership.md)).

## Reading an empty result

No findings means the **enabled detectors found nothing in this input**. It does not
say the input is safe, that a detector you did not include or enable would not have
matched, or that a comparison that shows no difference is harmless on other input.
`compareConfigurations` and `compareActionPolicies` report finalized findings only
and never a missed-detection rate or a sensitivity percentage. Keep server-side
enforcement on an unselected `full` artifact; client-side scanning is preventive UX.

## What is qualified

`scripts/qualify-configuration.mjs` (the `configuration` job of
`artifact-qualification.yml`) runs against the **exact installed artifacts**, not a
separate source build. The manifest each artifact reports is read from the loaded
binary, its digest is recomputed outside the artifact, and the SHA-256 of the binary
file that was loaded is recorded beside it.

| Row | Artifact | Status |
| --- | --- | --- |
| `node-addon/full`, `node-addon/common` | the installed `@redact-secret/core` addon | qualified |
| `wasm/full`, `wasm/common` | the installed `@redact-secret/wasm` builds through the package loader (the `pii` builds included) | qualified |
| `wasm/custom` | a generated [custom composition](custom-composition.md): packaged manifest, build report file digests and self-report compared; oracle: `full` narrowed to the same ids | qualified |
| custom Node addon, custom Python wheel | build refused before anything is emitted (`UNSUPPORTED_TARGET`) | asserted unsupported |
| Python wheel, CLI | `detectorSelection: false`, no configuration function, selection flag refused | asserted unsupported |

Journeys, each in its own worker thread (a fresh initialization owner) and each
asserted to emit no secret input byte or hash (raw, case-folded, SHA-256/1/512, MD5, hex, base64,
and 12-character windows):

- build defaults and runtime overrides (`include` of every id, reversed, `exclude: []`)
  give the same enabled set, detection identity and scans;
- detector selection happens before the prefilter and overlap resolution: excluding a
  provider detector hands its span to the contextual one with that detector's type and action,
  and the canonical order does not depend on the order requested;
- unknown, not-included, repeated, conflicting, pasted-secret and non-selectable ids, an
  unavailable PII selector, a reserved built-in id in a ruleset, and a per-call `detection`
  key are rejected with a fixed code, and a rejected request leaves the owner unconfigured;
- optional PII is off by default and on only when selected, and a comparison side the
  artifact cannot provide is `unsupported`;
- allowing a finding changes its action and leaves the detection identity alone, while disabling
  its detector changes the detection identity: the two are distinguishable in `compareConfigurations`;
- sessions: chunk partitions equal the whole-input output (provider token, key and value, JWT,
  multi-line private key, a mixed document), under defaults and under a narrowed set; a refused
  reconfiguration does not reach a live session; a finished session accepts nothing and finishes once;
  a ruleset on a session is `INVALID_OPTIONS`;
- esbuild bundles of the installed standard package and of a generated custom artifact run and report the
  same manifest digest as the unbundled artifact (see [bundling](custom-composition.md#bundling-with-esbuild)).
- the same generated custom WASM executes in Chromium and local Cloudflare `workerd`: selected,
  excluded and benign oracle probes, policy override, incremental partitions and ceiling rejection.
  These checks cover this composition and Chromium, not every subset or browser engine.

The report records the source commit, package integrity, binary digests and manifest digests. It is
evidence for a reviewer, not a published claim.

### Consumers: the adapters

The `redact-secret-adapters` issues
[#217](https://github.com/redact-secret/redact-secret-adapters/issues/217) (declarative `actionPolicy`
forwarding), [#213](https://github.com/redact-secret/redact-secret-adapters/issues/213) (explicit scanner
injection) and [#215](https://github.com/redact-secret/redact-secret-adapters/issues/215) (policy-overlay and
host-output recipes) are closed. Read-only, on 2026-10-07, their `develop` sources (31 TypeScript files) name
only `initialize`, `scan`, `redact`, `scanAndRedact`, `createIncrementalSanitizer` and `status` from
`@redact-secret/core`, with the per-call and per-session `actionPolicy` (object, text or bytes, mutually exclusive with a callback `policy`), `INVALID_ACTION_POLICY`,
and the `@redact-secret/core` `0.1.0-beta.14` floor; none of `compareActionPolicies`, the configuration functions, `detection`, or a
configuration-bound handle (deferred by #1222). The `adapterSurface` journey runs those calls against every
installed row (forms, conflict, rejection with a fixed code, the empty-input option probe, a session) and
is the evidence that the epic left them unchanged. The adapters' own host-output suite stays in that
repository; this repository does not duplicate it.
