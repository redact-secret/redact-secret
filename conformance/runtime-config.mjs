// The shared truth table for `resolveConfig` (issue #1251), as JavaScript
// runs it. The cases live in `conformance/fixtures/runtime-config-v1.json`
// and are run by the Rust core against its own resolver and, here, by every
// JavaScript surface against the resolver of the artifact it loaded. No
// surface keeps a copy of the table: this module only turns a fixture case
// into the arguments a binding takes and checks what it reported.

import { readFileSync } from "node:fs";

const FIXTURE_URL = new URL("./fixtures/runtime-config-v1.json", import.meta.url);

/** The parsed fixture. */
export function loadRuntimeConfigFixture() {
  return JSON.parse(readFileSync(FIXTURE_URL, "utf8"));
}

/** The cases that apply to the `full` or `common` entry point. */
export function casesFor(fixture, profile) {
  return fixture.cases.filter((fixtureCase) => fixtureCase.profiles.includes(profile));
}

/**
 * The arguments of a binding's `resolveConfig`: the compact JSON text of the
 * data members, the exact `ruleset` and `actionPolicy` bytes, whether a
 * callback is in force, and whether to disclose the ruleset identity.
 */
export function bindingArguments(fixtureCase) {
  const encode = (text) => (text === undefined ? undefined : new TextEncoder().encode(text));
  let config;
  if (fixtureCase.configText !== undefined) config = fixtureCase.configText;
  else if (fixtureCase.config !== undefined) config = JSON.stringify(fixtureCase.config);
  const policy =
    typeof fixtureCase.actionPolicy === "string" || fixtureCase.actionPolicy === undefined
      ? fixtureCase.actionPolicy
      : JSON.stringify(fixtureCase.actionPolicy);
  return {
    config,
    ruleset: encode(fixtureCase.ruleset),
    actionPolicy: encode(policy),
    callback: fixtureCase.callback === true,
    disclose: fixtureCase.discloseRulesetIdentity === true,
  };
}

/**
 * The runtime-level inputs (`resolveConfig(config, options)`) of a fixture
 * case, or `undefined` for a `rawOnly` case: text no JavaScript object can
 * produce, which only the binding-level run executes.
 */
export function runtimeArguments(fixtureCase) {
  if (fixtureCase.rawOnly === true) return undefined;
  let config;
  if (fixtureCase.config !== undefined) config = { ...fixtureCase.config };
  else if (fixtureCase.configText !== undefined) config = JSON.parse(fixtureCase.configText);
  if (fixtureCase.ruleset !== undefined || fixtureCase.actionPolicy !== undefined) {
    config = { ...(config ?? {}) };
    if (fixtureCase.ruleset !== undefined) config.ruleset = fixtureCase.ruleset;
    if (fixtureCase.actionPolicy !== undefined) config.actionPolicy = fixtureCase.actionPolicy;
  }
  const options = {};
  if (fixtureCase.callback === true) options.policy = { evaluate: () => "redact" };
  if (fixtureCase.discloseRulesetIdentity === true) options.discloseRulesetIdentity = true;
  return { config, options: Object.keys(options).length === 0 ? undefined : options };
}

/**
 * Checks one resolution against one case. `check` is an `assert`-style
 * equality function `(actual, expected, message) => void`.
 */
export function checkCase(fixtureCase, profile, resolution, manifest, check) {
  const at = `${fixtureCase.name} [${profile}]`;
  const expect = fixtureCase.expect;
  check(resolution.schema, "config-resolution/v1", `${at}: schema`);
  check(resolution.ok, expect.ok, `${at}: ok`);
  check(
    resolution.diagnostics.items.map((item) => item.code),
    expect.codes,
    `${at}: codes`,
  );
  if (expect.paths !== undefined) {
    check(
      resolution.diagnostics.items.map((item) => item.path),
      expect.paths,
      `${at}: paths`,
    );
  }
  const severities = resolution.diagnostics.items.map((item) => item.severity);
  const rank = { error: 0, warning: 1, info: 2 };
  check(
    severities,
    [...severities].sort((left, right) => rank[left] - rank[right]),
    `${at}: errors first`,
  );
  if (!expect.ok) {
    check(resolution.snapshot, null, `${at}: no snapshot`);
    return;
  }
  const snapshot = resolution.snapshot;
  check(snapshot.schema, "config-snapshot/v1", `${at}: snapshot schema`);
  check(snapshot.artifact.manifestDigest, manifest.digest, `${at}: bound to the manifest`);
  const detection = snapshot.detection;
  if (expect.mode !== undefined) check(detection.mode, expect.mode, `${at}: mode`);
  if (expect.enabledIds !== undefined) check(detection.enabled, expect.enabledIds, `${at}: enabled`);
  if (expect.enabledCount !== undefined) check(detection.enabledCount, expect.enabledCount, `${at}: enabledCount`);
  if (expect.disabledCount !== undefined) check(detection.disabled.length, expect.disabledCount, `${at}: disabledCount`);
  if (expect.disabledIds !== undefined) check(detection.disabled, expect.disabledIds, `${at}: disabled`);
  check(
    detection.compiledCount,
    detection.enabledCount + detection.disabled.length,
    `${at}: compiled is enabled plus disabled`,
  );
  check(detection.unavailable, manifest.notIncluded, `${at}: unavailable is what the artifact lacks`);
  if (expect.inert !== undefined) check(snapshot.effects.inert, expect.inert, `${at}: inert`);
  if (expect.policySource !== undefined) check(snapshot.actionPolicy.source, expect.policySource, `${at}: policy source`);
  if (expect.policyDigest !== undefined) check(snapshot.actionPolicy.digest, expect.policyDigest, `${at}: policy digest`);
  if (expect.policyRuleCount !== undefined) {
    check(snapshot.actionPolicy.ruleCount, expect.policyRuleCount, `${at}: rule count`);
  }
  if (expect.policyExplainable !== undefined) {
    check(snapshot.actionPolicy.explainable, expect.policyExplainable, `${at}: explainable`);
  }
  if (expect.limits !== undefined) check(snapshot.limits, expect.limits, `${at}: limits`);
  if (expect.origins !== undefined) {
    for (const [key, value] of Object.entries(expect.origins)) {
      check(snapshot.origins[key], value, `${at}: origin ${key}`);
    }
  }
  if (expect.piiSelectors !== undefined) check(snapshot.pii.selectors, expect.piiSelectors, `${at}: pii selectors`);
  const ruleset = snapshot.ruleset;
  if (expect.rulesetPresent !== undefined) check(ruleset.present, expect.rulesetPresent, `${at}: ruleset present`);
  if (expect.rulesetDisclosed !== undefined) {
    check(ruleset.disclosed, expect.rulesetDisclosed, `${at}: ruleset disclosed`);
    if (!expect.rulesetDisclosed) {
      check(ruleset.detectorIds, null, `${at}: ruleset ids withheld`);
      check(ruleset.digest, null, `${at}: ruleset digest withheld`);
    }
  }
  if (expect.rulesetDetectorCount !== undefined) {
    check(ruleset.detectorCount, expect.rulesetDetectorCount, `${at}: ruleset detector count`);
  }
  if (expect.rulesetDetectorIds !== undefined) {
    check(ruleset.detectorIds, expect.rulesetDetectorIds, `${at}: ruleset ids`);
  }
  if (expect.rulesetDigest !== undefined) check(ruleset.digest, expect.rulesetDigest, `${at}: ruleset digest`);
}
