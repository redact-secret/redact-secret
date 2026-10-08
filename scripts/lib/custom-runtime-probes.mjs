/** Runtime-neutral checks for one exact generated custom composition. */
export async function qualifyCustomRuntime(api, expected) {
  const checks = [];
  const assertCondition = (condition, message) => {
    if (!condition) throw new Error(message);
  };
  const equal = (actual, wanted, message) =>
    assertCondition(JSON.stringify(actual) === JSON.stringify(wanted), message);
  const shape = (findings) =>
    findings.map(({ detector, type, start, end, action, confidence }) => [
      detector,
      type,
      start,
      end,
      action,
      confidence,
    ]);

  await api.initialize();
  equal(api.artifactManifest(), expected.manifest, "custom runtime manifest differs from the qualified artifact");
  equal(api.describeConfig().detection.enabled, expected.enabled, "custom runtime enabled set differs");
  assertCondition(api.status().profile === "custom", "custom runtime profile differs");
  checks.push("exact manifest and enabled set");

  for (const [name, input] of Object.entries(expected.probes)) {
    equal(shape(api.scan(input)), expected.scans[name], "custom runtime differs from the narrowed full oracle");
  }
  assertCondition(expected.scans.provider.length > 0, "custom runtime positive control is vacuous");
  assertCondition(expected.scans.benign.length === 0, "custom runtime negative control is invalid");
  checks.push("selected, excluded and benign oracle probes");

  const input = expected.probes.provider;
  const whole = api.scanAndRedact(input);
  assertCondition(whole.text !== input, "custom runtime left the positive control unchanged");
  const actionPolicy = {
    actionPolicyRevision: 1,
    base: "default",
    rules: [{ id: "custom-runtime-allow", match: { detector: expected.enabled }, action: "allow" }],
  };
  const allowed = api.scanAndRedact(input, { actionPolicy });
  assertCondition(allowed.text === input, "custom runtime ignored the declarative policy override");
  assertCondition(allowed.findings.length === whole.findings.length, "custom runtime policy changed detection");
  assertCondition(
    allowed.findings.every((finding) => finding.action === "allow"),
    "custom runtime policy action differs",
  );
  checks.push("redaction and declarative policy override");

  for (let split = 0; split <= input.length; split += 1) {
    const session = api.createIncrementalSanitizer({ limits: expected.limits });
    const text =
      session.append(input.slice(0, split)).text + session.append(input.slice(split)).text + session.finalize().text;
    assertCondition(text === whole.text, "custom runtime incremental partition differs from whole input");
  }
  checks.push("incremental partition equivalence");

  const resolution = api.resolveConfig({ detection: { include: [expected.excluded] } });
  assertCondition(
    resolution.ok === false && resolution.diagnostics.items.some((item) => item.code === "DETECTOR_NOT_INCLUDED"),
    "custom runtime did not refuse an excluded detector",
  );
  let code;
  try {
    await api.initialize({ detection: { include: [expected.excluded] } });
  } catch (error) {
    code = error?.code;
  }
  assertCondition(code === "INVALID_DETECTION_CONFIG", "custom runtime did not enforce its capability ceiling");
  checks.push("excluded detector capability ceiling");

  qualifyClosedVocabulary(api);
  checks.push("v1 open and v2 closed policy vocabulary preview");
  return { checks, partitions: input.length + 1 };
}

/** A pure preview; closure validates names without installing an owner policy. */
export function qualifyClosedVocabulary(api) {
  const assertCondition = (condition, message) => {
    if (!condition) throw new Error(message);
  };
  const configuration = api.status().configuration;
  const unknownType = "synthetic_unknown_type";
  const unknownDetector = "synthetic-unknown-detector";
  const unknownPolicy = {
    actionPolicyRevision: 1,
    base: "default",
    rules: [{ id: "custom-runtime-unknown", match: { type: [unknownType] }, action: "warn" }],
  };
  const has = (resolution, code, severity) =>
    resolution.diagnostics.items.some((item) => item.code === code && item.severity === severity);
  const open = api.resolveConfig({ schema: "runtime-config/v1", actionPolicy: unknownPolicy });
  assertCondition(
    open.ok && has(open, "ACTION_POLICY_UNKNOWN_TYPE", "warning"),
    "custom runtime v1 vocabulary changed",
  );
  const strict = api.resolveConfig({ schema: "runtime-config/v2", closedTypes: [], actionPolicy: unknownPolicy });
  assertCondition(
    !strict.ok && has(strict, "ACTION_POLICY_UNKNOWN_TYPE", "error"),
    "custom runtime ignored the v2 closed type vocabulary",
  );
  const declared = api.resolveConfig({
    schema: "runtime-config/v2",
    closedTypes: [unknownType],
    actionPolicy: unknownPolicy,
  });
  assertCondition(
    declared.ok && !declared.diagnostics.items.some((item) => item.severity === "error"),
    "custom runtime refused a declared type",
  );
  const strictDetector = api.resolveConfig({
    schema: "runtime-config/v2",
    closedDetectors: [],
    actionPolicy: {
      ...unknownPolicy,
      rules: [{ id: "custom-runtime-unknown", match: { detector: [unknownDetector] }, action: "warn" }],
    },
  });
  assertCondition(
    !strictDetector.ok && has(strictDetector, "ACTION_POLICY_UNKNOWN_DETECTOR", "error"),
    "custom runtime ignored the v2 closed detector vocabulary",
  );
  for (const schema of [undefined, "runtime-config/v1"]) {
    const rejected = api.resolveConfig({ ...(schema ? { schema } : {}), closedTypes: [] });
    assertCondition(
      !rejected.ok && has(rejected, "UNKNOWN_FIELD", "error"),
      "closed vocabulary leaked into the v1 contract",
    );
  }
  for (const closedTypes of ["synthetic", [42]]) {
    const rejected = api.resolveConfig({ schema: "runtime-config/v2", closedTypes });
    assertCondition(
      !rejected.ok && has(rejected, "WRONG_TYPE", "error"),
      "closed vocabulary accepted a malformed list",
    );
  }
  const comparison = api.compareConfigurations("ordinary synthetic text", {
    actionPolicy: unknownPolicy,
    configs: [
      { schema: "runtime-config/v2", closedTypes: [] },
      { schema: "runtime-config/v2", closedTypes: [unknownType] },
    ],
  });
  assertCondition(
    comparison.results[0].status === "error" && comparison.results[1].status === "scanned",
    "configuration comparison ignored a side's closed vocabulary",
  );
  assertCondition(api.status().configuration === configuration, "vocabulary preview changed the owner");
  return { cases: 9, ownerUnchanged: true, comparison: true };
}
