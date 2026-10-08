/**
 * The configuration journeys of issue #1255 (child of epic #1246), run against
 * an installed or generated artifact by `scripts/qualify-configuration.mjs`.
 *
 * Each journey is a function of one *loaded artifact* (`api`: the package entry
 * point, the profile runtime over an installed WebAssembly build, or a generated
 * custom wrapper). It runs in its own worker thread because the initialization
 * owner (registry, PII activation, detector selection) is one-shot per thread, so
 * every journey starts from an owner nobody has configured. A journey returns
 * plain data; the driver compares what several journeys returned (the same
 * behavior reached through build defaults and through runtime overrides), and
 * `assertNoSecret` is applied to everything a journey returns or caught before it
 * leaves the worker.
 *
 * Every input here is synthetic and revoked-shaped; none is a real credential.
 * Nothing in a result holds an input: findings are ranges, snapshots are ids and
 * digests, and a caught error is its fixed code and message.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { qualifyClosedVocabulary } from "./custom-runtime-probes.mjs";

/** Obviously synthetic values, all taken from the repository's own corpora. */
export const SYNTHETIC = Object.freeze({
  github: "ghp_SYNTHETICREVOKED00000000000000000000",
  jwt: "eyJTWU5USEVUSUNfSEVBREVS.eyJTWU5USEVUSUNfUEFZTE9BRA.SYNTHETIC_REVOKED_SIGNATURE",
  awsAccessKey: "AKIASYNTHETICEXAMPLE",
  contextValue: "SYNTHETIC_REVOKED_CONTEXT_VALUE",
  email: "fixture876-q7m9@x4z8v2n6.synthetic",
  rulesetPrefix: "ACME_SYNTHETIC_",
  rulesetValue: "ACME_SYNTHETIC_REVOKED-00000000000000",
  pastedAsIdentifier: "ghp_SYNTHETICPASTEDASID0000000000000000",
});

/** The probes every journey scans. `null` means the probe must stay unchanged. */
export const PROBES = Object.freeze({
  provider: `API_KEY=${SYNTHETIC.github}`,
  structural: `token ${SYNTHETIC.jwt}`,
  awsAccessKey: `AWS_ACCESS_KEY_ID=${SYNTHETIC.awsAccessKey}`,
  contextual: `password: ${SYNTHETIC.contextValue}`,
  benign: "release notes: nothing to see here",
});

const PEM = [
  "-----BEGIN PRIVATE KEY-----",
  "U1lOVEhFVElDX1JFVk9LRURfQ09ORk9STUFOQ0U=",
  "-----END PRIVATE KEY-----",
  "",
].join("\n");

export const EMAIL_INPUT = `email: ${SYNTHETIC.email}`;
export const PII_ALL = Object.freeze(["pii:family:global:email"]);

export const LIMITS = Object.freeze({
  maxInputCodeUnits: 65_536,
  maxBufferedCodeUnits: 16_512,
  maxTokenCodeUnits: 8_192,
  maxMultilineCodeUnits: 16_384,
});

const RULESET = (detector, prefix) =>
  [
    "ruleset-revision: 1",
    `detector: ${detector}`,
    "specificity: contextual",
    `prefix: "${prefix}"`,
    "alphabet: alnum-dash",
    "run: at-least 20",
    "validator: none",
    "",
  ].join("\n");

const ALLOW_POLICY = (detector) =>
  JSON.stringify({
    actionPolicyRevision: 1,
    base: "default",
    rules: [{ id: "allow-one-detector", match: { detector: [detector] }, action: "allow" }],
  });

// ---------------------------------------------------------------------------
// Secret-freedom: no input byte and no hash of one in anything a journey emits.
// ---------------------------------------------------------------------------

/** Every value a journey must never emit, with the forms a leak could take. */
export function forbiddenForms(secrets = Object.values(SYNTHETIC)) {
  const forms = new Map();
  const add = (label, value) => {
    if (typeof value === "string" && value.length >= 8) forms.set(value, label);
  };
  for (const secret of secrets) {
    const bytes = Buffer.from(secret, "utf8");
    add("raw", secret);
    add("lowercase", secret.toLowerCase());
    for (const algorithm of ["sha256", "sha1", "md5", "sha512"]) {
      const digest = createHash(algorithm).update(bytes);
      add(algorithm, digest.copy().digest("hex"));
      add(`${algorithm}-base64`, digest.digest("base64"));
    }
    add("hex", bytes.toString("hex"));
    add("base64", bytes.toString("base64").replace(/=+$/, ""));
    add("base64url", bytes.toString("base64url"));
    // A long enough window is as good as the whole value to a reader.
    if (secret.length >= 16) {
      for (let at = 0; at + 12 <= secret.length; at += 4) add("window", secret.slice(at, at + 12));
    }
  }
  return forms;
}

/** Throws, naming only the label and the form, if `value` serializes any forbidden form. */
export function assertNoSecret(label, value, forms = forbiddenForms()) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  for (const [form, kind] of forms) {
    assert.ok(!text.includes(form), `${label}: output carries a secret (${kind} form)`);
  }
  return text.length;
}

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

/** The canonical-JSON digest of a manifest, recomputed outside the artifact. */
export function canonicalDigest(document) {
  const canonical = (value) => {
    if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
    if (value !== null && typeof value === "object") {
      return `{${Object.keys(value)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
        .join(",")}}`;
    }
    return JSON.stringify(value);
  };
  const { digest: _digest, ...body } = document;
  return `sha256:${createHash("sha256").update(canonical(body), "utf8").digest("hex")}`;
}

const shape = (findings) =>
  findings.map((finding) => [
    finding.detector,
    finding.type,
    finding.start,
    finding.end,
    finding.action,
    finding.confidence,
  ]);

async function caught(thunk) {
  try {
    await thunk();
  } catch (error) {
    return { code: error?.code ?? null, message: String(error?.message ?? "") };
  }
  return { code: null, message: "" };
}

function scanProbes(api) {
  return Object.fromEntries(Object.entries(PROBES).map(([name, input]) => [name, shape(api.scan(input))]));
}

function sessionText(api, input, size, options = {}) {
  const session = api.createIncrementalSanitizer({ limits: LIMITS, ...options });
  let text = "";
  let findings = 0;
  for (let at = 0; at < input.length; ) {
    let end = Math.min(input.length, at + size);
    // Never split a surrogate pair: a lone surrogate is not valid input.
    if (end < input.length && input.charCodeAt(end - 1) >= 0xd800 && input.charCodeAt(end - 1) <= 0xdbff) end += 1;
    const step = session.append(input.slice(at, end));
    text += step.text;
    findings += step.findings.length;
    at = end;
  }
  const last = session.finalize();
  return { text: text + last.text, findings: findings + last.findings.length };
}

/** The detector a journey perturbs, and a probe that carries it. */
function target(known) {
  const included = new Set(known.included);
  if (included.has("github-token")) return { id: "github-token", probe: PROBES.provider, secret: SYNTHETIC.github };
  return { id: "jwt", probe: PROBES.structural, secret: SYNTHETIC.jwt };
}

// ---------------------------------------------------------------------------
// Journeys. `ctx` is `{ api, row, known, init }`.
// ---------------------------------------------------------------------------

export const JOURNEYS = {
  /** The manifest, the snapshot and the status agree, before any input is scanned. */
  async manifest({ api, row }) {
    await api.initialize();
    const manifest = api.artifactManifest();
    assert.equal(manifest.schema, "artifact-manifest/v1");
    assert.equal(
      manifest.digest,
      canonicalDigest(manifest),
      "the manifest digest is not the digest of its own content",
    );
    assert.equal(manifest.artifact.variant, row.profile);
    assert.equal(manifest.artifact.kind, row.manifestKind);
    assert.equal(manifest.capabilities.detectorSelection, true);
    const ids = manifest.detectors.map((detector) => detector.id);
    const snapshot = api.describeConfig();
    assert.equal(snapshot.artifact.manifestDigest, manifest.digest, "the snapshot names a different artifact");
    assert.deepEqual(snapshot.detection.enabled, ids, "the defaults enable exactly the included detectors");
    assert.equal(snapshot.detection.compiledCount, ids.length);
    assert.deepEqual(snapshot.detection.unavailable, manifest.notIncluded);
    assert.equal(api.status().configuration, snapshot.digest);
    assert.equal(api.status().profile, row.profile);
    if (row.profile === "custom") assert.equal(snapshot.artifact.compositionId, manifest.composition.id);
    return {
      version: manifest.version,
      artifactKind: manifest.artifact.kind,
      manifestDigest: manifest.digest,
      snapshotDigest: snapshot.digest,
      piiLinked: manifest.pii.available,
      loaded: api.artifact === undefined ? null : api.artifact(),
      included: ids,
      notIncluded: snapshot.detection.unavailable,
      manifestJson: JSON.stringify(manifest),
      compositionId: snapshot.artifact.compositionId ?? null,
    };
  },

  /** What one initialization (defaults or an override) fixes: snapshot facts and scan results. */
  async effective({ api, init }) {
    await api.initialize(init);
    const snapshot = api.describeConfig();
    return {
      enabled: snapshot.detection.enabled,
      disabled: snapshot.detection.disabled,
      unavailableCount: snapshot.detection.unavailable.length,
      detectionDigest: snapshot.detectionDigest,
      origin: snapshot.origins.detection,
      scans: scanProbes(api),
      status: api.status().configuration === snapshot.digest,
    };
  },

  /** Selection happens before the prefilter and overlap resolution, so a removed provider changes the winner. */
  async overlap({ api, known }) {
    const { id, probe, secret } = target(known);
    await api.initialize({ detection: { exclude: [id] } });
    const snapshot = api.describeConfig();
    assert.ok(snapshot.detection.disabled.includes(id));
    assert.ok(!snapshot.detection.enabled.includes(id));
    const findings = api.scan(probe);
    const out = api.scanAndRedact(probe);
    return {
      id,
      disabled: snapshot.detection.disabled,
      findings: shape(findings),
      detectorsReported: [...new Set(findings.map((finding) => finding.detector))],
      textKeepsSecret: out.text.includes(secret),
      overlapOutcomesMayChange: snapshot.effects.overlapOutcomesMayChange,
    };
  },

  /** Rejections: nothing is ignored, nothing falls back, and a rejected request changes nothing. */
  async rejections({ api, row, known }) {
    const absent = known.notIncluded[0];
    const attempts = {};
    attempts.unknownId = await caught(() => api.initialize({ detection: { include: ["no-such-detector"] } }));
    if (absent !== undefined) {
      attempts.notIncluded = await caught(() => api.initialize({ detection: { include: [absent] } }));
    }
    attempts.pastedAsIdentifier = await caught(() =>
      api.initialize({ detection: { include: [SYNTHETIC.pastedAsIdentifier] } }),
    );
    attempts.both = await caught(() => api.initialize({ detection: { include: ["jwt"], exclude: ["jwt"] } }));
    attempts.nothingEnabled = await caught(() => api.initialize({ detection: { include: [] } }));
    attempts.piiSelector = await caught(() =>
      api.initialize({ pii: row.piiAvailable ? ["pii:no-such-family"] : [...PII_ALL] }),
    );
    // A rejected request changed nothing: the owner is still unconfigured.
    const afterRejections = api.status().initialized;
    await api.initialize();
    const enabled = api.describeConfig().detection.enabled;

    const resolved = {};
    const resolveOf = (name, config) => {
      const result = api.resolveConfig(config);
      resolved[name] = {
        ok: result.ok,
        snapshot: result.snapshot === null,
        codes: result.diagnostics.items.map((item) => [item.code, item.severity, item.path]),
      };
    };
    resolveOf("unknownId", { detection: { include: ["no-such-detector"] } });
    if (absent !== undefined) resolveOf("notIncluded", { detection: { include: [absent] } });
    resolveOf("pastedAsIdentifier", { detection: { include: [SYNTHETIC.pastedAsIdentifier] } });
    resolveOf("both", { detection: { include: ["jwt"], exclude: ["jwt"] } });
    resolveOf("unknownMember", { detection: {}, [SYNTHETIC.pastedAsIdentifier]: 1 });
    resolveOf("nothingEnabled", { detection: { include: [] } });
    resolveOf("pii", { pii: row.piiAvailable ? ["pii:no-such-family"] : [...PII_ALL] });
    resolveOf("reservedRulesetId", { ruleset: RULESET("github-token", SYNTHETIC.rulesetPrefix) });
    resolveOf("rulesetIdNotSelectable", {
      ruleset: RULESET("acme-internal", SYNTHETIC.rulesetPrefix),
      detection: { include: ["acme-internal"] },
    });
    attempts.detectionOnScan = await caught(() => api.scan(PROBES.benign, { detection: { include: ["jwt"] } }));
    attempts.detectionOnSession = await caught(() =>
      api.createIncrementalSanitizer({ limits: LIMITS, detection: { include: ["jwt"] } }),
    );
    attempts.callbackAndPolicy = await caught(() =>
      api.scan(PROBES.benign, { actionPolicy: ALLOW_POLICY("jwt"), policy: { evaluate: () => "warn" } }),
    );
    attempts.unknownDetectionMember = await caught(() => api.initialize({ detection: { allow: ["jwt"] } }));
    return { absent: absent ?? null, attempts, afterRejections, enabled, resolved };
  },

  /** The initialization owner is one-shot: equivalent calls are idempotent, a different one conflicts. */
  async ownership({ api, known }) {
    const { id } = target(known);
    const others = known.included.filter((other) => other !== id);
    const narrowed = { detection: { include: [...others].reverse() } };
    await api.initialize(narrowed);
    const first = api.describeConfig();
    await api.initialize({ detection: { exclude: [id] } }); // the same resolved set, spelled differently
    const equivalent = api.describeConfig().digest === first.digest;
    const plain = await caught(() => api.initialize());
    const different = await caught(() => api.initialize({ detection: { include: [id] } }));
    const after = api.describeConfig();
    return {
      id,
      canonicalOrder:
        JSON.stringify(first.detection.enabled) === JSON.stringify(known.included.filter((x) => x !== id)),
      equivalent,
      plain,
      different,
      unchanged: after.digest === first.digest,
    };
  },

  /** A session captures the owner's configuration at creation and keeps it. */
  async sessions({ api, known, init }) {
    await api.initialize(init);
    const probes = {
      provider: PROBES.provider,
      keyThenValue: PROBES.contextual,
      structural: PROBES.structural,
      multiline: `before\n${PEM}after`,
      mixed: `${PROBES.provider}\n${PROBES.contextual}\n${PROBES.structural}\n${PEM}tail`,
    };
    const early = api.createIncrementalSanitizer({ limits: LIMITS });
    // Reconfiguring after a session exists is refused and does not reach it.
    const reconfigure = await caught(() => api.initialize({ detection: { include: ["jwt"] } }));
    const late = api.createIncrementalSanitizer({ limits: LIMITS });
    const result = { partitions: {}, reconfigure };
    for (const [name, input] of Object.entries(probes)) {
      const whole = api.scanAndRedact(input);
      const sizes = [1, 2, 5, 13, 64, input.length];
      result.partitions[name] = sizes.map((size) => {
        const session = sessionText(api, input, size);
        return {
          size,
          equalsWhole: session.text === whole.text && session.findings === whole.findings.length,
          findings: session.findings,
        };
      });
    }
    // The two sessions made around the refused reconfiguration behave alike.
    const feed = (session) => {
      let text = "";
      for (const part of ["x ", PROBES.provider.slice(0, 20), PROBES.provider.slice(20), "\n"]) {
        text += session.append(part).text;
      }
      return text + session.finalize().text;
    };
    result.earlyEqualsLate = feed(early) === feed(late);

    // Terminal states: a finished session accepts nothing and finishes once.
    const done = api.createIncrementalSanitizer({ limits: LIMITS });
    done.append("a");
    done.finalize();
    result.appendAfterFinalize = await caught(() => done.append("b"));
    result.finalizeTwice = await caught(() => done.finalize());
    // An incremental session does not take a ruleset; it is rejected, not ignored.
    result.rulesetOnSession = await caught(() =>
      api.createIncrementalSanitizer({ limits: LIMITS, ruleset: RULESET("acme-internal", SYNTHETIC.rulesetPrefix) }),
    );
    // A detector the configuration excludes cannot be brought back through a session option.
    result.detectionOnSession = await caught(() =>
      api.createIncrementalSanitizer({ limits: LIMITS, detection: { include: known.included } }),
    );
    const { probe, secret } = target(known);
    result.targetRedacted = !api.scanAndRedact(probe).text.includes(secret);
    result.sessionTargetRedacted = !sessionText(api, probe, 3).text.includes(secret);
    return result;
  },

  /** Allowing a finding and disabling its detector are different changes, and the evidence says which. */
  async comparison({ api, row, known }) {
    await api.initialize();
    const { id, probe } = target(known);
    const policyOnly = api.compareConfigurations(probe, { configs: [{}, { actionPolicy: ALLOW_POLICY(id) }] });
    const configChange = api.compareConfigurations(probe, { configs: [{}, { detection: { exclude: [id] } }] });
    const pii = api.compareConfigurations(EMAIL_INPUT, { configs: [{}, { pii: [...PII_ALL] }] });
    const compact = (comparison) => ({
      mode: comparison.mode,
      enforced: comparison.enforced,
      statuses: comparison.results.map((result) => [result.status, result.failure ?? null]),
      counts: comparison.results.map((result) => result.counts ?? null),
      detectionDigests: comparison.configs.map((config) => config.detectionDigest),
      digests: comparison.configs.map((config) => config.digest),
      entries: comparison.differences.map(
        (difference) =>
          difference?.entries.map((entry) => [entry.kind, entry.correspondence ?? null, entry.changes ?? null]) ?? null,
      ),
    });
    // The same two controls through the single-pass policy comparison: detection is one identity.
    const actionOnly = api.compareActionPolicies(probe, {
      policies: [{ kind: "default" }, { kind: "action-policy", actionPolicy: ALLOW_POLICY(id) }],
    });
    return {
      id,
      policyOnly: compact(policyOnly),
      configChange: compact(configChange),
      pii: compact(pii),
      piiExpected: row.piiInProcess,
      actionComparison: {
        detection: actionOnly.detection,
        changedCount: actionOnly.changedCount,
        findingCount: actionOnly.findingCount,
      },
    };
  },

  /** Optional PII is off unless asked for, and a request the artifact cannot meet is not satisfied by another. */
  async pii({ api, row, init }) {
    await api.initialize(init);
    const snapshot = api.describeConfig();
    return {
      requested: init?.pii ?? [],
      available: snapshot.pii.available,
      families: snapshot.pii.families,
      activation: api.status().activation,
      detectionDigest: snapshot.detectionDigest,
      email: shape(api.scan(EMAIL_INPUT)),
      credentialsStillFound: shape(api.scan(PROBES.provider)).length > 0,
      profile: row.profile,
    };
  },

  /** Diagnostics: a typo, a shadowed rule and an excluded target are named by code and path only. */
  async diagnostics({ api, known }) {
    await api.initialize();
    const { id } = target(known);
    const policy = {
      actionPolicyRevision: 1,
      base: "default",
      rules: [
        { id: "first", match: { detector: [id] }, action: "warn" },
        { id: "second", match: { detector: [id] }, action: "block" },
        { id: "typo", match: { detector: [`${id}x`] }, action: "warn" },
      ],
    };
    const pastedPolicy = {
      actionPolicyRevision: 1,
      base: "default",
      rules: [{ id: "pasted", match: { detector: [SYNTHETIC.pastedAsIdentifier] }, action: "warn" }],
    };
    const typo = api.resolveConfig({ actionPolicy: policy });
    const pasted = api.resolveConfig({ actionPolicy: pastedPolicy });
    const disabled = api.resolveConfig({ detection: { exclude: [id] }, actionPolicy: policy });
    const callbackAndPolicy = api.resolveConfig({ actionPolicy: policy }, { policy: { evaluate: () => "warn" } });
    const callback = api.resolveConfig({}, { policy: { evaluate: () => "warn" } });
    const codes = (resolution) =>
      resolution.diagnostics.items.map((item) => [item.code, item.severity, item.path, item.id ?? null]);
    return {
      typo: { ok: typo.ok, codes: codes(typo) },
      pasted: { ok: pasted.ok, snapshot: pasted.snapshot === null, codes: codes(pasted) },
      disabled: { ok: disabled.ok, codes: codes(disabled) },
      callbackAndPolicy: {
        ok: callbackAndPolicy.ok,
        snapshot: callbackAndPolicy.snapshot === null,
        codes: codes(callbackAndPolicy),
      },
      callback: {
        ok: callback.ok,
        source: callback.snapshot?.actionPolicy.source,
        explainable: callback.snapshot?.actionPolicy.explainable,
      },
      truncated: typo.diagnostics.truncated,
    };
  },

  /** Rulesets: per call, never selectable by id, and never a built-in id. */
  async rulesets({ api }) {
    await api.initialize();
    const ruleset = RULESET("acme-internal", SYNTHETIC.rulesetPrefix);
    const input = `value ${SYNTHETIC.rulesetValue}`;
    const withRuleset = api.scan(input, { ruleset });
    const without = api.scan(input);
    const reserved = await caught(() => api.scan(input, { ruleset: RULESET("github-token", SYNTHETIC.rulesetPrefix) }));
    const resolution = api.resolveConfig({ ruleset });
    const disclosed = api.resolveConfig({ ruleset }, { discloseRulesetIdentity: true });
    return {
      withRuleset: shape(withRuleset),
      without: shape(without),
      reserved,
      snapshotRuleset: resolution.snapshot.ruleset,
      disclosedIds: disclosed.snapshot.ruleset.detectorIds,
      customDetectors: resolution.snapshot.detection.customDetectors,
    };
  },

  /** What the adapters (redact-secret-adapters #217/#213/#215) depend on is unchanged by the epic. */
  async closedVocabulary({ api }) {
    await api.initialize();
    return qualifyClosedVocabulary(api);
  },

  async adapterSurface({ api, known }) {
    await api.initialize();
    const names = ["initialize", "scan", "scanAndRedact", "redact", "createIncrementalSanitizer", "status"];
    const present = Object.fromEntries(names.map((name) => [name, typeof api[name] === "function"]));
    const { id, probe, secret } = target(known);
    const policyText = JSON.stringify({
      actionPolicyRevision: 1,
      base: "default",
      rules: [{ id: "warn-one", match: { detector: [id] }, action: "warn" }],
    });
    const asText = api.scanAndRedact(probe, { actionPolicy: policyText });
    const asBytes = api.scanAndRedact(probe, { actionPolicy: new TextEncoder().encode(policyText) });
    const asObject = api.scanAndRedact(probe, { actionPolicy: JSON.parse(policyText) });
    const emptyProbe = await caught(() => api.scanAndRedact("", { actionPolicy: policyText }));
    const both = await caught(() =>
      api.scanAndRedact(probe, { actionPolicy: policyText, policy: { evaluate: () => "warn" } }),
    );
    const rejected = await caught(() =>
      api.scanAndRedact(probe, { actionPolicy: `{"actionPolicyRevision":2,"x":"${secret}"}` }),
    );
    const session = api.createIncrementalSanitizer({ limits: LIMITS, actionPolicy: policyText });
    session.append(probe);
    const sessionResult = session.finalize();
    return {
      present,
      actionPolicyForms: [asText, asBytes, asObject].map((out) => [out.text.includes(secret), shape(out.findings)]),
      emptyProbe,
      both,
      rejected,
      sessionKeepsWarned: sessionResult.text.includes(secret) || sessionResult.findings.length > 0,
      defaultShape: shape(api.scan(PROBES.provider)),
    };
  },
};

export const JOURNEY_NAMES = Object.freeze(Object.keys(JOURNEYS));
