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
