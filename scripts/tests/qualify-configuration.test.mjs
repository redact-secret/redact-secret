import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";
import {
  assertNoSecret,
  canonicalDigest,
  forbiddenForms,
  JOURNEY_NAMES,
  JOURNEYS,
  SYNTHETIC,
} from "../lib/configuration-journeys.mjs";
import { copyRedactWasm } from "../lib/esbuild-redact-wasm.mjs";
import {
  checkAdapterSurface,
  checkComparison,
  checkEffectiveEquivalence,
  checkOwnership,
  checkPii,
  checkRejections,
  checkSelectionBeforeOverlap,
  checkSessions,
  QUICKSTART,
} from "../qualify-configuration.mjs";

const repo = (path) => fileURLToPath(new URL(`../../${path}`, import.meta.url));
const sha256 = (text, encoding = "hex") => createHash("sha256").update(text).digest(encoding);

test("no secret input byte or hash may leave a journey, in any form a reader could recognise", () => {
  const secret = SYNTHETIC.github;
  const leaks = {
    raw: `context ${secret}`,
    lowercase: secret.toLowerCase(),
    sha256: sha256(secret),
    "sha256-base64": sha256(secret, "base64"),
    base64: Buffer.from(secret).toString("base64").replace(/=+$/, ""),
    hex: Buffer.from(secret).toString("hex"),
    window: `…${secret.slice(8, 22)}…`,
  };
  for (const [name, text] of Object.entries(leaks)) {
    assert.throws(() => assertNoSecret(name, { nested: [text] }), /output carries a secret/, name);
  }
  // The assertion names the label and the form, never the value.
  assert.throws(
    () => assertNoSecret("label", leaks.raw),
    (error) => !error.message.includes(secret) && error.message.includes("label"),
  );
  const safe = {
    enabled: ["github-token"],
    digest: `sha256:${sha256("not a secret")}`,
    range: [8, 48],
    text: "<SECRET_1>",
  };
  assert.ok(assertNoSecret("safe", safe) > 0);
  assert.ok(forbiddenForms().size > 100);
});

test("the manifest digest is recomputed outside the artifact by the fixture's canonical rule", () => {
  const fixture = JSON.parse(readFileSync(repo("conformance/fixtures/artifact-manifest-v1.json"), "utf8"));
  let compared = 0;
  for (const entry of fixture.cases) {
    if (typeof entry.input !== "object" || entry.input === null || Array.isArray(entry.input)) continue;
    if (Object.hasOwn(entry.input, "digest")) continue;
    assert.equal(canonicalDigest(entry.input), `sha256:${entry.sha256}`, entry.name);
    compared += 1;
  }
  assert.ok(compared >= 3);
  assert.notEqual(canonicalDigest({ a: 1 }), canonicalDigest({ a: 2 }));
});

test("every journey the driver can run exists, and each one is a function", () => {
  assert.deepEqual(JOURNEY_NAMES.slice().sort(), [
    "adapterSurface",
    "comparison",
    "diagnostics",
    "effective",
    "manifest",
    "overlap",
    "ownership",
    "pii",
    "rejections",
    "rulesets",
    "sessions",
  ]);
  for (const name of JOURNEY_NAMES) assert.equal(typeof JOURNEYS[name], "function", name);
});

const row = { id: "fake/full", piiAvailable: true, known: { included: ["github-token", "jwt"], notIncluded: ["x"] } };
const scans = { provider: [["github-token", "github_token", 8, 48, "redact", "high"]] };

test("build defaults and runtime overrides must agree on the enabled set, the identity and every scan", () => {
  const defaults = {
    enabled: ["a"],
    disabled: [],
    unavailableCount: 1,
    detectionDigest: "d",
    origin: "artifact-default",
    scans,
  };
  const same = ["include=all", { ...defaults, origin: "runtime" }];
  checkEffectiveEquivalence(row, [defaults, same]);
  for (const change of [
    { enabled: ["a", "b"] },
    { detectionDigest: "e" },
    { scans: { provider: [] } },
    { origin: "artifact-default" },
  ]) {
    assert.throws(
      () => checkEffectiveEquivalence(row, [defaults, ["x", { ...same[1], ...change }]]),
      /./,
      Object.keys(change)[0],
    );
  }
});

test("disabling a provider detector must hand the span to the contextual one, with its own action", () => {
  const overlap = {
    id: "github-token",
    disabled: ["github-token"],
    findings: [["generic-token", "contextual_secret", 8, 48, "warn", "medium"]],
    detectorsReported: ["generic-token"],
    textKeepsSecret: true,
    overlapOutcomesMayChange: true,
  };
  checkSelectionBeforeOverlap(row, overlap, scans);
  assert.throws(() => checkSelectionBeforeOverlap(row, { ...overlap, detectorsReported: ["github-token"] }));
  assert.throws(() => checkSelectionBeforeOverlap(row, { ...overlap, overlapOutcomesMayChange: false }));
  assert.throws(() => checkSelectionBeforeOverlap(row, { ...overlap, textKeepsSecret: false }));
});

const compared = (detectionDigests, entries, counts = { allow: 1 }) => ({
  mode: "preview",
  enforced: false,
  statuses: [
    ["scanned", null],
    ["scanned", null],
  ],
  counts: [{}, counts],
  detectionDigests,
  digests: ["a", "b"],
  entries: [null, entries],
});

test("allowing a finding and disabling its detector stay distinguishable", () => {
  const good = {
    id: "github-token",
    piiExpected: true,
    policyOnly: compared(["d", "d"], [["changed", "exact", ["action", "reason"]]]),
    configChange: compared(["d", "e"], [["changed", "exact", ["type", "detector", "action"]]]),
    pii: {
      ...compared(["d", "e"], [["added", null, null]]),
      statuses: [
        ["scanned", null],
        ["scanned", null],
      ],
    },
  };
  checkComparison(row, good);
  // An allow that moved the detection identity, or a disable that did not, is a failure.
  assert.throws(() => checkComparison(row, { ...good, policyOnly: compared(["d", "e"], good.policyOnly.entries[1]) }));
  assert.throws(() =>
    checkComparison(row, { ...good, configChange: compared(["d", "d"], good.configChange.entries[1]) }),
  );
  assert.throws(() =>
    checkComparison(row, { ...good, policyOnly: compared(["d", "d"], [["changed", "exact", ["detector"]]]) }),
  );
  // A PII side the artifact cannot provide is unsupported, never scanned or skipped.
  const unsupported = {
    ...good,
    piiExpected: false,
    pii: {
      ...good.pii,
      statuses: [
        ["scanned", null],
        ["unsupported", "PII_SELECTOR_UNAVAILABLE"],
      ],
      entries: [null, null],
    },
  };
  checkComparison(row, unsupported);
  assert.throws(() => checkComparison(row, { ...unsupported, pii: good.pii }));
});

test("the rejection, ownership, session, PII and adapter checks fail on the first silent fallback", () => {
  const attempt = (code) => ({ code, message: "" });
  const codes = (list) => list.map((code) => [code, "error", "p"]);
  const rejections = {
    attempts: {
      unknownId: attempt("INVALID_DETECTION_CONFIG"),
      pastedAsIdentifier: attempt("INVALID_DETECTION_CONFIG"),
      both: attempt("INVALID_DETECTION_CONFIG"),
      unknownDetectionMember: attempt("INVALID_DETECTION_CONFIG"),
      notIncluded: attempt("INVALID_DETECTION_CONFIG"),
      nothingEnabled: attempt("EMPTY_DETECTION_SET"),
      piiSelector: attempt("PII_SELECTOR_INVALID"),
      detectionOnScan: attempt("INVALID_OPTIONS"),
      detectionOnSession: attempt("INVALID_OPTIONS"),
      callbackAndPolicy: attempt("INVALID_OPTIONS"),
    },
    afterRejections: false,
    enabled: row.known.included,
    resolved: Object.fromEntries(
      [
        ["unknownId", "UNKNOWN_DETECTOR_ID"],
        ["notIncluded", "DETECTOR_NOT_INCLUDED"],
        ["pastedAsIdentifier", "INVALID_IDENTIFIER"],
        ["both", "DETECTION_SELECTOR_CONFLICT"],
        ["unknownMember", "UNKNOWN_FIELD"],
        ["pii", "PII_SELECTOR_INVALID"],
        ["reservedRulesetId", "INVALID_RULESET"],
        ["rulesetIdNotSelectable", "UNKNOWN_DETECTOR_ID"],
      ].map(([name, code]) => [name, { ok: false, snapshot: true, codes: codes([code]) }]),
    ),
  };
  rejections.resolved.nothingEnabled = {
    ok: true,
    snapshot: false,
    codes: [["NO_BUILT_IN_DETECTORS", "warning", "detection"]],
  };
  checkRejections(row, rejections);
  assert.throws(() => checkRejections(row, { ...rejections, afterRejections: true }));
  assert.throws(() =>
    checkRejections(row, { ...rejections, attempts: { ...rejections.attempts, notIncluded: attempt(null) } }),
  );

  const ownership = {
    canonicalOrder: true,
    equivalent: true,
    plain: attempt("DETECTION_CONFIG_CONFLICT"),
    different: attempt("DETECTION_CONFIG_CONFLICT"),
    unchanged: true,
  };
  checkOwnership(row, ownership);
  assert.throws(() => checkOwnership(row, { ...ownership, plain: attempt(null) }));

  const partitions = { provider: [{ size: 1, equalsWhole: true }] };
  const sessions = {
    partitions,
    reconfigure: attempt("DETECTION_CONFIG_CONFLICT"),
    earlyEqualsLate: true,
    appendAfterFinalize: attempt("INVALID_STATE"),
    finalizeTwice: attempt("INVALID_STATE"),
    rulesetOnSession: attempt("INVALID_OPTIONS"),
    detectionOnSession: attempt("INVALID_OPTIONS"),
    targetRedacted: true,
    sessionTargetRedacted: true,
  };
  checkSessions(row, sessions, { narrowed: false });
  assert.throws(() => checkSessions(row, { ...sessions, rulesetOnSession: attempt(null) }, { narrowed: false }));
  assert.throws(() =>
    checkSessions(
      row,
      { ...sessions, partitions: { provider: [{ size: 3, equalsWhole: false }] } },
      { narrowed: false },
    ),
  );
  assert.throws(() => checkSessions(row, { ...sessions, sessionTargetRedacted: false }, { narrowed: false }));

  const off = {
    email: [],
    families: [],
    activation: "credentials=full;selectors=off",
    credentialsStillFound: true,
    detectionDigest: "a",
  };
  const on = {
    ...off,
    email: [["pii-domain", "pii_global_email", 7, 41, "redact", "high"]],
    families: ["pii:global:email"],
    detectionDigest: "b",
  };
  checkPii(row, off, on);
  assert.throws(() => checkPii(row, { ...off, email: on.email }, on));

  const forms = [[true, [["github-token", "github_token", 8, 48, "warn", "high"]]]];
  const surface = {
    present: { scan: true },
    actionPolicyForms: [forms[0], forms[0], forms[0]],
    emptyProbe: attempt(null),
    both: attempt("INVALID_OPTIONS"),
    rejected: attempt("INVALID_ACTION_POLICY"),
    sessionKeepsWarned: true,
  };
  checkAdapterSurface(row, surface);
  assert.throws(() => checkAdapterSurface(row, { ...surface, emptyProbe: attempt("INVALID_OPTIONS") }));
  assert.throws(() => checkAdapterSurface(row, { ...surface, present: { scan: false } }));
});

test("the esbuild recipe copies the artifact's binary next to the bundle and nothing else", async () => {
  const dir = mkdtempSync(join(tmpdir(), "esbuild-redact-wasm-"));
  try {
    const artifact = join(dir, "artifact");
    mkdirSync(artifact);
    writeFileSync(
      join(artifact, "index.js"),
      'export const wasm = new URL("x_custom_bg.wasm", import.meta.url).href;\n',
    );
    writeFileSync(join(artifact, "x_custom_bg.wasm"), "wasm bytes");
    writeFileSync(join(artifact, "notes.txt"), "not copied");
    const entry = join(dir, "app.mjs");
    writeFileSync(entry, 'import { wasm } from "./artifact/index.js"; console.log(wasm);\n');
    await build({
      entryPoints: [entry],
      bundle: true,
      format: "esm",
      platform: "node",
      outfile: join(dir, "out", "app.mjs"),
      plugins: [copyRedactWasm({ artifactDir: artifact })],
      logLevel: "silent",
    });
    assert.equal(readFileSync(join(dir, "out", "x_custom_bg.wasm"), "utf8"), "wasm bytes");
    assert.throws(() => readFileSync(join(dir, "out", "notes.txt")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the quickstart is five steps over @redact-secret/core, synthetic only, and the guide shows it verbatim", () => {
  const source = readFileSync(repo(QUICKSTART), "utf8");
  const guide = readFileSync(repo("docs/guides/configuration-quickstart.md"), "utf8");
  assert.ok(guide.includes(`\`\`\`js\n${source.trimEnd()}\n\`\`\``), "docs/guides/configuration-quickstart.md");
  const marks = [...source.matchAll(/^\/\/ (\d)\. /gm)].map((match) => Number(match[1]));
  assert.deepEqual(marks, [1, 2, 3, 4, 5]);
  const imports = [...source.matchAll(/from "([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual(imports, ["@redact-secret/core"]);
  for (const forbidden of ["node:fs", "node:net", "fetch(", "process.env", "readFile", "http"]) {
    assert.ok(!source.includes(forbidden), forbidden);
  }
  // The only credential-shaped input is the repository's revoked, obviously synthetic example.
  const credentials = source.match(/ghp_[A-Za-z0-9_]+/g) ?? [];
  assert.deepEqual([...new Set(credentials)], ["ghp_SYNTHETICREVOKED00000000000000000000"]);
});

test("the custom composition guide shows the esbuild plugin verbatim", () => {
  const plugin = readFileSync(repo("scripts/lib/esbuild-redact-wasm.mjs"), "utf8").trimEnd();
  const guide = readFileSync(repo("docs/guides/custom-composition.md"), "utf8");
  assert.ok(guide.includes(`\`\`\`js\n${plugin}\n\`\`\``));
});
