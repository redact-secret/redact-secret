// Node package smoke test for the compiled N-API addon
// (`decision-define-runtime-bindings`). Run with `npm run smoke` after
// `npm run build` / `npm run build:debug`. Not part of `cargo test`: this
// exercises the addon the way an actual Node consumer of one of its
// published per-platform packages (`npm/<platform>/package.json`) does,
// through `require`/`import`, not Rust unit tests.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  artifactManifest,
  artifactManifestCommon,
  compareActionPolicies,
  createIncrementalSanitizer,
  defaultPolicy,
  initialize,
  initializePii,
  piiActivation,
  redact,
  scan,
  scanAndRedact,
  version,
} from "./index.js";

const SYNTHETIC_TOKEN =
  "Authorization: Bearer sk-syntheticRevokedExampleToken00000000000000000000";
const ASTRAL_PREFIXED = `\u{1F511} ${SYNTHETIC_TOKEN}`;
const PII_SELECTOR = process.env.REDACT_SECRET_PII_SELECTOR;
const PII_INPUT = process.env.REDACT_SECRET_PII_INPUT;
const PII_TYPE = process.env.REDACT_SECRET_PII_TYPE;

function initializeSelected() {
  if (PII_SELECTOR === undefined) initialize();
  else initializePii([PII_SELECTOR]);
}

const INCREMENTAL_LIMITS = {
  maxInputCodeUnits: 32_768,
  maxBufferedCodeUnits: 16_512,
  maxTokenCodeUnits: 8_192,
  maxMultilineCodeUnits: 16_384,
};

function check(name, fn) {
  try {
    fn();
    console.log(`ok - ${name}`);
  } catch (error) {
    console.error(`not ok - ${name}`);
    console.error(error);
    process.exitCode = 1;
  }
}

function canonicalJson(value) {
  const sort = (item) =>
    Array.isArray(item)
      ? item.map(sort)
      : item !== null && typeof item === "object"
        ? Object.fromEntries(Object.keys(item).sort().map((key) => [key, sort(item[key])]))
        : item;
  return JSON.stringify(sort(value));
}

// The artifact manifest is read before anything is initialized: it must
// describe the addon and must not build a registry or lock the PII
// selection, so every later check (which may select PII) still applies.
check("artifact manifest describes the addon and touches no activation", () => {
  for (const [text, variant] of [
    [artifactManifest(), "full"],
    [artifactManifestCommon(), "common"],
  ]) {
    const manifest = JSON.parse(text);
    assert.equal(Object.keys(manifest)[0], "schema");
    assert.equal(manifest.schema, "artifact-manifest/v1");
    assert.equal(manifest.version, version());
    assert.deepEqual(manifest.artifact, { kind: "node-addon", pii: true, variant });
    const { digest, ...rest } = manifest;
    assert.equal(digest, `sha256:${createHash("sha256").update(canonicalJson(rest)).digest("hex")}`);
    assert.equal(manifest.typeVocabulary.complete, false);
  }
  // `common` is a subset of `full`: what it lacks is exactly what it lists as not included.
  const full = JSON.parse(artifactManifest());
  const common = JSON.parse(artifactManifestCommon());
  assert.deepEqual(full.notIncluded, []);
  assert.equal(common.detectors.length + common.notIncluded.length, full.detectors.length);
  assert.ok(common.detectors.length > 0 && common.detectors.length < full.detectors.length);
});

// Repeated initialization: idempotent, callable any number of times.
check("repeated initialization is idempotent", () => {
  initializeSelected();
  initializeSelected();
  initializeSelected();
});

if (PII_INPUT !== undefined) {
  check("PII selection and PII-off scan through the installed addon", () => {
    const globals = "pii:global:email,pii:global:iban,pii:global:network-address,pii:global:payment-card,pii:global:phone";
    const expected = PII_SELECTOR === undefined
      ? "credentials=full;selectors=off;families=;vocabulary=pii-context/v2"
      : PII_SELECTOR === "pii:global"
      ? `credentials=full;selectors=pii:global;families=${globals};vocabulary=pii-context/v2`
      : PII_SELECTOR === "pii:us"
        ? `credentials=full;selectors=pii:us;families=${globals},pii:us:ssn;vocabulary=pii-context/v2`
        : PII_SELECTOR === "pii:family:us:ssn"
          ? "credentials=full;selectors=pii:family:us:ssn;families=pii:us:ssn;vocabulary=pii-context/v2"
          : `credentials=full;selectors=${PII_SELECTOR};families=${PII_SELECTOR.replace("pii:family:", "pii:")};vocabulary=pii-context/v2`;
    assert.equal(piiActivation(), expected);
    assert.equal(typeof PII_INPUT, "string");
    assert.equal(typeof PII_TYPE, "string");
    const findings = scan(PII_INPUT);
    const expectedFindings = PII_SELECTOR === undefined
      ? []
      : [["pii-domain", PII_TYPE, "redact"]];
    assert.deepEqual(
      findings.map((finding) => [finding.detector, finding.type, finding.action]),
      expectedFindings,
    );
  });

  check("PII selection and PII-off match incrementally at every UTF-16 partition", () => {
    const wholeResult = scanAndRedact(PII_INPUT);
    const whole = wholeResult.findings.map((finding) => [
      finding.detector,
      finding.type,
      finding.action,
      finding.start,
      finding.end,
    ]);
    for (let split = 0; split <= PII_INPUT.length; split += 1) {
      const unit = PII_INPUT.charCodeAt(split);
      if (unit >= 0xdc00 && unit <= 0xdfff) continue;
      const session = createIncrementalSanitizer({ limits: INCREMENTAL_LIMITS });
      const results = [
        session.append(PII_INPUT.slice(0, split)),
        session.append(PII_INPUT.slice(split)),
        session.finalize(),
      ];
      const incremental = results.flatMap((result) => result.findings).map((finding) => [
        finding.detector,
        finding.type,
        finding.action,
        finding.start,
        finding.end,
      ]);
      const redacted = results.map((result) => result.text).join("");
      assert.equal(redacted, wholeResult.redacted, `partition ${split} text`);
      assert.deepEqual(incremental, whole, `partition ${split}`);
    }
  });
}

// Canonical synchronous conformance smoke case, with an astral character
// ahead of the match to exercise the UTF-16 offset conversion at its most
// divergent case.
check("scan finds a synthetic bearer token with UTF-16 offsets", () => {
  const findings = scan(ASTRAL_PREFIXED);
  assert.equal(findings.length, 1);
  const [finding] = findings;
  assert.equal(finding.action, "redact");
  // "\u{1F511} " is a surrogate pair (2 UTF-16 code units) plus a space.
  assert.equal(finding.start, ASTRAL_PREFIXED.indexOf("Bearer") + "Bearer ".length);
  assert.equal(ASTRAL_PREFIXED.slice(finding.start, finding.end).length > 0, true);
});

// Unicode offset test: JavaScript's own `.slice()` over `start`/`end` must
// select the same finding boundaries `scan` reports.
check("reported ranges are valid JavaScript UTF-16 slice boundaries", () => {
  const findings = scan(ASTRAL_PREFIXED);
  const [finding] = findings;
  const matched = ASTRAL_PREFIXED.slice(finding.start, finding.end);
  assert.equal(matched.startsWith("sk-syntheticRevokedExampleToken"), true);
});

check("scan reports invisible-character obfuscation on a split token", () => {
  const cleanFindings = scan(SYNTHETIC_TOKEN);
  assert.equal(cleanFindings.length, 1);
  assert.equal(cleanFindings[0].obfuscation, "none");

  const obfuscatedToken = SYNTHETIC_TOKEN.replace(
    "sk-syntheticRevokedExampleToken",
    "sk-synthetic‌RevokedExampleToken",
  );
  const findings = scan(obfuscatedToken);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].obfuscation, "invisible-characters");
});

check("scanAndRedact matches scan + redact", () => {
  const { findings, redacted } = scanAndRedact(SYNTHETIC_TOKEN);
  assert.equal(findings.length, 1);
  assert.equal(redacted, redact(SYNTHETIC_TOKEN, findings));
  assert.equal(redacted.includes("sk-syntheticRevokedExampleToken"), false);
});

// Policy callback failure: a thrown policy callback surfaces as a fixed,
// input-free POLICY_FAILURE error, not the thrown JS error itself.
check("a throwing policy callback surfaces POLICY_FAILURE", () => {
  assert.throws(
    () => scan(SYNTHETIC_TOKEN, () => {
      throw new Error("boom");
    }),
    (error) => {
      assert.equal(error.code, "POLICY_FAILURE");
      assert.equal(error.message, "The secret policy failed.");
      assert.equal(error.message.includes(SYNTHETIC_TOKEN), false);
      return true;
    },
  );
});

check("a policy callback returning an unknown action is rejected", () => {
  assert.throws(
    () => scan(SYNTHETIC_TOKEN, () => "delete"),
    (error) => {
      assert.equal(error.code, "INVALID_POLICY_ACTION");
      return true;
    },
  );
});

check("a custom policy callback controls the action", () => {
  const findings = scan(SYNTHETIC_TOKEN, () => "warn");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].action, "warn");
});

check("a custom placeholder formatter controls redaction output", () => {
  const findings = scan(SYNTHETIC_TOKEN);
  const redacted = redact(SYNTHETIC_TOKEN, findings, (_finding, context) =>
    `[[REMOVED_${context.placeholderIndex}]]`,
  );
  assert.equal(redacted.includes("[[REMOVED_1]]"), true);
});

check("a throwing formatter surfaces PLACEHOLDER_FAILURE", () => {
  const findings = scan(SYNTHETIC_TOKEN);
  assert.throws(
    () =>
      redact(SYNTHETIC_TOKEN, findings, () => {
        throw new Error("boom");
      }),
    (error) => {
      assert.equal(error.code, "PLACEHOLDER_FAILURE");
      return true;
    },
  );
});

check("malformed findings passed to redact are rejected as input-free errors", () => {
  assert.throws(
    () =>
      redact(SYNTHETIC_TOKEN, [
        {
          id: "finding-1",
          type: "synthetic",
          detector: "synthetic",
          confidence: "high",
          action: "delete",
          obfuscation: "none",
          start: 0,
          end: 5,
        },
      ]),
    (error) => {
      assert.equal(error.code, "INVALID_FINDINGS");
      assert.equal(error.message.includes(SYNTHETIC_TOKEN), false);
      return true;
    },
  );
});

check("version reports the shared product version", () => {
  assert.equal(typeof version(), "string");
  assert.ok(version().length > 0);
});

// Incremental sessions: append/finalize/abort against the real addon.

check("a value split across chunks, including an astral character, matches the whole-input result", () => {
  const session = createIncrementalSanitizer({ limits: INCREMENTAL_LIMITS });
  let text = "";
  for (const chunk of ["\u{1F511} api_key=SYN", "THETIC_REVOKED_MARKER\n", "tail"]) {
    text += session.append(chunk).text;
  }
  text += session.finalize().text;
  assert.equal(session.state, "finalized");
  assert.equal(text, "\u{1F511} api_key=<SECRET_1>\ntail");
  assert.equal(text.includes("SYNTHETIC_REVOKED_MARKER"), false);
});

check("abort discards retained plaintext and rejects every later operation", () => {
  const session = createIncrementalSanitizer({ limits: INCREMENTAL_LIMITS });
  session.append("api_key=SYNTHETIC_REVOKED_ABORT_MARKER");
  session.abort();
  assert.equal(session.state, "aborted");
  assert.throws(
    () => session.append("more"),
    (error) => {
      assert.equal(error.code, "INVALID_STATE");
      return true;
    },
  );
});

check("a second finalize is rejected rather than re-emitted", () => {
  const session = createIncrementalSanitizer({ limits: INCREMENTAL_LIMITS });
  session.finalize();
  assert.throws(
    () => session.finalize(),
    (error) => {
      assert.equal(error.code, "INVALID_STATE");
      return true;
    },
  );
});

check("an open construct one code unit past the token cap fails safely with no output", () => {
  const session = createIncrementalSanitizer({
    limits: { ...INCREMENTAL_LIMITS, maxTokenCodeUnits: 32 },
  });
  assert.throws(
    () => session.append("x".repeat(33)),
    (error) => {
      assert.equal(error.code, "TOKEN_LIMIT_EXCEEDED");
      return true;
    },
  );
  assert.equal(session.state, "failed");
});

check("an open construct exactly at the token cap is accepted, not rejected", () => {
  const session = createIncrementalSanitizer({
    limits: {
      maxInputCodeUnits: 512,
      maxBufferedCodeUnits: 192,
      maxTokenCodeUnits: 32,
      maxMultilineCodeUnits: 64,
    },
  });
  session.append("x".repeat(32));
  const result = session.finalize();
  assert.equal(result.text, "x".repeat(32));
  assert.equal(result.findings.length, 0);
});

check("a custom incremental policy controls the action with UTF-16 offsets", () => {
  const calls = [];
  const session = createIncrementalSanitizer({
    limits: INCREMENTAL_LIMITS,
    policy: (finding, context) => {
      calls.push({ finding, context });
      return "warn";
    },
  });
  const appended = session.append("api_key=SYNTHETIC_REVOKED_POLICY_MARKER\n");
  const result = session.finalize();
  const findings = [...appended.findings, ...result.findings];
  assert.equal(calls.length, 1);
  assert.equal(calls[0].context.findingIndex, 0);
  assert.equal(calls[0].finding.start, "api_key=".length);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].action, "warn");
});

check("a custom incremental formatter controls the placeholder text", () => {
  const session = createIncrementalSanitizer({
    limits: INCREMENTAL_LIMITS,
    formatter: (_finding, context) => `[[REMOVED_${context.placeholderIndex}]]`,
  });
  const appended = session.append("api_key=SYNTHETIC_REVOKED_FORMATTER_MARKER\n");
  const text = appended.text + session.finalize().text;
  assert.equal(text.includes("[[REMOVED_1]]"), true);
  assert.equal(text.includes("SYNTHETIC_REVOKED_FORMATTER_MARKER"), false);
});

check("a throwing incremental policy surfaces POLICY_FAILURE and discards retained text", () => {
  const session = createIncrementalSanitizer({
    limits: INCREMENTAL_LIMITS,
    policy: () => {
      throw new Error("boom");
    },
  });
  assert.throws(
    () => session.append("api_key=SYNTHETIC_REVOKED_POLICY_THROW_MARKER\n"),
    (error) => {
      assert.equal(error.code, "POLICY_FAILURE");
      assert.equal(error.message.includes(SYNTHETIC_TOKEN), false);
      return true;
    },
  );
  assert.equal(session.state, "failed");
});

check("invalid limits are rejected with INVALID_LIMITS before a session is created", () => {
  assert.throws(
    () =>
      createIncrementalSanitizer({
        limits: { ...INCREMENTAL_LIMITS, maxInputCodeUnits: 0 },
      }),
    (error) => {
      assert.equal(error.code, "INVALID_LIMITS");
      return true;
    },
  );
});

const ACTION_POLICY_INPUT = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000";
const WARN_GITHUB = Buffer.from(
  '{"actionPolicyRevision":1,"base":"default","rules":[{"id":"warn-github","match":{"type":["github_token"]},"action":"warn"}]}',
);

check("an action policy changes one action and leaves the default for the rest", () => {
  const [plain] = scan(ACTION_POLICY_INPUT);
  assert.equal(plain.action, "redact");
  const [overlaid] = scan(ACTION_POLICY_INPUT, undefined, undefined, undefined, WARN_GITHUB);
  assert.equal(overlaid.action, "warn");
  assert.equal(overlaid.start, plain.start);
  const result = scanAndRedact(ACTION_POLICY_INPUT, undefined, undefined, undefined, undefined, WARN_GITHUB);
  assert.equal(result.redacted, ACTION_POLICY_INPUT);
});

check("an incremental session binds the action policy it was created with", () => {
  const session = createIncrementalSanitizer({ limits: INCREMENTAL_LIMITS, actionPolicy: WARN_GITHUB });
  const released = [
    ...session.append(ACTION_POLICY_INPUT.slice(0, 20)).findings,
    ...session.append(ACTION_POLICY_INPUT.slice(20)).findings,
    ...session.finalize().findings,
  ];
  assert.deepEqual(
    released.map((finding) => finding.action),
    ["warn"],
  );
});

check("a rejected action policy is INVALID_ACTION_POLICY with the class and rule index", () => {
  assert.throws(
    () => scan("irrelevant", undefined, undefined, undefined, Buffer.from("{}")),
    (error) => {
      assert.equal(error.code, "INVALID_ACTION_POLICY");
      assert.equal(error.message, "The supplied action policy is invalid. (MISSING_FIELD)");
      return true;
    },
  );
  assert.throws(
    () => scan("irrelevant", () => "redact", undefined, undefined, WARN_GITHUB),
    (error) => {
      assert.equal(error.code, "INVALID_OPTIONS");
      return true;
    },
  );
});

check("defaultPolicy evaluates the core default without a copied table", () => {
  const finding = {
    id: "finding-1",
    type: "private_key",
    detector: "private-key",
    confidence: "low",
    obfuscation: "none",
    start: 0,
    end: 1,
  };
  assert.equal(defaultPolicy(finding), "block");
  assert.equal(defaultPolicy({ ...finding, type: "acme-unknown-type", confidence: "medium" }), "warn");
});

check("compareActionPolicies compares sides over one detection pass and enforces nothing", () => {
  const calls = [];
  const result = compareActionPolicies(
    ACTION_POLICY_INPUT,
    ["default", "action-policy", "callback"],
    [WARN_GITHUB],
    [
      (finding, context) => {
        calls.push(`${finding.id}:${context.findingIndex}/${context.findingCount}`);
        return "allow";
      },
    ],
  );
  assert.deepEqual(calls, ["finding-1:0/1"]);
  assert.equal(result.findings.length, 1);
  const [finding] = result.findings;
  assert.deepEqual(
    finding.decisions.map((decision) => [decision.action, decision.basis]),
    [
      ["redact", "default-policy"],
      ["warn", "rule"],
      ["allow", "callback"],
    ],
  );
  assert.equal(finding.decisions[1].ruleId, "warn-github");
  assert.equal(finding.differs, true);
  assert.equal(result.changedCount, 1);
  assert.equal(result.sides[1].documentSha256.length, 64);
  assert.equal(result.sides[2].documentSha256, undefined);
  assert.equal(scanAndRedact(ACTION_POLICY_INPUT).redacted.includes("ghp_"), false);
});

check("compareActionPolicies fails closed on a bad side count, a bad return and a bad document", () => {
  assert.throws(
    () => compareActionPolicies(ACTION_POLICY_INPUT, [], [], []),
    (error) => error.code === "INVALID_OPTIONS",
  );
  assert.throws(
    () => compareActionPolicies(ACTION_POLICY_INPUT, ["callback"], [], [() => "mask"]),
    (error) => error.code === "INVALID_POLICY_ACTION",
  );
  assert.throws(
    () =>
      compareActionPolicies(
        ACTION_POLICY_INPUT,
        ["callback"],
        [],
        [
          () => {
            throw new Error("synthetic");
          },
        ],
      ),
    (error) => error.code === "POLICY_FAILURE",
  );
  assert.throws(
    () => compareActionPolicies("irrelevant", ["action-policy"], [Buffer.from("{}")], []),
    (error) => error.code === "INVALID_ACTION_POLICY",
  );
});

if (process.exitCode) {
  console.error("\nsmoke test FAILED");
} else {
  console.log("\nsmoke test passed");
}
