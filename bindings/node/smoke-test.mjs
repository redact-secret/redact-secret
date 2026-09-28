// Node package smoke test for the compiled N-API addon
// (`decision-define-runtime-bindings`). Run with `npm run smoke` after
// `npm run build` / `npm run build:debug`. Not part of `cargo test`: this
// exercises the addon the way an actual Node consumer of one of its
// published per-platform packages (`npm/<platform>/package.json`) does,
// through `require`/`import`, not Rust unit tests.

import assert from "node:assert/strict";
import {
  createIncrementalSanitizer,
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

if (process.exitCode) {
  console.error("\nsmoke test FAILED");
} else {
  console.log("\nsmoke test passed");
}
