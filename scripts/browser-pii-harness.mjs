/**
 * Fresh-page qualification for PII activation on the actual browser Wasm
 * artifact. Each selector is loaded by a separate page/module instance
 * because activation is intentionally one-shot.
 */

import init, {
  createIncrementalSanitizer,
  initialize,
  piiActivation,
  scan,
  scanAndRedact,
} from "./artifact.js";

const INCREMENTAL_LIMITS = [32_768, 16_512, 8_192, 16_384];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

export async function qualify(fixtures, selector) {
  const checks = [];
  let failures = 0;
  const check = (name, run) => {
    try {
      run();
      checks.push({ name, ok: true });
    } catch (error) {
      failures += 1;
      checks.push({
        name,
        ok: false,
        detail: error instanceof Error ? error.message : String(error),
      });
    }
  };

  await init();
  initialize(selector === null ? [] : [selector]);

  const usSsn =
    selector === null || selector === "pii:family:us:ssn" || selector === "pii:us";
  const positive = usSsn ? fixtures.usSsnPositive : fixtures.paymentCardPositive;

  check("PII selector has the canonical activation identity", () => {
    const globals = "pii:global:email,pii:global:iban,pii:global:network-address,pii:global:payment-card";
    const expected = selector === null
      ? `credentials=${fixtures.profile};selectors=off;families=;vocabulary=pii-context/v1`
      : selector === "pii:global"
      ? `credentials=${fixtures.profile};selectors=pii:global;families=${globals};vocabulary=pii-context/v1`
      : selector === "pii:us"
        ? `credentials=${fixtures.profile};selectors=pii:us;families=${globals},pii:us:ssn;vocabulary=pii-context/v1`
        : selector === "pii:family:us:ssn"
          ? `credentials=${fixtures.profile};selectors=pii:family:us:ssn;families=pii:us:ssn;vocabulary=pii-context/v1`
          : `credentials=${fixtures.profile};selectors=pii:family:global:payment-card;families=pii:global:payment-card;vocabulary=pii-context/v1`;
    assert(piiActivation() === expected, "activation identity disagreed");
  });

  check("PII selector scans through the exported artifact", () => {
    const findings = scan(positive.input);
    const actual = findings.map((finding) => [
      finding.detector,
      finding.type,
      finding.action,
      finding.range.start,
      finding.range.end,
    ]);
    const expected = (selector === null ? [] : positive.expected).map((finding) => [
      finding.detector,
      finding.type,
      finding.action,
      finding.start,
      finding.end,
    ]);
    assert(JSON.stringify(actual) === JSON.stringify(expected), "finding metadata disagreed");
  });

  check("PII selection and PII-off match incrementally at every UTF-16 partition", () => {
    const tuple = (finding) => [
      finding.detector,
      finding.type,
      finding.action,
      finding.range.start,
      finding.range.end,
    ];
    const whole = scanAndRedact(positive.input);
    for (let split = 0; split <= positive.input.length; split += 1) {
      const unit = positive.input.charCodeAt(split);
      if (unit >= 0xdc00 && unit <= 0xdfff) continue;
      const session = createIncrementalSanitizer(...INCREMENTAL_LIMITS);
      const results = [
        session.append(positive.input.slice(0, split)),
        session.append(positive.input.slice(split)),
        session.finalize(),
      ];
      const text = results.map((result) => result.text).join("");
      const incremental = results.flatMap((result) => result.findings).map(tuple);
      assert(text === whole.text, `partition ${split} text disagreed`);
      assert(
        JSON.stringify(incremental) === JSON.stringify(whole.findings.map(tuple)),
        `partition ${split} findings disagreed`,
      );
    }
  });

  return { ok: failures === 0, failures, checks };
}
