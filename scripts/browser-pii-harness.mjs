/**
 * Fresh-page qualification for payment-card PII activation on the actual
 * browser Wasm artifact. Each selector is loaded by a separate page/module
 * instance because activation is intentionally one-shot.
 */

import init, { initialize, piiActivation, scan } from "./artifact.js";

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
  initialize([selector]);

  check("payment-card selector has the canonical activation identity", () => {
    const family = "pii:global:payment-card";
    const expected = selector === "pii:global"
      ? `credentials=${fixtures.profile};selectors=pii:global;families=pii:global:email,pii:global:iban,pii:global:network-address,${family};vocabulary=pii-context/v1`
      : `credentials=${fixtures.profile};selectors=pii:family:global:payment-card;families=${family};vocabulary=pii-context/v1`;
    assert(piiActivation() === expected, "activation identity disagreed");
  });

  check("payment-card selector scans through the exported artifact", () => {
    const findings = scan(fixtures.paymentCardPositive.input);
    const actual = findings.map((finding) => [
      finding.detector,
      finding.type,
      finding.action,
      finding.range.start,
      finding.range.end,
    ]);
    const expected = fixtures.paymentCardPositive.expected.map((finding) => [
      finding.detector,
      finding.type,
      finding.action,
      finding.start,
      finding.end,
    ]);
    assert(JSON.stringify(actual) === JSON.stringify(expected), "finding metadata disagreed");
  });

  return { ok: failures === 0, failures, checks };
}
