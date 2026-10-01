/**
 * The PII opt-in half of `scripts/qualify-browser-artifact.mjs`'s package
 * pages (issue #937): the published package's documented PII entry point,
 * `initialize({ pii })`, running in a real browser.
 *
 * Since #937 each profile ships two WebAssembly builds: a default one that
 * links no PII runtime, and a `pii` one that `initialize()` loads only when
 * it is given a PII selection. This page checks that the public PII
 * contract is unchanged across that split: the activation identity, a
 * representative finding, and the one-shot activation conflict. The runner
 * separately asserts that this page fetched only the `pii` build and the
 * default package page fetched only the default build.
 *
 * `@redact-secret/core` is bundled with a literal specifier; for the
 * `common` profile, `scripts/qualify-browser-artifact.mjs` aliases it to the
 * `@redact-secret/core/common` entry, so the same file serves both profiles.
 * Every input is a synthetic conformance fixture, and no diagnostic carries
 * an input or a matched value.
 */

import { initialize, piiActivation, SecretScanError, scan } from "@redact-secret/core";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

export async function qualify(fixtures) {
  const checks = [];
  let failures = 0;
  const check = async (name, run) => {
    try {
      await run();
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

  const { selector, family, positive } = fixtures.packagePii;

  await check("initialize({ pii }) loads the PII-capable artifact", async () => {
    await initialize({ pii: [selector] });
    await initialize({ pii: [selector] });
  });

  await check("the PII activation identity is unchanged", () => {
    const expected = `credentials=${fixtures.profile};selectors=${selector};families=${family};vocabulary=pii-context/v2`;
    assert(piiActivation() === expected, "activation identity disagreed");
  });

  await check("a PII selection scans through the package entry", () => {
    const actual = scan(positive.input).map((finding) => [finding.detector, finding.type, finding.action]);
    const expected = positive.expected.map((finding) => [finding.detector, finding.type, finding.action]);
    assert(JSON.stringify(actual) === JSON.stringify(expected), "finding metadata disagreed");
  });

  await check("a different later selection is still PII_ACTIVATION_CONFLICT", async () => {
    let thrown;
    try {
      await initialize();
    } catch (error) {
      thrown = error;
    }
    assert(thrown instanceof SecretScanError, "a foreign error escaped the package");
    assert(thrown.code === "PII_ACTIVATION_CONFLICT", `code was ${thrown.code}`);
  });

  return { ok: failures === 0, failures, checks };
}
