/**
 * Fresh-page qualification for PII activation on the actual browser Wasm
 * artifact. Each selector is loaded by a separate page/module instance
 * because activation is intentionally one-shot.
 *
 * Since issue #937 PII detection lives only in each profile's `pii` build,
 * staged as `./artifact-pii.js`; `qualify` runs against it by default.
 * `qualifyUnavailable` runs against the default build, `./artifact.js`, and
 * checks that it links no PII runtime observable from its exports: a valid
 * selection is `PII_SELECTOR_UNAVAILABLE`, selector grammar and activation
 * conflicts report the same codes as the `pii` build, and PII-off scanning
 * finds no PII.
 */

const INCREMENTAL_LIMITS = [32_768, 16_512, 8_192, 16_384];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function codeOf(run) {
  try {
    run();
  } catch (error) {
    return error?.code;
  }
  return undefined;
}

export async function qualifyUnavailable(fixtures) {
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
  const { default: init, initialize, piiActivation, scan } = await import("./artifact.js");
  await init();

  check("the default artifact rejects a valid PII selection as unavailable", () => {
    for (const selector of ["pii", "pii:global", "pii:us", "pii:family:global:phone"]) {
      const code = codeOf(() => initialize([selector]));
      assert(code === "PII_SELECTOR_UNAVAILABLE", `${selector}: code was ${code}`);
    }
  });

  check("the default artifact reports selector grammar errors unchanged", () => {
    assert(codeOf(() => initialize(["PII"])) === "PII_SELECTOR_INVALID", "invalid selector");
    assert(codeOf(() => initialize(["pii:kr"])) === "PII_SELECTOR_UNSUPPORTED", "unsupported selector");
  });

  check("a rejected PII selection is not cached; PII-off initialization succeeds", () => {
    initialize([]);
    const expected = `credentials=${fixtures.profile};selectors=off;families=;vocabulary=pii-context/v1`;
    assert(piiActivation() === expected, "activation identity disagreed");
  });

  check("a later PII selection is an activation conflict, as on the pii artifact", () => {
    const code = codeOf(() => initialize(["pii"]));
    assert(code === "PII_ACTIVATION_CONFLICT", `code was ${code}`);
  });

  check("the default artifact finds no PII", () => {
    for (const key of ["paymentCard", "phone", "usSsn"]) {
      const pii = scan(fixtures[key].positive.input).filter((finding) => finding.detector === "pii-domain");
      assert(pii.length === 0, `${key}: the default artifact reported PII`);
    }
  });

  return { ok: failures === 0, failures, checks };
}

export async function qualify(fixtures, selector, fixtureKey) {
  const {
    default: init,
    createIncrementalSanitizer,
    initialize,
    piiActivation,
    scan,
    scanAndRedact,
  } = await import("./artifact-pii.js");
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

  const fixture = fixtures[fixtureKey];
  const positive = fixture.positive;

  check("PII selector has the canonical activation identity", () => {
    const globals = "pii:global:email,pii:global:iban,pii:global:network-address,pii:global:payment-card,pii:global:phone";
    const expected = selector === null
      ? `credentials=${fixtures.profile};selectors=off;families=;vocabulary=pii-context/v2`
      : selector === "pii:global"
      ? `credentials=${fixtures.profile};selectors=pii:global;families=${globals};vocabulary=pii-context/v2`
      : selector === "pii:us"
        ? `credentials=${fixtures.profile};selectors=pii:us;families=${globals},pii:us:ssn;vocabulary=pii-context/v2`
        : selector === "pii:family:us:ssn"
          ? `credentials=${fixtures.profile};selectors=pii:family:us:ssn;families=pii:us:ssn;vocabulary=pii-context/v2`
          : `credentials=${fixtures.profile};selectors=${selector};families=${fixture.family};vocabulary=pii-context/v2`;
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
