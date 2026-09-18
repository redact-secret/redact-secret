/**
 * The in-page half of `scripts/qualify-browser-artifact.mjs`: the checks the
 * browser WebAssembly artifact must pass in every supported engine
 * (`decision-define-runtime-bindings`).
 *
 * This module is served next to the artifact it imports, so the generated
 * `default()` init resolves the artifact's `.wasm` from the same directory
 * and the whole surface is exercised exactly as a browser consumer loads it:
 * a real `fetch` of a real `.wasm` response, instantiated by the engine
 * under test. `./artifact.js` is a one-line re-export of the glue for the
 * detector profile under test (`redact_secret_wasm.js` for `full`,
 * `redact_secret_wasm_common.js` for `common`), staged by the runner.
 *
 * Every fixture comes from the canonical corpus
 * (`decision-govern-cross-language-conformance`), served alongside as
 * `fixtures.json`, and every input in it is synthetic or explicitly revoked.
 * For `common`, each fixture's expectation is the reviewed
 * `conformance/fixtures/common-profile-expectations.json` entry instead of
 * the `full` one (`decision-define-detector-profile-and-pack-contract`).
 * Nothing this module reports carries an input, a matched value, or a
 * placeholder: a failure names the fixture and the metadata tuples only.
 */

import init, {
  createIncrementalSanitizer,
  initialize,
  profile,
  redact,
  scan,
  scanAndRedact,
  version,
} from "./artifact.js";

/**
 * Fixtures above this many UTF-8 bytes are left to the whole-input checks.
 * Every construct in a smaller fixture then fits the session's token and
 * multiline limits, so no limit can make the two paths diverge.
 */
const INCREMENTAL_MAX_INPUT_BYTES = 64 * 1024;
/**
 * `createIncrementalSanitizer` limits: input, buffered (the construct
 * limit plus the core's 128-byte lookaround, as
 * `IncrementalLimits::minimum_buffered_bytes` derives it), token, multiline.
 */
const INCREMENTAL_LIMITS = [
  1 << 20,
  INCREMENTAL_MAX_INPUT_BYTES + 128,
  INCREMENTAL_MAX_INPUT_BYTES,
  INCREMENTAL_MAX_INPUT_BYTES,
];

const results = [];
let failures = 0;

function check(name, run) {
  try {
    run();
    results.push({ name, ok: true });
  } catch (error) {
    failures += 1;
    results.push({
      name,
      ok: false,
      detail: error instanceof Error ? error.message : String(error),
    });
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertEqual(actual, expected, message) {
  const left = JSON.stringify(actual);
  const right = JSON.stringify(expected);
  if (left !== right) throw new Error(`${message}: expected ${right}, got ${left}`);
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Converts a canonical UTF-8 byte offset to a UTF-16 code-unit offset
 * without using the artifact under test, so a conformance assertion cannot
 * validate the binding against its own conversion.
 */
function byteOffsetToCodeUnitOffset(text, byteOffset) {
  return decoder.decode(encoder.encode(text).slice(0, byteOffset)).length;
}

function expectedTuples(text, expected) {
  return expected.map((item) => [
    item.detector,
    item.type,
    item.confidence,
    byteOffsetToCodeUnitOffset(text, item.start),
    byteOffsetToCodeUnitOffset(text, item.end),
  ]);
}

function actualTuples(findings) {
  return findings.map((finding) => [
    finding.detector,
    finding.type,
    finding.confidence,
    finding.range.start,
    finding.range.end,
  ]);
}

/**
 * The `[start, end)` UTF-16 ranges `scan` reports for `text`. Ranges only:
 * a comparison never materializes a matched value.
 */
function reportedRanges(text) {
  return scan(text).map((finding) => [finding.range.start, finding.range.end]);
}

function errorCode(thrown) {
  return thrown !== null && typeof thrown === "object" && "code" in thrown
    ? thrown.code
    : undefined;
}

export async function qualify(fixtures) {
  // Before `default()`: the module's own exports are not callable at all, so
  // the first observable contract is the one after instantiation.
  await init();

  // The lifecycle gate, checked before `initialize()` succeeds: a
  // synchronous operation must fail deterministically rather than scan.
  check("operations before initialize fail with NOT_INITIALIZED", () => {
    let thrown;
    try {
      scan("AKIASYNTHETICEXAMPLE0");
    } catch (error) {
      thrown = error;
    }
    assert(thrown !== undefined, "scan resolved before initialize()");
    assertEqual(errorCode(thrown), "NOT_INITIALIZED", "pre-initialize code");
  });

  check("initialize is idempotent", () => {
    initialize();
    initialize();
    initialize();
  });

  check("version reports the shared product version", () => {
    assertEqual(version(), fixtures.version, "artifact version");
  });

  check("profile reports the compiled detector profile", () => {
    assertEqual(profile(), fixtures.profile, "artifact profile");
  });

  const synchronous = fixtures.synchronous;
  check("the canonical synchronous corpus is not vacuous", () => {
    assert(synchronous.length >= 100, `only ${synchronous.length} fixtures`);
    assert(
      synchronous.some((fixture) => fixture.expected.length > 0),
      "no positive fixture",
    );
    assert(
      synchronous.some((fixture) => fixture.expected.length === 0),
      "no negative fixture",
    );
  });

  check("scan matches the canonical synchronous corpus", () => {
    const mismatched = [];
    for (const fixture of synchronous) {
      const actual = actualTuples(scan(fixture.input));
      const expected = expectedTuples(fixture.input, fixture.expected);
      if (JSON.stringify(actual) !== JSON.stringify(expected)) {
        mismatched.push({ id: fixture.id, expected, actual });
      }
    }
    assert(
      mismatched.length === 0,
      `${mismatched.length} fixture(s) disagreed: ${JSON.stringify(mismatched.slice(0, 5))}`,
    );
  });

  // A `common` artifact that linked or ran a `provider` detector would
  // report a finding under an id outside its profile, on either path.
  check("every finding comes from a detector in the profile", () => {
    const allowed = new Set(fixtures.detectors);
    const foreign = new Set();
    for (const fixture of synchronous) {
      for (const finding of scan(fixture.input)) {
        if (!allowed.has(finding.detector)) foreign.add(finding.detector);
      }
    }
    assertEqual([...foreign], [], "detectors outside the profile");
  });

  // The incremental session must build the same profile's registry as the
  // whole-input path: split each positive fixture in two at a code-point
  // boundary and compare against `scanAndRedact` on the same artifact.
  check("an incremental session matches scanAndRedact on the same artifact", () => {
    const mismatched = [];
    let compared = 0;
    for (const fixture of synchronous) {
      if (fixture.expected.length === 0) continue;
      if (encoder.encode(fixture.input).length > INCREMENTAL_MAX_INPUT_BYTES) continue;
      let split = Math.floor(fixture.input.length / 2);
      const unit = fixture.input.charCodeAt(split);
      if (unit >= 0xdc00 && unit <= 0xdfff) split += 1;
      const session = createIncrementalSanitizer(...INCREMENTAL_LIMITS);
      const results = [
        session.append(fixture.input.slice(0, split)),
        session.append(fixture.input.slice(split)),
        session.finalize(),
      ];
      const text = results.map((result) => result.text).join("");
      const findings = actualTuples(results.flatMap((result) => result.findings));
      const whole = scanAndRedact(fixture.input);
      compared += 1;
      if (
        text !== whole.text ||
        JSON.stringify(findings) !== JSON.stringify(actualTuples(whole.findings))
      ) {
        mismatched.push(fixture.id);
      }
    }
    assert(compared > 0, "no fixture exercised the incremental session");
    assert(
      mismatched.length === 0,
      `${mismatched.length} fixture(s) disagreed: ${mismatched.slice(0, 5).join(", ")}`,
    );
  });

  // The corpus already carries an astral (supplementary-plane) character
  // ahead of a real detector's finding, so the check above is itself the
  // end-to-end "astral before a finding" evidence the conformance decision
  // requires. This asserts that evidence is actually present rather than
  // silently removed from the corpus.
  check("the corpus exercises an astral character before a finding", () => {
    const astral = fixtures.synchronous.filter(
      (fixture) =>
        fixture.expected.length > 0 &&
        [...fixture.input].some((character) => character.codePointAt(0) > 0xffff),
    );
    assert(astral.length > 0, "no positive fixture contains an astral character");
  });

  // The "after" case, over every positive fixture that can carry a suffix:
  // a finding whose expected span already reaches the end of the input is
  // an unterminated fail-safe match, so extending the input legitimately
  // extends it. The "within" case is not observable through any built-in
  // detector — none matches a span containing an astral character — and is
  // asserted at the unit level by `bindings/wasm/src/range.rs`.
  check("an astral character around a finding does not perturb its span", () => {
    // "\u{1F511}\n" is 3 UTF-16 code units and 5 UTF-8 bytes, so a binding
    // that leaked byte offsets would shift every span by 5 instead of 3.
    //
    // The trailing character must be a line terminator, not any boundary
    // character: `generic_token.rs`'s `AUTHORIZATION_PATTERN` anchors to
    // `is_line_start` with no other alternative (unlike its contextual-
    // assignment sibling, which also accepts a bare whitespace/`{,;`
    // boundary). That grammar promises invariance to whatever precedes the
    // *line* it matches on, not to whatever precedes the *input* — so a
    // prefix that does not preserve line-start would falsify a fixture the
    // grammar was never claiming to be invariant under, rather than
    // exercising the UTF-16 conversion this check exists to cover.
    const PREFIX = "\u{1F511}\n";
    const SHIFT = PREFIX.length;
    const perturbed = [];
    for (const fixture of fixtures.synchronous) {
      if (fixture.expected.length === 0) continue;
      const baseline = reportedRanges(fixture.input);
      const shifted = reportedRanges(PREFIX + fixture.input).map(
        ([start, end]) => [start - SHIFT, end - SHIFT],
      );
      if (JSON.stringify(shifted) !== JSON.stringify(baseline)) {
        perturbed.push(`${fixture.id} (prefix)`);
      }
      const inputBytes = encoder.encode(fixture.input).length;
      if (fixture.expected.some((item) => item.end === inputBytes)) continue;
      const suffixed = reportedRanges(`${fixture.input} \u{1F511}`);
      if (JSON.stringify(suffixed) !== JSON.stringify(baseline)) {
        perturbed.push(`${fixture.id} (suffix)`);
      }
    }
    assert(
      perturbed.length === 0,
      `${perturbed.length} fixture(s) shifted: ${perturbed.slice(0, 5).join(", ")}`,
    );
  });

  check("scanAndRedact equals scan then redact and removes every match", () => {
    for (const fixture of synchronous) {
      if (fixture.expected.length === 0) continue;
      const separate = redact(fixture.input, scan(fixture.input));
      const combined = scanAndRedact(fixture.input);
      assertEqual(
        combined.text,
        separate,
        `fixture ${fixture.id} scanAndRedact disagreed with scan + redact`,
      );

      // Reconstruct the exact expected output from the fixture's own
      // findings, rather than searching the output for leftover matched
      // text: some fixtures (e.g. `contextual-positive-remaining-declared-
      // names`) legitimately repeat the same synthetic value across several
      // findings that resolve to different actions, so a `warn`/`allow`
      // finding can leave a byte-identical copy of a `redact`/`block`
      // finding's value elsewhere in the output. A blanket "does the output
      // still contain this value" search cannot tell that apart from an
      // actual redaction failure; an exact positional reconstruction can.
      let placeholderIndex = 0;
      let cursor = 0;
      const pieces = [];
      for (const finding of combined.findings) {
        if (finding.action !== "redact" && finding.action !== "block") continue;
        placeholderIndex += 1;
        pieces.push(fixture.input.slice(cursor, finding.range.start));
        pieces.push(`<SECRET_${placeholderIndex}>`);
        cursor = finding.range.end;
      }
      pieces.push(fixture.input.slice(cursor));
      assertEqual(
        combined.text,
        pieces.join(""),
        `fixture ${fixture.id} did not produce the exact expected redacted output`,
      );
    }
  });

  // The first fixture whose default-policy findings include one that is
  // redacted. Under `common` the first positive fixture can resolve only to
  // a `warn` finding, which a placeholder formatter never sees.
  const redacting = synchronous.find((entry) =>
    scan(entry.input).some(
      (finding) => finding.action === "redact" || finding.action === "block",
    ),
  );

  check("a throwing policy callback surfaces POLICY_FAILURE", () => {
    const fixture = redacting;
    assert(fixture !== undefined, "no redacting fixture to drive the policy");
    let thrown;
    try {
      scan(fixture.input, () => {
        throw new Error("boom");
      });
    } catch (error) {
      thrown = error;
    }
    assert(thrown !== undefined, "the throwing policy did not surface");
    assertEqual(errorCode(thrown), "POLICY_FAILURE", "policy failure code");
    assert(
      !String(thrown.message).includes(fixture.input),
      "the error carried the scanned input",
    );
  });

  check("a custom policy callback controls the action", () => {
    const fixture = redacting;
    assert(fixture !== undefined, "no redacting fixture to drive the policy");
    const findings = scan(fixture.input, () => "warn");
    assert(findings.length > 0, "no finding to apply the policy to");
    for (const finding of findings) {
      assertEqual(finding.action, "warn", `fixture ${fixture.id} action`);
    }
  });

  check("a custom placeholder formatter controls redaction output", () => {
    const fixture = redacting;
    assert(fixture !== undefined, "no redacting fixture to drive the formatter");
    const output = redact(
      fixture.input,
      scan(fixture.input),
      (_finding, context) => `[[REMOVED_${context.placeholderIndex}]]`,
    );
    assert(
      output.includes("[[REMOVED_1]]"),
      `fixture ${fixture.id} ignored the formatter`,
    );
  });

  return { ok: failures === 0, failures, checks: results };
}
