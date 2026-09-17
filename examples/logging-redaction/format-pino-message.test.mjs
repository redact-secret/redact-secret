/**
 * Confirms `formatPinoMessage` (`./format-pino-message.mjs`) is byte-for-byte
 * identical to the real `quick-format-unescaped` package -- the same
 * dependency pino `10.3.1` requires directly and calls to format `msg`
 * (`lib/tools.js:6`) -- across every placeholder pino's own algorithm
 * branches on, plus the edge cases documented in `format-pino-message.mjs`'s
 * module docstring (unmatched placeholders, unused trailing values, `%%`).
 * `quick-format-unescaped` is an explicit devDependency, pinned to the exact
 * version pino `10.3.1` resolves (`^4.0.3` -> `4.0.4`), so this is a
 * conformance check against the real algorithm, not a description of it.
 */

import assert from "node:assert/strict";
import test from "node:test";

import realFormat from "quick-format-unescaped";

import { formatPinoMessage } from "./format-pino-message.mjs";

const cases = [
  { name: "single %s", fmt: "user %s logged in", values: ["alice"] },
  { name: "multiple %s", fmt: "user %s presented %s", values: ["alice", "SECRET_TOKEN_1"] },
  { name: "%d formats a number", fmt: "count is %d", values: [3] },
  { name: "%d coerces a numeric string", fmt: "count is %d", values: ["3"] },
  { name: "%f formats a float", fmt: "ratio is %f", values: [0.5] },
  { name: "%i floors a float", fmt: "count is %i", values: [3.9] },
  { name: "%j stringifies a plain object", fmt: "payload %j", values: [{ a: 1 }] },
  { name: "%o stringifies a plain object", fmt: "payload %o", values: [{ a: 1 }] },
  { name: "%O stringifies a plain object", fmt: "payload %O", values: [{ a: 1 }] },
  { name: "%o quotes a string value", fmt: "value %o", values: ["text"] },
  { name: "%o names a function value", fmt: "fn %o", values: [function named() {}] },
  { name: "%o anonymizes an anonymous function", fmt: "fn %o", values: [() => {}] },
  { name: "%% is a literal percent and consumes no value", fmt: "100%% done, %s left", values: ["nothing"] },
  { name: "an unmatched placeholder is left as literal text", fmt: "user %s presented %s", values: ["alice"] },
  { name: "an unused trailing value is dropped, not appended", fmt: "no placeholders here", values: ["SECRET_TOKEN_1"] },
  { name: "no placeholders, no values", fmt: "plain message", values: [] },
  { name: "a null interpolation value for %s stringifies as 'null'", fmt: "value is %s", values: [null] },
  { name: "a null interpolation value for %d is skipped", fmt: "count is %d", values: [null] },
  { name: "a boolean interpolation value", fmt: "active is %s", values: [true] },
  { name: "consecutive placeholders with no separator", fmt: "%s%s", values: ["SECRET_TOKEN_", "1"] },
  { name: "a trailing bare % with nothing after it", fmt: "100% done", values: ["x"] },
  { name: "unicode text around a placeholder", fmt: "café %s 中文", values: ["🔑"] },
];

test("formatPinoMessage matches the real quick-format-unescaped package byte-for-byte", () => {
  for (const { name, fmt, values } of cases) {
    const expected = realFormat(fmt, values);
    const actual = formatPinoMessage(fmt, values);
    assert.equal(actual, expected, `case: ${name}`);
  }
});

test("no interpolation values returns the format string unchanged, without scanning it for placeholders", () => {
  assert.equal(formatPinoMessage("100%% raw, %s untouched", []), "100%% raw, %s untouched");
});
