#!/usr/bin/env node
/**
 * End-to-end smoke test for the logging reference (issue #611):
 * `npm run reference:logging` from the repository root.
 *
 * Real pino, the released `@redact-secret/adapter-pino`, and the released
 * `@redact-secret/core`, all installed from the registry by `npm ci`. Every
 * value below is synthetic. The captured log bytes are checked for every
 * synthetic value before any line is printed, so a failure never prints
 * plaintext, and nothing is written to disk.
 */

import assert from "node:assert/strict";

import { createAppLogger } from "./app.mjs";

// Unmistakably synthetic: AKIA + SYNTHETICEXAMPLE is this repository's
// synthetic AWS access key ID; the others say what they are.
const SYNTHETIC = Object.freeze({
  awsKeyId: "AKIASYNTHETICEXAMPLE",
  apiKey: "synthetic-example-value-0000",
  bearer: "synthetic.example.token",
  password: "synthetic-not-a-secret",
});

function memoryDestination() {
  const lines = [];
  return { lines, write: (chunk) => void lines.push(String(chunk)) };
}

const blockAwsKeys = Object.freeze({
  evaluate: (finding) => (finding.type === "aws_access_key_id" ? "block" : "redact"),
});
const failingPolicy = Object.freeze({
  evaluate: () => {
    throw new Error("policy failure (synthetic)");
  },
});

const checks = [];
async function scenario(name, options, run, expect) {
  const destination = memoryDestination();
  const logger = await createAppLogger({ destination, ...options });
  run(logger);
  const output = destination.lines.join("");
  for (const value of Object.values(SYNTHETIC)) {
    // A fixed message: the assertion must not echo the captured bytes.
    assert.ok(!output.includes(value), `${name}: a synthetic secret reached the log destination`);
  }
  for (const needle of expect) {
    assert.ok(output.includes(needle), `${name}: expected ${JSON.stringify(needle)} in the log line`);
  }
  checks.push({ name, output: output.trimEnd() });
}

await scenario("message", {}, (log) => log.info(`deploy used ${SYNTHETIC.awsKeyId}`), ["deploy used <SECRET_1>"]);
await scenario("interpolation", {}, (log) => log.info("api_key=%s", SYNTHETIC.apiKey), ["api_key=<SECRET_1>"]);
await scenario(
  "merging object",
  {},
  (log) => log.info({ upstream: { header: `Authorization: Bearer ${SYNTHETIC.bearer}` } }, "proxied"),
  ["Authorization: Bearer <SECRET_1>"],
);
// `login failed: password=...` is detected from core #812 on; the pinned
// released beta.8 predates it, so this keeps the `with` form until the core
// pin moves past beta.8 (see README "Detection gaps").
await scenario(
  "error",
  {},
  (log) => log.error(new Error(`login failed with password=${SYNTHETIC.password}`)),
  ["login failed with password=<SECRET_1>"],
);
await scenario(
  "path redact still applies",
  {},
  (log) => log.info({ req: { headers: { authorization: "opaque" } } }, "request"),
  ['"authorization":"[Redacted]"'],
);
await scenario(
  "block replaces the whole message",
  { policy: blockAwsKeys },
  (log) => log.info(`deploy used ${SYNTHETIC.awsKeyId}`),
  ['"msg":"[REDACTED:BLOCKED]"'],
);
await scenario(
  "oversized field is not scanned and not written",
  { limits: { maxStringLength: 64 } },
  (log) => log.info(`${"x".repeat(80)} ${SYNTHETIC.awsKeyId}`),
  ['"msg":"[REDACTED:LIMIT_EXCEEDED]"'],
);
await scenario(
  "core failure fails closed",
  { policy: failingPolicy },
  (log) => log.info(`deploy used ${SYNTHETIC.awsKeyId}`),
  ['"msg":"[REDACTED:ERROR]"'],
);

for (const { name, output } of checks) console.log(`ok - ${name}: ${output.slice(0, 160)}`);
console.log(`\nlogging reference: ${checks.length} scenarios passed, no synthetic secret reached the destination`);
