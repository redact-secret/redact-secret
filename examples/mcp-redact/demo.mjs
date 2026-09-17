#!/usr/bin/env node
/**
 * Side-by-side demo for issue #327: the same synthetic tool result — a
 * secret leaked into a tool's stdout, the scenario the issue opens with —
 * run through block-all behavior (Docker MCP Gateway's default
 * `--block-secrets`: any match rejects the whole call,
 * `pkg/interceptors/block_secrets.go`) and through this middleware's
 * redact behavior.
 *
 * Uses the real, built `@redact-secret/core` (`npm run js:build` first),
 * not a fake — like `examples/safe-integration/server.mjs`, this file is
 * exercised against the real package rather than unit tested.
 *
 * Run: `node examples/mcp-redact/demo.mjs`
 */

import { initialize, scanAndRedact } from "@redact-secret/core";

import { buildBlockedResult, redactToolResult } from "./redact-tool-call.mjs";

await initialize();

// AKIA + SYNTHETICEXAMPLE: this repo's synthetic AWS access key ID, also
// used in `crates/secret-scan-core/src/detectors/aws.rs`'s own tests — not
// a real credential.
const syntheticToolResult = {
  content: [
    {
      type: "text",
      text: [
        "Deploy finished. Captured environment for debugging:",
        "AWS_ACCESS_KEY_ID=AKIASYNTHETICEXAMPLE",
        "DATABASE_URL=postgres://app:pw@db.internal:5432/app",
        "Build artifact: build-8421.tar.gz (142 MB)",
      ].join("\n"),
    },
  ],
};

function blockAll(result) {
  // The behavior this issue is responding to: any finding anywhere rejects
  // the whole call, with no partial or sanitized result ever returned.
  const probe = redactToolResult(scanAndRedact, result, {});
  const hasFindings = probe.outcome === "blocked" || probe.findings.length > 0;
  return hasFindings ? { rejected: true, reason: "secret detected; call rejected outright" } : result;
}

function redact(result) {
  const outcome = redactToolResult(scanAndRedact, result, {});
  return outcome.outcome === "blocked" ? buildBlockedResult() : outcome.result;
}

console.log("Synthetic tool result:\n" + JSON.stringify(syntheticToolResult, null, 2) + "\n");

console.log("=== block-all (Docker MCP Gateway --block-secrets style) ===");
console.log(JSON.stringify(blockAll(syntheticToolResult), null, 2) + "\n");

console.log("=== redact (examples/mcp-redact) ===");
console.log(JSON.stringify(redact(syntheticToolResult), null, 2));
