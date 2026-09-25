#!/usr/bin/env node
/**
 * Side-by-side demo for issue #327: the same synthetic tool result — a
 * secret leaked into a tool's stdout, the scenario the issue opens with —
 * run through block-all behavior (Docker MCP Gateway's default
 * `--block-secrets`: any match rejects the whole call,
 * `pkg/interceptors/block_secrets.go`) and through this middleware's
 * redact behavior, on the AI-context boundary.
 *
 * Uses the real `@redact-secret/core`, not a fake, through the pinned
 * `@redact-secret/adapter-ai-context` (see README § Running the demo for
 * how to make both resolvable here).
 *
 * Run: `node examples/mcp-redact/demo.mjs`
 */

import { createGoldenPathBoundary } from "./agent-context.mjs";
import { buildBlockedResult, redactToolResult } from "./redact-tool-call.mjs";

const boundary = await createGoldenPathBoundary();

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
  const probe = redactToolResult(boundary, result);
  const hasFindings = probe.outcome !== "ok" || probe.findings.length > 0;
  return hasFindings ? { rejected: true, reason: "secret detected; call rejected outright" } : result;
}

function redact(result) {
  const outcome = redactToolResult(boundary, result);
  return outcome.outcome === "ok" ? outcome.value : buildBlockedResult();
}

// Never print the unscanned result: no example logs raw input before scanning
// (issue #587), even a synthetic one. Only its shape is shown.
console.log(`Synthetic tool result: ${syntheticToolResult.content.length} content item(s), not printed before scanning\n`);

console.log("=== block-all (Docker MCP Gateway --block-secrets style) ===");
console.log(JSON.stringify(blockAll(syntheticToolResult), null, 2) + "\n");

console.log("=== redact (examples/mcp-redact) ===");
console.log(JSON.stringify(redact(syntheticToolResult), null, 2));
