#!/usr/bin/env node
/**
 * End-to-end smoke test for the tracing reference (issue #611):
 * `npm run reference:tracing` from the repository root.
 *
 * The real OpenTelemetry SDK, the released `@redact-secret/adapter-otel`,
 * and the released `@redact-secret/core`, all installed from the registry
 * by `npm ci`. Every value below is synthetic. The exported spans are
 * checked for every synthetic value before anything is printed, so a
 * failure never prints plaintext, and nothing is written to disk.
 */

import assert from "node:assert/strict";

import { InMemorySpanExporter } from "@opentelemetry/sdk-trace-base";

import { createAppMaskCallback, createAppTracerProvider } from "./app.mjs";

// Unmistakably synthetic: AKIA + SYNTHETICEXAMPLE is this repository's
// synthetic AWS access key ID; the others say what they are.
const SYNTHETIC = Object.freeze({
  awsKeyId: "AKIASYNTHETICEXAMPLE",
  apiKey: "synthetic-example-value-0000",
  bearer: "synthetic.example.token",
  password: "synthetic-not-a-secret",
});

const blockAwsKeys = Object.freeze({
  evaluate: (finding) => (finding.type === "aws_access_key_id" ? "block" : "redact"),
});
const failingPolicy = Object.freeze({
  evaluate: () => {
    throw new Error("policy failure (synthetic)");
  },
});

/** What the exporter received: only the fields the adapter protects. */
function exported(exporter) {
  return exporter.getFinishedSpans().map((span) => ({
    attributes: { ...span.attributes },
    events: span.events.map((event) => ({ name: event.name, attributes: { ...event.attributes } })),
  }));
}

const checks = [];
async function scenario(name, options, run, expect) {
  const exporter = new InMemorySpanExporter();
  const provider = await createAppTracerProvider({ exporter, ...options });
  run(provider.getTracer("reference-smoke"));
  await provider.forceFlush();
  const spans = exported(exporter);
  await provider.shutdown();
  const serialized = JSON.stringify(spans);
  for (const value of Object.values(SYNTHETIC)) {
    // A fixed message: the assertion must not echo the exported span.
    assert.ok(!serialized.includes(value), `${name}: a synthetic secret reached the exporter`);
  }
  expect(spans[0]);
  checks.push({ name, serialized });
}

await scenario(
  "GenAI and OpenInference attributes",
  {},
  (tracer) => {
    const span = tracer.startSpan("chat");
    span.setAttribute("gen_ai.prompt", `Use ${SYNTHETIC.awsKeyId} to deploy`);
    span.setAttribute("input.value", `api_key=${SYNTHETIC.apiKey}`);
    span.setAttribute("llm.input_messages", [`Authorization: Bearer ${SYNTHETIC.bearer}`, "hello"]);
    span.setAttribute("gen_ai.usage.input_tokens", 12);
    span.end();
  },
  (span) => {
    assert.equal(span.attributes["gen_ai.prompt"], "Use <SECRET_1> to deploy");
    assert.equal(span.attributes["input.value"], "api_key=<SECRET_1>");
    assert.deepEqual(span.attributes["llm.input_messages"], ["Authorization: Bearer <SECRET_1>", "hello"]);
    assert.equal(span.attributes["gen_ai.usage.input_tokens"], 12);
  },
);
await scenario(
  "exception event",
  {},
  (tracer) => {
    const span = tracer.startSpan("tool-call");
    span.recordException(new Error(`tool failed with password=${SYNTHETIC.password}`));
    span.end();
  },
  (span) => {
    const event = span.events.find((e) => e.name === "exception");
    assert.equal(event.attributes["exception.message"], "tool failed with password=<SECRET_1>");
  },
);
await scenario(
  "block replaces the whole attribute",
  { policy: blockAwsKeys },
  (tracer) => {
    const span = tracer.startSpan("chat");
    span.setAttribute("gen_ai.prompt", `Use ${SYNTHETIC.awsKeyId} to deploy`);
    span.end();
  },
  (span) => assert.equal(span.attributes["gen_ai.prompt"], "[REDACTED:BLOCKED]"),
);
await scenario(
  "oversized attribute is not scanned and not exported",
  { maxStringLength: 64 },
  (tracer) => {
    const span = tracer.startSpan("chat");
    span.setAttribute("gen_ai.completion", `${"x".repeat(80)} ${SYNTHETIC.awsKeyId}`);
    span.end();
  },
  (span) => assert.equal(span.attributes["gen_ai.completion"], "[REDACTED:LIMIT_EXCEEDED]"),
);
await scenario(
  "core failure fails closed",
  { policy: failingPolicy },
  (tracer) => {
    const span = tracer.startSpan("chat");
    span.setAttribute("gen_ai.prompt", `Use ${SYNTHETIC.awsKeyId} to deploy`);
    span.end();
  },
  (span) => assert.equal(span.attributes["gen_ai.prompt"], "[REDACTED:ERROR]"),
);

// The masking callback, on a nested trace payload.
{
  const maskSecrets = await createAppMaskCallback();
  const masked = maskSecrets({
    input: [{ role: "user", content: `Use ${SYNTHETIC.awsKeyId} to deploy` }],
    metadata: { upstream: `Authorization: Bearer ${SYNTHETIC.bearer}`, attempts: 2 },
  });
  const serialized = JSON.stringify(masked);
  for (const value of Object.values(SYNTHETIC)) {
    assert.ok(!serialized.includes(value), "mask callback: a synthetic secret survived masking");
  }
  assert.equal(masked.input[0].content, "Use <SECRET_1> to deploy");
  assert.equal(masked.metadata.attempts, 2);
  checks.push({ name: "masking callback (Langfuse-style)", serialized });
}

for (const { name, serialized } of checks) console.log(`ok - ${name}: ${serialized.slice(0, 160)}`);
console.log(`\ntracing reference: ${checks.length} scenarios passed, no synthetic secret reached the exporter`);
