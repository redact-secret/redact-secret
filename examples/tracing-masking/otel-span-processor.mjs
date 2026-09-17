/**
 * The live OpenTelemetry JS integration:
 *
 * ```js
 * import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
 * import { createRedactingSpanProcessor } from "./otel-span-processor.mjs";
 *
 * const exportingProcessor = new BatchSpanProcessor(otlpExporter);
 * const provider = new NodeTracerProvider({
 *   spanProcessors: [await createRedactingSpanProcessor(exportingProcessor)],
 * });
 * ```
 *
 * `await initialize()` must resolve before `scanAndRedact` is used
 * (`packages/javascript/src/index.ts`); this factory enforces that order.
 * Not imported by `redact-span-attributes.test.mjs` — like
 * `examples/safe-integration/server.mjs`, it is exercised against the real
 * built package, not unit tested with a fake.
 */

import { initialize, scanAndRedact } from "@redact-secret/core";

import { RedactingSpanProcessorWith } from "./redact-span-attributes.mjs";

export { RedactingSpanProcessorWith } from "./redact-span-attributes.mjs";

/** Awaits `initialize()` once, then wraps `next` with the real scanner. */
export async function createRedactingSpanProcessor(next, options = {}) {
  await initialize();
  return new RedactingSpanProcessorWith(next, scanAndRedact, options);
}
