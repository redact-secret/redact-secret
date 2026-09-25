/**
 * Reference architecture: OpenTelemetry tracing (issue #611).
 *
 * The whole integration is this file. Redaction runs inside the released
 * `@redact-secret/adapter-otel` package, installed from the npm registry at
 * the exact version `package-lock.json` pins, over the released
 * `@redact-secret/core`. Nothing here copies adapter code.
 *
 * The redacting processor wraps the processor that feeds the exporter, so
 * its `onEnd` is the authoritative scan point for everything that exporter
 * sends: span and span-event attributes are redacted in place before the
 * wrapped processor, and therefore the exporter, sees the span.
 */

import { BasicTracerProvider, SimpleSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { createMaskSecrets } from "@redact-secret/adapter";
import { createRedactingSpanProcessor } from "@redact-secret/adapter-otel";

/**
 * Creates the application's tracer provider. `exporter` is any span
 * exporter (OTLP in production; the smoke test passes an in-memory one).
 * Production hosts usually wrap a `BatchSpanProcessor` the same way.
 *
 * @param {{ exporter: import("@opentelemetry/sdk-trace-base").SpanExporter, policy?: object, maxStringLength?: number }} options
 */
export async function createAppTracerProvider({ exporter, policy, maxStringLength }) {
  // Awaits the core's `initialize()` once, before the first span ends.
  const redacting = await createRedactingSpanProcessor(new SimpleSpanProcessor(exporter), { policy, maxStringLength });
  // The redacting processor must be the only path to an exporter: a
  // processor listed beside it would see the span before it is redacted.
  return new BasicTracerProvider({ spanProcessors: [redacting] });
}

/**
 * The masking callback for a tracing SDK that hands the host a value to
 * mask before export, such as Langfuse's `mask` option:
 *
 * ```js
 * const maskSecrets = await createAppMaskCallback();
 * const langfuse = new Langfuse({ mask: ({ data }) => maskSecrets(data) });
 * ```
 *
 * Its scan point is authoritative only for what that SDK routes through
 * `mask`. It comes from the released `@redact-secret/adapter`; Langfuse
 * itself is not installed here.
 *
 * @param {{ policy?: object, limits?: object }} [options]
 */
export function createAppMaskCallback(options = {}) {
  return createMaskSecrets(options);
}
