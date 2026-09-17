/**
 * A `SpanProcessor` (OpenTelemetry JS, pinned against
 * `@opentelemetry/sdk-trace-base@2.11.0` while resolving issue #326:
 * https://github.com/open-telemetry/opentelemetry-js/blob/main/packages/sdk-trace/src/SpanProcessor.ts)
 * that redacts every string and string-array attribute — including
 * OpenInference (`llm.input_messages`, `input.value`, ...) and GenAI
 * semantic-convention attributes (`gen_ai.prompt`, ...) — on a span and its
 * events before handing the span to the next processor. It does not
 * allowlist those attribute names: every string-shaped attribute value is
 * scanned, which covers any semantic convention without hardcoding it and
 * without a dependency on either convention's attribute list.
 *
 * `ReadableSpan.attributes` is typed `readonly` but is a plain, mutable
 * object at runtime (not frozen) — confirmed against the pinned SDK
 * version's source; `onEnd` mutates it in place, matching how community
 * OTel JS redaction processors work. This file never imports
 * `@opentelemetry/sdk-trace-base` — a `SpanProcessor` is a structural
 * (duck-typed) interface in JS, so wrapping one needs no dependency, and
 * this module, like `mask-secrets.mjs`, is testable with a plain object.
 */

import { maskLeafWith } from "./mask-leaf.mjs";

function maskAttributeValue(scanAndRedact, value, options) {
  if (typeof value === "string") {
    return maskLeafWith(scanAndRedact, value, options);
  }
  if (Array.isArray(value) && value.every((item) => typeof item === "string")) {
    return value.map((item) => maskLeafWith(scanAndRedact, item, options));
  }
  // Numbers, booleans, and homogeneous number/boolean arrays are the only
  // other attribute value shapes OpenTelemetry allows; none of them can
  // carry a secret as free text, so they pass through unchanged.
  return value;
}

/** Mutates `attributes` in place. A no-op for `undefined`/`null`. */
export function redactAttributesWith(scanAndRedact, attributes, options = {}) {
  if (attributes == null) return;
  for (const key of Object.keys(attributes)) {
    attributes[key] = maskAttributeValue(scanAndRedact, attributes[key], options);
  }
}

/**
 * Wraps `next` (any object shaped like a `SpanProcessor`) and redacts
 * every span's and event's string attributes before delegating to it.
 * `scanAndRedact` is injected so this class is testable without the built
 * native addon or a real OpenTelemetry dependency; see
 * `otel-span-processor.mjs` for the live factory that supplies both.
 */
export class RedactingSpanProcessorWith {
  constructor(next, scanAndRedact, options = {}) {
    if (typeof next?.onEnd !== "function") {
      throw new TypeError("RedactingSpanProcessorWith: next must be a SpanProcessor");
    }
    if (typeof scanAndRedact !== "function") {
      throw new TypeError("RedactingSpanProcessorWith: scanAndRedact must be a function");
    }
    this._next = next;
    this._scanAndRedact = scanAndRedact;
    this._options = options;
  }

  onStart(span, parentContext) {
    this._next.onStart?.(span, parentContext);
  }

  onEnd(span) {
    redactAttributesWith(this._scanAndRedact, span.attributes, this._options);
    for (const event of span.events ?? []) {
      redactAttributesWith(this._scanAndRedact, event.attributes, this._options);
    }
    this._next.onEnd(span);
  }

  shutdown() {
    return this._next.shutdown();
  }

  forceFlush() {
    return this._next.forceFlush ? this._next.forceFlush() : Promise.resolve();
  }
}
