/**
 * The live Langfuse JS integration. `await initialize()` must resolve
 * before this module's `scanAndRedact` is used
 * (`packages/javascript/src/index.ts`); `createMaskSecrets` enforces that
 * order so a caller can't forget it. Not imported by
 * `mask-secrets.test.mjs` — like `examples/safe-integration/server.mjs`,
 * this thin file is exercised against the real built package, not unit
 * tested with a fake.
 *
 * Langfuse JS's `mask` option receives `{ data }`, where `data` is the
 * stringified JSON of the attribute's value, and must return the masked
 * string (https://langfuse.com/docs/observability/features/masking,
 * confirmed against the current docs while resolving issue #326):
 *
 * ```js
 * import { Langfuse } from "langfuse";
 * import { createMaskSecrets } from "./langfuse-mask.mjs";
 *
 * const maskSecrets = await createMaskSecrets();
 * const langfuse = new Langfuse({ mask: ({ data }) => maskSecrets(data) });
 * ```
 *
 * `maskSecrets` also accepts a parsed object/array directly (not only a
 * JSON string), so the same function works for the generic
 * "mask this payload before tracing" case the issue describes, not only
 * Langfuse's stringified form.
 */

import { initialize, scanAndRedact } from "@redact-secret/core";

import { maskSecretsWith } from "./mask-secrets.mjs";

/**
 * Awaits `initialize()` once, then returns `maskSecrets(data)`: a
 * single-argument function matching the issue's proposed signature and
 * ready to wrap for Langfuse's `mask: ({ data }) => maskSecrets(data)`.
 */
export async function createMaskSecrets(options = {}) {
  await initialize();
  return (data) => maskSecretsWith(scanAndRedact, data, options);
}
