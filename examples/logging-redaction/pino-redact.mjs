/**
 * The live pino integration:
 *
 * ```js
 * import pino from "pino";
 * import { createRedactingLogMethod } from "./pino-redact.mjs";
 *
 * const logMethod = await createRedactingLogMethod();
 * const logger = pino({
 *   hooks: { logMethod },
 *   redact: ["req.headers.authorization"], // pino's own path-based redact still applies, on top
 * });
 * ```
 *
 * `await initialize()` must resolve before `scanAndRedact` is used
 * (`packages/javascript/src/index.ts`); this factory enforces that order,
 * same as `examples/tracing-masking/langfuse-mask.mjs`. Not imported by
 * `pino-hook.test.mjs` -- like `examples/safe-integration/server.mjs`,
 * this thin file is exercised against the real built package, not unit
 * tested with a fake.
 */

import { initialize, scanAndRedact } from "@redact-secret/core";

import { createRedactingLogMethodWith } from "./pino-hook.mjs";

/** Awaits `initialize()` once, then returns a pino `hooks.logMethod`. */
export async function createRedactingLogMethod(options = {}) {
  await initialize();
  return createRedactingLogMethodWith(scanAndRedact, options);
}
