/**
 * The `full`-profile entry for `scripts/assessment-browser-performance.mjs`.
 * See `./assessment-browser-performance-harness-core.mjs` for the shared body
 * and why this stays a thin, literal-import wrapper.
 */
import { createIncrementalSanitizer, initialize, scanAndRedact } from "@redact-secret/core";

import { measure as measureCore } from "./assessment-browser-performance-harness-core.mjs";

export const measure = (profile) =>
  measureCore(profile, { createIncrementalSanitizer, initialize, scanAndRedact });
