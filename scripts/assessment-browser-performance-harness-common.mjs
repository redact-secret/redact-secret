/**
 * The `common`-profile entry for `scripts/assessment-browser-performance.mjs`
 * (`decision-define-detector-profile-and-pack-contract`). See
 * `./assessment-browser-performance-harness-core.mjs` for the shared body and
 * why this stays a thin, literal-import wrapper.
 *
 * `runtime.ts`'s `initialize()` rejects a loaded artifact whose `profile()`
 * disagrees with the facade it loaded through
 * (`packages/javascript/src/runtime.ts`), so measuring the `common` `.wasm`
 * requires importing it through the `@redact-secret/core/common` facade, not
 * the `full` facade's `@redact-secret/wasm` import aliased to the `common`
 * glue file. This entry point exists so the measurement uses the facade
 * that actually matches the artifact.
 */
import { createIncrementalSanitizer, initialize, scanAndRedact } from "@redact-secret/core/common";

import { measure as measureCore } from "./assessment-browser-performance-harness-core.mjs";

export const measure = (profile) =>
  measureCore(profile, { createIncrementalSanitizer, initialize, scanAndRedact });
