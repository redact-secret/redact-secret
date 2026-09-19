/**
 * The re-exports and derived constants `index.ts` and `common.ts` both
 * expose verbatim, one profile-independent public surface factored here
 * instead of duplicated across the package's two entry points. Each entry
 * point still binds its own five operations directly to its own `runtime`
 * (`./session.js` or `./session-common.js`), since that is the one part of
 * the surface that genuinely differs per profile.
 */

import type { RangeUnit } from "./types.js";

export {
  defaultPlaceholderFormatter,
  typedPlaceholderFormatter,
} from "./formatters.js";
export { SecretScanError } from "./errors.js";
export type { SecretScanErrorCode } from "./errors.js";
export { VERSION } from "./version.js";

/** The string-index unit of every range this package reports. */
export const RANGE_UNIT: RangeUnit = "utf16-code-units";

export type {
  DetectedSecretFinding,
  IncrementalLimits,
  IncrementalPolicyContext,
  IncrementalSanitizer,
  IncrementalSanitizerOptions,
  IncrementalSanitizerResult,
  IncrementalSanitizerState,
  IncrementalSecretPolicy,
  PlaceholderContext,
  PlaceholderFormatter,
  PolicyContext,
  RangeUnit,
  RedactOptions,
  ScanAndRedactOptions,
  ScanOptions,
  ScanResult,
  SecretAction,
  SecretConfidence,
  SecretFinding,
  SecretPolicy,
  WholeInputLimits,
} from "./types.js";
