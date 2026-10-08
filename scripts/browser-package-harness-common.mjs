/**
 * The `common`-profile in-page half of `scripts/qualify-browser-artifact.mjs`:
 * the published package's opt-in `@redact-secret/core/common` entry, running
 * in a real browser on the real `common` WebAssembly artifact
 * (`decision-define-detector-profile-and-pack-contract`).
 *
 * This is a thin, literal-import wrapper — a bundler needs a static specifier
 * to resolve and include the right compiled artifact, so this file cannot
 * import its entry dynamically or share one with `./browser-package-harness.mjs`.
 * Everything else lives in `./browser-package-harness-core.mjs`, shared with
 * the `full` profile.
 *
 * The common stream subpath opens the same common runtime, so these checks
 * also qualify its public factory without importing the full artifact.
 */

import {
  compareActionPolicies,
  createIncrementalSanitizer,
  initialize,
  RANGE_UNIT,
  redact,
  SecretScanError,
  scan,
  scanAndRedact,
  VERSION,
} from "@redact-secret/core/common";
import { createWebStreamSanitizer, WebStreamSanitizer } from "@redact-secret/core/common/web-stream";

import { qualify as qualifyCore } from "./browser-package-harness-core.mjs";

export const qualify = (fixtures) =>
  qualifyCore(fixtures, {
    RANGE_UNIT,
    SecretScanError,
    VERSION,
    compareActionPolicies,
    createIncrementalSanitizer,
    initialize,
    redact,
    scan,
    scanAndRedact,
    createWebStreamSanitizer,
    WebStreamSanitizer,
  });
