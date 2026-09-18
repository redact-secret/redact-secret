/**
 * The `full`-profile in-page half of `scripts/qualify-browser-artifact.mjs`:
 * the published package's default entry (`@redact-secret/core`), running in a
 * real browser on the real `full` WebAssembly artifact.
 *
 * This is a thin, literal-import wrapper — a bundler needs a static specifier
 * to resolve and include the right compiled artifact, so this file cannot
 * import its entry dynamically or take it as a parameter. Everything else
 * lives in `./browser-package-harness-core.mjs`, shared with the `common`
 * profile's `./browser-package-harness-common.mjs`.
 */

import {
  RANGE_UNIT,
  SecretScanError,
  VERSION,
  createIncrementalSanitizer,
  initialize,
  redact,
  scan,
  scanAndRedact,
} from "@redact-secret/core";
import { WebStreamSanitizer } from "@redact-secret/core/web-stream";

import { qualify as qualifyCore } from "./browser-package-harness-core.mjs";

export const qualify = (fixtures) =>
  qualifyCore(fixtures, {
    RANGE_UNIT,
    SecretScanError,
    VERSION,
    createIncrementalSanitizer,
    initialize,
    redact,
    scan,
    scanAndRedact,
    WebStreamSanitizer,
  });
