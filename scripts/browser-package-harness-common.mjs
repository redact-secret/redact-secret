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
 * Deliberately does NOT import `@redact-secret/core/web-stream`:
 * `packages/javascript/src/adapters/web-stream.ts` imports `runtime` from
 * `../session.js` at module scope, unconditionally — the `full` runtime —
 * so merely importing anything from that module would pull `full`'s
 * WebAssembly artifact loader into this bundle, defeating the point of
 * qualifying `common` on its own. `browser-package-harness-core.mjs` skips
 * every stream-adapter check when `WebStreamSanitizer` is omitted, so this
 * is a real, recorded coverage gap (the `common` package page cannot qualify
 * the stream adapters at all today), not a workaround that silently drops
 * coverage — see the issue #382 evidence record.
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
} from "@redact-secret/core/common";

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
  });
