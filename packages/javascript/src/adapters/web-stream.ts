/**
 * The Web Streams adapter: a byte-to-string `TransformStream` over one
 * incremental session (`decision-define-runtime-bindings`).
 *
 * This module is reached through the package's `./web-stream` subpath, and
 * its `createWebStreamSanitizer` always opens a `full`-profile session. For a
 * `common` byte stream, use `@redact-secret/core/common/web-stream` instead,
 * which shares the `WebStreamSanitizer` class defined in
 * `./web-stream-core.ts` with this module but binds the factory to the
 * `common` runtime.
 *
 * This module imports nothing from `node:`, so a browser bundle resolves
 * only it, `./web-stream-core.js`, the root module, and the WebAssembly
 * artifact.
 *
 * ```ts
 * await initialize();
 * await response.body.pipeThrough(createWebStreamSanitizer({ limits }))
 *   .pipeTo(destination);
 * ```
 */

import { runtime } from "../session.js";
import type { IncrementalSanitizerOptions } from "../types.js";

import { WebStreamSanitizer } from "./web-stream-core.js";

/**
 * Opens one incremental `full`-profile session and wraps it in a Web
 * transform.
 *
 * Requires a successful `await initialize()`, like every other synchronous
 * operation in this package; it throws `NOT_INITIALIZED` otherwise.
 */
export function createWebStreamSanitizer(
  options: IncrementalSanitizerOptions,
): WebStreamSanitizer {
  return new WebStreamSanitizer(runtime.createIncrementalSanitizer(options));
}

export { WebStreamSanitizer } from "./web-stream-core.js";
export { SecretScanError } from "../errors.js";
export type { SecretScanErrorCode } from "../errors.js";
export type {
  IncrementalLimits,
  IncrementalSanitizer,
  IncrementalSanitizerOptions,
  IncrementalSecretPolicy,
  SecretFinding,
} from "../types.js";
