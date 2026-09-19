/**
 * The `common`-profile Web Streams adapter: the same byte-to-string
 * `TransformStream` as `./web-stream.ts`, opened against the `common`
 * runtime instead of `full`
 * (`decision-define-detector-profile-and-pack-contract`).
 *
 * This module is reached only through the package's `./common/web-stream`
 * subpath. It imports `runtime` from `../session-common.js`, never
 * `../session.js`, and shares the `WebStreamSanitizer` class with
 * `./web-stream.ts` through `./web-stream-core.js` rather than importing
 * `./web-stream.ts` directly — that would pull the `full` runtime binding,
 * and in a browser bundle the `full` WebAssembly artifact, in alongside this
 * one. It imports nothing from `node:`.
 *
 * ```ts
 * await initialize();
 * await response.body.pipeThrough(createWebStreamSanitizer({ limits }))
 *   .pipeTo(destination);
 * ```
 */

import { runtime } from "../session-common.js";
import type { IncrementalSanitizerOptions } from "../types.js";

import { WebStreamSanitizer } from "./web-stream-core.js";

/**
 * Opens one incremental `common`-profile session and wraps it in a Web
 * transform.
 *
 * Requires a successful `await initialize()` from
 * `@redact-secret/core/common`; it throws `NOT_INITIALIZED` otherwise.
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
