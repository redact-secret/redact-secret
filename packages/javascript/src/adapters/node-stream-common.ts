/**
 * The `common`-profile Node.js stream adapter: the same byte-to-byte
 * `Transform` as `./node-stream.ts`, opened against the `common` runtime
 * instead of `full` (`decision-define-detector-profile-and-pack-contract`).
 *
 * This module is reached only through the package's `./common/node-stream`
 * subpath. It imports `runtime` from `../session-common.js`, never
 * `../session.js`, and shares the `NodeStreamSanitizer` class with
 * `./node-stream.ts` through `./node-stream-core.js` rather than importing
 * `./node-stream.ts` directly — that would pull the `full` runtime binding
 * in alongside this one.
 *
 * ```ts
 * await initialize();
 * await pipeline(source, createNodeStreamSanitizer({ limits }), destination);
 * ```
 */

import { runtime } from "../session-common.js";
import type { IncrementalSanitizerOptions } from "../types.js";

import { NodeStreamSanitizer } from "./node-stream-core.js";

/**
 * Opens one incremental `common`-profile session and wraps it in a Node
 * transform.
 *
 * Requires a successful `await initialize()` from
 * `@redact-secret/core/common`; it throws `NOT_INITIALIZED` otherwise.
 */
export function createNodeStreamSanitizer(
  options: IncrementalSanitizerOptions,
): NodeStreamSanitizer {
  return new NodeStreamSanitizer(runtime.createIncrementalSanitizer(options));
}

export { NodeStreamSanitizer } from "./node-stream-core.js";
export { SecretScanError } from "../errors.js";
export type { SecretScanErrorCode } from "../errors.js";
export type {
  IncrementalLimits,
  IncrementalSanitizer,
  IncrementalSanitizerOptions,
  IncrementalSecretPolicy,
  SecretFinding,
} from "../types.js";
