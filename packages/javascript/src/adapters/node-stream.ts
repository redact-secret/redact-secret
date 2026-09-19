/**
 * The Node.js stream adapter: a byte-to-byte `Transform` over one incremental
 * session (`decision-define-runtime-bindings`).
 *
 * This module is reached only through the package's `./node-stream` subpath,
 * and its `createNodeStreamSanitizer` always opens a `full`-profile session.
 * For a `common` byte stream, use `@redact-secret/core/common/node-stream`
 * instead, which shares the `NodeStreamSanitizer` class defined in
 * `./node-stream-core.ts` with this module but binds the factory to the
 * `common` runtime.
 *
 * It is the one published module that imports `node:stream`; the root export
 * and `./web-stream` never resolve a Node-only module, so a browser bundle
 * that uses them pulls none of this in.
 *
 * ```ts
 * await initialize();
 * await pipeline(source, createNodeStreamSanitizer({ limits }), destination);
 * ```
 *
 * Backpressure, error propagation, and teardown are Node's own: the transform
 * pushes into its readable side and lets the stream machinery stall the
 * producer, and `_destroy` — which Node runs for `destroy()`, for a failed
 * `pipeline`, and for a downstream error alike — aborts the session so the
 * plaintext it was still deciding about is discarded rather than flushed.
 */

import { runtime } from "../session.js";
import type { IncrementalSanitizerOptions } from "../types.js";

import { NodeStreamSanitizer } from "./node-stream-core.js";

/**
 * Opens one incremental `full`-profile session and wraps it in a Node
 * transform.
 *
 * Requires a successful `await initialize()`, like every other synchronous
 * operation in this package; it throws `NOT_INITIALIZED` otherwise.
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
