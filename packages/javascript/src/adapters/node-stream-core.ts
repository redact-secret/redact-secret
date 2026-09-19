/**
 * The runtime-neutral half of the Node.js stream adapter: the
 * `NodeStreamSanitizer` class itself, which wraps whatever incremental
 * session its constructor is given rather than opening one against a
 * specific detector profile (`decision-define-runtime-bindings`).
 *
 * `./node-stream.ts` (the `full` convenience factory) and
 * `./node-stream-common.ts` (the `common` one) both import the class from
 * here and re-export it, rather than importing it from each other: either
 * direction would pull that profile's `../session.js`/`../session-common.js`
 * binding — and, transitively, that profile's own `#native`/`#native-common`
 * import — into a bundle that only wants the other profile's factory. This
 * module itself imports neither `../session.js` nor `../session-common.js`.
 */

import { Transform } from "node:stream";
import type { TransformCallback } from "node:stream";

import type { IncrementalSanitizer, SecretFinding } from "../types.js";

import { createStreamSanitizerRuntime } from "./shared.js";

/** A byte-to-byte Node transform backed by one incremental session. */
export class NodeStreamSanitizer extends Transform {
  readonly #runtime;

  /**
   * Wraps `session`, which this transform owns: it is finalized when the
   * stream ends normally and aborted on every other exit.
   */
  constructor(session: IncrementalSanitizer) {
    super();
    this.#runtime = createStreamSanitizerRuntime(session);
  }

  /**
   * Every finding the session has finalized so far, frozen, with absolute
   * UTF-16 offsets into the logical whole-stream input. It stays empty when
   * the stream is destroyed before anything settles.
   */
  get findings(): readonly SecretFinding[] {
    return this.#runtime.findings;
  }

  override _transform(
    chunk: Uint8Array,
    _encoding: BufferEncoding,
    callback: TransformCallback,
  ): void {
    try {
      const { text } = this.#runtime.append(chunk);
      if (text.length > 0) this.push(text, "utf8");
      callback();
    } catch (error) {
      callback(error as Error);
    }
  }

  override _flush(callback: TransformCallback): void {
    try {
      const { text } = this.#runtime.finalize();
      if (text.length > 0) this.push(text, "utf8");
      callback();
    } catch (error) {
      callback(error as Error);
    }
  }

  override _destroy(
    error: Error | null,
    callback: (error?: Error | null) => void,
  ): void {
    this.#runtime.abort();
    callback(error);
  }
}
