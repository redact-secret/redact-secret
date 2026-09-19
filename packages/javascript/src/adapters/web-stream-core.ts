/**
 * The runtime-neutral half of the Web Streams adapter: the
 * `WebStreamSanitizer` class itself, which wraps whatever incremental
 * session its constructor is given rather than opening one against a
 * specific detector profile (`decision-define-runtime-bindings`).
 *
 * `./web-stream.ts` (the `full` convenience factory) and
 * `./web-stream-common.ts` (the `common` one) both import the class from
 * here and re-export it, rather than importing it from each other: either
 * direction would pull that profile's `../session.js`/`../session-common.js`
 * binding — and, in a browser bundle, that profile's own WebAssembly
 * artifact loader — into a bundle that only wants the other profile's
 * factory. This module imports neither `../session.js` nor
 * `../session-common.js`, and nothing from `node:`.
 *
 * Backpressure is the platform's: writes stall while the readable side is
 * full and resume when a reader pulls. The readable and writable sides are
 * wrapped so that a reader's `cancel()` and a writer's `abort()` — the two
 * ways a Web stream ends early — abort the session first, discarding the
 * plaintext it was still deciding about, before the underlying stream is torn
 * down.
 */

import type { IncrementalSanitizer, SecretFinding } from "../types.js";

import { createStreamSanitizerRuntime } from "./shared.js";

/** A byte-to-string Web transform backed by one incremental session. */
export class WebStreamSanitizer extends TransformStream<Uint8Array, string> {
  readonly #runtime;
  readonly #readable: ReadableStream<string>;
  readonly #writable: WritableStream<Uint8Array>;

  /**
   * Wraps `session`, which this transform owns: it is finalized when the
   * writable side closes normally and aborted on every other exit.
   */
  constructor(session: IncrementalSanitizer) {
    const sanitizer = createStreamSanitizerRuntime(session);
    super({
      transform(chunk, controller) {
        const { text } = sanitizer.append(chunk);
        if (text.length > 0) controller.enqueue(text);
      },
      flush(controller) {
        const { text } = sanitizer.finalize();
        if (text.length > 0) controller.enqueue(text);
      },
    });
    this.#runtime = sanitizer;

    const source = super.readable.getReader();
    this.#readable = new ReadableStream<string>({
      async pull(controller) {
        try {
          const result = await source.read();
          if (result.done) controller.close();
          else controller.enqueue(result.value);
        } catch (error) {
          controller.error(error);
        }
      },
      async cancel(reason) {
        sanitizer.abort();
        await source.cancel(reason);
      },
    });

    const sink = super.writable.getWriter();
    this.#writable = new WritableStream<Uint8Array>({
      write(chunk) {
        return sink.write(chunk);
      },
      close() {
        return sink.close();
      },
      async abort(reason) {
        sanitizer.abort();
        await sink.abort(reason);
      },
    });
  }

  override get readable(): ReadableStream<string> {
    return this.#readable;
  }

  override get writable(): WritableStream<Uint8Array> {
    return this.#writable;
  }

  /**
   * Every finding the session has finalized so far, frozen, with absolute
   * UTF-16 offsets into the logical whole-stream input. It stays empty when
   * the stream is cancelled or aborted before anything settles.
   */
  get findings(): readonly SecretFinding[] {
    return this.#runtime.findings;
  }

  /**
   * Discards retained plaintext before explicit early termination.
   *
   * Idempotent, and safe after the session has already ended: a later
   * `close()` on the writable side then fails with `INVALID_STATE` rather
   * than flushing anything.
   */
  abort(): void {
    this.#runtime.abort();
  }
}
