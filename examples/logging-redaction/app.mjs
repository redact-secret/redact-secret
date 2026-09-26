/**
 * Reference architecture: application logging (issue #611).
 *
 * The whole integration is this file. The redaction runs inside the
 * released `@redact-secret/adapter-pino` package, installed from the npm
 * registry at the exact version `package-lock.json` pins, over the released
 * `@redact-secret/core`. Nothing here copies adapter code.
 *
 * Two hooks, as the adapter requires. `hooks.logMethod` sees the caller's
 * arguments before pino merges, serializes, formats, or writes anything, so
 * nothing from a log call reaches a pino serializer, a transport, or the
 * destination until the adapter has scanned it. It never sees child-logger
 * bindings or `mixin()` output, so `hooks.streamWrite`
 * (`@redact-secret/adapter-pino@0.1.1`) scans every string of the finished
 * line just before it reaches the destination. Together they are the
 * authoritative scan point for this process's logs.
 */

import pino from "pino";
import { createRedactingLogMethod, createRedactingStreamWrite } from "@redact-secret/adapter-pino";

/**
 * Creates the application's logger. `destination` is any pino destination
 * (a file, stdout, a transport); the smoke test passes an in-memory one.
 * `mixin` is passed through to pino, so the smoke test can show its output
 * is scanned too.
 *
 * @param {{ destination?: import("pino").DestinationStream, policy?: object, limits?: object, mixin?: () => object }} [options]
 */
export async function createAppLogger({ destination, policy, limits, mixin } = {}) {
  // Each awaits the core's `initialize()` once, before the first log call.
  const logMethod = await createRedactingLogMethod({ policy, limits });
  const streamWrite = await createRedactingStreamWrite({ policy, limits });
  return pino(
    {
      hooks: { logMethod, streamWrite },
      ...(mixin === undefined ? {} : { mixin }),
      // pino's own path-based redact still applies, after the value-based scan.
      redact: ["req.headers.authorization"],
      base: undefined,
      timestamp: false,
    },
    destination,
  );
}
