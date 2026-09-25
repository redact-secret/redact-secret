/**
 * Reference architecture: application logging (issue #611).
 *
 * The whole integration is this file. The redaction runs inside the
 * released `@redact-secret/adapter-pino` package, installed from the npm
 * registry at the exact version `package-lock.json` pins, over the released
 * `@redact-secret/core`. Nothing here copies adapter code.
 *
 * `hooks.logMethod` sees the caller's arguments before pino merges,
 * serializes, formats, or writes anything, so it is the authoritative scan
 * point for this process's logs: nothing reaches a pino serializer, a
 * transport, or the destination until the adapter has scanned it.
 */

import pino from "pino";
import { createRedactingLogMethod } from "@redact-secret/adapter-pino";

/**
 * Creates the application's logger. `destination` is any pino destination
 * (a file, stdout, a transport); the smoke test passes an in-memory one.
 *
 * @param {{ destination?: import("pino").DestinationStream, policy?: object, limits?: object }} [options]
 */
export async function createAppLogger({ destination, policy, limits } = {}) {
  // Awaits the core's `initialize()` once, before the first log call.
  const logMethod = await createRedactingLogMethod({ policy, limits });
  return pino(
    {
      hooks: { logMethod },
      // pino's own path-based redact still applies, after the value-based scan.
      redact: ["req.headers.authorization"],
      base: undefined,
      timestamp: false,
    },
    destination,
  );
}
