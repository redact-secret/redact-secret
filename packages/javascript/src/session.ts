/**
 * The one runtime this package binds for the host it is running on.
 *
 * `index.ts` and both stream adapters import this module rather than each
 * building their own runtime, so a single `await initialize()` covers the
 * whole public surface no matter which subpath a caller reached first. ESM
 * evaluates this module once, so `dist/index.js` and
 * `dist/adapters/node-stream.js` share the same loaded binding.
 *
 * Nothing here is part of the published API: the package's `exports` map does
 * not reach this module.
 */

import { loadNativeBinding } from "#native";

import { createRedactSecretRuntime } from "./runtime.js";

export const runtime = createRedactSecretRuntime(loadNativeBinding, "full");
