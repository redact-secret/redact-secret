/**
 * The one runtime this package binds for the host it is running on, opted
 * into the `common` detector profile.
 *
 * `common.ts` imports this module rather than building its own runtime, the
 * same way `index.ts` imports `session.ts`. ESM evaluates this module once,
 * so every caller of `@redact-secret/core/common` shares the same loaded
 * binding.
 *
 * Nothing here is part of the published API: the package's `exports` map
 * does not reach this module.
 */

import { loadNativeBinding } from "#native-common";

import { createRedactSecretRuntime } from "./runtime.js";

export const runtime = createRedactSecretRuntime(loadNativeBinding, "common");
