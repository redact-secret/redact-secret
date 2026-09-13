import { initialize, scanAndRedact } from "@redact-secret/core";

import { createServerHandlerWith } from "./integration.mjs";

/** Create an authoritative, bounded server handler over the installed artifact. */
export async function createServerHandler(options) {
  await initialize();
  return createServerHandlerWith({ ...options, scanAndRedact });
}
