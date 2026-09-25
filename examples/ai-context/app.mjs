/**
 * Reference architecture: AI context construction (issue #611).
 *
 * This file adds no redaction logic. It composes two things:
 *
 * - the released `@redact-secret/core`, installed from the npm registry at
 *   the exact version `package-lock.json` pins, initialized once here;
 * - the MCP / AI-context golden path in `examples/mcp-redact`
 *   (`buildSafeContext`, `createGoldenPathBoundaryWith`), which runs on
 *   `@redact-secret/adapter-ai-context`, the #610 contract's
 *   implementation, with tool results sanitized by
 *   `@redact-secret/adapter-mcp` (the #612 MCP boundary), both installed
 *   there from the publish-shaped tarballs pinned in
 *   `adapters/pin-source.json`.
 *
 * The core is injected rather than loaded by the adapter, so the
 * application and the boundary share one initialized core instance.
 */

import * as core from "@redact-secret/core";

import { buildSafeContext, createGoldenPathBoundaryWith } from "../mcp-redact/agent-context.mjs";

export { buildSafeContext };

/**
 * Creates the boundary the application sanitizes every model-bound value
 * through. `onFinding` receives only the contract's allowlisted metadata,
 * never the input or a matched value.
 *
 * @param {{ policy?: object, onFinding?: Function }} [options]
 */
export async function createAppBoundary(options = {}) {
  await core.initialize();
  return createGoldenPathBoundaryWith(
    { scanAndRedact: core.scanAndRedact, createIncrementalSanitizer: core.createIncrementalSanitizer },
    options,
  );
}
