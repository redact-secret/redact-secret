import { initialize, scanAndRedact } from "@redact-secret/core";

import { prepareBrowserSubmissionWith } from "./integration.mjs";

/**
 * Scan before calling `fetch`. The absence of `request` for warning/block
 * states makes accidentally sending the original input harder.
 */
export async function prepareBrowserSubmission(content) {
  await initialize();
  return prepareBrowserSubmissionWith(scanAndRedact, content);
}
