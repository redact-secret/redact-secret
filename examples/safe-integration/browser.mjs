import { initialize, scanAndRedact } from "@redact-secret/core";

import { prepareBrowserSubmissionWith } from "./integration.mjs";

/**
 * Scan before calling `fetch`. The absence of `request` for warning/block
 * states makes accidentally sending the original input harder. Uses the
 * library default policy — unlike the explicit `serverPolicy` in
 * integration.mjs, which is the authoritative decision regardless of what
 * this preventive check decided.
 */
export async function prepareBrowserSubmission(content) {
  await initialize();
  return prepareBrowserSubmissionWith(scanAndRedact, content);
}
