/**
 * Shared scaffolding for both stream adapter suites.
 *
 * The adapters are glue over one incremental session, so each test opens a
 * session on a runtime bound to the deterministic sanitizing double and hands
 * it straight to the adapter's constructor — the same object
 * `createNodeStreamSanitizer` and `createWebStreamSanitizer` build from
 * `IncrementalSanitizerOptions` once `initialize()` has succeeded.
 */

import { createRedactSecretRuntime } from "../../src/runtime.js";
import type {
  IncrementalSanitizer,
  IncrementalSanitizerOptions,
} from "../../src/types.js";
import { createSanitizingBinding } from "../sanitizing-binding.js";

export const LIMITS = Object.freeze({
  maxInputCodeUnits: 1_048_576,
  maxBufferedCodeUnits: 16_512,
  maxTokenCodeUnits: 8_192,
  maxMultilineCodeUnits: 16_384,
});

/** Opens one session on a freshly initialized runtime. */
export async function openSession(
  options: Partial<IncrementalSanitizerOptions> = {},
): Promise<IncrementalSanitizer> {
  const runtime = createRedactSecretRuntime(async () => createSanitizingBinding());
  await runtime.initialize();
  return runtime.createIncrementalSanitizer({ limits: LIMITS, ...options });
}

export const encoder = new TextEncoder();

/** Bytes of `text`, for splitting at an arbitrary byte boundary. */
export function bytes(text: string): Uint8Array {
  return encoder.encode(text);
}

/**
 * Inputs whose sanitized form must not depend on where the byte stream is
 * split. Every secret-shaped value is synthetic.
 */
export const partitionCorpus = Object.freeze([
  Object.freeze({ id: "empty", input: "" }),
  Object.freeze({ id: "plain-ascii", input: "nothing sensitive here\n" }),
  Object.freeze({ id: "leading-bom-only", input: "\uFEFF" }),
  Object.freeze({
    id: "leading-bom-secret",
    input: "\uFEFFapi_key=SYNTHETIC_REVOKED_BOM_VALUE\n",
  }),
  Object.freeze({
    id: "later-literal-bom",
    input: "ordinary prefix \uFEFF api_key=SYNTHETIC_REVOKED_LATER_BOM\n",
  }),
  Object.freeze({
    id: "multibyte-around-secret",
    input: "키=값 api_key=SYNTHETIC_REVOKED_ONE ünd mehr\n",
  }),
  Object.freeze({
    id: "astral-plane",
    input: "🔑 api_key=SYNTHETIC_REVOKED_TWO 🔒 tail\n",
  }),
  Object.freeze({
    id: "two-secrets",
    input: "api_key=SYNTHETIC_REVOKED_A\napi_key=SYNTHETIC_REVOKED_B\n",
  }),
  Object.freeze({
    id: "secret-closes-at-end-of-input",
    input: "prefix api_key=SYNTHETIC_REVOKED_OPEN",
  }),
  Object.freeze({
    id: "marker-only",
    input: "api_key=\nnot a secret\n",
  }),
]);

/** The whole-input result the same session produces in one shot. */
export async function oracle(
  input: string,
): Promise<{ text: string; findings: readonly unknown[] }> {
  const session = await openSession();
  const appended = session.append(input);
  const finalized = session.finalize();
  return {
    text: appended.text + finalized.text,
    findings: [...appended.findings, ...finalized.findings],
  };
}
