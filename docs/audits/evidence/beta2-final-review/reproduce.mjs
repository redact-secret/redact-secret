// Revision-bound audit probes. These report defects; they are not CI pass gates.
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRedactSecretRuntime } from "../../../../packages/javascript/dist/runtime.js";
import { createBindingFromAddon } from "../../../../packages/javascript/dist/runtime/node.js";
import { createStreamSanitizerRuntime } from "../../../../packages/javascript/dist/adapters/shared.js";

const root = fileURLToPath(new URL("../../../../", import.meta.url));
const addonModule = { exports: {} };
process.dlopen(addonModule, resolve(root, process.argv[2] ?? "target/debug/libredact_secret_node.dylib"));
const runtime = createRedactSecretRuntime(async () => createBindingFromAddon(addonModule.exports));
await runtime.initialize();
const limits = {
  maxInputCodeUnits: 6_000_000,
  maxBufferedCodeUnits: 16_512,
  maxTokenCodeUnits: 8_192,
  maxMultilineCodeUnits: 16_384,
};
const session = () => runtime.createIncrementalSanitizer({ limits });
const marker = "SYNTHETIC_REVOKED_RETAINED_TEXT";
const observations = { node: process.version };

observations.invalidAppend = [];
for (const invalid of [42, "\ud800"]) {
  const active = session();
  assert.equal(active.append(marker).text, "");
  let code;
  try { active.append(invalid); } catch (error) { code = error.code; }
  const stateAfterError = active.state;
  let reemitted = false;
  try { reemitted = active.finalize().text === marker; } catch {}
  observations.invalidAppend.push({ code, stateAfterError, reemitted });
}

const input = "\ufeffapi_key=SYNTHETIC_REVOKED_BOM_VALUE\n";
const whole = runtime.scanAndRedact(input);
observations.bom = [];
const bytes = new TextEncoder().encode(input);
for (const boundary of [0, 1, 2, 3]) {
  const stream = createStreamSanitizerRuntime(session());
  const text = stream.append(bytes.subarray(0, boundary)).text
    + stream.append(bytes.subarray(boundary)).text + stream.finalize().text;
  observations.bom.push({
    boundary,
    textMatches: text === whole.text,
    wholeStart: whole.findings[0].start,
    streamStart: stream.findings[0].start,
  });
}

// 150k short lines isolate the JS argument-count ceiling without a benchmark.
const count = 150_000;
const denseInput = "api_key=SYNTHETIC_REVOKED_LARGE_VALUE\n".repeat(count);
const direct = session();
const directResult = direct.append(denseInput);
assert.equal(directResult.findings.length, count);
direct.finalize();
const adapted = session();
let errorName = null;
try {
  createStreamSanitizerRuntime(adapted).append(new TextEncoder().encode(denseInput));
} catch (error) { errorName = error.name; }
observations.denseFindings = {
  bytes: denseInput.length, directCount: directResult.findings.length,
  adapterError: errorName, sessionStateAfterError: adapted.state,
};
if (adapted.state === "accepting") adapted.abort();
console.log(JSON.stringify(observations, null, 2));
