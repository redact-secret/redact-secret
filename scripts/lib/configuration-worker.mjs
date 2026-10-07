/**
 * The worker thread of `scripts/qualify-configuration.mjs`: loads one artifact
 * the way a consumer does, runs one journey from `configuration-journeys.mjs`
 * on it, and posts the journey's data back after proving it carries no secret.
 *
 * One journey per worker, because the initialization owner (registry, PII
 * activation, detector selection) is thread-local and one-shot: a fresh worker
 * is a fresh process-equivalent, so no journey can lean on another's state.
 */

import { pathToFileURL } from "node:url";
import { parentPort, workerData } from "node:worker_threads";

import { assertNoSecret, JOURNEYS } from "./configuration-journeys.mjs";

/** `load` is `{ type: "package" | "custom", url }` or `{ type: "wasm", coreDist, profile }`. */
async function loadApi(load) {
  if (load.type === "package" || load.type === "custom") return import(load.url);
  if (load.type === "wasm") {
    // The package's own runtime over the *installed* @redact-secret/wasm build
    // for the profile: the same loader the Node fallback uses, including the
    // `pii` build when a PII selection is made.
    const dist = (name) => import(pathToFileURL(`${load.coreDist}/${name}`).href);
    const { createRedactSecretRuntime } = await dist("runtime.js");
    const { loadWasmFallback } = await dist("runtime/node.js");
    return createRedactSecretRuntime(({ pii }) => loadWasmFallback(load.profile, Boolean(pii)), load.profile);
  }
  throw new Error(`unknown artifact loader ${load.type}`);
}

try {
  const { load, journey, row, known, init } = workerData;
  const api = await loadApi(load);
  const run = new Map(Object.entries(JOURNEYS)).get(journey);
  if (typeof run !== "function") throw new Error(`unknown journey ${journey}`);
  const result = await run({ api, row, known, init });
  // The result leaves this thread only if nothing secret is in it.
  const bytes = assertNoSecret(`${row.id}/${journey}`, result);
  parentPort.postMessage({ ok: true, result, bytes });
} catch (error) {
  // Only fixed text: a journey's assertion messages name no input.
  parentPort.postMessage({
    ok: false,
    error: String(error?.message ?? error).slice(0, 400),
    code: error?.code ?? null,
  });
}
