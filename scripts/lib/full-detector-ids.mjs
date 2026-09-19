/**
 * The canonical `full` detector ids, in order, from the corpus's own oracle
 * (`crates/secret-scan-core/src/detectors/mod.rs`'s `BUILT_IN_PACKS`).
 *
 * A neutral module rather than an export of either qualify script: importing
 * `scripts/qualify-browser-artifact.mjs` would run its own `main()` as a side
 * effect (`await main()` at file scope, with no "am I the entry point"
 * guard), so `scripts/qualify-node-addon.mjs` cannot import it from there,
 * and vice versa. Both import this module instead.
 */

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/**
 * @returns {string[]} every built-in detector id, in `BUILT_IN_PACKS`'s
 * canonical order.
 */
export function fullDetectorIds() {
  const source = readFileSync(
    join(REPO_ROOT, "crates", "secret-scan-core", "src", "detectors", "mod.rs"),
    "utf8",
  );
  const table = source.match(/BUILT_IN_PACKS: &\[\(&str, Pack\)\] = &\[([\s\S]*?)\n\];/);
  if (table === null) {
    throw new Error("detectors/mod.rs: BUILT_IN_PACKS not found");
  }
  return [...table[1].matchAll(/\("([a-z0-9-]+)", Pack::/g)].map((match) => match[1]);
}
