/**
 * The `full`/`common` detector profile constants shared by every script
 * that builds, serves, or measures the browser WebAssembly artifact
 * (`decision-define-detector-profile-and-pack-contract`):
 * `scripts/build-browser-artifact.mjs`, `scripts/qualify-browser-artifact.mjs`,
 * and `scripts/assessment-browser-performance.mjs`.
 *
 * `outName` is the one fact given to `wasm-bindgen --out-name`; `glue` and
 * `binary` are the file names it generates from that, derived here rather
 * than duplicated as their own literals, so they can never desync from
 * `outName`.
 */

import { join } from "node:path";

/** One profile's constants; `relativeDir` is relative to the repo root, for
 * each caller to resolve against its own base path. */
function profile(outName, cargoArgs, relativeDir, buildCommand) {
  return {
    cargoArgs,
    outName,
    glue: `${outName}.js`,
    binary: `${outName}_bg.wasm`,
    relativeDir,
    buildCommand,
  };
}

export const DETECTOR_PROFILES = {
  full: profile(
    "redact_secret_wasm",
    [],
    join("bindings", "wasm", "pkg"),
    "npm run wasm:build",
  ),
  common: profile(
    "redact_secret_wasm_common",
    ["--no-default-features"],
    join("bindings", "wasm", "pkg-common"),
    "npm run wasm:build:common",
  ),
};
