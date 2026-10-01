/**
 * The `full`/`common` detector profile constants shared by every script
 * that builds, serves, or measures the browser WebAssembly artifact
 * (`decision-define-detector-profile-and-pack-contract`):
 * `scripts/build-browser-artifact.mjs`, `scripts/qualify-browser-artifact.mjs`,
 * and `scripts/assessment-browser-performance.mjs`.
 *
 * Each profile ships two builds side by side in one directory (issue #937):
 * the default build, which links no PII runtime and rejects a PII selection
 * with `PII_SELECTOR_UNAVAILABLE`, and its `pii` variant, built with the
 * `redact-secret-wasm` crate's `pii` Cargo feature, which `@redact-secret/core`
 * loads only when `initialize()` is given a PII selection. The top-level
 * fields describe the default build; `pii` describes the variant.
 *
 * `outName` is the one fact given to `wasm-bindgen --out-name`; `glue` and
 * `binary` are the file names it generates from that, derived here rather
 * than duplicated as their own literals, so they can never desync from
 * `outName`.
 */

import { join } from "node:path";

/** One build's `wasm-bindgen` output names and Cargo arguments. */
function build(outName, cargoArgs) {
  return {
    cargoArgs,
    outName,
    glue: `${outName}.js`,
    binary: `${outName}_bg.wasm`,
    /** Every file `wasm-bindgen --target web` emits for this build. */
    files: [`${outName}.js`, `${outName}.d.ts`, `${outName}_bg.wasm`, `${outName}_bg.wasm.d.ts`],
  };
}

/** One profile's constants; `relativeDir` is relative to the repo root, for
 * each caller to resolve against its own base path. */
function profile(outName, cargoArgs, relativeDir, buildCommand) {
  return {
    ...build(outName, cargoArgs),
    relativeDir,
    buildCommand,
    pii: build(`${outName}_pii`, [...cargoArgs, "--features", "pii"]),
  };
}

export const DETECTOR_PROFILES = {
  full: profile("redact_secret_wasm", [], join("bindings", "wasm", "pkg"), "npm run wasm:build"),
  common: profile(
    "redact_secret_wasm_common",
    ["--no-default-features"],
    join("bindings", "wasm", "pkg-common"),
    "npm run wasm:build:common",
  ),
};

/** The builds of one profile, default first: `[["default", build], ["pii", build]]`. */
export function profileBuilds(profileName) {
  const entry = DETECTOR_PROFILES[profileName];
  return [
    ["default", entry],
    ["pii", entry.pii],
  ];
}
