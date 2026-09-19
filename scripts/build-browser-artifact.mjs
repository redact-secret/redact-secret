/**
 * Builds the browser WebAssembly artifact from the workspace source
 * (`decision-define-runtime-bindings`).
 *
 * `cargo build` produces the `wasm32-unknown-unknown` cdylib and
 * `wasm-bindgen` generates the ES module glue for the `web` target, so the
 * emitted directory is loadable by a browser directly from a static server:
 * the generated `default()` init resolves `redact_secret_wasm_bg.wasm` relative
 * to its own `import.meta.url`.
 *
 * Only the four generated files are emitted. The published manifest for
 * `@redact-secret/wasm` lives at `bindings/wasm/npm/package.json`
 * (issue #79), and `scripts/qualify-package-consumer.mjs` copies this
 * directory over it, so a manifest emitted here would overwrite it.
 *
 * `--detector-profile` selects the compiled detector profile
 * (`decision-define-detector-profile-and-pack-contract`). `full`, the
 * default, is the build above, unchanged. `common` builds the crate with
 * `--no-default-features`, so only the `common` registry constructor is
 * linked, and emits `redact_secret_wasm_common{.js,.d.ts,_bg.wasm,_bg.wasm.d.ts}`
 * into `bindings/wasm/pkg-common` by default. Its own file names let both
 * artifacts sit side by side in one directory without either overwriting
 * the other.
 *
 * The `wasm-bindgen` CLI must be the exact version the crate is compiled
 * against; a mismatch produces glue that cannot instantiate the module, so it
 * fails here rather than in a browser. Usage:
 *
 *     node scripts/build-browser-artifact.mjs [--out-dir <dir>] [--debug]
 *         [--detector-profile full|common]
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { DETECTOR_PROFILES } from "./lib/detector-profiles.mjs";

export { DETECTOR_PROFILES };

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** The crate whose cdylib becomes the browser artifact. */
const CRATE = "redact-secret-wasm";
/** The `cargo` output name of the cdylib, whichever profile it was built for. */
const CARGO_OUT_NAME = "redact_secret_wasm";

function fail(message) {
  console.error(message);
  process.exit(1);
}

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    cwd: REPO_ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
    ...options,
  });
}

function parseArguments(argv) {
  const options = { outDir: undefined, profile: "release", detectorProfile: "full" };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--out-dir") {
      index += 1;
      const value = argv[index];
      if (value === undefined) fail("--out-dir requires a directory");
      options.outDir = value;
    } else if (argument === "--debug") {
      options.profile = "debug";
    } else if (argument === "--detector-profile") {
      index += 1;
      const value = argv[index];
      if (!Object.hasOwn(DETECTOR_PROFILES, value ?? "")) {
        fail(`--detector-profile must be one of ${Object.keys(DETECTOR_PROFILES).join(", ")}`);
      }
      options.detectorProfile = value;
    } else {
      fail(`unknown argument: ${argument}`);
    }
  }
  options.outDir ??= DETECTOR_PROFILES[options.detectorProfile].relativeDir;
  return options;
}

/**
 * Reads the resolved workspace metadata once: the shared product version and
 * the exact `wasm-bindgen` version the crate links, both taken from the
 * lockfile rather than from a hand-maintained copy.
 */
function readWorkspace() {
  const metadata = JSON.parse(
    run("cargo", ["metadata", "--format-version", "1", "--locked"]),
  );
  const crate = metadata.packages.find((entry) => entry.name === CRATE);
  if (crate === undefined) fail(`${CRATE} is not a workspace member`);
  const bindgen = metadata.packages.find(
    (entry) => entry.name === "wasm-bindgen",
  );
  if (bindgen === undefined) fail("wasm-bindgen is not a resolved dependency");
  return {
    version: crate.version,
    bindgenVersion: bindgen.version,
    targetDirectory: metadata.target_directory,
  };
}

function requireMatchingBindgenCli(expected) {
  let reported;
  try {
    reported = run("wasm-bindgen", ["--version"]).trim();
  } catch {
    fail(
      `wasm-bindgen ${expected} is not on PATH; install it with ` +
        `\`cargo install wasm-bindgen-cli --version ${expected} --locked\``,
    );
    return;
  }
  const actual = reported.split(/\s+/).at(-1);
  if (actual !== expected) {
    fail(
      `wasm-bindgen CLI is ${actual}, but the crate is built against ` +
        `${expected}; the generated glue would refuse the module`,
    );
  }
}

function main() {
  const options = parseArguments(process.argv.slice(2));
  const workspace = readWorkspace();
  requireMatchingBindgenCli(workspace.bindgenVersion);

  const detectorProfile = DETECTOR_PROFILES[options.detectorProfile];
  const build = [
    "build",
    "-p",
    CRATE,
    "--target",
    "wasm32-unknown-unknown",
    "--locked",
    ...detectorProfile.cargoArgs,
  ];
  if (options.profile === "release") build.push("--release");
  run("cargo", build, { stdio: "inherit" });

  const wasm = join(
    workspace.targetDirectory,
    "wasm32-unknown-unknown",
    options.profile,
    `${CARGO_OUT_NAME}.wasm`,
  );
  const outDir = resolve(REPO_ROOT, options.outDir);
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
  run(
    "wasm-bindgen",
    ["--target", "web", "--out-dir", outDir, "--out-name", detectorProfile.outName, wasm],
    { stdio: "inherit" },
  );

  console.log(
    `built the ${options.detectorProfile} browser artifact ${workspace.version} ` +
      `(${options.profile}) in ${options.outDir}`,
  );
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main();
}
