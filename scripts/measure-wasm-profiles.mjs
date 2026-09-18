/**
 * Builds and measures the real `full` and `common` WebAssembly artifacts,
 * for issue #381 (parent epic #377,
 * `decision-define-detector-profile-and-pack-contract`).
 *
 * Unlike `scripts/measure-detector-cost.mjs` (#378), which estimated a
 * smaller composition by temporarily commenting detectors out of the
 * source, this tool patches nothing. It builds the two shipped
 * configurations of the `redact-secret-wasm` crate with
 * `scripts/build-browser-artifact.mjs` — the default build (`full`) and
 * `--no-default-features` (`common`) — under the one release profile and
 * toolchain, then records for each:
 *
 * - `.wasm` raw, gzip -9, and brotli -11 size, glue size, and SHA-256;
 * - build evidence: the `redact_secret::detectors::<module>` names the
 *   binary's `name` section still carries after link-time dead-code
 *   removal, classified as `common`, shared engine, or `provider` code, and
 *   the export list both artifacts must share;
 * - initialization and processing time through `@redact-secret/core`,
 *   using the #378 protocol unchanged: `scripts/assessment-browser-performance.mjs`,
 *   `scale-logs-small-whole` and `scale-logs-medium-fixed4096`, 10 runs.
 *
 * It exits non-zero, after writing what it measured, when a guard fails:
 * the `common` binary is not smaller than `full`, links a `provider`
 * detector module, or exports a different surface. Usage:
 *
 *     npm run js:build   # once; the facade is not profile-sensitive
 *     node scripts/measure-wasm-profiles.mjs --out-dir docs/audits/evidence/381 \
 *       [--scratch-dir <dir>] [--runs 10] [--engine chromium ...]
 *
 * The two builds land in `--scratch-dir` (default `target/wasm-profiles`).
 *
 * `--engine` may repeat; the default is `chromium`, the #378 protocol.
 * Writes `<out-dir>/artifact-sizes.json`, `build-evidence.json`,
 * `performance.json`, and `raw/<profile>/<engine>-<workload>.json`.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { DETECTOR_PROFILES } from "./build-browser-artifact.mjs";
import { brotliSize, gzipSize } from "./measure-detector-cost.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
/** Inside the gitignored Cargo target directory, so recorded paths stay repo-relative. */
const DEFAULT_SCRATCH_DIR = join("target", "wasm-profiles");
const BASELINE_378 = join(REPO_ROOT, "docs", "audits", "evidence", "378", "artifact-sizes.json");

export const PROFILES = ["full", "common"];
export const ENGINES = ["chromium", "firefox", "webkit"];
export const WORKLOADS = ["scale-logs-small-whole", "scale-logs-medium-fixed4096"];

/**
 * The detector modules that implement the `common` pack, by detector id.
 * `scripts/tests/measure-wasm-profiles.test.mjs` pins the ids to the
 * `Pack::Common` rows of `BUILT_IN_PACKS`.
 */
export const COMMON_PACK_MODULES = {
  "private-key": "private_key",
  jwt: "jwt",
  "bearer-token": "bearer_token",
  "connection-string": "connection_string",
  "otpauth-uri": "otpauth",
  "generic-token": "generic_token",
};

/**
 * Shared lexical helpers under `detectors::` that are engine code, not pack
 * code (the contract's admission rule 4).
 */
export const SHARED_ENGINE_MODULES = ["text"];

function fail(message) {
  console.error(message);
  process.exit(1);
}

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: REPO_ROOT,
    stdio: ["ignore", "inherit", "inherit"],
  });
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) throw new Error(`${command} ${args.join(" ")} exited ${result.status}`);
}

function capture(command, args) {
  return execFileSync(command, args, { cwd: REPO_ROOT, encoding: "utf8" }).trim();
}

/** Every `redact_secret::detectors::<module>` a `name` section mentions, sorted and unique. */
export function detectorModules(nameSection) {
  const modules = new Set();
  for (const match of nameSection.matchAll(/redact_secret\[[0-9a-f]+\]::detectors::([a-z0-9_]+)::/g)) {
    modules.add(match[1]);
  }
  return [...modules].sort();
}

/** Splits linked detector modules into `common`, shared engine, and `provider` code. */
export function classifyModules(modules) {
  const common = new Set(Object.values(COMMON_PACK_MODULES));
  const shared = new Set(SHARED_ENGINE_MODULES);
  return {
    common: modules.filter((module) => common.has(module)),
    sharedEngine: modules.filter((module) => shared.has(module)),
    provider: modules.filter((module) => !common.has(module) && !shared.has(module)),
  };
}

/** `(value - baseline) / baseline`, as a percentage rounded to two places. */
export function percentChange(value, baseline) {
  return Math.round(((value - baseline) / baseline) * 10_000) / 100;
}

function sha256(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

/** Reads one built artifact: sizes, digests, exports, and linked detector modules. */
function inspectArtifact(profile, directory) {
  const { outName } = DETECTOR_PROFILES[profile];
  const wasm = readFileSync(join(directory, `${outName}_bg.wasm`));
  const glue = readFileSync(join(directory, `${outName}.js`));
  const module = new WebAssembly.Module(wasm);
  const nameSections = WebAssembly.Module.customSections(module, "name");
  if (nameSections.length !== 1) {
    throw new Error(`${profile}: expected one name section, found ${nameSections.length}`);
  }
  const modules = detectorModules(Buffer.from(nameSections[0]).toString("latin1"));
  return {
    sizes: {
      wasmRawBytes: wasm.length,
      wasmGzipBytes: gzipSize(wasm),
      wasmBrotliBytes: brotliSize(wasm),
      glueRawBytes: glue.length,
      glueGzipBytes: gzipSize(glue),
      glueBrotliBytes: brotliSize(glue),
    },
    sha256: { wasm: sha256(wasm), glue: sha256(glue) },
    exports: WebAssembly.Module.exports(module)
      .map((entry) => entry.name)
      .sort(),
    detectorModules: modules,
    classification: classifyModules(modules),
  };
}

/** Every failed guard, as a message. An empty list means every guard held. */
export function guardFailures(full, common) {
  const failures = [];
  if (common.sizes.wasmRawBytes >= full.sizes.wasmRawBytes) {
    failures.push(
      `common .wasm (${common.sizes.wasmRawBytes} B) is not smaller than full ` +
        `(${full.sizes.wasmRawBytes} B): provider code is reachable from the common constructor`,
    );
  }
  if (common.classification.provider.length > 0) {
    failures.push(`common links provider detector modules: ${common.classification.provider.join(", ")}`);
  }
  if (full.classification.provider.length === 0) {
    failures.push("full links no provider detector module: the name-section inventory is not working");
  }
  const expectedCommon = Object.values(COMMON_PACK_MODULES).sort();
  const linkedCommon = [...common.classification.common].sort();
  if (JSON.stringify(linkedCommon) !== JSON.stringify(expectedCommon)) {
    failures.push(`common links ${linkedCommon.join(", ")}, expected ${expectedCommon.join(", ")}`);
  }
  if (JSON.stringify(full.exports) !== JSON.stringify(common.exports)) {
    failures.push("full and common export different surfaces");
  }
  return failures;
}

function measurePerformance(profile, directory, engine, workload, rawDir, runs) {
  const jsonOut = join(rawDir, profile, `${engine}-${workload}.json`);
  mkdirSync(dirname(jsonOut), { recursive: true });
  // Repo-relative arguments, so the command each raw result records is
  // reproducible from any checkout.
  run(process.execPath, [
    join(REPO_ROOT, "scripts", "assessment-browser-performance.mjs"),
    "--engine", engine,
    "--detector-profile", profile,
    "--artifact-dir", relative(REPO_ROOT, directory),
    "--profile", workload,
    "--runs", String(runs),
    "--json-out", relative(REPO_ROOT, jsonOut),
  ]);
  const result = JSON.parse(readFileSync(jsonOut, "utf8"));
  const { initialization, processing, throughput } = result.performance;
  return {
    runtime: result.provenance.runtime,
    file: relative(dirname(rawDir), jsonOut),
    initializationMedianMs: initialization.median,
    processingMedianMs: processing.median,
    processingStdDevMs: processing.standardDeviation,
    throughputMedianBytesPerSecond: throughput.median,
  };
}

function toolchain() {
  const cargoToml = readFileSync(join(REPO_ROOT, "Cargo.toml"), "utf8");
  const release = cargoToml.match(/\[profile\.release\]\n([\s\S]*?)(?:\n\[|$)/);
  return {
    rustc: capture("rustc", ["--version"]),
    cargo: capture("cargo", ["--version"]),
    wasmBindgen: capture("wasm-bindgen", ["--version"]),
    node: process.version,
    releaseProfile: release === null ? null : release[1].trim().split("\n"),
    target: "wasm32-unknown-unknown",
    wasmOpt: "not invoked (the build pipeline runs no post-link optimizer)",
  };
}

function parseArguments(argv) {
  const options = { outDir: undefined, scratchDir: undefined, runs: 10, engines: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const value = argv[index + 1];
    if (argument === "--out-dir") options.outDir = value;
    else if (argument === "--scratch-dir") options.scratchDir = value;
    else if (argument === "--runs") options.runs = Number(value);
    else if (argument === "--engine") {
      if (!ENGINES.includes(value)) fail(`--engine must be one of ${ENGINES.join(", ")}`);
      options.engines.push(value);
    } else fail(`unknown argument: ${argument}`);
    index += 1;
  }
  if (options.outDir === undefined) fail("--out-dir is required");
  if (!Number.isSafeInteger(options.runs) || options.runs < 2) fail("--runs must be an integer of at least 2");
  if (options.engines.length === 0) options.engines = ["chromium"];
  return options;
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function main() {
  const options = parseArguments(process.argv.slice(2));
  const outDir = resolve(REPO_ROOT, options.outDir);
  const rawDir = join(outDir, "raw");
  const scratch = resolve(REPO_ROOT, options.scratchDir ?? DEFAULT_SCRATCH_DIR);
  mkdirSync(rawDir, { recursive: true });

  const source = {
    commit: capture("git", ["rev-parse", "HEAD"]),
    workingTreeClean: capture("git", ["status", "--porcelain", "crates/", "bindings/wasm/"]) === "",
  };

  const artifacts = {};
  const directories = {};
  for (const profile of PROFILES) {
    directories[profile] = join(scratch, profile);
    run(process.execPath, [
      join(REPO_ROOT, "scripts", "build-browser-artifact.mjs"),
      "--detector-profile", profile,
      "--out-dir", directories[profile],
    ]);
    artifacts[profile] = inspectArtifact(profile, directories[profile]);
  }
  const { full, common } = artifacts;

  const saved = (key) => ({
    bytes: full.sizes[key] - common.sizes[key],
    percent: -percentChange(common.sizes[key], full.sizes[key]),
  });
  const baseline = existsSync(BASELINE_378)
    ? JSON.parse(readFileSync(BASELINE_378, "utf8")).variants
    : undefined;
  const versus378 = baseline === undefined ? undefined : {
    full: {
      baselineVariant: "full",
      wasmRawBytes: full.sizes.wasmRawBytes - baseline.full.wasmRawBytes,
      wasmBrotliBytes: full.sizes.wasmBrotliBytes - baseline.full.wasmBrotliBytes,
    },
    common: {
      baselineVariant: "tiny-common",
      wasmRawBytes: common.sizes.wasmRawBytes - baseline["tiny-common"].wasmRawBytes,
      wasmBrotliBytes: common.sizes.wasmBrotliBytes - baseline["tiny-common"].wasmBrotliBytes,
    },
  };

  writeJson(join(outDir, "artifact-sizes.json"), {
    source,
    toolchain: toolchain(),
    profiles: Object.fromEntries(
      PROFILES.map((profile) => [profile, { sizes: artifacts[profile].sizes, sha256: artifacts[profile].sha256 }]),
    ),
    commonSavedVersusFull: {
      wasmRaw: saved("wasmRawBytes"),
      wasmGzip: saved("wasmGzipBytes"),
      wasmBrotli: saved("wasmBrotliBytes"),
    },
    deltaVersus378Estimate: versus378,
  });

  const failures = guardFailures(full, common);
  writeJson(join(outDir, "build-evidence.json"), {
    source,
    guards: { passed: failures.length === 0, failures },
    profiles: Object.fromEntries(
      PROFILES.map((profile) => [
        profile,
        {
          detectorModules: artifacts[profile].detectorModules,
          classification: artifacts[profile].classification,
          exports: artifacts[profile].exports,
        },
      ]),
    ),
  });

  const performance = {};
  for (const engine of options.engines) {
    for (const workload of WORKLOADS) {
      for (const profile of PROFILES) {
        performance[engine] ??= {};
        performance[engine][workload] ??= {};
        performance[engine][workload][profile] = measurePerformance(
          profile, directories[profile], engine, workload, rawDir, options.runs,
        );
      }
    }
  }
  writeJson(join(outDir, "performance.json"), {
    source,
    runs: options.runs,
    protocol: "scripts/assessment-browser-performance.mjs through @redact-secret/core, one fresh browser context per run (#378)",
    engines: performance,
  });

  console.log(
    `[measure-wasm-profiles] full ${full.sizes.wasmRawBytes} B raw / ${full.sizes.wasmBrotliBytes} B brotli; ` +
      `common ${common.sizes.wasmRawBytes} B raw / ${common.sizes.wasmBrotliBytes} B brotli`,
  );
  if (failures.length > 0) fail(`[measure-wasm-profiles] guard failed:\n  ${failures.join("\n  ")}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
