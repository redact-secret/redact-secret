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
 * - initialization and processing time through `@redact-secret/core`, via
 *   `scripts/assessment-browser-performance.mjs`, `scale-logs-small-whole`
 *   and `scale-logs-medium-fixed4096`, 10 runs.
 *
 * It exits non-zero, after writing what it measured, when a guard fails:
 * the `common` binary is not smaller than `full`, links a `provider`
 * detector implementation, does not link every `common` one, or exports a
 * different surface.
 *
 * Each profile directory also holds the profile's `pii` variant (issue
 * #937). The PII guards fail when a default artifact links any part of the
 * PII runtime (the `pii-domain` adapter's `Detector` implementation, a
 * `PiiFamily` implementation, or `unicode_normalization`), when a `pii`
 * variant does not link it (the inventory would then prove nothing), when
 * `common-pii` breaks a `common` guard, or when any of the four artifacts
 * exports a different surface. Usage:
 *
 *     npm run js:build   # once; the facade is not profile-sensitive
 *     node scripts/measure-wasm-profiles.mjs --out-dir docs/audits/evidence/381 \
 *       [--scratch-dir <dir>] [--runs 10] [--engine chromium ...]
 *     node scripts/measure-wasm-profiles.mjs --guard-only [--scratch-dir <dir>]
 *
 * `--guard-only` builds every artifact and checks the guards, and measures
 * no performance and writes no evidence file; CI runs it (#929, #937).
 * Performance is measured for the default `full` and `common` builds only.
 *
 * Which detector module belongs to which pack is read from the core's
 * `detectors/mod.rs` (`BUILT_IN_PACKS` and `built_in_detectors()`), so a new
 * provider module is classified without editing this script. A declared
 * module that registers no built-in detector (`pattern`, `text`,
 * `ruleset_adapter`, ...) is shared engine code.
 *
 * A module counts as linked when the binary's `name` section carries one of
 * its `Detector` implementations. Other symbols of a provider module can
 * appear without its detector: LLVM merges identical functions and keeps
 * one name for the merged body (a two-line byte predicate in a provider
 * module can carry the name of the same predicate a `common` detector
 * calls), and the incremental session's retention rules call a few
 * provider-specific context helpers in every profile. Those are reported as
 * `providerHelperModules` and are not a failure.
 *
 * The two builds land in `--scratch-dir` (default `target/wasm-profiles`).
 *
 * `--engine` may repeat; the default is `chromium`.
 * Writes `<out-dir>/artifact-sizes.json`, `build-evidence.json`,
 * `performance.json`, and `raw/<profile>/<engine>-<workload>.json`.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { DETECTOR_PROFILES, profileBuilds } from "./build-browser-artifact.mjs";
import { brotliSize, gzipSize } from "./measure-detector-cost.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
/** Inside the gitignored Cargo target directory, so recorded paths stay repo-relative. */
const DEFAULT_SCRATCH_DIR = join("target", "wasm-profiles");
const BASELINE_378 = join(REPO_ROOT, "docs", "audits", "evidence", "378", "artifact-sizes.json");

export const PROFILES = ["full", "common"];
/** Every artifact the guard inspects: each profile's default build and its `pii` variant (#937). */
export const ARTIFACTS = ["full", "common", "full-pii", "common-pii"];
export const ENGINES = ["chromium", "firefox", "webkit"];
export const WORKLOADS = ["scale-logs-small-whole", "scale-logs-medium-fixed4096"];

const DETECTORS_MOD_RS = join(REPO_ROOT, "crates", "secret-scan-core", "src", "detectors", "mod.rs");

/**
 * The pack of every detector module, read from the core's `detectors/mod.rs`
 * source text: the modules it declares, the module of each entry of
 * `built_in_detectors()`, and the pack of the same position in
 * `BUILT_IN_PACKS` (the core's tests pin both lists to the canonical order).
 * Returns `{ common, provider, sharedEngine }` as sorted module-name arrays.
 * Throws when the two lists disagree in length or a module holds detectors
 * of both packs.
 */
export function modulePacks(source) {
  const declared = [...source.matchAll(/^mod ([a-z0-9_]+);$/gm)].map((match) => match[1]);
  const imported = Object.fromEntries(
    [...source.matchAll(/^use ([a-z0-9_]+)::([A-Za-z0-9_]+);$/gm)].map((match) => [match[2], match[1]]),
  );
  const list = source.match(/fn built_in_detectors\(\) -> Vec<Box<dyn Detector>> \{\s*vec!\[([\s\S]*?)\n\s*\]\n\}/);
  const table = source.match(/BUILT_IN_PACKS: &\[\(&str, Pack\)\] = &\[([\s\S]*?)\n\];/);
  if (list === null || table === null) throw new Error("detectors/mod.rs: built_in_detectors() or BUILT_IN_PACKS not found");
  const entries = list[1].split("\n").map((line) => line.trim()).filter((line) => line && !line.startsWith("//"));
  const modules = entries.map((entry) => {
    const path = entry.match(/\b([a-z_][a-z0-9_]*)::/);
    if (path !== null) return path[1];
    const bare = entry.match(/Box::new\(([A-Za-z0-9_]+)\)/);
    if (bare !== null && imported[bare[1]] !== undefined) return imported[bare[1]];
    throw new Error(`detectors/mod.rs: cannot tell the module of built-in entry ${entry}`);
  });
  const packs = [...table[1].matchAll(/\("[a-z0-9-]+", Pack::(Common|Provider)\)/g)].map((match) => match[1]);
  if (modules.length !== packs.length) {
    throw new Error(`detectors/mod.rs: ${modules.length} built-in detectors but ${packs.length} BUILT_IN_PACKS rows`);
  }
  const byModule = new Map();
  modules.forEach((module, index) => {
    if (!declared.includes(module)) throw new Error(`detectors/mod.rs: ${module} is not a declared module`);
    byModule.set(module, new Set([...(byModule.get(module) ?? []), packs[index]]));
  });
  for (const [module, set] of byModule) {
    if (set.size > 1) throw new Error(`detectors/mod.rs: ${module} holds both common and provider detectors`);
  }
  const of = (pack) => [...byModule].filter(([, set]) => set.has(pack)).map(([module]) => module).sort();
  return {
    common: of("Common"),
    provider: of("Provider"),
    sharedEngine: declared.filter((module) => !byModule.has(module)).sort(),
  };
}

/** {@link modulePacks} of this checkout's core. */
export function loadModulePacks() {
  return modulePacks(readFileSync(DETECTORS_MOD_RS, "utf8"));
}

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

/**
 * Every module with a `<redact_secret::detectors::<module>::<type> as
 * redact_secret::types::Detector>` method the `name` section mentions: the
 * modules whose detectors are linked, sorted and unique.
 */
export function detectorImplementations(nameSection) {
  const modules = new Set();
  const pattern = /<redact_secret\[[0-9a-f]+\]::detectors::([a-z0-9_]+)::[A-Za-z0-9_]+(?:<[^>]*>)? as redact_secret\[[0-9a-f]+\]::types::Detector>::/g;
  for (const match of nameSection.matchAll(pattern)) modules.add(match[1]);
  return [...modules].sort();
}

/**
 * The parts of the PII domain runtime a `name` section links, sorted and
 * unique: `PiiDomain` for the `pii-domain` adapter's `Detector`
 * implementation, the type name of every `PiiFamily` implementation, and
 * `unicode_normalization`, which only the PII families use. `PiiSelection`
 * parsing and the activation identity are not the runtime: every artifact
 * keeps them, so a selector is rejected with the same code everywhere.
 */
export function piiRuntime(nameSection) {
  const parts = new Set();
  const adapter = /<redact_secret\[[0-9a-f]+\]::pii::PiiDomain as redact_secret\[[0-9a-f]+\]::types::Detector>::/;
  if (adapter.test(nameSection)) parts.add("PiiDomain");
  const family = /<redact_secret\[[0-9a-f]+\]::pii::(?:[a-z0-9_]+::)*([A-Za-z0-9_]+) as redact_secret\[[0-9a-f]+\]::pii::PiiFamily>::/g;
  for (const match of nameSection.matchAll(family)) parts.add(match[1]);
  if (/unicode_normalization\[[0-9a-f]+\]::/.test(nameSection)) parts.add("unicode_normalization");
  return [...parts].sort();
}

/** Splits linked detector modules into `common`, shared engine, `provider` and undeclared code. */
export function classifyModules(modules, packs) {
  const common = new Set(packs.common);
  const shared = new Set(packs.sharedEngine);
  const provider = new Set(packs.provider);
  return {
    common: modules.filter((module) => common.has(module)),
    sharedEngine: modules.filter((module) => shared.has(module)),
    provider: modules.filter((module) => provider.has(module)),
    undeclared: modules.filter((module) => !common.has(module) && !shared.has(module) && !provider.has(module)),
  };
}

/** `(value - baseline) / baseline`, as a percentage rounded to two places. */
export function percentChange(value, baseline) {
  return Math.round(((value - baseline) / baseline) * 10_000) / 100;
}

function sha256(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

/** The build constants of one of {@link ARTIFACTS}. */
export function artifactBuild(artifact) {
  const [profile, variant] = artifact.split("-");
  const entry = DETECTOR_PROFILES[profile];
  if (entry === undefined || (variant !== undefined && variant !== "pii")) {
    throw new Error(`unknown artifact ${artifact}`);
  }
  return variant === "pii" ? entry.pii : entry;
}

/** Reads one built artifact: sizes, digests, exports, and linked detector modules. */
function inspectArtifact(artifact, directory, packs) {
  const { outName } = artifactBuild(artifact);
  const wasm = readFileSync(join(directory, `${outName}_bg.wasm`));
  const glue = readFileSync(join(directory, `${outName}.js`));
  const module = new WebAssembly.Module(wasm);
  const nameSections = WebAssembly.Module.customSections(module, "name");
  if (nameSections.length !== 1) {
    throw new Error(`${artifact}: expected one name section, found ${nameSections.length}`);
  }
  const nameSection = Buffer.from(nameSections[0]).toString("latin1");
  const modules = detectorModules(nameSection);
  const implementations = detectorImplementations(nameSection);
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
    classification: classifyModules(modules, packs),
    detectorImplementations: implementations,
    implementationClassification: classifyModules(implementations, packs),
    piiRuntime: piiRuntime(nameSection),
  };
}

/**
 * Every failed guard, as a message. An empty list means every guard held.
 * `names` labels the two artifacts in messages; {@link piiGuardFailures}
 * reuses the same checks for the `full-pii`/`common-pii` pair.
 */
export function guardFailures(full, common, packs, names = { full: "full", common: "common" }) {
  const failures = [];
  if (common.sizes.wasmRawBytes >= full.sizes.wasmRawBytes) {
    failures.push(
      `${names.common} .wasm (${common.sizes.wasmRawBytes} B) is not smaller than ${names.full} ` +
        `(${full.sizes.wasmRawBytes} B): provider code is reachable from the common constructor`,
    );
  }
  const linked = common.implementationClassification;
  if (linked.provider.length > 0) {
    failures.push(`${names.common} links provider detector implementations: ${linked.provider.join(", ")}`);
  }
  for (const [profile, artifact] of [[names.full, full], [names.common, common]]) {
    const { undeclared } = artifact.implementationClassification;
    if (undeclared.length > 0) failures.push(`${profile} links detectors of undeclared modules: ${undeclared.join(", ")}`);
  }
  if (full.implementationClassification.provider.length === 0) {
    failures.push(`${names.full} links no provider detector implementation: the name-section inventory is not working`);
  }
  const expectedCommon = [...packs.common].sort();
  const linkedCommon = [...linked.common].sort();
  if (JSON.stringify(linkedCommon) !== JSON.stringify(expectedCommon)) {
    failures.push(`${names.common} links ${linkedCommon.join(", ")}, expected ${expectedCommon.join(", ")}`);
  }
  if (JSON.stringify(full.exports) !== JSON.stringify(common.exports)) {
    failures.push(`${names.full} and ${names.common} export different surfaces`);
  }
  return failures;
}

/**
 * Every failed PII-split guard (#937), given all four artifacts: the default
 * `full` and `common` builds link no part of the PII runtime; each `pii`
 * variant links it; `common-pii` obeys every {@link guardFailures} check
 * against `full-pii`; each default build is smaller than its `pii` variant;
 * and all four export one surface.
 */
export function piiGuardFailures({ full, common, "full-pii": fullPii, "common-pii": commonPii }, packs) {
  const failures = [];
  for (const [name, artifact] of [["full", full], ["common", common]]) {
    const linkedPii = artifact.piiRuntime ?? [];
    if (linkedPii.length > 0) failures.push(`${name} links the PII runtime: ${linkedPii.join(", ")}`);
  }
  for (const [name, artifact] of [["full-pii", fullPii], ["common-pii", commonPii]]) {
    const parts = artifact.piiRuntime ?? [];
    const families = parts.filter((part) => part !== "PiiDomain" && part !== "unicode_normalization");
    if (!parts.includes("PiiDomain") || !parts.includes("unicode_normalization") || families.length === 0) {
      failures.push(`${name} does not link the PII runtime: the name-section inventory is not working`);
    }
  }
  failures.push(...guardFailures(fullPii, commonPii, packs, { full: "full-pii", common: "common-pii" }));
  for (const [name, base, variant] of [["full", full, fullPii], ["common", common, commonPii]]) {
    if (base.sizes.wasmRawBytes >= variant.sizes.wasmRawBytes) {
      failures.push(`${name} .wasm (${base.sizes.wasmRawBytes} B) is not smaller than ${name}-pii (${variant.sizes.wasmRawBytes} B)`);
    }
  }
  for (const [name, artifact] of [["full-pii", fullPii], ["common-pii", commonPii]]) {
    if (JSON.stringify(artifact.exports) !== JSON.stringify(full.exports)) {
      failures.push(`${name} exports a different surface than full`);
    }
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
  const options = { outDir: undefined, scratchDir: undefined, runs: 10, engines: [], guardOnly: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const value = argv[index + 1];
    if (argument === "--guard-only") {
      options.guardOnly = true;
      continue;
    }
    if (argument === "--out-dir") options.outDir = value;
    else if (argument === "--scratch-dir") options.scratchDir = value;
    else if (argument === "--runs") options.runs = Number(value);
    else if (argument === "--engine") {
      if (!ENGINES.includes(value)) fail(`--engine must be one of ${ENGINES.join(", ")}`);
      options.engines.push(value);
    } else fail(`unknown argument: ${argument}`);
    index += 1;
  }
  if (options.outDir === undefined && !options.guardOnly) fail("--out-dir is required");
  if (!Number.isSafeInteger(options.runs) || options.runs < 2) fail("--runs must be an integer of at least 2");
  if (options.engines.length === 0) options.engines = ["chromium"];
  return options;
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function main() {
  const options = parseArguments(process.argv.slice(2));
  const scratch = resolve(REPO_ROOT, options.scratchDir ?? DEFAULT_SCRATCH_DIR);
  const packs = loadModulePacks();

  const source = {
    commit: capture("git", ["rev-parse", "HEAD"]),
    workingTreeClean: capture("git", ["status", "--porcelain", "crates/", "bindings/wasm/"]) === "",
  };

  const artifacts = {};
  const directories = {};
  for (const profile of PROFILES) {
    directories[profile] = join(scratch, profile);
    directories[`${profile}-pii`] = directories[profile];
    run(process.execPath, [
      join(REPO_ROOT, "scripts", "build-browser-artifact.mjs"),
      "--detector-profile", profile,
      "--out-dir", directories[profile],
    ]);
    for (const [variant] of profileBuilds(profile)) {
      const artifact = variant === "pii" ? `${profile}-pii` : profile;
      artifacts[artifact] = inspectArtifact(artifact, directories[profile], packs);
    }
  }
  const { full, common } = artifacts;
  const failures = [...guardFailures(full, common, packs), ...piiGuardFailures(artifacts, packs)];
  const summary =
    "[measure-wasm-profiles] " +
    ARTIFACTS.map(
      (name) => `${name} ${artifacts[name].sizes.wasmRawBytes} B raw / ${artifacts[name].sizes.wasmGzipBytes} B gzip / ${artifacts[name].sizes.wasmBrotliBytes} B brotli`,
    ).join("; ") +
    `; common detectors: ${common.implementationClassification.common.join(", ")}; ` +
    `provider helper modules in common: ${common.classification.provider.join(", ") || "none"}; ` +
    `PII runtime in full-pii: ${artifacts["full-pii"].piiRuntime.join(", ")}`;
  if (options.guardOnly) {
    console.log(summary);
    if (failures.length > 0) fail(`[measure-wasm-profiles] guard failed:\n  ${failures.join("\n  ")}`);
    return;
  }
  const outDir = resolve(REPO_ROOT, options.outDir);
  const rawDir = join(outDir, "raw");
  mkdirSync(rawDir, { recursive: true });

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
      ARTIFACTS.map((name) => [name, { sizes: artifacts[name].sizes, sha256: artifacts[name].sha256 }]),
    ),
    commonSavedVersusFull: {
      wasmRaw: saved("wasmRawBytes"),
      wasmGzip: saved("wasmGzipBytes"),
      wasmBrotli: saved("wasmBrotliBytes"),
    },
    deltaVersus378Estimate: versus378,
  });

  writeJson(join(outDir, "build-evidence.json"), {
    source,
    guards: { passed: failures.length === 0, failures },
    modulePacks: packs,
    profiles: Object.fromEntries(
      ARTIFACTS.map((name) => [
        name,
        {
          detectorModules: artifacts[name].detectorModules,
          classification: artifacts[name].classification,
          detectorImplementations: artifacts[name].detectorImplementations,
          implementationClassification: artifacts[name].implementationClassification,
          piiRuntime: artifacts[name].piiRuntime,
          exports: artifacts[name].exports,
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
    protocol: "scripts/assessment-browser-performance.mjs through @redact-secret/core, one fresh browser context per run",
    engines: performance,
  });

  console.log(summary);
  if (failures.length > 0) fail(`[measure-wasm-profiles] guard failed:\n  ${failures.join("\n  ")}`);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main();
}
