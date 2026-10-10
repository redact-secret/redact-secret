/**
 * Builds a static custom WebAssembly artifact from a declarative
 * `composition/v1` configuration (issue #1253,
 * `decision-define-the-configuration-capability-ceiling-runtime-ownership-and-surface-support`
 * section 2).
 *
 * The artifact links only the detectors the composition selects: this script
 * resolves the requested ids against the catalog, generates a leaf crate in an
 * ISOLATED build workspace whose registry construction path names exactly the
 * selected per-detector constructors of `redact_secret::composition`, builds
 * that crate for `wasm32-unknown-unknown`, binds it with `wasm-bindgen`, and
 * emits the artifact with its manifest, a capability report, the verified
 * default configuration and a build report. Nothing in the repository's source
 * tree is generated, patched or rewritten, and nothing is emitted unless every
 * check passed: an unsupported id, combination or target, a registry or manifest
 * that differs from the resolved composition, or a packaged manifest that is not
 * the artifact's own fails the build with the output directory untouched.
 *
 * Do not read "static" as "smaller by contract". Removing a detector removes its
 * code and data; the engine floor (pipeline, overlap resolution, redaction,
 * incremental retention logic) and the dependency code stay, and no size or speed
 * guarantee follows. `build-report.json` records the measured numbers when a
 * `full` baseline is available and says plainly when it is not.
 *
 * Usable from a webpack or Vite build hook (tooling only; the consumer's
 * TypeScript or JavaScript never reaches the core runtime):
 *
 *     import { buildCustomArtifact } from "./scripts/build-custom-artifact.mjs";
 *     // in a `buildStart` hook:
 *     await buildCustomArtifact({ composition: "redact.composition.json", outDir: "src/vendor/redact" });
 *
 * and from the command line:
 *
 *     node scripts/build-custom-artifact.mjs --config <composition.json>
 *         [--out-dir <dir>] [--work-dir <dir>] [--baseline <full.wasm>]
 *         [--print-plan] [--debug]
 *
 * Supported target: WebAssembly. A custom Node addon, Python wheel or CLI is
 * unsupported (the surface matrix of the accepted decision); `--target` accepts
 * only `wasm` and fails any other value before anything is built.
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  CompositionError,
  constructorName,
  generateLeafExample,
  generateLeafLib,
  generateLeafManifest,
  parseComposition,
  readCatalog,
  resolveComposition,
} from "./lib/composition.mjs";
import { measureElimination, sizes, wasmExports } from "./lib/wasm-inspect.mjs";

export { CompositionError };

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** The `wasm-bindgen --out-name` of every custom artifact. */
export const OUT_NAME = "redact_secret_wasm_custom";
/** The packaged manifest every custom artifact ships. */
export const PACKAGED_MANIFEST_FILE = "artifact-manifest.custom.json";
const LEAF_PACKAGE = "redact-secret-custom-artifact";
const LEAF_LIB = "redact_secret_custom_artifact";
const REPORT_SCHEMA = "custom-artifact-report/v1";

/** What a custom artifact does not remove, stated once so a report never implies more. */
export const ENGINE_FLOOR = Object.freeze([
  "the detection pipeline, overlap resolution and the default policy",
  "redaction, placeholder formatting and the action-policy engine",
  "the incremental sanitizer and the retention hints it consults for every built-in id",
  "the declarative ruleset adapter, the configuration resolver and the diagnostics",
  "shared text and normalization helpers, and the dependency code they use",
  "the wasm-bindgen glue and every export of the common function set",
]);

/** The surfaces a custom artifact does not exist for, with the accepted reason. */
export const UNSUPPORTED_TARGETS = Object.freeze({
  "node-addon": "a custom Node addon is unsupported; Node uses the published addon or the WebAssembly artifact",
  "python-wheel": "a custom Python wheel is unsupported; Python is a server enforcement surface and stays `full`",
  cli: "a custom CLI is unsupported; the CLI is a server enforcement surface and stays `full`",
  "rust-registry":
    "Rust composes natively through the same constructors (`redact_secret::composition`), without this script",
});

/** An error of the build that is not a rejected composition. */
export class BuildError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "BuildError";
    this.code = code;
  }
}

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function defaultRun(command, args, options = {}) {
  return execFileSync(command, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
    maxBuffer: 256 * 1024 * 1024,
    ...options,
  });
}

/** Reads the repository's resolved workspace facts once. */
function readWorkspace(run, root) {
  const metadata = JSON.parse(run("cargo", ["metadata", "--format-version", "1", "--locked"], { cwd: root }));
  const wasm = metadata.packages.find((entry) => entry.name === "redact-secret-wasm");
  const bindgen = metadata.packages.find((entry) => entry.name === "wasm-bindgen");
  if (wasm === undefined || bindgen === undefined) {
    throw new BuildError("WORKSPACE_INVALID", "the workspace has no redact-secret-wasm or wasm-bindgen package");
  }
  const rootManifest = readFileSync(join(root, "Cargo.toml"), "utf8");
  const requirement = /^wasm-bindgen\s*=\s*"([^"]+)"/mu.exec(rootManifest)?.[1];
  if (requirement === undefined) throw new BuildError("WORKSPACE_INVALID", "Cargo.toml does not pin wasm-bindgen");
  const release = /^\[profile\.release\]\n(?:(?!\[)[^\n]*\n?)*/mu.exec(rootManifest)?.[0] ?? "";
  return {
    version: wasm.version,
    bindgenVersion: bindgen.version,
    bindgenRequirement: requirement,
    releaseProfile: release.trimEnd(),
  };
}

/**
 * The catalog of every built-in detector, from the `full` manifest the CLI
 * prints: the same registration rows a registry is built from, never a second
 * list.
 */
export function loadCatalog({ run = defaultRun, root = REPO_ROOT } = {}) {
  const text = run(
    "cargo",
    ["run", "--quiet", "--locked", "-p", "redact-secret-cli", "--", "--print-artifact-manifest"],
    {
      cwd: root,
    },
  );
  return readCatalog(text);
}

function requireMatchingBindgen(run, expected) {
  let reported;
  try {
    reported = run("wasm-bindgen", ["--version"]).trim();
  } catch {
    throw new BuildError(
      "BINDGEN_MISSING",
      `wasm-bindgen ${expected} is not on PATH; install it with \`cargo install wasm-bindgen-cli --version ${expected} --locked\``,
    );
  }
  const actual = reported.split(/\s+/u).at(-1);
  if (actual !== expected) {
    throw new BuildError(
      "BINDGEN_MISMATCH",
      `wasm-bindgen CLI is ${actual}, but the crate is built against ${expected}; the glue would refuse the module`,
    );
  }
}

/** The 40-hex revision of a clean source tree, or null (a dirty tree has no honest revision). */
function sourceRevision(run, root) {
  try {
    const revision = run("git", ["rev-parse", "HEAD"], { cwd: root }).trim();
    const dirty =
      run("git", ["status", "--porcelain", "--", "crates", "bindings/wasm", "Cargo.toml", "Cargo.lock"], {
        cwd: root,
      }).trim() !== "";
    return { revision: /^[0-9a-f]{40}$/u.test(revision) ? revision : null, dirty };
  } catch {
    return { revision: null, dirty: null };
  }
}

/**
 * Checks that a lock file the leaf build wrote resolves every shared package
 * exactly as the repository's lock does: same version, same source, same
 * checksum. The only package the new lock may add is the generated leaf.
 */
export function verifyLockUnchanged(repositoryLock, builtLock, leaf = LEAF_PACKAGE) {
  const parse = (text) => {
    const packages = new Map();
    for (const block of text.split(/^\[\[package\]\]\n/mu).slice(1)) {
      const field = (name) => new RegExp(`^${name} = "([^"]*)"`, "mu").exec(block)?.[1] ?? null;
      const name = field("name");
      if (name === null) continue;
      const key = `${name}@${field("version")}`;
      packages.set(key, `${field("source")}|${field("checksum")}`);
    }
    return packages;
  };
  const before = parse(repositoryLock);
  const after = parse(builtLock);
  const problems = [];
  for (const [key, identity] of after) {
    if (key.startsWith(`${leaf}@`)) continue;
    if (!before.has(key)) problems.push(`${key} is not in the repository lock`);
    else if (before.get(key) !== identity) problems.push(`${key} resolves differently`);
  }
  return problems;
}

export function bundleEntry({ distDir }) {
  const imports = {
    runtime: JSON.stringify(join(distDir, "runtime.js")),
    binding: JSON.stringify(join(distDir, "runtime", "wasm-binding.js")),
    core: JSON.stringify(join(distDir, "entry-core.js")),
  };
  return `// Generated by scripts/build-custom-artifact.mjs: the wrapper of a static custom
// composition. It has the function set of \`@redact-secret/core/common\` and binds
// the custom glue next to it; \`PROFILE\` is "custom".
import { createRedactSecretRuntime } from ${imports.runtime};
import { assertWasmModuleShape, createBindingFromWasmModule } from ${imports.binding};

export * from ${imports.core};

async function initializeModule(module) {
  // Workers exposes a Node-compatible process, but its module lives in the
  // deployed bundle rather than Node's file system.
  const isCloudflareWorker =
    typeof navigator !== "undefined" && navigator.userAgent === "Cloudflare-Workers";
  const isNode =
    !isCloudflareWorker &&
    typeof process !== "undefined" &&
    process.versions !== undefined &&
    process.versions.node !== undefined &&
    typeof window === "undefined" &&
    typeof document === "undefined";
  if (isNode) {
    // Node's fetch cannot read a file: URL, so Node reads the bytes itself. The
    // specifier is computed so a browser bundler never resolves a node: module.
    const specifier = ["node", "fs/promises"].join(":");
    const { readFile } = await import(specifier);
    await module.default({ module_or_path: await readFile(new URL("./${OUT_NAME}_bg.wasm", import.meta.url)) });
  } else {
    await module.default();
  }
}

async function loadNativeBinding() {
  const module = await import("./${OUT_NAME}.js");
  assertWasmModuleShape(module);
  await initializeModule(module);
  return createBindingFromWasmModule(module);
}

const runtime = createRedactSecretRuntime(loadNativeBinding, "custom");

export const initialize = runtime.initialize;
export const piiActivation = runtime.piiActivation;
export const status = runtime.status;
export const artifact = runtime.artifact;
export const artifactManifest = runtime.artifactManifest;
export const resolveConfig = runtime.resolveConfig;
export const describeConfig = runtime.describeConfig;
export const scan = runtime.scan;
export const redact = runtime.redact;
export const scanAndRedact = runtime.scanAndRedact;
export const compareActionPolicies = runtime.compareActionPolicies;
export const compareConfigurations = runtime.compareConfigurations;
export const createIncrementalSanitizer = runtime.createIncrementalSanitizer;
export const defaultPolicy = runtime.defaultPolicy;

/** The detector profile of this wrapper: a static custom composition. */
export const PROFILE = "custom";
`;
}

/** Every `.d.ts` file the declarations of `common.d.ts` reach through relative imports. */
function declarationClosure(distDir) {
  const seen = new Map();
  const queue = ["common.d.ts"];
  while (queue.length > 0) {
    const relative = queue.pop();
    if (seen.has(relative)) continue;
    const text = readFileSync(join(distDir, relative), "utf8");
    seen.set(relative, text);
    for (const match of text.matchAll(/from\s+"(\.{1,2}\/[^"]+)\.js"/gu)) {
      const next = join(dirname(relative), `${match[1]}.d.ts`).replaceAll("\\", "/");
      queue.push(next);
    }
  }
  return seen;
}

const WRAPPER_DECLARATION = `// Generated by scripts/build-custom-artifact.mjs.
export * from "./types/common.js";
/** The detector profile of this wrapper: a static custom composition. */
export declare const PROFILE: "custom";
`;

function emitReportJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

const VERIFY_SCRIPT = `// Generated: loads the emitted wrapper in a fresh process and reports what the
// artifact says about itself. Reads and writes nothing.
const wrapper = await import(process.argv[2]);
await wrapper.initialize();
const manifest = wrapper.artifactManifest();
const snapshot = wrapper.describeConfig();
const status = wrapper.status();
const resolution = wrapper.resolveConfig();
process.stdout.write(JSON.stringify({
  profile: wrapper.PROFILE,
  status,
  manifest,
  snapshot,
  resolutionOk: resolution.ok,
  artifact: wrapper.artifact(),
  exports: Object.keys(wrapper).sort(),
}));
`;

/**
 * Resolves a composition without building anything: the plan a build would
 * execute, or the error it would stop at.
 */
export function planCustomArtifact({ composition, catalog, target = "wasm" }) {
  if (target !== "wasm") {
    const reason = UNSUPPORTED_TARGETS[target];
    throw new CompositionError("UNSUPPORTED_TARGET", reason === undefined ? "target" : `target (${reason})`);
  }
  const parsed = parseComposition(composition);
  return resolveComposition(parsed, catalog);
}

function readComposition(composition) {
  if (typeof composition !== "string") return composition;
  let text;
  try {
    text = readFileSync(composition, "utf8");
  } catch {
    throw new BuildError("COMPOSITION_UNREADABLE", "the composition file cannot be read");
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new CompositionError("INVALID_JSON");
  }
}

function writeLeaf(workDir, resolved, workspace, root) {
  const leaf = join(workDir, "leaf");
  mkdirSync(join(leaf, "src"), { recursive: true });
  mkdirSync(join(leaf, "examples"), { recursive: true });
  writeFileSync(
    join(workDir, "Cargo.toml"),
    `# Generated by scripts/build-custom-artifact.mjs: an isolated workspace for one custom artifact.
[workspace]
resolver = "3"
members = ["leaf"]

${workspace.releaseProfile}
`,
  );
  cpSync(join(root, "Cargo.lock"), join(workDir, "Cargo.lock"));
  writeFileSync(
    join(leaf, "Cargo.toml"),
    generateLeafManifest({
      version: workspace.version,
      coreDir: join(root, "crates", "secret-scan-core"),
      wasmDir: join(root, "bindings", "wasm"),
      bindgenRequirement: workspace.bindgenRequirement,
      pii: resolved.pii === "all",
    }),
  );
  writeFileSync(join(leaf, "src", "lib.rs"), generateLeafLib(resolved));
  writeFileSync(join(leaf, "examples", "print_manifest.rs"), generateLeafExample());
  // The packaged manifest is compiled in, so a placeholder lets the native
  // helper build; the real document replaces it before the artifact is built.
  writeFileSync(join(leaf, PACKAGED_MANIFEST_FILE), "{}");
  return leaf;
}

/**
 * Builds the custom artifact. Resolves and validates first; nothing is
 * written to `outDir` unless every check passed.
 *
 * @param {object} options
 * @param {string | object} options.composition a `composition/v1` document, or the path of its JSON file
 * @param {string} [options.outDir] where the artifact is emitted (default `target/custom-artifacts/<name>`)
 * @param {string} [options.workDir] the isolated build workspace (default `<outDir>.work`)
 * @param {string} [options.baseline] the `.wasm` of a `full` build of this source, for measured elimination
 * @param {boolean} [options.debug] build without `--release`
 * @param {string} [options.target] only `wasm`
 * @param {object[]} [options.catalog] a catalog, instead of reading it from the CLI
 * @param {Function} [options.run] a command runner (tests)
 * @param {string} [options.root] the repository root
 * @returns the build report
 */
export async function buildCustomArtifact(options) {
  const root = options.root ?? REPO_ROOT;
  const run = options.run ?? defaultRun;
  const log = options.log ?? (() => {});

  // 1. Resolve and validate: nothing below runs on an invalid input.
  const document = readComposition(options.composition);
  const catalog = options.catalog ?? loadCatalog({ run, root });
  const resolved = planCustomArtifact({ composition: document, catalog, target: options.target });
  const outDir = resolve(root, options.outDir ?? join("target", "custom-artifacts", resolved.name));
  const workDir = resolve(root, options.workDir ?? `${outDir}.work`);
  if (existsSync(outDir) && readdirSync(outDir).length > 0 && !existsSync(join(outDir, "build-report.json"))) {
    throw new BuildError("OUT_DIR_NOT_EMPTY", "the output directory exists and is not a previous custom artifact");
  }

  // 2. Workspace and toolchain.
  const workspace = readWorkspace(run, root);
  requireMatchingBindgen(run, workspace.bindgenVersion);
  const revision = options.sourceRevision ?? sourceRevision(run, root);
  // A rehearsal keeps its dirty/null identity and separately proves the exact version transform.
  const rehearsalSource = process.env.REHEARSAL_VERSION
    ? JSON.parse(
        run(
          "python3",
          [
            "-B",
            join(root, "scripts", "rehearsal-version.py"),
            "provenance",
            "--source",
            revision.revision ?? "",
            "--version",
            process.env.REHEARSAL_VERSION,
            "--run-id",
            process.env.GITHUB_RUN_ID ?? "",
          ],
          { cwd: root },
        ),
      )
    : undefined;
  rmSync(workDir, { recursive: true, force: true });
  mkdirSync(workDir, { recursive: true });
  const leaf = writeLeaf(workDir, resolved, workspace, root);
  const env = { ...process.env, CARGO_TARGET_DIR: join(workDir, "target") };
  // A dirty or unknown tree has no honest revision: the manifest then says null.
  if (revision.revision !== null && revision.dirty === false) env.REDACT_SECRET_SOURCE_REVISION = revision.revision;
  else delete env.REDACT_SECRET_SOURCE_REVISION;
  const cargo = (args, extra = {}) => run("cargo", args, { cwd: workDir, env, ...extra });

  // 3. What the composition actually builds, natively, compared with the plan.
  log("generating and checking the composition natively");
  const manifestText = cargo(["run", "--quiet", "--example", "print_manifest", "-p", LEAF_PACKAGE, "--", "manifest"]);
  const registryIds = cargo(["run", "--quiet", "--example", "print_manifest", "-p", LEAF_PACKAGE, "--", "registry"])
    .split("\n")
    .filter((line) => line !== "");
  const manifest = JSON.parse(manifestText);
  const mismatches = [];
  if (manifest.composition?.id !== resolved.id) mismatches.push("composition id");
  if (manifest.composition?.kind !== "custom" || manifest.artifact?.variant !== "custom") mismatches.push("variant");
  if (JSON.stringify(manifest.detectors.map((entry) => entry.id)) !== JSON.stringify(resolved.ids)) {
    mismatches.push("manifest detectors");
  }
  if (JSON.stringify(manifest.notIncluded) !== JSON.stringify(resolved.notIncluded)) mismatches.push("notIncluded");
  if (JSON.stringify(registryIds) !== JSON.stringify(resolved.ids)) mismatches.push("registry ids");
  if (manifest.artifact?.pii !== (resolved.pii === "all")) mismatches.push("pii");
  if (mismatches.length > 0) {
    throw new BuildError("MISLABELED", `the built composition differs from the resolved one: ${mismatches.join(", ")}`);
  }
  writeFileSync(join(leaf, PACKAGED_MANIFEST_FILE), manifestText);

  // 4. The artifact.
  log("building the WebAssembly artifact");
  const buildArgs = ["build", "-p", LEAF_PACKAGE, "--target", "wasm32-unknown-unknown"];
  if (!options.debug) buildArgs.push("--release");
  cargo(buildArgs, { stdio: "inherit" });
  const lockProblems = verifyLockUnchanged(
    readFileSync(join(root, "Cargo.lock"), "utf8"),
    readFileSync(join(workDir, "Cargo.lock"), "utf8"),
  );
  if (lockProblems.length > 0) {
    throw new BuildError("LOCK_DRIFT", `the isolated workspace resolved dependencies differently: ${lockProblems[0]}`);
  }
  const wasm = join(
    workDir,
    "target",
    "wasm32-unknown-unknown",
    options.debug ? "debug" : "release",
    `${LEAF_LIB}.wasm`,
  );
  const glueDir = join(workDir, "glue");
  mkdirSync(glueDir, { recursive: true });
  run("wasm-bindgen", ["--target", "web", "--out-dir", glueDir, "--out-name", OUT_NAME, wasm], { stdio: "inherit" });

  // 5. The wrapper, with the function set of `./common`.
  const distDir = join(root, "packages", "javascript", "dist");
  if (!existsSync(join(distDir, "runtime.js"))) {
    throw new BuildError("JS_NOT_BUILT", "packages/javascript/dist is missing; run `npm run js:build` first");
  }
  const { build } = await import("esbuild");
  const entry = join(workDir, "wrapper-entry.mjs");
  writeFileSync(entry, bundleEntry({ distDir }));
  const stage = join(workDir, "stage");
  rmSync(stage, { recursive: true, force: true });
  mkdirSync(stage, { recursive: true });
  for (const name of [`${OUT_NAME}.js`, `${OUT_NAME}.d.ts`, `${OUT_NAME}_bg.wasm`, `${OUT_NAME}_bg.wasm.d.ts`]) {
    cpSync(join(glueDir, name), join(stage, name));
  }
  await build({
    entryPoints: [entry],
    outfile: join(stage, "index.js"),
    bundle: true,
    format: "esm",
    platform: "neutral",
    target: "es2022",
    external: [`./${OUT_NAME}.js`],
    legalComments: "none",
    logLevel: "silent",
  });
  writeFileSync(join(stage, "index.d.ts"), WRAPPER_DECLARATION);
  for (const [relative, text] of declarationClosure(distDir)) {
    const target = join(stage, "types", relative);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, text);
  }
  writeFileSync(join(stage, PACKAGED_MANIFEST_FILE), manifestText);

  // 6. The artifact verifies itself in a fresh process.
  log("verifying the emitted artifact");
  const verifier = join(workDir, "verify.mjs");
  writeFileSync(verifier, VERIFY_SCRIPT);
  const observed = JSON.parse(
    run(process.execPath, [verifier, pathToFileURL(join(stage, "index.js")).href], { cwd: workDir }),
  );
  const problems = [];
  const reported = JSON.stringify(observed.manifest);
  if (observed.profile !== "custom" || observed.status.profile !== "custom") problems.push("profile");
  if (observed.manifest.digest !== manifest.digest) problems.push("manifest digest");
  if (observed.manifest.composition.id !== resolved.id) problems.push("composition id");
  if (JSON.stringify(observed.snapshot.detection.enabled) !== JSON.stringify(resolved.ids))
    problems.push("enabled set");
  if (observed.snapshot.artifact.compositionId !== resolved.id) problems.push("snapshot composition id");
  if (observed.snapshot.artifact.manifestDigest !== manifest.digest) problems.push("snapshot manifest digest");
  if (observed.snapshot.detection.mode !== "all-included") problems.push("default mode");
  if (observed.artifact !== "wasm") problems.push("artifact kind");
  if (reported.length === 0) problems.push("manifest");
  if (problems.length > 0) {
    throw new BuildError(
      "SELF_REPORT_MISMATCH",
      `the artifact's self-report differs from the build: ${problems.join(", ")}`,
    );
  }

  // 7. Measured elimination, only when a `full` baseline exists.
  const wasmBytes = readFileSync(join(stage, `${OUT_NAME}_bg.wasm`));
  const baselinePath = options.baseline;
  let elimination = {
    measured: false,
    reason: "no `full` baseline was supplied; pass --baseline <full.wasm> built from this source revision",
    custom: sizes(wasmBytes),
  };
  if (baselinePath !== undefined) {
    const baseline = readFileSync(baselinePath);
    elimination = {
      measured: true,
      baseline: { sha256: sha256Hex(baseline) },
      ...measureElimination(wasmBytes, baseline),
    };
  }

  // 8. Reports.
  const toolchain = {
    rustc: run("rustc", ["--version"], { cwd: workDir }).trim(),
    cargo: run("cargo", ["--version"], { cwd: workDir }).trim(),
    wasmBindgen: workspace.bindgenVersion,
    node: process.version,
    esbuild: (await import("esbuild")).version,
    target: "wasm32-unknown-unknown",
    profile: options.debug ? "debug" : "release",
  };
  const glueFiles = Object.fromEntries(
    [
      `${OUT_NAME}.js`,
      `${OUT_NAME}.d.ts`,
      `${OUT_NAME}_bg.wasm`,
      `${OUT_NAME}_bg.wasm.d.ts`,
      "index.js",
      "index.d.ts",
    ].map((name) => [name, sha256Hex(readFileSync(join(stage, name)))]),
  );
  const capability = {
    schema: "custom-artifact-capability/v1",
    composition: { name: resolved.name, id: resolved.id, pii: resolved.pii },
    included: resolved.detectors.map(({ id, pack, types }) => ({ id, pack, types })),
    notIncluded: resolved.notIncluded,
    capabilities: manifest.capabilities,
    ceiling: [
      "A runtime `initialize({ detection })` can only narrow within the included detectors.",
      "A detector that is not included is rejected with DETECTOR_NOT_INCLUDED; no other artifact is loaded to satisfy it.",
      "The action policy and whole-input limits are per call and need no rebuild; a policy cannot add a finding.",
    ],
    diagnostics: [
      {
        code: "OVERLAP_OUTCOMES_MAY_CHANGE",
        severity: "info",
        message: `${resolved.notIncluded.length} built-in detectors are not included: a span they would have owned can be reported by a weaker included detector, or not at all.`,
      },
    ],
    retainedEngineFloor: ENGINE_FLOOR,
    guarantees: "none: no size or speed guarantee follows from selecting fewer detectors",
    targets: { supported: ["wasm"], unsupported: UNSUPPORTED_TARGETS },
  };
  const report = {
    schema: REPORT_SCHEMA,
    version: workspace.version,
    engine: {
      sourceRevision: revision.revision,
      sourceTreeDirty: revision.dirty,
      ...(rehearsalSource ? { rehearsalSource } : {}),
    },
    toolchain,
    composition: { name: resolved.name, id: resolved.id, document: JSON.parse(resolved.document) },
    manifest: { file: PACKAGED_MANIFEST_FILE, digest: manifest.digest },
    artifact: { kind: "wasm", variant: "custom", pii: resolved.pii === "all", exports: wasmExports(wasmBytes) },
    files: glueFiles,
    bundledDefaults: manifest.defaults,
    elimination,
    reproduction: [
      "Same engine source revision, same toolchain versions and the same composition document reproduce the artifact.",
      "Byte-identical output is not promised across machines; the manifest digest and composition identity are.",
    ],
    isolation: "generated and built under the workspace directory; no repository source file was written",
  };
  emitReportJson(join(stage, "capability-report.json"), capability);
  emitReportJson(join(stage, "default-configuration.json"), observed.snapshot);
  writeFileSync(join(stage, "composition.json"), `${resolved.document}\n`);
  emitReportJson(join(stage, "build-report.json"), report);

  // 9. Emit atomically: the output directory changes only now.
  const staging = mkdtempSync(`${outDir}.emit-`);
  cpSync(stage, staging, { recursive: true });
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(dirname(outDir), { recursive: true });
  renameSync(staging, outDir);
  return { ...report, outDir, workDir, resolved };
}

function parseArguments(argv) {
  const options = { debug: false, printPlan: false };
  const needs = (name, index) => {
    const value = argv[index + 1];
    if (value === undefined) throw new BuildError("USAGE", `${name} requires a value`);
    return value;
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--config") options.composition = needs(argument, index++);
    else if (argument === "--out-dir") options.outDir = needs(argument, index++);
    else if (argument === "--work-dir") options.workDir = needs(argument, index++);
    else if (argument === "--baseline") options.baseline = needs(argument, index++);
    else if (argument === "--target") options.target = needs(argument, index++);
    else if (argument === "--debug") options.debug = true;
    else if (argument === "--print-plan") options.printPlan = true;
    else throw new BuildError("USAGE", `unknown argument: ${argument}`);
  }
  if (options.composition === undefined) throw new BuildError("USAGE", "--config <composition.json> is required");
  return options;
}

async function main() {
  try {
    const options = parseArguments(process.argv.slice(2));
    if (options.printPlan) {
      const plan = planCustomArtifact({
        composition: readComposition(options.composition),
        catalog: loadCatalog(),
        target: options.target,
      });
      process.stdout.write(
        `${JSON.stringify({ name: plan.name, id: plan.id, pii: plan.pii, ids: plan.ids, notIncluded: plan.notIncluded }, null, 2)}\n`,
      );
      return;
    }
    const report = await buildCustomArtifact({ ...options, log: (message) => console.error(message) });
    console.log(
      `built the custom artifact ${report.composition.id} (${report.composition.name}) in ${report.outDir}: ` +
        `${report.elimination.custom.raw} bytes raw, ${report.elimination.custom.brotli} brotli`,
    );
  } catch (error) {
    if (error instanceof CompositionError || error instanceof BuildError) {
      console.error(`${error.code}: ${error.message}`);
      process.exit(error instanceof CompositionError ? 2 : 1);
    }
    throw error;
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  await main();
}

export { constructorName };
