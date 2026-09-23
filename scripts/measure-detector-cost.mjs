/**
 * Builds and measures compile-time detector-composition variants of the
 * redact-secret core, for issue #378 (parent epic #377): artifact size
 * (native raw; WASM raw/gzip/brotli) and runtime cost (native whole-input,
 * WASM whole-input, WASM streaming/fixed-chunk) per variant.
 *
 * Mechanism: `built_in_detectors()` in
 * `crates/secret-scan-core/src/detectors/mod.rs` lists exactly one
 * `Box::new(...)` (or bare call) entry per detector, one per line, in the
 * same order as the canonical id list asserted by
 * `built_in_order_matches_the_typescript_oracle` in the same file. To build
 * a variant, this tool comments out (`// `) the vec entries at the
 * positions of the ids to exclude, runs a real `cargo`/`wasm-bindgen`
 * build, measures the result, and always restores the file with
 * `git checkout --` -- even on failure -- so the shipped registry never
 * changes. No public API, package split, or release action follows from
 * running this tool.
 *
 * Usage:
 *
 *     npm run js:build   # once; the JS wrapper is not detector-sensitive
 *     cargo build --release --locked -p redact-secret-cli  # warms the cache
 *
 *     node scripts/measure-detector-cost.mjs --variant full \
 *       --out-dir docs/audits/evidence/378 --scratch-dir /tmp/detector-cost
 *
 *     node scripts/measure-detector-cost.mjs --aggregate \
 *       --out-dir docs/audits/evidence/378
 *
 * `--variant <name>` builds and measures exactly one named variant (see
 * `VARIANTS` below), writing `<out-dir>/raw/<name>/{cli-whole,wasm-whole,
 * wasm-fixed4096,summary}.json`. `--aggregate` reads every
 * `<out-dir>/raw/*\/summary.json` already on disk and writes the top-level
 * `<out-dir>/compositions.json` and `<out-dir>/artifact-sizes.json`. Both
 * exist so a full 8-variant run can be split across separate invocations
 * without holding one long-lived process.
 */
import { execFileSync, spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { brotliCompressSync, constants as zlibConstants, gzipSync } from "node:zlib";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MOD_RS = join(REPO_ROOT, "crates", "secret-scan-core", "src", "detectors", "mod.rs");

/**
 * Canonical registration order, copied verbatim from
 * `built_in_order_matches_the_typescript_oracle` in
 * `crates/secret-scan-core/src/detectors/mod.rs`. Position N here must
 * match vec entry N in `built_in_detectors()`; `parseVecBlock` asserts the
 * entry count agrees with this list's length before any position is
 * trusted, so a future detector addition/removal fails loudly here instead
 * of silently mismatching.
 */
export const CANONICAL_IDS = [
  "private-key", "aws-access-key", "github-token", "gitlab-token", "openai-token",
  "anthropic-token", "shopify-token", "vault-token", "stripe-token", "slack-token",
  "pypi-token", "huggingface-token", "docker-token", "cloudflare-token", "digitalocean-token",
  "linear-token", "supabase-token", "supabase-management-token", "vercel-token", "npm-token", "google-api-key",
  "sendgrid-token", "microsoft-entra-client-secret", "azure-devops-personal-access-token",
  "notion-token", "atlassian-api-token", "twilio-auth-token", "twilio-api-key-secret",
  "telegram-bot-token", "discord-bot-token", "sentry-user-auth-token", "sentry-org-auth-token",
  "datadog-api-key", "datadog-application-key", "grafana-service-account-token",
  "grafana-cloud-access-policy-token", "new-relic-user-api-key", "new-relic-license-key",
  "mailchimp-api-key", "mailgun-api-key",
  "firebase-server-key", "terraform-cloud-token", "pulumi-access-token", "databricks-personal-access-token",
  "confluent-cloud-api-secret", "confluent-cloud-api-secret-legacy", "netlify-token", "postman-api-key",
  "heroku-api-key", "heroku-api-key-legacy",
  "jwt", "bearer-token", "connection-string", "otpauth-uri", "generic-token",
];

/**
 * Illustrative measurement groupings for this baseline only -- NOT a
 * proposed pack taxonomy; that contract is issue #379's job. Every
 * canonical id appears in exactly one of `STRUCTURAL_IDS` or one `GROUPS`
 * entry (asserted by `scripts/tests/measure-detector-cost.test.mjs`).
 */
export const STRUCTURAL_IDS = [
  "private-key", "jwt", "bearer-token", "connection-string", "otpauth-uri", "generic-token",
];
export const GROUPS = {
  ai: ["openai-token", "anthropic-token", "huggingface-token"],
  cloud: [
    "aws-access-key", "vault-token", "cloudflare-token", "digitalocean-token", "supabase-token",
    "supabase-management-token", "vercel-token", "google-api-key", "microsoft-entra-client-secret", "datadog-api-key",
    "datadog-application-key", "grafana-service-account-token", "grafana-cloud-access-policy-token",
    "new-relic-user-api-key", "new-relic-license-key", "firebase-server-key", "terraform-cloud-token",
    "pulumi-access-token", "databricks-personal-access-token",
    "confluent-cloud-api-secret", "confluent-cloud-api-secret-legacy", "netlify-token", "postman-api-key",
    "heroku-api-key", "heroku-api-key-legacy",
  ],
  devtools: [
    "github-token", "gitlab-token", "azure-devops-personal-access-token", "notion-token",
    "atlassian-api-token", "linear-token",
  ],
  "pkg-registry": ["pypi-token", "docker-token", "npm-token"],
  saas: [
    "shopify-token", "stripe-token", "slack-token", "sendgrid-token", "twilio-auth-token",
    "twilio-api-key-secret", "telegram-bot-token", "discord-bot-token", "sentry-user-auth-token",
    "sentry-org-auth-token", "mailchimp-api-key", "mailgun-api-key",
  ],
};

export const VARIANTS = {
  full: { exclude: [] },
  "engine-only": { exclude: [...CANONICAL_IDS] },
  "tiny-common": { exclude: CANONICAL_IDS.filter((id) => !STRUCTURAL_IDS.includes(id)) },
  "minus-ai": { exclude: GROUPS.ai },
  "minus-cloud": { exclude: GROUPS.cloud },
  "minus-devtools": { exclude: GROUPS.devtools },
  "minus-pkg-registry": { exclude: GROUPS["pkg-registry"] },
  "minus-saas": { exclude: GROUPS.saas },
};

function fail(message) {
  console.error(message);
  process.exit(1);
}

/** Locates the `vec![ ... ]` block inside `built_in_detectors()` and splits it into one non-blank line per entry. */
export function parseVecBlock(source) {
  const fnStart = source.indexOf("fn built_in_detectors()");
  if (fnStart === -1) throw new Error("built_in_detectors() not found");
  const vecStart = source.indexOf("vec![", fnStart);
  if (vecStart === -1) throw new Error("vec![ not found in built_in_detectors()");
  const bodyStart = vecStart + "vec![".length;
  const vecEnd = source.indexOf("\n    ]", bodyStart);
  if (vecEnd === -1) throw new Error("closing ] of vec![ not found");
  const body = source.slice(bodyStart, vecEnd);
  const lines = body.split("\n").filter((line) => line.trim().length > 0);
  return { lines, bodyStart, vecEnd };
}

/** Returns `source` with the vec entries for `excludeIds` commented out, everything else byte-identical. */
export function buildPatchedSource(source, excludeIds) {
  const { lines, bodyStart, vecEnd } = parseVecBlock(source);
  if (lines.length !== CANONICAL_IDS.length) {
    throw new Error(
      `vec! has ${lines.length} entries but ${CANONICAL_IDS.length} canonical ids are known -- id/line zip is unsafe`,
    );
  }
  const excludeSet = new Set(excludeIds);
  const patchedLines = lines.map((line, index) => {
    const id = CANONICAL_IDS[index];
    if (!excludeSet.has(id)) return line;
    const indent = line.match(/^(\s*)/)[1];
    return `${indent}// excluded by scripts/measure-detector-cost.mjs (${id})`;
  });
  return source.slice(0, bodyStart) + "\n" + patchedLines.join("\n") + source.slice(vecEnd);
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: REPO_ROOT,
    stdio: ["ignore", "inherit", "inherit"],
    ...options,
  });
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) throw new Error(`${command} ${args.join(" ")} exited ${result.status}`);
}

function runCapture(command, args) {
  return execFileSync(command, args, { cwd: REPO_ROOT, encoding: "utf8" });
}

/**
 * Patches `mod.rs`, runs `fn`, and writes the original bytes back (even on
 * failure). Refuses a locally modified `mod.rs`: the measurement is only
 * meaningful against committed source.
 */
function withPatchedRegistry(excludeIds, fn) {
  if (runCapture("git", ["status", "--porcelain", "--", MOD_RS]).trim() !== "") {
    throw new Error(`${MOD_RS} has uncommitted changes; commit or stash them first`);
  }
  const original = readFileSync(MOD_RS, "utf8");
  writeFileSync(MOD_RS, buildPatchedSource(original, excludeIds));
  try {
    return fn();
  } finally {
    writeFileSync(MOD_RS, original);
  }
}

function buildNative() {
  run("cargo", ["build", "--release", "--locked", "-p", "redact-secret-cli"]);
  const binaryPath = join(REPO_ROOT, "target", "release", "redact-secret");
  if (!existsSync(binaryPath)) throw new Error("native binary missing after build");
  return binaryPath;
}

function buildWasm(outDir) {
  run("node", ["scripts/build-browser-artifact.mjs", "--out-dir", outDir]);
}

export function gzipSize(buffer) {
  return gzipSync(buffer, { level: 9 }).length;
}

export function brotliSize(buffer) {
  return brotliCompressSync(buffer, {
    params: { [zlibConstants.BROTLI_PARAM_QUALITY]: 11 },
  }).length;
}

function measureSizes(nativeBinaryPath, wasmDir) {
  const nativeRawBytes = statSync(nativeBinaryPath).size;
  const wasmBuffer = readFileSync(join(wasmDir, "redact_secret_wasm_bg.wasm"));
  const jsBuffer = readFileSync(join(wasmDir, "redact_secret_wasm.js"));
  return {
    nativeRawBytes,
    wasmRawBytes: wasmBuffer.length,
    wasmGzipBytes: gzipSize(wasmBuffer),
    wasmBrotliBytes: brotliSize(wasmBuffer),
    jsGlueRawBytes: jsBuffer.length,
  };
}

function runMeasurementScript(args) {
  run(process.execPath, args);
}

async function runVariant(name, outDir, scratchRoot) {
  const definition = VARIANTS[name];
  if (definition === undefined) fail(`unknown variant: ${name}`);

  const rawDir = join(outDir, "raw", name);
  mkdirSync(rawDir, { recursive: true });
  const scratchDir = join(scratchRoot, name);
  mkdirSync(scratchDir, { recursive: true });
  const wasmDir = join(scratchDir, "wasm");

  let stableBinary;
  withPatchedRegistry(definition.exclude, () => {
    const builtBinary = buildNative();
    stableBinary = join(scratchDir, "redact-secret");
    copyFileSync(builtBinary, stableBinary);
    execFileSync("chmod", ["+x", stableBinary]);
    buildWasm(wasmDir);
  });

  const sizes = measureSizes(stableBinary, wasmDir);

  runMeasurementScript([
    join(REPO_ROOT, "scripts", "assessment-cli-performance.mjs"),
    "--binary", stableBinary,
    "--profile", "scale-logs-small-whole",
    "--runs", "10",
    "--json-out", join(rawDir, "cli-whole.json"),
  ]);
  runMeasurementScript([
    join(REPO_ROOT, "scripts", "assessment-browser-performance.mjs"),
    "--artifact-dir", wasmDir,
    "--profile", "scale-logs-small-whole",
    "--runs", "10",
    "--json-out", join(rawDir, "wasm-whole.json"),
  ]);
  runMeasurementScript([
    join(REPO_ROOT, "scripts", "assessment-browser-performance.mjs"),
    "--artifact-dir", wasmDir,
    "--profile", "scale-logs-medium-fixed4096",
    "--runs", "10",
    "--json-out", join(rawDir, "wasm-fixed4096.json"),
  ]);

  const includedIds = CANONICAL_IDS.filter((id) => !definition.exclude.includes(id));
  const summary = {
    variant: name,
    detectorCount: includedIds.length,
    includedIds,
    excludedIds: definition.exclude,
    sizes,
    rawFiles: {
      cliWhole: "cli-whole.json",
      wasmWhole: "wasm-whole.json",
      wasmFixed4096: "wasm-fixed4096.json",
    },
  };
  writeFileSync(join(rawDir, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
  console.log(`[measure-detector-cost] ${name}: ${includedIds.length} detectors, wasm raw ${sizes.wasmRawBytes}B / gzip ${sizes.wasmGzipBytes}B / brotli ${sizes.wasmBrotliBytes}B, native ${sizes.nativeRawBytes}B`);
  return summary;
}

function aggregate(outDir) {
  const rawRoot = join(outDir, "raw");
  if (!existsSync(rawRoot)) fail(`${rawRoot}: missing; run --variant first`);
  const variantNames = readdirSync(rawRoot).filter((name) =>
    existsSync(join(rawRoot, name, "summary.json")),
  );
  if (variantNames.length === 0) fail(`${rawRoot}: no variant summaries found`);

  const summaries = variantNames
    .sort()
    .map((name) => JSON.parse(readFileSync(join(rawRoot, name, "summary.json"), "utf8")));

  const compositions = {
    canonicalIds: CANONICAL_IDS,
    canonicalDetectorCount: CANONICAL_IDS.length,
    structuralIds: STRUCTURAL_IDS,
    groups: GROUPS,
    variants: Object.fromEntries(
      summaries.map((summary) => [
        summary.variant,
        {
          detectorCount: summary.detectorCount,
          includedIds: summary.includedIds,
          excludedIds: summary.excludedIds,
        },
      ]),
    ),
  };
  writeFileSync(join(outDir, "compositions.json"), `${JSON.stringify(compositions, null, 2)}\n`);

  const artifactSizes = {
    variants: Object.fromEntries(
      summaries.map((summary) => [summary.variant, { detectorCount: summary.detectorCount, ...summary.sizes }]),
    ),
  };
  writeFileSync(join(outDir, "artifact-sizes.json"), `${JSON.stringify(artifactSizes, null, 2)}\n`);
  console.log(`[measure-detector-cost] aggregated ${summaries.length} variant(s) into ${outDir}/compositions.json and artifact-sizes.json`);
}

function parseArguments(argv) {
  const options = { variant: undefined, aggregate: false, outDir: undefined, scratchDir: undefined };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--variant") options.variant = argv[(index += 1)];
    else if (argument === "--aggregate") options.aggregate = true;
    else if (argument === "--out-dir") options.outDir = argv[(index += 1)];
    else if (argument === "--scratch-dir") options.scratchDir = argv[(index += 1)];
    else fail(`unknown argument: ${argument}`);
  }
  if (options.outDir === undefined) fail("--out-dir is required");
  if (!options.aggregate && options.variant === undefined) fail("--variant <name> or --aggregate is required");
  return options;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const outDir = resolve(REPO_ROOT, options.outDir);
  mkdirSync(outDir, { recursive: true });

  if (options.aggregate) {
    aggregate(outDir);
    return;
  }

  const scratchRoot = options.scratchDir !== undefined
    ? resolve(options.scratchDir)
    : join(tmpdir(), "redact-secret-detector-cost");
  mkdirSync(scratchRoot, { recursive: true });
  await runVariant(options.variant, outDir, scratchRoot);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  await main();
}
