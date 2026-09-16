/** Run the bounded, complete cross-language assessment suite. */
import { spawnSync } from "node:child_process";
import {
  existsSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync,
} from "node:fs";
import { join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { loadTsModule } from "./lib/load-ts-module.mjs";
import { loadAssessmentSchema } from "./lib/assessment-emit.mjs";
import { loadWorkloadProfiles, REPO_ROOT } from "./lib/assessment-provenance.mjs";

const DEFAULT_PROFILES = ["scale-logs-small-whole", "scale-logs-medium-fixed4096"];

function fail(message) {
  console.error(message);
  process.exit(1);
}

function requiredValue(argument, value) {
  if (value === undefined || value.length === 0) fail(`${argument} requires a value`);
  return value;
}

function parseArguments(argv) {
  const options = {
    outputDir: "assessment-output", python: ".venv/bin/python",
    binary: "target/release/redact-secret", addonDir: "bindings/node",
    artifactDir: "bindings/wasm/pkg", engine: "chromium", runs: 2,
    profiles: [],
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const value = argv[index + 1];
    if (argument === "--output-dir") { options.outputDir = requiredValue(argument, value); index += 1; }
    else if (argument === "--python") { options.python = requiredValue(argument, value); index += 1; }
    else if (argument === "--binary") { options.binary = requiredValue(argument, value); index += 1; }
    else if (argument === "--addon-dir") { options.addonDir = requiredValue(argument, value); index += 1; }
    else if (argument === "--artifact-dir") { options.artifactDir = requiredValue(argument, value); index += 1; }
    else if (argument === "--engine") { options.engine = requiredValue(argument, value); index += 1; }
    else if (argument === "--runs") { options.runs = Number(requiredValue(argument, value)); index += 1; }
    else if (argument === "--profile") { options.profiles.push(requiredValue(argument, value)); index += 1; }
    else fail(`unknown argument: ${argument}`);
  }
  if (!Number.isSafeInteger(options.runs) || options.runs < 2 || options.runs > 100) {
    fail("--runs must be an integer from 2 through 100");
  }
  if (!['chromium', 'firefox', 'webkit'].includes(options.engine)) {
    fail("--engine must be one of chromium, firefox, webkit");
  }
  if (options.profiles.length === 0) options.profiles = [...DEFAULT_PROFILES];
  if (new Set(options.profiles).size !== options.profiles.length) fail("--profile values must be unique");
  return options;
}

function displayPath(path) {
  const shown = relative(REPO_ROOT, path);
  return shown.startsWith("..") ? path : shown;
}

function makePaths(outputDir, surface, profileId, accuracy) {
  const directory = join(outputDir, surface);
  mkdirSync(directory, { recursive: true });
  return {
    resultPath: join(directory, `${profileId}.json`),
    markdownPath: join(directory, `${profileId}.md`),
    mismatchesPath: accuracy ? join(directory, `${profileId}-mismatches.json`) : undefined,
  };
}

function runCommand(command, args) {
  const outcome = spawnSync(command, args, { cwd: REPO_ROOT, stdio: "inherit" });
  return outcome.error === undefined && outcome.status === 0;
}

function commandFor(surface, kind, profile, paths, options) {
  const outputArgs = ["--json-out", displayPath(paths.resultPath), "--markdown-out", displayPath(paths.markdownPath)];
  if (kind === "accuracy" && paths.mismatchesPath !== undefined) {
    outputArgs.push("--mismatches-out", displayPath(paths.mismatchesPath));
  }
  if (surface === "rust-core") {
    return {
      command: "cargo",
      args: ["run", "--release", "--quiet", "--locked", "-p", "redact-secret", "--example", "assessment_adapter", "--", kind, ...(profile === undefined ? [] : ["--profile", profile, "--runs", String(options.runs)]), ...outputArgs],
    };
  }
  if (surface === "python") {
    return {
      command: process.execPath,
      args: [kind === "accuracy" ? "scripts/assessment-python-run.mjs" : "scripts/assessment-python-performance.mjs", "--python", options.python, ...(profile === undefined ? [] : ["--profile", profile, "--runs", String(options.runs)]), ...outputArgs],
    };
  }
  if (surface === "node") {
    return {
      command: process.execPath,
      args: [kind === "accuracy" ? "scripts/assessment-run.mjs" : "scripts/assessment-node-performance.mjs", ...(profile === undefined ? [] : ["--profile", profile, "--runs", String(options.runs), "--addon-dir", options.addonDir]), ...outputArgs],
    };
  }
  if (surface === "browser-wasm") {
    return {
      command: process.execPath,
      args: [kind === "accuracy" ? "scripts/assessment-browser-run.mjs" : "scripts/assessment-browser-performance.mjs", "--engine", options.engine, "--artifact-dir", resolve(REPO_ROOT, options.artifactDir), ...(profile === undefined ? [] : ["--profile", profile, "--runs", String(options.runs)]), ...outputArgs],
    };
  }
  return {
    command: process.execPath,
    args: [kind === "accuracy" ? "scripts/assessment-cli-run.mjs" : "scripts/assessment-cli-performance.mjs", "--binary", options.binary, ...(profile === undefined ? [] : ["--profile", profile, "--runs", String(options.runs)]), ...outputArgs],
  };
}

function runAttempt(surface, kind, profileId, profile, outputDir, options) {
  const paths = makePaths(outputDir, surface, profileId, kind === "accuracy");
  const invocation = commandFor(surface, kind, profile, paths, options);
  const base = {
    surface, kind, profileId,
    resultPath: relative(outputDir, paths.resultPath),
    markdownPath: relative(outputDir, paths.markdownPath),
    mismatchesPath: paths.mismatchesPath === undefined ? undefined : relative(outputDir, paths.mismatchesPath),
  };
  if (!runCommand(invocation.command, invocation.args)) return { ...base, failureCode: "runner-failed" };
  if (!existsSync(paths.resultPath)) return { ...base, failureCode: "result-missing" };
  try {
    return { ...base, result: JSON.parse(readFileSync(paths.resultPath, "utf8")) };
  } catch {
    return { ...base, failureCode: "invalid-result" };
  }
}

async function linkNodeAddon(addonDir) {
  const runtimeEntry = join(REPO_ROOT, "packages", "javascript", "dist", "runtime", "node.js");
  if (!existsSync(runtimeEntry)) return undefined;
  const runtime = await import(pathToFileURL(runtimeEntry).href);
  const specifier = runtime.resolveAddonSpecifier();
  if (specifier === undefined) return undefined;
  const scope = join(REPO_ROOT, "packages", "javascript", "node_modules", "@redact-secret");
  const link = join(scope, specifier.split("/")[1]);
  if (existsSync(link)) return undefined;
  mkdirSync(scope, { recursive: true });
  symlinkSync(resolve(REPO_ROOT, addonDir), link, "junction");
  return link;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const outputDir = resolve(REPO_ROOT, options.outputDir);
  if (existsSync(outputDir)) fail(`${displayPath(outputDir)} already exists; choose a new --output-dir`);

  const schema = await loadAssessmentSchema();
  const document = loadWorkloadProfiles();
  const profiles = schema.validateAssessmentWorkloadProfiles(document.profiles);
  const selectedProfiles = options.profiles.map((profileId) => {
    const profile = profiles.find((candidate) => candidate.id === profileId);
    if (profile === undefined || profile.purpose !== "scale") fail(`${profileId}: unknown scale profile`);
    return { id: profile.id, chunkProfile: profile.chunkProfile };
  });
  if (!selectedProfiles.some((profile) => profile.chunkProfile === "whole")) {
    fail("the complete suite requires at least one whole-input --profile");
  }
  if (!selectedProfiles.some((profile) => profile.chunkProfile !== "whole")) {
    fail("the complete suite requires at least one incremental --profile");
  }
  if (!runCommand("cargo", ["build", "--release", "--locked", "-p", "redact-secret", "--example", "assessment_adapter"])) fail("Rust assessment release build failed");
  mkdirSync(outputDir, { recursive: true });

  const attempts = [];
  let addonLink;
  try {
    addonLink = await linkNodeAddon(options.addonDir);
    for (const surface of ["rust-core", "python", "node", "browser-wasm", "cli"]) {
      attempts.push(runAttempt(surface, "accuracy", "accuracy-corpus", undefined, outputDir, options));
      for (const profile of selectedProfiles) {
        attempts.push(runAttempt(surface, "performance", profile.id, profile.id, outputDir, options));
      }
    }
  } finally {
    if (addonLink !== undefined) rmSync(addonLink, { recursive: true, force: true });
  }

  const complete = await loadTsModule(join(REPO_ROOT, "assessment", "complete.ts"));
  const aggregate = complete.buildCompleteAssessment({
    attempts, performanceProfiles: selectedProfiles, repetitions: options.runs,
    validateResult: (result) => schema.validateAssessmentResults([result]),
  });
  writeFileSync(join(outputDir, "summary.json"), `${JSON.stringify(aggregate, null, 2)}\n`);
  writeFileSync(join(outputDir, "baseline.md"), complete.renderCompleteAssessmentMarkdown(aggregate));
  console.error(`complete assessment: ${aggregate.status}; evidence: ${displayPath(outputDir)}`);
  if (aggregate.status !== "complete") process.exitCode = 1;
}

await main();
