/**
 * Narrow host adapter for evaluating the real, built `redact-secret` CLI
 * binary — the process-boundary counterpart to `assessment-python.mjs`'s
 * Python worker and `assessment-node-performance.mjs`'s in-process Node
 * addon driver.
 *
 * The shared TypeScript layer (`assessment/adapters/scoring.ts`,
 * `assessment/schema.ts`) still owns the common corpus, generator, scoring,
 * and result contract; this module owns only the CLI's public host contract:
 * spawning the binary, feeding standard input, and reading its documented
 * `--json` report and exit codes (`crates/secret-scan-cli/src/main.rs`). It
 * never inspects or duplicates detector or policy logic.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

import { REPO_ROOT } from "./assessment-provenance.mjs";

export const CLI_BINARY_NAME = "redact-secret";

/** The default local build location a bare `cargo build --release` produces. */
export function defaultCliBinaryPath() {
  const suffix = process.platform === "win32" ? ".exe" : "";
  return resolve(REPO_ROOT, "target", "release", CLI_BINARY_NAME + suffix);
}

/**
 * Resolves the binary an accuracy or performance run measures. Never builds
 * one itself — a missing artifact fails loudly rather than silently falling
 * back to a debug build or a different binary than the caller asked for.
 */
export function resolveCliBinary(explicitPath) {
  const binary = explicitPath === undefined ? defaultCliBinaryPath() : resolve(REPO_ROOT, explicitPath);
  if (!existsSync(binary)) {
    throw new Error(
      `${binary}: missing; build it first with \`cargo build --release -p redact-secret-cli\``,
    );
  }
  return binary;
}

/** Runs one CLI-shaped process to completion and returns its raw result. */
export function runCliProcess(command, args, stdinBuffer = Buffer.alloc(0)) {
  const result = spawnSync(command, args, { input: stdinBuffer, maxBuffer: 64 * 1024 * 1024 });
  if (result.error !== undefined) throw result.error;
  return result;
}

/** Builds the debug CLI once and returns Cargo's exact executable path. */
export function buildCliForSelfTest() {
  const result = spawnSync(
    "cargo",
    ["build", "-p", "redact-secret-cli", "--bin", CLI_BINARY_NAME, "--message-format=json-render-diagnostics"],
    { cwd: REPO_ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
  );
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) throw new Error("cargo could not build the CLI self-test binary");

  for (const line of result.stdout.trim().split("\n").reverse()) {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      continue;
    }
    if (
      message.reason === "compiler-artifact" &&
      message.target?.name === CLI_BINARY_NAME &&
      message.target.kind?.includes("bin") &&
      typeof message.executable === "string"
    ) {
      return message.executable;
    }
  }
  throw new Error("cargo did not report the CLI self-test binary path");
}

/**
 * Runs `--json` check mode against standard input and returns the report's
 * safe finding metadata in the CLI's own canonical UTF-8 byte ranges.
 *
 * `invoke(args, stdinBuffer)` abstracts over which process this drives: a
 * resolved release binary for a real evaluation run, or `cargo run -p
 * redact-secret-cli --` for the self-test, which needs no prebuilt artifact.
 *
 * Throws on anything that keeps this from being a completed evaluation: a
 * non-{0,1} exit code, unparseable JSON, an unexpected range unit, or any
 * reported source failure (including a standard-input decode failure) — an
 * evaluation that could not finish must never be reported as one that
 * finished and found nothing.
 */
export function scanStdinJson(invoke, stdinBuffer) {
  const result = invoke(["--json"], stdinBuffer);
  if (![0, 1].includes(result.status)) {
    throw new Error(`redact-secret --json exited ${result.status} before completing`);
  }
  let report;
  try {
    report = JSON.parse(result.stdout.toString("utf8"));
  } catch {
    throw new Error("redact-secret --json produced unparseable output");
  }
  if (report.rangeUnit !== "utf8-bytes") {
    throw new Error(`redact-secret reported an unexpected range unit: ${report.rangeUnit}`);
  }
  if (!Array.isArray(report.failures) || report.failures.length > 0) {
    const codes = Array.isArray(report.failures) ? report.failures.map((failure) => failure.code).join(", ") : "unknown";
    throw new Error(`redact-secret reported source failure(s) before completing: ${codes}`);
  }
  if (!Array.isArray(report.sources) || report.sources.length !== 1) {
    throw new Error("redact-secret --json reported an unexpected source count for standard input");
  }
  return report.sources[0].findings;
}

/** Runs `--version` and returns the raw output plus the parsed version string. */
export function cliVersion(invoke) {
  const result = invoke(["--version"], Buffer.alloc(0));
  if (result.status !== 0) throw new Error("redact-secret --version did not exit cleanly");
  const raw = result.stdout.toString("utf8").trim();
  const version = raw.startsWith(`${CLI_BINARY_NAME} `) ? raw.slice(CLI_BINARY_NAME.length + 1) : raw;
  return { raw, version };
}

/** The Rust toolchain that built the artifact, for provenance's `runtime` field. */
export function rustcVersion() {
  try {
    return execFileSync("rustc", ["--version"], { encoding: "utf8" }).trim();
  } catch {
    return "native";
  }
}
