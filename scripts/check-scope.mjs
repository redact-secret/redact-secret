#!/usr/bin/env node
// Recommend the scoped local checks for a change (issue #896).
//
// `npm run ci` chains every repository gate, and CI always runs all of them
// plus the Rust, wasm, artifact and SAST jobs. That stays the pre-merge truth.
// For local iteration, `package.json` also groups the same gates into scoped
// scripts -- `check:docs`, `check:detector`, `check:js`, `check:rust`,
// `check:release` -- and this script maps the files a branch changes to the
// scopes that cover them:
//
//   node scripts/check-scope.mjs                 # changes vs origin/main, plus uncommitted and untracked files
//   node scripts/check-scope.mjs --base main     # a different base ref
//   node scripts/check-scope.mjs --run           # run the recommended commands, stop at the first failure
//   node scripts/check-scope.mjs -- docs/a.md    # explicit paths instead of git
//
// The mapping is a fixed, ordered rule table; a path no rule matches falls
// back to the full `npm run ci`, so an unknown kind of change is never
// under-checked. `scripts/tests/check-scope.test.mjs` fails when a gate in
// `npm run ci` belongs to no scope, so the scopes cannot drift from the suite.

import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const SCOPES = ["docs", "detector", "js", "rust", "release"];

// Ordered rules; a path collects the scopes of every rule it matches.
// `prefix` matches a path prefix, `suffix` a file extension, `exact` a path.
export const PATH_RULES = [
  { suffix: ".md", scopes: ["docs"] },
  { prefix: "docs/coverage/", scopes: ["docs", "detector"] },
  { prefix: "docs/contracts/", scopes: ["docs", "detector"] },
  { prefix: "docs/audits/evidence/", scopes: ["docs", "detector"] },
  { prefix: "docs/releases/", scopes: ["docs", "release"] },
  { prefix: "docs/", scopes: ["docs"] },
  { prefix: "conventions/", scopes: ["docs"] },
  { prefix: ".agents/", scopes: ["docs"] },
  { prefix: ".claude/", scopes: ["docs"] },
  { prefix: ".codex/", scopes: ["docs"] },
  { prefix: "conformance/", scopes: ["detector", "js", "rust"] },
  { prefix: "assessment/", scopes: ["detector"] },
  { prefix: "benchmarks/", scopes: ["detector", "docs"] },
  { prefix: "crates/secret-scan-core/", scopes: ["rust", "detector"] },
  { prefix: "crates/", scopes: ["rust"] },
  { prefix: "bindings/node/", scopes: ["rust", "js"] },
  { prefix: "bindings/wasm/", scopes: ["rust", "js"] },
  { prefix: "bindings/python/", scopes: ["rust", "release"] },
  { prefix: "packages/", scopes: ["js"] },
  { prefix: "examples/", scopes: ["js"] },
  { prefix: ".github/", scopes: ["release"] },
  { prefix: "sast/", scopes: ["release"] },
  { prefix: "scripts/", scopes: ["release"] },
  { exact: "package.json", scopes: ["release", "js"] },
  { exact: "package-lock.json", scopes: ["release", "js"] },
  { exact: "Cargo.toml", scopes: ["rust", "release"] },
  { exact: "Cargo.lock", scopes: ["rust", "release"] },
  { exact: "deny.toml", scopes: ["rust", "release"] },
  { exact: "rust-toolchain.toml", scopes: ["rust", "release"] },
  { exact: "clippy.toml", scopes: ["rust"] },
  { exact: "rustfmt.toml", scopes: ["rust"] },
  { prefix: ".cargo/", scopes: ["rust"] },
];

function ruleMatches(rule, path) {
  if (rule.exact !== undefined) return path === rule.exact;
  if (rule.prefix !== undefined) return path.startsWith(rule.prefix);
  return path.endsWith(rule.suffix);
}

/** Gate names chained by `npm run` in one package.json script body. */
export function npmRunTargets(command) {
  return [...command.matchAll(/npm run ([A-Za-z0-9:_-]+)/g)].map((match) => match[1]);
}

export function loadScripts(root = REPO_ROOT) {
  return JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")).scripts;
}

/**
 * Map changed paths to the commands to run. Returns `{ full, scopes, gates,
 * unmatched }`: `full` is true when any path matched no rule (run
 * `npm run ci`); `gates` are individual `npm run ci` gates whose command names
 * a changed file (a gate's own script or test) and that no chosen scope
 * already runs, so a checker edit always runs its own gate.
 */
export function recommend(paths, scripts) {
  const ciGates = npmRunTargets(scripts.ci ?? "");
  const scopes = new Set();
  const gates = new Set();
  const unmatched = [];
  for (const path of paths) {
    let matched = false;
    for (const rule of PATH_RULES) {
      if (!ruleMatches(rule, path)) continue;
      matched = true;
      for (const scope of rule.scopes) scopes.add(scope);
    }
    // A gate names its checker by path and its unit tests by basename.
    const needle = path.startsWith("scripts/tests/") ? path.slice("scripts/tests/".length) : path;
    for (const gate of ciGates) {
      if ((scripts[gate] ?? "").includes(needle)) gates.add(gate);
    }
    if (!matched) unmatched.push(path);
  }
  const chosen = SCOPES.filter((scope) => scopes.has(scope));
  const inScopes = new Set(chosen.flatMap((scope) => npmRunTargets(scripts[`check:${scope}`] ?? "")));
  return {
    full: unmatched.length > 0,
    scopes: chosen,
    gates: [...gates].filter((gate) => !inScopes.has(gate)).sort(),
    unmatched,
  };
}

/** The ordered npm script names to run for a recommendation. */
export function commands(result) {
  if (result.full) return ["ci"];
  return [...result.gates, ...result.scopes.map((scope) => `check:${scope}`)];
}

function git(args) {
  return execFileSync("git", args, { cwd: REPO_ROOT, encoding: "utf8" }).split("\n").filter(Boolean);
}

function changedPaths(base) {
  const mergeBase = git(["merge-base", base, "HEAD"])[0];
  const paths = new Set([
    ...git(["diff", "--name-only", mergeBase]),
    ...git(["ls-files", "--others", "--exclude-standard"]),
  ]);
  return [...paths].sort();
}

function main(argv) {
  let base = "origin/main";
  let run = false;
  let explicit = null;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--run") run = true;
    else if (arg === "--base") base = argv[++index];
    else if (arg === "--") explicit = argv.slice(index + 1);
    else if (arg === "--help" || arg === "-h") {
      console.log("usage: node scripts/check-scope.mjs [--base <ref>] [--run] [-- <path>...]");
      return 0;
    } else {
      console.error(`check-scope: unknown argument ${arg}`);
      return 2;
    }
    if (explicit) break;
  }

  const paths = explicit ?? changedPaths(base);
  if (paths.length === 0) {
    console.log(`No changed files against ${base}.`);
    return 0;
  }
  const result = recommend(paths, loadScripts());
  console.log(`${paths.length} changed file(s)${explicit ? "" : ` against ${base}`}.`);
  if (result.full) {
    console.log("No scope covers these paths, so run the full suite:");
    for (const path of result.unmatched) console.log(`  unscoped: ${path}`);
  } else {
    console.log(`Scopes: ${result.scopes.join(", ")}`);
  }
  const list = commands(result);
  for (const name of list) console.log(`  npm run ${name}`);
  console.log("CI runs the full suite on every pull request regardless of scope.");
  if (!run) return 0;

  // Under `npm run`, reuse that npm's own entry point; otherwise `npm` on PATH.
  const [npm, prefix] = process.env.npm_execpath ? [process.execPath, [process.env.npm_execpath]] : ["npm", []];
  for (const name of list) {
    console.log(`\n> npm run ${name}`);
    const status = spawnSync(npm, [...prefix, "run", name], { cwd: REPO_ROOT, stdio: "inherit" }).status;
    if (status !== 0) return status ?? 1;
  }
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
