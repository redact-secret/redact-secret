#!/usr/bin/env node
import { execFile, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const exec = promisify(execFile);
export const repositoryRoot = fileURLToPath(new URL('../', import.meta.url));
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const SHA = /^[a-f0-9]{40}$/;
const usage = 'npm run benchmark:candidate -- --benchmark-ref <full-40-character-sha> [--benchmark-repo <absolute-path>] [--output-dir <absolute-path>] [--filter <detector-id>]';

export function parseArguments(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index], value = argv[index + 1];
    if (!/^--[a-z][a-z0-9-]*$/.test(key ?? '') || value === undefined || value.startsWith('--') || key.slice(2) in values) throw new Error(usage);
    values[key.slice(2)] = value;
  }
  if (!values['benchmark-ref'] || Object.keys(values).some(key => !['benchmark-ref', 'benchmark-repo', 'output-dir', 'filter'].includes(key))) throw new Error(usage);
  if (!SHA.test(values['benchmark-ref'])) throw new Error('benchmark-ref-must-be-full-commit-sha');
  for (const key of ['benchmark-repo', 'output-dir']) if (values[key] && !path.isAbsolute(values[key])) throw new Error(`${key}-must-be-absolute`);
  if (values.filter && !/^[a-z0-9-]+$/.test(values.filter)) throw new Error('invalid-filter');
  return values;
}

function git(args, cwd = repositoryRoot) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

export function inspectCleanRevision(root) {
  const commit = git(['rev-parse', 'HEAD'], root);
  if (!SHA.test(commit)) throw new Error('product-revision-is-not-a-full-commit');
  if (git(['status', '--porcelain'], root)) throw new Error('product-worktree-must-be-clean');
  return commit;
}

export function verifyBenchmarkRepository(root) {
  const remote = git(['remote', 'get-url', 'origin'], root).replace(/\.git$/, '');
  if (!/^(?:git@github\.com:|https:\/\/github\.com\/)redact-secret\/redact-secret-benchmarks$/.test(remote)) throw new Error('wrong-benchmark-repository');
}

export function resolveExactCommit(root, requested) {
  let resolved;
  try { resolved = git(['rev-parse', `${requested}^{commit}`], root); }
  catch {
    execFileSync('git', ['fetch', '--no-tags', 'origin', requested], { cwd: root, stdio: 'inherit' });
    resolved = git(['rev-parse', `${requested}^{commit}`], root);
  }
  if (resolved !== requested) throw new Error('benchmark-head-mismatch');
  return resolved;
}

export function verifyCheckoutHead(root, requested) {
  if (git(['rev-parse', 'HEAD'], root) !== requested) throw new Error('benchmark-head-mismatch');
}

export async function sha256File(file) {
  return createHash('sha256').update(await readFile(file)).digest('hex');
}

export async function withTemporaryDirectory(prefix, action) {
  const directory = await mkdtemp(path.join(tmpdir(), prefix));
  try { return await action(directory); }
  finally { await rm(directory, { recursive: true, force: true }); }
}

async function run(command, args, cwd, failureCode = 'command-failed') {
  try {
    await exec(command, args, { cwd, timeout: 10 * 60_000, maxBuffer: 16 * 1024 * 1024, env: { ...process.env, npm_config_update_notifier: 'false' } });
  } catch (error) { throw new Error(failureCode, { cause: error }); }
}

async function pack(directory, destination) {
  const { stdout } = await exec(npm, ['pack', '--json', '--pack-destination', destination], { cwd: directory, maxBuffer: 4 * 1024 * 1024 });
  const result = JSON.parse(stdout)[0];
  if (!result?.filename) throw new Error('npm-pack-produced-no-artifact');
  return path.join(destination, result.filename);
}

async function buildCandidate(productCheckout, artifactDirectory, scratch) {
  await run(npm, ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], productCheckout, 'product-install-failed');
  await run(npm, ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], path.join(productCheckout, 'bindings/node'), 'node-toolchain-install-failed');
  await run(npm, ['run', 'js:build'], productCheckout, 'javascript-build-failed');
  await run(npm, ['run', 'build'], path.join(productCheckout, 'bindings/node'), 'node-addon-build-failed');
  const wasmOutput = path.join(scratch, 'wasm-output');
  await run(npm, ['run', 'wasm:build', '--', '--out-dir', wasmOutput], productCheckout, 'wasm-build-failed');
  await mkdir(artifactDirectory, { recursive: true });
  const core = await pack(path.join(productCheckout, 'packages/javascript'), artifactDirectory);
  const runtime = await import(`${pathToFileURL(path.join(productCheckout, 'packages/javascript/dist/runtime/node.js')).href}?candidate=${Date.now()}`);
  const specifier = runtime.resolveAddonSpecifier();
  if (!specifier) throw new Error('unsupported-candidate-platform');
  const suffix = specifier.split('/')[1].replace('node-', '');
  const sourceNode = path.join(productCheckout, 'bindings/node/npm', suffix);
  const nodeManifest = JSON.parse(await readFile(path.join(sourceNode, 'package.json'), 'utf8'));
  const nodeStage = path.join(scratch, 'node-package');
  await cp(sourceNode, nodeStage, { recursive: true });
  await cp(path.join(productCheckout, 'bindings/node', nodeManifest.main), path.join(nodeStage, nodeManifest.main));
  const node = await pack(nodeStage, artifactDirectory);
  const wasmStage = path.join(scratch, 'wasm-package');
  await cp(path.join(productCheckout, 'bindings/wasm/npm'), wasmStage, { recursive: true });
  await cp(wasmOutput, wasmStage, { recursive: true });
  const wasm = await pack(wasmStage, artifactDirectory);
  return { core, node, wasm, coreSha256: await sha256File(core) };
}

async function addWorktree(source, target, commit) {
  execFileSync('git', ['worktree', 'add', '--detach', target, commit], { cwd: source, stdio: 'inherit' });
  verifyCheckoutHead(target, commit);
}

async function removeWorktree(source, target) {
  try { execFileSync('git', ['worktree', 'remove', '--force', target], { cwd: source, stdio: ['ignore', 'ignore', 'ignore'] }); }
  catch { await rm(target, { recursive: true, force: true }); }
}

async function benchmarkSource(options, scratch) {
  if (options['benchmark-repo']) return { root: options['benchmark-repo'], temporaryClone: false };
  const sibling = path.resolve(repositoryRoot, '../redact-secret-benchmarks');
  try { verifyBenchmarkRepository(sibling); return { root: sibling, temporaryClone: false }; }
  catch {}
  const root = path.join(scratch, 'benchmark-source');
  await run('git', ['clone', '--no-checkout', 'https://github.com/redact-secret/redact-secret-benchmarks.git', root], scratch, 'benchmark-clone-failed');
  return { root, temporaryClone: true };
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArguments(argv);
  const productCommit = inspectCleanRevision(repositoryRoot);
  return withTemporaryDirectory('redact-secret-benchmark-', async scratch => {
    const source = await benchmarkSource(options, scratch);
    verifyBenchmarkRepository(source.root);
    const benchmarkCommit = resolveExactCommit(source.root, options['benchmark-ref']);
    const productCheckout = path.join(scratch, 'product-checkout');
    const benchmarkCheckout = path.join(scratch, 'benchmark-checkout');
    const outputDirectory = options['output-dir'] ?? path.join(repositoryRoot, 'benchmark-evidence', `${productCommit.slice(0, 12)}-${benchmarkCommit.slice(0, 12)}`);
    const artifactDirectory = path.join(outputDirectory, 'artifacts');
    try {
      await addWorktree(repositoryRoot, productCheckout, productCommit);
      await addWorktree(source.root, benchmarkCheckout, benchmarkCommit);
      const artifacts = await buildCandidate(productCheckout, artifactDirectory, scratch);
      await run(npm, ['ci', '--no-audit', '--no-fund'], benchmarkCheckout, 'benchmark-install-failed');
      const candidateArgs = ['run', 'eval:candidate', '--',
        '--candidate-package', artifacts.core, '--candidate-node-package', artifacts.node, '--candidate-wasm-package', artifacts.wasm,
        '--candidate-source-commit', productCommit, '--product-state', 'clean', '--expected-artifact-sha256', artifacts.coreSha256,
        '--output-dir', outputDirectory];
      if (options.filter) candidateArgs.push('--filter', options.filter);
      await run(npm, candidateArgs, benchmarkCheckout, 'candidate-evaluation-failed');
      const evidence = path.join(outputDirectory, 'candidate-evidence-v1.json');
      await run(npm, ['run', 'eval:validate', '--', evidence], benchmarkCheckout, 'candidate-evidence-validation-failed');
      const report = JSON.parse(await readFile(evidence, 'utf8'));
      if (report.status !== 'complete' || report.candidate.sourceCommit !== productCommit || report.benchmark.sourceCommit !== benchmarkCommit || report.candidate.artifactSha256 !== artifacts.coreSha256)
        throw new Error('candidate-evidence-identity-mismatch');
      const negatives = report.results.filter(row => row.kind === 'must-not-flag');
      const positives = report.results.filter(row => row.expectedSpans > 0);
      console.log(`Candidate ${productCommit} against benchmark ${benchmarkCommit}`);
      console.log(`Artifact SHA-256: ${artifacts.coreSha256}`);
      console.log(`Negative flags: ${negatives.filter(row => row.baseline.outcome !== 'clean').length} before / ${negatives.filter(row => row.outcome !== 'clean').length} after`);
      console.log(`Paired-positive misses: ${positives.filter(row => String(row.baseline.outcome).includes('MISS')).length} before / ${positives.filter(row => String(row.outcome).includes('MISS')).length} after`);
      console.log(`Evidence: ${evidence}`);
      return { evidence, report };
    } finally {
      await removeWorktree(repositoryRoot, productCheckout);
      await removeWorktree(source.root, benchmarkCheckout);
    }
  });
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  main().catch(error => {
    const code = error instanceof Error && /^[a-z][a-z0-9-]+$/.test(error.message) ? error.message : 'candidate-benchmark-failed';
    console.error(`Candidate benchmark failed: ${code}. No successful evidence was reported.`);
    process.exitCode = 1;
  });
}
