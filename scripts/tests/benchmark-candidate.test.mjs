import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { parseArguments, inspectCleanRevision, resolveExactCommit, sha256File, verifyBenchmarkRepository, verifyCheckoutHead, withTemporaryDirectory } from '../benchmark-candidate.mjs';

const git = (root, ...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();

async function repository(remote = 'git@github.com:redact-secret/redact-secret-benchmarks.git') {
  const root = await mkdtemp(path.join(tmpdir(), 'benchmark candidate test '));
  git(root, 'init', '-q'); git(root, 'config', 'user.name', 'Test'); git(root, 'config', 'user.email', 'test@example.invalid');
  git(root, 'remote', 'add', 'origin', remote);
  await writeFile(path.join(root, 'file.txt'), 'synthetic\n'); git(root, 'add', 'file.txt'); git(root, 'commit', '-qm', 'test');
  return root;
}

test('arguments require a full benchmark commit and absolute paths', () => {
  const sha = 'a'.repeat(40);
  assert.equal(parseArguments(['--benchmark-ref', sha, '--benchmark-repo', '/tmp/path with spaces', '--filter', 'openai-token'])['benchmark-ref'], sha);
  for (const argv of [[], ['--benchmark-ref', 'main'], ['--benchmark-ref', 'abc123'], ['--benchmark-ref', `${sha}x`], ['--benchmark-ref', sha, '--output-dir', 'relative'], ['--benchmark-ref']])
    assert.throws(() => parseArguments(argv));
});

test('repository identity, exact HEAD, and dirty policy fail closed', async t => {
  const root = await repository(); t.after(() => rm(root, { recursive: true, force: true }));
  verifyBenchmarkRepository(root);
  const commit = git(root, 'rev-parse', 'HEAD');
  assert.equal(resolveExactCommit(root, commit), commit);
  assert.equal(inspectCleanRevision(root), commit);
  await writeFile(path.join(root, 'file.txt'), 'changed\n');
  assert.throws(() => inspectCleanRevision(root), /product-worktree-must-be-clean/);
  assert.throws(() => verifyCheckoutHead(root, '0'.repeat(40)), /benchmark-head-mismatch/);
});

test('wrong benchmark repository is rejected', async t => {
  const root = await repository('https://github.com/example/not-the-benchmark.git'); t.after(() => rm(root, { recursive: true, force: true }));
  assert.throws(() => verifyBenchmarkRepository(root), /wrong-benchmark-repository/);
});

test('artifact hashing is byte exact and temporary directories are cleaned', async () => {
  let target;
  const digest = await withTemporaryDirectory('candidate evidence with spaces ', async root => {
    target = root; const file = path.join(root, 'artifact.tgz'); await writeFile(file, 'immutable-candidate'); return sha256File(file);
  });
  assert.equal(digest, 'd14e0edc00c9672581e58e175dfe75a0e69758946e293323f8e3b84e9d87ccaf');
  await assert.rejects(readFile(target));
});

test('benchmark installation runs lifecycle scripts needed to materialize generated fixtures', async () => {
  const source = await readFile(new URL('../benchmark-candidate.mjs', import.meta.url), 'utf8');
  assert.match(source, /\['ci', '--no-audit', '--no-fund'\], benchmarkCheckout/);
  assert.doesNotMatch(source, /\['ci', '--ignore-scripts'[^\n]+benchmarkCheckout/);
});
