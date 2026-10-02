import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  formatSection,
  inspectCleanRevision,
  parseArguments,
  resolveExactCommit,
  sha256File,
  summarizeSection,
  verifyBenchmarkRepository,
  verifyCheckoutHead,
  withTemporaryDirectory,
} from "../benchmark-candidate.mjs";

const git = (root, ...args) => execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim();

async function repository(remote = "git@github.com:redact-secret/redact-secret-benchmarks.git") {
  const root = await mkdtemp(path.join(tmpdir(), "benchmark candidate test "));
  git(root, "init", "-q");
  git(root, "config", "user.name", "Test");
  git(root, "config", "user.email", "test@example.invalid");
  git(root, "remote", "add", "origin", remote);
  await writeFile(path.join(root, "file.txt"), "synthetic\n");
  git(root, "add", "file.txt");
  git(root, "commit", "-qm", "test");
  return root;
}

test("arguments require a full benchmark commit and absolute paths", () => {
  const sha = "a".repeat(40);
  assert.equal(
    parseArguments(["--benchmark-ref", sha, "--benchmark-repo", "/tmp/path with spaces", "--filter", "openai-token"])[
      "benchmark-ref"
    ],
    sha,
  );
  for (const argv of [
    [],
    ["--benchmark-ref", "main"],
    ["--benchmark-ref", "abc123"],
    ["--benchmark-ref", `${sha}x`],
    ["--benchmark-ref", sha, "--output-dir", "relative"],
    ["--benchmark-ref"],
  ])
    assert.throws(() => parseArguments(argv));
});

test("repository identity, exact HEAD, and dirty policy fail closed", async (t) => {
  const root = await repository();
  t.after(() => rm(root, { recursive: true, force: true }));
  verifyBenchmarkRepository(root);
  const commit = git(root, "rev-parse", "HEAD");
  assert.equal(resolveExactCommit(root, commit), commit);
  assert.equal(inspectCleanRevision(root), commit);
  await writeFile(path.join(root, "file.txt"), "changed\n");
  assert.throws(() => inspectCleanRevision(root), /product-worktree-must-be-clean/);
  assert.throws(() => verifyCheckoutHead(root, "0".repeat(40)), /benchmark-head-mismatch/);
});

test("wrong benchmark repository is rejected", async (t) => {
  const root = await repository("https://github.com/example/not-the-benchmark.git");
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.throws(() => verifyBenchmarkRepository(root), /wrong-benchmark-repository/);
});

test("artifact hashing is byte exact and temporary directories are cleaned", async () => {
  let target;
  const digest = await withTemporaryDirectory("candidate evidence with spaces ", async (root) => {
    target = root;
    const file = path.join(root, "artifact.tgz");
    await writeFile(file, "immutable-candidate");
    return sha256File(file);
  });
  assert.equal(digest, "d14e0edc00c9672581e58e175dfe75a0e69758946e293323f8e3b84e9d87ccaf");
  await assert.rejects(readFile(target));
});

test("benchmark installation runs lifecycle scripts needed to materialize generated fixtures", async () => {
  const source = await readFile(new URL("../benchmark-candidate.mjs", import.meta.url), "utf8");
  assert.match(source, /\[["']ci["'], ["']--no-audit["'], ["']--no-fund["']\], benchmarkCheckout/);
  assert.doesNotMatch(source, /\[["']ci["'], ["']--ignore-scripts["'][^\n]+benchmarkCheckout/);
});

test("section summaries compare one measure over one population", () => {
  const row = (kind, outcome, baselineOutcome, actualFindings = 0, expectedSpans = 0) => ({
    corpusSection: "expanded-corpus",
    kind,
    expectedSpans,
    actualFindings,
    outcome,
    baseline: { outcome: baselineOutcome },
  });
  const report = {
    results: [
      row("must-not-flag", "observed:0", null),
      // baselined, flagged before, clean now
      row("must-not-flag", "clean", "flagged:1"),
      // baselined, still flagged
      row("must-not-flag", "flagged:2", "observed:1", 2),
      // unbaselined and newly flagged
      row("must-not-flag", "flagged:1", null, 1),
      // a co-detection the scorer marks clean: a raw finding, not an outcome flag
      row("must-not-flag", "clean", "clean", 3),
      row("must-redact", "EXACT", null, 1, 1),
      row("must-redact", "MISS", null, 0, 1),
      row("must-redact", "MISS", "EXACT", 0, 1),
      row("policy", "MISS", "EXACT", 0, 1),
    ],
  };
  const summary = summarizeSection(report, "expanded-corpus");
  assert.deepEqual(summary, {
    rows: 9,
    negativeBefore: 2,
    negativeAfter: 1,
    negativeBaselined: 3,
    negativeUnbaselinedFlagged: 1,
    negativeUnbaselined: 2,
    negativeRawFindings: 3,
    negativeTotal: 5,
    missesBefore: 0,
    missesAfter: 1,
    positiveBaselined: 1,
    missesUnbaselined: 1,
    positiveUnbaselined: 2,
    positiveTotal: 3,
    policyMisses: 1,
    policyTotal: 1,
  });
  // Before and after share one denominator; the raw count is labelled raw and never sits beside a scored one.
  const text = formatSection("Expanded corpus", summary);
  assert.match(text, /negative flags 2 before \/ 1 after, over the same 3 baselined fixtures \(outcome-scored\)/);
  assert.match(text, /1\/2 unbaselined flagged \(outcome-scored\)/);
  assert.match(text, /3\/5 raw fixtures with a finding \(raw finding count/);
});

test("a corpus that grows with raw co-detections does not read as a regression", () => {
  const row = (outcome, baselineOutcome, actualFindings) => ({
    corpusSection: "expanded-corpus",
    kind: "must-not-flag",
    expectedSpans: 0,
    actualFindings,
    outcome,
    baseline: { outcome: baselineOutcome },
  });
  const results = [
    ...Array.from({ length: 5 }, () => row("flagged:1", "flagged:1", 1)),
    ...Array.from({ length: 50 }, () => row("clean", "clean", 2)),
    ...Array.from({ length: 20 }, () => row("clean", null, 1)),
  ];
  const summary = summarizeSection({ results }, "expanded-corpus");
  assert.equal(summary.negativeBefore, summary.negativeAfter);
  assert.equal(summary.negativeRawFindings, 75);
  assert.equal(summary.negativeBaselined, 55);
});
