---
name: benchmark-candidate
description: Build the current clean Redact Secret commit as immutable npm candidate artifacts, evaluate it at an exact redact-secret-benchmarks commit, and interpret sanitized evidence for a product issue.
---

# benchmark-candidate

Use this skill only as a thin product-side orchestration and evidence-reading
layer. The benchmark repository owns fixture truth, execution, scoring, schemas,
and candidate revalidation. Never implement benchmark logic here, import product
detector sources into the benchmark, or invoke `resolve-issue`.

## Inputs

Require:

- one relevant product issue URL or number; and
- one explicit lowercase full 40-character `redact-secret-benchmarks` commit.

Do not resolve a branch, tag, abbreviated SHA, or moving default branch on the
user's behalf. If the benchmark commit is absent, stop and request it.

## Preflight

Read the product issue and its acceptance criteria. Use `graft ask` with the
issue title or named detector before opening source. Confirm `git rev-parse HEAD`
is a full commit and `git status --porcelain` is empty. A dirty worktree is not
suitable for formal evidence; do not use an override or describe it as
reproducible.

## Execute and validate

Run:

```sh
rtk npm run benchmark:candidate -- \
  --benchmark-ref <full-40-character-benchmark-commit> \
  [--filter <detector-id>] \
  [--benchmark-repo <absolute-path>] \
  [--output-dir <absolute-path>]
```

Then run the benchmark revision's validator against the emitted
`candidate-evidence-v1.json`. Treat any nonzero command, non-`complete` status,
failure entry, identity mismatch, or selected/scanned fixture-count mismatch as
incomplete. Never mark an acceptance criterion complete from incomplete
evidence.

## Interpret

For the selected issue, report:

- product commit and clean state;
- benchmark commit and clean state;
- candidate façade SHA-256 and all component hashes;
- benchmark lockfile and corpus hashes;
- scanner adapter/configuration hash, runtime, run ID, timestamps, and scope;
- baseline versus candidate flags for `must-not-flag` fixtures;
- baseline versus candidate `MISS`/`PARTIAL` outcomes for paired positives; and
- the absolute evidence path.

Label a run with `selection.scope: filtered-development` as focused evidence.
Keep fixed-corpus results (existing fixture identities and baseline comparison)
separate from any later expanded-corpus run. A focused run never represents
whole-suite qualification.

Link the evidence to the product issue and, when tracking promotion/revalidation,
to [benchmark issue #10](https://github.com/redact-secret/redact-secret-benchmarks/issues/10)
and [product issue #390](https://github.com/redact-secret/redact-secret/issues/390).
Do not modify benchmark ground truth based on candidate output. Do not close an
issue or check its benchmark gate solely because local product conformance
passes; both the product conformance gate and exact-candidate benchmark evidence
must be complete and linked.
