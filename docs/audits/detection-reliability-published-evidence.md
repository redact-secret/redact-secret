# Detection reliability and published evidence review

[Documentation home](../README.md) · [Audit archive](README.md) ·
[Public reliability contract](../reference/detection-reliability.md)

- Issue: [#200](https://github.com/redact-secret/redact-secret/issues/200).
- Reviewed on: 2026-09-13.
- Testbed source revision: `a356e702e59b03cf297e0af15ba0423bc8466d48`.
- Machine-readable evidence: [verification summary](evidence/200/verification-summary.json).
- Status: **EVIDENCE PUBLISHED; FORMAL SAME-REVISION RC MATRIX PENDING #203.**

This review publishes a bounded reliability contract from the completed
five-surface Testbed without presenting test-set success as universal accuracy.
It changes no detector, policy, range, overlap, or redaction behavior and does
not authorize a version, tag, publication, deployment, or release.

## Assessment coverage and identity

The committed complete assessment is `complete` with no validation failures.
Its 15 runs cover one accuracy profile and two repeated performance profiles on
each of Rust, installed Python, Node, browser WebAssembly, and CLI. The scale
profiles exercise one whole-input and one incremental path; the CLI's
incremental product boundary is standard input.

All results identify one source revision. Accuracy results identify corpus
version `1` and SHA-256
`9c72ab77bb1ee54c6912592c2ce3de72c0c152356283d620498aac5fe08c26d9`;
performance results identify workload-profile version `1` and SHA-256
`b4db2cd22b4c008c9d63789df8ca2e21e697a21a84699466ea5f96c89d8e2806`.
Each performance distribution contains the required two samples.

The assessment corpus has 9 fixtures across logs (3), code (2), chat (2), and
negative text (2). Six expected findings and 3 expected-empty fixtures are the
published denominators. The corpus, complete rollup, every per-surface result,
and every safe mismatch sidecar are committed under `assessment/`.

## Findings

Rust, Python, Node, browser WebAssembly, and CLI agree exactly: 1 exact true
positive, 5 false negatives, 1 false positive, and 0 policy mismatches. There
are 2 actual findings per surface. The one incorrect-range finding is paired
with the corresponding missing expected range, so it contributes both the
false positive and one false negative. Expected-empty fixtures with findings
are 0/3. Policy correctness is 1/1 among exact-range matches.

The result is intentionally not collapsed into an “accuracy” percentage.
There is no sampled production population, prevalence model, confidence
interval, or exhaustive provider-format inventory behind this 9-fixture set.

## Range and redaction interpretation

The only range disagreement is the Bearer assessment case documented in the
[beta.2 disposition](../../assessment/results/beta.2/README.md). Every surface
selects the credential value while the assessment label includes the scheme.
The selected value is redacted, but the unchanged label correctly keeps the
case outside the exact-match numerator.

Eight scale-profile result rows completed the real whole-input and incremental
redaction paths for Rust, Python, Node, and browser WebAssembly. The CLI's two
scale rows instead completed check mode over standard input. Completion is path
evidence, not a redaction correctness denominator. The CLI accuracy adapter has
an exact byte-output oracle for every emitted `redact`/`block` fixture, and the
Python adapter verifies whole/incremental sanitized-output equality for all 9
fixtures. Other accuracy adapters score findings only. The public contract
therefore publishes no cross-surface assessment redaction percentage.

Canonical redaction correctness and supported range-unit conversion are
reported separately by the
[public-contract and cross-runtime conformance review](public-contract-cross-runtime-conformance.md),
at revision `5607de8973ddb83f9b61f840f67eb8534d5cea0d` and synchronous-corpus
SHA-256 `27beff0ae10480c0e10f840be56f9cf07a2f76fa3a94b4af3c91d68ac0cc30a5`.
Keeping the differently revisioned evidence sets separate avoids borrowing a
conformance pass as an accuracy result or presenting it as one formal RC run.

## Limitation and defect disposition

The [beta.2 assessment](../../assessment/results/beta.2/README.md) disposes all
six mismatch records without changing their reviewed labels: shortened GitHub
and AWS shapes remain outside fixed provider grammars; `seed` remains outside
the contextual-name allowlist; and the Bearer mismatch is a disagreement
between the assessment range and the stable value-only detector contract.
Confirmed detector defects: **0**.

These dispositions do not assert the missed shapes are harmless. They state
the present supported boundary and the precision cost of broadening it. New
requirements must be implemented in the deterministic Rust core with synthetic
regressions and explicit false-positive/false-negative tradeoffs.

The remaining evidence gaps are not hidden:

| Owner | Remaining limit |
| --- | --- |
| [#203](https://github.com/redact-secret/redact-secret/issues/203) | Formal full-platform artifacts and all installed consumers must be qualified from one later, explicitly selected RC revision |
| [#224](https://github.com/redact-secret/redact-secret/issues/224) | Installed Node and browser artifacts do not yet replay every canonical incremental fixture across applicable partitions |
| [#180](https://github.com/redact-secret/redact-secret/issues/180) | Parent detection-assurance closeout remains the administrative owner of its completed evidence children |

The Testbed observation is host-bound (macOS arm64, Node 22, CPython 3.14,
Chromium) and revision-bound. Manifest version `0.1.0-beta.1` identifies the
candidate builds; it is not evidence of registry publication.

## Verification method

`assessment/adapters/reliability-evidence.test.ts` re-derives the fixture and
finding denominators, corpus hash, five-surface inventory, source/profile
identity, run completeness, per-surface accuracy, safe mismatch shape, and
range-disagreement count from committed evidence. It also verifies the public
contract links this summary and retains the non-universal and non-release
disclaimers.

The evidence is reproduced with the documented bounded command after building
the actual artifacts:

```bash
npm run assessment:all -- --python .venv/bin/python --output-dir assessment-output
```

This review consumed the already completed Testbed rather than rerunning a
long artifact build merely to copy environment-dependent timings. Repository
CI, Rust tests, and Clippy were run for this change as recorded in the issue
handoff.

## Plaintext and authority boundaries

This document and its JSON summary contain only safe aggregate metrics,
fixture identifiers, source ranges, hashes, artifact names, and issue links.
They contain no matched value or fixture input. This review performed no
network operation from the core, release operation, version change, tag,
publication, deployment, issue mutation, or workflow dispatch.
