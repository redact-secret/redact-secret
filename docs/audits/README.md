# Review and audit archive

[Documentation home](../README.md)

Audit verdicts apply to the revision and date recorded in each document. They
are not live status dashboards, and a later code fix does not rewrite what an
earlier reviewer observed. Under
[`decision-retire-historical-audit-bodies-before-release-qualification`](../decisions/2026-10-06-retire-historical-audit-bodies-before-release-qualification.md)
every document here is a temporary review: it may be committed during
development and its body leaves this tree, with a verified 40-hex permalink,
before release qualification. Existing units are retired by the epic
[#1259](https://github.com/redact-secret/redact-secret/issues/1259); until
then an entry's presence here is not a retention decision.

Organized by kind, per
[DS0](../decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md):
**releases** (candidate and readiness reviews, one section per version),
**epic close-outs** (a multi-issue body of work's completion record),
**subsystem reviews** (a cross-cutting review not tied to one release or
epic), and **evidence** (a single issue's record, `evidence/<issue>/`).

## Releases

Start with the [beta.14 candidate public-contract review](beta14-candidate-public-contract-review.md).
The [beta.12 candidate public-contract review](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/beta12-candidate-public-contract-review.md), the [beta.11](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/beta11-candidate-public-contract-review.md),
[beta.10](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/beta10-candidate-public-contract-review.md) and
[beta.9](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/beta9-candidate-public-contract-review.md) candidate public-contract reviews,
the [beta.6 candidate public-contract review](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/beta6-candidate-public-contract-review.md),
the [beta.5 release readiness review](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/beta5-release-readiness-review.md), the
[beta.5](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/beta5-candidate-public-contract-review.md) and
[beta.4](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/beta4-candidate-public-contract-review.md) candidate public-contract reviews, and the
[beta.2 final code review](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/beta2-final-code-review.md) remain historical evidence.
The earlier [local pre-release review](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/pre-release-code-and-docs-review.md)
and [qualification follow-up](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/release-qualification-follow-up.md) describe beta.1.

| Topic | Evidence |
| --- | --- |
| Beta.14 candidate identity and public contract | [Retained candidate review](beta14-candidate-public-contract-review.md) (the artifact inventory selects it by `candidate_version`) |
| Remediation classification | [Release gaps](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/release-gap-disposition.md), [deferred quality](deferred-quality-backlog.md) |
| Beta.5 release retrospective and v0.1.0 readiness criteria (#531) | [What failed, how each problem was resolved, what remains open](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/beta5-release-retrospective.md); checklist at [v0.1.0 release-readiness checklist](../releases/release-readiness-v0.1.0.md) |
| Beta.6 release retrospective (#615) | [What went well, what went wrong, what #614 fixed, what remains open](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/beta6-release-retrospective.md); release record at [0.1.0-beta.6](../releases/0.1.0-beta.6/README.md) |

## Epic close-outs

| Topic | Evidence |
| --- | --- |

## Subsystem reviews

| Topic | Evidence |
| --- | --- |

## Evidence

One record per issue, under `evidence/<issue>/`. Per
[DS0](../decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md),
each folder's kind is what reads or produces it: **product judgement** (an
ADR or release relies on it — frozen here) or **benchmark measurement** (a
`redact-secret-benchmarks` run produced it — belongs there, a stub here).
Two folders sit outside both rows by an explicit constraint recorded when
this table was last swept (2026-09-22, per
[#604](https://github.com/redact-secret/redact-secret/issues/604)): #367 is a
live CI contract embedded in the archive, deferred to
[#596](https://github.com/redact-secret/redact-secret/issues/596) (DS4); #200
is test-bound until [#594](https://github.com/redact-secret/redact-secret/issues/594)
(DS2). Every folder below was reviewed for that sweep; "kept in place" states
why.

| Issue | Evidence | Kind | Disposition |
| --- | --- | --- | --- |
| Bare vendor-prefixed OpenAI value redacted under a generic policy layer (#552) | [`decision-govern-bare-vendor-prefixed-policy-layer`](../decisions/2026-09-21-govern-bare-vendor-prefixed-policy-layer.md): a marker-less `sk-`-family value at the provider-documented 48-byte body width now redacts as `vendor_prefixed_credential`, below every provider contract's specificity | decision record | n/a — not an `evidence/` folder |
| PII us-ssn identity-only mismatch, public investigation (#1003) | [4,655 synthetic cases against the identity seam and the #910 oracle: no public defect, 110 boundary-adjacency mismatches by contract](evidence/1003/README.md) | product judgement | kept in place — final record; the protected case was not opened |
| Plaintext memory lifetime inventory (#1079) | [Every owned buffer that can hold input-derived text in the core, with owner, lifetime and release point on success, error, abort, finalize and drop; bindings and CLI at summary level; terminal-transition tests; ten findings, no erasure anywhere](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1079/README.md) | product judgement | kept in place — final record; the contract it supports is [plaintext lifetime](../reference/plaintext-lifetime.md) |
| Optional zeroization design for core-owned plaintext buffers (#1080) | [What `zeroize` 1.9.0 guarantees from its source, the proposed buffers, transitions and feature, a measured prototype (no added transitive dependency, `forbid(unsafe_code)` kept, about 5% incremental-path cost, 0.21% WebAssembly size), the no-dependency alternative, and the no-core-features rule it conflicts with](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1080/README.md) | product judgement | kept in place — final record; a proposal, no build zeroizes anything; the contract it would extend is [plaintext lifetime](../reference/plaintext-lifetime.md) |
| Action policy parser size in the WebAssembly artifacts and JavaScript conformance coverage (#1219) | [Brotli sizes of the four WebAssembly artifacts against `db0e5c8d` (`full` +5,653, 3.43%), where the bytes are, and what the shared action policy fixture does and does not reach through the Node addon and the WebAssembly artifact](evidence/1219/README.md) | measurement | kept in place — final record; later parser growth re-measures against it |
| Comparison cost in the WebAssembly artifacts and the JavaScript comparison conformance run (#1220) | [Brotli sizes of the four WebAssembly artifacts before and after exposing `compareActionPolicies` (`full` +4,363, 2.54%), where the bytes are, the one reduction taken (a flat result array, -881) and the ones rejected, and what the shared explain-and-compare fixture reaches through the Node addon, the WebAssembly artifact and the package](evidence/1220/README.md) | measurement | kept in place — final record; later growth of the comparison re-measures against it |
