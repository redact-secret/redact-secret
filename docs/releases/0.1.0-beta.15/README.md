# 0.1.0-beta.15 release evidence

Published on 2026-10-10 UTC from `2aea4ee95ccf9a5b891ad77f30e2edd8213622fd`.
The original [Release run 38079305406](https://github.com/redact-secret/redact-secret/actions/runs/38079305406)
succeeded on attempt 1: all ten npm packages, both crates, all nine Python files,
eight native Node registry-install lanes and Chromium passed. Python spells
this version `0.1.0b15`; npm and Cargo use `0.1.0-beta.15`.
The owner explicitly authorized Release and Reconcile and delegated approvals.
Codex root reviewed the exact-source evidence and accepted the 32 cost rows
under that delegation; the owner directly approved the browser exception. No live Reconcile repair or package
republication was needed. No GitHub Release object or new binary attachments
are asserted by this record.

## Immutable identity

- Source: `2aea4ee95ccf9a5b891ad77f30e2edd8213622fd`, tree
  `0a1393da28c17d468ee0612f47404382460ddfdf`, merged by PR 1324.
- Conformance corpus tree: `9a66504a20cb014ab56d5ad8f046cb06109246fe`.
- Original Release [artifact inventory](artifact-inventory.json): SHA-256
  `92ddb328f20e675fc40eff4055e9f5544fde3688e2a70f5e3c239816a949c19f`.
  It records 57 artifact entries, 24 corpus hashes and this Release's own
  installed-artifact/configuration qualification. Earlier matching bytes were
  not substituted for the original Release receipts.
- Annotated, unsigned tag: `v0.1.0-beta.15`, object
  `920a8f68ef74f8b5b87c029287264dd6ef4d5013`, peeled to the source above.
  The later documentation closeout commit does not change that identity.
- Original workflow [manifest](original-manifest.json): exact-byte SHA-256
  `8be431058b9ba0efa36bf88652bbcde7d7c3ed9a01c3b596f8e3bb5c6363b770`.
  The final [manifest](manifest.json) is labeled reconstructed only because it
  adds independently verified `release_evidence`; no original registry state,
  checksum, artifact digest or support-drift record is corrected.

## Qualification and public contract

[Ordinary qualification 38049229310](https://github.com/redact-secret/redact-secret/actions/runs/38049229310),
[SAST 38049229060](https://github.com/redact-secret/redact-secret/actions/runs/38049229060)
and [rehearsal 38049329352](https://github.com/redact-secret/redact-secret/actions/runs/38049329352)
passed the exact source. The rehearsal's first attempt had a Windows checkout
DNS failure; one failed-jobs-only recovery passed, without a source change.
The Release performed its own qualification and actual registry clean installs.

### Public API and compatibility review

The complete candidate review remains at its verified
[40-hex main permalink](https://github.com/redact-secret/redact-secret/blob/2aea4ee95ccf9a5b891ad77f30e2edd8213622fd/docs/audits/beta15-candidate-public-contract-review.md),
SHA-256 `31b3988373f4dabd550c81c455eccd0d10b18172d2c17ced2f160eab7c2f2609`. Its inventory-bound disposition is
accepted with limitations. Its current conclusions move here and its temporary
body is retired without a per-issue stub; review evidence does not itself
approve publication.

Rust root exports grow 72 to 95 without removal. JavaScript full/common entries
add `artifactManifest`, `resolveConfig`, `describeConfig` and
`compareConfigurations`, with readonly manifest/configuration/comparison types;
`initialize` gains owner-bound detector selection. Python adds
`artifact_manifest()` without selection/resolver/comparison. The CLI adds
standalone `--print-artifact-manifest`, without runtime selection/comparison.

Default activation keeps all included detectors and PII off. Selection is fixed
at owner/session construction; per-call `detection` keys are `INVALID_OPTIONS`
and conflicting initialization is `DETECTION_CONFIG_CONFLICT`. Concrete
migration costs are:

- `CoreStatus.configuration` is required, and its profile union includes `custom`.
- Rust `SecretScanErrorCode::ALL` grows 23 to 26; error/profile enums remain non-exhaustive.
- Own or inherited incremental `ruleset` keys, including `undefined`, are rejected.
  Whole-input rulesets and incremental action policies remain supported.
- Custom placeholder names now uppercase ASCII only; non-ASCII outputs can change.
- Explicit `runtime-config/v2` closed vocabulary validates previews only;
  it neither enforces later scans nor prevents policy activation.

Custom composition qualifies a generated WebAssembly artifact on scoped Chromium
and local workerd, not other browsers, deployed Workers accounts or custom
Node/Python/CLI artifacts. Same-runtime independent scanner handles and
incremental rulesets remain unsupported. Bare JFrog `AKCp` and memory zeroization
remain deferred. PII evidence/regression work establishes no recall expansion
or support promotion; reserved-value/context/grammar and decoding contracts stay.

The final-source startup fixes preserve canonical bytes, fail-closed digest
comparison and owner semantics: Linux libc diagnostics omit network collection
with flag restoration; Node full/common uses builtin synchronous SHA-256 inside
initialization. Browser/edge/neutral custom artifacts retain Web Crypto.

## Performance and scoped owner decisions

The complete immutable [formal evidence](https://github.com/redact-secret/redact-secret-benchmarks/issues/906#issuecomment-6097375295)
retains every sample from [performance 38050213095](https://github.com/redact-secret/redact-secret-benchmarks/actions/runs/38050213095),
at benchmark `594f001eca967da83d38c349af5997c41369bc03` against baseline
`3144bb32c6ebf8f1eefa2cbbad7d431d1d6e8c4c`: six paired rounds, twelve samples
per side. Machine fixed RC remains **45/46 passing, REJECT**. Node medium
initialization 14.301824 ms passes 15 ms; browser-small 32.9 ms exceeds 30 ms. Its five
samples 22.4/32.9/16.3/17.3/17.3 ms are retained without rerun or outlier exclusion.
The [browser exception](https://github.com/redact-secret/redact-secret-benchmarks/issues/906#issuecomment-6101104598)
is a separate source-scoped human beta decision, not a changed threshold or
machine PASS.

The full judge reports 32 budget breaches, 4 initialization plus 28 applicable
sizes, with 0 invalid measurements and 0 unevaluated core sizes. The delegated
[32 scoped approvals](https://github.com/redact-secret/redact-secret-benchmarks/issues/906#issuecomment-6101145713)
are recorded in the [live ledger](https://github.com/redact-secret/redact-secret-benchmarks/blob/019a450a4dbecf7d4dc0941b06ca4fbcb726cd0e/benchmarks/accepted-regressions.json)
(PR 907 and main promotion PR 908). Ledger acceptance does not rewrite raw costs
or machine-enforce the recorded observed bounds. Latency 10/10 and memory 16/16
are within reviewed budgets; detection is unchanged at TP 21/FP 1/FN 5/policy 0.
Feature/compiler/CPU causes are unproven; historical size-baseline compiler and
profile differences remain unisolated.

The fresh thirty-child custom diagnostic passes detector/workload parity and
six repeatable rows with `releaseVerdict:null`. It is local Darwin evidence,
not Linux/browser/workerd cost qualification. Benchmark bodies stay in the
benchmarks repository and are linked here.

## Support evidence and unresolved qualifications

The [generated support note](support-status.md) describes the existing active
qualification view of published **beta.14**, not a fresh beta.15 measurement:
102 named providers, 184 credential families, 129 stable, 33 provisional, 5 pending
and 17 unsupported. The previous historical schema/population is incomparable,
so no defensible beta.15 stable delta is stated. No support matrix is re-pinned.

The original manifest's raw `support_matrix_drift.summary` is preserved:
**15 regressions, 11 new/unclassified, 15 stale-provenance warnings, 0 improvements**.
That drift walker compares the legacy `573e1288` matrix to active view `6c1ffd67`
without the release-note comparability guard. These remain material historical
metadata flags and unresolved support reasons, not evidence of new beta.15
source downgrades. Full family/reason records remain in both manifests; they
are not silently zeroed or dismissed as qualified.

Current PII target `5696d7e1a2950bdf54fa21244f351e1c4b171f25` has **six pending**,
`qualified:false` and `supportClaims:false`. Public synthetic measurement is
recorded, but validator, public qualification, cost and protected gates remain
unmet. Historical Beta.11 five-provisional/US-SSN-pending statuses describe that
older code only. Neither this release nor unchanged PII comparisons promotes
support or supplies a protected-population qualification.

## Registry verification and dry-run recovery check

The final manifest records all ten npm shasums/integrity values, both unyanked
crate checksums and nine Python file SHA-256 values, matched against the
original Release inventory. All eight native Node platforms and Chromium
executed successful clean installs from the actual public registry. Native/WASM
npm tarballs are repacked, so their tarball bytes are not claimed comparable to
pre-pack binaries; compiled-file equality and registry checksums remain distinct.

Additional [published-consumer smoke receipts](published-consumer-smoke.json)
record one clean Darwin-arm64 Python wheel installation and exact Rust library
registry consumer. Version, synthetic redaction and Python manifest checks pass;
wheel/native bytes and Cargo.lock/downloaded-crate checksum match Release
inventory. They do not claim an all-platform Python/Rust or CLI install matrix.
Initial metadata-only local Python CA and crates API 403 failures were preserved;
OS-trust TLS and the official sparse registry resolved them without a certificate
verification bypass.

[Reconcile dry-run 38081324692](https://github.com/redact-secret/redact-secret/actions/runs/38081324692)
completed successfully on attempt 1. The retained [verification](reconciliation-verification.json)
records 13 skip, 0 publish and 0 block, one actual job and three unexpanded
skipped definitions. Facade skip is inferred from the successful strict
repack/registry-checksum comparison, without a printed facade skip line; the
annotated tag remained unchanged.
It published nothing, repaired nothing and did not rerun registry installs or tag.

All ten [observed npm dist-tags](npm-dist-tags.json) name `beta` at beta.15
and `latest` at beta.14 on 2026-10-10. This Release publishes with `--tag beta`
and does not move `latest`; this closeout performs no registry writes. Actions binary
retention is finite. Necessary safe evidence is retained durably before expiry.

The [durable publication and reconciliation archive](https://github.com/redact-secret/redact-secret-benchmarks/issues/906#issuecomment-6101553163)
retains original manifest/inventory, actual verification and three independent
reviews, with exact file hashes and remote API byte reconstruction.

The archived independent publication review predates Reconcile and accurately
records that check as pending. The separate final independent Reconcile review
resolves it; neither earlier review nor the immutable archive is rewritten.
