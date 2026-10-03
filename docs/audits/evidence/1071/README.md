# #1071 — Beta.13 release-readiness record and blocker disposition

Product judgement. Review record for
[#1071](https://github.com/redact-secret/redact-secret/issues/1071) (epic
[#1065](https://github.com/redact-secret/redact-secret/issues/1065)), written
against the frozen Beta.13 candidate. It is evidence, not release approval:
release authority is unchanged (see [AGENTS.md](../../../../AGENTS.md#release-authority)),
and this record selects no version, creates no tag and publishes nothing.

#1071's own text describes the v0.1.0 go/no-go for the whole epic. This record
does **not** decide v0.1.0. It decides one narrower question: is
`0.1.0-beta.13` ready to be released from the frozen candidate. Anything the
epic text would call "blocks v0.1.0" is recorded as **carried to the v0.1.0
decision / Beta.14** unless it is a concrete Beta.13 release blocker.

## Candidate

| Item | Value |
| --- | --- |
| Source | `401158d09a677b110fa60209256ba184b1f08f8f` (`main`) |
| Product source vs `0027da0` (the revision the Beta.13 prep PR #1192 merged at) | Identical. `git diff 0027da0b 401158d0` touches only `CHANGELOG.md` and files under `docs/` (11 files); `crates`, `packages`, `bindings`, `conformance` and every workflow are byte-identical, and the `conformance` tree id is `9b84d5f39fa5` in both. This docs PR changes documentation only, so the source tree stays identical to the frozen candidate. |
| Benchmarks pin | `573e1288` (support matrix, candidate `fe6e923`, trufflehog 3.97.4) |

## Evidence on this candidate

| Gate | Result | Evidence |
| --- | --- | --- |
| Artifact qualification (all targets, Node 20/22/24, three browsers, clean installs, Python wheels, MCP golden path) | success | [run 37093118224](https://github.com/redact-secret/redact-secret/actions/runs/37093118224) at `401158d0` |
| SAST | success | [run 37093118072](https://github.com/redact-secret/redact-secret/actions/runs/37093118072) |
| Scorecard | success (alerts: see dispositions) | [run 37093118069](https://github.com/redact-secret/redact-secret/actions/runs/37093118069) |
| Package Release Rehearsal | success on `0027da0` ([run 37087510742](https://github.com/redact-secret/redact-secret/actions/runs/37087510742)); `401158d0` has the same product source and workflows, so the rehearsal's inputs are identical | not re-dispatched, by design |
| Reconcile Release dry run and refusal (R5) | both done, see [readiness table](../../../releases/release-readiness-v0.1.0.md) | runs [37093975420](https://github.com/redact-secret/redact-secret/actions/runs/37093975420), [37095965449](https://github.com/redact-secret/redact-secret/actions/runs/37095965449) |
| Release governance | `scripts/verify-release-governance.py` exits 0 on 2026-10-03: `release` environment exists with required reviewer `milocosmopolitan`, admins cannot bypass, `main` protected with required checks | recorded in the readiness table |
| Performance acceptance and regression budget (#143) | passed on every metric except the init ratio below; size rows accepted under `beta13-401158d-*` (benchmarks #677); browser-wasm init ratio acceptance in benchmarks #678 | [run 37093955815](https://github.com/redact-secret/redact-secret-benchmarks/actions/runs/37093955815), [37097499497](https://github.com/redact-secret/redact-secret-benchmarks/actions/runs/37097499497), [37097776536](https://github.com/redact-secret/redact-secret-benchmarks/actions/runs/37097776536). Confirming run on the accepted ledger: [run 37099250035](https://github.com/redact-secret/redact-secret-benchmarks/actions/runs/37099250035) (benchmarks `develop` at `8aeefd85`, candidate `401158d0`): acceptance ACCEPTED, regression budget accepted (init ratio 1.2696, accepted tradeoff; size rows accepted tradeoff), one dispatch. |
| Conformance on the candidate artifacts | every runtime passed applicable conformance on this SHA: Rust native on Linux, macOS and Windows, MSRV, wasm32, CLI on six targets, Node addon on 8 targets with Node 20/22/24 qualification, WebAssembly in Chromium, Firefox and WebKit and through the Node fallback, Python wheels (abi3 floor and current interpreter) and sdist, clean installs from the built artifacts | run 37093118224 |

Not covered, and not claimable from this record: the **published** registry
packages (they do not exist for Beta.13 until the Release run), and other
operating systems or interpreters than those in the qualification matrix.

## Performance tradeoffs on this candidate

| Metric | Observed | Budget | Disposition |
| --- | --- | --- | --- |
| `size/wasm/full/gzip`, `size/wasm/common/gzip`, `size/browser-bundle/quickstart/gzip` | 206,697 / 142,866 / 214,214 bytes, byte-identical to `0027da0` | +5% over beta.8 | Documented, accepted (option A of 2026-09-30), keyed to `401158d0` |
| `initialization/browser-wasm/scale-logs-small-whole/initialization-ratio` | 1.2097 (run 37093955815, within budget), 1.5000 (37097499497), 1.4400 (37097776536) | 1.25 | Accepted tradeoff for this candidate on the `0027da0` precedent (1.397) and the Beta.10 acceptance (1.488); identical code across the runs shows the spread is paired-ratio variance on a shared runner. Nothing else was accepted. |

Note for the record: the three runs above are the verified values from the
run artifacts. Earlier summaries attributed 1.50 to run 37093955815; the
artifact for that run shows 1.2097, and 1.50 belongs to run 37097499497.

## Disposition of every issue and alert that could plausibly block

Exactly one disposition each. "Carried" means carried to the v0.1.0 decision
or Beta.14; it is not a Beta.13 release blocker.

| Item | Disposition | Rationale |
| --- | --- | --- |
| [#860](https://github.com/redact-secret/redact-secret/issues/860) (provider research epic) | Deferred without blocking | Research and the Beta.13 candidate measurement are posted on the issue (`benchmark:candidate` complete, 0 required-positive misses); remaining items are provider-count growth, which the epic's own stable boundary excludes as a prerequisite. |
| [#1003](https://github.com/redact-secret/redact-secret/issues/1003) (PII `us-ssn` protected run) | Deferred without blocking | PII statuses stay `pending` and outside the stable claim; not re-qualified on the Beta.13 candidate; deferred to Beta.14 with named prerequisites (candidate freeze, #143 acceptances incl. packed-size rows, an official `pii-profile-cost-v2` run, a new custodian corpus in a new epoch). Epoch unspent. Details on #1003 and benchmarks #667, #647. The shipped wording already states `pending`. |
| [#1066](https://github.com/redact-secret/redact-secret/issues/1066) (public contract) | Fixed | Contract, both ADRs, audit and #1182-#1188 merged; every runtime passed conformance on the candidate artifacts (above). |
| [#1067](https://github.com/redact-secret/redact-secret/issues/1067) (detection reliability) | Documented supported limitation, carried | Support counts carry denominators and identity; every inventory detector maps to a pinned family; PII is `pending`. Still open and carried: the PII re-qualification (above) and the `benchmark-pins:sync` resync, which is only possible after benchmarks pins the published release. `benchmark-pins:check:ancestry` passes with 0 errors and 2 expected warnings. |
| Dependabot `undici` (6 alerts), `pytest` | Deferred without blocking | `undici` is a development-scope lockfile entry; `pytest` is `.github/requirements/python-coverage.txt` (CI coverage only). Neither is in a published artifact. |
| Scorecard `PinnedDependencies` (3 alerts: `pip` commands without hashes in `python-wheels.yml`, `complete-assessment.yml`) | Deferred without blocking | CI-only hardening score items; no published artifact depends on them. Carried to Beta.14. |
| Scorecard `BinaryArtifacts` (`scripts/tests/__pycache__/test_validate_decisions.cpython-314.pyc`) | Deferred without blocking | One stray tracked bytecode file in a test directory; it ships in no artifact. Removing it is a one-file hygiene fix kept out of this docs-only PR. |
| Scorecard `Vulnerabilities`, `CIIBestPractices`, `Maintained`, `CodeReview` | Deferred without blocking | Project-process scores (the `Vulnerabilities` alert is the same development-only advisories above); OpenSSF track is [#1137](https://github.com/redact-secret/redact-secret/issues/1137). |
| WebAssembly size growth | Documented supported limitation | Accepted tradeoff, option A; budgets unchanged, acceptance keyed per candidate. |
| Browser-wasm initialization ratio | Documented supported limitation | Accepted tradeoff above. |
| [#1172](https://github.com/redact-secret/redact-secret/issues/1172), [#1178](https://github.com/redact-secret/redact-secret/issues/1178), [#1180](https://github.com/redact-secret/redact-secret/issues/1180) (new API requests) | Intentionally out of the stable contract | New public API solely on request is a stated non-goal of the epic; deferred without blocking. |
| [#1111](https://github.com/redact-secret/redact-secret/issues/1111) (Baseten `b10_`) | Deferred without blocking | New detector family; the epic excludes further provider expansion from the stable boundary. Needs a revoked key's structure measured first. |
| `conformance/README.md` says the Rust runner allows "8x" for a debug binary; the code uses 32x (`DEBUG_RUNTIME_ALLOWANCE` in `crates/secret-scan-core/tests/adversarial_bounds.rs`) | Deferred without blocking | A documentation-only mismatch that is stricter in the documentation than in the code; fixing it changes the conformance tree identity, so it is left for a re-bind and is not made in this PR. |
| Python `ScanResult.findings` (decision D8) | Fixed (decided) | Stays a `list` for 0.1.x; a tuple would be a deliberate breaking change for a later minor version. See the #1066 audit. |
| Open Beta.14 detector issues #1102-#1110, contribution-funnel #1048-#1052, placeholder epics #999-#1002, #1090 | Deferred without blocking | Not release gates. |

No unresolved release-blocking defect is hidden behind "beta" wording: every
row above is either fixed, a stated limitation, or explicitly carried.

## Recommendation

**Option 1: `0.1.0-beta.13` is ready to be released from the frozen candidate
`401158d09a677b110fa60209256ba184b1f08f8f`**, under these explicit conditions.
It is not ready to be called anything else, and nothing here says anything
about v0.1.0 beyond what is carried.

Condition that only the Beta.13 Release run can discharge (a named condition,
not a waiver):

1. Readiness row 4: a Release run for this version reaches `tag-release` with
   zero `reconcile-release.yml` dispatches. Rows 1-3 are observed live on the
   same run. Their structural gates are green.

Maintainer-only steps that remain (none is taken by this record):

1. Explicit release approval for `0.1.0-beta.13`, and the `release`
   environment deployment approval (required reviewer `milocosmopolitan`).
2. Confirmation that npm, crates.io and PyPI publishing permissions and tokens
   are in place for the run.
3. Dispatch of the Release workflow from `main`, and, only if it is needed, a
   separately authorized Reconcile Release.

The other option, blocking Beta.13, would need a named concrete defect. None
was found: no failing gate, no open unexplained regression, and no hidden
defect.
