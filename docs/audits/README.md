# Review and audit archive

[Documentation home](../README.md)

Audit verdicts apply to the revision and date recorded in each document. They
are historical evidence, not live status dashboards. A later code fix does not
rewrite what an earlier reviewer observed.

Organized by kind, per
[DS0](../decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md):
**releases** (candidate and readiness reviews, one section per version),
**epic close-outs** (a multi-issue body of work's completion record),
**subsystem reviews** (a cross-cutting review not tied to one release or
epic), and **evidence** (a single issue's frozen record, `evidence/<issue>/`).

## Releases

Start with the [beta.6 candidate public-contract review](beta6-candidate-public-contract-review.md).
The [beta.5 release readiness review](beta5-release-readiness-review.md), the
[beta.5](beta5-candidate-public-contract-review.md) and
[beta.4](beta4-candidate-public-contract-review.md) candidate public-contract reviews, and the
[beta.2 final code review](beta2-final-code-review.md) remain historical evidence.
The earlier [local pre-release review](pre-release-code-and-docs-review.md)
and [qualification follow-up](release-qualification-follow-up.md) describe beta.1.

| Topic | Evidence |
| --- | --- |
| Beta.6 candidate identity and public contract | [Current candidate review](beta6-candidate-public-contract-review.md) |
| Beta.5 release readiness | [Pre-candidate review and fixes](beta5-release-readiness-review.md) |
| Historical candidate identity and public contract | [Beta.5](beta5-candidate-public-contract-review.md), [beta.4](beta4-candidate-public-contract-review.md), [beta.1](candidate-public-contract-review.md) |
| Beta.4 release readiness (#362) | [Release readiness review](beta4-release-readiness-review.md) |
| Beta.2 final code review | [Historical evidence](beta2-final-code-review.md) |
| Beta.1 local pre-release review | [Local review](pre-release-code-and-docs-review.md) |
| Beta.1 qualification follow-up | [Follow-up](release-qualification-follow-up.md) |
| Beta.2 final review reproduction probes | [Offline synthetic-input probes for issues #234–#238](evidence/beta2-final-review/README.md) |
| Release artifact installation and qualification | [Evidence path and authority boundary](release-artifact-installation-and-qualification.md) |
| Release authority and publishers | [Recorded evidence](release-approval-and-registry-publisher-evidence.md) |
| CI, release automation, and supply chain (release-candidate scope) | [Automation review](ci-release-automation-supply-chain-review.md) |
| Remediation classification | [Release gaps](release-gap-disposition.md), [deferred quality](deferred-quality-backlog.md) |
| Earlier release readiness | [Readiness audit](release-readiness-audit.md) |
| Independent repeat audit (#145, top-level review) | [Revision-bound verdict and residual findings](repeated-release-readiness-audit.md) |
| Release rehearsal coverage and the Reconcile Release exercise (#530) | [What the no-publication rehearsal covers, what it cannot, and the pending live Reconcile Release commands](release-rehearsal-coverage.md) |
| Beta.5 release retrospective and v0.1.0 readiness criteria (#531) | [What failed, how each problem was resolved, what remains open](beta5-release-retrospective.md); checklist at [v0.1.0 release-readiness checklist](../releases/release-readiness-v0.1.0.md) |
| Beta.6 release retrospective (#615) | [What went well, what went wrong, what #614 fixed, what remains open](beta6-release-retrospective.md); release record at [0.1.0-beta.6](../releases/0.1.0-beta.6/README.md) |

## Epic close-outs

| Topic | Evidence |
| --- | --- |
| Rust migration acceptance | [Closed-issue ledger](closed-issue-acceptance-evidence-ledger.md) |
| Modular detector profiles and size-aware WASM distribution (#377) | [Epic closeout](modular-detector-profiles-epic-closeout.md) |
| Detection assurance | [Epic closeout](detection-assurance-epic-closeout.md), [historical closeout](detection-assurance-closeout-audit.md), [residual evidence](detection-assurance-residual-evidence-backlog.md) |
| Epic D close-out measurement (#548) | [`stable` 2 of 46 on a candidate of clean `main` under the pinned scanners; all 17 T1 families clear every product-quality gate; ledger re-keying and the trufflehog pin/ledger mismatch attributed; `generic-token` Markdown inline-code fix](evidence/548/README.md) |

## Subsystem reviews

| Topic | Evidence |
| --- | --- |
| Detection reliability | [Published evidence review](detection-reliability-published-evidence.md) |
| Public contract and cross-runtime conformance | [Current contract review](public-contract-cross-runtime-conformance.md) |
| Core and CLI | [Boundary review](core-conformance-cli-boundary-review.md) |
| JavaScript and Python | [Binding and package review](javascript-python-bindings-package-contracts-review.md) |
| CI workflow inspection | [Maintenance review](ci-maintenance-review.md) |
| Repository transfer | [Transfer evidence](repository-transfer-evidence.md) |

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
| Precision contracts (#367) | [Beta.4 twin baseline and corpus audit; the live contract itself moved to `docs/contracts/precision/`](evidence/367/README.md) | mixed — a live CI contract embedded in frozen evidence | kept in place; DS4 (#596) resolves the live-contract half |
| Beta.5 precision gate (#376) | [One-line result and permalink to the full measurement](evidence/376/README.md) | benchmark measurement | **moved** — full record now in `redact-secret-benchmarks`'s [`evidence/376/`](https://github.com/redact-secret/redact-secret-benchmarks/blob/695500611224a434ce89392b97d4107275587079/evidence/376/README.md) and [`docs/reports/beta-5/results.md`](https://github.com/redact-secret/redact-secret-benchmarks/blob/695500611224a434ce89392b97d4107275587079/docs/reports/beta-5/results.md), per BDS3; this folder is now the stub the convention specifies |
| Per-detector artifact/runtime cost baseline (#378) | [Compositions, artifact sizes, runtime cost](evidence/378/README.md) | product judgement | kept in place — this repository's own performance evidence, not a benchmark-repo run |
| Full and common WebAssembly artifacts (#381) | [Real-artifact sizes, build evidence, performance, browser qualification, decision gate](evidence/381/README.md) | product judgement | kept in place |
| Modular detector profile qualification (#382) | [Node/WASM runtime qualification, package exports, CI/release wiring, known limitations](evidence/382/README.md) | product judgement | kept in place |
| Release-regression discovery evidence triage (#402) | [Candidate ec1f86b0c07e regression triage](evidence/402/README.md) | product judgement | kept in place; its two `evidence/376` citations now point at the moved record |
| OpenAI token shapes 1-3 discovery evidence triage (#405) | [Candidate fe4f1d1 regression triage](evidence/405/README.md) | product judgement | kept in place |
| Release-regression discovery evidence triage, Slack shape-1 (#406) | [Candidate fe4f1d1 regression triage](evidence/406/README.md) | product judgement | kept in place; its `evidence/376` citation now points at the moved record |
| Release-regression discovery evidence triage, Docker shape-1 (#407) | [Candidate fe4f1d1 regression triage](evidence/407/README.md) | product judgement | kept in place; its `evidence/376` citation now points at the moved record |
| Release-regression discovery evidence triage, Cloudflare shape-1 (#408) | [Candidate fe4f1d1 regression triage](evidence/408/README.md) | product judgement | kept in place; its `evidence/376` citation now points at the moved record |
| Closing the six gates in benchmark-regressions.json (#429) | [Product conformance and benchmark rerun evidence, pin-manifest staleness finding](evidence/429/README.md) | product judgement | kept in place |
| Declarative ruleset parser WebAssembly size increment (#441) | [Before/after artifact sizes, prototype parser, build evidence](evidence/441/README.md) | product judgement | kept in place |
| Structural/contextual detector shape inventory (#475) | [Valid-but-non-secret shapes for generic-token, bearer-token, connection-string, jwt, cited fixtures](evidence/475/README.md) | product judgement | kept in place |
| Declarative ruleset names section false-positive/containment evidence (#484) | [Design rationale, corpus regression evidence, conformance coverage, and the open external benchmark gap](evidence/484/README.md) | product judgement | kept in place |
| Google OAuth credential coverage evidence (#487) | [`GOCSPX-`/`1//`/`ya29.` tool-corroboration research; none adopted](evidence/487/README.md) | product judgement | kept in place |
| Declarative ruleset implementation WebAssembly size re-measurement (#495) | [Real compiled artifact sizes vs. the #441 baseline, covering #483 and #495 together](evidence/495/README.md) | product judgement | kept in place |
| Vercel credential taxonomy audit (#516) | [Prefix provenance, TruffleHog/gitleaks/flare-redact corroboration, per-class disposition](evidence/516/README.md) | product judgement | kept in place |
| Google credential-family audit beyond `google-api-key` (#519) | [OAuth client secret, service-account private key, Gemini API credentials, OAuth refresh/access; per-family disposition and evidence tier](evidence/519/README.md) | product judgement | kept in place |
| Firebase secret-bearing credential detection with public-config discrimination (#520) | [New `firebase-server-key` detector, `google-api-key`/client-config discrimination mechanism, Realtime Database secret gap](evidence/520/README.md) | product judgement | kept in place — reviewed for restated iterative history; already a synthesized final record, no comment thread to trim |
| Terraform Cloud/Enterprise token detection (#521) | [New `terraform-cloud-token` detector, provider-documented exact-width evidence, agent-pool/Enterprise shape reuse](evidence/521/README.md) | product judgement | kept in place |
| Metamorphic robustness and fixed-corpus miss root-cause synthesis (#552) | [Shared root cause across four families plus the confirmed `generic-token` markdown-boundary fix](evidence/552/README.md) — `openai-token`'s disposition superseded, see the document's 2026-09-21 update | product judgement | kept in place — its "Update" note trimmed to results plus comment permalinks, per the forward rule |
| Bare vendor-prefixed OpenAI value redacted under a generic policy layer (#552) | [`decision-govern-bare-vendor-prefixed-policy-layer`](../decisions/2026-09-21-govern-bare-vendor-prefixed-policy-layer.md): a marker-less `sk-`-family value at the provider-documented 48-byte body width now redacts as `vendor_prefixed_credential`, below every provider contract's specificity | decision record | n/a — not an `evidence/` folder |
| `bearer-token`/`sendgrid-token` twin-failure and differential-disagreement classification (#553) | [Five `flagged:1` twins traced to two already-shipped decisions; no detector defect, new decision recorded](evidence/553/README.md) | product judgement | kept in place — added an update correcting a stale cross-repo tracking reference (`redact-secret-benchmarks#66` closed without doing the work; `#78` did, and is linked) with a comment permalink, per the forward rule |
| `docker-token`/`cloudflare-token` shape-1 provider-evidence review (#566) | [Live re-check of Docker and Cloudflare provider docs; neither shape is provider-documented; both misses stay a benchmarks-side fixture artifact, no grammar widened](evidence/566/README.md) | product judgement | kept in place — reviewed for restated iterative history; the one narrative comment is an earlier draft the README supersedes, not duplicated content |
| Beta.7 detector candidate ranking: provider-documentation and generic-overlap evidence (#582) | [Provider docs silent on format for all five T2 families; generic detector measured (full-span only under recognized names)](evidence/582/README.md) | product judgement | kept in place — final record, no iterative log restated |
| T1 provider evidence for `discord:bot-token` (#646) | [Not found (exhaustive, 2026-09-23): Discord states no bot-token grammar; one legacy 24/6/27 example header in the API reference and an OpenAPI `BotToken` scheme with no pattern](evidence/646/README.md) | product judgement | kept in place — final record; research passes stay in issue comments, linked |
| T1 provider evidence for `docker:oauth-access-token` (#647) | [`dckr_oat_` prefix provider-stated in Docker's AI Governance API spec; body length/alphabet not provider-stated; 27-vs-32 conflict left open](evidence/647/README.md) | product judgement | kept in place — final record; the two research passes stay in issue comments, linked |
| T1 provider evidence for `docker:personal-access-token` (#648) | [Docker's AI Governance API spec states the PAT format as `dckr_pat_*` (prefix provable at T1); the 27-char `[A-Za-z0-9_-]` body is tool-corroborated only, with no provider contradiction](evidence/648/README.md) | product judgement | kept in place — final record; research passes stay in issue comments, linked |
| T1 provider evidence for `firebase:server-key` (#649) | [Not found (exhaustive, 2026-09-23): Google's only shape statements (AIza example, 175-char blog length) contradict the AAAA/140 contract](evidence/649/README.md) | product judgement | kept in place — final record; research passes stay in issue comments, linked |
| T1 provider evidence for `generic:bearer-token` (#650) | [RFC 6750 §2.1 states the carrier grammar (case-insensitive `Bearer`, SP separator, `b64token` alphabet, trailing `=` only), but not the token's contents or length; whether a keyword outside the span meets T1 is left to the maintainer](evidence/650/README.md) | product judgement | kept in place — final record; research passes stay in issue comments, linked |
| T1 provider evidence for `generic:otp-seed` (#652) | [Google-hosted Key Uri Format proves the otpauth envelope, hotp/totp type and Base32 secret; no length stated; conditional on accepting Google as provider](evidence/652/README.md) | product judgement | kept in place — final record; research passes stay in issue comments, linked |
| T1 provider evidence for `generic:unclassified-assignment-literal` (#653) | [Not found (exhaustive, 2026-09-23): the family has no provider, and the RFC grammars (RFC 6749 `*VSCHAR`, RFC 8265 `1*(freepoint)`) allow any printable value with no prefix, length, or marker; stays T3](evidence/653/README.md) | product judgement | kept in place — final record; research passes stay in issue comments, linked |
| T1 provider evidence for `new-relic:license-key` (#656) | [docs.newrelic.com states the ingest license key as "40 chars, suffix NRAL"; the canonical API-keys page still says "40-character hexadecimal"; body alphabet, FFFF and eu01xx are not provider-stated](evidence/656/README.md) | product judgement | kept in place — final record; research passes stay in issue comments, linked |
| T1 provider evidence for `openai:secret-api-key` (#657) | [Not found (exhaustive, 2026-09-23): no OpenAI-domain source states the key format; staff forum post (`sk-proj-`) and openai/codex watermark code recorded as near-misses](evidence/657/README.md) | product judgement | kept in place — final record; research passes stay in issue comments, linked |
| T1 provider evidence for `telegram:bot-token` (#660) | [Not found (exhaustive, 2026-09-23): core.telegram.org gives example tokens only; TDLib maintainer states no future-proof format exists](evidence/660/README.md) | product judgement | kept in place — final record; research passes stay in issue comments, linked |
| T1 provider evidence for `twilio:api-key-secret` (#661) | [Not found (exhaustive, 2026-09-23): no provider-stated secret shape; only the paired SID `^SK[0-9a-fA-F]{32}$` is documented](evidence/661/README.md) | product judgement | kept in place — final record; research passes stay in issue comments, linked |
| T1 provider evidence for `twilio:auth-token` (#662) | [Length (32) provider-stated only in `twilio/twilio-cli` validator code, client-side and skippable; alphabet and prefix not provider-stated; caveats left for maintainer](evidence/662/README.md) | product judgement | kept in place — final record; the two research passes stay in issue comments, linked |
| Candidate identity and public-contract verification (#144) | [Checks, opengrep report, and package manifests](evidence/144/README.md) | product judgement | kept in place |
| Independent release-readiness audit (#145, evidence folder) | [CI/local check log, dependency-cutover rehearsal, SAST/registry evidence](evidence/145/README.md) | product judgement | kept in place |
| Release-qualification rehearsal (#174) | [Registry/governance checks, SAST, qualification matrix, download verification](evidence/174/README.md) | product judgement | kept in place |
| Public contract and cross-runtime conformance evidence (#199) | [Per-host artifact checks and pinned fixture corpora](evidence/199/README.md) | product judgement | kept in place |
| Detection reliability published-evidence run (#200) | [Cross-language testbed run and per-surface detection tallies](evidence/200/README.md) | product judgement | kept in place — test-bound until [#594](https://github.com/redact-secret/redact-secret/issues/594) (DS2) |
| Cloudflare Workers and Vercel Edge verification (#462) | [Real-runtime reproduction, root cause, and fix status per platform](evidence/462/README.md) | product judgement | kept in place |
