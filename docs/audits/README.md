# Review and audit archive

[Documentation home](../README.md)

Audit verdicts apply to the revision and date recorded in each document. They
are historical evidence, not live status dashboards. A later code fix does not
rewrite what an earlier reviewer observed.

Start with the [beta.5 release readiness review](beta5-release-readiness-review.md)
and the [beta.5 candidate public-contract review](beta5-candidate-public-contract-review.md).
The [beta.4 candidate public-contract review](beta4-candidate-public-contract-review.md) and the
[beta.2 final code review](beta2-final-code-review.md) remain historical evidence.
The earlier [local pre-release review](pre-release-code-and-docs-review.md)
and [qualification follow-up](release-qualification-follow-up.md) describe beta.1.

| Topic | Evidence |
| --- | --- |
| Detection reliability | [Published evidence review](detection-reliability-published-evidence.md) |
| Public contract and cross-runtime conformance | [Current contract review](public-contract-cross-runtime-conformance.md) |
| Beta.5 release readiness | [Pre-candidate review and fixes](beta5-release-readiness-review.md) |
| Beta.5 candidate identity and public contract | [Current candidate review](beta5-candidate-public-contract-review.md) |
| Historical candidate identity and public contract | [Beta.4](beta4-candidate-public-contract-review.md), [beta.1](candidate-public-contract-review.md) |
| Release artifact installation and qualification | [Evidence path and authority boundary](release-artifact-installation-and-qualification.md) |
| Rust migration acceptance | [Closed-issue ledger](closed-issue-acceptance-evidence-ledger.md) |
| Core and CLI | [Boundary review](core-conformance-cli-boundary-review.md) |
| JavaScript and Python | [Binding and package review](javascript-python-bindings-package-contracts-review.md) |
| CI and supply chain | [Automation review](ci-release-automation-supply-chain-review.md) |
| Remediation classification | [Release gaps](release-gap-disposition.md), [deferred quality](deferred-quality-backlog.md) |
| Earlier release readiness | [Readiness audit](release-readiness-audit.md) |
| Independent repeat audit (#145) | [Revision-bound verdict and residual findings](repeated-release-readiness-audit.md) |
| Precision contracts (#367) | [Frozen contracts, beta.4 twin baseline and corpus audit](evidence/367/README.md) |
| Beta.5 precision gate (#376) | [Candidate comparison, policy changes, and accuracy-corpus re-pin](evidence/376/README.md) |
| Per-detector artifact/runtime cost baseline (#378) | [Compositions, artifact sizes, runtime cost](evidence/378/README.md) |
| Full and common WebAssembly artifacts (#381) | [Real-artifact sizes, build evidence, performance, browser qualification, decision gate](evidence/381/README.md) |
| Modular detector profile qualification (#382) | [Node/WASM runtime qualification, package exports, CI/release wiring, known limitations](evidence/382/README.md) |
| Modular detector profiles and size-aware WASM distribution (#377) | [Epic closeout](modular-detector-profiles-epic-closeout.md) |
| Release-regression discovery evidence triage (#402) | [Candidate ec1f86b0c07e regression triage](evidence/402/README.md) |
| OpenAI token shapes 1-3 discovery evidence triage (#405) | [Candidate fe4f1d1 regression triage](evidence/405/README.md) |
| Release-regression discovery evidence triage, Slack shape-1 (#406) | [Candidate fe4f1d1 regression triage](evidence/406/README.md) |
| Release-regression discovery evidence triage, Cloudflare shape-1 (#408) | [Candidate fe4f1d1 regression triage](evidence/408/README.md) |
| Release-regression discovery evidence triage, Docker shape-1 (#407) | [Candidate fe4f1d1 regression triage](evidence/407/README.md) |
| Detection assurance | [Epic closeout](detection-assurance-epic-closeout.md), [historical closeout](detection-assurance-closeout-audit.md), [residual evidence](detection-assurance-residual-evidence-backlog.md) |
| Repository transfer | [Transfer evidence](repository-transfer-evidence.md) |
| Release authority and publishers | [Recorded evidence](release-approval-and-registry-publisher-evidence.md) |
| Closing the six gates in benchmark-regressions.json (#429) | [Product conformance and benchmark rerun evidence, pin-manifest staleness finding](evidence/429/README.md) |
| Declarative ruleset parser WebAssembly size increment (#441) | [Before/after artifact sizes, prototype parser, build evidence](evidence/441/README.md) |
| Structural/contextual detector shape inventory (#475) | [Valid-but-non-secret shapes for generic-token, bearer-token, connection-string, jwt, cited fixtures](evidence/475/README.md) |
| Google OAuth credential coverage evidence (#487) | [`GOCSPX-`/`1//`/`ya29.` tool-corroboration research; none adopted](evidence/487/README.md) |
| Vercel credential taxonomy audit (#516) | [Prefix provenance, TruffleHog/gitleaks/flare-redact corroboration, per-class disposition](evidence/516/README.md) |
| Google credential-family audit beyond `google-api-key` (#519) | [OAuth client secret, service-account private key, Gemini API credentials, OAuth refresh/access; per-family disposition and evidence tier](evidence/519/README.md) |
| Firebase secret-bearing credential detection with public-config discrimination (#520) | [New `firebase-server-key` detector, `google-api-key`/client-config discrimination mechanism, Realtime Database secret gap](evidence/520/README.md) |
| Terraform Cloud/Enterprise token detection (#521) | [New `terraform-cloud-token` detector, provider-documented exact-width evidence, agent-pool/Enterprise shape reuse](evidence/521/README.md) |
| Release rehearsal coverage and the Reconcile Release exercise (#530) | [What the no-publication rehearsal covers, what it cannot, and the pending live Reconcile Release commands](release-rehearsal-coverage.md) |
| Declarative ruleset implementation WebAssembly size re-measurement (#495) | [Real compiled artifact sizes vs. the #441 baseline, covering #483 and #495 together](evidence/495/README.md) |
| Beta.5 release retrospective and v0.1.0 readiness criteria (#531) | [What failed, how each problem was resolved, what remains open](beta5-release-retrospective.md); checklist at [v0.1.0 release-readiness checklist](../release-readiness-v0.1.0.md) |
| Declarative ruleset names section false-positive/containment evidence (#484) | [Design rationale, corpus regression evidence, conformance coverage, and the open external benchmark gap](evidence/484/README.md) |
