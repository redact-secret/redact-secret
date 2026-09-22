# Issue #145 — independent release-readiness audit evidence

[Audit archive](../../README.md) · [Issue #145](https://github.com/redact-secret/redact-secret/issues/145) ·
[Independent repeat audit](../../repeated-release-readiness-audit.md)

Recorded 2026-09-11T16:17–16:27 UTC at commit `eb9edea0945b2a74077e4c45a1dad17ddbe0a590`
(conformance tree `f4023bf298c65c62ea0eab41ca74227782f741cb`), macOS arm64;
Node 22.16.0; CPython 3.14.7; Rust stable and MSRV 1.88. This is the raw
evidence behind the parent audit's B6/B7 gap findings — candidate-version
approval outstanding, suppression ownership unrecorded — plus the wider
recovery and dependency-cutover picture it evaluated.

`SHA256SUMS.txt` fixes the byte content of every other file in this folder;
none of them may be edited without recomputing and updating it.

## What is here

- `verification-summary.json` — the full record: four real CI workflow runs
  (CI, Python wheels, Artifact qualification, SAST — every job `success`),
  450 Rust tests passed, 14 local check commands (`npm run release:check`,
  `cargo test`/`clippy`/`fmt`/`doc`, `cargo package`, MSRV and wasm32
  `cargo check`, the Python unit-test discovery, `run-sast.py`,
  `qualify-python-wheel.py` twice, seven publisher `--dry-run` invocations,
  two `npm audit` runs), each with its own log `sha256`. Also records that
  this evidence's own revision is a documentation-only commit layered on the
  tested `source_revision` and does not itself inherit remote qualification
  (`evidence_scope`), and that human disposition owners for the SAST
  baseline were not recorded (`sast_comparison.human_disposition_owners_recorded: false`)
  — B7's finding.
- `artifact-inventory.json` — the qualified artifact file list this
  revision's matrix run produced.
- `dependency-cutover-plan.json` / `dependency-dry-runs.json` — the planned
  npm dependency-package cutover and the seven real `--dry-run` publisher
  invocations that rehearsed it.
- `issue-graph.json` — the issue dependency graph this audit reasoned over
  (see `repeated-release-readiness-audit.md`'s own summary of #139–#157).
- `live-controls-and-registries.json` — the same registry/governance
  existence and branch-protection checks [evidence/174](../174/README.md)
  ran, re-verified at this later revision.
- `npm-audits.json` — `npm audit --package-lock-only --json` for the root
  workspace and `bindings/node`.
- `opengrep-ci.json` / `opengrep-local.json` — the CI-run and local SAST
  scan reports; `sast_comparison.local_equals_ci_except_generated_at: true`
  in the summary records they agree.
- `pending-coverage.json` — coverage gaps still open at this revision.
- `recovery-probes.json` / `reproduce-recovery-gaps.txt` — probes into the
  publish/recovery state-machine gaps this audit found, and the plain-text
  reproduction log for them.
- `remote-artifact-metadata.json` — metadata fetched for each already-built
  remote artifact under inspection.
- `sast-dispositions.json` — the suppression/exclusion disposition list B7
  found lacked recorded human owners.

No candidate version was approved and no release was authorized from this
evidence; `repeated-release-readiness-audit.md` is the disposition, this
folder is what it cites.
