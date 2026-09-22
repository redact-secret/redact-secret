---
decision_id: decision-pin-opengrep-and-establish-a-reviewed-sast-baseline
status: accepted
scope: workspace
title: Pin OpenGrep and establish a reviewed SAST baseline
decided_at: 2026-09-10
spec: evidence-and-gates
aliases: decision-enforce-opengrep-in-ci-as-a-required-gate
---

# Pin OpenGrep and establish a reviewed SAST baseline

This record is the representative ADR for the OpenGrep SAST cluster (issue
[#599](https://github.com/redact-secret/redact-secret/issues/599), DS6c, under
epic [#591](https://github.com/redact-secret/redact-secret/issues/591)): the
one pinned, fail-closed scan command whose exit code is the only SAST signal
this repository trusts. [Folded records](#folded-records) lists the decision
merged into this one under
[`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`](2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md)'s
Merge grade; its `decision_id` is preserved in this record's `aliases:`
field above, and its full original text stays reachable at its permalink.
The current rules -- pinning, baseline dispositions, and the CI gate with
its SARIF projection -- live in
[`docs/specs/evidence-and-gates.md`](../specs/evidence-and-gates.md).

## Decision

Adopt [OpenGrep](https://github.com/opengrep/opengrep) as this repository's
static-analysis (SAST) tool, invoked through exactly one reproducible command
(`python3 scripts/run-sast.py`, documented in `sast/README.md`), rather than
each contributor or CI job choosing an ad hoc `semgrep --config auto` or
similar. The binary, its Sigstore signing identity, and the ruleset revision
are all pinned in `sast/opengrep.lock.json`; nothing about the scan depends
on what the Semgrep Registry or `opengrep-rules`' `main` branch currently
contains.

Rules are vendored, not fetched at scan time: `sast/rules` holds the
`lang/security` (and `curl/security`, `github-actions/security`) packs from
[`opengrep/opengrep-rules`](https://github.com/opengrep/opengrep-rules) at
one immutable pinned commit, covering Rust, Python, JavaScript/TypeScript,
shell, and this repository's own GitHub Actions workflows -- the surfaces
issue #155 names. `scripts/install-opengrep.py` fails closed on any SHA-256
or `cosign verify-blob` mismatch against the pinned release and identity;
`scripts/run-sast.py` fails closed if the vendored ruleset's own digest
drifts from the pinned value, and fails closed on any finding or scan error
`sast/baseline.json` has not explicitly dispositioned as `blocking`,
`false_positive`, or `hardening`.

## Rationale

A SAST gate that trusts whatever the latest tool version or rule registry
returns is not reproducible: a rule added upstream tomorrow can fail a build
today's contributor had no way to anticipate, and a compromised registry or
tampered binary would be trusted implicitly. Pinning the binary by
cryptographically verified checksum and Sigstore identity, and the ruleset by
commit, turns "does this pass SAST" into a question with the same answer on
every clean checkout of the same revision -- exactly what issue #155's
run-twice-and-diff verification checks for.

Classifying every finding as `blocking`, `false_positive`, or `hardening`
(never leaving one unclassified, and never letting a `blocking`
classification silently pass) keeps the baseline honest: a baseline that can
absorb an unreviewed finding by omission is not a baseline, and a rule this
strict about *new* findings would be pointless if it also let a *scan error*
(a broken rule, a timeout, a parse failure) report success by producing no
findings at all -- so both are checked through the same disposition
mechanism.

The vendored ruleset's Commons Clause condition (layered on LGPL-2.1; see
`sast/rules/LICENSE.upstream`) only restricts reselling the ruleset itself.
Since `sast/rules` is a dev-time input never bundled into a published
package, this repository's own release artifacts are unaffected -- recorded
here so a future contributor does not need to re-derive that from the
license text.

## Consequences

- A clean checkout's first `python3 scripts/run-sast.py` downloads the pinned
  OpenGrep binary and requires `cosign` on `PATH`; CI installs it via
  `sigstore/cosign-installer`. There is no offline fallback that skips
  provenance verification -- that would defeat the point of pinning a
  signing identity.
- Bumping the OpenGrep version or the vendored rules' revision is a
  deliberate act that touches `opengrep.lock.json` and re-triages every new
  finding/error into `sast/baseline.json` before it can merge; see
  `sast/README.md`'s update procedure.
- This baseline covers Rust, Python, JavaScript/TypeScript, shell, and GitHub
  Actions as of the pinned rules revision. Extending coverage to another
  vendored path (or another platform's OpenGrep binary) is a re-pin, not a
  new mechanism.

## Folded records

Each row is a decision merged into this one (Merge grade). The `decision_id`
column is preserved verbatim in this record's `aliases:` frontmatter field so
an old reference still resolves; the permalink is the folded record's last
text on `main` before this merge, at
`ed80bc8aaa5058e11bf8b6fc43214b0194de886a`.

| Original `decision_id` | Date | Issue | Decision | Full record |
| --- | --- | --- | --- | --- |
| `decision-enforce-opengrep-in-ci-as-a-required-gate` | 2026-09-10 | [#156](https://github.com/redact-secret/redact-secret/issues/156), [#172](https://github.com/redact-secret/redact-secret/issues/172) | Run the pinned `run-sast.py` command as `.github/workflows/sast.yml` on every PR and push to `main`, gated by its exit code alone; SARIF upload and main-only suppression sync are best-effort projections. | [full record](https://github.com/redact-secret/redact-secret/blob/ed80bc8aaa5058e11bf8b6fc43214b0194de886a/docs/decisions/2026-09-10-enforce-opengrep-in-ci-as-a-required-gate.md) |
