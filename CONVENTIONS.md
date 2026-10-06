# Conventions

## Feature notes

Keep repository Markdown as the source documentation during beta. Include
user-facing documentation updates in each feature change, including changed
support, examples, and limitations. Public guides live under `docs/`.

Use `_notes/features/<feature>/README.md` as a small, temporary staging page for
feature notes. Name feature directories with short, descriptive kebab-case names.
These notes do not select a delivery platform: a separate web-app repository
versus GitHub Wiki remains undecided. See the
[documentation readiness checklist](docs/documentation-readiness.md).

Each page has one job: let a reader understand the feature quickly. Keep only what is useful:

- what the feature does and why it exists;
- what works now;
- what is planned or being considered; and
- links to the relevant source, tests, architecture, or work items.

Use `current`, `planned`, `proposed`, or `unknown` when a state label makes the note clearer. Keep the distinction simple:

- `current` is supported by the repository now;
- `planned` has an existing planning source;
- `proposed` is an idea that is not committed; and
- `unknown` needs more information.

Prefer links over copied detail. The source code, repository architecture, and planning records remain authoritative. Do not create separate architecture, resource, requirements, or roadmap documents for every feature; add another file only when the single page genuinely becomes difficult to use. The project-wide [ROADMAP.md](ROADMAP.md) is not a feature document and is the one roadmap the repository keeps.

## Review and evidence lifecycle

Commit a review or evidence unit under `docs/audits/` while the work is in
progress. Its entry file (`<name>.md` or `evidence/<unit>/README.md`) starts
with a front matter block naming `owner`, `reviewed_source` (a 40-hex commit),
`status` (`in-progress`, `final`, `deferred` or `retained`) and `retire_on`
(`before-qualification`, `after-issue:#N` or `after-release:<version>`); a
`final` unit also carries `record`, the 40-hex main-commit permalink to its
complete text. It is a temporary review, not a permanent record.

`npm run lifecycle:check` (in `npm run ci`) accepts a declared unit, warns on
a historical body listed in `scripts/audit-lifecycle-legacy-units.txt`, and
fails on a new unit without a block, a stale `after-release` or `after-issue`
exception, or a `record` that is not a verified 40-hex permalink.
`npm run lifecycle:release` is the qualification form: it also fails on every
`final`, `in-progress` or `before-qualification` unit. Scripts must not write
under `docs/audits/`.

Before release qualification, retire every `final` unit: verify the permalink,
keep current conclusions in the authoritative spec, contract or release record,
and delete the body without leaving a per-issue stub. Anything a script or CI
reads moves to a live-input or generated path first. Never move the same
archive to another tracked folder and call it retired. Benchmark results and
credential-evidence dossiers stay in `redact-secret-benchmarks`; cite them by
permalink and do not copy them here. The rule and its reasons are in
[`decision-retire-historical-audit-bodies-before-release-qualification`](docs/decisions/2026-10-06-retire-historical-audit-bodies-before-release-qualification.md).

## Governed convention records

- [Keep feature notes small and useful](conventions/feature-documentation.md)
- [Convert confirmed detector defects into synthetic regressions](conventions/synthetic-secret-regressions.md)

## Terminal output policy

Use RTK for human-facing exploratory commands:

- `rtk ls` for directory inspection
- `rtk grep` for repository search
- `rtk read` for reading files
- `rtk git status` for repository status
- `rtk git diff` for reviewing changes
- `rtk git log` for commit history
- `rtk tsc` for TypeScript diagnostics
- `rtk lint` for lint diagnostics
- `rtk test ...` for failure-focused test output

Use the normal command when exact or machine-readable output is required, including JSON, patches, deployment output, security scans, and raw diagnostic logs. If RTK is unavailable, use the normal command and report the fallback.
