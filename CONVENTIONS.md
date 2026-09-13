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

Prefer links over copied detail. The source code, repository architecture, and planning records remain authoritative. Do not create separate architecture, resource, requirements, or roadmap documents for every feature; add another file only when the single page genuinely becomes difficult to use.

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
