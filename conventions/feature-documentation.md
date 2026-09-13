---
convention_id: convention-feature-documentation
status: accepted
scope: workspace
strength: default
---

# Convention

Keep repository Markdown as the source documentation during beta and update
user-facing guides under `docs/` in each feature change. Use
`_notes/features/<feature>/README.md` as a small, temporary staging page for
feature notes. Each page should explain what the feature does, what works now,
what may come next, and where the relevant source or planning record lives.
Use `current`, `planned`, `proposed`, or `unknown` only when the label helps.
The public delivery platform remains undecided; staging notes do not commit
the project to GitHub Wiki or a separate web-app repository.

## Rationale

This repository is small and focused. One concise page per feature is easier to
scan, maintain, and later adapt to the selected public delivery platform than
a multi-document feature system. Links prevent the temporary notes from
becoming a competing source of truth.

Separate architecture, resource, requirements, or roadmap documents are not expected. Add another file only when the feature page genuinely becomes difficult to use.

## Guidance

The readable repository guidance is maintained in [`CONVENTIONS.md`](../CONVENTIONS.md#feature-notes).
