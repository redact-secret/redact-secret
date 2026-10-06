# Repository transfer runbook and completion record

Issue #157 transferred the existing repository into the `redact-secret`
organization and established `redact-secret/redact-secret` as its canonical
GitHub identity on 2026-09-11. The transfer preserved the repository node,
history, issue graph, pull requests, milestones, and wiki rather than replacing
the repository with a new Git history.

The safe pre/post inventory and the limitations of the reconstructed baseline
are recorded in
[`docs/audits/repository-transfer-evidence.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/repository-transfer-evidence.md).
This document authorizes no release, tag, publication, deployment, credential
creation, credential revocation, or archival operation.

## Pre-transfer checklist

- **Registry names were finalized before cutover.**
  `decision-adopt-redact-secret-naming-contract` records the accepted identity
  matrix. Registry ownership, first-publication bootstrap, and account-side
  trusted-publisher configuration remain release prerequisites; a repository
  transfer cannot prove or mutate those account settings.
- **The placeholder was identified before cutover.** Issue #151 recorded the
  empty public placeholder and administrator access. It was renamed
  non-destructively to `redact-secret/redact-secret-placeholder` before the
  canonical repository occupied the target path.
- **Repository-owned references were enumerated.** Cargo, npm, Python, schema,
  documentation, governance scripts, and local wiki-checkout references were
  all part of the post-transfer rewrite rather than being silently left behind.
- **Organization issue types were prepared.** `Task`, `Bug`, `Feature`, and
  `Epic` are enabled in the destination organization. Issue #60 is explicitly
  assigned `Epic` after the transfer.

## Transfer procedure

The administrator cutover used GitHub's repository transfer and rename:

1. Rename the empty target placeholder non-destructively.
2. Transfer the existing repository to the `redact-secret` organization and
   rename it to `redact-secret`.
3. Verify the preserved repository node ID, default branch, Git history, issue
   and pull-request graph, milestones, wiki head, and safe settings metadata.
4. Verify that the former web and Git locations redirect to the canonical
   repository and do not recreate a repository at the former path.
5. Reapply repository controls that did not exist before the transfer: protect
   `main`, require review and the release-readiness checks, and protect the
   `release` environment with a required reviewer and a `main`-only deployment
   policy.
6. Run CI, Python wheels, Artifact qualification, and SAST/OpenGrep from the
   transferred repository.

## Post-transfer completion checklist

- Repository, homepage, issue, changelog, security, and schema URLs in current
  manifests and documentation use `redact-secret/redact-secret`.
- `scripts/verify-release-governance.py` defaults to the canonical repository.
- `.codex/rules/git.rules`, `.codex/config.toml`, and the local review skill use
  the `redact-secret.wiki` sibling name.
- `scripts/check-legacy-identifiers.py` rejects the former GitHub path and wiki
  sibling name outside reviewed historical records.
- The Python repository redirect document sends readers to the canonical
  monorepo.
- Account-side npm and PyPI publisher configuration is recorded as a release
  prerequisite when it cannot be read through a public API. The first npm
  publication still uses the separately governed bootstrap-to-OIDC process;
  no credential operation is part of this repository transfer.
- The evidence record contains the post-transfer workflow run identifiers and
  conclusions once all four required workflows finish.

## Verification

Run the repository checks and the safe live-state reader:

```bash
npm run ci
python3 -B scripts/verify-release-governance.py \
  --check-repo \
  --npm "@redact-secret/core" \
  --crate redact-secret \
  --crate redact-secret-cli \
  --pypi redact-secret
```

The live-state output contains only identifiers, setting names, timestamps,
and public registry results. Never record credential values.
