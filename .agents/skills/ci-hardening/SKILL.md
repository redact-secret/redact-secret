---
name: ci-hardening
description: Audit this repository's GitHub Actions workflows and repo settings for supply-chain weaknesses with zizmor and OpenSSF Scorecard, then propose exact patches. Use when asked to harden or review CI/CD, before touching a publish/release workflow, or for "ci-hardening", "/ci-hardening". Report-only unless asked to apply.
---

# ci-hardening

Find ways CI or release automation could be abused. Propose patches; apply only when asked.

## Run

- `uvx zizmor --format plain .github/workflows/` (or `pipx run zizmor`). Record the zizmor version.
- `scorecard --repo=github.com/redact-secret/redact-secret --format json`. This needs `GITHUB_AUTH_TOKEN`; skip it and say so if the token is unavailable.
- Read every workflow yourself as well, especially `release.yml` (the multi-registry publish pipeline) and `sast.yml`. The tools miss repo-specific intent — for example that `release.yml` publishes to three independent registries (npm, crates.io, PyPI) plus a GitHub Release, each with its own credential and job boundary.

## Checks

| Check | Pass when |
| --- | --- |
| Action pinning | Every `uses:` is pinned to a full commit SHA with a version comment |
| Token permissions | Top-level `permissions: {}` (the literal default in `release.yml`/`sast.yml`); broader scopes only on the job that needs them |
| npm publish jobs | `NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}` is scoped to the exact job publishing that artifact (core wrapper, platform `node-*` packages); dist-tag is explicit and never `latest` for a prerelease; a version that already exists on the registry is never republished |
| crates.io publish jobs | `CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}` is scoped the same way for `redact-secret` and `redact-secret-cli`; `cargo publish` runs `--locked` |
| PyPI publish job | Stays on OIDC trusted publishing (`permissions.id-token: write`, `pypa/gh-action-pypi-publish`) with no `PYPI_TOKEN`-shaped secret reintroduced |
| Long-lived registry tokens | Flag `NPM_TOKEN`/`CARGO_REGISTRY_TOKEN` as findings to migrate toward OIDC trusted publishing now that the PyPI job already proves the pattern works in this workflow — note as a proposed hardening, not a required fix, since npm/crates.io trusted-publishing support and this repo's registry-side configuration must be confirmed before treating it as actionable |
| Injection | No `${{ github.event.* }}` or other untrusted context interpolated inside a bare `run:` string; no `pull_request_target` that checks out PR code |
| Credentials | `persist-credentials: false` on every `actions/checkout` step unless a later step in that job pushes |
| Branch protection | `main` requires the `ci` and `sast` checks; force-push disabled. Read via `gh api repos/redact-secret/redact-secret/branches/main/protection` |
| Release manifest integrity | The publish jobs write the durable release manifest (source revision, artifact set, registry state) described in `docs/releasing.md` before or alongside publish, not only after a successful run, so a partial-failure run is still recorded |
| Artifacts | Qualification reports and the release manifest are uploaded; nothing secret-bearing (tokens, raw request bodies) is uploaded |

## Output

| Severity | Workflow:line or setting | Finding | Exploit path | Patch |
| --- | --- | --- | --- | --- |

Give each patch as a minimal diff. End with the Scorecard score, if run, and a one-line verdict.

## Rules

- Never print, create, or move secrets. Do not change repo settings or push unless asked.
