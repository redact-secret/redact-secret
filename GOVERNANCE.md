# Governance

This document says who runs Redact Secret, how decisions are made, and how
the project keeps going if a maintainer becomes unavailable. It covers the
`redact-secret/redact-secret` repository; the other repositories in the
[`redact-secret`](https://github.com/redact-secret) organization follow the
same model unless their own `GOVERNANCE.md` says otherwise.

## Model

Redact Secret is a maintainer-led open source project. Maintainers make final
decisions after public discussion. The project values written, reviewable
evidence over authority: a decision is recorded where anyone can read why it
was made, and anyone can propose changing it the same way.

## Roles

| Role | Who | Responsibilities |
| --- | --- | --- |
| **Maintainer** | [@milocosmopolitan](https://github.com/milocosmopolitan) (Milo Kang), lead maintainer | Sets direction and the [roadmap](ROADMAP.md); reviews and merges pull requests; accepts or rejects ADRs; triages issues and security reports; owns release approval and publication; enforces the [code of conduct](CODE_OF_CONDUCT.md). |
| **Contributor** | Anyone who opens an issue, discussion, or pull request | Follows [CONTRIBUTION.md](CONTRIBUTION.md), the [code of conduct](CODE_OF_CONDUCT.md), and the synthetic-data rule in [SECURITY.md](SECURITY.md). |
| **Security reporter** | Anyone who reports a vulnerability privately | Follows [SECURITY.md](SECURITY.md#reporting-a-vulnerability); is credited unless they ask not to be. |

`.github/CODEOWNERS` routes review requests to the maintainers. The
maintainer list here and `.github/CODEOWNERS` change together.

### Becoming a maintainer

A contributor with a sustained record of accepted, well-tested pull requests
and careful review may be invited by the existing maintainers. The invitation,
and the new maintainer's added roles, are recorded by a pull request that
updates this file and `.github/CODEOWNERS`. A maintainer who steps down, or
has been inactive for twelve months, moves to an emeritus line in this file.

## How decisions are made

- **Day-to-day changes** — bug fixes, new detectors under an existing policy,
  documentation — are decided in pull request review. A pull request merges
  once CI is green and a maintainer approves it.
- **Rules** live in the five spec files under [`docs/specs/`](docs/specs/).
  Applying an existing policy to one more provider family or instance is a
  spec-file row plus evidence, decided in pull request review.
- **New policy, a new trade-off, or a precedent that spans families** needs
  an Architecture Decision Record under
  [`docs/decisions/`](docs/decisions/DECISIONS.md). The ADR states the
  options and evidence; a maintainer accepts or rejects it in its pull
  request.
- **Releases** require explicit maintainer approval after tests pass and the
  public API and changelog have been reviewed
  ([release runbook](docs/releasing.md)).
- **Disagreements** are discussed on the issue or pull request first. If
  maintainers cannot reach consensus, the lead maintainer decides and records
  the reasoning in the thread or ADR.

## Access continuity

The project must be able to continue with minimal interruption if any one
person becomes unavailable. These measures apply:

- **Source and history** are public on GitHub and owned by the
  `redact-secret` organization, not a personal account; every release is
  reproducible from a public annotated tag and its recorded release manifest
  ([release status](docs/releases/status.md)).
- **Publication needs no personal credentials.** Releases run only from the
  `release` GitHub Actions environment on `main`. PyPI uses Trusted Publishing
  (short-lived OIDC tokens, no stored password), and npm packages are
  published with provenance from the same workflow. The npm and crates.io
  tokens are organization repository secrets that any organization owner can
  rotate.
- **Administrative access** — GitHub organization ownership and owner or
  publisher rights on the npm `@redact-secret` scope, the `redact-secret`
  and `redact-secret-cli` crates, and the `redact-secret` PyPI project — must
  be held by at least two people: the maintainers listed above and the
  designated backup listed below. The backup does not take part in
  day-to-day work; they keep access so they can appoint new maintainers,
  rotate credentials, or transfer the project if no maintainer is reachable
  for 30 days.
- **Designated backup:** _to be named by the lead maintainer_.
- **Documentation** — architecture, ADRs, the release runbook, and the
  [repository transfer runbook](docs/repository-transfer-runbook.md) — lets a
  new maintainer build, test, and release without private knowledge.

## Changing this document

Changes to governance are made by pull request, are open for comment for at
least seven days unless they only update the people listed, and are approved
by a maintainer.
