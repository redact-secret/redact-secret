---
decision_id: decision-publish-a-commit-bound-public-site-feed
status: accepted
scope: workspace
title: Publish release identity and support status to the public site as a generated, commit-bound feed
decided_at: 2026-09-28
spec: distribution
---

# Publish release identity and support status to the public site as a generated, commit-bound feed

## Context

The public site (`redact-secret-www`) states the current release and which
provider credential families are supported. Its content plan
([redact-secret-www#6](https://github.com/redact-secret/redact-secret-www/issues/6),
"Data ownership and synchronization") assigns product release identity and
the support matrix to this repository's generated manifests and forbids
scraping Markdown for them. Both facts already exist here in machine-readable
form: the durable release record `docs/releases/<version>/manifest.json`
(checked by `scripts/validate-release-records.py`) and the pinned
`benchmarks/support-matrix.json` (projected into `docs/support-matrix.md` and
the README by `scripts/generate-support-matrix-docs.py`). Neither is shaped
for a site: they carry run ids, digests, internal review reasons, and
evidence bodies a marketing page must not restate, and their schemas change
for this repository's own reasons.

Issue [#945](https://github.com/redact-secret/redact-secret/issues/945)
asks for one feed the site can consume
([redact-secret-www#12](https://github.com/redact-secret/redact-secret-www/issues/12),
[#14](https://github.com/redact-secret/redact-secret-www/issues/14)).

## Decision

`scripts/generate-site-feed.py` generates
[`docs/contracts/site-feed/v1/feed.json`](../contracts/site-feed/v1/feed.json)
from those two manifests, and
[`feed.schema.json`](../contracts/site-feed/v1/feed.schema.json) (JSON Schema
draft 2020-12) beside it defines it. The feed is committed; `npm run
site-feed:check`, part of `npm run ci`, fails when it is not byte-identical to
a fresh generation or does not satisfy its schema.

- **Content.** `schemaVersion` (`redact-secret.site-feed/v1`), `generatedAt`,
  `sources` (each input's path and the sha256 of its bytes at the same
  commit), `release` (version, annotated tag, source revision, verification
  date, and each published package with the version its registry spells), and
  `supportMatrix` (benchmarks revision, the product version the matrix
  measured, whether the release's drift gate ran against exactly this matrix,
  counts, the status distribution, and per family only provider, family id,
  name, status, evidence tier, and qualification profile). Reasons, provider
  sources, fixtures, digests of artifacts, and run ids stay with their owners.
- **Release selection.** The highest version under `docs/releases/` by SemVer
  precedence. Generation fails, rather than falling back to an older record,
  when that record lacks final release evidence, its tag does not target its
  source revision, or any artifact is not recorded as published.
- **Determinism.** `generatedAt` is the latest timestamp the inputs carry (the
  release verification date at midnight UTC, or the matrix's `generatedAt`),
  never wall-clock time, so regeneration without an input change yields
  identical bytes.
- **Commit binding.** The site fetches
  `https://raw.githubusercontent.com/redact-secret/redact-secret/<40-hex commit>/docs/contracts/site-feed/v1/feed.json`,
  records that commit as the feed's source revision, and computes the sha256
  of the bytes itself. The feed cannot name its own commit or digest; the
  `sources` digests let a consumer verify the inputs at the same commit. No
  release asset is published for it.
- **Secret safety.** Every string field has a bounded identifier, version,
  digest, or short-name pattern in the schema, and the generator copies only
  allowlisted structured fields. No free-text field exists into which a value
  could be copied.

### Compatibility policy

Within `v1`, a change is compatible when a consumer that validates against
the `v1` schema at an earlier commit keeps working: new values in the data
(a new release, family, package, or status count) and relaxing a description.
Anything else is breaking and ships as a new path `docs/contracts/site-feed/v2/`
with `schemaVersion` `redact-secret.site-feed/v2`: removing or renaming a
field, changing a field's type, meaning, or nullability, adding a required
field or an enum value (the schema closes objects with
`additionalProperties: false`, so even an optional field breaks a strict
validator), or changing how the release is selected or `generatedAt` is
derived. `v1` then keeps being generated beside `v2` until the site has moved
and an issue retires it.

## Consequences

- A release closeout PR that adds `docs/releases/<version>/` and a re-pin of
  `benchmarks/support-matrix.json` must also run `npm run
  site-feed:generate`; CI fails until it does, so the site never reads a feed
  that disagrees with the records on the same commit.
- The site states only what these records already state, including the gap
  between the released version and the version the matrix measured.
- The adapters and benchmarks repositories own their own feeds; this one
  covers the product release and support matrix only.
