---
decision_id: decision-inventory-gitlab-token-families
status: accepted
scope: workspace
title: Inventory the GitLab token-prefix table and contract the two undeclared prefixes; record routable tokens and the legacy runner-registration token as explicit, tracked gaps
decided_at: 2026-09-20
---

# Inventory the GitLab token-prefix table and contract the two undeclared prefixes

## Decision

Issue #518 (B1g, under Epic #501) asks for a complete inventory of GitLab's
credential families before any grammar change: "Inventory first, implement
second... contract the families with adequate evidence and record the rest
as `pending` or `unsupported` with reasons." Unlike issue #517 (B1f), which
asked GitHub's surface be audited "per family rather than per prefix regex"
and therefore split one finding type into six, #518 names no such request —
its acceptance criteria ask for a support decision per family and evidence
for what is contracted, not a new finding-type taxonomy. `gitlab-token`
keeps its single finding type, `gitlab_token`, for every family below;
`glpat-` (personal access tokens, and the three token kinds that share its
prefix) is unchanged in every respect.

### The inventory

Source: `docs.gitlab.com/security/tokens/`'s "Token prefixes" table
(observed 2026-09-20; T1 — provider documentation states the literal
prefix). Its own preceding sentence: "the following table shows the
prefixes for each type of token. With the exception of Personal Access
tokens, these prefixes cannot be configured."

| Family | Prefix | Disposition | Change |
|---|---|---|---|
| Personal access token | `glpat-` | supported | none |
| Impersonation token | `glpat-` (shared) | supported | none |
| Project access token | `glpat-` (shared) | supported | none |
| Group access token | `glpat-` (shared) | supported | none |
| OAuth Application Secret | `gloas-` | supported | none |
| Deploy token | `gldt-` | supported | none |
| Runner authentication token | `glrt-` / `glrtr-` | supported (non-routable form) | none |
| Runner authentication token, routable form | `glrt-`/`glrtr-` + `.`-delimited payload | **pending** | none (see below) |
| CI/CD Job token | `glcbt-` | supported | none |
| Trigger token | `glptt-` | supported | none |
| Feed token | `glft-` | supported | none |
| Incoming mail token | `glimt-` | supported | none |
| GitLab agent for Kubernetes token | `glagent-` | supported | none |
| Workspace token (GitLab 18.2+) | `glwt-` | supported | none |
| SCIM Token | `glsoat-` | **added, now supported** | new prefix |
| Feature Flags Client token | `glffct-` | **added, now supported** | new prefix |
| GitLab session cookie | `_gitlab_session=` | **unsupported** | none (recorded, was silent) |
| Legacy, unprefixed runner *registration* token | none (opaque) | **unsupported** | none (recorded, was silent) |
| Administrator-customized PAT prefix | none (configurable) | unsupported (pre-existing, T3 policy) | none |

Eleven of the thirteen documented rows already matched an existing
`PREFIXES` entry (`crates/secret-scan-core/src/detectors/gitlab.rs`
before this change had 11 prefixes; `glrt-`/`glrtr-` cover one row each of
the table's "Runner authentication token" entry). Two rows — SCIM Token and
Feature Flags Client token — had no entry. Both are added to `PREFIXES`,
which grows from 11 to 13; the shared `RunLength::AtLeast(20)` floor is
applied to both, matching the project's existing convention of one
conservative floor across all `gitlab-token` prefixes (documented lengths
are absent from the source table for every prefix, not just these two — the
same T0-length situation `docs/audits/evidence/516/README.md` records for
Vercel's five prefixes, resolved there the same way: keep the conservative
floor rather than invent a tighter one).

### Why the routable runner-token variant is pending, not silently missed

GitLab's Cells architecture introduces a "routable" token format for runner
authentication tokens: `<prefix><base64-payload>.<token-version>.<base64-
payload-length><crc32>` (GitLab's Cells routable-tokens design document,
corroborated via search-indexed content and a live GitLab infrastructure
issue that shows a concrete instance shape, `glrt-t3_XXXX.XX`; T2 — no
provider documentation page for this specific structure was reachable live
during this review, so it is not scored T1). `scan_prefixed_runs`'s
alnum/dash/underscore alphabet does not include `.`, so it stops at the
routable payload's first `.` and evaluates only what precedes it against
the 20-byte floor:

- A payload of 20 bytes or more still matches, truncated at the `.` —
  missing the version/checksum tail but still flagging and redacting the
  credential (`gitlab-boundary-routable-truncated-match`,
  `matches_a_routable_runner_token_truncated_at_its_dot_delimited_tail`).
- A payload under 20 bytes is missed entirely
  (`gitlab-boundary-routable-short-payload`,
  `misses_a_routable_runner_token_with_a_short_payload`).

No source consulted states the payload's own byte length, so neither
outcome can be tightened into a scored contract without guessing — the same
reasoning `docs/decisions/2026-09-20-map-github-token-families-onto-
independent-finding-types.md` applied to deferring CRC32-in-Base62
verification for GitHub's classic families. This is recorded `pending`,
not silently excluded: two fixtures pin exactly what the grammar currently
does (truncated match above the floor, full miss below it), so a future
change to this boundary is a deliberate decision, not an accidental
regression. Unblocking condition: a provider or independently-agreeing tool
source states the payload's own length or alphabet in prose.

### Why the legacy runner registration token and the session cookie are unsupported, not pending

Two rows in the source table's neighborhood are recorded `unsupported`
rather than `pending`, because — unlike the routable variant — there is no
candidate grammar to revisit later, the same distinction
`docs/audits/evidence/516/README.md` draws between Vercel's five pending
prefixed classes and its excluded bare-OAuth class:

- The legacy runner *registration* token (as opposed to the `glrt-`/
  `glrtr-` runner *authentication* token) predates the current prefix
  scheme, carries no prefix of any kind, and GitLab's own runner
  creation-workflow migration guide states it is being phased out
  (`docs.gitlab.com/ci/runners/new_creation_workflow/`, observed
  2026-09-20: "the option to pass runner registration tokens... is
  considered legacy and is not recommended," directing users to "the
  runner creation workflow to generate an authentication token"). An
  opaque, unprefixed value is not a candidate for this prefix-anchored
  grammar regardless of provider status, the same reasoning this project
  already applies to Vercel's bare 24-character OAuth pair and to Linear's
  unprefixed OAuth access token.
- The GitLab session cookie (`_gitlab_session=`) is a `name=value` cookie,
  not a `glXXX-`-prefixed bearer credential; its value carries no
  documented prefix of its own. A dedicated rule for it would mean matching
  an arbitrary opaque cookie value, which is a materially different (and
  much higher false-positive-risk) detection problem than this file's
  prefix-anchored grammar and is out of scope here.

Both dispositions are backed by a benign-control fixture
(`gitlab-negative-legacy-runner-registration-token`,
`gitlab-negative-session-cookie`) so the "not a credential shape we cover"
claim is asserted, not merely implied by absence.

### Benign controls for non-credential GitLab identifiers

Per the issue's acceptance criterion, `gitlab-negative-numeric-resource-ids`
adds a REST-API-shaped fixture asserting that numeric project and group IDs
(`/api/v4/projects/278964/repository/commits?group_id=9970`) produce no
finding — they carry no documented prefix and are ordinary resource
identifiers, not credentials.

## Rationale

### Why no finding-type split

`docs/coverage/evidence-requirements.md` §4 requires `positive`,
`near-miss-negative`, `boundary`, and `overlap` evidence directly (not
borrowable) for every declared type; only `malformed` and `adversarial` are
in the generator's `SHAREABLE_DIMENSIONS`. Splitting `gitlab-token`'s
thirteen prefixes into thirteen finding types, as #517 did for GitHub's six,
would require thirteen independent sets of those four dimensions for a gain
this issue does not ask for — GitHub's split was motivated by that issue's
own explicit "per family, not per prefix" framing, which #518 does not
repeat. Should a future issue want the support matrix to state GitLab
family status independently (the same motivation #517 recorded), this
inventory's per-family table is the input that issue would need; splitting
the finding type itself stays out of scope here.

### Why the boundary/malformed dimensions did not need new representative fixtures

The existing `gitlab-boundary-*` fixtures (below-min, invalid-alphabet,
delimiter, case-sensitivity, custom-prefix) already exercise the shared
scan mechanics `glsoat-`/`glffct-` reuse verbatim — same alphabet, same
`AtLeast(20)` floor, same boundary check — via `glpat-` as the
representative prefix, the same "one grammar, one representative fixture
set" pattern the pre-existing `gitlab-token` declaration already uses
across its eleven prior prefixes. `detects_every_documented_prefix`
(`crates/secret-scan-core/src/detectors/gitlab.rs`) is parameterized over
`PREFIXES`, so it exercises both new prefixes automatically with no test
changes of its own.

## Consequences

- `crates/secret-scan-core/src/detectors/gitlab.rs`: `PREFIXES` grows from
  11 to 13 entries (`glsoat-`, `glffct-` appended); the struct doc comment
  now names all three tracked gaps instead of only the PAT-customization
  one. No existing prefix, alphabet, or length changed. Five new unit tests
  lock in the routable-token truncated-match/short-payload split and the
  legacy-registration-token non-match.
- `conformance/fixtures/synchronous-corpus.json`: `gitlab-positive-all-
  prefixes` gains two lines (`glsoat-`, `glffct-`); five new fixtures
  (`gitlab-negative-numeric-resource-ids`, `gitlab-negative-session-
  cookie`, `gitlab-negative-legacy-runner-registration-token`,
  `gitlab-boundary-routable-short-payload`, `gitlab-boundary-routable-
  truncated-match`) assert the benign controls and the two routable-token
  outcomes. `fixtureCount` updated from 1349 to 1354.
  `conformance/fixtures/common-profile-expectations.json` regenerated
  (`REDACT_SECRET_UPDATE_COMMON_EXPECTATIONS=1`); every new fixture is
  `Pack::Provider`-only and resolves empty under the `common` profile, same
  as `gitlab-token`'s existing fixtures.
- `docs/coverage/coverage-declarations.json`, `docs/coverage/inventory-
  report.json` regenerated (`scripts/generate-coverage-{declarations,
  inventory}.py`) rather than hand-edited; `gitlab-token`'s `positive`,
  `boundary`, and `near-miss-negative` dimensions each gained evidence
  fixture ids, still resolving `supported`. All values are synthetic
  (`SYNTHETIC`/`REVOKED` markers or clearly-fake identifiers); no real
  credential appears in any fixture, log, or documentation example here.
- T1/T2 leaked-span behavior for the previously-supported eleven prefixes
  is unchanged: same prefixes, same body grammar, same byte spans. No
  existing fixture, test, or documentation example needed to change beyond
  the regenerated derived-coverage artifacts above.
