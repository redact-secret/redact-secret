# Contributing to Redact Secret

Redact Secret provides deterministic secret detection and redaction through one
Rust core shared by JavaScript, Python, Rust, and CLI consumers. Beta releases
are prereleases; describe current support and limitations without claiming v1
stability.

**One rule applies to every path: synthetic data only.** Never put a live,
revoked-but-real, or real-derived credential, or real personal data, in an
issue, pull request, fixture, log, screenshot, or comment. Not even a truncated
or partly masked fragment. Build an independently made synthetic value with the
same shape instead (the
[reporting guide](docs/guides/reporting-detection-issues.md#never-submit-a-real-credential)
shows how). Report a suspected vulnerability privately as described in
[SECURITY.md](SECURITY.md), never in a public issue.

## Which contribution path should I use?

Find your situation, read only the linked page, and stop there. Nothing below
the table is required reading for a reporter.

| I want to... | Your role | Start here | Minimum reading |
| --- | --- | --- | --- |
| Tell you a harmless value was flagged | Reporter | [False positive form](https://github.com/redact-secret/redact-secret/issues/new?template=false-positive.yml) | the form itself |
| Tell you a credential or PII value was missed | Reporter | [Missed detection form](https://github.com/redact-secret/redact-secret/issues/new?template=missed-detection.yml) | the form itself |
| Ask for a provider credential or PII type to be supported | Reporter | [Request support form](https://github.com/redact-secret/redact-secret/issues/new?template=request-detector.yml) | the form itself; a name is enough |
| Report a crash, thrown error, or binding mismatch | Reporter | [Bug report form](https://github.com/redact-secret/redact-secret/issues/new?template=bug-report.yml) | the form itself |
| Report confusing docs or an installation problem | Reporter | [Integration or docs form](https://github.com/redact-secret/redact-secret/issues/new?template=integration-docs.yml) | the form itself |
| Report a broken link or wrong content on the website | Reporter | [Website feedback form](https://github.com/redact-secret/redact-secret/issues/new?template=website-feedback.yml) | the form itself |
| Share a safe made-up input that might be worth testing | Fixture contributor | [Synthetic edge case form](https://github.com/redact-secret/redact-secret/issues/new?template=synthetic-edge-case.yml), or a pull request using the [fixture row](#before-opening-a-change) | [synthetic regression convention](conventions/synthetic-secret-regressions.md) |
| Document how a provider's credentials look, from public sources | Researcher | [Propose a provider for credential research](https://github.com/redact-secret/redact-secret-benchmarks/issues/new?template=suggest-research.yml) | the form; no core change needed |
| Implement an issue marked `implementation-ready` | Implementer | [Implementer path](#implementer-pick-up-an-implementation-ready-issue) | the issue body, then that section |
| Fix a documentation, wrapper, engine, or CI problem | Implementer | [Before opening a change](#before-opening-a-change) | the row for your change |
| Decide taxonomy, evidence tier, contract, or promotion | Maintainer | [Advanced: maintainer evidence and promotion](#advanced-maintainer-evidence-and-promotion) | everything under that heading |
| Ask a question or float an early idea | anyone | [Discussions](https://github.com/redact-secret/redact-secret/discussions) (**Q&A**, **Ideas**, **Show and tell**) | nothing |

Not sure which row fits? Use the
[Synthetic edge case form](https://github.com/redact-secret/redact-secret/issues/new?template=synthetic-edge-case.yml)
or a Discussion. A maintainer re-routes it. Support in issues and Discussions
is best-effort, with no response-time or long-term-support commitment.
`redact-secret-www` is private, so website problems are filed here through the
website feedback form.

## What happens to what you submit

Every contribution moves through the same five work-item states. They label an
issue's progress and never a family's support status. You do not manage the
states or coordinate repositories; a maintainer moves an item and says so in a
comment. The words are defined once in the
[handoff contract](docs/contracts/contribution/implementation-ready-handoff.md#vocabulary).

| State | Meaning for you |
| --- | --- |
| `intake` | Your report was received. This is where every form starts. |
| `research-needed` | A maintainer triaged it; provider facts or sources still need research. |
| `implementation-ready` | Research is complete and the behavior is frozen, so the task can be implemented and tested as written. |
| `verification-needed` | A candidate is implemented here; independent evaluation has not yet measured that exact candidate. |
| `complete` | The independent measurement of that exact candidate was recorded. |

Behind those states work flows through four repositories in order, and each
owns one step:

1. [`credential-evidence`](https://github.com/redact-secret/credential-evidence)
   researches provider facts (shapes, sources, issuance).
2. This repository adopts the researched contract and implements it with
   conformance fixtures.
3. [`redact-secret-benchmarks`](https://github.com/redact-secret/redact-secret-benchmarks)
   evaluates the exact candidate independently.
4. The same benchmarks repository reports results and decides support status.

Filing an issue or opening a pull request never makes a family supported,
`provisional`, or `stable`. Support status comes only from the benchmark
evaluation, which reaches this repository as the pinned
[support matrix](docs/support-matrix.md#what-each-status-means). `complete`
means the measurement was recorded, not that the candidate passed.

## Paths by role

### Reporter

1. Open the matching form from the table above. A short description is enough
   to start, in English or Korean.
2. Write an independently made synthetic example. The
   [reporting guide](docs/guides/reporting-detection-issues.md) is optional
   help, including a local reproduction that prints only classifications and
   ranges.
3. Your issue starts as `intake`. Filing it does not by itself change any
   fixture or confirm a defect, and you are never asked to file a second issue
   in another repository.

### Researcher

Research needs public provider documentation and no code. Use the
[research proposal form](https://github.com/redact-secret/redact-secret-benchmarks/issues/new?template=suggest-research.yml)
if you already know a provider's credential format, or
[`credential-evidence`](https://github.com/redact-secret/credential-evidence)
for the research itself. A reviewed research handoff is what lets a maintainer
mark an implementation issue `implementation-ready`. If you only want something
detected, use the Request support form instead.

### Fixture contributor

Contribute the smallest synthetic input that measures one contract behavior,
either through the Synthetic edge case form or as a pull request. A confirmed
false positive or false negative becomes a permanent synthetic regression
fixture ([convention](conventions/synthetic-secret-regressions.md)). Fixture
rules and the shared corpus are in the [conformance corpus](conformance/README.md).
Use the conformance row of the table in
[Before opening a change](#before-opening-a-change) to check it.

### Implementer: pick up an `implementation-ready` issue

1. Read only the issue's first screen: Task, Expected positives, Expected
   negatives and twins, Files likely to change, Commands to run. The collapsed
   "Maintainer evidence and research" section is for maintainers.
2. Create a branch from `main`. For a new detector, scaffold it instead of
   copying the layout by hand (see [Before opening a change](#before-opening-a-change));
   for any other route, edit the files the issue lists:
   `npm run contrib:new-detector -- <detector-id> --dry-run`, then without
   `--dry-run`. Replace every `TODO(scaffold)` marker.
3. Run the issue's commands, then `python3 -B scripts/contribution-readiness.py`
   to see what is still missing in the same words CI uses.
4. Open the pull request, linking the issue. If the issue asks for a detector,
   also follow the [boundary change](#boundary-changes) reading and the
   [new detector family checklist](#new-detector-family-checklist). The
   pull request does not set support status.

### Maintainer

You own taxonomy, evidence tier, dossier normalization, contract freeze,
adoption, and promotion. Those details are kept in full under
[Advanced: maintainer evidence and promotion](#advanced-maintainer-evidence-and-promotion)
and in [GOVERNANCE.md](GOVERNANCE.md).

## Before opening a change

What to read and run depends on the change. A small change needs only its row
below; `npm run check:changed` prints the scoped commands for your branch.

| Change | Read first | Run locally |
| --- | --- | --- |
| Documentation or Markdown only | [CONVENTIONS.md](CONVENTIONS.md) | `npm run check:docs` |
| Conformance fixture | [conformance corpus](conformance/README.md) | `npm run check:detector && npm run check:js && npm run check:rust` |
| JavaScript wrapper or examples | [ARCHITECTURE.md](ARCHITECTURE.md) | `npm run check:js` |
| Rust engine, CLI, or binding | [ARCHITECTURE.md](ARCHITECTURE.md), [workspace policy](docs/rust-workspace.md) | `npm run check:rust` |
| Release, CI, packaging, or `scripts/` | [release runbook](docs/releasing.md) | `npm run check:release` |
| Boundary change ([below](#boundary-changes)) | everything in that section | the full suite: `npm run ci` and `npm run check:rust` |

CI runs the full suite on every pull request whatever the scope, so you do
not need to reproduce the platform matrix, the wheel build, or the artifact
qualifiers locally to open one. [Developer onboarding](docs/onboarding.md#run-the-repository-checks)
has the full table and the complete sequence.

`python3 -B scripts/contribution-readiness.py` summarizes your branch in the
same words: what a detector, fixture, documentation, benchmark-regression or
release change already has, and the exact command for what is missing. Pull
requests get the same text in the CI step summary. It only reads; the gates
stay strict and are the only thing that can fail a pull request.

To start a new detector from an `implementation-ready` issue, generate its
skeleton instead of copying the layout by hand:

```bash
npm run contrib:new-detector -- <detector-id> --dry-run   # print the plan, write nothing
npm run contrib:new-detector -- <detector-id>             # or --handoff <file>.handoff.json
```

It writes the module and test skeleton and adds the registry row, policy
classification, inventory entry, conformance fixture stubs, spec row and
changelog line, each marked `TODO(scaffold)`. It refuses to overwrite any file
or entry and writes nothing unless every target is clear. Placeholders are
synthetic only, and it does no research, benchmark classification or
promotion. It then prints the regeneration and scoped-check commands to run
after you replace the markers (`git grep -n --untracked 'TODO(scaffold)' -- . ':!scripts/' ':!CONTRIBUTION.md'`). The
[handoff contract](docs/contracts/contribution/implementation-ready-handoff.md)
defines the optional input file.

Keep fixtures to the smallest synthetic input that measures one contract behavior.
Never include active credentials or matched plaintext in diagnostics. Keep the
Rust core side-effect free, detection separate from enforcement, and host I/O in
adapters. Behavior changes need deterministic regressions in the shared
[conformance corpus](conformance/README.md) and explicit false-positive and
false-negative tradeoffs.

## Development checks

For environment setup and a complete local check sequence, see
[developer onboarding](docs/onboarding.md). Public user guides start at
the [documentation home](docs/README.md).

The authoritative commands and pinned tool versions live in
[workspace policy](docs/rust-workspace.md#verification) and
[artifact qualification](docs/qualification.md). Run the checks for every
package you change. Changes to packaging, compatibility, or release behavior also
require artifact inspection and clean-install smoke tests.

Pull requests should explain the observable change, its verification, and any
compatibility impact.

### Requirements for acceptable contributions

A contribution is accepted when it meets all of the following. The automated
items are enforced by CI on every pull request; the rest are checked in review.

- **Coding standard.** Follow [CONVENTIONS.md](CONVENTIONS.md). Rust code is
  formatted with `rustfmt` (`rustfmt.toml`) and must pass `cargo clippy` with
  warnings denied (`clippy.toml`, `RUSTFLAGS=-D warnings`); TypeScript must
  type-check under `strict`. JavaScript and TypeScript are formatted and
  linted with [Biome](https://biomejs.dev/) (`biome.json`; run `npm run lint`,
  and `npm run format` to apply fixes). Python in `bindings/python` and
  `scripts/` is formatted and linted with [Ruff](https://docs.astral.sh/ruff/)
  (`ruff.toml`, version pinned by hash in
  `.github/requirements/python-lint.txt`; run
  `ruff check bindings/python scripts` and
  `ruff format --check bindings/python scripts`). The `lint` job in CI fails
  the pull request on any violation. Do not silence a warning to make CI pass;
  fix its cause.
- **Tests.** Every behavior change to a detector, redaction, overlap
  resolution, or policy comes with deterministic automated tests in the same
  pull request, in the shared [conformance corpus](conformance/README.md) or
  the package's own test suite. A pull request that changes behavior without a
  test is not ready to merge. New functionality is accepted only with tests
  that exercise it. Statement coverage must stay at or above 80% for each
  language layer: Rust lines (`rust-coverage`), `packages/javascript/src`
  (`js-coverage`, `npm run js:coverage`), and the `redact_secret` Python
  wrapper (`python-coverage`); see
  [onboarding](docs/onboarding.md#measure-statement-coverage).
- **Regression tests for bug fixes.** A bug fix includes a test that fails
  without the fix. A confirmed false positive or false negative becomes a
  permanent synthetic regression fixture
  ([convention](conventions/synthetic-secret-regressions.md)).
- **Synthetic data only.** Fixtures, logs, snapshots, and documentation use
  unmistakably synthetic or revoked examples. Never commit a real credential.
- **Boundaries.** Keep the core side-effect free (no runtime network access,
  telemetry, secret storage, or environment-dependent behavior), keep
  detection separate from policy enforcement, and state the false-positive and
  false-negative tradeoffs of a detector change. A material boundary change
  needs an ADR.
- **Supply chain and static analysis.** Dependency changes must pass
  `cargo deny`, and the pinned OpenGrep SAST gate (`.github/workflows/sast.yml`)
  must pass. A new finding is fixed, or dispositioned in
  `sast/baseline.json` with a reason a reviewer can check.
- **Changelog.** Follow [Changelog coverage](#changelog-coverage) below.
- **License and origin.** Contributions are licensed under the repository's
  [MIT License](LICENSE). By opening a pull request you certify the
  [Developer Certificate of Origin 1.1](https://developercertificate.org/):
  you wrote the change or otherwise have the right to submit it under that
  license. The pull request template asks you to confirm this; a
  `Signed-off-by` trailer is welcome but not required.
- **Conduct.** Follow the [code of conduct](CODE_OF_CONDUCT.md). How changes
  are decided is described in [GOVERNANCE.md](GOVERNANCE.md).

### Changelog coverage

A pull request that changes the detector registry, the policy that classifies
its findings, the CLI, or a binding's own source must also change
`CHANGELOG.md`'s `## Unreleased` section. The `Changelog coverage` CI job
enforces it (`scripts/check-changelog-coverage.py`, issue #633), and the
guarded path list lives in that script's `GUARDED_PATHS`.

Write the entry for someone consuming the published package: what they can now
observe, what changed about an existing finding type, and what they must do if
a type or its default action changed. When the change alters no observable
behavior -- a refactor, a test, a comment -- apply the `no-changelog` label to
the pull request instead, so the waiver is visible to the reviewer. By contributing, you agree that your contribution is licensed
under the repository's [MIT License](LICENSE).

During beta, repository Markdown is the documentation source. Include updates
to the relevant user guides, examples, support statements, and limitations in
each feature change. Use the [documentation readiness checklist](docs/documentation-readiness.md)
to identify affected topics and record verification evidence. Before stable
release, reconcile all required topics with the final public contracts and
complete the delivery checks after a platform has been chosen.

## Advanced: maintainer evidence and promotion

Contributors do not need this section to report, research, contribute a
fixture, or implement an `implementation-ready` issue. Maintainers own it, and
a pull request that adds or changes a detector is reviewed against it. Nothing
here is optional for maintainers, and none of it weakens a gate. The state
vocabulary and ownership table are in the
[handoff contract](docs/contracts/contribution/implementation-ready-handoff.md).

### Boundary changes

A boundary change -- a new or changed detector, PII context rule, policy,
public API, evidence rule, or release gate -- also needs this reading, because
the ADR and spec-file rules bind it:

- Read [ARCHITECTURE.md](ARCHITECTURE.md), [CONVENTIONS.md](CONVENTIONS.md), and the
  [decision router](docs/decisions/DECISIONS.md). A material boundary change needs
  an ADR rather than an undocumented convention.
- New evidence goes where
  [`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`](docs/decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md)
  places its kind, not wherever is convenient: a product-judgement review
  under `docs/audits/` as a temporary review with its lifecycle block, retired
  before release qualification under
  [`decision-retire-historical-audit-bodies-before-release-qualification`](docs/decisions/2026-10-06-retire-historical-audit-bodies-before-release-qualification.md);
  a benchmark or scanner measurement in `redact-secret-benchmarks`, never
  copied into this repository; and an iterative or exploratory log as an
  issue comment, cited by permalink from whichever final record needs it, not
  restated there.
- Current rules are stated in the five spec files under `docs/specs/`
  (`detector-families.md`, `contextual-detection.md`, `engine.md`,
  `distribution.md`, `evidence-and-gates.md`); each links the ADR that
  decided it. A decision that applies an existing policy to one more
  provider family or one more instance is a spec-file row plus its
  supporting evidence, not a new ADR — a new ADR is warranted only for new
  policy, a new trade-off, or a precedent that spans families.

### New detector family checklist

Coverage growth is the classic way to lose precision: recall rises, false
positives rise faster, unless every new family arrives with the evidence
that keeps its numbers honest. A detector family does not merge until its
evidence lands with it -- this is a merge gate, not a follow-up, and it is
machine-checked in [`redact-secret-benchmarks`](https://github.com/redact-secret/redact-secret-benchmarks)
by `scripts/check-evidence-arrival.mjs` (`npm run arrival:check`, issue #52
there). Satisfy every item below, in that repository's PR, so the check
passes without anyone having to read the checker script itself:

0. **Research and handoff.** The route is credential-evidence research,
   then product-contract adoption in this repository, then evaluation, then
   benchmark results. Provider facts (shapes, sources, issuance, carrier
   layouts) are researched in
   [`credential-evidence`](https://github.com/redact-secret/credential-evidence)
   and in the family's provider dossier,
   `benchmarks/support/dossiers/<provider>.md` in `redact-secret-benchmarks`,
   which must carry `research.verdict: ready` before the family is handed to
   core (the handoff states are in the benchmarks
   [contribution handoff states](https://github.com/redact-secret/redact-secret-benchmarks/blob/main/docs/specs/contribution-handoff-states.md)).
   A support request ([issue form](.github/ISSUE_TEMPLATE/request-detector.yml))
   needs nothing from the reporter beyond a name; maintainers link or open
   the research issue in `redact-secret-benchmarks` themselves, and a
   reporter is never asked to file a second issue. The product PR links the dossier by its
   `main` URL (living documentation links `main`, not a branch or a commit).
   This repository keeps no dossier and no research record of its own: the
   detector module doc, the `docs/specs/detector-families.md` row, and the
   frozen evidence under `docs/audits/evidence/<issue>/` are the product
   record, and a retired temporary review is cited by a 40-hex permalink. Do
   not copy research or benchmark results into this repository
   ([policy](docs/decisions/2026-10-06-retire-historical-audit-bodies-before-release-qualification.md#5-boundaries-between-repositories)).
1. **Provider or tool evidence.** Record the family's evidence in the
   benchmarks product-contract registry
   (`benchmarks/evaluation/domains/credential/assessment.ts` in
   `redact-secret-benchmarks`): a `providerSource`, `twinSource`, or
   `candidateSource` (each a `url`, an `observedAt` date, a `formatVersion`,
   and what it `covers`), or at least one `corroboration` entry (`tool`,
   `label`, `url`), for the family. Anything not directly backed by provider
   documentation is a T2 (tool-corroborated) contract, not T1, and must say so
   rather than assert provider grounding it doesn't have --
   [`decision-freeze-precision-contracts-seven-provider-families`](docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md#folded-records)
   (Pulumi row) shows a T1-prefix/T2-body contract written up this way.
   The older `benchmarks/lib/assessment.ts` path survives only as a
   compatibility re-export of that file for existing importers; write new
   evidence against the domain path.
2. **Canonical positives.** At least one fixture carrying the family's
   documented shape in a realistic context, run through the differential
   method against the pinned scanners.
3. **Negative twins.** At least one twin fixture (`twinOf` + `mutation` +
   `mutationKind`) a near-identical non-secret must not flag. Where no
   provider grammar exists to mutate, record
   `contracts["<family>"].unprobeable` with a `reason` and an `observedAt`
   date instead of authoring one -- Datadog's API key, Discord's bot token,
   Twilio's Auth Token and API Key Secret, Telegram's bot token, and
   Microsoft Entra's application client secret already use this escape
   hatch in `benchmarks/support-matrix.json`, each with a reason tied to
   what the provider's page does and doesn't state.
4. **Adversarial benign controls.** At least one control fixture -- a
   public identifier, placeholder, reference, or ordinary prose -- that
   must not be flagged.
5. **Metamorphic cases.** At least one fixture carrying an encoding,
   whitespace, CRLF, Unicode, or chunk-boundary variant
   (`benchmarks/operators/context.ts`).
6. **Mutation cases.** At least one fixture whose prefix, length, alphabet,
   or separator can be mutated (`benchmarks/operators/lexical.ts`).
7. **Differential observation.** At least one fixture assigned to the
   family in `benchmarks/fixture-detectors.json` so it runs against the
   pinned scanners.

**The detector and its contract land together.** The support matrix derives
its family list from the contracts registered in `assessment.ts` (the path in
item 1), so a
detector merged here without a matching contract in
`redact-secret-benchmarks` isn't `provisional` -- it's invisible to the
support matrix until someone notices the family count is wrong. Coordinate
the product PR and the benchmarks PR to land in the same window rather than
sequencing detector-then-contract; the family identifiers `assessment.ts`
keys its contracts by come from `redact-secret-benchmarks`' own
`benchmarks/support/taxonomy.json`, not from this repository's detector
registry, so a new provider or credential family needs a taxonomy entry
there too before it has an id for the contract to key on.

**Detector-to-family mapping gate.** `npm run detector-family-coverage:check`
(`scripts/check-detector-family-coverage.py --strict`, offline) lists each
detector in `docs/coverage/detector-inventory.json` that no family in the
pinned `benchmarks/support-matrix.json` names, and each matrix entry naming a
detector the inventory lacks. The gaps that exist today (the detectors under
"not yet measured" in [`docs/support-matrix.md`](docs/support-matrix.md) and four
stale matrix ids) are recorded with a reason each in
[`docs/coverage/detector-family-coverage-allowlist.json`](docs/coverage/detector-family-coverage-allowlist.json).
A new detector without a family fails CI unless you add a reviewed, reasoned
entry there; an entry that is no longer a gap also fails, so the allowlist only
shrinks as the pinned matrix is refreshed.

**This checklist is necessary, never sufficient, for `stable`.** Clearing
it means the evidence *exists*. Whether a family is `stable` is decided by
`redact-secret-benchmarks` and reaches this repository only as the pinned
support matrix; this document does not restate that rule. The rule has one
home here: the support-matrix row of
[evidence and gates](docs/specs/evidence-and-gates.md) and its user-facing form,
[what each status means](docs/support-matrix.md#what-each-status-means). Stable
is reached through one of three qualification profiles (documented, empirical,
policy-qualified), each with its own evidence floors, so a T1 provider contract
is required for the documented profile only. A family can clear this checklist
and still classify `provisional`; it cannot classify anything but
`provisional` (at best) without clearing this checklist first.

### Benchmark-originated bug checklist

For a bug found by
[`redact-secret-benchmarks`](https://github.com/redact-secret/redact-secret-benchmarks),
link its benchmark fixture ID, corpus hash, measured candidate identity,
expected and actual safe metadata, finding kind, independent expectation-review
evidence, and product bug issue. Do not change an expectation merely to make a
scanner pass.

Before describing the bug as verified, record both gates in
[`conformance/benchmark-regressions.json`](conformance/benchmark-regressions.json):

- the minimal canonical regression passes every required supported conformance
  surface; and
- the exact fixed candidate was rerun in the benchmark repository and the
  verification evidence is linked.

Follow
[`decision-govern-benchmark-regression-promotion`](docs/decisions/2026-09-18-govern-benchmark-regression-promotion.md)
for fixture placement, detector-unit-test criteria, ownership, and historical
reconciliation. A code fix or a closed implementation issue alone does not
satisfy both gates.

## Branching strategy

`main` is the integration and release-source branch. Merge normal development,
version preparation, and release fixes from working branches through pull
requests. Qualify an exact merged commit, publish from `main`, and use the
resulting annotated version tag's peeled commit as the immutable release
identity. The [release runbook's branching model](docs/releasing.md#branching-model)
defines qualification, publication, reconciliation, and closeout.

## Releases

Follow the [release authority](AGENTS.md#release-authority) and the
[release runbook](docs/releasing.md) for candidate preparation,
non-publishing qualification, approval, publication, recovery, and closeout.
The Rust crates, npm packages, Python distribution, and CLI share one SemVer
version, source revision, and eventual `v{version}` tag
([lockstep decision](docs/decisions/2026-09-09-release-bindings-in-lockstep.md),
[artifact qualification guide](docs/qualification.md)).

### Release evidence

[Release status](docs/releases/status.md) lists every published version and
its durable record. Subsequent development is recorded under `Unreleased` in
the [changelog](CHANGELOG.md). Candidate reviews live under
[docs/audits](docs/audits/README.md).
