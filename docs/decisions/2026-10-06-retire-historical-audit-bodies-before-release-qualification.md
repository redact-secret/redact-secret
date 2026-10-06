---
decision_id: decision-retire-historical-audit-bodies-before-release-qualification
status: accepted
scope: workspace
title: Retire historical audit bodies before release qualification instead of retaining them permanently
decided_at: 2026-10-06
spec: evidence-and-gates
supersedes: decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement
---

# Retire historical audit bodies before release qualification instead of retaining them permanently

## Context

[`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`](2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md)
(the taxonomy ADR) and `AGENTS.md` place final product-judgement evidence under
`docs/audits/evidence/<issue>/`, "frozen". Read literally, every review ever
written stays in the current tree forever. The tree now carries 452 audit
files in 152 units, a 70 KB index, and live consumers hidden inside the
archive (see epic [#1259](https://github.com/redact-secret/redact-secret/issues/1259)).
Every published tag already contains each body, and `main` history is never
rewritten, so permanent tree retention buys nothing that history and a
verified permalink do not. It costs reading time, index growth and a
reachability gate that has to keep the whole archive linked.

## Decision

Review and evidence files may be committed while work is in progress. Their
bodies leave the current tree before release qualification, and history plus a
verified permalink preserve them. This supersedes only the taxonomy ADR's row
"Final evidence, product judgement ... `docs/audits/evidence/<issue>/`,
frozen" and the matching `AGENTS.md` and `CONTRIBUTION.md` sentences. Every
other part of the taxonomy ADR (live contract and generated rows, the
benchmark-evidence route, issue-comment logs, spec routing, ADR grades, the
permalink form, the ADR criterion, the wiki) stands unchanged.

### 1. Six kinds, defined separately

| Kind | Test | Location | Lifetime |
| --- | --- | --- | --- |
| Current contract | states what is true now | spec (`docs/specs/`), ADR, reference page, public docs | kept; changed by editing the spec or by a new ADR |
| Live input | CI, a script or code reads it | a non-archive path (`docs/contracts/`, `benchmarks/`, `conformance/`, `sast/`) with its check intact | kept while read |
| Generated-and-checked artifact | a script produces it | committed only with a regeneration-equality check | kept while the check exists |
| Temporary review | a review, evidence unit, exploratory output, rejected patch or inert harness written during development | `docs/audits/<name>.md` or `docs/audits/evidence/<unit>/` | until its retirement trigger, never past qualification (section 4) |
| Historical judgement | a temporary review that reached `status: final` | git history, cited by a 40-hex permalink | permanent in history, absent from the tree |
| Release record | one per published version | `docs/releases/<version>/` | permanent, concise |

A file that something reads is a live input or generated artifact whatever
folder holds it; moving it out of `docs/audits/` is a precondition of retiring
its unit, not an alternative to it. Moving an archive to another tracked
folder is not retirement.

### 2. Metadata a temporary unit carries

A temporary unit is one entry file with a front matter block, parsed by the
same `key: value` rules as `scripts/validate-decisions.py`. The entry file is
`docs/audits/<name>.md` or `docs/audits/evidence/<unit>/README.md`; other
files in the unit carry nothing. Fields, all required except `record`:

```text
---
owner: #1260                # issue number, or GitHub login for an issueless unit
reviewed_source: <40-hex>   # commit the review judged
status: in-progress         # in-progress | final | deferred | retained
retire_on: before-qualification   # before-qualification | after-issue:#N | after-release:<version>
record: <40-hex blob permalink>   # required when status is final
---
```

Why a front matter block and not a manifest: a manifest is a second archive
that goes stale, can name units that no longer exist, and needs its own
retirement. A block in the entry file is deleted with the unit, is found by
enumerating the filesystem as `scripts/check-audits-index.py` already does,
and lets a check fail on a unit that has no block, so no unit can sit in the
tree untracked. The check that enforces this is #1266's; this ADR fixes only
the format.

Status rules:

- `in-progress`: open work. It becomes `final` or `deferred`, or is deleted,
  before qualification.
- `final`: the review is complete. `retire_on` is `before-qualification` and
  `record` names the permalink of section 3. A `final` unit is eligible for
  retirement now and is not carried into qualification.
- `deferred`: the unit still states an open obligation. `retire_on` is
  `after-issue:#N` for an open issue. Issue status alone never keeps a body:
  the default is to restate the obligation in that issue with a 40-hex
  permalink to the body and retire the body (section 3); `deferred` is for an
  obligation that cannot be stated without the body.
- `retained`: only the current candidate review (below). `retire_on` is
  `after-release:<version>`.

### 3. Retiring a final record

A unit is retired only when all of these hold, checked before the deletion
commit:

1. A full 40-hex permalink
   `https://github.com/redact-secret/redact-secret/blob/<sha>/<path>` names a
   commit that is an ancestor of `origin/main` and contains every file of the
   unit byte-identical to the tree being removed. A branch, a workbench SHA,
   an abbreviated SHA or `blob/main` fails. This is the taxonomy ADR's
   permalink form plus a completeness test.
2. Every conclusion that current code, a spec row or a release depends on
   lives in the authoritative spec, contract, ADR or release record, in the
   present tense. Negative conclusions (a rejected design, a measured number
   that closed an option) move as one spec row or ADR sentence with the
   permalink, never as the rejected patch or harness itself.
3. Anchors, checksums and provenance other places cite are either carried in
   that conclusion or reachable through the permalink; incoming links in the
   tree and in other repositories are rewritten to the permalink first.
4. Anything a script or CI reads has moved to a live-input or generated path.

No stub, tombstone or per-issue file is left behind. The unit-to-permalink
table lives in the retiring commit message or pull request body and wherever
a current document still needs the history. The audit index loses the entry
with the unit, so index size is bounded by what is in the tree.

Open and deferred work follows its `status`; it never justifies leaving a
completed body in place. A rejected experiment keeps no body or code, only its
negative conclusion under rule 2. A current candidate review is the one
`retained` unit: the review of the version being prepared may stay through
qualification with `retire_on: after-release:<version>`; after publication a
reviewed closeout pull request moves its conclusions into
`docs/releases/<version>/` and retires the body, and every older candidate
review retires in the cleanup before the next qualification.

An integrity or checksum bundle follows what it verifies. One that a script
checks is a live input or generated artifact and keeps its check. One that
only attests a retired body retires with it: the git blob ids at the permalink
commit are the integrity record. Registry file checksums, artifact inventory,
run identifiers and tag targets belong to the release record and are never
retired.

### 4. Where cleanup sits in a release

Cleanup is a reviewed pull request merged to `main` in "Prepare the
candidate", before the source SHA is recorded. The exact merged commit is then
qualified (`Package Release Rehearsal` and `Artifact qualification` on that
SHA, then `Release`). Publication performs no tree mutation: it neither edits
nor deletes files and creates no commit. Any tree change after qualification,
including cleanup, makes a new SHA and needs fresh qualification. Historical
tags and history stay intact; a retired body remains in every tag that
shipped it. `docs/releases/<version>/` records, the genuine release approval
evidence, and required current contracts are preserved.

### 5. Boundaries between repositories

Core keeps its specs, contracts, live inputs and release records, and its own
temporary reviews of product judgements. Credential-evidence research
(provider dossiers, captures, verdicts) and benchmark or scanner results
belong to `redact-secret-benchmarks`, per the taxonomy ADR and
[`decision-move-performance-results-criteria-and-judgement-to-benchmarks`](2026-09-22-move-performance-results-criteria-and-judgement-to-benchmarks.md).
Core states the conclusion it relies on and cites the external record by
permalink: a past state with a 40-hex commit, living documentation with
`main`, never a branch. Core never copies an external dossier or result in
to satisfy retirement; if a core body is the only home of such material, the
fix is a coordinated follow-up in that repository, not a copy here.

## Consequences

- New work follows this lifecycle without reading the epic: write the review
  with its block, finish it, record the permalink, retire it before
  qualification.
- Eligibility is mechanical, so #1266 can fail a release candidate that still
  carries a `final` unit, a unit without a block, or a `final` unit whose
  `record` does not verify. #1262 to #1265 migrate live inputs and retire
  existing units against this rule; this ADR changes no script and no file
  under `docs/audits/`.
- The taxonomy ADR is not rewritten. It carries a supersession notice and a
  `superseded_by` field; its status stays `accepted` because only one row is
  superseded.
- Detection, policy, output and the public API are unchanged.
