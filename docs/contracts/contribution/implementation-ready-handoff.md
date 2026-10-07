# The implementation-ready handoff contract

Defined by [#1049](https://github.com/redact-secret/redact-secret/issues/1049),
part of [#999](https://github.com/redact-secret/redact-secret/issues/999).
Decision:
[`decision-define-the-implementation-ready-handoff-contract`](../../decisions/2026-10-07-define-the-implementation-ready-handoff-contract.md).
The benchmark side is
[`contribution-handoff-states`](https://github.com/redact-secret/redact-secret-benchmarks/blob/main/docs/specs/contribution-handoff-states.md#shared-vocabulary)
(redact-secret-benchmarks#533); this page adopts its five words unchanged.

An `implementation-ready` issue means: research is complete, the supported and
excluded behavior is frozen for this issue, and the contributor implements and
tests the reviewed contract instead of rediscovering it. It is a coding
handoff. It is never a stable-support verdict, and it never makes
under-specified security work acceptable.

## Vocabulary

Five work-item states. They label an issue, never a family's support status.
Use them as GitHub labels with the `state:` prefix (`state:intake`,
`state:research-needed`, `state:implementation-ready`,
`state:verification-needed`, `state:complete`); one at a time per issue.

| State | Meaning | Applied by |
| --- | --- | --- |
| `intake` | A report or suggestion was received and is not yet triaged | any contributor opens; a core maintainer triages |
| `research-needed` | Triaged; shapes, sources or issuance are not yet recorded or reviewed | credential-evidence researcher works the case; benchmarks dossier owner for a legacy dossier |
| `implementation-ready` | Every required field below holds and core adopted the contract | core maintainer, by the adoption comment |
| `verification-needed` | Core implemented a candidate; benchmarks has not measured that exact candidate | core maintainer, by the reverse handoff |
| `complete` | Benchmarks measured the exact candidate and recorded the result | benchmarks maintainer, by the evidence PR |

`complete` means the loop closed and the measurement is recorded. It does not
mean the candidate passed, was promoted, or is stable. No status, tier or
verdict is inferred from a state, and tooling that reads a `state:` label must
not write one. The labels are applied to the core implementation issue; the
benchmarks counterpart keeps its own labels with the same words.

## Ownership

| Repository | Owns | Moves | Named owner |
| --- | --- | --- | --- |
| `credential-evidence` | provider facts: shapes, sources, issuance, carrier layouts; the revision-bound research handoff | `intake` to `research-needed`, and the research handoff itself | credential-evidence researcher on the case |
| `redact-secret` (core) | the product contract (supported and excluded behavior, policy default, trade-offs), the implementation, conformance fixtures, the spec row | `implementation-ready`, `verification-needed` | core maintainer ([@milocosmopolitan](https://github.com/milocosmopolitan), `GOVERNANCE.md`) |
| `redact-secret-benchmarks` | independent evaluation of the exact candidate, benchmark evidence, dossier verdicts, support-status promotion | `complete` | benchmarks maintainer (the `evaluation.owner` role, `benchmarks-maintainer`) |

Research and implementation are never one issue. The research issue lives in
`credential-evidence` (or a benchmarks research issue for a legacy dossier);
the implementation issue lives in core and is created or relabeled only when
every condition below holds.

## Required fields

All fields are required before `implementation-ready` is applied. The
machine-readable form is
[`implementation-ready-handoff-v1.schema.json`](implementation-ready-handoff-v1.schema.json)
(`schemaVersion: redact-secret.implementation-handoff/v1`); an example is
[`examples/ory-siblings.handoff.json`](examples/ory-siblings.handoff.json).

| Field (JSON path) | Content | Issue section |
| --- | --- | --- |
| `issue`, `state` | core issue number; the literal `implementation-ready` | header |
| `identity.family`, `identity.route`, `identity.detector`, `identity.findingTypes` | taxonomy id; one of `new-detector`, `extend-detector`, `contextual-rule`, `fixture-only`, `policy-change`; detector id; finding kinds | 1 |
| `task` | one cold-readable task sentence | 1 |
| `positives[]` | supported shapes and contexts, in words or character classes | 2 |
| `exclusions[]` | excluded shapes, gated parts and accepted false negatives, each with a reason | 3 |
| `twins[]` | near-miss twins and benign siblings, each with the reason it is a control | 3 |
| `surfaces[]` | files or globs likely to change (a hint) | 4 |
| `commands[]` | exact scoped local checks | 5 |
| `policy.defaultAction`, `policy.confidence`, `policy.tradeoffs.{falsePositive,falseNegative}` | policy classification and both trade-offs | 3 or 6 |
| `conformance.fixturesRequired`, `bindingsEquivalent`, `syntheticOnly` | fixture groups for the shared corpus, equivalence harness green, synthetic values only | 3 and 5 |
| `research.handoff`, `verdict`, `tier`, `readAt`, `dossier` | 40-hex permalink of the reviewed research handoff, verdict `ready`, tier, the commit it was read at, optional dossier link | 6 |
| `research.adoption.{ruling,adoptedOn}` | the core adoption ruling (comment or ADR link) and date | 6 |
| `research.limitations[]` | unresolved limitations, each restated in `exclusions[]` | 6 |
| `evaluation.benchmarkIssue`, `owner`, `evidenceLabel`, `supportStatus` | benchmarks issue that will measure the exact candidate, owner role, `project-authored` or `independent`, and the literal `separate` | 6 |

A field that cannot be filled keeps the issue in `research-needed`; the
maintainer names the missing field in a comment rather than moving the label.

### Gates that cannot be waived

1. The research handoff is reviewed and core adopted the supported and excluded
   contract. A legacy dossier supports the handoff only where its documented
   consumer still requires it
   ([`CONTRIBUTION.md`](../../../CONTRIBUTION.md#new-detector-family-checklist)).
   A historical handoff (for example the #1014 record) is read again at its
   current revision before the label is applied.
2. Every unresolved limitation is an exclusion. Nothing issuance-gated or
   date-gated is inside the supported contract.
3. No field carries a real, revoked-but-real or realistic credential literal.
   Shapes are words or grammars; values in tests are built at run time from
   repeated filler or are unmistakably synthetic.
4. The handoff names the benchmark counterpart. Independent evaluation and
   support-status promotion stay separate and are never written into the issue
   as a result.
5. The security-first default holds: ambiguity is resolved toward redaction and
   documented, never left for the implementer to decide.

## Contributor-first issue layout

The first screen is everything a contributor needs. Section 6 is collapsed and
is for maintainers; the implementer does not need it to start.

````markdown
## 1. Task
<one sentence: what to build, which detector or surface>

## 2. Expected positives
- <shape or context, in words or a character class>

## 3. Expected negatives and twins
Must not be flagged:
- <near-miss twin or benign sibling> -- <why it is a control>
Not supported by this issue:
- <excluded shape or gated part> -- <why>

## 4. Files or surfaces likely to change
- <path or glob>

## 5. Commands to run
```bash
npm run check:detector
```

<details>
<summary>6. Maintainer evidence and research</summary>

- State: implementation-ready (core adoption ruling: <link>, <date>)
- Research handoff: <40-hex permalink> (verdict ready, tier <T>, read at <40-hex>)
- Policy: <default action>, confidence <level>; false positive: <...>; false negative: <...>
- Conformance: <fixture groups>; equivalence harness green; synthetic values only
- Independent evaluation: redact-secret-benchmarks#<N>, owner benchmarks-maintainer, evidence label <label>
- Support status: separate. This handoff is not a support verdict.
- Unresolved limitations (restated above as exclusions): <list>
</details>
````

An issue body with that layout is the primary artifact. A checked-in or
CI-supplied handoff file is its machine-readable twin.

## Handoff file

- **Name:** `<slug>.handoff.json`, for example `ory-siblings.handoff.json`.
- **Schema:** [`implementation-ready-handoff-v1.schema.json`](implementation-ready-handoff-v1.schema.json),
  `schemaVersion` `redact-secret.implementation-handoff/v1`.
- **Where it lives:** nowhere by default. It is generated from the issue body or
  passed by path, for example to the scaffold (#1050,
  `npm run contrib:new-detector -- --handoff <file>`) and to the CI summary
  (#1051). It is a live input, not a temporary review, and it is not committed
  under `docs/audits/`. Checked-in examples live under
  `docs/contracts/contribution/examples/`.
- **Validation:** the schema checks structure and vocabulary. A consumer also
  rejects a file whose strings contain a credential-shaped literal, whose
  `state` is not `implementation-ready`, whose `exclusions[]` omit an entry for
  every `research.limitations[]`, or whose `evaluation.supportStatus` is not
  `separate`. Those four rules are the lint the schema cannot express.
- **Compatibility:** a breaking change (field removed, enum word changed) bumps
  to `v2` and amends the decision. Adding an optional field does not.

## What other repositories mirror

Not edited here. Each repository documents the same words and owners:

- **`credential-evidence`:** the five state words and the table above, with the
  researcher as owner of `intake` to `research-needed` and of the research
  handoff; a reviewed handoff states its commit so core can fill
  `research.handoff` and `research.readAt`, and lists its exclusions and twins in
  a form core can copy.
- **`redact-secret-benchmarks`:** already defines the five words in
  `contribution-handoff-states`. It adds a link back to this page, names the
  benchmarks maintainer as `evaluation.owner`, and keeps `verification-needed`
  and `complete` as its labels on the counterpart issue. Its "Data the core
  issue receives" fields map to `research.*` and `evaluation.*` here.

## Worked example

[#1110](https://github.com/redact-secret/redact-secret/issues/1110) rewritten
under this contract: [worked example](worked-example-1110.md), with its
machine-readable form [`examples/ory-siblings.handoff.json`](examples/ory-siblings.handoff.json).
