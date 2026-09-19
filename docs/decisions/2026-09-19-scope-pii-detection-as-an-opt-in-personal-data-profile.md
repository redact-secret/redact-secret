---
decision_id: decision-scope-pii-detection-as-an-opt-in-personal-data-profile
status: proposed
scope: workspace
title: Scope PII detection as an opt-in personal-data profile
decided_at: 2026-09-19
---

# Scope PII detection as an opt-in personal-data profile

Proposed for the beta.6 cycle. This record is a **specification and design**,
not an accepted decision: it amends a standing architectural exclusion, so it
needs explicit review before any implementation issue is opened. It changes no
detector, public API, artifact, or release by itself, and authorizes no
release.

## Context

### The standing exclusion

[`ARCHITECTURE.md`](../../ARCHITECTURE.md#deliberate-exclusions) lists, under
"Deliberate exclusions":

> - PII detection, prompt-injection analysis, organization data policy, or
>   other broader context-safety functions.
>
> Those capabilities may wrap or follow Redact Secret, but they must not
> weaken the deterministic core or create another authoritative detector
> implementation.

Adding a PII detector is therefore **not** an ordinary detector addition
(which is a minor change under
`decision-define-detector-profile-and-pack-contract`). It is an amendment to
the product boundary. Nothing below may be implemented until that amendment is
accepted, and the amendment's whole price is stated here so it can be refused
cheaply.

### Why the exclusion exists, and what actually changes

The exclusion protects four properties, only one of which PII genuinely
threatens:

| Property | Threatened by PII detection? |
| --- | --- |
| Determinism, no network, no model invocation | No, **if** the grammar is checksum- or structure-decidable. Yes, and fatally, for name/address/free-text PII, which needs NER. |
| One authoritative detector implementation | No. PII detectors live in the same Rust core, under the same conformance corpus. |
| No plaintext in findings, errors, or diagnostics | No. The same safe-metadata contract applies unchanged. |
| **Precision, and the bounded-redaction tradeoff** | **Yes.** This is the real cost, and the rest of this record is mostly about containing it. |

A credential is a *self-identifying* string: `ghp_` followed by 36 token bytes
is a GitHub token and nothing else. Personal data is not. A 16-digit run that
passes Luhn is a payment card about as often as it is an order id, and roughly
one in ten random 16-digit runs passes Luhn. Nine digits are a US SSN or a part
number. Four dotted digit groups are an IPv4 address or a version string. The
repository's entire precision posture — "specific or structural evidence
outranks broad contextual evidence", "entropy is never sufficient by itself" —
was built for a class of value that carries its own issuer marker. Personal
data mostly does not.

The consequence is not "PII detection is impossible here". It is that **the
admissible PII grammar is far narrower than the category "PII"**, and that PII
findings must not be allowed to change what `full` does today.

### What consumers are actually asking for

The concrete demand behind this is log, trace, and prompt sanitization: the
same pipeline that already strips a `sk-...` key out of a tool result is the
natural place to strip a customer's payment card or resident registration
number out of the same tool result. Running a second, unrelated scanner over
the same text costs a second pass, a second set of ranges, and a second
overlap problem that neither scanner can see.

That demand is real, it is server-side, and it is a poor fit for the browser —
the inverse of the `common` profile's consumer.

## Decision

### Summary

1. Amend the `ARCHITECTURE.md` exclusion from "no PII detection" to "no
   **undecidable** PII detection": named entities, addresses, free-text
   identity, inference, and re-identification scoring stay excluded
   permanently. A bounded set of checksum- or structure-decidable personal
   identifiers becomes admissible.
2. Introduce a **risk class** on every finding: `credential` (every detector
   that exists today) or `personal-data`. It is public, additive metadata.
3. Introduce a third pack, `pii`, and exactly one new profile, `full-pii`
   (= `common` + `provider` + `pii`). `full` and `common` are unchanged,
   byte-for-byte, on every surface.
4. Resolve PII candidates in a **separate overlap domain** that runs after
   credential resolution and yields to it, so that `full-pii`'s credential
   findings are provably identical to `full`'s.
5. Give personal-data findings their own placeholder namespace (`<PII_n>`),
   numbered independently of `<SECRET_n>`.
6. Ship `full-pii` on Rust, Node, Python, and the CLI. **Not** on the browser
   WebAssembly artifact in this cycle.

### 1. Amended product boundary

The exclusion list becomes:

> - prompt-injection analysis, organization data policy, or other broader
>   context-safety functions; and
> - personal-data detection that is not decidable from the text alone:
>   personal names, postal addresses, dates of birth in free text, job or
>   health descriptions, any form of named-entity recognition, inference over
>   surrounding text, and re-identification risk scoring.

A personal-data grammar is **admissible** only if it satisfies all four:

- **A1 Decidable.** Membership is decided by a published structure, a
  checksum, or a reviewed context gate — never by a model, a dictionary of
  names, or a probability threshold.
- **A2 Bounded.** The grammar has explicit length and alphabet bounds, and a
  reviewed false-positive contract naming what it deliberately misses.
- **A3 Side-effect free.** No network validation (no BIN lookup, no carrier
  lookup, no IBAN registry call), no locale detection from the environment.
- **A4 Non-weakening.** Its presence cannot remove, reclassify, or renumber
  any credential finding. This is enforced mechanically (§4, §7).

Entropy remains insufficient by itself, and remains unavailable to this class
entirely: there is no personal-data analogue of `generic-token`.

### 2. Risk class as finding metadata

`DetectedFinding` and `Finding` gain one field:

```text
id, class, type, detector, confidence, action, start, end
```

`class` is `"credential"` or `"personal-data"`. Every existing detector
reports `credential`. The field is additive on every surface and in the
conformance schema; because the corpus is the cross-language contract, adding
it is a schema change and every binding runner must carry it in the same
change.

`class` is the first key the default policy reads (§5) and the key the default
placeholder formatter reads (§6). It is deliberately *not* a new
`Specificity` variant and *not* part of the overlap tie-break ladder — see §4.

A custom `Policy` receives `class` like any other safe metadata. Detection
still never receives, and never returns, a matched value.

### 3. The `pii` pack and the `full-pii` profile

`decision-define-detector-profile-and-pack-contract` defines `full` as "every
officially supported built-in detector". That sentence is amended to:

> `full` holds every officially supported built-in **credential** detector.

`full` is no longer the top of the profile lattice; it remains the
**compatibility baseline for credential detection**, which is the property
consumers actually depend on.

| Pack | Rule | Members |
| --- | --- | --- |
| `common` | unchanged | 6 |
| `provider` | unchanged | 36 |
| `pii` | An admissible personal-data grammar under A1–A4. Every `pii` detector reports `class = personal-data`. | Tier A (§8), 4 at first |

| Profile | Packs | Default? | Surfaces |
| --- | --- | --- | --- |
| `common` | `common` | no | Rust, Node, browser |
| `full` | `common`, `provider` | **yes, everywhere, unchanged** | all |
| `full-pii` | `common`, `provider`, `pii` | no | Rust, Node, Python, CLI |

No `pii`-only profile and no `common-pii` profile ship. Each profile costs an
expectation set, an artifact row, and a qualification row; the ADR above keeps
profiles few and evidence-gated, and no consumer has named either one.

Composition uses the same mechanism as `common`: one registry constructor per
profile, obeying the reachability rule, with a checked-in pack table. A
`full-pii` constructor references the `full` constructor plus the `pii`
constructors; `full`'s constructor must **not** reference any `pii`
constructor, so a `full` artifact links no PII code and its size is unchanged.
This is the opposite direction of the `common` reachability rule and is
checked the same way: by artifact size (§7.6).

`pii` detectors take the canonical order **after** every existing built-in.
The canonical order is not reordered, so the fourth overlap tie breaker ranks
any two existing detectors exactly as before.

### 4. Two resolution domains

This is the mechanism that makes A4 true rather than aspirational.

Today, one greedy pass accepts mutually disjoint ranges from one ranked
candidate list. If PII candidates entered that list, a PII candidate could
outrank and displace a credential candidate, and `full-pii` would silently
detect *fewer* credentials than `full`. That is unacceptable at an enforcement
boundary.

The pipeline becomes:

```text
candidates
    |
    +-- class = credential --> rank (unchanged ladder) --> greedy disjoint --> C
    |
    +-- class = personal-data --> rank (same ladder, within class)
                                      |
                                      v
                            greedy disjoint among themselves
                                      |
                                      v
                       drop any candidate overlapping a range in C
                                      |
                                      v
                                      P
    |
    v
findings = merge(C, P) ordered by start offset
```

Properties, each a test in §7:

- **Credential invariance.** For every input, the multiset of
  `(type, detector, confidence, start, end)` over `class = credential`
  findings in `full-pii` equals that in `full`. PII can only *lose* to a
  credential, never the reverse.
- **PII yields on overlap.** An email inside a JWT payload, or inside a
  credential-bearing connection URI whose accepted range covers it, produces
  no personal-data finding: the credential range already redacts it. An email
  in the *userinfo* of a connection URI, which lies outside the accepted
  password span, does survive and is reported.
- **No new tie breaker.** `Specificity` gains no variant and its ordering is
  untouched. Within the personal-data domain the existing ladder is reused
  (`Structural > Contextual`, `Entropy` unused), so there is exactly one
  ranking rule in the core.
- **Cost.** One extra partition of the candidate vector and one extra greedy
  pass over the PII subset, plus an interval check of each surviving PII
  candidate against `C`. `C` is already sorted, so the check is a binary
  search: the pipeline stays `O(n log n)`.

Incremental sanitization inherits this unchanged: a personal-data candidate is
final under exactly the conditions its own grammar closes on, and the
credential-yield check needs only the credential findings already finalized
for the same span. No `pii` detector may open a retention construct in this
cycle — every Tier A grammar is single-line and bounded — so the shared
retention reserve is untouched.

### 5. Default policy

`private_key` blocks; that is unchanged and stays credential-only. **No
personal-data type ever produces `block`.** Blocking is an enforcement signal
about a credential that must not travel; a customer's email address in a
support log is not that.

| Personal-data type | Default action | Why |
| --- | --- | --- |
| Checksum-validated identifier (`payment_card_number`, `iban`, `kr_resident_registration_number` with a valid check digit) | `redact` | The checksum plus an issuer-shaped prefix makes a false positive rare and the value unambiguously sensitive. |
| Context-gated identifier (`us_social_security_number`, RRN failing the post-2020 checksum) | `redact` | The context gate carries the evidence the checksum cannot. |
| Structurally-decidable but low-specificity (`email_address`, `phone_number`, `ip_address`) | `warn` | Redacting every email destroys the debuggability of the very logs this is used on. The finding is reported; the text is preserved; a stricter consumer policy can escalate. |

The reasoning is asymmetric on purpose, and the asymmetry is the point: a
credential false negative leaks a key, so the default leans aggressive. A
personal-data false positive corrupts the text for everyone, and the same
pipeline runs on logs whose value *is* their fidelity, so the default leans
conservative and hands escalation to the consumer's own `Policy`.

A consumer that wants every personal-data finding redacted writes a four-line
policy over `class`. A consumer that wants credentials enforced and personal
data merely reported gets that by default.

### 6. Placeholder namespace

The default formatter picks its label from `class` and numbers within class:

```text
input:  contact alice@example.com with key ghp_<synthetic>
output: contact <PII_1> with key <SECRET_1>
```

Credential placeholder numbering in `full-pii` is therefore identical to
`full` for the same input. Finding **ids** are still assigned over the merged,
position-ordered list, so a `full-pii` run renumbers ids relative to `full`;
that is stated in the changelog and in the guides. Placeholders, which appear
in output text, are the thing consumers diff, and those stay stable.

A custom formatter receives `class` and the per-class index. The existing
placeholder-safety rules (non-empty, bounded, no unsafe characters, no
recoverable content) apply unchanged.

### 7. Qualification obligations

For every profile and every surface exposing it:

1. **Membership.** `full`'s ids equal the canonical 42-id list in order, and
   contain no `pii` id. `full-pii`'s ids equal `full`'s followed by the
   declared `pii` list. Every built-in has exactly one pack.
2. **Credential invariance.** Over the whole canonical corpus and the whole
   assessment corpus, `full-pii`'s `credential` findings equal `full`'s, by
   `(type, detector, confidence, range)`. This is the A4 enforcement test and
   it is a release gate.
3. **`full` untouched.** `full` artifacts, findings, redacted output, ids,
   placeholders, exports, and WebAssembly byte size match the pre-change
   baseline exactly.
4. **Findings.** The canonical corpus runs under `full-pii` against reviewed,
   committed expectations kept beside the canonical fixtures. Incremental
   partition equivalence holds for `full-pii`.
5. **Reserved ids.** Every profile constructor rejects a custom detector
   reusing any built-in id, `pii` ids included, in every profile.
6. **Reachability guard.** The `full` WebAssembly artifact's size must not
   grow. Growth means `pii` code became reachable from the `full`
   constructor.
7. **Per-detector precision contract.** Every `pii` detector ships a reviewed
   precision contract and coverage declarations on the same terms as a
   provider family (`decision-freeze-precision-contracts-for-seven-provider-families`),
   with `positive`, `overlap`, `adversarial`, `boundary`, and
   `near-miss-negative` dimensions populated.
8. **Personal-data false-positive gate.** Measured on the existing negative
   corpora before the profile is qualified — see §8, step 2.

### 8. Delivery plan

The order exists so that the expensive, irreversible step (writing detectors)
happens after the cheap step that can cancel it (measuring their false-positive
rate). Steps 1 and 2 are both cheaper than step 4 by more than two orders of
magnitude.

| # | Work | Ends at |
| --- | --- | --- |
| 1 | This record, reviewed and accepted; `ARCHITECTURE.md` exclusion amended | An accepted boundary, or a cheap refusal |
| 2 | **Measure first.** Implement each candidate grammar as a throwaway script, run it over `conformance/`'s negative fixtures, the `assessment/` negative corpus, and the benchmark corpus. Publish a per-grammar FP count and the text that triggered it. | An evidence record. Any grammar over the reviewed FP threshold is cut here, not after it ships. |
| 3 | Core plumbing, **no detectors**: `class` metadata, the second resolution domain, the placeholder namespace, the conformance schema field, binding pass-through. `full` output byte-identical. | A merged core change whose entire observable effect on `full` is one new metadata field reading `credential` |
| 4 | Tier A detectors + fixtures + coverage declarations + precision contracts | Detectors passing their own contracts |
| 5 | `pii` pack, `full-pii` constructor, reachability, surfaces (Rust, Node, Python `profile=`, CLI `--profile`) | An opt-in profile on four surfaces |
| 6 | Qualification (§7), evidence record, docs, changelog | A qualified profile |
| 7 | **beta.6 gate**, on the pattern of `decision-gate-beta5-on-precision-gains-and-positive-preservation`: credential invariance exact, PII FP rate under its reviewed threshold, no credential precision or recall movement in either direction | Release readiness — not release authority |

#### Tier A — proposed initial `pii` pack

Four detectors. Each is checksum- or structure-decidable and each has a
reviewed miss list.

| id | type | Evidence | Validation | Confidence | Default |
| --- | --- | --- | --- | --- | --- |
| `payment-card-number` | `payment_card_number` | Structural | IIN prefix from a pinned table **and** documented length **and** Luhn **and** (a separator grammar `NNNN-NNNN-NNNN-NNNN` / spaced, **or** a credential-bearing context keyword) | High | `redact` |
| `iban` | `iban` | Structural | ISO 3166 country code, per-country length from a pinned table, ISO 7064 mod-97-10 | High | `redact` |
| `kr-resident-registration-number` | `kr_resident_registration_number` | Structural | `YYMMDD-Gxxxxxx`: valid date, century/sex digit 1–8, then **either** the legacy weighted check digit (issued before Oct 2020) **or**, for a checksum that does not validate, a context gate | High / Medium | `redact` |
| `email-address` | `email_address` | Structural | RFC 5322 `addr-spec` subset: bounded local part, bounded domain, at least one dot, TLD shape; excludes the placeholder-word and template-reference exclusions the existing detectors already apply | Medium | `warn` |

Deliberate Tier A misses, stated so they are not later read as defects:

- A bare 16-digit Luhn-passing run with no IIN prefix, no separator, and no
  context is **not** a payment card. Order ids, tracking numbers, and internal
  account numbers live in exactly that shape, and the FP cost is unbounded.
- A payment card split across a line break is not detected.
- An RRN issued after October 2020 has randomized trailing digits and **cannot**
  be checksum-validated. Those are reachable only through the context gate, so
  a bare post-2020 RRN in unlabelled text is a known false negative. This is
  the single most important limitation in Tier A and it is stated in the user
  documentation, not only here.
- An email in a `{{template}}`, a `${interpolation}`, or a documented example
  domain (`example.com`, `example.org`, `.test`, `.invalid`) is excluded.

#### Tier B — deferred, evidence-gated, same epic

Not in beta.6. Each is admissible in principle and blocked on step 2's numbers:

- `us-social-security-number` — 9 digits with weak internal structure.
  Context-gated only. Needs its FP number on the negative corpus first.
- `phone-number-e164` — `+` plus country code plus E.164-bounded digits only.
  No national formats, ever, without a locale contract this product does not
  have.
- `ip-address` — the most-requested and the weakest: IPv4 is four dotted digit
  groups, which is also a version string, a semver, and a dotted id. Needs the
  reserved/documentation-range exclusions and a measured FP rate against real
  log corpora before it is worth shipping. IP addresses are also only
  conditionally personal data, which is a policy question this core must not
  answer.

### 9. Surfaces

| Surface | `full-pii` | How selected |
| --- | --- | --- |
| Rust | yes | `DetectorRegistry::with_full_pii_built_in` / the incremental counterpart; reachability does the rest |
| Node | yes | `@redact-secret/core/full-pii`, plus `*FullPii` addon exports; one compiled addon, as with `common` |
| Python | yes | `scan(..., profile="full-pii")`. The earlier "intentionally no `profile` argument" is amended: it was justified by "server-side use should run `full`", and `full-pii` ⊃ `full`, so the argument does not bar a *larger* profile. |
| CLI | yes | `--profile full-pii`. The earlier "intentionally no `--profile` flag" is amended on the same ground: it was justified by "a smaller profile would only weaken enforcement". The flag accepts only profiles that are supersets of `full`; `common` stays unreachable from the CLI. |
| Browser (WebAssembly) | **no** | Personal-data scanning is a server-side compliance boundary. A third `.wasm` costs install size to every `@redact-secret/wasm` consumer for a profile the browser should not be the authority for. Revisit only when an issue names a browser consumer, its byte budget, and why client-side is the right boundary for it. |

Because the CLI flag is opt-in, existing CLI exit-code behaviour is unchanged.
Under `--profile full-pii`, a `warn`-defaulted personal-data finding still
makes `check` exit `1`, since exit `1` means "something was found". A consumer
that wants PII reported but not CI-failing uses `--redact`, or a policy, or
parses the JSON report — this is called out in the CLI guide because it is the
most likely surprise.

## Versioning and compatibility

| Change | Class |
| --- | --- |
| Add the `class` field to findings | Minor, additive, on every surface and in the conformance schema |
| Add the `pii` pack and the `full-pii` profile | Minor: `full` and `common` are unaffected |
| Add a detector to `pii` | Minor: `full-pii` gains coverage |
| Move a detector between `pii` and a credential pack | Breaking: it changes a finding's `class`, its default action, and its placeholder namespace |
| Redefine `full` as credential-only | Documentation-breaking, behaviour-neutral. `full`'s membership and output do not change; the sentence describing it does. The changelog must call this out explicitly, because a reader who understood `full` as "everything" will be wrong about it afterwards. |

## Rejected alternatives

- **Put PII detectors in `full`.** Every existing consumer's output changes
  silently: new findings, renumbered ids, redactions in text they expect
  untouched. It also makes A4 unenforceable, because there would be no
  reference profile to compare against. Rejected outright.
- **One resolution domain, with PII ranked below every credential.** Ranking
  is not the problem; *disjointness* is. A PII candidate ranked last still
  consumes a range, and a later credential candidate overlapping it would be
  dropped by the greedy pass. Only a separate domain that yields to the
  accepted credential set gives the invariance guarantee.
- **A new `Specificity::PersonalData` variant.** It would put personal data on
  the same ladder as credentials, which is exactly what §4 must prevent, and
  it changes a frozen cross-language ordering that 42 detectors depend on.
- **A separate `@redact-secret/pii` package or crate.** A second scanner over
  the same text means two passes, two range sets, and an overlap problem
  neither side can see — the exact defect that makes the in-core design worth
  its governance cost. It also re-creates the "second authoritative detector
  implementation" the architecture forbids.
- **Model- or dictionary-backed PII (names, addresses, free text).** Not
  decidable, not deterministic, not side-effect free. Permanently excluded,
  and the amended exclusion says so by name.
- **Network validation** (BIN lookup, IBAN registry, carrier lookup). Violates
  the side-effect-free core.
- **Reversible tokenization / format-preserving encryption of PII.** A
  different product with key management. Placeholders stay non-recoverable.
- **Redacting `email_address` by default.** Tested against the primary use
  case — log and trace sanitization — and it destroys the artifact's value.
  `warn` plus a one-line consumer policy is strictly better.
- **Shipping Tier B in beta.6.** Its three grammars carry the FP risk that
  would define the feature's reputation, and none of them has a measured
  number yet. Step 2 exists to produce those numbers.

## Non-goals

- No named-entity recognition, no model invocation, no dictionaries of names.
- No locale auto-detection and no national phone or ID formats beyond those
  named in Tier A.
- No address, date-of-birth-in-free-text, health, or biometric classes.
- No re-identification or privacy risk scoring, no DSAR or consent tooling, no
  data-retention policy.
- No browser `full-pii` artifact in this cycle.
- No change to `full`, `common`, the canonical order, the `Specificity`
  ladder, or any existing default export.
- No release, version choice, or publication. That remains under `AGENTS.md`
  release authority.

## Consequences

The product gains a second risk class without giving up the property that
makes it usable at an enforcement boundary: `full` still means exactly what it
meant, and the invariance test proves it on every run. The cost is a third
pack, a fourth profile to qualify, a conformance schema change that every
binding must carry, a second overlap domain in the pipeline's hottest path,
and a permanent obligation to defend a set of grammars that are intrinsically
less self-identifying than anything in the registry today.

The expensive half of that cost is deferred behind step 2. If the measured
false-positive rates come back poor, the plan stops there having spent a
script and an evidence record, and the standing exclusion is simply left in
place.
