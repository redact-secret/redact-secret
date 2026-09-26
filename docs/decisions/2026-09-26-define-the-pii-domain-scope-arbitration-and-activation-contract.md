---
decision_id: decision-define-the-pii-domain-scope-arbitration-and-activation-contract
status: accepted
scope: workspace
title: Define the PII domain, scope, arbitration, and activation contract
decided_at: 2026-09-26
spec: engine
---

# Define the PII domain, scope, arbitration, and activation contract

## Context

Beta.10 must add structured PII without creating a second overlap engine. Issues
[#578](https://github.com/redact-secret/redact-secret/issues/578),
[#791](https://github.com/redact-secret/redact-secret/issues/791), and
[#794](https://github.com/redact-secret/redact-secret/issues/794) require a
domain model, explicit jurisdiction scope, and cross-surface activation
contract before any PII detector ships.

## Decision

### Identity, sensitivity, and policy are separate

`pii-v1` interprets shared evidence through two internal results:

```text
identity:    unmatched | established | ambiguous
sensitivity: not-established | sensitive | non-sensitive
```

Identity answers what the value is; sensitivity answers whether this occurrence
is sensitive. A valid value with unestablished sensitivity is separately
accounted, not a miss or ordinary false positive. Only `sensitive` outcomes
enter public overlap and policy; the other states produce no finding.

Each family declares `contextRequirement` with exact semantics:

- `none`: the family predicate establishes sensitivity without positive
  context; positive context changes neither sensitivity state nor confidence;
- `reinforcing`: the family predicate can establish sensitivity, while
  positive context may raise sensitivity confidence but is not required; or
- `required-for-sensitive-classification`: structure establishes identity,
  but sensitivity stays `not-established` until reviewed positive context is
  associated with the candidate.

Context never establishes identity. Randomness may be recorded diagnostically
but supplies no positive PII authority. Evidence details, scores, weights, and
identity alternatives remain internal. This contract adds no probability or
evidence-detail API.

Negative evidence changes sensitivity to `non-sensitive` only when the whole
candidate matches a named reserved/test grammar, or when an associated
high-signal negative vocabulary entry is named by that family's reviewed
occurrence-exclusion contract. Association uses the bounded context contract.
An ambiguous term, substring, fuzzy resemblance, or unlisted negative entry
has no negative effect. Authoritative negative evidence is applied after
positive evidence and wins that occurrence; it never changes identity.

Policy receives exactly one safe finding for a surviving sensitive occurrence,
never one finding per possible jurisdiction. Registry family ids are internal
colon-form identifiers and are not public `Finding.type` values. The public
type algorithm preserves the existing identifier grammar unchanged:

- `pii:global:<slug>` becomes `pii_global_<slug>`;
- `pii:<cc>:<slug>` becomes `pii_jurisdiction_<cc>_<slug>`; and
- ambiguous identity becomes `pii_ambiguous_<identity-domain>`.

Hyphens become underscores. The `global`, `jurisdiction`, and `ambiguous`
namespaces keep the mapping injective. Admission fails above 64 bytes or when
existing `is_identifier` rejects it; the core grammar is unchanged. Stable
examples are `pii_global_email`, `pii_jurisdiction_us_ssn`, and
`pii_ambiguous_national_id`. Conformance must distinguish
`pii:global:us-ssn` from `pii:us:ssn`, and `pii:global:ambiguous-national-id`
from an ambiguous national-ID outcome. The detector id is `pii-domain`;
alternative family ids remain internal.

### Scope and family identity

Scope is either `global` or `jurisdiction:<CC>`, where `<CC>` is uppercase ISO
3166-1 alpha-2. Canonical family ids are `pii:global:<slug>` or
`pii:<cc>:<slug>` with lowercase ASCII slugs. Display names are independent
metadata. Each family also declares an `identityDomain`, initially one of
`email`, `payment-card`, `network-address`, `iban`, `phone`, or `national-id`.

No geolocation, translation, network lookup, context language, caller locale,
or unrelated input supplies jurisdiction. Unsupported jurisdictions never
fall through to another family.

### Cross-jurisdiction arbitration before ordinary overlap

PII detectors first emit validated internal identity candidates. Before those
candidates enter the existing ranked-candidate list, the PII domain adapter:

1. discards alternatives rejected by family-specific identity evidence;
2. groups the survivors by exact original-input byte range and
   `identityDomain`;
3. sorts and deduplicates family ids in each group; and
4. emits one internal PII candidate: `established` for one family or
   `ambiguous` for more than one.

Different ranges or identity domains are not grouped. The one aggregate then
enters the ordinary resolved-action, specificity, confidence, span-width,
detector-order, and emission-order overlap pipeline. Existing pairwise-disjoint
selection remains authoritative. Multiple overlapping jurisdiction findings
do not survive merely to express ambiguity, and registration order cannot
turn an ambiguous same-range identity into a unique one.

Each surviving alternative evaluates sensitivity under its own family
contract. The aggregate is `sensitive` if any alternative is sensitive,
`non-sensitive` only if all alternatives are non-sensitive, and
`not-established` otherwise. This conservative join can report an ambiguous
collision when one supported interpretation is sensitive without making a
family-specific public claim.

### Aggregate metadata and ordinary overlap

Every family alternative records separate identity and sensitivity
`Confidence`. A sensitive aggregate's public `Confidence` is the lower of
(a) the lowest identity confidence across every remaining alternative and
(b) the lowest sensitivity confidence among its sensitive alternatives. Thus
ambiguity never increases confidence.

PII identity evidence has `Specificity::Structural`. Sensitivity evidence has
`Specificity::Structural` when the occurrence is sensitive without context and
`Specificity::Contextual` when context is required to establish it. The
aggregate uses the lower specificity across identity and every sensitive
alternative; it never claims `Provider` or `PrivateKey`. Obfuscation is
`InvisibleCharacters` if any alternative reports it or the normalized range
contains a governed removed code point, otherwise `None`.

The PII domain adapter occupies one fixed detector-order slot after the
credential profile. Its internal family registry is sorted by family id, but
family order never becomes aggregate detector order. It sorts aggregate
emission by `(range.start, range.end, identityDomain, publicType)`; that index
is the candidate-order key. The range is the group's exact shared original
range and detector id is `pii-domain`.

The existing `default_action_for(publicType, confidence)` supplies both
resolved-action severity and the default policy input. No PII type is added to
`ALWAYS_REDACT_TYPES` by this decision: `High` redacts and `Medium` or `Low`
warns. Obfuscation and internal alternatives do not affect default action.
Changing those actions requires a separate policy decision. Partial masking,
last-four preservation, typed placeholders, and restoration remain separate.

Evaluation scores identity and sensitivity separately. An ambiguous result is
an identity success only for a corpus row authored as a genuine collision
whose expected family set equals the internal alternative set. Against a row
with one expected family it is `unresolved-identity`, not a true positive and
not an ordinary negative-corpus false positive. Sensitivity is scored from its
own expected state regardless of that identity result. Public-policy tests see
the single safe ambiguous finding only when sensitivity is `sensitive`.

### Selector grammar and closure

PII is off when the selector list is absent or empty. Input selectors use
ASCII lowercase and exactly one of these forms:

```text
pii                              # alias of pii:global
pii:global                       # every available global family
pii:<cc>                         # global families plus every available family for cc
pii:family:global:<slug>         # exactly one global family
pii:family:<cc>:<slug>           # exactly one jurisdictional family
```

`<cc>` is a lowercase ISO 3166-1 alpha-2 code and `<slug>` matches
`[a-z0-9]+(?:-[a-z0-9]+)*`. `pii:national-id` is reporting-only and is rejected
as a selector. `off` is represented only by an empty list and cannot be mixed
with selectors.

Canonicalization expands `pii` to `pii:global`, removes duplicates, and sorts
selectors bytewise. Closure is then computed against the loaded artifact's
support registry. `pii:<cc>` always includes the `pii:global` closure;
family selectors remain exact and do not gain unrelated global families.
Multiple selectors form a set union. Closure is sorted by canonical family id.
An unknown syntax or unsupported jurisdiction fails; a syntactically valid
family or jurisdiction known to the registry but absent from the loaded
artifact fails as unavailable. Nothing is silently ignored.

The canonical activation identity is:

```text
credentials=<full|common>;
selectors=<off|comma-separated canonical selectors>;
families=<comma-separated closed family ids>;
vocabulary=<context-contract version>
```

Existing `profile()` values continue to mean only `full` or `common`.
Activation identity is a separate observable value.

### Registry composition and target surface mappings

Before any PII detector ships, the implementation must satisfy this target:

- build the existing `full` or `common` credential registry unchanged;
- resolve PII closure against the artifact's declared family availability;
- append one `pii-domain` adapter after credential detectors, with its internal
  family registry in canonical family-id order; and
- aggregate same-range/domain PII identities before ordinary overlap as above.

Per-family detector behavior is invariant across selector sets. `full` remains
the authoritative server credential profile; `common` is still preventive.
PII selection is orthogonal and has identical family semantics in both.

The exact future public mappings are:

- **Rust:** `PiiSelection::parse(&[&str])`,
  `DetectorRegistry::with_built_in_and_pii(&PiiSelection)`,
  `DetectorRegistry::with_common_built_in_and_pii(&PiiSelection)`, and
  `DetectorRegistry::activation_identity()`;
- **JavaScript:** `initialize({ pii: string[] })` on the root or `./common`
  entry point, and `piiActivation()` returning the canonical identity;
- **Python:** `initialize(pii: Sequence[str] = ())` before PII-enabled scans,
  and `pii_activation()`; credential-only use keeps its current direct
  import-and-scan path when `initialize` is not called; and
- **CLI:** repeatable `--pii <selector>` and
  `--print-pii-activation`, which prints the canonical identity and exits
  without reading input.

Incremental sessions capture the initialized selection at construction and
cannot change it. Calling either binding's initializer again with a different
canonical selection fails. These APIs are target contracts, not claims about
the current beta.9 surface.

Every surface maps failures to the same input-free codes and messages:

| Code | Message |
| --- | --- |
| `PII_SELECTOR_INVALID` | `PII selector is invalid.` |
| `PII_SELECTOR_UNSUPPORTED` | `PII jurisdiction or family is unsupported.` |
| `PII_SELECTOR_UNAVAILABLE` | `PII selection is unavailable in this artifact.` |
| `PII_ACTIVATION_CONFLICT` | `PII activation is already initialized differently.` |

No message, cause, or diagnostic repeats selector input.

## Consequences

The contract composes with the existing registry and overlap algorithm. A new
family may widen `pii:global`, but changes the observable activation identity.
The target APIs and PII detectors remain unimplemented.
