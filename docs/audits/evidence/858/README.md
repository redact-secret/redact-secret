# Issue #858 — Vercel modern credential taxonomy and bounded contract

[Audit archive](../../README.md) ·
[Detector-family specification](../../../specs/detector-families.md) ·
[Live precision contracts](../../../contracts/precision/precision-contracts.json) ·
[Issue #858](https://github.com/redact-secret/redact-secret/issues/858) ·
[Prior audit #516](../516/README.md) ·
[Benchmark handoff #373](https://github.com/redact-secret/redact-secret-benchmarks/issues/373)

Reviewed 2026-09-26 against product revision
`266204c87126a9de2c0ff28e7913bccabebd1d98`. This is a product-contract
decision, not a detector change. It adds no positive fixture, support claim,
or qualification status.

## Decision

Vercel's 2026 announcement names five independently meaningful modern
credential classes. They are separate benchmark families even though the
current runtime reports all five through the compatibility finding type
`vercel_token` and detector id `vercel-token`:

| Contract family | Credential class | Evidence-backed literal marker | Overall disposition |
| --- | --- | --- | --- |
| `vercel:personal-access-token` | personal access token | `vcp_` | pending, T0 |
| `vercel:integration-token` | integration token | only `vci`; `_` is unresolved | pending, T0 |
| `vercel:app-access-token` | app access token | `vca_` | pending, T0 |
| `vercel:app-refresh-token` | app refresh token | `vcr_` | pending, T0 |
| `vercel:api-key` | API key | `vck_` | pending, T0 |

The prefixes identify the credential classes; they do not establish a body
grammar. No provider-controlled source reviewed here states a body length,
alphabet, checksum, or complete boundary rule for any of the five. A prefix
announcement therefore does not establish a safe positive fixture or a T1
detector contract.

The semantic taxonomy is split now so evidence and debt cannot move between
classes. The runtime finding type is not split in this change because no class
has a complete positive contract to implement. A later behavior change must
enter through the benchmark finding-promotion lifecycle and decide public
finding-type compatibility separately.

## Provider evidence and its bounds

### Five-prefix announcement

Vercel's changelog, published 2026-02-09, says each credential type now has a
prefix and maps `vcp`, `vci`, `vca`, `vcr`, and `vck` to personal access,
integration, app access, app refresh, and API-key credentials respectively.
It establishes the five class meanings and those three-letter prefix stems.
It does not print an underscore after those stems and states no body grammar.

### Literal underscores

- `vcp_` is provider-documented in the current Access tokens guide, which
  says personal access tokens begin with that literal prefix. The guide's
  masked filler is not a generated value and establishes no width or alphabet.
- `vca_` and `vcr_` appear in the provider's Sign in with Vercel token
  examples. The page calls both formats opaque and reuses one example body,
  so it establishes the literal markers and class roles, not a general body
  grammar or two independent body observations.
- `vck_` is used by Vercel's public CLI source when masking and labeling an AI
  Gateway API key. This provider-controlled code establishes the literal
  marker only.
- No provider-controlled documentation or code found by this review prints a
  `vci_` value. The changelog establishes only the `vci` stem and the
  integration-token meaning. The current detector's underscore is therefore
  an implementation hypothesis, not a frozen contract property.

Single examples and synthetic provider tests are useful for confirming a
literal marker. They are not independent evidence for a universal body
alphabet, minimum, maximum, exact width, or checksum.

## The unprefixed REST example is unresolved

The current Create an Auth Token reference returns two fields in one example:

- `bearerToken`, rendered as an unprefixed 24-character value; and
- `token.prefix`, rendered as `vcp_`.

The endpoint creates a personal authentication token, while the current
Access tokens guide says personal access tokens begin with `vcp_`. Those
provider-controlled statements do not reveal whether the rendered bearer
value is legacy issuance, stale schema example data, a redacted/generated
placeholder, or a current unprefixed class. The metadata field might describe
the actual value, but the reference does not state that relationship.

Accordingly, this review does not use the example to claim an unprefixed
24-character modern personal-token grammar, and it does not claim that all
current personal tokens are prefixed. The example is an explicit unresolved
provider contradiction outside the modern positive contract.

The separate OAuth integration code-exchange documentation also contains
unprefixed example credentials. Example-only opaque values cannot be safely
distinguished from ordinary identifiers. They remain unsupported by a
dedicated Vercel detector; contextual detection may report them under a
generic family when independent context is strong enough. This is not a
claim that the values are legacy, current, or one universal 24-character
Vercel class.

## Existing implementation versus reviewed contract

The current `vercel-token` detector accepts each of `vcp_`, `vci_`, `vca_`,
`vcr_`, and `vck_` followed by at least 20 alphanumeric, underscore, or dash
characters. That suffix rule is not supported by the provider evidence above.
It remains unchanged here so a contract audit does not silently introduce a
behavior change or bypass benchmark promotion. Its matches must not be treated
as provider-documented positives, and the implementation does not establish
the contract it attempts to recognize.

This corrects #516 in three places:

1. #516 inferred a complete `vci_` literal from a changelog that prints only
   `vci`.
2. #516 described the existing 20-character floor as conservative and
   false-negative-safe. A minimum can create false negatives for shorter
   issued values, while the broad alphabet and open upper bound can create
   false positives; neither direction is proven without an issuance grammar.
3. #516 resolved unprefixed examples as a distinct, current 24-character
   surface. The Create an Auth Token example's simultaneous unprefixed bearer
   value and `vcp_` metadata, plus the current Access tokens prose, leaves that
   conclusion undecidable.

## Exact spans, contexts, and collisions

No exact redaction span is frozen because no complete positive lexical
contract exists. If a future source establishes a full grammar, the expected
span is the complete credential value, including its class marker and every
validated body/checksum byte, but excluding surrounding quotes, assignment
syntax, Bearer syntax, punctuation, and whitespace.

No bare or contextual positive is approved by this record. In particular:

- ordinary values that merely start with one of the five stems are not
  provider-confirmed credentials;
- Vercel deployment, project, team, integration, and client identifiers are
  sibling/public identifiers, not automatically benign twins for every
  credential class; and
- an unprefixed 24-character identifier is not a globally valid negative or
  positive solely because a Vercel API example has that width.

## Benchmark handoff for #373

Benchmark evidence must keep five independent T0 families. Do not transfer the
old aggregate five-cell debt to a single replacement row, and do not create a
must-redact fixture from a prefix plus an invented suffix.

Safe work is limited to recording the blocked cells and adding controls that
do not assert issuance. A positive cell for one class unblocks only when a
provider-controlled source or reviewed promoted finding establishes enough of
that class's literal marker, body grammar, and boundaries to build a
deterministic synthetic value. `vci_` additionally needs provider-controlled
evidence that the underscore is part of the value. Opaque/unprefixed values
need either a provider-stated lexical contract or a separately reviewed,
context-bounded generic contract; example width alone is insufficient.

## Outcome

- Five modern semantic families: split and recorded separately.
- Five modern positive lexical contracts: pending, T0.
- Opaque legacy/unprefixed values: unsupported by a dedicated Vercel rule;
  issuance status unresolved.
- Runtime behavior and public finding types: unchanged.
- Support matrix and qualification status: unchanged; benchmark evidence, not
  this record, owns any future movement.
