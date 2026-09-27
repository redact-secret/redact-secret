# Issue #864: Amazon Bedrock long-term and short-term API key contracts

[Audit archive](../../README.md) ·
[Issue #864](https://github.com/redact-secret/redact-secret/issues/864) ·
[Spec: detector families](../../../specs/detector-families.md)

Frozen final record, written 2026-09-27. The iterative research stays in the
two issue comments linked below; nothing here restates their logs. This
record holds synthetic values only: no real, real-derived or provider-blog
example key appears in the repository.

## Verdict

Two families, one module (`detectors::aws_bedrock`):

| detector | type | grammar | tier |
| --- | --- | --- | --- |
| `aws-bedrock-long-term-api-key` | `aws_bedrock_long_term_api_key` | `ABSK`, 109 to 269 standard-Base64 bytes, up to two `=` | prefix and alphabet: T1; band: T2 |
| `aws-bedrock-short-term-api-key` | `aws_bedrock_short_term_api_key` | `bedrock-api-key-`, the exact 133-byte Base64 head, at least 64 more standard-Base64 bytes, up to two `=` | prefix, head and alphabet: T1; tail floor: T2 |

Both are provider pack, always redacted, high confidence, provider
specificity.

## Maintainer ruling (T1, 2026-09-27)

The maintainer accepted T1 for both families on 2026-09-27, recorded on
#778 and #779. A scan pattern is not itself a format specification, so each
ruling is scoped narrowly:

- **`aws-bedrock-long-term-api-key`:** T1 for the `ABSK` prefix and the
  standard-Base64 alphabet with `={0,2}` padding, on the AWS Security Blog,
  "Securing Amazon Bedrock API keys" (2025-10-17), which prints a `Pattern:`
  for the type — accepted as provider evidence for the prefix and alphabet
  only, not a format specification. Total length (132, or 136 for a `+1`
  secondary key) and IAM user-name variants other than `BedrockAPIKey-` stay
  T2/unspecified.
- **`aws-bedrock-short-term-api-key`:** T1 for the `bedrock-api-key-`
  prefix, the fixed 133-character Base64 head, and the standard
  padded-Base64 alphabet, on the AWS-authored token generators
  (`aws-bedrock-token-generator-python`'s `token_generator.py`:
  `AUTH_PREFIX = "bedrock-api-key-"`, `TOKEN_VERSION = "&Version=1"`, Base64
  of a SigV4-presigned `https://bedrock.amazonaws.com/?Action=CallWithBearerToken`
  URL; the JS `src/token.ts` and Java `BedrockTokenGenerator.java`
  generators), plus the AWS Security Blog pattern (whose printed body class
  is malformed; the intended class is `[A-Za-z0-9+/]`). Total length (not
  documented; "over 1000 characters" is vendor-blog only) and the
  session-token part of the body stay T2/unspecified.

The IAM `ServiceSpecificCredential` reference (public alias versus secret
split, long-term) remains supporting context, not part of the T1 scope.
The benchmarks counterpart
([redact-secret-benchmarks#384](https://github.com/redact-secret/redact-secret-benchmarks/issues/384))
owns fixtures and the qualification run, and moves its `providerSource` from
"T1 candidate" to T1 through its own reviewed change, not a hand edit.

## Research

- Long-term key research (#778):
  [comment](https://github.com/redact-secret/redact-secret/issues/778#issuecomment-5852332628).
- Short-term key research (#779):
  [comment](https://github.com/redact-secret/redact-secret/issues/779#issuecomment-5852343524).

## One family or two

Two. They share the `AWS_BEARER_TOKEN_BEDROCK` variable and the
`Authorization: Bearer` header, so the prefix decides the family, and a test
pins that neither detector claims the other's shape. They differ in what the
contract can say:

- a long-term key is issued by AWS, appears in `CloudTrail`, and has no
  documented length;
- a short-term key is minted client-side, lives at most 12 hours, is a
  Base64 URL with a fixed head, and has no upper length bound (a session
  token lengthens it).

Separate types also let a user's policy and the benchmarks support matrix
treat them apart, as the matrix already does for other AWS families.

## Grammar decisions and their evidence

- **Malformed blog class.** The blog prints the short-term body class as
  `[A-Za-Z0-9\\]`, an invalid range. Every generator uses standard padded
  Base64, so the intended class `[A-Za-z0-9+/]` is used. No source documents
  a URL-safe variant, so `-` and `_` are rejected, not accepted.
- **Fixed head.** The 99 bytes
  `bedrock.amazonaws.com/?Action=CallWithBearerToken&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential`
  encode to 132 stable characters; the 133rd is fixed by the following `=`.
  A unit test re-derives the head with an independent encoder.
- **Long-term head not required.** The blog pattern fixes
  `QmVkcm9ja0FQSUtleS` (`BedrockAPIKey`), which fits only a key whose IAM
  user has that name. The grammar accepts any `ABSK` + Base64 body and
  records the head only as a signal.
- **Long-term band.** 109 to 269 is the tolerance two AWS-adjacent and
  community scanners use; one vendor measures 132 total. A key outside the
  band is missed, not truncated. This is T2.
- **Short-term tail floor.** 64 bytes, deliberately below any token the
  generator constructs (about 496 total with an empty session token), so it
  excludes only the constant head. T2. No cap.
- **Boundaries.** The byte before must not be `[A-Za-z0-9+/_-]`; `=` is
  allowed so `AWS_BEARER_TOKEN_BEDROCK=ABSK…` matches. The byte after the
  padding must not be `[A-Za-z0-9+/=_-]`. Padding is part of the span.
- **No collision with `aws_access_key_id`.** `AKIA`/`ASIA` ids are plain
  text with their own 20-byte shape; neither Bedrock detector matches one,
  and the AWS detector does not match a Bedrock key. The `ASIA` id embedded
  in a short-term key is Base64-wrapped, so the encoded form has no overlap.

## Coverage before this change

Probes from the two research comments show that the bare token, the
documented `AWS_BEARER_TOKEN_BEDROCK` assignment (dotenv, `export`, YAML,
Python `os.environ`) and a JSON value under a non-secret name produced no
finding, while `Authorization: Bearer` was already covered by
`bearer-token` and generic key names by `generic-token`. The value of a
dedicated type is the bare and environment misses and a provider-specific
finding for the labelled forms; overlap resolution prefers the
provider-specificity candidate.

## Fixtures and tests

The Rust unit and integration tests build every key at runtime (prefix plus
generated Base64 filler), so no realistic key literal lives in test code.
The 40 `aws-bedrock-*` fixtures in
`conformance/fixtures/synchronous-corpus.json` (the coverage gate requires
them) hold literal values, which are deliberately low entropy: a repeated
Base64 encoding of the word "SyntheticRevoked" after the prefix (and, for
the short-term key, after the fixed public head). Their expectations were
written by hand from the grammar, not copied from detector output. Per
family: 8 positives (bare, dotenv, quoted `export`, YAML, JSON, SDK call,
tool call, padding), an overlap with `bearer-token`, negatives (env
reference, empty assignment, public alias and ARN; a placeholder for the
long-term key, prefix-only and head-only for the short-term key), boundary
twins, and one dense adversarial line. The unit tests in
`crates/secret-scan-core/src/detectors/aws_bedrock.rs` cover:

- positives with exact spans: bare, `AWS_BEARER_TOKEN_BEDROCK=`, `export`,
  quoted, YAML, JSON, `Authorization: Bearer`, curl, Python environment
  assignment, SDK-call argument, agent tool-call JSON, a code fence, and
  trailing punctuation;
- twins, one property changed each: body below and above the band, `-` and
  `_` in the body, mid-body `=`, three `=`, `ABSX` and `absk`, a Base64
  neighbour before and after, a truncated head at 1, 28, 100 and 132
  characters, a one-character-off head, a wrong short-term prefix and case,
  the head with no tail;
- benign values: `ABSK...`, `ABSK<your-key>`, an empty and a `${VAR}`
  assignment, the decoded public alias, an IAM ARN, `AKIA…`;
- cross-shape isolation and an adversarial repetition line;
- `crates/secret-scan-core/tests/aws_bedrock_keys.rs`: the full default
  registry, every context above with exactly one finding at the exact span
  (a `Bearer` header resolves to the Bedrock detector), twins, an `AKIA` id
  beside a Bedrock key, and every two-chunk incremental partition equal to
  the whole-input result;
- registry reconciliation through `built_in_inventory_matches_the_declared_baseline`
  and the provider-candidate table in `detectors::mod`.

The reconciliation trigger in `docs/coverage/detector-inventory.json` uses the
same low-entropy repeated encoding, not a random body. Generated files
(`docs/coverage/*`, `common-profile-expectations.json`, the corpus
`fixtureCount`) are regenerated by their scripts, not merged by hand, when
sibling detector changes land.

## False-positive and false-negative trade-off

- **False negatives.** A long-term key outside the band; a short-term key
  whose head changes (query-parameter order or a `Version` bump); a key with
  a glued neighbour such as `ABSK…_suffix`.
- **False positives.** A long Base64 blob that starts with `ABSK` by chance.
  Placeholders are too short or hold non-Base64 bytes.
- **Cost.** A first-byte scan, a leading-boundary check before any run
  scan, then one forward pass over a candidate's Base64 run. Linear in the
  input, no per-line state, so incremental and WASM scanning pay the same
  cost as the other prefixed families. The adversarial repetition test
  covers `ABSK` and the short-term prefix repeated end to end.

## Not done here

- No support-matrix or benchmarks pin change; the benchmarks counterpart
  supplies the contract and corpus.
- The benchmarks counterpart still authors its own independent fixtures
  and contract; the corpus entries above satisfy this repository's coverage
  gate only.
- No version, changelog release entry, tag or release.
