---
decision_id: decision-scope-supabase-legacy-anon-jwt-exclusion
status: accepted
scope: workspace
title: Scope a payload-trusting exclusion for the legacy Supabase anon JWT to iss+role together
decided_at: 2026-09-20
---

# Scope a payload-trusting exclusion for the legacy Supabase anon JWT to `iss`+`role` together

## Decision

`jwt.rs`'s structural detector (`crates/secret-scan-core/src/detectors/jwt.rs`)
gains one narrow, deliberate exception to its otherwise-structural-only
contract: a three-segment match is dropped when its payload segment
base64url-decodes to UTF-8 text containing both `"iss":"supabase"` and
`"role":"anon"` as literal substrings. Every other claim — `alg`, `exp`, an
absent or fabricated signature, `service_role` or any other `role` value, or
a payload that fails to decode at all — is still ignored, exactly as before.

The check is substring containment on the decoded payload text, not a JSON
parse: this crate's core has zero non-dev dependencies
(`crates/secret-scan-core/Cargo.toml`), so no JSON parser is available, and
adding one for a single narrow carve-out was rejected as disproportionate.
Base64url decode/encode are hand-rolled the same way
[`super::discord::decodes_to_ascii_digits`] already decodes a JWT-shaped
first segment to distinguish it from a Discord bot token.

## Rationale

Issue #472: Supabase's legacy JWT-format keys are structurally
indistinguishable JWTs that differ only in their `role` claim. The `anon` key
is a public identifier by Supabase's own design — it ships in browser
bundles and `NEXT_PUBLIC_*` variables in every Supabase quick-start — while
`service_role` is a genuine elevated-access secret. Both were previously
classified identically by the purely structural `jwt` detector at
`high`/`redact`, so the default policy rewrote working, intentionally public
configuration. This is exactly the treatment `additional_providers.rs`
already gives the *new*-format pair: `SUPABASE`'s `sb_secret_` shape excludes
`sb_publishable_` as "a public identifier, not a secret;" this decision
extends that same distinction to the legacy JWT format, which the new
format's own rollout has not yet displaced — the large majority of existing
Supabase projects still carry JWT-format keys.

The new-format exclusion is safe because the *prefix itself* is the
provider's public-key namespace — no secret can carry it. A JWT has no such
namespace; `role` is a claim inside an unverified, unsigned-at-detection-time
payload, so this carve-out is judged riskier and is scoped as narrowly as
the issue itself argues for:

- **Both claims, not either alone.** `"role":"anon"` under a non-Supabase
  `iss`, or `"iss":"supabase"` under a non-`anon` role (including
  `service_role`), still fall through to detection. Requiring both closes
  off the two cheapest ways to game a single-claim check.
- **Substring containment, not the whole payload's shape.** The check does
  not require the two claims to be the only claims, adjacent, or in a fixed
  order — real Supabase payloads carry `ref`, `iat`, and `exp` alongside
  them — but it also does not attempt to parse or validate the surrounding
  JSON. A decode failure (invalid base64 remainder, or bytes that are not
  valid UTF-8) is treated as "claim not present," never as "assume public":
  the structural match stands unless both claims are affirmatively read.
- **Decode failure keeps the detector's own contract, not silence.** The
  existing test `structural_match_ignores_decoded_claims_semantics` (an
  `alg:none`, already-expired, unsigned token) still matches: decoding only
  ever *removes* a finding, and only under this one exact condition. Every
  other decoded-claims question this detector was already documented not to
  evaluate stays unevaluated.

Downgrading to `warn` instead of a full exclusion (the alternative the issue
itself raised) was rejected: the anon key is not merely lower-risk, it is
*intended* to be public and committed, the same reasoning that already
justifies a full exclusion (not a downgrade) for `sb_publishable_` and
Stripe's `pk_live_`/`pk_test_`. A `warn` finding on every `NEXT_PUBLIC_*`
Supabase config is exactly the repeatedly-dismissed noise `AGENTS.md`'s
false-positive/false-negative tradeoff framing warns against.

## Consequences

- **Accepted false-negative risk, stated plainly.** The detector cannot
  verify a JWT's signature. A crafted token whose payload claims
  `"iss":"supabase"` and `"role":"anon"` — but whose signature segment
  actually carries exfiltrated high-entropy material — passes this
  exclusion. This is judged an acceptable, narrow residual: the realistic
  exfiltration channel (the signature segment) is not what any other
  provider's high-confidence findings in this codebase authenticate either,
  and the alternative (declining to fix #472 at all) leaves every ordinary
  Supabase `NEXT_PUBLIC_SUPABASE_ANON_KEY` misclassified as a redact-worthy
  secret today.
- `jwt.rs` gains `JwtMatch` (carrying the payload segment's byte range),
  `base64_url_sextet`, `base64_url_decode`, and
  `is_supabase_legacy_anon_claim`. `match_jwt_at` returns the new struct
  instead of a bare end offset.
- Unit tests in `jwt.rs` cover: the anon claim excluded regardless of field
  order; `service_role` still reported; `"role":"anon"` under a non-Supabase
  `iss` still reported; a Supabase `iss` without an anon role still
  reported; a payload with a non-decodable base64 remainder still reported;
  a payload that decodes to invalid UTF-8 still reported.
- `conformance/fixtures/synchronous-corpus.json` carries all four cells of
  the new-format/legacy-format × public/secret matrix for the legacy half
  (`jwt-negative-legacy-supabase-anon-claim`,
  `jwt-positive-legacy-supabase-service-role-claim`,
  `jwt-positive-anon-role-non-supabase-issuer`,
  `jwt-positive-malformed-payload-remainder`); the new-format half was
  already covered by the existing `supabase-*` fixtures.
  `conformance/fixtures/incremental-corpus.json` carries the anon/
  service_role pair on adjacent lines so every chunk-partitioning proof
  covers the discriminating boundary, the same shape issue #316 established
  for the new-format prefix pair.
- Every surface loads this same Rust core
  (`ARCHITECTURE.md`'s runtime-surfaces table), so no binding-specific
  change was needed; `every_fixture_reproduces_the_canonical_whole_input_reference`
  in `crates/secret-scan-core/tests/incremental_partitions.rs` asserts the
  new fixtures agree between whole-input and incremental scanning at every
  partition boundary.
