# Addendum to #1225: the HubSpot personal access key under a prefix

**Result:** [#1233](../1233/README.md) applied the #1225 vocabulary admission rule to
the HubSpot CLI field and matched `personalAccessKey` and `HUBSPOT_PERSONAL_ACCESS_KEY`
only as whole names, listing `my_personal_access_key` and `oldPersonalAccessKey` as
not matched. The independent Batch 2 closeout showed the consequence: `MY_HUBSPOT_PERSONAL_ACCESS_KEY`
and `my_personal_access_key`, the same field under a user's own prefix, were silent
while `HUBSPOT_PERSONAL_ACCESS_KEY` was a high `redact`, so a real key in a prefixed
variable stayed in the output. The name `personal_access_key` now also qualifies behind
a generic prefix, exactly as `api_key`, `password` and `secret` do (`MYAPP_API_KEY`).
This amends the "whole name, never a prefix or suffix rule" clause of the #1225
admission rule for this one name, a policy deviation recorded here and in the spec row.

## Root cause

`EXACT_HIGH_SIGNAL_NAMES` in `crates/secret-scan-core/src/detectors/generic_token.rs`
matches only the normalized name itself; the prefixed-name rule
(`has_prefixed_credential_name`) read only `HIGH_SIGNAL_NAMES`. The #1233 tests pinned the
prefixed forms as clean.

## The change

`PREFIXED_EXACT_HIGH_SIGNAL_NAMES = ["personal_access_key"]` goes through the same
prefixed-name rule: a non-empty prefix, and a prefix whose first segment says the value is
not the secret (`masked_`, `redacted_`, `publishable_`, ...) still excludes it. The suffix is the
whole name, so the neighbours do not match.

## Boundary and tradeoffs

| Name | Result |
| --- | --- |
| `MY_HUBSPOT_PERSONAL_ACCESS_KEY`, `my_personal_access_key`, `MY_PERSONAL_ACCESS_KEY`, `oldPersonalAccessKey`, `hubspotProdPersonalAccessKey`, `prod_personal_access_key` | high, redact, exactly the value (every layout of #1233) |
| `personalAccessKey`, `HUBSPOT_PERSONAL_ACCESS_KEY` | unchanged |
| `personalAccessKeyId`, `personalAccessKeyExpiresAt`, `personalAccessKeyHint`, `personalAccessKeyLength`, `my_personal_access_key_id`, `MY_HUBSPOT_PERSONAL_ACCESS_KEY_ID`, `..._EXPIRES_AT`, `HUBSPOT_PERSONAL_ACCESS_KEY_ID` | silent (do not end in the name) |
| `my_personal_key`, `my_access_key_name`, `hubspot_key`, `accessKey`, `personalKey`, `portalId`, `authType` | silent |
| `publishable_`, `masked_` or `redacted_` prefix | silent |
| placeholders, references, masks, empty and under-8-byte values under a prefixed name | silent |
| a low-entropy value under a prefixed name | medium, warn |

* FN removed: a real key in a user-prefixed variable or field, including an old key
  that may still be live (`oldPersonalAccessKey`).
* FP added: a non-secret literal of 8 or more bytes under a name that ends in
  `personal_access_key` (any provider's, since the suffix is the field name and not a
  HubSpot claim); a user lowers the action with the user action configuration.
* Not changed: no HubSpot attribution, no width or alphabet claim, no other name admitted.
  The evidence's own benign neighbours (`-Id`, `-ExpiresAt`, `-Hint`, `-Length`,
  `portalId`, `authType`) stay silent.

## Tests

`crates/secret-scan-core/tests/hubspot_prefixed_personal_access_key_1225.rs` (5 tests): nine
names across five layouts, fifteen neighbours, the not-the-secret prefixes, placeholders and
masks under a prefix, the medium-confidence warn; whole input, 7-byte and 1-byte chunks equal to
whole. The two #1233 clean cases for `my_personal_access_key` and `oldPersonalAccessKey` in
`tests/batch2_gaps_1232_1234.rs` are removed, replaced by this file.
