# #860 issuance research: `convex:deployment-key` (cloud `eyJ2` body)

[Issuance research index](README.md) ·
[Handoff](../convex.md) ·
[Rulings R9–R10](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5880547337)

Frozen 2026-09-28. Desk research only: no key was issued, and no issued or
leaked credential is evidence. The hex-body keys are already READY and
implemented ([#912](https://github.com/redact-secret/redact-secret/issues/912));
this covers only the gated cloud body.

**Gated property:** the alphabet (standard or URL-safe Base64, padding) and
length of the cloud deploy-key body after `<type>:<name-or-slugs>|`, and
whether scope changes the length.

**Research verdict: NARROWED.** The body *structure* is now T1: it is the
Base64 encoding of an externally tagged JSON object whose tag is `v2`. The
length and exact Base64 flavour are still not T1 (the issuer is closed
source). **Maintainer disposition (2026-09-28): still gated;** the lead is
derived from code, not stated, and the length is unknown.

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [get-convex/convex-backend `npm-packages/convex/src/cli/lib/envvars.ts` L402-L411 @ 309e941](https://github.com/get-convex/convex-backend/blob/309e941f7d9ceea64da09c84f3564b53b5f88ec8/npm-packages/convex/src/cli/lib/envvars.ts#L402-L411) | shipped in convex 1.25.1 (CHANGELOG); HEAD 2026-09-28 | provider CLI code (executing) | R1/R6 executing check = T1 | `JSON.parse(Buffer.from(key + "=", "base64").toString("utf8"))` then `if (!("v2" in decoded)) continue;`: "Only parseable v2 tokens to be sure this is a Convex token" |
| 2 | same file L390-L399 (comment) and `npm-packages/convex/CHANGELOG.md` 1.25.1 | 1.25.1 | provider code comment and changelog | R6 comment = T2 | "This only fails so catastrophically when the key ends with `=`" (implies `=` padding appears on some keys, not all) |
| 3 | [convex-backend `npm-packages/dashboard/dashboard-management-openapi.json` L6568-L6570 @ 309e941](https://github.com/get-convex/convex-backend/blob/309e941f7d9ceea64da09c84f3564b53b5f88ec8/npm-packages/dashboard/dashboard-management-openapi.json#L6568-L6570) (also `generatedApi.ts` L2772-L2790) | file since 2026-01-30 | provider OpenAPI schema | provider docs = T1 for what it states | `SerializedAccessToken`: "serialized (json) and base64 encoded … The json is externally tagged. Expect it to look like {"v1": "workostoken"}" |
| 4 | [convex-backend `crates/authentication/src/application_auth.rs` L35-L70 @ 309e941](https://github.com/get-convex/convex-backend/blob/309e941f7d9ceea64da09c84f3564b53b5f88ec8/crates/authentication/src/application_auth.rs#L35-L70) | HEAD | provider server code | R1 (T1) | a key that is not a hex-encrypted admin key is routed to access-token auth: "Access Tokens are base64 encoded strings" (comment, T2); the executing branch is T1 for the hex/access-token split |
| 5 | [convex-backend `crates/big_brain_private_api_types/src/lib.rs` L210-L216 @ 309e941](https://github.com/get-convex/convex-backend/blob/309e941f7d9ceea64da09c84f3564b53b5f88ec8/crates/big_brain_private_api_types/src/lib.rs#L210-L216) | HEAD | provider code | R1 | `to_deploy_key_prefix`: preview-deployment keys look like `preview:branch-name\|<rest>`; the identifier has `:` and `\|` replaced by `_`, truncated to 40 |
| 6 | [get-convex/agent-benchmarks `src/backend-environment.ts` L2284-L2294 @ 128bbe5](https://github.com/get-convex/agent-benchmarks/blob/128bbe59647e209c1fe8dbfa1ac97282345e3e4b/src/backend-environment.ts#L2284-L2294) | 2026-06-25 | provider-authored redaction regex | R2 = T1 | `/\bdev:([^\|\s"']+)\|[^\s"']+/g`: no length; the body alphabet is only "non-space, no quote" (no narrowing) |
| 7 | [Convex docs, create deploy key](https://docs.convex.dev/management-api/create-deploy-key) | read 2026-09-28 | provider docs | R4 prefix only | a truncated example ending `\|ey...` |

## Resulting facts (not a full contract)

- The body is Base64(JSON object with the top-level key `v2`): T1 (#1
  executing, #3 schema).
- The visible lead `eyJ2` (= `{"v`) is a T1 prefix (R4, consistent with #1
  and #3).
- Derived, not stated: serde externally tagged compact JSON begins `{"v2":`,
  whose Base64 is `eyJ2MiI6` in both the standard and URL-safe alphabets
  (the first 6 bytes form two whole groups). Usable as a stronger anchor only
  if a derived fact is accepted; the maintainer did not accept it.
- Alphabet: Base64 of some flavour, with `=` padding observed in the docs and
  implied by #2. Standard versus URL-safe is not stated; `Buffer.from(…,
  "base64")` accepts both, so #1 does not settle it.
- Length: **no source.** The `v2` payload is opaque, and may vary with scope.
- Side finding (affects the implemented name grammar): a preview
  *deployment* key's name part is an arbitrary branch identifier of up to 40
  characters with `:` and `|` replaced by `_` (#5). That is wider than the
  handoff's `[a-z0-9][a-z0-9-]{0,62}` slug class (`/`, `.` and uppercase are
  possible). It is an accepted false negative today.

## Residual risk

- **False negatives:** every cloud `eyJ2` key until a length or alphabet
  source or an issuance check exists (the status quo).
- A floor-only rule (`<typed lead>|eyJ2MiI6[A-Za-z0-9+/_-]{N,}={0,2}`) would
  have a low false-positive rate, but N would be project policy, not T1.
- Items 2, 4, 5 and 6 of the handoff's issuance checklist (length, alphabet
  classes, trailing `=` count, scope effect) remain the only way to freeze
  the length.
