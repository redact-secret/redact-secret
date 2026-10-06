# Addendum to #1226: the Atlas API key slots and its public half

**Result:** the #1226 record called `mongodb-atlas:programmatic-api-private-key`
"source-unresolved: no wire carrier". credential-evidence
[#256](https://github.com/redact-secret/credential-evidence/issues/256) and
[#258](https://github.com/redact-secret/credential-evidence/issues/258) (contract
`mongodb-atlas:programmatic-api-private-key@1`, handoff
`docs/handoffs/atlas-private-key-slots.md`, claims `creation-response-member` and
`cli-profile-property`, observed 2026-10-06) name two plaintext slots. Both were
already detected by the existing vocabulary; this addendum pins them with
deterministic tests and spec text, and fixes one false positive on the public
half. Evidence is project-authored, draft, not independent validation.

## Evidence read (read-only)

* `privateKey`: a read-only string member of `ApiKeyUserDetails`, the 200 answer
  of `createOrgApiKey` and `createGroupApiKey`; unredacted when first created,
  redacted afterwards (mongodb/openapi `v2.yaml` at `5e6f651`).
* `private_api_key`: the Atlas CLI profile property, next to `public_api_key`,
  set with `atlas config set` (the command reference lists both).
* The public key: `publicKey` of the same object, `minLength` and `maxLength` 8;
  "the username-like half". The Case
  `mongodb-atlas-digest-header-and-public-key-non-values` (`must-not-flag`, basis
  `project-policy`, maintainer-only) lists the public key on its own, the Digest
  header, a redacted private key display and an environment reference as non-values.
* No grammar of the private key (alphabet, length, prefix) is established, and
  environment-variable, flag, Terraform and `curl --user` slots are not
  established. Nothing here claims one.

## Part 1: the two private slots (pinned, no code)

CLI `0.1.0-beta.14` at `efe71496` and the tests agree: `{"privateKey":"<value>"}`
(also inside a document with `publicKey`, and CRLF/pretty-printed),
`private_api_key = "<value>"` (quoted, bare, INI section) and
`MONGODB_ATLAS_PRIVATE_API_KEY=<value>` are a `contextual_secret`, high, `redact`,
exactly the value; `"privateKey":"********-****-****-************"`, an `x` mask,
`<private-api-key>`, `YOUR_PRIVATE_API_KEY` (since the #1234 addendum),
`${ATLAS_PRIVATE_KEY}`, `$MONGODB_ATLAS_PRIVATE_API_KEY` and `redacted` are silent.
No width, alphabet or provider type is asserted; the finding stays generic.

## Part 2: the public half

Before: `public_api_key = "abcd1234"`, `MONGODB_ATLAS_PUBLIC_API_KEY=abcd1234` and
`{"publicApiKey":"abcd1234"}` were each a `contextual_secret`, medium, `warn`,
while `publicKey` and `public_key` were silent. The names end in `api_key`, a
high-signal suffix, and the value is at the 8-byte floor, so the generic reading
reported the public half, which the evidence's Case lists as a control.

Decision: exempt exactly what the evidence lists as the public half and nothing
broader. `is_atlas_public_api_key_assignment` (`generic_token.rs`), modelled on the
Confluent key-id exemption (#993), excludes a value of exactly 8 bytes under the
whole normalized name `public_api_key` (`publicApiKey`, `PUBLIC_API_KEY`) or
`mongodb_atlas_public_api_key`. No alphabet is claimed (the evidence's open
question `public-key-alphabet`).

| Input | Result |
| --- | --- |
| 8 bytes under `public_api_key`, `publicApiKey`, `PUBLIC_API_KEY`, `MONGODB_ATLAS_PUBLIC_API_KEY`, `publicKey`, `public_key` | silent |
| 9 or 12 bytes, or a UUID-shaped value, under `public_api_key` | reported (unchanged): the evidence's length is the only thing excused |
| 8 bytes under `private_api_key`, `api_key`, `secret_api_key` or `my_public_api_key` | reported (unchanged) |
| the pair in one document | only the private half is reported |

Tradeoff: FP removed, a documented-public 8-byte identifier reported under its own
name. FN added: an 8-byte value that is really a secret filed under
`public_api_key`; the private half is documented as a different name and a
secret-half reading is not weakened, and a longer value under the public name is
still read. The finding was a `warn` (text unchanged by default), so the cost of
the previous behaviour was a reported false positive, not a redaction.

## Tests

`crates/secret-scan-core/tests/atlas_api_key_slots_1226.rs` (6 tests), whole input,
7-byte and 1-byte chunks equal to whole: the creation-response member, the CLI
property and variable, masked and placeholder forms, the public half under eight
names, the pair, and the unchanged readings.
