# Worked example: #1110 rewritten as an implementation-ready issue

A draft body for
[#1110](https://github.com/redact-secret/redact-secret/issues/1110) under the
[handoff contract](implementation-ready-handoff.md). It is a draft in the
repository; the live issue is not edited by this change. Section 1 to 5 are
enough to implement. The `state:implementation-ready` label is applied only after
a maintainer posts the adoption ruling that section 6 links, because the issue's
own disposition says the #1014 handoff is historical and must be reconciled with
the current credential-evidence handoff first. Until then the issue is
`state:research-needed`, and the adoption link below is the one to replace with
that ruling.

---

## 1. Task

Add an always-redact detector, `ory-token`, for the Ory session token
(`ory_session_token`) and the Ory OAuth2 access, refresh and authorization-code
tokens (`ory_oauth2_token`). Add synthetic fixtures for every item in sections 2
and 3.

## 2. Expected positives

- `ory_st_` followed by exactly 32 characters of `[A-Za-z0-9]` (39 bytes in
  total). Finding type `ory_session_token`.
- `ory_at_`, `ory_rt_` or `ory_ac_`, then a key part of at least 43 characters of
  `[A-Za-z0-9_-]`, one `.`, then a signature of exactly 43 characters of
  `[A-Za-z0-9_-]`. A wider key part (44 or 48 bytes) still matches. Finding type
  `ory_oauth2_token`.
- Each shape is found bare and inside an `X-Session-Token` header, an
  `Authorization: Bearer` header, an `ORY_ACCESS_TOKEN=` assignment, a
  constructor argument and an OAuth2 token response JSON.

## 3. Expected negatives and twins

Must not be flagged:

- `ory_st_` with 31 or 33 body characters, or with `-` or `_` in the body -- the
  generator fixes length and alphabet.
- `ory_at_` with a 42-byte key part, a 42- or 44-byte signature, no `.`, two
  `.`, or `+` or `/` in the body -- breaks the Hydra HMAC grammar; a third
  dot-separated segment is a JWT.
- `ORY_ST_` in uppercase, or a leading or trailing glue byte around a valid body
  -- the prefix is case-sensitive and the boundary rule rejects glued runs.
- `ory_kratos_session` and `ory_session_` cookie names, `ory_st_` placeholders
  shorter than 32, an `ory_pat_` placeholder, and
  `ORY_SESSION_TOKEN=${ORY_SESSION_TOKEN}` -- names and references, not values.
- A JWT whose payload only mentions `ory_at_` -- the `jwt` detector owns it.

Not supported by this issue:

- `ory_pat_`, `ory_apikey_`, `ory_wak_` admin keys -- no source gives a body
  length or alphabet; issuance-gated and tracked separately. No type, no claim.
- `ory_lo_` logout flow token -- not an account credential.
- JWT access tokens, enterprise custom OAuth2 prefixes, pre-2023 unprefixed
  session tokens -- no distinctive shape (accepted false negatives).

Test values are built at run time from repeated filler. Never write a realistic
key literal.

## 4. Files or surfaces likely to change

- `crates/secret-scan-core/src/detectors/**` (a new `ory-token` detector, one
  entry in the registry)
- `conformance/fixtures/**`
- `docs/specs/detector-families.md` (the spec row, with both trade-offs)
- `CHANGELOG.md` (`## Unreleased`)

## 5. Commands to run

```bash
npm run check:detector
npm run check:rust
npm run check:js
```

The wasm32 core tests and the equivalence harness stay green.

<details>
<summary>6. Maintainer evidence and research</summary>

- State: implementation-ready once the adoption ruling is posted on this issue
  (replace the link with that comment).
- Research handoff: the
  [#1014 Ory record](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1014/ory.md)
  (verdict ready for the siblings, tier T1, read at
  `2816897f96c405c3eb8c87a0c70eba5df273c121`). It is historical: read it
  against the current credential-evidence handoff at adoption time; do not
  repeat issuance.
- Policy: always redact, high confidence. False positive: an unrelated
  `ory_(st|at|rt|ac)_` run with the exact body grammar is redacted; the exact
  lengths make this rare. False negative: admin keys, JWT access tokens, custom
  prefixes and pre-2023 session tokens are not detected.
- Conformance: positive, near-miss twin, benign sibling, boundary and carrier
  fixtures; equivalence harness green; synthetic values only.
- Independent evaluation:
  redact-secret-benchmarks#583, owner `benchmarks-maintainer`, evidence label
  `project-authored`.
- Support status: separate. This handoff is not a support verdict, and the
  family does not become stable by being implemented.
- Unresolved limitation, restated above as an exclusion: the admin key body
  length and alphabet.
</details>
