# #1012 research: `netlify:other-prefixed-tokens` (`nfc_`, `nfo_`, `nfu_`, `nfb_`)

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29.

**Verdict: BLOCKED (body), per prefix.** The four prefixes and a 40-character
token capacity are T1 from Netlify's announcement. The `_` separator, the
36-character body and the alphabet are not stated by Netlify for any class,
and third-party rules disagree on the body width. `nfc_` is one cheap
issuance away from READY.

Note: redact-secret-benchmarks recorded this family as ready at T1 in PR
#506 (merged 2026-09-29,
[`netlify.md` @ 5380aa3](https://github.com/redact-secret/redact-secret-benchmarks/blob/5380aa3a421555883225a62358fa40f81dcd2baa/benchmarks/support/dossiers/netlify.md)).
This record reads the evidence bar more strictly: the announcement states a
capacity and prefixes, not a body grammar. The two records should be
reconciled before a contract freezes.

## Current product behaviour

`netlify-token` (`crates/secret-scan-core/src/detectors/netlify.rs`) claims
`nfp_` + exactly 36 `[A-Za-z0-9_]` and tests the four other prefixes as
non-matches. Its module doc says gitleaks converges on `nfp_` + 36; at
gitleaks HEAD the rule has no prefix at all (a keyword-gated run of 40–46),
so that sentence overstates it.

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [Netlify Support Forums, "Change to the Netlify authentication token format"](https://answers.netlify.com/t/change-to-the-netlify-authentication-token-format/106146) | 2023-11-07, by a Netlify staff member (now labelled alumni) | provider announcement | T1 (prefixes, capacity) | "All Netlify authentication tokens will start with a nf prefix followed by a single identifying character. They are: nfp for Personal Access Tokens. nfc for Netlify CLI tokens. nfo for OAuth access tokens. nfu for app.netlify.com tokens. nfb for Netlify build tokens." … "increase capacity for the token to 40 characters." No separator, body length or alphabet |
| 2 | [netlify/netlify-mcp `src/utils/api-networking.test.ts` L17 @ 57e547a](https://github.com/netlify/netlify-mcp/blob/57e547a1b23ace88227b6fc0ce014ec390e4c4f7/src/utils/api-networking.test.ts#L17) | at the pinned commit | provider test placeholder | R5 (`nfp_` only) | `nfp_` + short placeholder bodies; shows the `_` for the personal class only |
| 3 | [trufflehog `pkg/detectors/netlify/v2/netlify_v2.go` L25 @ 48b58d3](https://github.com/trufflesecurity/trufflehog/blob/48b58d3bf3f02ba17bf23b87f095499bc80c6fd7/pkg/detectors/netlify/v2/netlify_v2.go#L25) | 2025-04-28 | peer scanner rule | T2 (`nfp_` only) | `nfp_[a-zA-Z0-9_]{36}` |
| 4 | [gitleaks `cmd/generate/config/rules/netlify.go` L9-L25 @ b58d3f1](https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/cmd/generate/config/rules/netlify.go#L9-L25) | 2024-10-30 | peer scanner rule | none for the prefixes | keyword `netlify`, value 40–46 extended alphanumerics; no `nf*` prefix |
| 5 | [koki-develop/mask-go `builtin_netlify_auth_token.go` L5-L63 @ 1b861d7](https://github.com/koki-develop/mask-go/blob/1b861d7ac421b392a5bb962207fd1886b28e013e/builtin_netlify_auth_token.go#L5-L63) | 2026-08-31 | independent implementation | T2 class | `nf` + one of `pcoub` + `_` + exactly 36; its comment notes the announcement writes three-character prefixes with no separator |
| 6 | [puck-security/geiger `internal/modules/netlify.go` L15-L20 @ be0bc39](https://github.com/puck-security/geiger/blob/be0bc39ca4862f8d6552b6be90538095ee2a794b/internal/modules/netlify.go#L15-L20) | 2026-07-06 | peer scanner rule | conflicting | `nf[a-z]_[A-Za-z0-9]{30,}` |
| 7 | [Vulnetix/cli `internal/sast/rules/vnx-sec-092.rego` L25-L26 @ c6e24fc](https://github.com/Vulnetix/cli/blob/c6e24fc9b0148dc0a227da70774300fba7f339ee/internal/sast/rules/vnx-sec-092.rego#L25-L26) | 2026-06-14 | peer scanner rule | conflicting | `nf[pcoub]_[A-Za-z0-9]{40,}` (a body of 40 or more contradicts the 40-character capacity) |
| 8 | [testpatterndev/patterns `global-netlify-token.yaml` L23 @ 64580c8](https://github.com/testpatterndev/patterns/blob/64580c807ea3a3c2896ca4e0f7044da56333fff6/data/patterns/global-netlify-token.yaml#L23) | 2026-07-06 | peer scanner rule | conflicting | `nf[bcou]_[A-Za-z0-9_]{20,36}` |
| 9 | A committed `nfc_` key-shaped value in an unrelated public repository | 2026-04 | observation | not evidence (withheld) | recorded only as a lead that `nfc_` tokens circulate; no shape is taken from it |

Searched, nothing further: the forum thread JSON (no staff follow-ups);
code search `nfc_`, `nfu_`, `nfb_` in `org:netlify` (0 hits; `nfo_` hits are
substrings of `info_`); web search (regextokens and benchmarks PR #506 only);
GitHub's pattern list (no Netlify row).

## Exact missing evidence

- **`nfc_` (CLI):** the separator, a body of exactly 36 and its alphabet.
  Evidence for 36: the 40 capacity (#1) and one independent implementation
  (#5); peer rules conflict (#6–#8). One more corroboration class, or one
  issuance, closes it.
- **`nfo_` (OAuth):** no observed shape of any kind.
- **`nfu_` (app session) and `nfb_` (build):** no observed shape; both are
  platform-minted, so not trivially issuable.

## Structure-only issuance check

- `nfc_`: run `netlify login` once. Record total length (40?), whether byte 4
  is `_`, the body classes (any `_` or `-`?). `rawValueRetained: false`, then
  revoke in the user settings.
- `nfo_`: authorize a test OAuth app once; same record.
- `nfu_`: read the shape (length, `_` position, classes only) of the app
  session token in the browser's storage; do not copy it.
- `nfb_`: a build step that prints only the length and character classes of
  the build token variable.

## Residual risk

A bounded interim contract (`nf[coub]_` + `[A-Za-z0-9]`, total at most 40, T1
cap) is defensible, but its floor would be policy. Named contexts
(`NETLIFY_AUTH_TOKEN=`) are already redacted.
