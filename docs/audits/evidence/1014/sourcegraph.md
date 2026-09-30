# #1014 handoff: `sourcegraph:access-token`

[#1014 index](README.md) · rank 14 ·
[Research table #16](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447016)

**Readiness: READY for the personal access token (`sgp_`), T1 as of
2025-11-18 (ruling R9).** The Cody Gateway user token (`sgd_`) is left for a
later extension, see Excluded shapes. **Route:** new detector
`sourcegraph-token`, finding type `sourcegraph_access_token`.

## Role and blast radius

A Sourcegraph access token (`SRC_ACCESS_TOKEN`, sent as `Authorization: token`
by `src` and the editor extensions) acts as the user on a Sourcegraph instance:
code search and code navigation over every repository the user can see, batch
changes and, for a site administrator, instance administration. The 2023
Sourcegraph incident began with a leaked site-admin token in a pull request
([SecurityWeek](https://www.securityweek.com/sourcegraph-discloses-data-breach-following-access-token-leak/),
[BleepingComputer](https://www.bleepingcomputer.com/news/security/sourcegraph-website-breached-using-leaked-admin-access-token/),
2023-08 and 2023-09, press class), so leaked tokens of this family have
real history. The token is pasted into editor and MCP configs, where agents
see it.

## Supported shape

Discovery started broad (web search, issue trackers, scanner rule sets, press)
and labelled classes afterwards. Sources, re-checked 2026-09-30:

- **Provider generator (R1, dated by R9).** `sourcegraph-public-snapshot`
  `internal/accesstoken/personal_access_token.go` at
  [`c864f15`](https://github.com/sourcegraph/sourcegraph-public-snapshot/blob/c864f15af264f0f456a6d8a83290b5c940715349/internal/accesstoken/personal_access_token.go#L13-L48)
  (snapshot of 2024-08-22, repository archived; last change to the file
  2024-05-10): "Personal access tokens have the form:
  sgp_<instance-identifier>_<token>". 20 random bytes are hex-encoded (40
  lowercase hex). The instance identifier is either `local` (no license key or a
  dev instance) or the first 16 hex characters of an HMAC of the license key.
  `InstanceIdentifierLength = 16`.
- **Provider validator, snapshot (R1).** `lib/accesstoken/personal_access_token.go`
  at the same commit: `^(?:sgp_|sgph_)?(?:[a-fA-F0-9]{16}_|local_)?([a-fA-F0-9]{40})$`,
  with the doc comment listing the three accepted forms: bare token,
  `sgp_<token>`, `sgp_<instance-identifier>_<token>`.
- **Provider validator, current public repo (R1, newer than the snapshot).**
  `sourcegraph/src-cli`, which is still public and maintained (last push
  2026-09-28), vendored the library on 2025-11-18
  ([`7cb402a`](https://github.com/sourcegraph/src-cli/commit/7cb402a6c3730d375ec167ab295d331d855fa5a4),
  "vendor in lib from sourcegraph (#1202)"). Its regex is
  `^(?:(?:sgp_|sgph_)(?:[a-zA-Z0-9]+_)?)?([a-fA-F0-9]{40})$`: the instance
  identifier is now any alphanumeric run, and the prefix is required when an
  identifier is present. The same repo's `code_intel_upload.go` (changed
  2026-02-27 and 2026-03-13) tells users the expected format is "sgp_<40 hex
  chars> or sgp_<instance-id>_<40 hex chars>". The 40-hex token body is the same
  in both eras.
- **Corroboration, independent of the two provider repos.** The
  [1Password shell-plugins issue #233](https://github.com/1Password/shell-plugins/issues/233)
  (2023-03-30, community class) records Sourcegraph's PR #49989 that introduced
  the `sgp_` prefix "to make them identifiable as secrets", with prefix-less
  tokens still accepted. The scanner rules agree on the shape: gitleaks and
  trufflehog `sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}`
  plus a bare 40-hex alternative; noseyparker
  `\bsgp_(?:[a-fA-F0-9]{16}_|local_)?[a-fA-F0-9]{40}\b` (scanner class, T2).
  The GitHub secret-scanning partner list carries Sourcegraph access tokens.
  The gitleaks
  [issue #1697](https://github.com/gitleaks/gitleaks/issues/1697) (2025-01-15) shows the `sgp_` shape only as a masked pattern.

| Form | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Instance-bound | `sgp_` + `[A-Za-z0-9]+` + `_` + 40 hex | generator (16 hex or `local`) + 2025-11 validator (alnum id) | T1 (R1, R9) |
| Local / no identifier | `sgp_` + 40 hex | validator regexes in both eras (`(…)?` optional) | T1 (R1) |

The two validators differ only in the identifier: the snapshot accepts 16 hex or
`local`, and the 2025 library accepts any alphanumeric run. Every identifier the
generator issues is inside both. The detector claims the newer, wider grammar
(a union of what the provider accepts), as in the Polar handoff. The body is
the provider's 40 hex; the validators accept upper-case hex while the
generator emits lower case. The detector follows the validator (R1 validator
code) and accepts both.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Bare 40-hex legacy token (no `sgp_`) | the scanners' fallback alternative; no distinctive shape; collides with git SHAs; generic context |
| `sgph_` prefix | accepted by both validators but no generator or doc states what issues it; the prefix is T1 by validator, the role is unknown. Recommended as a follow-up only after the maintainer confirms it is issued (see issuance checklist) |
| `sgd_` + 64 hex (Cody Gateway user key: double SHA-256 of a personal token) | a real credential, but one provider source (`internal/accesstoken/cody_access_token.go`, snapshot 2024-08-22) and no newer source; it is a derived token that the gateway, not the user, stores. Deferred extension with the same R9 tier; would add one `PrefixShape::exact("sgd_", 64, hex)` |
| `slk_` license-key token, product-subscription token | scanner-only (trufflehog `sourcegraphcody`, partner list); no provider source checked; T2 |
| `sgp_local_` sentinel inside docs, `sgp_` + `x` placeholders in `src` help text | placeholders; they fail the 40-hex body |

## Tier rationale

T1 under R1 and R9: prefix, identifier rule and body come from provider server
code (generator and validator), dated 2024-05/2024-08 for the generator, and the
current provider validator in a public repo is dated 2025-11-18 and widens the
identifier without changing the body. R9's caveat ("as of the date, until a
newer provider source contradicts it") holds: the newer source widens, not
contradicts. The Sourcegraph server repository is no longer public, so a
post-2025 generator change cannot be ruled out; the validators in `src-cli`
(active through 2026-03) would have needed to follow it. The scanners' bare
40-hex alternative is deliberately not used.

## Overlap and output policy

- **Existing detectors.** None claims `sgp_`, `sgd_` or `sgph_` on `main`
  `cfa87360`. Measured on `b9e9091`: `SRC_ACCESS_TOKEN=` 
  gives `contextual_secret`; bare, chat and JSON `"token"` are missed.
- **Generic hex.** A `sgp_` token that is reported today only through context
  is promoted to the provider type; the bare 40-hex form keeps falling to
  generic hex policy, which is unchanged.
- **New output.** One provider type, high confidence, always redact.

## Implementation notes

`KnownFormatProviderDetector`; a hand-written matcher is simpler than
`PrefixShape::exact` because the identifier is variable: `sgp_`, then an
optional `[A-Za-z0-9]+` run ended by `_` (cap the run at 32 bytes, well above
the issued 16, so a long `sgp_<word>_` cannot consume a line), then exactly 40
hex, then a non-`[A-Za-z0-9_-]` boundary. A 41st hex or alphanumeric byte fails
the match. Leading boundary `[A-Za-z0-9_-]`. Signals:
`sourcegraph-documented-prefix`, `sourcegraph-validator-grammar`.

## Test axes

**Positives:** every #860 index context; `SRC_ACCESS_TOKEN=` in `.env`;
`Authorization: token sgp_…` (not the `Bearer` scheme); an MCP server config
`env` block; the `src login` command line; the `sgp_` + 40 hex form; the
16-hex-identifier form; the `local` form; an upper-case hex body.

**Near-miss twins:** body of 39 or 41 hex; a non-hex byte at the end of the
body; `sgp_` + identifier with no `_`; `SGP_` uppercase; `sgp-` separator; a
leading glue byte (`xsgp_…`); a trailing glue byte.

**Benign:** `sgp_` + a run of `x` (the `src` help placeholder); a bare 40-hex git
SHA; `SRC_ACCESS_TOKEN=${SRC_ACCESS_TOKEN}`; the word `sgp_token` alone.

## False-positive / false-negative boundary

- **Accepted false negatives:** legacy bare-hex tokens outside named
  contexts; `sgd_`, `sgph_` and `slk_` tokens until extended; an
  identifier longer than 32 bytes, if Sourcegraph ever issues one.
- **Accepted false positives:** an unrelated `sgp_<word>_` + exactly 40 hex;
  none is known. The `sgp_` prefix plus a 40-hex tail is unlikely to occur
  by accident.

## Issuance checklist (optional confirmation; structure only)

Not required for READY. The useful facts, one revoked personal token from a
current instance:

- total length and the identifier segment (expect `local` or 16 hex);
- case of the hex body (expect lower);
- whether any token starts `sgph_` and what issues it;
- `rawValueRetained: false` and revoked.
