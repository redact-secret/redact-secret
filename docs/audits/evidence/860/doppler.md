# #860 handoff: `doppler:service-token` (and six sibling token types)

[#860 handoff index](README.md) ·
[Research table #40](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852387097)

**Readiness: READY.** Every supported fact is on one provider page. **Route:**
new detector `doppler-token` with seven finding types.

## Role and blast radius

Doppler is a secrets manager. A service token reads one config (all of its
secrets) and is typically placed in CI, containers and agent runtimes. The same
page documents six sibling bearer tokens under one `dp.<type>.` scheme: CLI
(`ct`), personal (`pt`), service account (`sa`), service account identity
(`said`, short-lived, minted by OIDC exchange), SCIM (`scim`) and audit
(`audit`). All seven are secrets, and Doppler publishes no public or
publishable token.

## Decision: one detector, seven types

Scope is **all seven documented types**, not service tokens only:

- the seven share one provider page, one body grammar and one scan; limiting
  the detector to `dp.st.` would leave six T1 bearer secrets (including
  personal and CLI tokens, whose scope is user-wide and so wider than a
  service token's) with the same bare/chat/JSON-`token` gap;
- each type gets its own finding type, following
  [Map GitHub's six token families onto six independent finding types under one detector](../../../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md):
  the roles differ in blast radius, and a policy or the benchmark support
  matrix can treat them apart.

| Prefix | Finding type |
| --- | --- |
| `dp.st.` | `doppler_service_token` |
| `dp.pt.` | `doppler_personal_token` |
| `dp.ct.` | `doppler_cli_token` |
| `dp.sa.` | `doppler_service_account_token` |
| `dp.said.` | `doppler_service_account_identity_token` |
| `dp.scim.` | `doppler_scim_token` |
| `dp.audit.` | `doppler_audit_token` |

The #860 family id is `doppler:service-token`; the benchmarks side may qualify
the service token first and the siblings with the same generator.

## Supported shapes

Source: [docs.doppler.com/reference/auth-token-formats](https://docs.doppler.com/reference/auth-token-formats)
(provider docs; per-type regex; page `dateModified` 2025-05-29). **Re-checked
2026-09-28:** the seven regexes are unchanged and the page date is still
2025-05-29.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `dp.` + one of `st`, `pt`, `ct`, `sa`, `said`, `scim`, `audit` + `.` | provider docs regex | T1 |
| Environment segment (`dp.st.` only, optional) | `[a-z0-9_-]{2,35}` then `.` | provider docs regex; docs examples use the environment slug | T1 |
| Body | 40–44 bytes of `[A-Za-z0-9]` | provider docs regex | T1 |
| Separators | `.` after `dp`, after the type, and after the optional segment; none inside the body | provider docs regex | T1 |
| Checksum | none documented | — | — |

Total length: 46–50 without a segment (`dp.st.` + 40–44), up to 86 with a
35-byte segment. All documentation examples, and the one empirical user
observation in the research table, have a 43-byte body; the contract keeps the
documented 40–44 band.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| The `dp.st…` preview (Unicode ellipsis plus the last 6 body bytes) shown by the CLI and dashboard | non-secret display form; fails the grammar by construction |
| `dp.st.` + a segment that breaks the segment grammar (uppercase, 1 byte, over 35 bytes, a byte outside `[a-z0-9_-]`) followed by `.` and a body | the documented regex does not match it; claiming it would widen the grammar |
| A body of 39 or 45+ alphanumeric bytes | outside the documented band; a longer run is an embedded value, not a truncated key |
| A body containing `_` or `-` | the documented body alphabet is alphanumeric only |
| Service-token slugs (`--slug` values) and token names | non-secret identifiers, not in `dp.` form |

## Tier rationale

T1 throughout: the issuer states prefix, optional segment, body length band,
alphabet and separators as a regex for each type. Scanner rules (trufflehog,
Nosey Parker, gitleaks `pt` only, GitHub secret scanning without `said`) are
corroboration only and lag the page; none is used to narrow or widen it.

## Overlap and output policy

- **Existing detectors.** No provider detector claims `dp.`. Measured on `main`
  (see the [index](README.md#current-coverage-on-main-synthetic-probe-2026-09-28)):
  `contextual_secret` redacts the value under credential-named keys and
  `bearer_token` under `Authorization: Bearer`. Bare, chat and JSON `"token"`
  are missed today. `vendor_prefixed_credential` (only `sk-` prefixes),
  `jwt` and `connection_string_password` do not apply.
- **New output.** Seven provider types, high confidence, always redact. The
  provider finding wins the overlap with `contextual_secret` and
  `bearer_token`, so one finding per span.
- **Sibling precedence.** `dp.said.` must not be read as `dp.sa.` plus a body
  beginning `id.`: the body alphabet excludes `.`, so `dp.sa.` + `id` fails,
  but a test pins it. Longest-prefix-wins handles `dp.said.` vs `dp.sa.`.

## Implementation notes

A bespoke scan in a `detectors::doppler` module (the optional segment cannot
be expressed as a single `PrefixShape` run):

1. find `dp.`, match one of the seven type literals and the following `.`,
   with a leading boundary (the byte before `dp` is not `[A-Za-z0-9_.-]`);
2. for `st` only, if a `[a-z0-9_-]{2,35}` run is followed by `.`, consume it
   as the segment and continue after the `.`; if the segment grammar fails,
   try the no-segment form at the same position;
3. take the maximal `[A-Za-z0-9]` run as the body and accept it only when its
   length is 40–44 and the next byte is not `[A-Za-z0-9_-]`. A following `.`
   is allowed (sentence punctuation) and is not part of the span.

The span covers the prefix, segment and body. Signals:
`doppler-documented-prefix`, `doppler-documented-length-band`.

## Test axes

**Positives** (generated at test time; body from a seeded alphanumeric filler):

- each of the seven prefixes with a 40-, 43- and 44-byte body;
- `dp.st.` with no segment, a 2-byte and a 35-byte segment, and segments using
  `-` and `_`;
- every context in the index probe, plus YAML, a code fence, `DOPPLER_TOKEN=`
  in a CI log line, a Kubernetes `stringData` value, and trailing sentence
  punctuation.

**Near-miss twins** (one property changed each; all unclaimed):

- body of 39 and 45 bytes;
- a `_` or `-` inside the body;
- unknown types (`dp.xx.`, `dp.st2.`) and case changes (`DP.ST.`, `dp.ST.`);
- segment of 1 byte, 36 bytes, or with an uppercase byte;
- a missing `.` (`dpst.`, `dp.st` + body);
- a leading glue byte (`xdp.st.…`, `_dp.st.…`) and a trailing glue byte
  (`…a`, `…_x`).

**Benign** (unclaimed by the new detector):

- the `dp.st…` + 6 preview;
- `dp.st.xxxx`-style and `dp.st.<config>.*` placeholders;
- `DOPPLER_TOKEN=${{ secrets.DOPPLER_TOKEN }}`;
- service-token slug UUIDs;
- `doppler` CLI commands.

## False-positive / false-negative boundary

- **Accepted false negatives:** a body outside 40–44, a segment outside the
  documented grammar, a token glued to an identifier, any undocumented future
  type, and a token split across lines.
- **Accepted false positives:** a non-Doppler string that happens to be
  `dp.<documented type>.` plus a bounded 40–44 alphanumeric run. No such
  convention was found, so the risk is negligible.

## Issuance checklist (optional confirmation; structure only)

For one service token (with an environment), one personal token and one
service account token:

- total length and body length;
- whether the environment segment is present, equals the environment slug,
  and its length;
- body alphabet classes (confirm no `_` or `-`);
- `rawValueRetained: false` and revoked.

The open question in the research table ("are bodies always 43?") would
narrow, not change, the contract; the documented band stays.
