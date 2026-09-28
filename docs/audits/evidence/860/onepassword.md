# #860 handoff: `onepassword:service-account-token`

[Tier B re-rank](tier-b-rerank.md) ·
[Research table #39](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386967)

**Readiness: READY.** **Route:** new detector
`onepassword-service-account-token`, finding type
`onepassword_service_account_token`.

## Role and blast radius

A 1Password service-account token (`OP_SERVICE_ACCOUNT_TOKEN`) is the whole
credential for a service account. It embeds the account's key material:
Secret Key, SRP-x, the master unlock key and the device identity. A leak
exposes every vault the service account can read. That is often a
production secrets store fed to CI and agents.

## Supported shape

Source: 1Password's service-account security page
([developer.1password.com](https://developer.1password.com/docs/service-accounts/security/)).
It says two things:

- The format "uses `ops_` as the token prefix", chosen "to help code
  analyzers find accidental credential exposure".
- The rest is a serialized object that is "Base64 URL encoded".

The page prints one encoded example.

**Re-checked 2026-09-28** (R5 hinges on the example). The live page still
states the prefix and the Base64 URL encoding. Its one encoded example was
measured by script, with no value retained:

- 634 characters in total;
- begins `ops_eyJ`;
- only `[A-Za-z0-9]` after the prefix;
- no `=` padding.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `ops_` | provider docs (prose) | T1 |
| Body lead | `eyJ` (Base64 of `{"`) | follows from "serialized … Base64 URL encoded" JSON; the docs example begins `ops_eyJ` (R4/R5) | T1 |
| Alphabet | Base64url `[A-Za-z0-9_-]`, optional `={0,2}` kept inside the span | provider docs ("Base64 URL encoded") | T1 |
| Length | variable by construction (serialized JSON carrying the account email, sign-in address and key material); one T1 example of 634 | provider docs + example (R5) | T1 (variable) |
| Floor | at least 250 Base64url bytes after `ops_eyJ` | project policy: a false-positive guard far below the 634 T1 example and the documented field set | policy |
| Separators / checksum | none | — | — |

**Why a floor and not a length.** The token is serialized user data, so no
fixed length exists. The provider's example (634) is one instance. The
observed range is 634–870; dashboard and CLI serializations reportedly
differ. The floor only has to reject identifiers and placeholders. The
decoded JSON always carries the eight documented fields (`email`, `muk`,
`secretKey`, `srpX`, `signInAddress`, `userAuth`, `throttleSecret`,
`deviceUuid`), so no real token is near 250 Base64 bytes. 250 is also the
existing gitleaks floor, so the two scanners agree on what counts as
too short.

**Alphabet: the provider's class, not the samples'.** Every sample seen,
including the docs example, is alphanumeric after the prefix. gitleaks uses
`[a-zA-Z0-9+/]`. The provider states Base64url, so the contract uses
`[A-Za-z0-9_-]`. A token containing `-` or `_` would be truncated by an
alphanumeric-only rule, and that would leak the tail. R8 applies in spirit:
do not narrow from absence.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Connect server token (`OP_CONNECT_TOKEN`) | a standard three-segment JWT; the `jwt` detector keeps it |
| Account Secret Key `A3-XXXXXX-…` | a separate credential with its own grammar; not this family (a candidate for later research) |
| `op://vault/item/field` secret references | references, not secrets. `generic-token` already excludes them (`is_onepassword_reference`), and they never begin `ops_eyJ` |
| `ops_…`, `ops_token`, `ops_***`, `ops_function` | placeholders and identifiers; they fail the `eyJ` lead or the floor |
| Standard-Base64 `+` or `/` inside the body | not the stated encoding; the run stops there, and the trailing boundary rejects the match rather than truncating it |

## Overlap and output policy

- **Existing detectors.** No provider detector claims `ops_`; the only
  `ops_` matches in the core are unrelated identifiers. Measured on `main`:
  - env, `export`, `X-API-Key`, JSON `api_key` and the SDK keyword argument
    give `contextual_secret`, high, redact, full span;
  - Bearer gives `bearer_token`, full span;
  - bare, chat and JSON `"token"` are **missed**.
- **`generic-token` deferral.** `onepassword` / `op` are not added to
  `DEDICATED_PROVIDER_SEGMENTS` (Tier A shared rule).
- **New output.** Provider type, `Confidence::High`, in
  `ALWAYS_REDACT_TYPES`. No `block`, although this is the highest-sensitivity
  family in Tier B; the policy layer, not the detector, owns blocking.

## Implementation notes

Use `KnownFormatProviderDetector` with one
`PrefixShape::at_least("ops_eyJ", 250, pattern::is_alnum_dash, …)` (`is_alnum_dash` is exactly `[A-Za-z0-9_-]`, the Base64url alphabet). Add a post check
that absorbs up to two trailing `=` into the span. The boundary is
`[A-Za-z0-9_-]` plus `+`, `/` and `=` beyond the absorbed padding, so a
glued standard-Base64 tail rejects the match.

Signals: `onepassword-documented-prefix`, `base64url-json-lead`.

**Cost.** One literal anchor and one linear run. A token is 600–900 bytes,
within any practical `IncrementalLimits::max_token_bytes`. A caller that sets
a token limit below the token's length makes the incremental session fail
closed on it. That is existing engine behavior, and the test notes it.

## Test axes

**Positives:**

- every context in the re-rank's probe list;
- `OP_SERVICE_ACCOUNT_TOKEN=` in `.env` and in a GitHub Actions `env:` map;
- `op` CLI invocation with the variable exported;
- an MCP server `env` block;
- body lengths 250 (floor), 630 and 866;
- a body containing `-` and `_`;
- a body ending `=` and `==`.

**Near-miss twins:**

- 249 bytes after `ops_eyJ`;
- `ops_eyj` (lowercase `j`);
- `OPS_eyJ`;
- `ops-eyJ`;
- a `+` in the middle;
- a leading glue byte (`xops_eyJ…`);
- a trailing glue byte `/`.

**Benign:**

- `ops_...` placeholders;
- `op://Private/item/credential`;
- a 611-byte Connect JWT (stays `jwt`);
- `ops_function_name`;
- `OP_SERVICE_ACCOUNT_TOKEN=${{ secrets.OP_TOKEN }}`.

## False-positive / false-negative boundary

- **Accepted false negatives:**
  - a token under 250 Base64 bytes after the lead (none is possible from the
    documented field set);
  - a future non-JSON serialization without the `eyJ` lead;
  - a token truncated by a log line limit to under the floor.
- **Accepted false positives:**
  - `ops_` + any Base64url JSON blob of at least 250 bytes that is not a
    service-account token. None is known, and such a blob is still sensitive
    enough to redact.

## Issuance checklist (optional confirmation; structure only)

For one token created in the web dashboard and one created with
`op service-account create`, record:

- total length;
- whether each begins `ops_eyJ`;
- alphabet classes present after the prefix: upper, lower, digit, `-`, `_`,
  `+`, `/`;
- the count of trailing `=`;
- `rawValueRetained: false`, and whether the token was revoked.
