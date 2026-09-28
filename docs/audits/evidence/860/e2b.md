# #860 handoff: `e2b:api-key`

[#860 handoff index](README.md) ·
[Research table #05](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386450)

**Readiness: READY.** **Route:** new detector `e2b-api-key`, finding type
`e2b_api_key`.

## Role and blast radius

An E2B team API key (`E2B_API_KEY`, sent as `X-API-Key`) creates and controls
cloud sandboxes where agents run code. A leaked key lets anyone start
sandboxes on the team's quota and reach sandboxes it owns.

## Supported shape

Sources: e2b-dev/infra provider code at
[`132dadd`](https://github.com/e2b-dev/infra/tree/132dadd2ef55bbac301528500e8a4538caf4b163):

- `packages/shared/pkg/keys/constants.go`: `ApiKeyPrefix = "e2b_"`;
- `packages/shared/pkg/keys/key.go`: `keyLength = 20` bytes from
  `crypto/rand`, then `hex.EncodeToString`;
- the legacy SQL generator (20 random bytes as hex, "so it's 40 characters");
- the local-dev seed test asserting `len(prefix) + 2*20`.

The docs name the variable and show `e2b_…` placeholders only. **Re-checked
2026-09-28:**

- `constants.go` was last changed 2026-08-23
  ([`4580311`](https://github.com/e2b-dev/infra/commit/4580311916a7d9fcdc1ec884ab26d6cab30d4d54));
- `key.go` was last changed 2026-04-21
  ([`62b9d32`](https://github.com/e2b-dev/infra/commit/62b9d3274fe00f50229bf886139f093fea1342f0));
- the prefix and `keyLength = 20` are unchanged.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `e2b_` | provider code + docs | T1 |
| Body | exactly 40 | provider generator (R1) | T1 |
| Alphabet | lowercase hex `[0-9a-f]` (Go `hex.EncodeToString`) | provider generator (R1) | T1 |
| Separators / checksum | none | — | — |

Total length 44.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| `sk_e2b_` + 40 hex user access token | retired: generation stopped 2026-07-01, the tokens stopped working 2026-08-01, and the generator table was dropped. No live token exists. Generic context still redacts one under a credential name. The leading boundary keeps `e2b_` inside `sk_e2b_` from being claimed as an API key |
| Uppercase-hex body | the server's verifier accepts it, but the generator never issues it. Claiming it would widen the issued grammar |
| Sandbox envd/traffic tokens (64 hex, no prefix) | not lexically detectable; SHA-256 hex shape |
| `e2b_` identifiers: `e2b_code_interpreter`, `e2b_desktop`, `e2b_sandbox`, `e2b_dev` | package and module names; fail the exact-40-hex body |

## Tier rationale

T1 for all four facts under R1: prefix, length and alphabet come from the
provider's own generator and test; the docs corroborate the prefix. The one
contradicting lead (a third-party connector page showing a 32 length) was
traced in the research to an illustrative value and is not used.

## Overlap and output policy

- **Existing detectors.** None claims `e2b_`. Without the prefix, the 40-hex
  body is SHA-1/git-SHA shaped, so the prefix is load-bearing and no generic
  hex rule is involved. Measured on `main`: named contexts `contextual_secret`,
  Bearer `bearer_token`; bare, chat and JSON `"token"` are missed.
- **New output.** Provider type, high confidence, always redact.

## Implementation notes

`KnownFormatProviderDetector` with one `PrefixShape::exact("e2b_", 40, is_lower_hex, …)`
and the `[A-Za-z0-9_-]` boundary. Signals: `e2b-documented-prefix`,
`e2b-generator-length`.

## Test axes

**Positives:**

- every index context;
- `E2B_API_KEY=` in `.env`;
- `Sandbox.create(api_key=…)` / `Sandbox.create({ apiKey })`;
- an MCP server config `env` block;
- `X-API-Key` in a curl line.

**Near-miss twins:**

- body of 39 or 41;
- an uppercase hex byte;
- a `g` or `-` in the body;
- `E2B_` uppercase prefix;
- `e2b-` separator;
- `sk_e2b_` + 40 (unclaimed by this type);
- a leading glue byte (`xe2b_…`, `_e2b_…`) and a trailing glue byte.

**Benign:**

- `e2b_code_interpreter`, `e2b_desktop` imports;
- `e2b_…`/`e2b_***` placeholders;
- a bare 40-hex git SHA;
- `E2B_API_KEY=${E2B_API_KEY}`;
- a 64-hex sandbox token.

## False-positive / false-negative boundary

- **Accepted false negatives:**
  - an uppercased copy of a key;
  - retired `sk_e2b_` tokens outside named contexts;
  - any future generator change.
- **Accepted false positives:** an unrelated `e2b_` + exactly 40 lowercase
  hex value, such as an identifier that suffixes a SHA-1. This is rare, and
  if it happens a digest is redacted.

## Issuance checklist (optional confirmation; structure only)

For one console-issued key:

- total length (expect 44) and body length;
- alphabet classes (expect lowercase hex only);
- `rawValueRetained: false` and revoked.
