# #860 handoff: `wandb:api-key`

[Tier B re-rank](tier-b-rerank.md) ·
[Research table #37](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386967)

**Readiness: READY for the `wandb_v1_` key.** The legacy 40-hex key stays
with generic context (not selected). **Route:** new detector `wandb-api-key`,
finding type `wandb_api_key`.

## Role and blast radius

A Weights & Biases API key (`WANDB_API_KEY`, `~/.netrc` for `api.wandb.ai`,
sent as Basic `api:<key>`) reads and writes every project the user or
service account can reach. That includes model artifacts, datasets, run
logs and Weave traces of agent sessions, and those often contain prompts and
data.

## Supported shape

Sources:

- **Prefix, R5.** A W&B-authored test constant in
  [`wandb/weave-claude-code`](https://github.com/wandb/weave-claude-code/blob/8c4111adbafe7abf15312b3188eb69a0b7bf8f79/tests/config-set-masks-secrets.test.ts#L13)
  begins `wandb_v1_`. R5 gives a provider test fixture the weight of a docs
  example.
- **Length.** The docs say
  "[W&B now issues longer API keys (about 86 characters)](https://docs.wandb.ai/support/models/articles/why-does-my-api-key-fail-with-must-be-40-characters)".
  The key page adds that "Key ID: the first part of the key".
  [wandb/wandb#10688](https://github.com/wandb/wandb/pull/10688) (released in
  0.22.3) parametrizes its validator tests with keys of 39, 40 and **86**
  characters. The Weave PR #5732 fixtures also use 86-character keys (R5).
- **Alphabet, R1.** The current SDK validator
  ([`validation.py`](https://github.com/wandb/wandb/blob/98f93d636e523bf6e195a2a154f23ba8775623a9/wandb/sdk/lib/wbauth/validation.py#L26-L63))
  requires the secret to fullmatch `[\w-]+`. Its error text says a key "may
  only contain the letters A-Z, digits and underscores". A source comment
  adds that dashes are allowed only because the on-prem `<host>-` prefix is
  split with `split()`.

**Re-checked 2026-09-28** (R1 and R5 hinge on these):

- `validation.py` at `98f93d6` has the `[\w-]+`, 40+ rule and the error text;
- the #10688 test patch contains `"X" * 39`, `"X" * 40` and `"X" * 86`;
- the weave-claude-code constant begins `wandb_v1_` (44 characters in total,
  placeholder-grade; it establishes the prefix only);
- the docs page still says "about 86 characters".

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `wandb_v1_` | provider test constant (R5) | T1 |
| Total length | exactly 86 (body 77) | SDK and Weave test fixtures of 86 (R5) + docs "about 86" | T1 by example |
| Alphabet | `[A-Za-z0-9_]` | provider validator + its error text (R1) | T1 |
| Internal split `_` after 27 | not required | trufflehog v2, Kingfisher, Poltergeist only | T2 (not used) |

The contract does **not** require the 27/`_`/49 split. That split is
scanner-only, and the validator's underscore-inclusive alphabet already
admits it. Requiring it would narrow the grammar on T2 evidence.

**The "about 86" hedge.** The docs word is soft, but every provider test that
exercises a new key uses exactly 86, and every scanner rule agrees on 86. A
key of another length gives a false negative, which is today's status quo in
bare, chat and JSON `"token"` contexts. It gives no false positive. The
optional issuance check below resolves the hedge. It is recommended, but it
does not block the contract.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Legacy 40 lowercase hex (optionally `<host>-` + 40) | SHA-1 and git-SHA shaped, with no anchor. Generic context already redacts it under `WANDB_API_KEY=` (measured). A keyword-gated #868-style row is possible later; it is not part of this contract |
| Internal client JWTs accepted as keys | `jwt` detector |
| OIDC identity-token files (`WANDB_IDENTITY_TOKEN_FILE`) | a different credential |
| `wandb_v1_` + a short or placeholder body (the 44-character test constant, `wandb_v1_...`) | fails the exact 86 |

**On-prem host prefix.** Self-managed keys are `<host>-<key>`, and the Weave
fixtures include `local-` + 86. The leading boundary for this family is
`[A-Za-z0-9_]` (not `-`). So `local-wandb_v1_…` yields a finding on the
`wandb_v1_…` part, and the public host label is left out.

## Overlap and output policy

- **Existing detectors.** None claims `wandb_v1_`. Measured on `main`:
  - env, `export`, `X-API-Key`, JSON `api_key` and the SDK keyword argument
    give `contextual_secret`, high;
  - Bearer gives `bearer_token`, high;
  - bare, chat and JSON `"token"` are missed.
  - The legacy 40-hex key behaves the same in the named contexts.
- **New output.** Provider type, `Confidence::High`, `ALWAYS_REDACT_TYPES`.
- **`generic-token` deferral.** `wandb` is **not** added. The legacy 40-hex
  key depends on generic context, and deferral would silence it.

## Implementation notes

Use `KnownFormatProviderDetector` with
`PrefixShape::exact("wandb_v1_", 77, pattern::is_alnum_underscore, …)`. Use a
detector-specific boundary: `[A-Za-z0-9_]` before the prefix, and
`[A-Za-z0-9_-]` after the body.

Signals: `wandb-fixture-prefix`, `wandb-fixture-length`.

## Test axes

**Positives:**

- every context in the re-rank's probe list;
- `WANDB_API_KEY=` in `.env`;
- `wandb.login(key="…")`;
- a `.netrc` `password` line for `api.wandb.ai`;
- `local-` + key (finding on the key part only);
- a body containing `_` at offset 27 and a body with no inner `_` (both
  claimed).

**Near-miss twins:**

- total 85 or 87;
- a `-` inside the body;
- `WANDB_V1_`;
- `wandb_v2_`;
- `wandb-v1-`;
- a leading glue byte (`xwandb_v1_…`, `_wandb_v1_…`);
- a trailing glue byte.

**Benign:**

- `wandb_v1_...` and the 44-character test constant shape;
- a bare 40-hex git SHA;
- `WANDB_API_KEY=${WANDB_API_KEY}`;
- `wandb_version_1_migration` identifiers.

## False-positive / false-negative boundary

- **Accepted false negatives:**
  - new keys that are not exactly 86 (the hedge);
  - legacy 40-hex keys outside named contexts;
  - a future `wandb_v2_`.
- **Accepted false positives:** `wandb_v1_` + exactly 77 `[A-Za-z0-9_]` that
  is not a key, for example a long snake_case identifier of exactly that
  width. That is rare. Unlike `ak_`, the 9-byte prefix is itself specific.

## Issuance checklist (recommended confirmation; structure only)

For one user key and one service-account key created today, record:

- total length (expect 86);
- whether each begins `wandb_v1_`;
- the offset of any further `_`;
- alphabet classes;
- whether the displayed Key ID equals the leading `wandb_v1_` + 27;
- `rawValueRetained: false`, revoked.

A length other than 86 re-opens the contract with the observed value, and
the detector does not land at 86.
