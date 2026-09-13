# Risk-based evidence requirements and exception rules

Issue [#102](https://github.com/redact-secret/redact-secret/issues/102)
(tracking-key `dacd-f1-t2`, under Epic [#96](https://github.com/redact-secret/redact-secret/issues/96))
asks for the minimum evidence a row of the coverage baseline
([`detector-inventory.json`](./detector-inventory.json)) must show before it
can honestly resolve, and the rule for when a row may instead resolve to
`not-applicable` or `intentionally-unsupported`.

This document defines that model. It does not itself change any generator or
CI gate:

- Encoding these requirements into the canonical corpus schema so they are
  machine-validated is issue [#103](https://github.com/redact-secret/redact-secret/issues/103)
  (tracking-key `dacd-f1-t3`) — see `conformance/schema.ts`'s
  `CanonicalCoverageDeclaration`/`validateCanonicalCoverageDeclarations` and
  the encoded result, [`docs/coverage/coverage-declarations.json`](./coverage-declarations.json).
- Making drift from this model a CI failure is issue
  [#104](https://github.com/redact-secret/redact-secret/issues/104).

Everything below is stated in terms of vocabulary the corpus already has
(`conformance/schema.ts`'s `kind`, `tier`, `support`, `contexts`, `mutation`,
`resource`, and the lifecycle `surface`/`operations`) and the baseline's own
`specificity` and `consumers` — no new field is invented here.

## 1. Behavior classes

The issue names five behavior classes. Each maps onto vocabulary the corpus
and baseline already carry:

| Behavior class | What it covers | How a row belongs to it |
|---|---|---|
| **provider** | A fixed vendor-issued token grammar (prefix + charset + length) — matching does not depend on where the token sits. | `detector-inventory.json` entries with `specificity: "provider"` (16 of the 22 declared types: `aws-access-key`, `github-token`, `gitlab-token`, `openai-token`, `anthropic-token`, `shopify-token`, `vault-token`, `stripe-token`, `slack-token`, `pypi-token`, `huggingface-token`, `docker-token`, `cloudflare-token`, `digitalocean-token`, `linear-token`, `supabase-token`, `vercel-token`). |
| **structural** | A shape-based grammar with no vendor prefix: the pattern itself (PEM block, JWT's three dot-separated segments, a URI's `scheme://user:pass@host` shape, an HTTP `Bearer <token>` header) is the whole signal. | `specificity: "private-key"` or `"structural"` (`private-key`, `jwt`, `bearer-token`, `connection-string`). |
| **contextual** | Detection confidence is driven by the surrounding text, not by the value's own shape (`key = <high-entropy-value>`, `Authorization: <scheme> <value>`). | `specificity: "contextual"` (`generic-token`'s two types: `contextual_secret`, `authorization_credential`). |
| **incremental** | Whole-input scan results reproduced identically across UTF-8/UTF-16 partitions, plus session lifecycle (append/finalize/abort, resource limits, error codes). | Not a `types` row — it is the `incremental` and `stream` values of `CanonicalLifecycleFixture.surface`, evidenced by `incremental-corpus.json` and `incremental-lifecycle-corpus.json`. |
| **binding-edge** | Whether a binding surface (CLI, Node addon, Python, WASM) agrees with the Rust core after translating offsets, redacting, or reporting failure in its own native shape. | The `consumers` array in `detector-inventory.json` (9 declared consumer test files) plus `unicode-conversion-corpus.json` and `error-codes.json`. |

`provider`, `structural`, and `contextual` partition the 22 `types` rows
completely — every declared type belongs to exactly one class, by its own
`specificity` field. `incremental` and `binding-edge` are cross-cutting: they
do not own rows of their own, they own the `consumers` array and the
lifecycle/unicode corpora, and they reuse rather than re-derive the
grammar-level evidence the other three classes already produced (see §4).

## 2. Evidence dimensions

The issue names nine dimensions. Each is defined here as a concrete,
already-representable fact about a fixture — not a new concept:

| Dimension | Definition | Corpus evidence |
|---|---|---|
| **positive** | A true match: the detector fires and the finding's detector, type, confidence, specificity, and UTF-8 byte span are all asserted. | `kind: "positive"`, `support: "supported"`. |
| **near-miss negative** | An input adjacent to the true grammar (wrong prefix, wrong alphabet, wrong length, inserted whitespace) that must *not* match. | `kind: "negative"` (`tier: "negative"`), or `support: "intentionally-unsupported"` when the near-miss is a known, accepted gap rather than a correctness requirement. |
| **boundary** | An input at the accepted/rejected edge of the detector's *own* grammar — a length threshold, a required prefix character, a scheme's own validity rule. | `kind: "boundary"`. In this corpus these are frequently produced as one grammar-mutation family: an accepted form beside its boundary-kind rejected neighbor (see the `mutation-github-*` fixtures). |
| **malformed** | Input that is structurally broken, not merely grammar-adjacent — invalid percent-encoding, unpaired UTF-8 continuation bytes — which the scanner must survive without a corrupted or crashing result. | `tier: "malformed"` on the whole-input surface; `appendBytesHex` on the `stream` surface (the only surface allowed to carry invalid UTF-8). |
| **overlap** | Two or more candidate matches contend for the same byte range; evidence pins which one the policy keeps. | `kind: "overlap"`. |
| **host-context** | The lexical environment around an otherwise-identical value (`.env` line, JSON value, shell argument, source-code literal, HTTP header, log line, prose). | `CanonicalFixture.contexts`. |
| **range** | UTF-8 byte / UTF-16 code-unit offset correctness across encoding boundaries, in particular an astral (surrogate-pair) character immediately before, inside, or after a finding. | `unicode-conversion-corpus.json`, plus every `expected.start`/`expected.end` landing on a real code-point boundary (`utf8BoundaryOffsets`, enforced by `validateCanonicalFixtures`). |
| **incremental** | The same whole-input result reproduced at every streaming/UTF-16 partition, and a session's lifecycle (accepting → finalized/aborted/failed) under append/finalize/abort and declared resource limits. | `incremental-corpus.json` (partition invariance) and `incremental-lifecycle-corpus.json` (lifecycle, limits, error codes). |
| **adversarial** | A pathological or hostile input bounded and verified not to exceed declared resource caps. | `kind: "adversarial"` (`tier: "adversarial"`), which `validateCanonicalFixtures` requires to carry a `resource` expectation (`maxInputBytes`, `maxFindings`, `maxRuntimeMs`). |

## 3. Avoiding the detector-by-context Cartesian product

22 declared types times 22 host contexts is 484 cells; requiring a positive
fixture in every one would multiply fixture count for no additional
assurance whenever context-embedding behavior is orthogonal to which
provider's prefix a value happens to carry. The model instead requires
**representative lexical classes**, not literal contexts, and scopes the
requirement to where context actually changes behavior:

**The 22 `CanonicalHostContext` values partition into five representative
classes**, each with a lexical justification, a named representative member,
and its own gap ledger, defined in
[`host-context-classes.md`](./host-context-classes.md) (issue #110) — this
section only summarizes the class names so the risk-scoping rule below reads
standalone:

| Class | Contexts |
|---|---|
| structured-data-kv | `dotenv`, `json`, `yaml`, `toml` |
| shell-invocation | `shell`, `powershell`, `docker-compose`, `github-actions`, `terraform`, `kubernetes` |
| source-code | `javascript`, `typescript`, `python` |
| wire-and-log | `http`, `curl`, `log`, `terminal`, `stack-trace` |
| prose-and-markup | `chat`, `markdown`, `xml`, `plain-text` |

**The requirement is risk-scoped by behavior class**, because context changes
what a `provider`/`structural` detector sees far less than it changes what a
`contextual` one sees:

- **provider and structural**: matching is grammar-driven and
  context-independent by design — a `ghp_...` token is the same match whether
  it sits in JSON or a shell script. The requirement is at the **class
  level**: at least one member detector of the class must carry supported
  positive evidence in a context from each of the five representative
  classes. Every other member of the same class defaults to a single
  `plain-text` fixture and inherits the rest. Today `github-token` (22
  contexts) is that representative for `provider`; a member may still earn
  extra, *targeted* context evidence beyond the default when its own grammar
  interacts with a context differently — `connection-string` additionally
  carries a `log` fixture because connection strings leak into logs at a
  materially higher rate than other provider-shaped secrets.
- **contextual**: the type's own name says confidence is host-context
  dependent, so this is exactly the class where context is not
  interchangeable. The requirement is at the **type level**: each contextual
  type needs its own representative-class coverage, not a borrowed one. Both
  contextual types now meet this requirement with their own evidence; see §6.

Per-scheme evidence (where a type declares `schemes`) is not subject to this
rule: a type's scheme set is small and closed (`connection_string_password`
has 10, `authorization_credential` has 2), so requiring positive evidence for
every declared scheme is not a combinatorial risk and the generator already
tracks it exhaustively, per scheme, today.

## 4. Requirement matrix

`●` required · `○` representative-class-only (see §3) · `—` not-applicable,
owned by another class (bounded rationale: `owned-elsewhere`, §5) · `pending`
means required and currently unmet for at least one row (§5).

| Dimension | provider | structural | contextual | incremental | binding-edge |
|---|---|---|---|---|---|
| positive | ● | ● | ● | — (reuses the owning type's) | — (reuses the canonical corpus's) |
| near-miss negative | ● | ● | ● (heightened — entropy/context heuristics over-match more easily than a fixed grammar) | — | — |
| boundary | ● | ● (plus per-scheme boundary for schemed types) | ● | — | — |
| malformed | ● | ● | ● | ● (invalid-UTF-8 stream chunks) | ● (error-code parity, `error-codes.json`) |
| overlap | ● | ● | ● | — | — |
| host-context | ○ (class-level) | ○ (class-level) | ● (type-level, §3) | — | — |
| range | ○ (astral-neighbor stress is class-level, not per-type) | ○ | ○ | ● (partition must not split a surrogate pair) | ● (this *is* the class — offset translation agreement) |
| incremental | — | — | — | ● | ● (only for consumers on the `incremental`/`stream` surface) |
| adversarial | ● | ● | ● | ● (`adversarial_bounds.rs` covers both whole-input and incremental surfaces) | ● (same consumer) |

## 5. The exception rule: a bounded rationale

A row (or dimension cell) may resolve to `not-applicable`,
`intentionally-unsupported`, or a documented `pending` gap instead of
`supported`, but only by citing one of a fixed, small set of rationale
codes — never free-form prose standing alone. This is what keeps an
exception *bounded*: a reviewer checks the code applies, not an essay.

| Code | Meaning | Example in this baseline |
|---|---|---|
| `no-concept` | The dimension's underlying concept does not exist for this row. | `private_key`'s `schemes: null` — private keys have no accepted-URI-scheme concept, so the scheme dimension is `not-applicable`, not unresolved. |
| `owned-elsewhere` | The dimension is required by the matrix but is evidenced once, by a different class, and re-deriving it here would duplicate evidence without adding assurance. | `incremental`'s `positive` cell: the finding being partitioned was already positive-evidenced by its owning `provider`/`structural`/`contextual` row; requiring a second, independent positive fixture here would be Cartesian-product busywork the matrix deliberately excludes. |
| `single-detector-family` | Two declared types share one detector, so evidence gathered under one type's fixtures (adversarial caps, malformed survival) already covers the other. | `contextual_secret` and `authorization_credential` may share `generic-token` evidence for `adversarial` and `malformed`. Overlap is type-specific because the evidence must pin which finding type wins; it cannot be borrowed from a sibling type. |
| `pending` | The dimension is genuinely required, currently unmet, and tracked with an owning backlog item — an honest gap, not an invented pass. | `authorization_credential`'s `positive` and `boundary` cells: tracked as `C/F-03` in [`docs/audits/deferred-quality-backlog.md`](../audits/deferred-quality-backlog.md), which already states the exact missing evidence (one supported positive fixture per scheme, one boundary fixture at `MIN_AUTHORIZATION_VALUE_LENGTH`). |

A row or cell with no applicable code from this table is not exempt — it
must carry real evidence or resolve to `unresolved`, the corpus's own honest
default for a reachable type with no evidence (see `docs/coverage/README.md`).

## 6. Resolving every declared row without invented evidence

Applying §4's matrix and §5's exception codes to the current baseline
(`docs/coverage/detector-inventory.json`, joined by
`scripts/generate-coverage-inventory.py` into
`docs/coverage/inventory-report.json`):

### `types` rows (22)

- **16 provider rows** (`aws_access_key_id` … `vercel_token`): each already
  carries `positive`, `near-miss negative` (`negative`), `boundary`,
  `malformed`, `overlap`, and `adversarial` evidence
  (`evidence.kindsWithSupportedEvidence` reports all four `kind` values with
  `support: "supported"` present for every one). `host-context` and `range`
  resolve `○` under `owned-elsewhere`/class-level: `github_token` supplies
  the class's 5-lexical-class representative (22 contexts exercised),
  `aws_access_key_id` supplies a second sample (3 contexts), and the
  remaining 14 correctly default to their single `plain-text` fixture. No
  row needs invented context fixtures of its own. **All 16 resolve
  `supported`.**
- **5 structural rows** (`private_key`, `jwt`, `bearer_token`,
  `connection_string_password`, `otpauth_secret`): same dimension coverage as
  provider.
  `private_key`'s scheme dimension resolves `not-applicable` under
  `no-concept` (`schemes: null`), not `unresolved` — the current baseline
  already encodes this correctly. Since issue
  [#186](https://github.com/redact-secret/redact-secret/issues/186),
  `connection_string_password` is the structural class's representative for
  `host-context`: supported positive fixtures cover `dotenv`, `shell`,
  `javascript`, `log`, and `markdown`, while the other four rows resolve the
  class-level dimension through `owned-elsewhere`. It also resolves each of
  its declared schemes independently: since issue
  [#108](https://github.com/redact-secret/redact-secret/issues/108) (deepened
  scheme and escaping coverage), every declared scheme (`postgres`,
  `postgresql`, `mysql`, `mariadb`, `mongodb`, `mongodb+srv`, `redis`,
  `rediss`, `amqp`, `amqps`) carries its own positive fixture, plus
  credential-absent, malformed-authority, and boundary fixtures naming that
  scheme, so none defaults to a borrowed or unresolved state. The same pass
  also dispositioned the escaping surface the scheme matrix does not itself
  cover: percent-encoded reserved delimiters kept undecoded in the selected
  span, an unescaped `@` or `/` in userinfo truncating or invalidating the
  authority, `?`/`#` terminating the authority the same as `/`, a rejected
  IPv6 host with a non-hex group, and a rejected non-ASCII (Unicode/IDN)
  host label. **All 5 resolve `supported` at the type level**, and
  `connection_string_password`'s per-scheme ledger now shows full coverage
  rather than partial.
- **2 contextual rows** (`contextual_secret`, `authorization_credential`,
  both on `generic-token`): `single-detector-family` is limited to shared
  detector robustness such as `malformed` and `adversarial`; overlap evidence
  must resolve independently for each finding type. `contextual_secret` has
  direct `positive`, `near-miss negative`, `boundary`, `overlap`, and (since
  issue #111) `host-context` evidence and resolves `supported` on every dimension the `contextual`
  behavior class requires — its own positive fixtures now reach all five
  representative classes (`structured-data-kv`, `shell-invocation`,
  `source-code`, `wire-and-log`, `prose-and-markup`; see
  [`host-context-classes.md`](./host-context-classes.md) §4-5), which is
  what §3's type-level rule requires for the `contextual` class.
  Since issue [#190](https://github.com/redact-secret/redact-secret/issues/190),
  `authorization_credential` likewise has direct positive evidence in
  `dotenv`, `shell`, `javascript`, `log`, and `markdown`, reaching all five
  representative classes at the type level. Its boundary, near-miss,
  malformed, range, and overlap evidence remains direct or bounded under the
  matrix; its overlap fixture is not borrowed from `contextual_secret`.

### `consumers` rows (9, the `binding-edge` class)

Each declared consumer path owns `range` (offset-translation agreement) and,
for the two whose `role` names the incremental/stream surface
(`crates/secret-scan-core/tests/incremental_partitions.rs`,
`bindings/python/tests/test_incremental.py`), the `incremental` dimension;
`crates/secret-scan-core/tests/adversarial_bounds.rs` owns `adversarial` for
both surfaces. None needs its own `positive`, `near-miss negative`,
`boundary`, `overlap`, or `host-context` evidence — those cells resolve
`owned-elsewhere`, because every consumer re-asserts findings the canonical
corpus already positive-evidenced under a `provider`/`structural`/
`contextual` row; re-deriving grammar-level evidence per binding would be
exactly the Cartesian-product duplication §3 rules out. All 9 declared
consumer paths currently exist on disk (`generate-coverage-inventory.py`'s
own structural check), so none needs a `pending` exception either.

**Result: every one of the 22 `types` rows and 9 `consumers` rows resolves
under this model using evidence the corpus already has or a `no-concept` or
`owned-elsewhere` exemption implied by its own declared shape. No pending
dimension remains. Nothing here required inventing a context or scheme that
does not already exist in the corpus or the baseline.**
