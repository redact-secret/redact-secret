# RSS-1 — Redact Secret behavior specification

**Status:** draft · **Revision:** RSS-1 · **Contract:** [`conformance/`](../conformance/README.md) · **Schema:** [`conformance/schema.json`](../conformance/schema.json) · **Inventory:** [`docs/coverage/detector-inventory.json`](../docs/coverage/detector-inventory.json)

RSS-1 defines what Redact Secret does to a string: which ranges it classifies as
credentials, how it resolves conflicts between them, what a policy may decide,
what the sanitized output looks like, and what a bounded incremental session must
reproduce. It is written in enough detail that a JavaScript, Python, Rust or CLI
consumer can predict the exact output before running it. The
[conformance corpus](../conformance/README.md) is the executable form of this
document; where the two disagree, the corpus wins and this document is a defect.

The reason for a specification rather than four ports is drift. This product took
the opposite route from a multi-implementation spec: there is exactly **one**
implementation — the Rust core — and the bindings only convert values, callbacks,
errors and string ranges. So this document is not a porting guide. It is the
statement of what that single core guarantees, what it deliberately refuses to
guarantee, and which of its behaviors a binding is forbidden to reinterpret.

**Key words.** MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as in RFC 2119.

**Safety rule over the whole document.** Every credential-shaped string here, in
the corpus, in tests and in diagnostics is unmistakably synthetic or revoked. No
normative artifact of this project may carry a real credential.

## Contents

- [1. Why one core and many bindings](#1-why-one-core-and-many-bindings)
- [2. The trust boundary](#2-the-trust-boundary)
- [3. Ranges, findings and coordinates](#3-ranges-findings-and-coordinates)
- [4. The scan pipeline](#4-the-scan-pipeline)
- [5. Overlap resolution](#5-overlap-resolution)
- [6. Detection coverage](#6-detection-coverage)
- [7. Detector profiles](#7-detector-profiles)
- [8. Policy](#8-policy)
- [9. Redaction and placeholders](#9-redaction-and-placeholders)
- [10. Incremental sanitization](#10-incremental-sanitization)
- [11. Limits and failure modes](#11-limits-and-failure-modes)
- [12. Conformance](#12-conformance)
- [13. Surface contracts](#13-surface-contracts)
- [14. Deliberate deviations and non-goals](#14-deliberate-deviations-and-non-goals)
- [15. Change control](#15-change-control)

---

## 1. Why one core and many bindings

A detector written as a regular expression does not mean the same thing in four
languages. Lookaround is available in JavaScript and Python and absent from RE2
and Rust's `regex`; `\b`, `\d` and `\w` are ASCII in some engines and Unicode in
others; `$` matches before a trailing newline in Python and at end of input
elsewhere. Every one of those is a silent behavior difference, and a redactor
that behaves differently per language is worse than no redactor, because the team
stops being able to reason about what leaves the process.

Redact Secret removes the ambiguity at the root: detection exists once, in Rust,
and every surface calls it.

```text
JavaScript        Python        Rust          CLI
     |               |            |             |
  N-API / wasm      PyO3          |             |
     +---------------+------------+-------------+
                     |
                     v
           crates/secret-scan-core
                     |
      detect -> resolve -> policy -> redact
                     |
                     v
           safe text + safe metadata
```

A binding MUST NOT reimplement detection, overlap resolution, policy defaults,
redaction or incremental retention. It MAY only convert host values, callbacks,
errors and string ranges, and it MUST preserve the selected span while doing so.

The core MUST be side-effect free: no runtime network access, no filesystem
access, no environment lookup, no telemetry, no secret storage, no model
invocation, no UI work, and no clock- or locale-dependent behavior. The same
input, registry, policy and formatter MUST produce byte-identical output on every
supported surface and on every run.

## 2. The trust boundary

Two paths carry credentials, and the product exists to keep them apart.

```text
Intentional credential path
  User -> Credential Manager -> Secret Vault -> Provider Gateway -> Provider

Untrusted text path
  User / Tool / MCP / Log -> Redact Secret -> Sanitized Text
                                   -> Conversation / Context / Storage / Model
```

A vault MAY hold secrets. Conversation history, model context, knowledge stores,
logs, telemetry and diagnostics MUST NOT.

Client-side scanning is preventive UX only. **Server-side scanning is the
authoritative enforcement boundary** and MUST run even when a client also scans,
because direct API clients, older or modified clients, CLIs, SDKs, MCP
integrations and agents can all bypass the client. An application MUST NOT log
raw request or tool bodies before scanning them.

No finding, error, callback argument, fixture, snapshot, log line or diagnostic
may expose matched plaintext. This is structural rather than conventional: the
expectation object in the corpus schema is closed (§12.2), so the format has no
field in which plaintext could travel.

## 3. Ranges, findings and coordinates

### 3.1 Range units

The core works in UTF-8 byte offsets. Each binding converts to its host's natural
unit without changing the selected span.

| Surface | Public range unit | `RANGE_UNIT` |
|---|---|---|
| Rust crate | UTF-8 bytes | `utf8-bytes` |
| Node.js | UTF-16 code units | `utf16-code-units` |
| Browser JavaScript | UTF-16 code units | `utf16-code-units` |
| Python | Unicode code points | `unicode-code-points` |
| CLI | UTF-8 bytes | `utf8-bytes` |

Ranges are half-open — `start` included, `end` excluded — and always refer to the
**original** input, even when the sanitized output has a different length. A byte
offset MUST fall on a UTF-8 code point boundary; an offset that would split a
multi-byte character is invalid.

Numeric positions MUST NOT be copied between runtimes without converting against
the same input. One astral character is 2 UTF-16 code units, 1 code point and 4
UTF-8 bytes, so the three units diverge most sharply there; conversion is asserted
against `fixtures/unicode-conversion-corpus.json`, which places a
supplementary-plane character before, inside and after a finding.

### 3.2 Findings

A finding carries `id`, `type`, `detector`, `confidence`, `action`, `start` and
`end`. There is no field for the matched value.

Within one scan, findings MUST be ordered by position in the original input and
numbered from `finding-1` with no gaps. IDs are scan-local: they MUST NOT be
treated as stable identities across changed inputs or separate scans. An
incremental session uses absolute positions into the whole session input and
continuous numbering across appends; a CLI multi-file run renumbers so IDs are
unique across the run.

### 3.3 Confidence, specificity, action

`confidence` is `high`, `medium` or `low`. It describes the strength of the
evidence, never a probability and never a claim that the credential is live.

`specificity` is the conflict-resolution rank of the evidence, weakest first:

| Value | Meaning |
|---|---|
| `entropy` | Entropy-only heuristic; also the default when a candidate declares none |
| `contextual` | Credential assignment (`API_KEY=…`) |
| `structural` | Structural syntax (`Authorization: Bearer …`, connection URLs) |
| `provider` | Provider-specific token format |
| `private-key` | Private key or comparably specific material |

A candidate that omits specificity MUST default to `entropy`, so an unclassified
detector can never displace a classified one.

`action` is `block`, `redact`, `warn` or `allow`. The first two replace text; the
last two leave the input unchanged.

## 4. The scan pipeline

```text
UTF-8 input
  -> built-in detector registry
  -> candidate validation and normalization
  -> deterministic priority and overlap resolution
  -> findings with stable IDs and source ranges
  -> policy evaluation over safe metadata
  -> one-pass redaction
  -> sanitized text + findings without matched values
```

The core MUST NOT normalize or decode input before detection where doing so would
change source coordinates or lexical meaning. A decoded view would report ranges
that do not exist in the caller's string, so detectors inspect the original UTF-8
text and emit candidate ranges into it.

Validation then rejects a candidate that is malformed, empty, out of bounds, not
char-aligned, or whose type name is not a valid identifier. Two further rejections
exist specifically to close leak channels:

- A candidate whose matched text is **exactly** its own public type name or
  detector id is rejected. A public metadata field that mirrors input is a way for
  plaintext to escape through a field that is supposed to be safe.
- A candidate whose matched text is **exactly equal** to a published vendor
  placeholder literal — AWS's documented `AKIAIOSFODNN7EXAMPLE` and its paired
  example secret — is discarded. Matching is whole-candidate equality only, never
  substring and never pattern, so the carve-out cannot be used as a template to
  conceal part of a real secret.

Entropy is a supporting signal throughout. It MUST NOT on its own justify
classifying arbitrary random-looking text as a secret.

## 5. Overlap resolution

Two detectors will claim overlapping ranges, and the choice between them must not
depend on iteration order, hashing or timing. Candidates are therefore ranked on a
**total** order and resolved greedily.

Precedence, in order:

1. **specificity**, descending (§3.3);
2. **confidence**, descending (`high` > `medium` > `low`);
3. **span width**, narrower first;
4. **detector registration order** in the registry, ascending;
5. **candidate emission order** within a detector, ascending.

The last two keys are unique per candidate, so the ordering is total. An
implementation MUST NOT add a further tie-breaker and MUST NOT depend on hash-map
or set iteration order anywhere in this path.

Resolution walks that order once and accepts a candidate only when its range is
disjoint from every already accepted range. A rejected candidate does not reopen
an earlier decision. Survivors are then sorted by position and assigned one-based
IDs.

Two consequences are deliberate. Specific provider or structural evidence outranks
broad contextual evidence, which favors precision and bounded redaction at the
cost of missing truncated, novel, malformed or unsupported variants. And because
the narrower span wins a tie, the pipeline bounds over-redaction rather than
maximizing the number of removed characters.

## 6. Detection coverage

### 6.1 Families

| Family | Supported structure |
|---|---|
| Private keys | PEM-style private-key blocks |
| Provider credentials | AWS access-key IDs; GitHub, GitLab, OpenAI, Anthropic, Shopify, modern Vault patterns |
| Additional provider formats | Qualified Stripe, Slack, PyPI, Hugging Face, Docker Hub, Cloudflare, DigitalOcean, Linear, Supabase, Vercel, npm, SendGrid, Google Cloud/Gemini, Microsoft Entra client secret, Azure DevOps PAT, Notion, Atlassian Cloud, Twilio, Telegram Bot API, Discord bot, Sentry, Datadog, Grafana, New Relic |
| Authorization | JWT, Bearer, Basic and Token credentials |
| Context | Credential assignments, including AWS secret-access-key and session-token names |
| Connections | Credential-bearing `postgresql`, `postgres`, `mysql`, `mariadb`, `mongodb`, `mongodb+srv`, `redis`, `rediss`, `amqp`, `amqps`, `azure` URLs |
| One-time password provisioning | `otpauth://totp` and `otpauth://hotp` with base32 shared secrets |

This is a family overview, not a promise to match every token each provider
issues. The exact supported grammars are whatever `synchronous-corpus.json` pins.
The complete set of emittable finding types, joined to its default-policy class,
is `docs/coverage/detector-inventory.json`; a build MUST fail when the registry,
the emitted types or the default policy drift from that file.

### 6.2 Declared limits

The core never contacts a provider, so it cannot and does not establish whether a
credential is active, expired or valid. Detection answers only what a range looks
like.

Accordingly:

- An empty result means no supported pattern matched. It MUST NOT be presented as
  certifying that text is secret-free.
- Synthetic text imitating a supported credential will match, and a harmless
  assignment to a credential-like name may be classified from context.
- Truncated, unusually short, new, unsupported, encoded or differently formatted
  credentials may be missed.
- The generic name `token`, alone, is deliberately ignored.
- This is not a general DLP tool and not a repository-history scanner.

## 7. Detector profiles

| Profile | Membership | Availability |
|---|---|---|
| `full` | Every built-in detector. Default and compatibility baseline. | Every surface |
| `common` | Private keys, JWT/Bearer authorization, connections, one-time-password provisioning, and the generic credential-assignment context detector. Omits both provider rows entirely. | JavaScript (`@redact-secret/core/common`) and Rust (`DetectorRegistry::with_common_built_in`) only |

`common` exists for size- and latency-sensitive **preventive** consumers — browser
UX, small agent or tool processes. It MUST NOT introduce a false positive relative
to `full`; it may only drop candidates `full` would have reported.

Its false-negative tradeoff is confined to provider tokens. A bare provider token
with no surrounding structural or contextual evidence is not detected at all, and
a provider token that *is* caught by a `common` detector's context is reported
under that detector's type and confidence instead of the provider-specific one —
`warn` where `full` would `redact`.

A surface that exposes a profile MUST expose which profile it was built from
(`PROFILE` in JavaScript, `DetectorRegistry::profile()` and
`IncrementalSanitizer::profile()` in Rust). JavaScript `initialize()` MUST reject
with `INITIALIZATION_FAILED` when the loaded artifact reports a different profile
than the entry point that loaded it — the same detail-free rejection an unusable
or version-mismatched artifact gets.

Because `common` findings differ from `full` by design, they are pinned in
`fixtures/common-profile-expectations.json` rather than derived at runtime.

## 8. Policy

Detection answers *what a range appears to be*. Policy independently answers *what
to do about it*. The two MUST stay separable: adding a detector MUST NOT change
policy semantics, and tightening a policy MUST NOT change detector behavior.

A policy callback receives immutable finding metadata and a policy context. It
MUST NOT receive the input or the matched value — which is also what makes a
custom policy safe to run inside a host that must not see plaintext.

The default policy has three classes:

| Class | Rule |
|---|---|
| `block` | `private_key`, at any confidence |
| `always-redact` | 36 known credential types, at any confidence |
| `confidence-gated` | Everything else: `redact` at `high`, otherwise `warn` |

The `always-redact` set is:

```text
anthropic_api_key                   atlassian_api_token
authorization_credential            aws_access_key_id
azure_devops_personal_access_token  bearer_token
cloudflare_api_token                connection_string_password
digitalocean_token                  discord_bot_token
docker_token                        github_token
gitlab_token                        google_api_key
grafana_cloud_access_policy_token   grafana_service_account_token
huggingface_token                   jwt
linear_token                        microsoft_entra_client_secret
new_relic_user_api_key              notion_integration_token
npm_access_token                    openai_api_key
otpauth_secret                      pypi_api_token
sendgrid_api_key                    sentry_org_auth_token
sentry_user_auth_token              shopify_access_token
slack_token                         stripe_credential
supabase_secret_key                 telegram_bot_token
vault_token                         vercel_token
```

`docs/coverage/detector-inventory.json` is the authoritative copy of that set and
a core test fails when the two disagree, so the list above cannot silently go
stale.

The default policy is deterministic, infallible and independent of policy context
— which is also what makes it valid as an incremental policy, since a progressive
evaluation cannot know the session's final finding count (§10).

A consumer MAY enforce a stricter server-side policy. A policy that returns a
value outside the four actions fails with `INVALID_POLICY_ACTION`; one that throws
fails with `POLICY_FAILURE`.

## 9. Redaction and placeholders

Redaction is a single ordered pass over the selected ranges. Only `redact` and
`block` ranges are replaced; `warn` and `allow` ranges MUST be left
byte-identical.

Default placeholders are `<SECRET_1>`, `<SECRET_2>`, …, where `N` is one-based
among **replaced** findings only — a `warn` or `allow` finding does not consume a
number. A placeholder is a label, not an encoding: it MUST NOT be recoverable to
the removed text.

A custom formatter receives safe metadata and a placeholder index, and its output
is validated. The core MUST reject:

- an empty placeholder;
- a placeholder longer than 256 bytes (`MAX_PLACEHOLDER_LENGTH`);
- a placeholder that **contains any replaced matched value as a substring**,
  checked against every replaced range of 256 bytes or fewer, since a longer value
  could never fit inside a valid placeholder anyway;
- a formatter that fails (`PLACEHOLDER_FAILURE`) or returns an invalid value
  (`INVALID_PLACEHOLDER`).

That third rule is the one that matters: without it, a hostile or careless
formatter could reintroduce the secret into the sanitized output through the very
string meant to remove it.

**Direct redaction.** Findings passed straight to a redaction API are trusted
caller assertions. The core validates their metadata, bounds, char alignment,
ordering, mutual disjointness and placeholder safety, and sorts unsorted input. It
does **not** rerun detection, does not resolve conflicting caller-supplied
findings, and cannot establish that the findings belong to the input passed
alongside them — the caller is responsible for passing the same original input
that was scanned.

`scanAndRedact` MUST equal `scan` followed by `redact` with the same registry,
policy and formatter, for every corpus fixture.

## 10. Incremental sanitization

A secret may cross any chunk boundary, so scanning each chunk independently leaks
it. A session retains unresolved text until its detection window closes, then
emits text and findings. An `append` MAY legitimately return empty text.

**Partition invariance** is the central guarantee. For every fixture in
`incremental-corpus.json`, a bounded session MUST reproduce the whole-input
reference exactly — concatenated text, findings, actions, order, IDs, absolute
ranges and placeholder numbering — at *every* partition of the input:

- every UTF-8 byte boundary, including indices inside a multi-byte code point,
  reached through the same fatal, stateful streaming decoder a byte-oriented host
  must place in front of a core whose string type cannot hold a partial code
  point;
- every host-native string boundary — every Rust `&str` char boundary, every
  JavaScript UTF-16 code unit boundary — plus the maximally fragmented partition
  of one chunk per unit.

Only the *distribution* of safe output across `append` and `finalize` results may
vary. Feeding the whole input in one `append` MUST accept exactly what the
fragmented partitions accept. Partitions are generated deterministically by each
runner and MUST NOT be stored as fixture data.

**Two capabilities do not exist here, by construction**, and a runner records that
rather than asserting an equivalence that cannot hold:

- *custom synchronous detectors* — an incremental session takes no registry,
  because a custom detector declares no retention bound;
- *whole-input count-dependent policies* — the incremental policy context carries
  the finalized index but no total.

A session that has finalized or aborted MUST reject further input with
`INVALID_STATE`.

## 11. Limits and failure modes

Incremental limits are `max_input_bytes`, `max_buffered_bytes`, `max_token_bytes`
and `max_multiline_bytes`. Construction rejects limits where any value is zero,
where `max_token_bytes` or `max_multiline_bytes` exceeds `max_input_bytes`, or
where `max_buffered_bytes` is below the minimum needed to hold the larger of the
token and multiline windows plus the lookaround margin.

Every limit **fails closed**, with the corresponding `*_LIMIT_EXCEEDED` code —
never with truncated-but-successful output, because output that looks complete and
is not is exactly how a partial secret reaches a log.

Whole-input operations have **no implicit resource cap**. The host MUST impose
one.

Every failure uses a stable code and a fixed, input-free message. A message MUST
NOT be derived from input, from a matched value or from file contents. The
registry is `conformance/fixtures/error-codes.json`:

| Surface | Codes |
|---|---|
| incremental | `INVALID_OPTIONS`, `INVALID_LIMITS`, `INVALID_INPUT`, `INPUT_LIMIT_EXCEEDED`, `BUFFER_LIMIT_EXCEEDED`, `TOKEN_LIMIT_EXCEEDED`, `MULTILINE_LIMIT_EXCEEDED`, `DETECTOR_FAILURE`, `POLICY_FAILURE`, `INVALID_POLICY_ACTION`, `PLACEHOLDER_FAILURE`, `INVALID_PLACEHOLDER`, `INVALID_STATE` |
| stream | `INVALID_CHUNK`, `INVALID_UTF8` |

Bindings surface the same code: `SecretScanError` in JavaScript, `SecretScanError`
subclasses in Python, `SecretScanError` in a Rust `Result`. Fixture-validation
diagnostics report only a fixture ID and a stable code.

## 12. Conformance

### 12.1 Fixture format

A fixture requires `id`, `detector`, `kind`, `support`, `tier`, `contexts`,
`input`, `expected` and `note`, and may carry `mutation` and `resource`.

| Field | Domain |
|---|---|
| `kind` | `positive`, `negative`, `boundary`, `overlap`, `adversarial` |
| `support` | `supported`, `intentionally-unsupported`, `not-yet-evaluated` |
| `tier` | `canonical`, `negative`, `malformed`, `contextual`, `adversarial`, `regression` |
| `contexts` | one or more of 22 host contexts: `plain-text`, `dotenv`, `json`, `yaml`, `toml`, `shell`, `powershell`, `docker-compose`, `github-actions`, `terraform`, `kubernetes`, `javascript`, `typescript`, `python`, `http`, `curl`, `log`, `terminal`, `stack-trace`, `chat`, `markdown`, `xml` |

### 12.2 Safe expectations

An expectation carries exactly `detector`, `type`, `confidence`, `specificity`,
`start` and `end`. The object is **closed**: both validators — `schema.ts`'s key
check and `schema.json`'s `additionalProperties: false` — reject any additional
key, so the fixture format itself has no way to carry plaintext into a public
expectation.

A conforming validator MUST also enforce the cross-field invariants JSON Schema
cannot express: no overlapping expectations, and every range within the bounds of
`input`.

### 12.3 Mutation provenance

`operation: "declared-boundary"` marks a hand-authored fixed case; its `seedId` is
a human-assigned per-fixture identity and there is nothing to reproduce beyond the
fixture itself.

Any other `operation` is a claim that a deterministic generator keyed by
`(grammar, seedId, operation, ordinal)` reproduces `input` byte-for-byte. Such a
claim MUST be paired with a small pure generator and a test that regenerates the
set on every run, asserting it is both self-identical (determinism) and
byte-identical to the committed fixtures (reproducibility). `github-classic` and
`docker-token-exact-length` are the existing pairings.

Generators prove provenance; they do not generate the corpus.
`synchronous-corpus.json` stays hand-maintained.

### 12.4 Adversarial resource caps

Every `adversarial`-tier fixture declares `maxInputBytes`, `maxFindings` and
`maxRuntimeMs`. A runner MUST assert all three on the whole-input surface and,
where the language has one, on the incremental surface — including a fragmented
partition, since fragmentation is where an implementation that rescans retained
text degrades.

`maxInputBytes` and `maxFindings` are properties of the fixture and are asserted
exactly. `maxRuntimeMs` describes the shipped optimized build; an unoptimized test
build MAY be held to a fixed, documented multiple (Rust allows 8× for debug and
the declared cap exactly when optimized), but never to a value derived from the
machine it happens to run on. These caps exist to catch superlinear blowup, which
is orders of magnitude, not a constant factor.

### 12.5 Required consumers

Conformance MUST be asserted through **built artifacts**, not only through the
source tree: the N-API addon, the browser WebAssembly artifact in Chromium,
Firefox and WebKit, the CLI binary, the Python extension, and the packed
JavaScript package with its real artifact dependencies.

A runner that converts canonical UTF-8 offsets to its own unit MUST use a
reference conversion **independent of the binding under test** — otherwise a
conversion bug validates itself. Package-consumer qualification records, per
declared Node major and browser engine, the source revision, package artifact
hashes, runtime, command and incremental corpus hash.

### 12.6 Regression intake

Every confirmed false positive or false negative becomes a permanent fixture:

1. Discard the submitted credential value; retain only a safe description of the
   grammar, boundary and host context needed to reproduce the defect.
2. Construct an unmistakably synthetic or revoked replacement **from scratch** —
   never transform, encode, hash, truncate or snapshot the submitted value.
3. Assign a stable fixture ID, the `regression` tier, applicable contexts, safe
   expected metadata, and a note describing the *behavior*, not the reported
   plaintext.
4. Prove the fixture fails before the repair where practical, then passes on every
   affected consumer.
5. Inspect failures and logs so they carry only fixture identity and safe
   metadata. Where safe reproduction is impossible, document the excluded shape
   without retaining the report material.

If the submission is, or might be, an active credential, it MUST NOT enter the
corpus, an issue or a pull request at all. Report it privately through
`SECURITY.md` first, so it never becomes a second exposure of the same material.

Benchmark-originated regressions follow the same steps: minimal whole-input
behavior in `synchronous-corpus.json` at `tier: "regression"`, a matching
incremental case only when chunk boundaries, retained state or finalization can
affect the result, and cross-repository identity plus acceptance gates recorded in
`conformance/benchmark-regressions.json` — `benchmarkCommit` pinning the benchmark
revision alongside the product-side `fixingCommit`. Discovery matrices, generated
variants, competitor output, holdout material and raw results stay in the
benchmarks repository.

## 13. Surface contracts

### 13.1 Operations

| Operation | JavaScript | Python / Rust | Result |
|---|---|---|---|
| Detect and apply policy | `scan` | `scan` | Findings |
| Replace supplied ranges | `redact` | `redact` | Text |
| Both | `scanAndRedact` | `scan_and_redact` | Text and findings |

Rust additionally takes a registry, policy and formatter; Python takes optional
`policy` and `formatter`; JavaScript takes an options object with `policy` and
`placeholderFormatter`. Policy and formatter callbacks are available in every
language. Custom **detector** callbacks are a direct Rust surface only, because a
custom detector declares no retention bound and therefore cannot participate in a
bounded incremental session (§10).

### 13.2 JavaScript initialization

A consumer MUST `await initialize()` before any synchronous scan, redaction,
incremental or adapter operation. The explicit contract exists so that a native or
WebAssembly loading failure is observable at one known point, without making every
scan asynchronous.

Loading failure rejects with `INITIALIZATION_FAILED` and no detail — including on
a musl host, where no glibc addon is published.

The incremental limit properties keep their historical `CodeUnits` names for
compatibility, but their numeric ceilings are enforced by the core as **UTF-8
byte** limits. A caller sizing non-ASCII input MUST measure with `TextEncoder`.

### 13.3 CLI

| Exit | Check mode | Redact mode |
|---|---|---|
| 0 | Every source scanned, no findings | Whole output written successfully |
| 1 | Every source scanned, at least one finding | Unused |
| 2 | Usage, read, UTF-8, limit or write failure | Processing failed; output may be partial |

Check mode flags **any** finding, including `warn` and `allow`. Redact mode
replaces only `redact` and `block` spans, so a successful redaction does not
guarantee that every detected range was removed.

The CLI MUST NOT walk directories recursively and MUST NOT modify files in place;
redaction accepts exactly one input. Standard input is incremental and UTF-8
decoding is strict, so a failure MAY leave a sanitized but **incomplete** prefix on
stdout — a consumer MUST accept output only after exit 0. A run that could not
decode part of its input has not proved that part clean, and therefore exits 2.

`--json` emits `version`, `rangeUnit`, `findingCount`, `sources` and `failures`,
with run-unique finding IDs and UTF-8 byte ranges into each original source.
Neither format prints matched file content; text reports and diagnostics escape
non-printing path characters and backslashes, and JSON decoding recovers the
original path.

Paths and standard input share a total-input bound, but streamed input carries
additional open-line and multiline limits, so a long unbroken line can fail on
stdin while passing as a file. The asymmetry is intended and is documented in
`--help`.

## 14. Deliberate deviations and non-goals

1. **No second implementation.** The TypeScript detector core that once served as
   the behavioral oracle was removed when the Rust core reached parity. Git
   preserves its history; the repository does not maintain a second detector.
2. **No input normalization before detection**, where it would change source
   coordinates or lexical meaning. A decoded view would report ranges that do not
   exist in the caller's string.
3. **No entropy-only classification.** Accepts false negatives on high-entropy but
   unstructured secrets, in exchange for never redacting arbitrary random-looking
   text.
4. **Narrower span wins ties**, bounding over-redaction rather than maximizing the
   number of removed characters.
5. **`common` omits provider detectors entirely** rather than approximating them,
   so the profile difference stays a clean subset instead of a second grammar to
   maintain.
6. **No implicit whole-input cap.** The core imposes no size limit on whole-input
   operations; a host that needs one sets it, and the incremental surface is where
   bounded operation is specified.
7. **No integration packages.** Logging, telemetry, model context and MCP are
   application use cases. The repository ships core APIs and generic examples only
   — no LangChain, OpenTelemetry, pino, Python-logging or MCP package.
8. **`token` alone is ignored**, accepting one false negative to avoid a large
   false-positive class.
9. **No reversible redaction.** There is no vault, no keyed transform and no
   restore path. A placeholder that can be reversed is a secret store with extra
   steps, and this product's output is meant to be safe to keep.

## 15. Change control

A change that alters observable behavior — detector grammar, precedence, a default
policy class, placeholder rules, range semantics, error codes or limit validation
— MUST arrive with its corpus changes in the same commit, and MUST state its
false-positive and false-negative tradeoff.

A behavioral change MUST NOT land in one binding ahead of the others. The core is
the only place it may be made.

Governance of decisions, release authority and branch policy is out of scope here
and lives in `AGENTS.md`, `CONTRIBUTION.md` and `docs/decisions/`.

---

*Released under the MIT licence. Every credential-shaped string in this document
is synthetic or revoked.*
