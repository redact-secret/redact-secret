# Redact Secret Specification

Status: draft · Revision: **RSS-1** · Scope: `crates/secret-scan-core` and every
binding over it (`bindings/node`, `bindings/wasm`, `bindings/python`,
`crates/secret-scan-cli`, `packages/javascript`).

This document is the normative behavioral contract of Redact Secret. It states
what an implementation must do; the executable form of the same contract is the
[conformance corpus](../conformance/README.md), and the two are meant to agree
exactly. Where prose and corpus disagree, the corpus is authoritative and this
document is a defect.

**Key words.** MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be
interpreted as in RFC 2119.

**Machine-readable companions.**

| Artifact | Role |
| --- | --- |
| `conformance/schema.json` | JSON Schema (draft 2020-12) for the fixture format |
| `conformance/schema.ts` | Same shape plus the cross-field invariants JSON Schema cannot express |
| `conformance/fixtures/synchronous-corpus.json` | Whole-input detector, exclusion, overlap, adversarial corpus |
| `conformance/fixtures/incremental-corpus.json` | Incremental references, asserted at every partition |
| `conformance/fixtures/incremental-lifecycle-corpus.json` | Lifecycle, abort, malformed-UTF-8, limit scenarios |
| `conformance/fixtures/unicode-conversion-corpus.json` | Range-unit conversion references |
| `conformance/fixtures/error-codes.json` | The safe error-code registry |
| `conformance/fixtures/common-profile-expectations.json` | Pinned `common`-profile findings |
| `docs/coverage/detector-inventory.json` | Every emittable finding type joined to its default policy class |

**Safety rule over the whole document.** Every example value in this
specification, in the corpus, in tests, in fixtures, in diagnostics, and in
documentation MUST be unmistakably synthetic or revoked. No normative artifact
may carry a real credential.

---

## 1. Why one core and many bindings

A detector expressed as a regular expression diverges across language engines:
Unicode shorthand classes, lookaround support, backtracking behavior, and
byte-vs-code-point semantics all differ between JavaScript, Python, Go, and
Rust. Reimplementing detection per runtime therefore produces per-runtime
behavior, which is indistinguishable from a per-runtime security hole.

Redact Secret resolves this by having exactly one implementation:

```text
JavaScript        Python        Rust          CLI
     |               |            |             |
  N-API / wasm      PyO3         |             |
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

**RSS-1.1** A binding MUST NOT reimplement detection, overlap resolution,
policy defaults, redaction, or incremental retention. It MAY only convert host
values, callbacks, errors, and string ranges.

**RSS-1.2** The core MUST be side-effect free: no runtime network access, no
filesystem access, no environment lookup, no telemetry, no secret storage, no
model invocation, no UI work, no clock- or locale-dependent behavior.

**RSS-1.3** The same input, registry, policy, and formatter MUST produce
byte-identical output on every supported surface and on every run.

---

## 2. Trust boundary

Two paths exist and MUST NOT be conflated:

```text
Intentional credential path
  User -> Credential Manager -> Secret Vault -> Provider Gateway -> Provider

Untrusted text path
  User / Tool / MCP / Log -> Redact Secret -> Sanitized Text
                                   -> Conversation / Context / Storage / Model
```

**RSS-2.1** A vault MAY hold secrets. Conversation history, model context,
knowledge stores, logs, telemetry, and diagnostics MUST NOT.

**RSS-2.2** Client-side scanning is preventive UX only. Server-side scanning is
the authoritative enforcement boundary and MUST run even when a client also
scans, because direct API clients, older clients, CLIs, SDKs, MCP integrations,
and agents may bypass the client.

**RSS-2.3** An application MUST NOT log raw request or tool bodies before
scanning them.

**RSS-2.4** No finding, error, callback argument, fixture, snapshot, log line,
or diagnostic may expose matched plaintext. This is a structural requirement,
not a convention: the expectation schema is closed (§11.2) precisely so the
format has no field in which plaintext could travel.

---

## 3. Data model

### 3.1 Range units

The core works in UTF-8 byte offsets. Each binding converts without changing
the selected span.

| Surface | Public range unit | `RANGE_UNIT` |
| --- | --- | --- |
| Rust crate | UTF-8 bytes | `utf8-bytes` |
| Node.js | UTF-16 code units | `utf16-code-units` |
| Browser JavaScript | UTF-16 code units | `utf16-code-units` |
| Python | Unicode code points | `unicode-code-points` |
| CLI | UTF-8 bytes | `utf8-bytes` |

**RSS-3.1.1** Ranges are half-open: `start` inclusive, `end` exclusive.

**RSS-3.1.2** All offsets MUST refer to the **original** input, even when the
sanitized output has a different length.

**RSS-3.1.3** A byte offset MUST fall on a UTF-8 code point boundary. An offset
that would split a multi-byte character is invalid and MUST be rejected.

**RSS-3.1.4** Numeric positions MUST NOT be copied between runtimes without
conversion against the same input. Conversion MUST be asserted against
`fixtures/unicode-conversion-corpus.json`, whose astral cases place a
supplementary-plane character before, inside, and after a finding — the
maximally divergent case (1 astral character = 2 UTF-16 code units = 1 code
point = 4 UTF-8 bytes).

### 3.2 Finding

A finding carries `id`, `type`, `detector`, `confidence`, `action`, `start`,
`end` — and nothing else that could reference input.

**RSS-3.2.1** Within one scan, findings MUST be ordered by position in the
original input and numbered from `finding-1` with no gaps.

**RSS-3.2.2** Finding IDs are scan-local. They MUST NOT be treated as stable
identities across changed inputs or separate scans.

**RSS-3.2.3** An incremental session MUST use absolute positions into the whole
session input and continuous numbering across appends.

**RSS-3.2.4** A CLI multi-file run MUST renumber findings so that IDs are
unique across the run.

### 3.3 Confidence

`high` | `medium` | `low`. Confidence is a detector-assigned property of the
evidence, never a probability estimate and never a claim that the credential is
live.

### 3.4 Specificity

Ordered, weakest to strongest:

| Value | Meaning |
| --- | --- |
| `entropy` | Entropy-only heuristic; also the default for a candidate that declares none |
| `contextual` | Credential assignment (`API_KEY=...`) |
| `structural` | Structural syntax (`Authorization: Bearer ...`, connection URLs) |
| `provider` | Provider-specific token format |
| `private-key` | Private key or comparably specific material |

**RSS-3.4.1** A candidate that omits specificity MUST default to `entropy`, so
that an unclassified detector can never displace a classified one.

### 3.5 Action

`block` | `redact` | `warn` | `allow`. `block` and `redact` replace text;
`warn` and `allow` leave the input unchanged.

---

## 4. The pipeline

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

**RSS-4.1** The core MUST NOT normalize or decode input before detection when
doing so would change source coordinates or lexical meaning. Detectors inspect
the original UTF-8 string and emit candidate ranges into it.

**RSS-4.2** Candidate validation MUST reject a candidate that is malformed,
empty, out of bounds, not char-aligned, or whose type name is not a valid
identifier.

**RSS-4.3** A candidate whose matched text is exactly its own public type name
or detector id MUST be rejected: a public field that mirrors input is a leak
channel.

**RSS-4.4 (vendor placeholder carve-out)** A candidate whose matched text is
**exactly equal** to a published vendor placeholder literal (for example AWS's
documented `AKIAIOSFODNN7EXAMPLE`) MUST be discarded. Matching MUST be by
whole-candidate equality only — never substring, never pattern — so the
carve-out cannot be used as a template to conceal part of a real secret.

**RSS-4.5** Entropy is a supporting signal only. It MUST NOT by itself justify
classifying arbitrary random-looking text as a secret.

---

## 5. Overlap resolution

**RSS-5.1** Conflict precedence, in order, is:

1. specificity, descending (§3.4);
2. confidence, descending (`high` > `medium` > `low`);
3. span width, **narrower** first;
4. detector registration order in the registry, ascending;
5. candidate emission order within a detector, ascending.

**RSS-5.2** The last two keys are unique per candidate, so the ordering is
total. An implementation MUST NOT introduce a further tie-breaker, and MUST NOT
depend on hash-map or set iteration order anywhere in this path.

**RSS-5.3** Resolution is a deterministic greedy pass over that total order
that accepts a candidate only when its range is disjoint from every already
accepted range. Rejected candidates do not reopen earlier decisions.

**RSS-5.4** Specific provider or structural evidence therefore outranks broad
contextual evidence. The tradeoff is explicit and accepted: precision and
bounded redaction, at the cost of missing truncated, novel, malformed, or
unsupported variants.

**RSS-5.5** Surviving findings are then sorted by original-input position and
assigned one-based IDs (§3.2.1).

---

## 6. Detection

### 6.1 Coverage families

| Family | Supported structure |
| --- | --- |
| Private keys | PEM-style private-key blocks |
| Provider credentials | AWS access-key IDs; GitHub, GitLab, OpenAI, Anthropic, Shopify, modern Vault patterns |
| Additional provider formats | Qualified Stripe, Slack, PyPI, Hugging Face, Docker Hub, Cloudflare, DigitalOcean, Linear, Supabase, Vercel, npm, SendGrid, Google Cloud/Gemini, Microsoft Entra client secret, Azure DevOps PAT, Notion, Atlassian Cloud, Twilio, Telegram Bot API, Discord bot, Sentry, Datadog, Grafana, New Relic |
| Authorization | JWT, Bearer, Basic, and Token credentials |
| Context | Credential assignments, including AWS secret-access-key and session-token names |
| Connections | Credential-bearing `postgresql`, `postgres`, `mysql`, `mariadb`, `mongodb`, `mongodb+srv`, `redis`, `rediss`, `amqp`, `amqps`, `azure` URLs |
| One-time password provisioning | `otpauth://totp` and `otpauth://hotp` with base32 shared secrets |

**RSS-6.1.1** This is a family overview, not a promise to match every token a
provider issues. The exact supported grammars are whatever
`synchronous-corpus.json` pins.

**RSS-6.1.2** The complete set of emittable finding types, each joined to its
default-policy class, is `docs/coverage/detector-inventory.json`. An
implementation MUST fail its own build or test suite when the registry, the
emitted types, or the default policy drift from that file.

### 6.2 Detector profiles

| Profile | Membership | Availability |
| --- | --- | --- |
| `full` | Every built-in detector. Default and compatibility baseline. | Every surface |
| `common` | Private keys, JWT/Bearer authorization, connections, one-time-password provisioning, and the generic credential-assignment context detector. Omits both provider rows entirely. | JavaScript (`@redact-secret/core/common`) and Rust (`DetectorRegistry::with_common_built_in`) only |

**RSS-6.2.1** `common` MUST NOT introduce a false positive relative to `full`.
It may only drop candidates `full` would have reported.

**RSS-6.2.2** `common`'s false-negative tradeoff is on provider tokens: a bare
provider token with no surrounding structural or contextual evidence is not
detected at all, and a provider token caught by a `common` detector's context is
reported under **that** detector's type and confidence instead of the
provider-specific one — for example `warn` where `full` would `redact`.

**RSS-6.2.3** A surface that exposes a profile MUST expose which profile it was
built from (`PROFILE` in JavaScript; `DetectorRegistry::profile()` and
`IncrementalSanitizer::profile()` in Rust).

**RSS-6.2.4** JavaScript `initialize()` MUST reject with
`INITIALIZATION_FAILED` when the loaded native artifact reports a different
profile than the entry point that loaded it — the same detail-free rejection an
unusable or version-mismatched artifact gets.

**RSS-6.2.5** `common` findings differ from `full` by design and therefore MUST
be pinned in `fixtures/common-profile-expectations.json` rather than derived at
runtime.

### 6.3 Declared limits of detection

**RSS-6.3.1** The core MUST NOT contact a provider. It cannot and does not
establish whether a credential is active, expired, or valid.

**RSS-6.3.2** An empty result means no supported pattern matched. It MUST NOT
be presented as certifying that text is secret-free.

**RSS-6.3.3** The generic name `token`, alone, is deliberately ignored.

**RSS-6.3.4** Synthetic text imitating a supported credential will match;
detection cannot establish that a match is real. A harmless assignment to a
credential-like name may likewise be classified from context.

**RSS-6.3.5** This is not a general DLP tool and not a repository-history
scanner.

---

## 7. Policy

**RSS-7.1** Detection answers *what a range appears to be*. Policy
independently chooses one of `redact`, `block`, `warn`, `allow`. The two MUST
stay separable: adding a detector MUST NOT change policy semantics, and
tightening a policy MUST NOT change detector behavior.

**RSS-7.2** A policy callback MUST receive only immutable finding metadata and
a policy context. It MUST NOT receive the input or the matched value.

**RSS-7.3** The default policy is:

| Class | Rule |
| --- | --- |
| `block` | `private_key`, at any confidence |
| `always-redact` | 36 known credential types (the `ALWAYS_REDACT_TYPES` set), at any confidence |
| `confidence-gated` | Everything else: `redact` at `high`, otherwise `warn` |

**RSS-7.4** The default policy MUST be deterministic, infallible, and
independent of policy context — which is also what makes it valid as an
incremental policy (§9.5).

**RSS-7.5** A consumer MAY enforce a stricter server-side policy. A policy that
returns a value outside the four actions MUST fail with
`INVALID_POLICY_ACTION`; a policy that throws MUST fail with `POLICY_FAILURE`.

---

## 8. Redaction and placeholders

**RSS-8.1** Redaction is a single ordered pass over the selected ranges. Only
`redact` and `block` ranges are replaced; `warn` and `allow` ranges MUST be left
byte-identical.

**RSS-8.2** Default placeholders are `<SECRET_1>`, `<SECRET_2>`, …, where `N` is
one-based among **replaced** findings only. A `warn` or `allow` finding MUST NOT
consume a placeholder number.

**RSS-8.3** A placeholder is a label, not an encoding. It MUST NOT be
recoverable to the removed text.

**RSS-8.4** A custom formatter receives safe metadata and a placeholder index
only. The core MUST reject:

- an empty placeholder;
- a placeholder longer than `MAX_PLACEHOLDER_LENGTH` (256);
- a placeholder that **contains any replaced matched value as a substring** —
  checked against every replaced range whose length is ≤ 256, since a longer
  value can never fit inside a valid placeholder;
- a formatter that fails (`PLACEHOLDER_FAILURE`) or returns an invalid value
  (`INVALID_PLACEHOLDER`).

**RSS-8.5 (direct redaction)** Findings supplied directly to a redaction API
are trusted caller assertions. The core MUST validate their metadata, bounds,
char alignment, ordering, mutual disjointness, and placeholder safety, and MUST
sort unsorted input. It MUST NOT rerun detection, MUST NOT resolve conflicting
caller-supplied findings, and cannot establish that the findings belong to the
input passed alongside them — the caller is responsible for passing the same
original input that was scanned.

**RSS-8.6** `scanAndRedact` MUST equal `scan` followed by `redact` with the
same registry, policy, and formatter, for every corpus fixture.

---

## 9. Incremental sanitization

A secret may cross any chunk boundary; scanning chunks independently leaks it.

**RSS-9.1** A session retains unresolved text until its detection window
closes, then emits text and findings. An `append` MAY legitimately return empty
text.

**RSS-9.2 (partition invariance)** For every fixture in
`incremental-corpus.json`, a bounded session MUST reproduce the whole-input
reference exactly — concatenated text, findings, actions, order, IDs, absolute
ranges, and placeholder numbering — at **every** partition of the input:

- every UTF-8 byte boundary, including indices inside a multi-byte code point
  (reached through the same fatal, stateful streaming decoder a byte-oriented
  host must place in front of a core whose string type cannot hold a partial
  code point);
- every host-native string boundary (every Rust `&str` char boundary, every
  JavaScript UTF-16 code unit boundary), plus the maximally fragmented
  partition of one chunk per unit.

Only the *distribution* of safe output across `append` and `finalize` results
may vary. Feeding the whole input in one `append` MUST accept exactly what the
fragmented partitions accept.

**RSS-9.3** Partitions are generated deterministically by each runner. They
MUST NOT be stored as fixture data.

**RSS-9.4** Limits are `max_input_bytes`, `max_buffered_bytes`,
`max_token_bytes`, `max_multiline_bytes`. Construction MUST reject limits where
any value is zero, where `max_token_bytes` or `max_multiline_bytes` exceeds
`max_input_bytes`, or where `max_buffered_bytes` is below the minimum needed to
hold the larger of the token and multiline windows plus the lookaround margin
(`INVALID_LIMITS`). Exceeding a limit at runtime MUST fail closed with the
corresponding `*_LIMIT_EXCEEDED` code — never with truncated-but-successful
output.

**RSS-9.5 (by-construction exclusions)** Two whole-input capabilities do not
exist incrementally, and a runner MUST record that rather than assert an
equivalence that cannot hold:

- **custom synchronous detectors** — an incremental session takes no registry,
  because a custom detector declares no retention bound;
- **whole-input count-dependent policies** — the incremental policy context
  carries the finalized index but no total, because a progressive evaluation
  cannot know the session's final finding count.

**RSS-9.6** A session that has finalized or aborted MUST reject further input
with `INVALID_STATE`.

---

## 10. Errors

**RSS-10.1** Every failure MUST use a stable code and a fixed, input-free
message. A message MUST NOT be derived from input, from a matched value, or
from a filename's contents.

**RSS-10.2** The registry is `conformance/fixtures/error-codes.json` — 15 codes
today:

| Surface | Codes |
| --- | --- |
| incremental | `INVALID_OPTIONS`, `INVALID_LIMITS`, `INVALID_INPUT`, `INPUT_LIMIT_EXCEEDED`, `BUFFER_LIMIT_EXCEEDED`, `TOKEN_LIMIT_EXCEEDED`, `MULTILINE_LIMIT_EXCEEDED`, `DETECTOR_FAILURE`, `POLICY_FAILURE`, `INVALID_POLICY_ACTION`, `PLACEHOLDER_FAILURE`, `INVALID_PLACEHOLDER`, `INVALID_STATE` |
| stream | `INVALID_CHUNK`, `INVALID_UTF8` |

**RSS-10.3** Bindings MUST surface the same code: `SecretScanError` in
JavaScript, `SecretScanError` subclasses in Python, `SecretScanError` in a Rust
`Result`.

**RSS-10.4** Fixture-validation diagnostics MUST report only a fixture ID and a
stable code, never the fixture's `input` or a matched substring.

**RSS-10.5** Whole-input operations have **no implicit resource cap**. The host
MUST impose one.

---

## 11. Conformance

### 11.1 Fixture format

A fixture requires `id`, `detector`, `kind`, `support`, `tier`, `contexts`,
`input`, `expected`, `note`, and MAY carry `mutation` and `resource`.

| Field | Domain |
| --- | --- |
| `kind` | `positive`, `negative`, `boundary`, `overlap`, `adversarial` |
| `support` | `supported`, `intentionally-unsupported`, `not-yet-evaluated` |
| `tier` | `canonical`, `negative`, `malformed`, `contextual`, `adversarial`, `regression` |
| `contexts` | one or more of 22 host contexts: `plain-text`, `dotenv`, `json`, `yaml`, `toml`, `shell`, `powershell`, `docker-compose`, `github-actions`, `terraform`, `kubernetes`, `javascript`, `typescript`, `python`, `http`, `curl`, `log`, `terminal`, `stack-trace`, `chat`, `markdown`, `xml` |

### 11.2 Safe expectations

**RSS-11.2.1** An expectation carries exactly `detector`, `type`, `confidence`,
`specificity`, `start`, `end`. The object is **closed**: both validators
(`schema.ts`'s key check and `schema.json`'s `additionalProperties: false`) MUST
reject any additional key. The format itself therefore has no way to carry
plaintext into a public expectation.

**RSS-11.2.2** A conforming validator MUST also enforce the cross-field
invariants JSON Schema cannot express: no overlapping expectations, and every
range within the bounds of `input`.

### 11.3 Mutation provenance

**RSS-11.3.1** `operation: "declared-boundary"` marks a hand-authored fixed
case; its `seedId` is a human-assigned per-fixture identity and there is nothing
to reproduce beyond the fixture.

**RSS-11.3.2** Any other `operation` is a claim that a deterministic generator
keyed by `(grammar, seedId, operation, ordinal)` reproduces `input`
byte-for-byte. Such a claim MUST be paired with a small pure generator function
and a test that regenerates the set on every run, asserting it is both
self-identical (determinism) and byte-identical to the committed fixtures
(reproducibility). Existing pairings: `github-classic` and
`docker-token-exact-length`.

**RSS-11.3.3** Generators prove provenance; they do not generate the corpus.
`synchronous-corpus.json` stays hand-maintained.

### 11.4 Adversarial resource caps

**RSS-11.4.1** Every `adversarial`-tier fixture declares `maxInputBytes`,
`maxFindings`, `maxRuntimeMs`. A runner MUST assert all three on the whole-input
surface and, where the language has one, on the incremental surface — including
a fragmented partition, since fragmentation is where an implementation that
rescans retained text degrades.

**RSS-11.4.2** `maxInputBytes` and `maxFindings` are properties of the fixture
and MUST be asserted exactly.

**RSS-11.4.3** `maxRuntimeMs` describes the shipped optimized build. An
unoptimized test build MAY be held to a fixed, documented multiple (Rust: 8× for
debug, exactly the declared cap when optimized). It MUST NOT be held to a value
derived from the machine it happens to run on. These caps exist to catch
superlinear blowup — orders of magnitude, not a constant factor.

### 11.5 Required consumers

**RSS-11.5.1** Conformance MUST be asserted through **built artifacts**, not
only through the source tree: the N-API addon, the browser WebAssembly artifact
in Chromium, Firefox, and WebKit, the CLI binary, the Python extension, and the
packed JavaScript package with its real artifact dependencies.

**RSS-11.5.2** A runner that converts canonical UTF-8 offsets to its own unit
MUST use a reference conversion **independent of the binding under test**.

**RSS-11.5.3** Package-consumer qualification MUST record, per declared Node
major and browser engine, the source revision, package artifact hashes, runtime,
command, and incremental corpus hash.

---

## 12. Regression intake

**RSS-12.1** Every confirmed false positive or false negative becomes a
permanent fixture, via:

1. discard the submitted credential value; retain only a safe description of the
   grammar, boundary, and host context;
2. construct an unmistakably synthetic or revoked replacement **from scratch** —
   never transform, encode, hash, truncate, or snapshot the submitted value;
3. assign a stable fixture ID, the `regression` tier, applicable contexts, safe
   expected metadata, and a note describing the *behavior*, not the reported
   plaintext;
4. prove the fixture fails before the repair where practical, then passes on
   every affected consumer;
5. inspect failures and logs so they carry only fixture identity and safe
   metadata. Where safe reproduction is impossible, document the excluded shape
   without retaining the report material.

**RSS-12.2** If the submission is, or might be, an active credential, it MUST
NOT enter the corpus, an issue, or a pull request. Report it privately through
`SECURITY.md` first, so it never becomes a second exposure of the same material.

**RSS-12.3 (benchmark-originated)** Minimal whole-input behavior goes in
`synchronous-corpus.json` at `tier: "regression"`; a matching incremental case
is added only when chunk boundaries, retained state, or finalization can affect
the result. Cross-repository identity and acceptance gates are recorded in
`conformance/benchmark-regressions.json`, with `benchmarkCommit` pinning the
benchmark revision alongside the product-side `fixingCommit`. Discovery
matrices, generated variants, competitor output, holdout material, and raw
results stay in the benchmarks repository.

---

## 13. Surface contracts

### 13.1 Operations

| Operation | JavaScript | Python / Rust | Result |
| --- | --- | --- | --- |
| Detect and apply policy | `scan` | `scan` | Findings |
| Replace supplied ranges | `redact` | `redact` | Text |
| Both | `scanAndRedact` | `scan_and_redact` | Text and findings |

**RSS-13.1.1** Rust additionally takes a registry, policy, and formatter.
Python takes optional `policy` and `formatter`. JavaScript takes an options
object with `policy` and `placeholderFormatter`.

**RSS-13.1.2** Custom **detector** callbacks are a direct Rust surface only.
Policy and formatter callbacks are available across languages.

### 13.2 JavaScript initialization

**RSS-13.2.1** A consumer MUST `await initialize()` before any synchronous
scan, redaction, incremental, or adapter operation. The explicit contract exists
so that native or WebAssembly loading failure is observable without making every
scan asynchronous.

**RSS-13.2.2** Loading failure MUST reject with `INITIALIZATION_FAILED` and no
detail — including on a musl host, where no glibc addon is published.

**RSS-13.2.3** JavaScript incremental limit properties keep their historical
`CodeUnits` names for compatibility, but their numeric ceilings are enforced by
the core as **UTF-8 byte** limits. Callers sizing non-ASCII input MUST measure
with `TextEncoder`.

### 13.3 CLI

| Exit | Check mode | Redact mode |
| --- | --- | --- |
| 0 | Every source scanned, no findings | Whole output written successfully |
| 1 | Every source scanned, at least one finding | Unused |
| 2 | Usage, read, UTF-8, limit, or write failure | Processing failed; output may be partial |

**RSS-13.3.1** Check mode flags **any** finding, including `warn` and `allow`.
Redact mode replaces only `redact` and `block` spans, so a successful redaction
does not guarantee that every detected range was removed.

**RSS-13.3.2** The CLI MUST NOT walk directories recursively and MUST NOT modify
files in place. Redaction accepts exactly one input.

**RSS-13.3.3** Standard input is incremental and UTF-8 decoding is strict. A
failure MAY leave a sanitized but **incomplete** prefix on stdout; a consumer
MUST accept output only after exit 0. A run that could not decode part of its
input has not proved that part clean and therefore exits 2.

**RSS-13.3.4** `--json` emits `version`, `rangeUnit`, `findingCount`, `sources`,
`failures`, with run-unique finding IDs and UTF-8 byte ranges into each original
source. Neither format prints matched file content. Text reports and diagnostics
escape non-printing path characters and backslashes; JSON decoding recovers the
original path.

**RSS-13.3.5** Paths and standard input share a total-input bound, but streamed
input carries additional open-line and multiline limits. A long unbroken line can
therefore fail on stdin while passing as a file. This asymmetry is intended and
MUST be documented in `--help`.

---

## 14. Deliberate deviations and non-goals

1. **No second implementation.** The TypeScript detector core that once served
   as the behavioral oracle was removed once the Rust core reached parity. Git
   preserves its history; the repository MUST NOT maintain a second detector
   implementation.
2. **No input normalization before detection** where it would change source
   coordinates or lexical meaning — a decoded view would report ranges that do
   not exist in the caller's string.
3. **No entropy-only classification.** Accepts false negatives on
   high-entropy-but-unstructured secrets in exchange for not redacting arbitrary
   random-looking text.
4. **Narrower span wins ties**, bounding over-redaction rather than maximizing
   removed characters.
5. **`common` omits provider detectors entirely** rather than approximating
   them, so the profile difference is a clean subset rather than a second
   grammar to maintain.
6. **No implicit whole-input cap.** The core does not impose a size limit on
   whole-input operations; a host that needs one must set it, and the
   incremental surface is where bounded operation is specified.
7. **No integration packages.** Logging, telemetry, model context, and MCP are
   application use cases. The repository ships core APIs and generic examples
   only — no LangChain, OpenTelemetry, pino, Python-logging, or MCP package.
8. **`token` alone is ignored**, accepting a false negative to avoid a large
   false-positive class.

---

## 15. Versioning and change control

**RSS-15.1** This revision is `RSS-1`. A change that alters observable behavior
(detector grammar, precedence, default policy class, placeholder rules, range
semantics, error codes, or limit validation) MUST arrive with corpus changes in
the same commit, and MUST state its false-positive and false-negative tradeoff.

**RSS-15.2** A behavioral change MUST NOT land in one binding ahead of the
others; the core is the only place it may be made.

**RSS-15.3** Governance of decisions, release authority, and branch policy is
out of scope here and lives in `AGENTS.md`, `CONTRIBUTION.md`, and
`docs/decisions/`.

---

*Redact Secret is released under the MIT licence. Every credential-shaped string
in this document is synthetic or revoked.*
