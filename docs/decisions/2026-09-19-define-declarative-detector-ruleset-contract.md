---
decision_id: decision-define-declarative-detector-ruleset-contract
status: accepted
scope: workspace
title: Define the declarative detector ruleset contract
decided_at: 2026-09-19
---

# Define the declarative detector ruleset contract

Issue [#441](https://github.com/redact-secret/redact-secret/issues/441). The
issue's own research pass already settled direction, terminology, matching
vocabulary, and loading mechanism (marked **[SETTLED]** in the issue body);
this record is the reviewed, durable form of those points plus the exact
values the issue left open: cost bounds, the ordering/specificity cap, the
closed validator enum's starting membership, the profile and conformance
interaction, and which surfaces accept a ruleset first. The measured evidence
the issue required before this ADR was written is
[`docs/audits/evidence/441/README.md`](../audits/evidence/441/README.md).
This record authorizes, but does not itself perform, the parser and loader
implementation; that is separate follow-up work. It changes no shipped
detector, no compiled artifact, and no public API by itself.

## Context

The stable cross-language extension surface covers policy and placeholder
callbacks only. Custom detector *callbacks* are excluded on every binding
(`README.md`, `ARCHITECTURE.md`) because a callback hands detection logic to
host runtime code: a second implementation, running per candidate, that could
diverge from the Rust core and that exposes plaintext across the FFI boundary
to do its job. That reasoning is sound and unchanged by this decision — see
[Why the existing exclusions are not reversed](#why-the-existing-exclusions-are-not-reversed).

It also means an organization with an internal credential format — an
in-house service token, a partner API key, a legacy prefix — has no usable
path to detecting it on any binding but Rust, where `Detector`, `Candidate`,
`DetectorContext`, `DetectorRegistry`, and `RegisteredDetector` are already
public API (`crates/secret-scan-core/src/registry.rs`). The gap is
JavaScript, Python, and the CLI, which is most consumers; the common
workaround is a second regex pass on the caller's own side of the API,
recreating exactly the divergent implementation the callback exclusion
exists to prevent.

A **declarative ruleset** is not a callback: it hands the core caller-supplied
data, and the core keeps performing every match itself, the same as it does
for a built-in detector. `crates/secret-scan-core/src/detectors/pattern.rs`
is already a restricted, linear-time matching vocabulary of exactly the
needed shape — a fixed set of byte-class alphabets, `RunLength::{Exact,
AtLeast}` quantifiers mirroring `{n}`/`{n,}`, a literal prefix, and a
byte-adjacent boundary check — written specifically because the core may
depend on nothing (`[workspace.metadata.redact-secret] allowed-dependencies
= []`) and so cannot use a regex crate. Its own module comment records that
every provider detector's grammar reduced to this shape except OpenAI's,
which composes the same primitives directly. There is no backtracking, so
the ReDoS surface is zero today by construction, not by review; a ruleset
format that serializes this exact shape keeps that property, rather than
introducing a new matching engine that would need to earn it again.

`decision-define-detector-profile-and-pack-contract`'s Consequences section
already anticipated this: "Declarative provider-rule tables, which #377 left
for separate investigation, are the lever if [the engine] floor or
per-detector code duplication becomes the dominant cost." This decision is
that separate investigation.

## Decision

### Terminology

The caller-supplied unit is a **ruleset**, never a **pack**. `pack` is fixed
by `decision-define-detector-profile-and-pack-contract` as an internal,
non-published compile-time tag on a built-in detector (`common`/`provider`)
used for link-time profile composition — the opposite properties from what
this decision means (external, runtime-supplied, data not a build-time tag).
Reusing the word would make "a profile is a union of declared packs" and "a
caller supplies a ruleset" collide in the same sentence. Every name in code,
tests, and documentation for this feature uses **ruleset** or **ruleset
detector**.

### Governance: what this does and does not reverse

| Rule | Source | Violated? |
| --- | --- | --- |
| "Custom detector **callbacks** are excluded" | `README.md:146` | **No.** A ruleset is data the core parses and matches itself; no host code runs per candidate. |
| Callbacks "would expose plaintext across the FFI boundary and could restore **divergent** detector behavior" | `ARCHITECTURE.md:411-412` | **No.** No plaintext crosses the boundary (bytes go in, ranges come out, exactly like every built-in detector today), and the core still performs all matching through the unmodified `pattern.rs` engine, so no second implementation appears. |
| "No dynamic, network-loaded, or **user-supplied rule packs** or plugins" | `decision-define-detector-profile-and-pack-contract`, Non-goals | **Yes — directly, and only this line.** Amended below. |

See [Why the existing exclusions are not reversed](#why-the-existing-exclusions-are-not-reversed)
for the full reasoning behind the first two rows, and [Amendment to the
profile/pack contract](#amendment-to-the-profilepack-contract) for the
third.

Security posture improves rather than degrades. `SECURITY.md` already
concedes that Rust custom detectors are "trusted in-process code" and that
fixed library errors "do not sandbox a malicious extension" — a native
`Detector` can capture plaintext through a closure. A ruleset has no code to
execute, so that capture path does not exist for it. This gives the three
binding surfaces an extension mechanism that is *safer* than the one Rust
consumers already have.

### Why the existing exclusions are not reversed

`README.md:146`'s "Custom detector callbacks are excluded" and
`ARCHITECTURE.md:411-412`'s "Custom detector callbacks across bindings are
intentionally excluded because they would expose plaintext across the FFI
boundary and could restore divergent detector behavior" both name
*callbacks* specifically, and both reasons are properties of a callback, not
of caller-supplied detection logic in general:

- **No plaintext crosses the boundary.** A callback must run host code
  against the plaintext value to decide anything, which is why it needs the
  plaintext. A ruleset is parsed once, before any input is scanned, into
  the same `Candidate`-producing shape a built-in detector already uses;
  the ruleset's own bytes (the grammar) cross the boundary, never the
  scanned input's matched substring.
- **No divergent implementation.** A callback's result depends on whatever
  the host runtime does with it — Node, the browser, and Python could each
  interpret the "same" callback differently. A ruleset's bytes are parsed by
  the one Rust parser described in [Loading mechanism](#loading-mechanism-the-core-parses-the-format-itself),
  producing the one `Vec<PrefixShape>`-equivalent structure `pattern.rs`
  already matches; N-API, wasm, and PyO3 all hand the same bytes to the same
  parser and get the same accept/reject outcome and the same detection
  behavior.

Both rows stay accurate as written; this decision does not edit either
document's *exclusion* sentence, only adds a pointer to the ruleset path
beside it (see [Documentation](#documentation)).

### Matching vocabulary: a serialization of `pattern.rs`, not a new engine

No new matching engine and no regex engine are added. A ruleset detector's
value grammar is exactly one [`PrefixShape`](../../crates/secret-scan-core/src/detectors/pattern.rs):

- `alphabet`: one of the seven existing named byte classes —
  `alnum`, `alnum-dash`, `alnum-dash-dot`, `upper-alnum`, `digit`,
  `lower-hex`, `base64-body` (`pattern.rs`'s `is_alnum`, `is_alnum_dash`,
  `is_alnum_dash_dot`, `is_upper_alnum`, `is_digit`, `is_lower_hex`,
  `is_base64_body`). A ruleset cannot define a new alphabet.
- `prefix`: one literal string.
- `run`: `exact <n>` or `at-least <n>`, mirroring `RunLength::{Exact,
  AtLeast}`.
- `validator`: `none`, or one name from the closed enum in
  [Closed validator enum](#closed-validator-enum-postcheck).

Loading a ruleset materializes a `Vec<PrefixShape>` and feeds it to the
existing `scan_prefixed_shapes` — the same left-to-right, longest-prefix-wins,
linear-time pass every built-in prefixed detector already runs through. The
implementation issue that follows this ADR adds a parser and a thin
`Detector` adapter; it does not touch `pattern.rs`'s matching logic at all.

A **names-only ruleset** (no `detector:` blocks with a value grammar, only
caller-supplied high-signal/ambiguous assignment-keyword names) is not a
separate design: `crates/secret-scan-core/src/detectors/generic_token.rs`'s
`HIGH_SIGNAL_NAMES`/`AMBIGUOUS_NAMES` constants and `normalize_name` are the
ruleset schema's **names section**; the `PrefixShape` grammar above is its
**value section**. A names-only ruleset is a ruleset whose value section is
empty — no new matching vocabulary, no new specificity band (see
[Ordering and the specificity cap](#ordering-and-the-specificity-cap)), no
added ReDoS surface — and is the natural first shipping slice for the
implementation issue, not a competing option. Its real risk: caller-supplied
high-signal names shift `generic-token`'s entropy thresholds
(`HIGH_ENTROPY_THRESHOLD` 3.0 / `AMBIGUOUS_ENTROPY_THRESHOLD` 3.5) and
confidence, so it can raise false positives and change overlap outcomes for
`generic-token` specifically. The blast radius is bounded to that one
built-in detector's behavior, not the matching engine.

### Closed validator enum (`PostCheck`)

The one part of a detector's grammar that cannot be pure data is
[`PostCheck`](../../crates/secret-scan-core/src/detectors/pattern.rs)
(`fn(&[u8], usize, usize) -> bool`), used today by exactly one built-in
shape: Cloudflare's `checksum_tail_is_lower_hex`
(`crates/secret-scan-core/src/detectors/cloudflare.rs`), which checks that
the matched run's final bytes are lowercase hex. A ruleset detector selects
a validator by a fixed **name** from a closed, core-provided enum; it can
never supply a function, an expression, or a parameterized check body. An
unknown name is rejected at load (`UnknownValidator`), following FRS-1's
same rule for this exact hazard (external behavior reference only; no
schema, code, or content copied from it).

Starting membership, grounded in the one validator that already exists in
reviewed code:

- `none` — no post-check.
- `trailing-lower-hex` — the final `n` alphabet bytes of the match must be
  lowercase hex, generalizing `checksum_tail_is_lower_hex`'s already-shipped
  shape (`n` comes from the ruleset detector's own run-length field, not a
  second caller-supplied parameter).

Growing this enum is a reviewed, core-only change with the same weight as
adding a built-in detector — never a ruleset-supplied capability. A ruleset
selects a validator; it never defines one.

### Loading mechanism: the core parses the format itself

Two constraints, both hard, decide this (option A, over the rejected
alternative of a typed builder each binding fills from its own native
objects — option B):

- **No dependencies.** `crates/secret-scan-core/Cargo.toml`'s
  `[dependencies]` is empty and `allowed-dependencies = []` in the root
  manifest (`docs/rust-workspace.md`). There is no serde and no JSON parser
  in the core. A text format needs a hand-written minimal parser, the same
  kind `pattern.rs`'s module comment already justifies for the same reason.
- **No filesystem access.** `docs/rust-workspace.md`'s "No runtime I/O"
  source-boundary check forbids `std::fs`/`std::net`/`std::env` etc. under
  `crates/secret-scan-core/src`. "Load" therefore means **parse
  caller-supplied bytes**, never read a path. The CLI and each binding do
  their own file/argument reading and hand the parsed bytes to the core;
  the core never learns where they came from.

Option B (core exposes a typed builder; each binding translates its own
native objects into it) is rejected because the *rejection rules* — unknown
field, unknown revision, unsupported construct, unknown validator name —
would then be implemented once per binding. N-API, wasm, and PyO3 could
diverge on *which rulesets load at all*, which is the exact
divergent-implementation failure the callback exclusion exists to prevent,
re-entering through the loader instead of through per-candidate execution.
One parser in the core means every surface rejects the same bytes with the
same fixed error, the property [`docs/audits/evidence/441/README.md`](../audits/evidence/441/README.md)'s
prototype demonstrates directly: 7 rejection-class unit tests, each a fixed
enum variant carrying no content from the rejected input.

The measured cost of this choice — parser bytes landing in the
detector-independent "engine floor"
(`decision-define-detector-profile-and-pack-contract`, 55–58% of `full`'s
WASM size, paid by every consumer including `common` browser users who load
no ruleset) — is a real ~2.9% brotli WASM increment for a representative
371-line prototype covering a subset of the full validation surface below
(see [evidence/441](../audits/evidence/441/README.md) for the exact
before/after artifact sizes and methodology). Treat that as a lower bound:
the real implementation's fuller validation (all cost bounds, the complete
error catalog, ordering enforcement) adds somewhat more. It stays in the low
single-digit percent of `full`'s WASM size, consistent with a bounded parser
rather than a second detection engine.

### Cost bounds

Ruleset content is caller-supplied and therefore untrusted, even though
matching itself stays linear. The real cost of the `pattern.rs` shape is
`prefix count × input length`; without a floor on prefix length or a ceiling
on shape count and run length, a ruleset could still make that product
large. Fixed bounds, each rejecting at load with no partial parse:

| Bound | Value | Why |
| --- | --- | --- |
| Minimum prefix length | 3 bytes | A zero- or one-byte prefix makes most or all byte positions a candidate start, degrading toward the unbounded case the linear scan exists to avoid. 3 bytes matches the shortest real built-in prefixes (`hf_`, `sk-`) — the bound excludes no realistic format. |
| Maximum run length (`exact`/`at-least` count) | 4,096 bytes | Matches the existing `MAX_CONTEXT_VALUE_LENGTH` bound `generic_token.rs` already applies to a single detected value — the established precedent for "how long a single credential value is allowed to be" in this codebase, reused rather than re-derived. |
| Maximum detectors per ruleset | 64 | About 1.5× the current 42 built-in count: generous enough for a real organization's internal-format inventory, small enough that a scan's added detector-shape work per input stays the same order of magnitude as the existing built-in set, not a new unbounded dimension. |
| Minimum detectors per ruleset | 1 | An empty ruleset is rejected (`EmptyRuleset`), not silently accepted as a no-op — silent acceptance of an empty caller intent is exactly the "fail open" FRS-1 warns against. |

These are per-ruleset and per-detector-shape bounds; the *per-input* cost
ceiling composes from them with the existing whole-input bound
(`DEFAULT_MAX_INPUT_BYTES`/`WholeInputLimits`,
`decision-bound-whole-input-operations-by-default`): total added ruleset
scan work per call is `O(claimed detector shapes × bounded input length)`,
the same complexity class every existing linear detector already
contributes, not a new one.

### Fail-closed loading rule

Loading a ruleset either returns every validated detector or rejects the
whole ruleset with one fixed, input-free error — **never a partial load**.
The canonical rejection classes, each a fixed enum variant carrying no byte
derived from the rejected content:

- `UnknownRevision` — the `ruleset-revision` value is not the one supported
  revision.
- `UnknownField` / `UnsupportedConstruct` — a field name, block header, or
  line shape the grammar does not define.
- `UnknownAlphabet` — an `alphabet` name outside the seven listed above.
- `UnknownValidator` — a `validator` name outside the closed enum.
- `SpecificityNotClaimable` — a `specificity` name that either does not
  exist or is reserved to built-ins (see next section).
- `MissingField` — a required field absent from a detector block.
- `PrefixTooShort` / `RunLengthOutOfBounds` / `TooManyDetectors` — a
  [cost bound](#cost-bounds) violation.
- `DuplicateDetectorId` — two detector blocks declare the same id.
- `ReservedDetectorId` — a detector id collides with any `full` built-in id,
  mirroring the reserved-id rule `decision-define-detector-profile-and-pack-contract`
  already applies to native custom detectors, extended to ruleset ids so a
  ruleset `github-token` cannot emit findings under a built-in id with
  different behavior.
- `EmptyRuleset` — no detector blocks at all.

The implementation issue adds one test per class to the conformance corpus
(see [Conformance](#conformance)); [`docs/audits/evidence/441/README.md`](../audits/evidence/441/README.md)'s
prototype already demonstrates 7 of these classes end to end as real,
passing unit tests, so the catalog above is proven parseable and rejectable
in the actual constrained environment (no dependencies, no `unsafe`,
`#![deny(missing_docs)]`), not merely specified.

### Ordering and the specificity cap

The pipeline's tie-breaker
(`crates/secret-scan-core/src/pipeline.rs`, `RankedCandidate::priority`) is
fixed: resolved-action severity, then `specificity`, then `confidence`, then
narrower range, then `detector_order`, then `candidate_order`. `Specificity`
is a closed 5-value enum (`Entropy < Contextual < Structural < Provider <
PrivateKey`, `types.rs`) and a ruleset cannot add a value.

**A ruleset detector may claim only `Entropy` or `Contextual`.**
`Structural`, `Provider`, and `PrivateKey` are reserved to built-ins; a
ruleset detector block requesting one of those three is rejected at load
(`SpecificityNotClaimable`). Combined with the existing rule that custom
detectors — ruleset or native — register after every built-in in
`detector_order` (`decision-define-detector-profile-and-pack-contract`:
"Every profile constructor registers the profile's built-in detectors
first... then the custom detectors in the order given"), this makes "a
ruleset may add detections but must not overturn a built-in's resolved
finding" hold for every tie scenario the priority function can reach:

- A ruleset candidate can never outrank a built-in `Structural`, `Provider`,
  or `PrivateKey` candidate on the specificity key, because it cannot claim
  a value at or above any of them.
- A ruleset candidate at the same specificity as a competing built-in
  (`Contextual` vs. `generic-token`'s own `Contextual` claim, most likely)
  that also ties on confidence and range length falls through to
  `detector_order`, where the built-in's lower registration index wins.
- A ruleset candidate that ties on specificity but has genuinely higher
  confidence at the identical range can still win overlap resolution at the
  confidence key — this is unchanged, ordinary same-tier overlap behavior
  identical to how two built-ins of equal specificity but different
  confidence already interact in `full` today. The issue's own hazard
  language names *specificity* specifically ("a ruleset claiming
  `Specificity::Provider` silently outranks built-in `Structural`/
  `Contextual` candidates"); confidence is not a new axis this decision
  needs to further restrict.

This is distinct from, and does not change, `common`'s existing
**per-detector invariance** property: invariance still holds per detector
(a detector's own candidates for a given input are unaffected by whether a
ruleset is loaded). What can change is the **resolved finding set**, exactly
as adding any new detector already changes it — a ruleset detector
competing for the same span as a lower-specificity built-in can still win
that span on confidence, the same as two built-ins would.

### Plaintext safety

`Candidate` already carries `type_name`/`confidence`/`specificity`/`range`/
`signals` and never matched text, and `signals` never reach public results
(`types.rs`). The one residual risk this decision must close explicitly: a
ruleset-supplied string (a detector's declared `id`) appearing in a public
`Finding.detector` field, an error, or a diagnostic alongside input-derived
bytes.

**Closed the same way a native custom detector's id already is:** a ruleset
detector id must satisfy `is_identifier`
(`crate::types::is_identifier`/`MAX_IDENTIFIER_LENGTH`, the exact predicate
`DetectorRegistry::register` already applies to a Rust custom detector's
id) — non-empty, bounded length, restricted character set. An id failing
that check is rejected at load, not sanitized or truncated. No ruleset
string is ever formatted alongside input-derived bytes in any error or
diagnostic: every rejection is the fixed, content-free enum in
[Fail-closed loading rule](#fail-closed-loading-rule), and every accepted
`Finding.detector`/`Finding.type` value is the caller's already-validated
identifier — the same public shape (`id, type, detector, confidence,
action, start, end`, never a matched value) `ARCHITECTURE.md`'s "Public API
and extension boundary" section documents for every existing detector.

### Profile interaction

A ruleset sits **outside profile identity**. `Profile::Full`/`Profile::Common`
keep meaning exactly what they mean today — which built-in packs a registry
holds — and `decision-define-detector-profile-and-pack-contract`'s
per-profile qualification (membership, per-detector invariance, findings
against reviewed expectations) is unaffected by whether a ruleset is also
loaded. A registry built with a ruleset continues to report its `Profile` as
`Full` or `Common`; ruleset presence is a **separate, additional fact** the
implementation issue exposes (exact shape — a count, a boolean, a list of
loaded ruleset detector ids — is that issue's `core-public-api`-reviewed
decision, not this ADR's). This keeps `common`'s promise ("qualified against
its own reviewed expectations, not derived from `full` at runtime") intact:
a `common` registry with a loaded ruleset is still qualifiable as `common`
plus an explicitly separate, caller-owned addition, never a silent third
profile.

### Conformance

Declared **in contract**, not out of it. Ruleset *behavior* is
cross-language behavior — the same parser accepting or rejecting the same
bytes, and the same matching engine producing the same candidates, must
hold on the Rust core, Node, the browser WebAssembly artifact, and Python.
Declaring it out of contract is the cheap path but sits badly with option
A's own rationale (one parser, one behavior, every surface); FRS-1's
"failing open is how a redactor leaks" applies here too; a divergence only
conformance would have caught is exactly the failure re-entering through an
untested loader.

The implementation issue commits a **fixed reference ruleset fixture** —
synthetic detector definitions exercising the value grammar, the names
section, every [rejection class](#fail-closed-loading-rule), and the
[ordering cap](#ordering-and-the-specificity-cap) — under `conformance/`
alongside the existing canonical corpus
(`conformance/fixtures/synchronous-corpus.json`), and every binding surface
that accepts a ruleset in its first slice (see next section) runs it as
part of the shared behavioral contract
(`decision-govern-cross-language-conformance`), not a per-binding smoke test.
This is a decision to add that fixture when the loader lands, not a fixture
this ADR itself adds.

### Surface exposure

JavaScript, Python, and the CLI accept a ruleset in the first shipping
slice, together — not staggered. Option A's whole cost was paying the
parser once in the core; a binding's own surface for handing it bytes is
comparatively cheap plumbing, unlike (for contrast) the `common` profile's
separate WebAssembly artifact and package subpath, which needed its own
lockstep manifest and release job per `decision-define-detector-profile-and-pack-contract`.
Each binding's shape follows its existing conventions rather than
introducing a new one:

- **JavaScript (Node and browser WebAssembly):** a `Uint8Array`/`string`
  ruleset argument alongside the existing registry construction path, the
  same "caller hands bytes, core parses" shape `policy`/`formatter`
  callbacks already use for passing data across the boundary.
- **Python:** a `bytes`/`str` argument in the same position.
- **CLI:** a `--ruleset <path>` flag. The CLI does the file read (the core
  never does filesystem access, per [Loading mechanism](#loading-mechanism-the-core-parses-the-format-itself))
  and hands the core the bytes, the same division of responsibility the CLI
  already uses for its other file-reading flags.

The Rust core itself needs no new surface: `DetectorRegistry::register`
already accepts a native `Detector`; the implementation issue's ruleset
loader is one more way to obtain a `Vec<Box<dyn Detector>>` to register, not
a new registration mechanism.

Exact function/method names and their `core-public-api` manifest entries are
the implementation issue's reviewed change, not this ADR's.

### Amendment to the profile/pack contract

`decision-define-detector-profile-and-pack-contract`'s Non-goals list:

> No dynamic, network-loaded, or user-supplied rule packs or plugins.

is amended, in that document, to:

> No dynamic or network-loaded rule packs or plugins. (Amended by
> `decision-define-declarative-detector-ruleset-contract`: a caller-supplied
> **declarative ruleset** — data the core parses and validates itself, never
> executable code, never fetched over a network, never read from a path by
> the core — is in scope. This line's exclusion is narrowed to keep out only
> a dynamically loaded, network-fetched, or callback-shaped extension
> mechanism, which stays excluded.)

That document's other three Non-goals bullets ("No custom detector callbacks
across FFI, and no user-composed profiles", "No online credential
validation", "No `common` profile for Python or the CLI in this contract")
are untouched: a ruleset is not a callback, performs no validation against
an external service, and this decision does not add or change a `Profile`
value.

### Documentation

`README.md:146` and `ARCHITECTURE.md:411-412` keep their exclusion sentence
for callbacks unchanged (it stays accurate; see [Why the existing exclusions
are not reversed](#why-the-existing-exclusions-are-not-reversed)) and each
gains one sentence immediately after it, pointing at the ruleset path this
decision fixes, so an organization with an internal credential format finds
the accepted extension mechanism at the exact place the current exclusion
text would otherwise read as a dead end — the "bolt on a second regex pass"
workaround stops being the obvious next move. Both additions are applied in
this same change; both are forward pointers to this decision and the
tracked implementation issue, not a claim that the loader ships today.

## Rejected alternatives

- **Keep the exclusion as-is (no ruleset path at all).** This was the
  issue's original alternative 1; the issue's research pass closed it. It
  leaves every JavaScript, Python, and CLI consumer with an internal format
  no path but a Rust PR and a release wait, and its usual workaround (a
  second regex pass outside the library) recreates the divergent
  implementation the callback exclusion exists to prevent — worse than the
  data-only path this decision defines.
- **Callback-shaped custom detectors across bindings.** Rejected on the
  existing, unchanged grounds: host code per candidate, plaintext crossing
  the FFI boundary, and no guarantee of matching behavior across runtimes.
- **A typed builder per binding (option B).** Rejected: the load-time
  rejection rules would be implemented once per binding, letting N-API,
  wasm, and PyO3 diverge on which rulesets load at all — the
  divergent-implementation failure re-entering through the loader.
- **A new regex-like matching engine or an embedded regex crate.** Rejected:
  breaks `allowed-dependencies = []` for a crate, or reimplements a
  backtracking engine that reopens the ReDoS surface `pattern.rs` was
  written specifically to avoid. The existing vocabulary already covers
  every provider grammar but one, which composes it directly.
- **Unbounded ruleset size/shape count.** Rejected: caller-supplied content
  is untrusted; an unbounded ruleset turns a linear per-shape scan into an
  effectively unbounded per-input cost multiplier. [Cost bounds](#cost-bounds)
  fixes finite, evidenced values instead.
- **Letting a ruleset claim any specificity, including `Provider`/
  `PrivateKey`.** Rejected: this is the exact hazard the issue names — a
  ruleset detector could silently outrank a built-in's resolved finding
  through the specificity tie-break alone, before confidence or
  registration order are even considered.
- **Declaring ruleset behavior out of the conformance contract.** Rejected:
  cheap, but contradicts option A's whole rationale (one parser, one
  behavior everywhere) and is exactly the class of untested divergence
  FRS-1 warns produces a redactor that fails open.
- **Staggering surface exposure (Rust/CLI first, JavaScript/Python later).**
  Considered, rejected: unlike the `common` profile's separate WebAssembly
  artifact, a binding's ruleset-bytes argument is thin plumbing over the one
  core parser: there is no comparable per-surface cost that would justify
  shipping the surfaces separately.

## Non-goals

- No new matching engine, no regex crate, no change to `pattern.rs`'s
  existing alphabets, `RunLength` shape, or boundary check.
- No custom detector callbacks across FFI, and no user-composed profiles —
  unchanged from `decision-define-detector-profile-and-pack-contract`.
- No network-loaded or dynamically-fetched ruleset content; the core never
  performs filesystem or network access to obtain one.
- No online credential validation.
- No change to `full`/`common` membership, canonical order, or default
  findings.
- No new `Specificity` value, and no ruleset claim at or above `Structural`.
- No parser, loader, or binding-surface implementation in this change; that
  is tracked separately and authorized, not performed, by this decision.
- No release, version choice, or publication. That remains under
  `AGENTS.md` release authority.

## Consequences

This decision supersedes the "No dynamic, network-loaded, or user-supplied
rule packs or plugins" Non-goal in
`decision-define-detector-profile-and-pack-contract`, narrowed as shown in
[Amendment to the profile/pack contract](#amendment-to-the-profilepack-contract);
that document is updated in this same change. `README.md:146` and
`ARCHITECTURE.md:411-412` each gain one pointer sentence in this same
change, per [Documentation](#documentation); their existing exclusion
sentences are unchanged.

An organization with an internal credential format gains a real, reviewed
path on every binding once the follow-up implementation issue lands: supply
a small text ruleset, get the same linear-time, ReDoS-free matching every
built-in detector already gets, with fail-closed loading and a specificity
cap that guarantees it can add detections but never silently outrank a
built-in one. The measured cost is real but bounded — a low single-digit
percent WASM size increment paid once by every consumer regardless of
profile or of whether they ever load a ruleset — and is now a number in
[evidence/441](../audits/evidence/441/README.md) rather than an estimate.

The follow-up implementation issue must, at minimum: add the parser and
loader with the exact [cost bounds](#cost-bounds) and
[rejection catalog](#fail-closed-loading-rule) fixed here; add the
`Detector` adapter that turns parsed `PrefixShape`s (and the names-only
path) into registrable detectors under the
[ordering/specificity cap](#ordering-and-the-specificity-cap); add the
[reference ruleset conformance fixture](#conformance); add the
JavaScript/Python/CLI surfaces from [Surface exposure](#surface-exposure)
through the reviewed `core-public-api` manifest; and re-measure the real
compiled artifact against [evidence/441](../audits/evidence/441/README.md)'s
baseline once it exists, the same way
`decision-define-detector-profile-and-pack-contract`'s own triggers call for
re-measurement with `scripts/measure-detector-cost.mjs`.
