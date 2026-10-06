# #1072 — Declarative ruleset v1: stable-contract audit

Product judgement. Final record for
[#1072](https://github.com/redact-secret/redact-secret/issues/1072) (parent
[#1065](https://github.com/redact-secret/redact-secret/issues/1065), consumed
by [#1066](https://github.com/redact-secret/redact-secret/issues/1066)). It audits `ruleset-revision: 1` and records a
recommended disposition. **It changes no ruleset code, grammar, fixture or
shipped behavior**, and the disposition below was a recommendation for the
owner; the owner accepted it on 2026-10-02 (see [Owner decisions](#owner-decisions)). The contract itself is
[`decision-define-declarative-detector-ruleset-contract`](../../../decisions/2026-09-19-define-declarative-detector-ruleset-contract.md)
(accepted 2026-09-19, [#441](https://github.com/redact-secret/redact-secret/issues/441));
the implementation is [#483](https://github.com/redact-secret/redact-secret/issues/483),
[#495](https://github.com/redact-secret/redact-secret/issues/495) and
[#484](https://github.com/redact-secret/redact-secret/issues/484).

## Disposition

**Revise before stable, in a bounded way, then freeze.** Rulesets stay in the
0.1.x stable contract. Three leniencies that are cheap to remove now and a
breaking change later are tightened first; one user-visible behavior (a
ruleset detection is `warn`, so it is never redacted by default) is documented
as the contract; the missing evidence and grammar text are supplied. No
feature is added and no excluded construct is admitted.

The core is sound: one Rust parser shared by every surface, fail-closed
loading, a closed vocabulary, linear matching, fixed cost bounds, plaintext-free
errors, and containment under the built-ins all held under test (below). The
reason not to freeze unchanged is not design. It is that the shipped parser
accepts some inputs the contract says it rejects or that can never do what
they say, and a revision-1 file that depends on any of them would pin a defect.

### Exact list of required changes

| # | Change | Kind | Evidence |
| --- | --- | --- | --- |
| R1 | Reject a repeated field inside one `detector:` block. Today the last occurrence silently wins, although the guide says "exactly five fields" and the parser's own comment says "each required exactly once". Recommended class: `UNSUPPORTED_CONSTRUCT` (no new public class). | Parser, 3 lines | [Duplicate fields](#grammar-and-leniencies) |
| R2 | Reject a `prefix` that contains a code point the normalizer removes (invisible and format characters). It loads today and can never match, because detection runs on the stripped copy. Recommended class: `UNSUPPORTED_CONSTRUCT`. | Parser | [Invisible prefix](#grammar-and-leniencies) |
| R3 | Accept `run` counts only in canonical decimal (`[1-9][0-9]*`). `+20` and `020` load today because the parser uses Rust's integer parser, which a second implementation would not replicate. Recommended class: `UNSUPPORTED_CONSTRUCT`. | Parser | [Non-canonical counts](#grammar-and-leniencies) |
| R4 | Publish the normative text grammar (the [Grammar](#normative-grammar-for-revision-1) section below, moved into `docs/guides/rulesets.md`), including what is rejected on purpose: byte order mark, comments, tabs, repeated blocks of `ruleset-revision`, detector ids outside `is_identifier`. | Docs | [Normative grammar](#normative-grammar-for-revision-1) |
| R5 | State in the guide, README and CLI help that **a ruleset detection is `confidence: medium` and therefore `warn` under the default policy**: `scanAndRedact` and `redact-secret --redact` leave the matched text unchanged, and only a caller policy (Rust, JavaScript, Python) can redact it. Add the action to the reference fixture so the behavior is pinned across surfaces. | Docs + fixture | [Default action](#default-action-of-a-ruleset-detection) |
| R6 | Run `conformance/fixtures/ruleset-reference.json` on the Node addon, the WebAssembly artifact and the CLI in CI, or correct the fixture description, which claims every surface does. Rust and Python run it today; the Node addon and WebAssembly artifact do not (they passed a one-off run for this record, see [Cross-runtime conformance](#cross-runtime-conformance)). | Tests / qualification scripts | [Cross-runtime conformance](#cross-runtime-conformance) |
| R7 | Write the revisioning policy ([below](#2-revisioning-and-forward-compatibility)) as a decision. It is new policy, not an application of an existing one. Written as *Define declarative ruleset revisioning and the revision 1 freeze*, accepted 2026-10-02. | ADR | [Revisioning](#2-revisioning-and-forward-compatibility) |

R1 to R3 change what revision 1 accepts, so they must land before the stable
candidate freezes. Together they reject only input that was already
contradicting the documented grammar or could not work; none rejects a ruleset
that any shipped test, fixture or guide example contains.

### Decisions for the owner

| # | Decision | Options | Recommendation |
| --- | --- | --- | --- |
| D1 | Accept the disposition above. | (a) as written; (b) freeze unchanged and document R1 to R3 as frozen leniencies; (c) mark rulesets experimental and outside the stable contract | (a). (b) pins "last duplicate wins" and a never-matching prefix into a stable file format. (c) is the safe fallback if R1 to R3 cannot land in Beta.13: every ruleset surface is already additive, so promoting it later costs nothing. |
| D2 | Default action of a ruleset detection. | (a) Document `warn` as the contract (R5). (b) Let `DefaultPolicy` redact ruleset detections. (c) Add a restricted `action` field in revision 2. | (a) for 0.1.x. (b) lifts a ruleset candidate over the built-in `warn` candidates that the first overlap key compares, which breaks the ADR's containment rule ("can never silently outrank a built-in's resolved finding"). (c) is the honest long-term answer to "my ruleset should redact", but needs its own containment argument and is a revision-2 candidate, not a Beta.13 change. |
| D3 | Whether the CLI's `--redact --ruleset` should refuse to run. | (a) Keep: it runs and changes nothing for ruleset matches (tested). (b) Exit `2` with a usage message until D2(c) exists. | (a) with the help text from R5. Refusing would be a new failure mode for a documented combination. |
| D4 | Whether JavaScript should expose the rejection class. | (a) No: `SecretScanError` stays one fixed message per code (Rust, Python, CLI and the raw addon and WebAssembly errors already carry the class). (b) Add an optional field later. | (a); (b) is additive, so it can follow stable without a revision. |

## Method

- Source: `4069e52a7eed84274069541498fa08aaed8d3ffe` (`main`), `rustc` 1.98.1,
  Apple M4 (macOS arm64), Node.js 22.16.0. The machine was shared and heavily
  loaded (load average 40 to 80 while this ran). Durations below are the
  minimum of several runs, the least-disturbed sample, and are still upper
  bounds; only ratios and growth rates are claimed.
- Code read: `crates/secret-scan-core/src/ruleset.rs` (parser and error
  catalog), `src/detectors/ruleset_adapter.rs` (matching),
  `src/detectors/pattern.rs` (shared engine), `src/registry.rs`,
  `src/pipeline.rs`; the Node, WebAssembly and Python bindings'
  ruleset paths; `crates/secret-scan-cli/src/{args,modes,failure}.rs`;
  the guide, README section, ADR and fixture.
- Behavior probed with [`ruleset_probe.rs`](ruleset_probe.rs), a throwaway
  program on the public Rust API (`load_ruleset`, `DetectorRegistry`, `scan`).
  It is not built by the repository. All rulesets and inputs are synthetic.
- Competitive sources were fetched on 2026-10-02 from the primary
  documentation or source named in each row; what could not be verified is
  said so.

## Inventory of the shipped contract

| Item | Shipped value | Where defined |
| --- | --- | --- |
| Text format | UTF-8, at most 65,536 bytes, `key: value` lines, blank lines ignored | `ruleset.rs` `MAX_RULESET_BYTES`, `parse_ruleset` |
| First line | `ruleset-revision: 1` exactly; any other value `UNKNOWN_REVISION`, any other key `UNSUPPORTED_CONSTRUCT` | `parse_ruleset` |
| Blocks | `detector: <id>` (five fields) and `names: ambiguous` (`name:` lines); may interleave and repeat | `parse_ruleset` |
| `detector` id | `is_identifier`, which is `^[a-z][a-z0-9]*([._-][a-z0-9]+)*$` and at most 64 bytes; not a built-in or reserved id; unique in the ruleset | `flush_block`, `types.rs` |
| `specificity` | `entropy` or `contextual`; anything else `SPECIFICITY_NOT_CLAIMABLE` | `parse_specificity` |
| `prefix` | double-quoted, no escapes, 3 to 64 bytes, byte-exact and case-sensitive | `parse_prefix` |
| `alphabet` | `alnum`, `alnum-dash`, `alnum-dash-dot`, `upper-alnum`, `digit`, `lower-hex`, `base64-body` | `AlphabetName` |
| `run` | `exact <n>` or `at-least <n>`, 1 to 4,096 | `parse_run` |
| `validator` | `none` or `trailing-lower-hex` | `ValidatorName` |
| Names section | `names: ambiguous`; `name:` matching `[A-Za-z][A-Za-z0-9_.-]*`, at most 64 bytes, at most 32 added after de-duplication against built-ins | `flush_names` |
| Detector count | 1 to 64 `detector:` blocks (a names-only ruleset is valid) | `MAX_RULESET_DETECTORS` |
| Candidate | `Confidence::Medium` always; `type` equals the detector id; specificity as declared | `ruleset_adapter.rs` |
| Registration | after every built-in, profile identity unchanged (`Full` or `Common`) | `registry.rs`, ADR "Profile interaction" |
| Errors | one public code `INVALID_RULESET` and 18 classes in a `#[non_exhaustive]` `RulesetErrorClass` | `ruleset.rs` |
| Surfaces | Rust `load_ruleset`; JavaScript `ruleset` option on `scan` and `scanAndRedact` (Node, WebAssembly, both profiles); Python `ruleset=` on `scan` and `scan_and_redact`; CLI `--ruleset <path>` with an explicit file source | guide, bindings |
| Not accepted | incremental sessions and their stream adapters, CLI standard input, `redact` (it takes findings, not detectors), more than one ruleset per call | bindings, `args.rs` |

Counts: the parser has 45 unit tests, the adapter 11, and the reference fixture
covers 8 accepted detectors, the names section, one ordering tie and all 18
rejection classes. The ADR's "12 fixed classes" is stale; the fixture and guide
list 18.

## Research questions

### 1. Freeze-worthiness

**Is every field necessary?** Yes, with one qualification.

| Field | Verdict | Note |
| --- | --- | --- |
| `ruleset-revision` | Necessary | The only forward-compatibility gate (see below). |
| `detector` | Necessary | Becomes both `Finding.detector` and `Finding.type`. The type is therefore hyphenated (`acme-alnum-token`), unlike built-in snake_case types (`github_token`). That is a contract fact consumers key on; it goes in the guide. |
| `specificity` | Necessary, name is a rank not a method | `entropy` and `contextual` are only the two lowest tie-break ranks. Nothing is entropy-checked. A reader will assume otherwise, so the guide must say so; the name mirrors the public `Specificity` enum and should not be renamed. |
| `prefix`, `alphabet`, `run` | Necessary | They are the whole matching shape. |
| `validator` | Necessary only if `trailing-lower-hex` is needed | One real use (the Cloudflare shape). Keep: removing a field after stable is a break, adding one later is not. |
| `names: ambiguous` / `name:` | Necessary, but the bucket name leaks an implementation detail | `ambiguous` is `generic-token`'s internal bucket. A rename would be breaking, so v2 would add an alias rather than rename. The high-signal bucket stays unclaimable. |

**Misleading names likely to need a rename after stable.** None that justify
changing now. The risks are documentation: `specificity` (above) and
`ambiguous`.

**Defaults and omissions.** There are no defaults: all five fields are
required (`MISSING_FIELD`), the revision is mandatory, and nothing is inferred.
That is the right stable shape; a default added later is additive, a default
removed is not. `validator: none` is spelled out rather than omitted, which is
verbose but unambiguous.

**Is the text grammar specified well enough for an independent
implementation?** No. The guide describes fields, not the line grammar, so an
independent tool cannot tell what the Rust parser rejects. Probing found the
following ([`ruleset_probe.rs`](ruleset_probe.rs), `grammar()`):

#### Grammar and leniencies

| Input | Result | Assessment |
| --- | --- | --- |
| Byte order mark before the first line | `UNSUPPORTED_CONSTRUCT` | Safe (fail closed); Windows editors add one. Keep and document. |
| CRLF line endings | accepted | Fine. |
| `# comment` line, with or without a colon | `UNSUPPORTED_CONSTRUCT` | There is no comment syntax. Keep; a revision-2 candidate. |
| `ruleset-revision: 1.0`, `"1"` | `UNKNOWN_REVISION` | Correct. |
| A `detector:` block before the revision line | `UNSUPPORTED_CONSTRUCT` | The revision is mandatory and first. |
| Two rulesets concatenated (a second `ruleset-revision` line) | `UNKNOWN_FIELD` (read as a field of the open block), with the same or distinct ids | So two ruleset files cannot be joined; there is no include. |
| `Prefix:` (key case) | `UNKNOWN_FIELD` | Keys are case-sensitive. Document. |
| Tab between `at-least` and the count | `UNSUPPORTED_CONSTRUCT`; several spaces accepted | Document: space-separated. |
| Prefix containing `:`, `"`, `\`, spaces, non-ASCII | accepted | Fine and literal; there are no escapes. |
| Detector id `Acme-Token` or 65 bytes | `UNSUPPORTED_CONSTRUCT` | The id grammar is not stated in the guide. Document `is_identifier`. |
| `validator: trailing-lower-hex` with `alphabet: upper-alnum` | accepted | Harmless (only digits can satisfy it) but incoherent. Document; do not reject. |
| `ruleset-in-common`: a ruleset on a `common` registry | accepted, registry reports `Common` | As designed. |
| **Repeated field** (`prefix:` twice) | accepted, **last one wins** | **R1.** Contradicts "exactly once". A typo that duplicates a field silently changes what is detected. |
| **Prefix with a zero-width character** | accepted, **never matches** (0 findings on input that contains the literal) | **R2.** Detection runs on the copy with invisible characters removed ([normalization decision](../../../decisions/2026-09-19-normalize-invisible-characters-before-detection.md)), so the prefix cannot occur. A fail-open loader: the author believes a format is covered. |
| **`run: at-least +20`, `at-least 020`** | accepted | **R3.** Rust's integer parser is more permissive than the intended grammar. |

Reported ranges are correct when the *input* contains invisible characters
(`ACME​_...` is found and the range covers the original bytes), so the
normalization interaction is sound except for the prefix itself.

##### Normative grammar for revision 1

This is the grammar the parser implements, with R1 to R3 applied. It is the
text R4 moves into the guide.

```text
ruleset      = *blank revision *( blank / block )
revision     = "ruleset-revision:" SP "1" EOL            ; first non-blank line
block        = detector-block / names-block
detector-block = "detector:" SP id EOL 5( field )        ; each field exactly once, any order
field        = specificity / prefix / alphabet / run / validator
specificity  = "specificity:" SP ( "entropy" / "contextual" ) EOL
prefix       = "prefix:" SP DQUOTE 3*64 OCTET DQUOTE EOL ; no escapes, no invisible code points
alphabet     = "alphabet:" SP ( "alnum" / "alnum-dash" / "alnum-dash-dot" / "upper-alnum"
                              / "digit" / "lower-hex" / "base64-body" ) EOL
run          = "run:" SP ( "exact" / "at-least" ) 1*SP count EOL
count        = nonzero-digit *DIGIT                      ; 1..4096, canonical decimal
validator    = "validator:" SP ( "none" / "trailing-lower-hex" ) EOL
names-block  = "names:" SP "ambiguous" EOL *( "name:" SP name EOL )
name         = ALPHA *( ALPHA / DIGIT / "_" / "." / "-" ) ; at most 64 bytes
id           = lower *( lower / DIGIT ) *( ( "." / "_" / "-" ) 1*( lower / DIGIT ) )
                                                         ; is_identifier, at most 64 bytes
blank        = *WSP EOL
```

Whole-document rules: UTF-8 (no byte order mark), at most 65,536 bytes, at
most 64 detector blocks and at least one detector block or one `name:`, keys case-sensitive, whitespace at the
start and end of a line and around the first `:` ignored, no comments, no
escapes, no include.
Anything else is one of the 18 classes and the whole document is rejected.

### 2. Revisioning and forward compatibility

Proposed policy (to be recorded as a decision, R7):

| Question | Answer |
| --- | --- |
| What does `ruleset-revision: 2` mean? | A different, versioned grammar identified by the first line. A library that does not know it fails closed with `UNKNOWN_REVISION`, never partially loads and never guesses. |
| Can revision 1 and 2 coexist in one stable library? | Yes. The revision selects the parse function; both produce the same internal specification type, so matching, ordering and the `Detector` adapter are shared. The first line is already parsed alone, before any block, so no parser restructuring is needed. |
| Must unknown future fields keep failing closed? | Yes, in every revision. This is what makes it safe for a ruleset written for a newer library to meet an older one: it is rejected, not silently weakened. Competitors that skip unknown keys fail open; see below. |
| Can revision 2 add fields and preserve revision 1 byte for byte? | Yes, and it should. Revision 1 means exactly the vocabulary frozen at 0.1.0: the same bytes are accepted or rejected with the same class, and produce the same candidates, for as long as revision 1 is supported. Revision 2 may be a strict superset (every valid revision-1 body is valid under `ruleset-revision: 2` with the same meaning), so migration is editing one line. |
| How long is revision 1 supported after revision 2 exists? | Recommended: for the whole major version series in which revision 2 first ships and the next one; removal only in a major release, with a decision record and a migration note. A 0.x library may not drop it. |
| May alphabets or validators grow inside revision 1? | **No.** Growing the vocabulary is additive for the library but not for the file: a ruleset using a new alphabet would load on a new binding and be rejected by an older one, so "revision 1" would stop naming one thing. Safe, because the failure is closed, but it makes the revision number meaningless as a portability guarantee. New alphabets, validators, specificities, fields and block kinds go into the next revision. |
| May cost bounds change inside revision 1? | Tightening: no (it rejects accepted files). Loosening: no, for the same portability reason. They change with the revision. |
| What is additive and allowed within revision 1? | New `RulesetErrorClass` variants only where they relabel a rejection that already happened (the enum is `#[non_exhaustive]`); performance work; diagnostics; new surfaces that accept the same bytes (for example incremental sessions). Everything that changes which bytes are accepted, or what an accepted file detects, is a new revision. |
| What is semantic breakage? | A different match for an accepted file (changed alphabet membership, boundary rule, validator semantics, tie-break, confidence), a changed `type` or `detector` string, a changed default action, a removed field. |

Cost of the policy: a new alphabet needs a revision bump even though it is a
one-line change. That is intended; bindings ship in lockstep, so the bump
costs nothing to adopt.

### 3. Expressiveness boundary

Recommendation: **keep every deferred construct excluded from revision 1.**

| Excluded construct | Keep excluded? | Reason | Where it would come from |
| --- | --- | --- | --- |
| Context keywords, proximity | Yes | Needs a second matching pass and a window rule; the built-in contextual detectors and the names section already cover the common case (an in-house assignment keyword). Every comparison tool has keywords, so it is the most requested next feature. | Revision 2 candidate, if measured demand: a bounded keyword gate (literal list, fixed window) |
| Companion fields | Yes | Requires multi-match semantics and a notion of related findings; none exists in `Finding`. | Not planned |
| Negative context, allow-lists | Yes | A false-positive control would be valuable, but it is exactly the surface where ReDoS-free guarantees and ordering get complicated. | Revision 2 candidate: literal deny-list on the matched value only |
| Include/exclude paths | Yes | The core scans text and has no notion of a path; the CLI chooses its sources. | Host concern (CLI flag), never the ruleset |
| `AND` / `OR` / `NOT`, nesting | Yes | Turns the format into an expression language and breaks the "one `PrefixShape`" invariant. | Not planned |
| Rule references | Yes | Ordering and cycle questions for no stated need. | Not planned |
| Regex | Yes | A second matching engine is what the ADR rejected: it cannot be linear-time and identical on four runtimes without a dependency the core forbids by policy. | Not planned; FRS-1-style subsets exist but need their own engine |
| Caller-set confidence, entropy, action | Yes for 0.1.x | Confidence is the one tie-break key the specificity cap does not bound; a settable action lifts a ruleset over built-in `warn` candidates (see D2). | Revision 2 candidate for `action` only, with a containment argument |
| Arbitrary post-checks | Yes | A callback or expression is exactly what the ruleset exists to avoid. | Named, core-provided validators (for example the Luhn and IBAN checks that already exist internally) can be added to the closed enum in a new revision |
| PII rules | Yes | PII has its own domain, arbitration and activation contract; a ruleset cannot name a PII selector. | Not planned |

### 4. Security and complexity invariants

| Invariant | Result |
| --- | --- |
| Linear matching, no ReDoS | Holds. A 3-byte prefix over one long run (`at-least 4096`, `exact 4096`) and a periodic prefix, at 64 KiB, 256 KiB, 1 MiB and 4 MiB: time grows about 4x per 4x of input (the periodic prefix: 2.4, 9.5, 45 and 192 ms; the others differ by at most one noisy step). A quadratic engine would have grown 16x per step. The engine memoizes run ends (`pattern.rs` `RunEnds`), so a rejected start does not rescan. |
| Detector count times input | Holds. 64 three-byte prefixes against an input engineered to hit all of them and produce 21,000 findings cost 2.2x the built-ins alone on 1 MiB (97 ms against 43 ms); on ordinary text the ruleset added no measurable cost (19.4 ms against 21.6 ms). The shared prefilter rules a detector out before it searches. |
| Prefix and run bounds | Prefix 3 to 64 bytes, run 1 to 4,096, 64 detectors, 32 names, 64 KiB, all enforced before any scan and tested at the boundary (`run-4096` accepted, `run-4097` `RUN_LENGTH_OUT_OF_BOUNDS`, id of 64 bytes accepted, 65 rejected). |
| Name expansion | At most 32 normalized names added, compared per captured assignment name; bounded and linear. |
| Overlap containment | Holds. The reference fixture's ordering case and a probe with a ruleset prefix `ghp_` show the built-in `github-token` winning at the same span. A ruleset can add detections but not displace a built-in. |
| Plaintext-free errors | Holds. Every rejection is a fixed class; the CLI test seeds a canary into the ruleset and finds it in neither stream. |
| Malicious or oversized ruleset | Rejected whole before parse work scales: over 64 KiB `RULESET_TOO_LARGE`, invalid UTF-8 `UNSUPPORTED_CONSTRUCT`. |
| Unicode and invisible characters | Sound for input (ranges cover the original bytes), unsound for the prefix (R2). |
| Incremental and streaming exclusion | Acceptable for stable. The reason in the guide is that no ruleset detector declares the retention bound a session must enforce. That is a limitation, not a principle: a `run: at-least` match has no length bound of its own (only its minimum is bounded), so supporting sessions needs a design that ties it to the session's token limit, but lifting the exclusion later accepts the same bytes and is additive. It must be listed as unsupported, which also means CLI `--ruleset` requires a file source and the JavaScript stream adapters take no ruleset. |
| Detector id and type collisions | A ruleset id cannot be a built-in id or a reserved id (`RESERVED_DETECTOR_ID`). `type` equals the id, so it cannot collide with a built-in snake_case type either. |
| Composing rulesets | Not supported and not documented: two value rulesets with distinct ids can be registered together in Rust (112 detectors), two rulesets that both have a names section cannot (both register the same internal detector id, `INVALID_DETECTOR`), and the bindings accept exactly one. Document "one ruleset per call". |

### 5. Runtime and API ergonomics

| Surface | Ownership and caching | Notes |
| --- | --- | --- |
| Rust | `load_ruleset(&[u8]) -> Vec<Box<dyn Detector>>`, consumed by `DetectorRegistry::with_built_in` or `with_common_built_in` | Detectors are boxed and not `Clone`, so each registry needs its own load. Parse alone for 64 detectors (the maximum) took 55 us, parse plus registry 87 us, and a built-in-only registry 15 us. |
| JavaScript (Node) | `ruleset?: Uint8Array \| string`; one-entry per-thread cache keyed by (profile, PII selection, ruleset bytes), a rejected ruleset is never cached (#1059) | Alternating between two rulesets rebuilds every call. Measured below. |
| JavaScript (WebAssembly) | Same one-entry cache keyed by the bytes | The parser is linked into every artifact, including `common`: +23,724 B raw and +7,167 B brotli on `full` when it landed ([#495](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/495/README.md)). Consumers who never load a ruleset pay it. |
| Python | `ruleset=` bytes, bytearray or str; one-entry per-thread cache keyed by (PII epoch, bytes) | Detection runs with the GIL released. |
| CLI | `--ruleset <path>`; read once, parsed to validate, one registry for all files (#1059) | Requires an explicit file source. |

#1059 is confirmed fixed in the code of every binding. The measurement of the
bindings is in [Cross-runtime conformance](#cross-runtime-conformance).

### 6. Competitive research

Sources fetched 2026-10-02. "Not found" means the primary page I read did not
say; it is not evidence of absence.

| Tool | Expressive power | Runtime-code / ReDoS | Portability | Verification / network | Override built-ins | FP controls | Versioning |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [flare-redact](https://github.com/flare-collection/flare-redact) | Custom JavaScript `RegExp` detectors, plus FRS-1 data packs with named native validators, context windows and allow-lists | Custom `RegExp`: its own README says JavaScript RegExp "does not provide a formal linear-time guarantee". FRS-1 forbids lookaround, backreferences and `\d \w \s`; input capped at 16 MiB, findings at 50,000 | FRS-1 has one spec and a cross-language corpus (4 languages) | Not found | Not verified | prefilter literals, 80-character context window, allow-lists, named validators | Spec marked "stable", revision "FRS-1"; per its spec an unknown version, field or construct rejects the pack (the Go SDK page says the same; not confirmed in the spec text) |
| [TruffleHog](https://trufflesecurity.com/docs/custom-detectors) | YAML regex with `keywords`, `entropy`, `exclude_words`, `exclude_regexes_*` | Go regex; linear time not stated | Go only | Optional HTTP verification webhook: the candidate secret is sent over the network | Not verified | keywords, entropy, exclusions | No schema version found |
| [Gitleaks](https://raw.githubusercontent.com/gitleaks/gitleaks/master/README.md) | TOML `regex`, `secretGroup`, `entropy`, `path`, `keywords`, allowlists with `condition` | Go regex, no lookahead; no user code | Go only | None found | `[extend]`: extended rules take precedence on a duplicate id; `disabledRules` drops inherited ones | allowlists (AND/OR), stopwords, entropy, keywords | The default config names a minimum tool version; unknown-field behavior not found |
| [Presidio](https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/pattern_recognizer.py) | Regex or deny-list recognizers, context words, `validate_result` / `invalidate_result`, subclasses with arbitrary Python, remote recognizers, YAML | Python `regex` module with a 60 s default timeout as the ReDoS defense (nondeterministic); subclasses run arbitrary code | Python only | `RemoteRecognizer` calls external detectors | Registry removal discussed, not verified | context words, validators, scores | No version found (tutorial page returned 404; some points come from search snippets) |
| [OpenRedaction](https://raw.githubusercontent.com/sam247/openredaction/main/README.md) | `customPatterns`: regex, priority, placeholder, severity | JavaScript `RegExp`; no ReDoS protection documented | JavaScript only | Local-only claim | Undocumented | Not documented | Not documented |

What Redact Secret should **not** copy:

- Arbitrary regex as the rule body (flare-redact custom detectors, TruffleHog,
  Gitleaks, Presidio, OpenRedaction): it is what makes the others
  engine-specific and, for JavaScript and Python, not linear-time.
- Callbacks and subclasses (Presidio, flare-redact custom detectors) and
  verification webhooks (TruffleHog, Presidio remote recognizers): they send or
  expose plaintext, which the core's boundary (no network, no plaintext
  across a callback) rules out.
- A wall-clock timeout as the complexity defense (Presidio): nondeterministic.
- Silent override by duplicate id (Gitleaks `extend`): the reserved-id rule is
  stricter on purpose.
- Numeric `priority` as an implicit overlap resolver (OpenRedaction): ordering
  here is the documented precedence.

What the comparison supports keeping: only FRS-1 documents rejecting unknown
fields, versions and constructs. No other tool in the set had a rule-format
version I could verify, so a fail-closed revision line is a differentiator,
not table stakes.

## Default action of a ruleset detection

Every ruleset candidate is `Confidence::Medium` and its `type` is the detector
id, which is in no always-redact list. The default policy redacts only high
confidence or a known type, so it returns `warn`. Probe and tests agree:

| Check | Result |
| --- | --- |
| `scan_and_redact` with a ruleset and `DefaultPolicy` | one finding, `action=Warn`, `confidence=Medium`, text unchanged |
| CLI test `ruleset_applies_in_redact_mode_too_though_default_policy_only_warns_at_medium_confidence` | `--redact --ruleset` exits `0` and the output equals the input |
| The reference fixture | pins detector, type, confidence and range, **not action** |
| The guide, README section and CLI help | do not mention it; the guide's example calls `scanAndRedact(input, { ruleset })` |

So the documented path reads as "declare your internal token and it is
redacted", and does not do that. This is a design consequence (the fixed
medium confidence is what contains a ruleset), not a defect in the code, but
it is a contract gap in the documentation, and the most likely first surprise
for a user. R5 closes it; D2 records why the alternatives were not chosen.

## Cross-runtime conformance

Run on the same source commit, `4069e52a7eed84274069541498fa08aaed8d3ffe`.

| Surface | What ran | Result |
| --- | --- | --- |
| Rust core | `tests/ruleset_conformance.rs` (accepted, names, ordering, all 18 classes) and the 45 parser and 11 adapter unit tests | pass: `ruleset_conformance` 5 of 5; the whole workspace run (`cargo test --workspace --locked --no-fail-fast`) passed 2,635 tests with none failed |
| Python | `test_ruleset_conformance.py` and `test_ruleset.py`, inside `pytest bindings/python/tests` | pass (9,084 tests in the suite) |
| Node addon | The same fixture through the raw addon `scan` (a one-off runner: 8 accepted cases and the names, ordering and 18 rejection cases, 31 checks; offsets converted from UTF-8 bytes to UTF-16 units) | 31 of 31 |
| WebAssembly (`full`) | The same one-off runner through the generated glue of the artifact built from this commit | 31 of 31 |
| CLI | The same fixture through the release binary with `--json --ruleset` (UTF-8 byte ranges compared directly; 18 rejection files exit `2` with `INVALID_RULESET`) plus `tests/cli.rs` ruleset tests | 31 of 31. The CLI states the rejection class as 18 distinct fixed sentences, not by class name |
| Error format | Rust, Python, the Node addon and WebAssembly append the class name in parentheses; the CLI prints a per-class sentence; the public JavaScript `SecretScanError` prints neither (D4) | as designed |

Only the Rust and Python rows are CI-gated today. The Node, WebAssembly and CLI
rows are one-off runs for this record (R6): the fixture's own description says
every surface runs it, `conformance/README.md` names only the Rust and Python
consumers, and `scripts/qualify-*.mjs` contain no ruleset case.

The runs used the conformance tree identity
`e4609c2025634872ff000bb036a061b2d1e661f5` (`git rev-parse HEAD:conformance`).

##### Repeated-call cost (#1059)

Per-call cost of a short scan, minimum of five batches, release builds of the
addon and the artifact (the Python extension was a debug build, so only its
ratios are meaningful). The host was loaded; compare rows within a column.

| Case | Node addon | WebAssembly | Python (debug build) |
| --- | --- | --- | --- |
| Scan, no ruleset | 23.7 us | 109.0 us | 1,289 us |
| Scan, same 8-detector ruleset every call | 35.2 us | 131.9 us | 1,033 us |
| Scan, two rulesets alternating | 231.5 us | 905.7 us | 3,467 us |

The #1059 fix holds: repeating one ruleset costs 11 to 23 us over no ruleset
(a byte comparison of the ruleset against the cache key, no re-parse), instead
of a parse and registry build per call. The remaining footgun is the
one-entry cache: a caller that alternates two rulesets, for example one per
tenant, rebuilds on every call and pays 6.6x (Node), 6.9x (WebAssembly) and
3.4x (Python debug) a cached call. That is a documented-limit candidate, not a
defect; a larger cache is additive and can follow stable. Rust and the CLI
parse once by construction (55 us for a 64-detector ruleset).

## Reproduce

```bash
# probe (public Rust API, throwaway)
cp docs/audits/evidence/1072/ruleset_probe.rs <scratch>/src/main.rs   # see the file header
cargo run --release

# shared reference fixture
cargo test -p redact-secret --test ruleset_conformance --locked
python -m pytest bindings/python/tests/test_ruleset.py bindings/python/tests/test_ruleset_conformance.py
cargo test -p redact-secret-cli --test cli --locked ruleset
```

## Implementation

Added after the owner accepted D1(a), D2(a), D3(a) and D4(a). Everything above
this heading is the audit as it was written; this section records what landed.

### #1182: R1 to R5

| Row | What changed | Class | Where |
| --- | --- | --- | --- |
| R1 | A field repeated inside one `detector:` block is rejected | `UNSUPPORTED_CONSTRUCT` | `ruleset.rs` `flush_block` |
| R2 | A `prefix` containing a code point `normalize::is_invisible` removes is rejected | `UNSUPPORTED_CONSTRUCT` | `ruleset.rs` `parse_prefix` |
| R3 | A `run` count must be ASCII digits without a leading zero (`+20`, `020`, `00` rejected); a lone `0` stays `RUN_LENGTH_OUT_OF_BOUNDS` | `UNSUPPORTED_CONSTRUCT` | `ruleset.rs` `parse_run` |
| R4 | The normative grammar is published in `docs/guides/rulesets.md#grammar` | n/a | guide |
| R5 | The default action `warn` is stated in the guide, the README and the CLI `--help` and README text for `--ruleset`; the reference fixture pins `action` for every ruleset detection | n/a | guide, README, CLI, fixture |

No new rejection class was needed: all three tightenings use the existing
`UNSUPPORTED_CONSTRUCT`, so the 18 classes and the `#[non_exhaustive]` enum are
unchanged. The CLI sentence for that class now also says "repeated field". The
fixture keeps `rejections` as one entry per class (18) and adds
`tightenedRejections` (9 inputs: five repeated fields, two invisible prefix
characters, `+20` and `020`) so the "each class exactly once" check still
holds. The grammar rule for a count of `0` differs slightly from the draft's
`nonzero-digit *DIGIT`: `0` is a bounds error, not a shape error, because that
class already existed and fixtures pin it.

Deviation from the audit's draft: none beyond that sentence. D2, D3 and D4 are
documentation only.

### #1183: R6

The reference fixture now runs in CI on the Node addon
(`scripts/qualify-node-addon.mjs`, both profiles), the WebAssembly artifact
through its generated glue in the Node fallback job
(`scripts/qualify-node-wasm-fallback.mjs`, both profiles) and the release CLI
(`scripts/qualify-cli-binary.mjs`), through one shared checker,
`scripts/lib/ruleset-reference.mjs`. They are existing steps of the
artifact-qualification workflow, which `release.yml` also calls, so no job or
matrix leg was added; the only workflow change is that a change to the shared
checker triggers the pull-request run. Each run checks 40 cases: 9 accepted
(with the `warn` action), 3 names, 1 ordering, the 18 class rejections and the
9 `tightenedRejections`. Offsets are compared in UTF-8 bytes for the CLI and
UTF-16 for the JavaScript surfaces, converted by an independent function. The
class is read from the raw addon and glue error message and from the CLI's
fixed per-class sentence; the public JavaScript package hides it by design
(D4), so it is not run through this checker. Rust and Python keep their own
consumers.

The browser pages are not extended. They run the same glue and `.wasm` bytes,
but their harness runs in a page with a hand-built fixture payload and no
shared module with this checker, so adding the fixture there needs a
browser-safe copy of the checker. The fixture description says so.

## Owner decisions

Accepted by the owner on 2026-10-02, **as recommended**.

| # | Decision | Accepted |
| --- | --- | --- |
| D1 | Revise before stable (R1 to R3), then freeze revision 1 | 2026-10-02, option (a) as recommended |
| D2 | A ruleset detection stays `warn` under the default policy; documented as the 0.1.x contract | 2026-10-02, option (a) as recommended |
| D3 | `--redact --ruleset` keeps running; documented | 2026-10-02, option (a) as recommended |
| D4 | JavaScript errors stay one fixed message per code; an additive optional field may follow later | 2026-10-02, option (a) as recommended |

## Outcome

- R1 to R5 landed in [#1182](https://github.com/redact-secret/redact-secret/issues/1182)
  and R6 in [#1183](https://github.com/redact-secret/redact-secret/issues/1183)
  (see Implementation above).
- R7 is written and accepted:
  [`decision-define-declarative-ruleset-revisioning`](../../../decisions/2026-10-02-define-declarative-ruleset-revisioning.md),
  linked from `docs/specs/engine.md`. The ADR amendment for the stale
  dependency and class facts landed in
  [#1185](https://github.com/redact-secret/redact-secret/issues/1185).
- The accepted contract text is in
  [`api-contract.md`](../../../reference/api-contract.md#stable-contract-1).
- Remaining: conformance of the ruleset on the candidate artifacts
  ([#199](https://github.com/redact-secret/redact-secret/issues/199)) and the
  benchmarks follow-ups
  [`redact-secret/redact-secret-benchmarks#647`](https://github.com/redact-secret/redact-secret-benchmarks/issues/647)
  and
  [`redact-secret/redact-secret-benchmarks#648`](https://github.com/redact-secret/redact-secret-benchmarks/issues/648).
