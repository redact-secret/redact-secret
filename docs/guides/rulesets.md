# Declarative rulesets

[Documentation home](../README.md) · [Detection and limits](../reference/detection.md)

An organization with an internal credential format — an in-house service
token, a partner API key, a legacy prefix — can declare it without writing
code. A ruleset is UTF-8 text, at most 64 KiB, matched by the same
linear-time, ReDoS-free engine every built-in detector already runs through
(`crates/secret-scan-core/src/detectors/pattern.rs`): no regex, no new
matching vocabulary.

Custom detector callbacks are not part of the cross-language extension
surface: all built-in detectors run in Rust, and bindings must not create
another detector implementation. A ruleset is data the core parses and
matches itself, never a callback. The contract is
[`decision-define-declarative-detector-ruleset-contract`](../decisions/2026-09-19-define-declarative-detector-ruleset-contract.md);
issues #495 and #484 implement it for the Rust core, JavaScript (Node and
browser WebAssembly), Python, and the CLI.

## Write a ruleset

```text
ruleset-revision: 1
detector: acme-internal-token
specificity: contextual
prefix: "ACME_"
alphabet: alnum-dash
run: at-least 20
validator: none
```

The first line is always `ruleset-revision: 1`. Every following `detector:
<id>` line starts a block of exactly five fields, each given exactly once (a
repeated field is rejected; the last one does not win):

| Field | Values |
| --- | --- |
| `specificity` | `entropy` or `contextual` only — `structural`, `provider`, and `private-key` are reserved to built-in detectors and rejected |
| `prefix` | a double-quoted literal, 3–64 bytes, matched byte-exact and case-sensitive (no escape sequences); it may not contain an invisible or format code point, because detection runs on a copy with those removed and such a prefix could never match |
| `alphabet` | one of `alnum`, `alnum-dash`, `alnum-dash-dot`, `upper-alnum`, `digit`, `lower-hex`, `base64-body` |
| `run` | `exact <n>` or `at-least <n>`, `1 ≤ n ≤ 4096`, `<n>` in canonical decimal (`+20` and `020` are rejected) |
| `validator` | `none`, or `trailing-lower-hex` (the matched run's final `n` alphabet bytes — `n` from the block's own `run` count — must be lowercase hex) |

## Matching semantics

A ruleset detector's matching semantics are exactly a built-in prefixed
detector's:

- **Case-sensitive, byte-exact prefix matching.** No case folding, no NFKC,
  no decoding, no unescaping.
- **Matching runs on the normalized scan copy; reported ranges use original
  input coordinates.** Every detector matches after invisible and format
  code points are stripped
  (`decision-normalize-invisible-characters-before-detection`); every
  reported range is translated back to the caller's original text before it
  becomes a public result. A ruleset detector is not a special case.
- **Boundary behavior is fixed, not caller-configurable.** A match that is a
  truncated slice of a longer run of the same alphabet is rejected, not
  truncated — a ruleset has no way to loosen or tighten this.

Every ruleset candidate carries `Confidence::Medium`, fixed regardless of the
ruleset's own content, and registers after every built-in detector. Combined
with the specificity restriction above, a ruleset can add detections but can
never silently outrank a built-in's resolved finding. A caller with a loaded
ruleset still sees `Full`/`Common` from `DetectorRegistry::profile()`;
ruleset presence is a separate fact the caller already has from the number
of detectors `load_ruleset` returned.

## Default action

Because every ruleset candidate is medium confidence and its `type` is the
detector id (not a known credential type), the default policy returns `warn`
for it: the finding is reported, and `scanAndRedact`, `scan_and_redact` and
`redact-secret --redact` leave the matched text in place. This is the
contract, not a gap: the fixed medium confidence is what keeps a ruleset from
outranking a built-in, and the reference fixture pins `action: warn` for every
ruleset detection on every surface. To redact a ruleset detection, supply a
policy that returns `redact` for its detector id (Rust, JavaScript, Python).
Without `--action-policy`, the CLI can report a ruleset detection in check mode
but not remove it in redact mode: `--redact --ruleset` still runs, and
changes nothing for ruleset matches. One rule in an
[action policy](action-policy.md) (`--action-policy`) makes it redact. Check mode flags it either way. A
caller-set action is out of scope for revision 1.

## Grammar

This is the normative text grammar of `ruleset-revision: 1`, in the ABNF style
of RFC 5234. The Rust parser implements it for every surface, and the
conformance fixture (`conformance/fixtures/ruleset-reference.json`) pins it.

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
                                                         ; at most 64 bytes
blank        = *WSP EOL
```

Whole-document rules:

- UTF-8, no byte order mark (a leading one is `UNSUPPORTED_CONSTRUCT`), at
  most 65,536 bytes, at most 64 `detector:` blocks, and at least one
  `detector:` block or one `name:` line.
- Keys are case-sensitive. Whitespace at the start and end of a line and
  around the first `:` is ignored. Separate the words of a `run` value with
  spaces, not tabs.
- No comments (a `#` line is `UNSUPPORTED_CONSTRUCT`), no escapes, no include,
  and no concatenation: a second `ruleset-revision` line is read as an unknown
  field of the open block.
- `detector:` and `names:` blocks may interleave and repeat. A field repeated
  inside one `detector:` block is `UNSUPPORTED_CONSTRUCT`.
- A detector id must be a lowercase identifier (`is_identifier`) that is not a
  built-in or reserved id, and unique in the ruleset. Its `Finding.type` is the
  id itself, hyphens included (`acme-internal-token`), unlike the snake_case
  types of built-in detectors.
- `specificity` is only a tie-break rank; nothing is entropy-checked.
- A `count` of `0` is `RUN_LENGTH_OUT_OF_BOUNDS`; any other non-canonical form
  (a sign, a leading zero, a non-digit) is `UNSUPPORTED_CONSTRUCT`.
- Anything else the grammar does not accept is one of the 18 classes below, and
  the whole document is rejected.

## Names section

A ruleset can also add to `generic-token`'s contextual-assignment name
vocabulary, without a `detector:` block at all:

```text
ruleset-revision: 1
names: ambiguous
name: corp_passphrase
```

`names: ambiguous` is the only claimable bucket in this revision — a caller
can add an in-house assignment keyword (`corp_passphrase`) to the same **ambiguous**
bucket `auth`/`credential`/`signing_key` already belong to, kept at that
bucket's higher entropy bar and always `Confidence::Medium`; a ruleset cannot
add to the high-signal bucket (`api_key`, `password`, …) in this revision.
Every `name:` value is normalized the same way a scanned input's captured
assignment name already is, so `CorpPassphrase`, `corp-passphrase`, and `corp_passphrase` are
the same addition. A name that normalizes to an existing built-in name is a
silent no-op — a ruleset can never remove, override, or re-bucket a built-in
name. A names-only ruleset (no `detector:` blocks) is valid; a names section
registers its own separate detector rather than changing `generic-token`
itself, so it inherits the same containment property as a value-section
ruleset detector.

## Rejection

A malformed ruleset is rejected as a whole — never partially loaded — with
the fixed `INVALID_RULESET` code and one of a closed set of rejection
classes (`RulesetErrorClass`: `RULESET_TOO_LARGE`, `UNKNOWN_REVISION`,
`UNKNOWN_FIELD`, `UNSUPPORTED_CONSTRUCT`, `UNKNOWN_ALPHABET`,
`UNKNOWN_VALIDATOR`, `SPECIFICITY_NOT_CLAIMABLE`, `MISSING_FIELD`,
`PREFIX_TOO_SHORT`, `PREFIX_TOO_LONG`, `RUN_LENGTH_OUT_OF_BOUNDS`,
`TOO_MANY_DETECTORS`, `DUPLICATE_DETECTOR_ID`, `RESERVED_DETECTOR_ID`,
`EMPTY_RULESET`, `NAME_BUCKET_NOT_CLAIMABLE`, `NAME_TOO_LONG`,
`TOO_MANY_NAMES`) — never a byte from the rejected ruleset. Python raises it
as `InvalidRulesetError`. A repeated field, an invisible or format character
in a `prefix`, and a non-canonical `run` count are all
`UNSUPPORTED_CONSTRUCT`. The class is available in Rust, Python, the CLI
(as a fixed sentence per class), and the raw Node addon and WebAssembly errors;
the public JavaScript `SecretScanError` carries only the `INVALID_RULESET` code
and one fixed message.

## Load a ruleset on each surface

- **Rust:** `redact_secret::load_ruleset(bytes) -> Result<Vec<Box<dyn Detector>>, RulesetError>`,
  registered the same way a native custom detector is:
  `DetectorRegistry::with_built_in(detectors)`.
- **JavaScript (Node and browser WebAssembly):** a `ruleset` option on `scan`/
  `scanAndRedact`, taking a `Uint8Array` or a UTF-8 `string`.
- **Python:** a `ruleset` keyword argument on `scan`/`scan_and_redact`, taking
  `bytes`, `bytearray`, or `str`.
- **CLI:** `--ruleset <path>`, requiring an explicit file source — standard
  input's streaming session accepts no custom detector, ruleset or
  otherwise, because none declares the retention bound a streaming session
  must enforce.

```ts
import { readFile } from "node:fs/promises";
import { initialize, scanAndRedact } from "@redact-secret/core";

await initialize();
const ruleset = await readFile("acme.ruleset");
const result = scanAndRedact(input, { ruleset });
```

```python
import redact_secret

with open("acme.ruleset", "rb") as file:
    ruleset = file.read()
result = redact_secret.scan_and_redact(text, ruleset=ruleset)
```

```bash
redact-secret --ruleset acme.ruleset config.txt
```

## Out of scope

Deliberately out of scope for this revision: `AND`/`OR`/`NOT`, nesting,
rule-to-rule reference, context keyword/companion fields, caller-set
confidence or entropy threshold, regex or any pattern beyond the alphabets
above, and migrating built-in detectors onto this format. See
`decision-define-declarative-detector-ruleset-contract` for the full
rationale.
