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
<id>` line starts a block of exactly five fields:

| Field | Values |
| --- | --- |
| `specificity` | `entropy` or `contextual` only — `structural`, `provider`, and `private-key` are reserved to built-in detectors and rejected |
| `prefix` | a double-quoted literal, 3–64 bytes, matched byte-exact and case-sensitive (no escape sequences) |
| `alphabet` | one of `alnum`, `alnum-dash`, `alnum-dash-dot`, `upper-alnum`, `digit`, `lower-hex`, `base64-body` |
| `run` | `exact <n>` or `at-least <n>`, `1 ≤ n ≤ 4096` |
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
as `InvalidRulesetError`.

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
