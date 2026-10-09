# Email family contract v1

This contract applies the accepted `pii-v1` domain policy to one family. It is
the product-side contract for issue #876, not a claim of benchmark
qualification or stable support.

## Identity and activation

| Field | Value |
| --- | --- |
| Family | `pii:global:email` |
| Exact selector | `pii:family:global:email` |
| Identity domain | `email` |
| Public finding type | `pii_global_email` |
| Detector | `pii-domain` |
| Family-contract version | `1` |
| Qualification profile | `pii-v1` |
| Context requirement | `required-for-sensitive-classification` |
| Initial status | `pending` until exact-artifact benchmark evidence is reviewed |

`pii:global` closes over this family. An empty selector list remains byte-for-
byte credential-only behavior.

## Supported RFC 5322 / RFC 6531 subset

The detector recognizes one whole `addr-spec` candidate with these deliberate
limits:

- The local part is one or more dot-separated atoms. ASCII atoms use RFC 5322
  `atext`; non-ASCII atom characters are Unicode alphabetic or numeric scalar
  values admitted by the RFC 6531 SMTPUTF8 extension. The original spelling
  and case are preserved.
- The domain is ASCII LDH syntax (including syntactically valid-looking
  `xn--` labels; v1 does not decode or validate IDNA) and has at least two
  dot-separated labels, except that the exact
  single-label RFC 6761 names `example`, `invalid`, `localhost`, and `test` are
  admitted only as non-sensitive reserved controls. A label starts and ends in
  an ASCII alphanumeric; its interior may additionally contain `-`. ASCII
  domain comparison for reserved
  namespaces is case-insensitive. The detector does not perform DNS, IDNA, or
  case conversion.
- Local part length is 1–64 UTF-8 bytes, every domain label is 1–63 UTF-8
  bytes, the domain is at most 255 UTF-8 bytes, and the complete candidate is
  at most 254 UTF-8 bytes. These are byte bounds, including for SMTPUTF8.
- A candidate must be bounded on the left by something other than local-part
  atom syntax, `.`, or `@`, and on the right by something other than a
  domain-label character, `.`, or `@`. One exception
  ([#926](https://github.com/redact-secret/redact-secret/issues/926)): RFC
  5322 `atext` includes `=`, so in `key=local@domain` the local-part run
  starts at the key. When the run before its first `=` is a reviewed
  `pii-context` high-signal email field label after the context-only
  normalization (the whole key, or its last separator-delimited tokens:
  `email`, `e-mail`, `customer_email`, `이메일`, `고객_이메일`), that run and the
  `=` are a label, and the candidate starts after the `=`. The remainder must
  still be a valid local part, or there is no candidate. Any other key
  (`user=`, `emailx=`, `user.email=`) and any later `=` stay local-part
  syntax. `atext` also includes `|`, so in a pipe-delimited record
  (`id=7|email=local@domain`) the run starts at the first field
  ([#940](https://github.com/redact-secret/redact-secret/issues/940)): each
  `|` starts a new field, the run from it to that field's first `=` is judged
  by the same label rule, and the first field from the left whose key is a
  label ends the label. A field key may also end at a bare `|`
  ([#943](https://github.com/redact-secret/redact-secret/issues/943)): when
  the text of a field before a `|` is a reviewed email label by the same rule
  (`email|local@domain`, `|email|local@domain|`, `id=7|email|local@domain`,
  `|customer_email|…`, `|이메일|…`), that `|` is a field boundary and the
  candidate starts after it. A `|` after any other text (`|emailx|`,
  `|user|a|`, `user|user.email=`) stays local-part syntax. The first label
  field from the left wins, whichever delimiter ends it. A local part that
  starts with `|` after whitespace (`|email |local@domain|`) is not trimmed:
  the finding includes that `|`. A combining mark or governed invisible
  scalar is not accepted as either boundary, and a Unicode alphabetic or
  numeric scalar is not accepted on the domain side; the detector rejects the
  whole occurrence rather than matching a suffix or prefix. A URL
  authority/userinfo occurrence is excluded as a semantic collision.
- Enclosing-token lookbehind is bounded to 257 bytes: one maximum-size
  255-byte source-route domain plus its leading `@` and trailing `:`. Whitespace,
  comma, semicolon, and angle delimiters isolate unrelated earlier tokens.

The v1 subset does **not** support quoted-string local parts, domain literals
(`IPv4`, `IPv6`, or other generalized address literals), comments, folding
white space, obsolete local/domain forms, source routes, display-name/mailbox
syntax, a trailing root dot, other single-label domains, Unicode domains,
combining marks, or Unicode normalization/case folding. A canonically
equivalent but non-NFC spelling is
not rewritten; unsupported scalars split or reject the candidate. This is a
precision-oriented subset, not a claim to implement the complete RFC grammar.

Normative identity sources are:

- RFC 5322 sections 3.2.3 and 3.4.1 (`standard`, lexical, revision RFC 5322);
- RFC 6531 section 3.3 (`standard`, lexical/SMTPUTF8, revision RFC 6531); and
- RFC 5321 sections 4.1.2 and 4.5.3.1 (`standard`, domain and length bounds,
  revision RFC 5321).

## Sensitivity and negative evidence

Structure establishes email identity only. A public finding is emitted only
when the shared context matcher associates a reviewed high-signal email
context (`email`, `e-mail`, `이메일`, or `고객 이메일`, and, since
`pii-context/v2` ([#927](https://github.com/redact-secret/redact-secret/issues/927)),
`email address`, `e-mail address`, or `이메일 주소`) with the candidate.
Ambiguous `contact` / `연락처` vocabulary does not establish sensitivity.

After positive context, either of these named negative-evidence grammars makes
the occurrence non-sensitive:

1. the **whole parsed domain** is `example.com`, `example.net`, or
   `example.org`, or a subdomain of one of those RFC 2606 documentation
   domains; or
2. the whole parsed domain is, or lies below, the RFC 6761 special-use names
   `example`, `invalid`, `localhost`, or `test`.

RFC 2606 sections 2–3 and RFC 6761 sections 6.2–6.5 are the typed
`standard` sources for those reserved/documentation controls. Substrings and
resemblance do not suppress: `notexample.com`, `example.com.invalidated`, and
an `example` word outside the parsed domain are not whole-domain matches. The
family also names only `en-example-label` and `ko-example-label` from
`pii-context/v2` as occurrence-level exclusions.

## Safe fixture plan

- **Identity-only controls:** reserved/documentation candidates prove lexical
  identity without producing a public finding, including when positive context
  is present. Expected metadata never copies the candidate.
- **Sensitive public-finding fixtures:** fixed candidates are produced from the
  recorded seed `redact-secret-email-v1-fixture-876` and have no real-world
  provenance. They do not use a reserved domain, so high-signal context can
  exercise the public finding path. They are test data, not assertions that a
  mailbox or domain exists.
- **Negative and interaction fixtures:** malformed atoms and labels, byte and
  surrounding boundaries, placeholders, prose, URL/userinfo and credential
  collisions, context-negative cases, overlap, Unicode UTF-8/UTF-16 offsets,
  exact/global selector closure, and every incremental partition.

No fixture, expectation, snapshot, diagnostic, or evidence record contains a
real person's data or exposes matched plaintext.

## Trade-offs

False positives are limited by whole-candidate parsing, required high-signal
context, and named negative evidence. A syntactically valid generated address
under an email-labelled field can still be a non-sensitive identifier.

The logfmt label split (`email=local@domain`) removes the false negative of
a labelled `key=value` record. Its cost is a real local part that literally
begins with a reviewed email label and `=`: it is read as that label plus a
shorter address, which is still redacted, so the range loses only the key.
The pipe-field splits (#940, #943) have the same cost for a local part that
contains `|label=`, `label|`, or `|label|`: the address is still redacted and
the range loses only the label. They are security-first: a label joined by a
bare `|` would otherwise leave the whole labelled address in plain text.

False negatives include every unsupported RFC form above, single-label/local
delivery domains, combining-mark SMTPUTF8 spellings, an address without
reviewed high-signal context, and an otherwise sensitive occurrence under a
reserved/documentation namespace. The detector performs no deliverability,
ownership, DNS, or mailbox validation.


## Evidence handoff boundary

The [family handoff](https://github.com/redact-secret/redact-secret/issues/1294#issuecomment-6082141341) reviews the
[immutable pii-evidence candidate](https://github.com/redact-secret/pii-evidence/blob/841bad92c3af75199088fda55b12a36b6f197808/docs/research/snapshot-v2-handoff.json)
`public-pii-phi/2026-10-08/ee61c7afc32d`. At the #1293 review this candidate
was unregistered and unpublished; that historical review did not adopt it as
an active qualification snapshot.
Its project-maintained research dispositions are not independent validation.

Issue #1296 retains the frozen grammar and context rules. Reserved-domain
positives remain non-sensitive, and CSV headers, escaped JSON labels and
medical prose do not establish a new context or decoding contract. The
source-backed raw carrier shapes are transferred into the product corpus
with existing deterministic seeded material and explicit product expectations,
not copied canonical truth. Approved-label positives have benign twins.
No current-contract recall defect is established by this handoff.

## Active-v2 disposition

Epic [#1303](https://github.com/redact-secret/redact-secret/issues/1303) revisits
the released active snapshot `public-pii-phi/2026-10-08/ee61c7afc32d` at
[pii-evidence source](https://github.com/redact-secret/pii-evidence/blob/e22bbc16cb9009de1a6a91e97e7322ebbc32bcf0/docs/research/snapshot-v2-handoff.json).
The current comparison uses `pii-v1` revision 3, artifact schema 1.5, mapping
revision 3 and population version 3. Context and identity are retained by
that mapping; the earlier mapping-loss rationale is historical. Canonical
reported outcomes remain evidence-owned and are not rewritten by the product
disposition. The [active-v2 case ledger](https://github.com/redact-secret/redact-secret/issues/1305#issuecomment-6089713572)
records each applicability ruling and its source lineage.

Issue #1306 retains the current contract. Whole reserved/documentation domains
remain non-sensitive, including under high-signal or medical labels. Quoted
local parts, candidates immediately enclosed in `<...>` or adjacent to
comments, and source-route forms remain unsupported. CSV headers and escaped
nested labels do not acquire context or decoding authority. Authored sensitivity does not override these product exclusions.
A canonical public-output type miss can therefore coexist with established
internal identity and intentional suppression. No actionable current-contract
defect is established; the seeded carrier, approved-label and benign pairs
added for #1295 remain product regression controls, not evidence replacements.
