# Evidence: #1226, Batch 2 Atlas password, API private key and service-account secret

**Result:** the product contract for the three G6 rows is adopted as a
conditional policy, with the Atlas database-user password stance the benchmarks
readiness inventory was waiting on. The current policy is preserved where it is
in contract: the `mongodb` and `mongodb+srv` URI userinfo password through the
connection-string detector, and a documented password field through the
contextual vocabulary. A user-chosen password that is short, low entropy or
punctuation-bearing is a stated blind spot; no provider grammar is invented and
no claim is made that all passwords are protected. The API private key is the
client's Digest input, not a PEM and not in the Digest header; the service-account
secret is opaque and `mdb_sa_sk_` is only a truncated example. No row is claimed
covered, passing or ready, no benchmark result is stated, and no code, detector,
registry entry or type changes.

Issue [#1226](https://github.com/redact-secret/redact-secret/issues/1226)
(measurement child benchmarks
[#745](https://github.com/redact-secret/redact-secret-benchmarks/issues/745)),
Batch 2 of the credential-evidence adoption inventory
([#231](https://github.com/redact-secret/credential-evidence/issues/231), handoff
[#235](https://github.com/redact-secret/credential-evidence/issues/235)). The
class rules and the legend are in the [#1223 record](../1223/README.md); the
representation decision is
[`decision-keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract`](../../../decisions/2026-10-05-keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract.md).

## Sources

| Role | Source |
| --- | --- |
| Provider facts (pending inputs) | The three proposed contracts of credential-evidence#235 and the [Batch 2 handoff](https://github.com/redact-secret/credential-evidence/blob/005a7331cf90403bd4ce4abcb93bd8b085d315a9/docs/handoffs/batch-2-bounded-carriers.md) (credential-evidence#248, project-authored, not independent). It records the password as a write-only, caller-chosen request property with no generated grammar and an unresolved percent-encoding question; the private key as a client-configured Digest input whose wire header holds a hash, returned unredacted once at creation; and the service-account secret as carried in an HTTP Basic header with `mdb_sa_sk_` plus an ellipsis only a truncated example and `mdb_sa_id_` a public id. It also holds three public-sibling records (the public key, the credential object id, the client id). |
| Independent baseline | None. benchmarks#739 readiness (comment 6001345412): `mongodb-atlas:database-user-password` blocked (`representation-policy-undecided`), `mongodb-atlas:programmatic-api-private-key` carrier-unresolved, `mongodb-atlas:service-account-secret` blocked (awaiting evidence review). |
| Product policy (this record) | The connection-string grammar (`connection_string_password`, valid percent escapes not decoded), the contextual vocabulary and its confidence gate (`decision-warn-unconditionally-on-high-signal-contextual-names`), the Basic envelope ([#1213](../1213/README.md)) and the representation decision above. |

## Adopted contracts

| Question | `mongodb-atlas:database-user-password` | `mongodb-atlas:programmatic-api-private-key` | `mongodb-atlas:service-account-secret` |
| --- | --- | --- | --- |
| Layout kinds in contract | (1) The password in `mongodb://` and `mongodb+srv://` URI userinfo, through the connection-string detector. (2) A documented password field (assignment, form body, JSON or YAML member) through the contextual vocabulary, for a reviewed layout. | None asserted. The Digest `Authorization` header carries a hash, not the key, and is out of contract. Only a reviewed plaintext slot (for example a create-response member or a client configuration field) can be in contract, and the existing field grammar then applies. | An `Authorization: Basic` envelope (the token request, as the evidence records it), and a `client_secret`-style field only where a reviewed layout names one. |
| Value admission and span | URI: the password substring after the userinfo `:`, undecoded, exactly the substring; host, path and query stay outside. Field: the shared contextual grammar, 8-byte floor, exactly the value, ending at the form delimiter. | The existing field grammar for the slot. No width, alphabet or prefix is claimed. | Basic: the whole encoded envelope, never decoded, 12 bytes or more. Field: the shared grammar, exactly the value. |
| Finding type | URI: `connection_string_password`. Field: `contextual_secret`. No provider type. | `contextual_secret` (the `private_key` name family is already high-signal); not a PEM block and not typed as one. | Basic: `authorization_credential`. Field: `contextual_secret`. No provider type and no `mdb_sa_sk_` detector. |
| Default action | URI: redact (always-redact) at any confidence. Field: redact at high confidence (a random value of 16 bytes or more), warn at medium (for example a 14-byte or punctuation-bearing password), nothing under 8 bytes. | As the field. | Basic: redact. Field: as the field. |
| Controls and exclusions | Username, database name, URI host, path and query, placeholders, references, masks. | The 8-character public key, the credential object id, redacted later responses and masks, the Digest `response` hash, `username`, `realm`, `nonce`, `uri`, `qop`, `nc` and `cnonce`. | The public `mdb_sa_id_` client id, the secret's object id, the masked or truncated display (`mdb_sa_sk_` plus an ellipsis), placeholders, references, masks. |

### Stated blind spots and the explicit dispositions

* **User-chosen passwords are not a grammar.** The product claims the carrier,
  not the password. A password under the 8-byte contextual floor is not read in a
  field; a password under 16 bytes or of low entropy in a field is `medium` and
  `warn` (high confidence needs 16 bytes and the entropy threshold), which the
  accepted default leaves in the text and a user action policy may escalate; a
  password in a carrier the core does not read (a command-line flag, an SDK
  argument, an interactive prompt, a configuration shape the evidence has not
  named) is not read; and a password whose raw punctuation the carrier grammar
  treats as a delimiter (`&` in a form body, an unquoted space, a closing quote)
  is cut there and the residue stays in the output. The product does not claim
  all passwords are protected and invents no provider grammar.
* **Percent encoding.** In a URI userinfo, or a form or assignment value, a
  password containing `%XX` is kept as written inside the span and not decoded.
  Whether Atlas itself requires the encoding in a connection string is the
  evidence's question and is not decided here. The general rule for a carrier
  that ends a value at `%` is the decision above.
* **The API private key.** A curl invocation that passes `<public>:<private>`
  with `--user ... --digest` is a layout the product does not read today (no
  finding was observed). Making it in contract is a new carrier decision with
  its own benign corpus, not a repair, and the evidence has not named it.
* **No bare grammar.** A bare `mdb_sa_sk_...` value in prose, outside a credential
  slot, is not read. The evidence records no width or alphabet.

## Product observations

Product observations at core `3b1a5aa9` (CLI `0.1.0-beta.13` line, debug build of
this commit, check mode, UTF-8 byte ranges), small synthetic inputs, values
invented and not shown. Not benchmark results and not coverage claims.

| Input (synthetic) | Observed finding |
| --- | --- |
| a `mongodb+srv` URI with a user name, a 14-byte password in the userinfo, a host, a database path and a `retryWrites` query | `connection_string_password`, high, redact, over exactly the 14-byte password (21-35); host, path and query silent |
| a `mongodb` URI with a one-letter user name, a 3-byte password in the userinfo, a host and a database path | `connection_string_password`, medium, redact (12-15) |
| a `mongodb` URI with a one-letter user name, a 13-byte password in the userinfo that contains valid percent escapes, a host and a database path | `connection_string_password`, high, redact, over the 13-byte password with its escapes undecoded (12-25) |
| JSON `{"password":"<20 random>"}`, YAML `password: <20 random>` | `contextual_secret`, high, redact, over the value (13-33; 10-30) |
| JSON `{"password":"<14 mixed>"}` | `contextual_secret`, medium, warn (30-44 in a two-line input) |
| JSON `{"password":"<14, punctuation>"}` | `contextual_secret`, medium, warn (13-27) |
| JSON `{"password":"<6 bytes>"}` | no finding |
| form `username=app&password=<17, with two %XX escapes>&roles=x` | `contextual_secret`, high, redact, over the whole 17-byte value to the `&`, escapes included (22-39) |
| JSON `{"privateKey":"<36, UUID-shaped>","publicKey":"<8>"}` (the shape is invented, not claimed as Atlas's) | `contextual_secret`, high, redact, over the `privateKey` value only (85-121 in a two-line input); `publicKey` silent |
| `"privateKey":"********-****-****-************"` | no finding |
| `Authorization: Digest username=".", realm="MMS Public API", nonce=".", uri=".", response="<32 hex>", qop=auth, nc=00000001, cnonce="."` | no finding |
| `curl --user "<8>:<36>" --digest <url>` | no finding |
| `Authorization: Basic <48 bytes>` | `authorization_credential`, high, redact, whole envelope (37-85 after a request line) |
| `client_id=mdb_sa_id_<24 hex>` then `client_secret=mdb_sa_sk_<24>` | `contextual_secret`, high, redact, over the 34-byte secret only (59-93); the client id silent |
| JSON `{"clientSecret":"mdb_sa_sk_<24>"}` | `contextual_secret`, high, redact, over the value (17-51) |
| `client_secret=mdb_sa_sk_...`; JSON `maskedSecretValue` with `mdb_sa_sk_...<4>`; a bare `mdb_sa_sk_<24>` in prose | no finding |

## Per-row table

Legend as in the [#1223 record](../1223/README.md#per-row-table): layout kind URI
is the mongodb URI userinfo reading; P1 and P2 are the preconditions defined
there. The evidence handoff marks all three rows `ready`; for the private key
that mark rests on a Digest input with no wire carrier, so the product treats no
layout as named and the row starts at P2.

### G6: 3 families

| Family | Layout kind (evidence-named, unreviewed) | Product disposition kind | Benchmarks inventory | Evidence handoff | Precondition |
| --- | --- | --- | --- | --- | --- |
| `mongodb-atlas:database-user-password` | F + URI | existing generic paths: documented password field and mongodb URI userinfo; user-chosen passwords are a stated blind spot | blocked (representation-policy-undecided) | ready | P1 |
| `mongodb-atlas:programmatic-api-private-key` | C / X | plaintext slot conditional on a reviewed layout; the Digest header is out of contract | carrier-unresolved (carrier-source-missing) | ready | P2: the evidence contract names no plaintext slot (client-configured Digest input, no wire carrier); a reviewed create-response or config slot is needed before any layout is in contract |
| `mongodb-atlas:service-account-secret` | BA | existing generic path: Basic envelope; a form field only where a reviewed layout names it | blocked (awaiting-evidence-review) | ready | P1 |

## Handoff

The benchmarks side may treat as adopted: for the password row, the URI userinfo
expectation (exact undecoded password, `connection_string_password`, redact) and,
for a reviewed field layout, the field expectation including `warn` at medium,
with user-chosen short, low-entropy and punctuation-bearing passwords recorded as
blind spots and not scored as misses; for the service-account secret, once its
layout is reviewed, the whole-envelope Basic expectation and the public client
id, masked display and truncated example as controls; for the private key,
nothing until a reviewed plaintext slot exists, with the Digest header and the
public key as controls. What stays blocked: all three rows wait for a reviewed
evidence contract and an independent baseline, and the private key additionally
for a named plaintext slot. Percent-encoded password variants beyond the URI
reading are unassertable under the decision. Exact candidate source and digests
go to benchmarks only after a gap is demonstrated; none is. No pin, version or
release changes.

## Gates of the issue

| Gate | State |
| --- | --- |
| Freeze layout, admission, span, attribution, default action, exclusions per ready row | Met at class level (this record and the spec rows); per row conditional, no row is ready. |
| Link baseline case ids and identities; disposition every row | Open, no baseline. |
| Repair only demonstrated gaps | Open, none demonstrated. The password blind spots are accepted, recorded limits. |
| Deterministic conformance for changed logic | Open, no logic changed. |
| Shared parser fix once | Open, none needed so far. |
| Node/WASM, Python, Rust and CLI whole and stream behavior | Open. Only the CLI was observed, at one commit. |
| Candidate revision and digests to benchmarks; accept replay | Open, conditional on a demonstrated gap. |
| Record no-code conclusions | Open, conditional on a baseline. |

## Tradeoffs

* A `warn` for a moderate-length password under a documented field leaves the
  text unchanged by default. Raising it to `redact` would redact every 8 to 15-byte
  or low-entropy literal under `password`, including prose false positives that
  `decision-warn-unconditionally-on-high-signal-contextual-names` records. The
  accepted default stays; a caller that wants redaction sets its action policy.
* The URI reading redacts at any confidence, so a placeholder-like short
  password in a connection string is redacted: security-first and unchanged.
* Treating the private key and service-account secret by existing names and the
  Basic envelope means a Basic envelope also hides the public client id. A key
  in a layout the product does not read, such as the curl `--user` form, stays
  visible, and that is disclosed rather than fixed here.

## Tests

None added: documentation and policy only. The URI grammar, the contextual
vocabulary and the Basic envelope are pinned by their existing tests
(`connection_string` and `generic_token` unit tests,
`batch1_credential_slots_1209_1213.rs`). The observations above are pinned by
this record only.
