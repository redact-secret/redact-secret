---
decision_id: decision-read-the-curl-user-password-argument-as-a-contextual-secret
status: accepted
scope: workspace
title: Read the password of a curl -u / --user argument as a contextual secret
decided_at: 2026-10-07
spec: contextual-detection
---

# Read the password of a curl -u / --user argument as a contextual secret

## Context

Issue [#1247](https://github.com/redact-secret/redact-secret/issues/1247) asks
whether the product reads the password component of `curl -u user:pass`
(`--user`, `--proxy-user`, with or without `--digest`) or keeps it a stated false
negative. The question came from the Group C/D/E closeout (#1226, #1228, #1229,
#1230): Zendesk (`email/token:<token>`), JFrog (API key or reference token as the
Basic password) and Atlas (`public:private` with `--digest`) all document this
carrier, and no per-family fix can cover it.

Product observation at `f6f481b1` (published `@redact-secret/core` 0.1.0-beta.14,
synthetic values built at run time): URL userinfo (`https://u:p@host`) is read as
`connection_string_password`; `curl -u`, `--user` and `-u` are silent, except that a
Zendesk string is already read by its literal `/token:` ([#1230](https://github.com/redact-secret/redact-secret/issues/1230)).

The evidence-separation rules require the benign corpus to exist before any
implementation and to be authored by someone other than the implementer
(`redact-secret-benchmarks` evaluation method 06, "author the benign rationale
independently of every scanner result"; CONTRIBUTING there, "author the expected
result from how the value was constructed, never from any scanner's output"). That
corpus is `corpora/proposed/curl-user-carrier-1247/` in `redact-secret-benchmarks`
(128 cases: 48 `must-redact` with a password-only span, 70 `must-not-flag`, 10
stated false negatives; built at run time, no secret-shaped literal stored). It is
not registered in any category yet, so it does not enter normal evaluation; the
implementer receives it and does not edit it.

Baseline of the current scanner on that corpus, taken after the cases were written
and not used to shape them: 2 of 48 positives exact (both Zendesk `/token:`), 1 with
another span (the URL userinfo password of a flag-plus-URL case), 45 silent; 0
findings on the 70 benign cases; 1 of the 10 stated false negatives is already
covered by another rule (a variable assignment).

## Decision

**Adopt.** The password component of a curl credential argument is read.

1. **What is read.** The argument of `-u`, `--user`, `--proxy-user` and `-U` of a
   `curl` command: the user is the text before the first `:` and the password is
   everything after it, as curl itself splits it. `--digest`, `--basic`,
   `--anyauth`, `--ntlm`, `--negotiate` and `--netrc*` change the wire scheme, not
   the argument, and do not change the reading.
2. **Finding.** `contextual_secret`, exactly the password bytes as written (no shell
   unescaping, no percent decoding), **high** confidence, default action `redact`
   (security-first). The user, the email and a literal `/token` stay unclaimed. No
   new finding type, detector id or public interface.
3. **Exclusions.** Empty password, and every value the connection-string reader
   and the contextual readers already exclude as a non-secret: whole-value
   environment, template and command-substitution references, angle placeholders,
   masks, placeholder vocabulary and fill-in prose, and the connection-string
   literals (`password`, `secret`, `example`, `changeme`, `changeit`,
   `mysecretpassword` and the rest of that list). No new vocabulary. A weak
   real-shaped value (`admin`, `pass`, `test1234`) is **not** excluded.
4. **Zendesk, JFrog, Atlas.** They are the same reading and gain no type: the
   Zendesk token is the password after `/token:`, the JFrog key or reference token
   is the password, the Atlas private key is the password and its public key stays
   unclaimed. The existing `/token:` literal reading and this reading produce one
   finding on one span.

### Implementer contract

A. **Command word.** A `curl` word: optionally path-qualified (`/usr/bin/curl`) and
   optionally `.exe`, preceded by line start, whitespace or one of `` ( ` " ' ; & | = { ``,
   followed by whitespace. `mycurl`, `libcurl`, `curl-config` and `curlimages/curl`
   are not curl words. A wrapper word before it (`sudo`, `time`, `LC_ALL=C`,
   `bash -c "`) changes nothing.

B. **Command window.** From the end of the curl word to the first unquoted,
   unescaped `;`, `&`, `|`, or a newline not preceded by a backslash continuation
   (`\`+LF or `\`+CRLF continue), or end of input, or 8,192 bytes, whichever is first.
   A `-u` outside a window belongs to another command (`docker run -u 1000:1000`,
   `echo -u a:b | curl url`) and is not read. Options after the URL are read.

C. **Option spellings** (exact, case-sensitive): `-u`, `-U`, `--user`,
   `--proxy-user`; the argument is the next word (`-u ARG`), attached (`-uARG`),
   or after `=` for the long forms (`--user=ARG`). A short option may close a
   cluster of argument-less short options from `s S f L k v g i I O J R N Z #`
   (`-sSfLku ARG`). Long-option abbreviations (`--us`) are not read.

D. **Word grammar.** An argument is one shell word: unquoted bytes up to
   unescaped whitespace (a backslash escapes the next byte and is kept in the span),
   `'...'` literal, `"..."` with `\"`, `\\`, `\$` and `` \` `` escapes kept as
   written. The span excludes the enclosing quote characters; inside quotes a space
   is a password byte; a `"` inside `'...'` and a `'` inside `"..."` are password
   bytes. `user:"pw"` (quote opened right after the colon) is read inside the quotes.
   No colon means no password. An unterminated quote is silent (stated false
   negative). The password may contain `:`, `@`, `%`, `/`; none is parsed.

E. **Bounds.** Password at most 4,096 bytes (longer is silent), the shared
   connection-string bound. Unquoted `)` is a password byte; `$(curl -u u:pw)` may
   include the `)` in the span, an accepted over-redaction.

F. **Overlap.** A provider type that claims the same bytes wins (existing
   priority); the same span from the `/token:` literal is not reported twice. URL
   userinfo in the same command keeps its own `connection_string_password` span.

G. **Chunk and stream rule.** The result for any chunking is identical to the
   whole-input result. A finding is emitted only when the argument end is known
   (unquoted whitespace, closing quote, or finalization); nothing is emitted and
   retracted. The incremental session retains the current command line from the
   curl word start, at most 8,192 bytes plus a 256-byte path prefix, across chunk
   boundaries. Required split tests: every offset from the curl word start to the
   span end plus one byte, one-byte chunks, and a split inside a multibyte
   character before the span. An unterminated quote at end of stream is silent.

H. **Bindings.** One reader in the Rust core; Node, WASM, Python and CLI whole and
   streamed give equal findings, offsets in each surface's existing unit (UTF-16
   for Node and WASM, as documented for each other binding). The equivalence
   harness takes the benchmarks corpus cases as run-time generated fixtures; no
   literal secret value is committed in this repository.

I. **Acceptance for the implementer.** All 48 `must-redact` cases exact, none of the
   70 `must-not-flag` cases flagged, the 10 stated false negatives silent for this
   reader (a case another rule covers may report through that rule), then
   registration of the corpus in `redact-secret-benchmarks` and measurement there;
   support status is not inferred from this repository.

## What stays a stated false negative

The curl config file (`-K`, `~/.curlrc` `user = "u:p"`); a command held as an
argument array (Python `subprocess`, JSON); other tools with the same shape (HTTPie
`-a`, `wget --password`, `mysql -p`); a credential assigned to a variable and passed
by reference; an unterminated quote; a password over 4,096 bytes; a quote escaped
inside a quoted command string needing a second shell pass; a long-option
abbreviation. The family evidence records keep these as stated.

## Alternatives considered

- **Keep the false negative.** Rejected. The leak is a plaintext password in the
  output for a very common command, the grammar is fixed by curl, and the false
  positive side is bounded by exclusions the product already maintains.
- **Read the whole `user:pass` argument.** Rejected. It redacts the user name and,
  for Zendesk and Atlas, a public identifier, and matches neither URL userinfo nor
  the Basic-envelope precedent of leaving the non-secret half readable.
- **A new finding type (`curl_user_password`).** Rejected. It changes every
  binding's type list and the public contract for a carrier whose value has no
  grammar of its own; `contextual_secret` at high confidence already redacts.
- **Only the `--digest` form or only the three named providers.** Rejected. The
  reading is the carrier's, not the provider's; a provider-keyed reading leaves
  every other `curl -u` password readable.
- **Exclude `admin`, `pass` and similar docs literals.** Rejected for now. They are
  real passwords of real systems; the cost is one redacted word in a tutorial.

## Consequences

Tradeoff. False negatives removed: the password of every curl credential argument
inside the grammar above, including the three providers' carriers. False positives
added: a documentation password that is not in the exclusion lists (`-u user:pass`,
`-u admin:admin`) is redacted; a path-qualified or wrapped `curl` word that is not
the real command; over-redaction of a `)` in `$(curl -u u:pw)`. Residual false
negatives are listed above. Confidence is high because the carrier defines the slot,
not because the value looks random, so a short low-entropy password is redacted
too.

This ADR is the decision only. No reader is implemented here: stage 2 implements it
from the contract above against the independent corpus, and stage 3 registers and
measures the corpus in `redact-secret-benchmarks`. `docs/specs/contextual-detection.md`
gains the carrier row.
