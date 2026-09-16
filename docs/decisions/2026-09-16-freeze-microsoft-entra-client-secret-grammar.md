---
decision_id: decision-freeze-microsoft-entra-client-secret-grammar
status: accepted
scope: workspace
title: Freeze the Microsoft Entra application client-secret grammar as an unprefixed digit-Q-tilde marker
decided_at: 2026-09-16
---

# Freeze the Microsoft Entra application client-secret grammar as an unprefixed digit-Q-tilde marker

## Decision

Add a dedicated `microsoft-entra-client-secret` detector
(`crates/secret-scan-core/src/detectors/microsoft_entra.rs`) for issue #297,
matching a Microsoft Entra (Azure AD) application client-secret *Value* by
the shape:

```
<3 bytes from [A-Za-z0-9_.~]><1 ASCII digit>Q~<31-34 bytes from [A-Za-z0-9_.~-]>
```

(37-40 bytes total), bounded on both sides by a byte outside
`[A-Za-z0-9_.~-]` or the edge of input. Confidence is `High` and specificity
is `Provider`; the default policy always redacts a match
(`microsoft_entra_client_secret` in `ALWAYS_REDACT_TYPES`,
`crates/secret-scan-core/src/policy.rs`), the same class every other
dedicated provider detector in this registry gets.

No surrounding context (`client_secret=`, `clientSecret:`, ...) is required
to classify a match: the `<digit>Q~` marker is treated as specific enough on
its own, matching how every other `Specificity::Provider` detector in this
module works.

Known unsupported variant: a client secret in the older, unmarked format
that predates this shape carries no `Q~` marker and is indistinguishable
from ordinary opaque text without one. It is not detected by this rule, with
or without surrounding context; that gap is a scope boundary of this
detector, not something a future contextual heuristic in `generic_token.rs`
is expected to close, since `client_secret=<opaque-value>` already produces
a lower-specificity `contextual_secret` finding today via the existing
`client_secret` high-signal name.

## Rationale

Microsoft's own credential documentation
(`https://learn.microsoft.com/entra/identity-platform/how-to-add-credentials`)
describes how to create a client secret but publishes no grammar for the
resulting *Value* — only that it must be recorded immediately because it is
never shown again. Issue #297's acceptance criteria require freezing "the
supported grammar, confidence, action, and known unsupported variants...
before implementation" and note that "ambiguous unprefixed values require
reliable context." Since this grammar carries no vendor-documented literal
prefix, that freeze has to be an explicit judgment call rather than a
transcription of a spec, which is why it gets a decision record — unlike the
existing literal-prefixed providers in `additional_providers.rs` (Stripe,
Slack, npm, ...), none of which needed one.

The shape above is not invented here. It is the community-reverse-engineered
grammar independently converged on by two widely-deployed scanners, consulted
only as external behavioral references per `AGENTS.md` (no code copied from
either):

- gitleaks 8.30.1's `azure-ad-client-secret` rule (boundary class loosely
  quote/backtick/whitespace/`=:(),><`, elided here for Markdown safety):
  `([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})`
- trufflehog's `azure_entra/serviceprincipal/v2` (`spv2.go`) `SecretPat`:
  `(?:[^a-zA-Z0-9_~.-]|\A)([a-zA-Z0-9_~.-]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:[^a-zA-Z0-9_~.-]|\z)`

Both agree on the load-bearing part of the grammar: a single digit
immediately followed by the literal `Q~`, then 31-34 bytes from a charset
that includes `-`. They differ only on whether the 3 bytes *before* the
digit may also include `-`; this detector follows gitleaks's narrower
`[A-Za-z0-9_.~]` there (no `-`), favoring precision over recall in an
already-undocumented grammar, consistent with this registry's existing
precedent of picking the narrower documented shape when sources disagree
(e.g. `additional_providers.rs`'s Stripe entry excluding `pk_live_`/`pk_test_`).

Because two independent scanners reverse-engineered the identical
`<digit>Q~` anchor from real-world samples without needing surrounding
context to disambiguate it, this detector treats that anchor as itself
"reliable context" in the sense the acceptance criteria mean it — it is
specific enough that a bare match is actionable, the same trust every other
provider-prefixed grammar in this registry gets. This is different from a
value with no distinguishing marker at all (a plain base64 blob), which
would need a surrounding `client_secret=`-style assignment to be actionable
and is exactly the gap `generic_token.rs`'s existing contextual heuristic
already covers at `Specificity::Contextual`.

## Consequences

- `crates/secret-scan-core/src/detectors/mod.rs` registers the new detector
  after `sendgrid-token` and before `jwt`; overlap resolution's registration
  order tie-break is unaffected in practice since this grammar cannot
  overlap another built-in provider's shape.
- `docs/coverage/detector-inventory.json` gains a `microsoft_entra_client_secret`
  row (`always-redact`); `docs/coverage/coverage-declarations.json`,
  `inventory-report.json`, and `coverage-report.md` are regenerated from it
  and `conformance/fixtures/synchronous-corpus.json`, not hand-edited.
- New corpus fixtures: `microsoft-entra-client-secret-positive-bare`,
  `-overlap-generic-context`, `-adversarial-long-padding`,
  `-boundary-below-min`, `-boundary-above-max`, `-boundary-invalid-alphabet`,
  `-boundary-missing-digit`, `-boundary-short-prefix`,
  `-negative-ordinary-reference`, `-negative-placeholder`,
  `-negative-lookalike`.
- A value at the old, unmarked client-secret format, or any value whose
  digit-Q-tilde marker sits fewer than 3 bytes from the start of input (so
  the full prefix cannot be evaluated), goes undetected by this dedicated
  detector; `client_secret=`/`clientSecret:`-style assignments still get a
  lower-confidence, lower-specificity contextual finding through the
  existing generic-token path regardless of which format the value is in.
- A benign string that happens to contain a digit immediately followed by
  `Q~` and 31-34 bytes from the suffix alphabet would false-positive; this
  is accepted as the same class of risk every other provider-prefixed
  detector in this registry already carries, and is bounded by requiring an
  exact digit, the exact two-byte literal, and a suffix length inside a
  4-byte-wide window rather than an open-ended minimum.
