# Beta.4 candidate public-contract review

Reviewed on 2026-09-17 for release tracking issue
[#362](https://github.com/redact-secret/redact-secret/issues/362). The candidate
is `0.1.0-beta.4` (`0.1.0b4` on PyPI) on `rc/0.1.0-beta.4`, based on reviewed
`main` revision `0165af7acba873e8eb5a755a18dd5d0d4650aa49`. The exact frozen
candidate revision is recorded by the qualification inventory and release
manifest so that this document does not claim evidence for a later source
change.

## Public API and compatibility

The Rust crate-root exports, JavaScript exports and type declarations, Python
module declarations, and CLI argument surface have no public API diff from
`v0.1.0-beta.3`. Range units, callback contracts, initialization, incremental
session behavior, error codes, and package export maps remain unchanged.

Beta.4 expands observable detection and policy behavior. It adds provider
finding types for Microsoft Entra, Azure DevOps, Google, Notion, Atlassian,
Discord, Telegram, Twilio, Datadog, Sentry, Grafana, and New Relic credentials.
Unambiguous provider formats are always redacted. Context-dependent Twilio,
Datadog, and New Relic license-key findings retain confidence-gated behavior:
high confidence redacts and medium confidence warns. Provider candidates take
precedence over overlapping generic contextual candidates under the existing
specificity rules; disjoint findings and the overlap tie-break sequence are
unchanged.

The generic detector now excludes documented secret references, source-code
expressions, masked placeholders, and additional template or bind syntaxes.
It also prevents values from crossing line boundaries and recognizes nested
assignments without a separator inside an enclosing quote. These changes favor
precision and correct incremental agreement. Their intentional false-negative
boundaries and each new provider grammar's false-positive tradeoffs are
documented in the dated ADRs linked from `docs/decisions/DECISIONS.md` and in
the beta.4 changelog.

## Integration boundaries

The new tracing, MCP, and logging material is example code rather than a new
published integration package. It scans application-owned values before they
cross the relevant boundary and preserves prototype-named object keys as data.
The pino example formats message interpolation before scanning, with a pinned
real-pino destination-byte regression. Serializers or formatters that create
new strings afterward remain outside that guarantee. Python logging sanitizes
cached exception text and returns a fixed marker at the traversal depth limit.
Client-side scanning remains preventive UX; server-side scanning remains the
authoritative enforcement boundary.

## Changelog and blocker disposition

The former `Unreleased` content is condensed under the dated
`0.1.0-beta.4` heading. Detailed detector grammars remain in their ADRs and
reference documentation. Issue #361, the only newly discovered beta.4 release
blocker, is closed by merged PR #364 with the required pinned-pino tests. The
readiness fixes and review from PR #363 are also integrated in the reviewed
`main` baseline.

Publication still depends on local release checks and exact-revision Artifact
qualification, Package Release Rehearsal, and SAST. Those runs, the artifact
inventory, registry observations, installed-consumer evidence, tag target, and
final manifest belong to the versioned durable release record.
