# Reporting detection issues and other feedback

[Documentation home](../README.md) · [Troubleshooting](../troubleshooting.md)

Choose the form that best matches your feedback. English or Korean is welcome.
제보는 영어와 한국어 모두 가능합니다. If you are unsure of a detector family,
leave it blank. For a suspected security vulnerability, use the private process
in [SECURITY.md](../../SECURITY.md) — never a public issue.

| What you noticed | Form |
| --- | --- |
| A harmless value was flagged or redacted | [False positive report](https://github.com/redact-secret/redact-secret/issues/new?template=false-positive.yml) |
| A supported credential was missed or given the wrong action | [Missed detection report](https://github.com/redact-secret/redact-secret/issues/new?template=missed-detection.yml) |
| A provider credential or PII entity should be supported | [Request a detector](https://github.com/redact-secret/redact-secret/issues/new?template=request-detector.yml) |
| Installation, adapter behavior, or a guide was confusing | [Integration or docs feedback](https://github.com/redact-secret/redact-secret/issues/new?template=integration-docs.yml) |

The reproduction steps below apply to false positives and missed detections.
For a detector request, a public format link and a short use case are enough.
For integration or documentation feedback, a brief description is enough to start;
the maintainer can ask for versions or a safe reproduction afterward.

## Never submit a real credential

Do not paste a live, revoked-but-real, or real-derived credential or real
personal data into any public form, attached file, or comment — not even a
truncated, masked, or partial fragment of a credential. "Real-derived" includes taking a real value and editing a
few characters: the grammar and provider fingerprint usually survive that
edit. Instead, build an **independently authored synthetic equivalent**:

1. Look up the provider's public format documentation, or read the detector's
   grammar in [detection and limits](../reference/detection.md), for the
   prefix, length, and character set the real value had.
2. Generate a *new* random value with that same shape — do not transform the
   real one. For example, a value shaped like `sk_live_<24 base62 chars>`
   becomes a freshly generated `sk_live_` followed by 24 characters you pull
   from a random generator, not the original 24 characters with a few swapped.
3. Confirm the synthetic value still reproduces the behavior you are
   reporting. If it stops matching (or starts matching, for a missed
   detection report you're trying to narrow down), your synthetic value
   probably dropped a structural detail — restore the shape, not the
   original characters.
4. If the finding depends on surrounding context (a variable name, a header,
   nearby prose) rather than the value's grammar alone, describe or
   reconstruct that context with placeholder text too.

Raw logs, screenshots, prompt exports, and tool payloads are **discouraged**
for the same reason a full log line usually carries more than the one value
you meant to share. Only attach one if you have personally read every line
and manually sanitized anything that isn't already a synthetic value covered
by step 2 above. When in doubt, describe the shape in prose instead of
attaching the artifact.

## Local reproduction template

Run the same core the published packages use, locally, against a file you
authored yourself under step 2 above (never a checked-in fixture and never a
copy of production data). It never prints the input or a matched value —
only classifications and ranges, matching the guarantee in
[SECURITY.md](../../SECURITY.md#security-model).

With the CLI (works for any language ecosystem; see
[installation](../getting-started.md)):

```bash
cargo install redact-secret-cli --version <your-installed-version> --locked
redact-secret --json local-repro.txt > local-repro-metadata.json
cat local-repro-metadata.json
```

Without a Rust toolchain, the same metadata is available from the JavaScript
package:

```js
import { artifact, initialize, scan, VERSION } from "@redact-secret/core";
import { readFileSync } from "node:fs";

await initialize();
const input = readFileSync("local-repro.txt", "utf8");
const { findings } = scan(input);

console.log(JSON.stringify({
  packageVersion: VERSION,
  artifact: artifact(),
  nodeVersion: process.version,
  findingCount: findings.length,
  findings: findings.map(({ type, detector, confidence, action, start, end }) =>
    ({ type, detector, confidence, action, start, end })),
}, null, 2));
```

Paste the resulting JSON into the "Safe reproduction shape" field. It carries
only detector ids, confidence, action, and offsets — no text from your file.

## Required fields

| Field | Why it's required |
| --- | --- |
| Package version | Behavior is versioned; a fix or its absence is specific to a release. |
| Runtime | Rust, Node, browser WebAssembly, Python, and the CLI can differ in offset units, artifact selection, or supported detectors. |
| Detector family (if known) | Narrows triage; leave blank if you don't know which detector is involved. |
| Expected action | States the disagreement precisely — `allow` expected but got a finding, or a finding expected but got `allow`, etc. |
| Safe reproduction shape | Without it, a report cannot be reproduced or triaged at all. |

## What happens after you file

Filing a false positive or missed detection report does **not** by itself
change any conformance fixture or expected result, and does not by itself open
a confirmed product defect. A detector request also does not imply that a
family will be implemented or qualified.
Benchmark-originated and reporter-originated findings share one governed
lifecycle, owned by
[`redact-secret-benchmarks`](https://github.com/redact-secret/redact-secret-benchmarks)
and described in
[`decision-govern-benchmark-regression-promotion`](../decisions/2026-09-18-govern-benchmark-regression-promotion.md):

```
observed → reviewed → promoted → fixed → verified
```

(`rejected` and `policy-decision` are the reviewed alternate endings.)

A maintainer triages your report and, if it holds up, records it as
`observed` in that repository's known-gap ledger. Only after independent
review confirms the expected behavior (`reviewed`) does it get linked to a
focused product issue and a canonical fixture here (`promoted`). Your issue
stays open for tracking in the meantime; it is not itself the record that
changes behavior.

## No automatic telemetry

Redact Secret's core performs no runtime network access and collects no
telemetry (see [SECURITY.md](../../SECURITY.md#security-model)). Nothing in
your installation reports usage, findings, or input automatically. Filing a
report here is an entirely manual, opt-in action you take by copying the
metadata above into a public issue yourself.
