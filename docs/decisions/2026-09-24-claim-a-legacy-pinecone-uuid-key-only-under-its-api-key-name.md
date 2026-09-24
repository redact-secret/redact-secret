---
decision_id: decision-claim-a-legacy-pinecone-uuid-key-only-under-its-api-key-name
status: accepted
scope: workspace
title: Claim a legacy Pinecone UUID key only under a Pinecone API-key name, and redact it
decided_at: 2026-09-24
spec: detector-families
---

# Claim a legacy Pinecone UUID key only under a Pinecone API-key name, and redact it

## Decision

`pinecone-api-key` reports a legacy bare-UUID Pinecone key as
`pinecone_api_key` at high confidence when the UUID is the value assigned to a
Pinecone API-key name on the same line. There are two ways to qualify:

- **A Pinecone-qualified key name.** After `normalize_name`, the name is
  `pinecone_api_key`, `pinecone_apikey` or `pinecone_key`. This covers
  `PINECONE_API_KEY=`, `pinecone_api_key:`, `pinecone.api_key =` and
  `PINECONE_KEY=`.
- **A bare API-key name on a Pinecone line.** The name normalizes to `api_key`
  or `apikey` and the same line contains `pinecone`, case-insensitively. This
  covers `pinecone.init(api_key="...")`, `pinecone.init({ apiKey: ... })` and
  an `Api-Key:` header sent to a `pinecone.io` host.

Only spaces, tabs, quotes and at least one `=` or `:` may sit between the name
and the value. The UUID must be lowercase `8-4-4-4-12` hex that is not a
slice of a wider identifier. A UUID whose hex digits are all the same
character is a placeholder and is not reported.

Every other UUID stays unclaimed. That includes a bare UUID, a UUID in prose,
a UUID under a project, index, database or service-account id name
(`PINECONE_PROJECT_ID`, `project_id=`, `X-Project-Id:`, `indexId`), and a UUID
whose name is on a different line.

This answers the question
[#702](https://github.com/redact-secret/redact-secret/issues/702) asks for this
family: a provider-named assignment is redacted, not warned.

## Rationale

The benchmark measured the gap independently of scanner output
(redact-secret-benchmarks record `product-702`, corpus `beta8-212`, product
`main` 4f92665). The same legacy UUID was redacted at high confidence by
`generic-token` under `apiKey:` and `Api-Key:`. It got no finding under
`PINECONE_API_KEY=`, `pinecone_api_key` or `pinecone.init(api_key=...)`. The
defect was the inconsistency: the same credential, assigned to a name that
says it is that credential, got a different outcome depending on how the name
was spelled.

- **The name is the evidence.** A UUID carries no marker of its own, so the
  name that holds it decides. `generic-token` already accepts `api_key` and
  `apiKey` as high-signal names and redacts a UUID under them at high
  confidence. `PINECONE_API_KEY` names the same thing and adds the provider,
  so it is at least as strong. Reporting it at medium confidence would make
  the less specific spelling the more trusted one.
- **The keyword co-occurrence tier stays where it is.**
  `heroku-api-key-legacy`, `confluent-cloud-api-secret-legacy`,
  `datadog-application-key-legacy`, `mailchimp-api-key`, `mailgun-api-key` and
  `okta-api-token` report at medium confidence and warn. They fire when a
  provider keyword appears anywhere on the line, which is weaker evidence.
  This decision does not change them. The rest of #702's question, whether
  those keyword-gated families should also redact under a provider-named
  assignment, stays open.
- **An allow-list of names instead of a deny-list.** `heroku-api-key-legacy`
  drops identifier-shaped keys (issue #714) after a keyword match. This path
  admits only the listed credential names. The benchmark's twins keep the UUID
  byte for byte and rename only the key to a Pinecone project, index,
  database, service-account or UUID id name. All twelve stay clean, and the
  24 controls stay clean too.
- **No new detector id.** The legacy key is the same Pinecone API key in an
  older shape, so it keeps the `pinecone_api_key` type, which is always
  redacted. `generic-token` still reports its own candidate on the same span,
  and overlap resolution picks the provider-specific one at the same redact
  action.

## What this costs

- **False negatives.** A legacy key under any other name is still missed,
  for example `PC_KEY=`, a CLI flag with no `=` or `:`, or a name on the line
  above. A generic provider-named rule (every `<provider>_api_key`) would close
  more of #702 but would change behavior for every family at once, so it is
  not adopted here.
- **False positives.** A UUID that really is an identifier but is stored under
  `PINECONE_API_KEY` or `api_key` on a Pinecone line is now redacted. The
  benchmark's controls found no such case, and redacting a public UUID costs
  little.
- **The `common` profile.** `pinecone-api-key` is a provider-pack detector, so
  the `common` profile still reports nothing for the four name-gated
  positives that `generic-token` cannot parse. That profile's documented scope
  is unchanged.

## Consequences

- `crates/secret-scan-core/src/detectors/pinecone.rs`: the registry entry
  becomes `PineconeApiKeyDetector`, which runs the unchanged `pcsk_` shape and
  then `legacy_candidates`.
- `conformance/fixtures/synchronous-corpus.json` adds four
  `pinecone-api-key-positive-legacy-uuid-*` positives, one overlap fixture and
  four `pinecone-api-key-negative-legacy-uuid-*` twins.
- `conformance/benchmark-regressions.json` gets no `benchmark-gap-702` record
  yet. Record `product-702` is still `observed`, and the vendored pin manifest
  does not carry the `beta8-212` corpus hash it cites. The record follows the
  `benchmark-gap-749` precedent and waits for the corpus to reach
  redact-secret-benchmarks `main`.
