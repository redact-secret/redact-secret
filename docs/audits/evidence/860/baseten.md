# #860 handoff: `baseten:api-key`

[#860 handoff index](README.md) ·
[Research table #10](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386571)

**Readiness: DATE-GATED.** No key of this shape exists before
**2026-10-01 15:00 GMT**. **Route:** new detector `baseten-api-key`, finding
type `baseten_api_key`. No arrival or support claim is made before real keys
exist.

## Role and blast radius

A Baseten API key (`BASETEN_API_KEY`, `Authorization: Bearer` or the legacy
`Api-Key` scheme) calls deployed inference models and, for management keys,
manages deployments. Personal, team (optionally environment-scoped) and
org-level management keys share the documented format. No public key type
exists.

## Supported shape (T1; takes effect on the date)

Source: [docs.baseten.co/organization/api-keys](https://docs.baseten.co/organization/api-keys.md).
The provider publishes the format "so secret-scanning tools can identify
exposed credentials", as the regex `b10_[A-Za-z0-9]{8}\.[A-Za-z0-9]{32}`. It
also states that keys created before 3:00 PM GMT on 2026-10-01 do not carry
the prefix.

**Re-checked 2026-09-28:**

- the regex and the cutoff sentence are unchanged;
- the page now also shows an illustrative full-width placeholder: `b10_`, a
  sequential 8-byte id, `.`, and a sequential 32-byte alphabet run. The
  research noted this example as absent;
- the list-keys response example still shows `b10_` + 8 as the visible key
  prefix.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `b10_` | provider docs (scanner regex) | T1 |
| Key id | exactly 8 `[A-Za-z0-9]` | provider docs | T1 |
| Separator | `.` | provider docs | T1 |
| Secret | exactly 32 `[A-Za-z0-9]` | provider docs | T1 |
| Checksum | none documented | — | — |

Total 45. The visible `b10_` + 8 prefix is how keys are listed and revoked, so
it is **not** secret on its own; only the full 45-byte value is claimed.

## Why it is date-gated, not READY

The grammar is complete and T1, but no key with this shape can exist until the
cutoff.

- **Product.** A detector could be built from synthetic tests at any time. It
  should land only after the date, together with the confirmation below, so
  that the finding type is never shipped for a shape the provider has not yet
  issued.
- **Benchmarks.** No arrival or empirical claim before real keys exist. Any
  observation must come from a key created after the cutoff.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Pre-cutoff keys: unprefixed, apparently `<8>.<32>` (the length is not sourced) | generic dotted token. Not attributable without context; named and header contexts are already covered |
| `b10_` + 8 alone (visible key prefix) | a non-secret identifier used for listing and revocation |
| Frontier Gateway federated keys: `sky_` + 12 + `.` + secret of unstated length | separate credential; secret length unknown |
| BYO federated keys (any 32–128 bytes) | no shape |
| `b10_` Python identifiers in truss (`b10_remote`, …) | not the full shape |

## Overlap and output policy

- **Existing detectors.** None claims `b10_`. The dotted body is inside
  `bearer_token`'s alphabet, and the probe on `main` shows `bearer_token` for
  Bearer and `contextual_secret` for named contexts, both full span. Bare,
  chat and JSON `"token"` are missed. The legacy `Authorization: Api-Key <key>`
  header is a `generic-token` question outside this contract.
- **Planned output.** Provider type, high confidence, always redact.

## Implementation notes (after the date)

`PrefixShape::exact("b10_", 41, alnum_or_dot, …).with_post_check(dot_at_offset_8_only)`
with the `[A-Za-z0-9_-]` boundary. A trailing `.` after the 32-byte secret is
sentence punctuation and is not part of the span; the exact width already
guarantees that. Signals: `baseten-documented-prefix`,
`baseten-documented-grammar`.

The docs' full-width sequential placeholder matches the exact grammar, so it
**is claimed**, per the #867 placeholder precedent. Tests record that as
accepted behavior.

## Test axes

**Positives:**

- every index context;
- `Authorization: Api-Key` (legacy scheme);
- `BASETEN_API_KEY=`;
- a truss `config.yaml` secret;
- the OpenAI-compatible `base_url` client call.

**Near-miss twins:**

- id of 7 or 9;
- secret of 31 or 33;
- a `-`, `_` or second `.` in either part;
- `B10_`;
- `b10-`;
- a missing `.`;
- a leading glue byte and a trailing glue byte.

**Benign:**

- `b10_` + 8 (visible prefix) in list output and in
  `baseten org api-key delete --prefix`;
- `b10_remote` imports;
- `sky_` gateway ids;
- unprefixed `<8>.<32>` values (not claimed by this detector).

## False-positive / false-negative boundary

- **False negatives:**
  - every pre-cutoff key outside named or header contexts, until users
    rotate;
  - gateway and BYO keys.
- **False positives:** the documentation placeholder, and any unrelated
  `b10_` + 8 + `.` + 32 alphanumeric value. None is known.

## Issuance checklist — after 2026-10-01 15:00 GMT (structure only)

1. Create one personal key and, if available, one team key and one management
   key.
2. For each record: total length (expect 45), `b10_` present, id length,
   separator byte and position, secret length, alphabet classes,
   `rawValueRetained: false`, revoked.
3. Only after a match: land the detector and let the benchmarks side record
   arrival.
