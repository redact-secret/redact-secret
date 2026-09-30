# #1013 evidence: `slack:app-level-token`

[Index](README.md) ·
[Issue #1013](https://github.com/redact-secret/redact-secret/issues/1013) ·
[Spec: detector families](../../../specs/detector-families.md)

Frozen 2026-09-29. Desk research only: no token was issued, and no issued or
leaked credential is evidence. Shapes use D = digit, U = uppercase, l =
lowercase, with a count.

**Contract under test (Beta.8 wave 1, #726/#729):** `xapp-` + four
dash-separated sections, digits / alphanumeric / digits / alphanumeric,
widths open.

**Matrix blocker (pin at `b9e90915`):** corroborated route 0 / 0 / 0 (no
ledger record for this family).

**Verdict: READY-T2, conditional** on the maintainer accepting Slack's own
four-section placeholders as provider examples and bounding the shorter
Slack placeholders (Q-SL below). If that is refused, the family is
STILL-BLOCKED and only hands-on issuance closes it.

## Sources

All read 2026-09-29.

| # | Source | Date | Owner | Class | Statement (shape only) |
| --- | --- | --- | --- | --- | --- |
| 1 | docs.slack.dev/authentication/tokens | live | Slack | provider docs | T1 for the prefix and role: "App-level token strings begin with `xapp-`." No example |
| 2 | docs.slack.dev/apis/events-api/using-socket-mode | live | Slack | provider-example | `xapp-` D1-D3: two sections |
| 3 | [slackapi/java-slack-sdk `docs/english/guides/socket-mode.md#L180`](https://github.com/slackapi/java-slack-sdk/blob/49b62a6b866bf43eb4c3bfe9c8423a65400d2928/docs/english/guides/socket-mode.md#L180) (served on docs.slack.dev) | present at 2025-08-07 | Slack | provider-example (placeholder) | `xapp-` D1-U1D3-D3-l3: four sections, digit / alnum / digit / alnum. L213 of the same file is three sections |
| 4 | [java-slack-sdk `bolt-socket-mode/src/test/java/samples/OAuth.java#L29`](https://github.com/slackapi/java-slack-sdk/blob/49b62a6b866bf43eb4c3bfe9c8423a65400d2928/bolt-socket-mode/src/test/java/samples/OAuth.java#L29) | 2021-01-07 | Slack | provider-owned-code (sample) | four sections, D1-U1D3-D3-l3 |
| 5 | [slackapi/slack-cli `internal/goutils/strings_test.go#L198-L202`](https://github.com/slackapi/slack-cli/blob/20dd73092a65d3797180f95f0ee765053d7ef634/internal/goutils/strings_test.go#L198-L202) | 2025-03-31 | Slack | provider-owned-code (test fixture) | four sections, D1-U1D3-D4-U4 |
| 6 | [slack-cli `internal/goutils/strings.go#L125`](https://github.com/slackapi/slack-cli/blob/20dd73092a65d3797180f95f0ee765053d7ef634/internal/goutils/strings.go#L125) | 2025-03-31 | Slack | provider-owned-code (redactor) | `xapp-[\w.-]*`: prefix only |
| 7 | [gitleaks `cmd/generate/config/rules/slack.go#L90-L91`](https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/cmd/generate/config/rules/slack.go#L90-L91) | 2023-06-15 | gitleaks | peer-scanner-rule | `(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+`, commented "based on a limited number of examples". Widths open; its test samples (from a third-party repo) are 1/11/13/64 |
| 8 | [google/osv-scalibr `veles/secrets/slacktoken/detector.go#L35-L39`](https://github.com/google/osv-scalibr/blob/5ab8022c6d67ff99d91d9750f2456ed9549fe8cb/veles/secrets/slacktoken/detector.go#L35-L39) | 2025-09-27 | Google | peer-scanner-rule | `xapp-\d{1,10}-[A-Za-z0-9]{11}-[0-9]{13}-[a-fA-F0-9]{64}`: "digits …, an app ID, … and 64 hex characters" |
| 9 | [docker/portcullis `rules.go#L1297-L1303`](https://github.com/docker/portcullis/blob/a2eb85db2b08ca2c73739d87df4de58e99fe1b86/rules.go#L1297-L1303) | 2026-05-08 | Docker | peer-scanner-rule | "`xapp-<digit>-<workspace>-<int>-<hex>` … The four-segment shape"; `xapp-\d-[A-Z0-9]{8,16}-\d{8,16}-[a-fA-F0-9]{32,128}` |
| 10 | [openclaw/openclaw `extensions/slack/src/monitor/provider.ts#L185-L192`](https://github.com/openclaw/openclaw/blob/ec38fb6cb407e5107f4830172166c90dbb0569e4/extensions/slack/src/monitor/provider.ts#L185-L192) | 2026-01-14 | openclaw | independent-implementation (parses the app id) | `^xapp-\d-([a-z0-9]+)-`: section 1 digits, section 2 the app id, more sections follow |
| 11 | [peaberry-studio/arche `integration.ts#L96-L99`](https://github.com/peaberry-studio/arche/blob/abe588b2af4954f8e17070c0bd0dc63ee21215af/apps/web/src/lib/slack/integration.ts#L96-L99) | 2026-04-17 | peaberry-studio | independent-implementation | `^xapp-\d+-(A[0-9A-Z]+)-`: section 2 is an `A…` app id |
| 12 | [praetorian-inc/noseyparker `slack.yml#L74`](https://github.com/praetorian-inc/noseyparker/blob/2e6e7f36ce36619852532bbe698d8cb7a26d2da7/crates/noseyparker/data/default/builtin/rules/slack.yml#L74) | 2023-11-02 | Praetorian | peer-scanner-rule | `xapp-[0-9]{12}-[a-zA-Z0-9/+]{24}`: two sections (contradicts) |
| 13 | bolt-python [`test_lazy_listeners.py#L60`](https://github.com/slackapi/bolt-python/blob/eddc4766559e5dc623700015c70ea360d076dced/tests/adapter_tests/socket_mode/test_lazy_listeners.py#L60) (about 45 similar); bolt-js [`basic.spec.ts#L21`](https://github.com/slackapi/bolt-js/blob/b64c469e04a92420b1f66ebafaf87f412961e865/test/unit/App/basic.spec.ts#L21) | — | Slack | provider fixtures | three sections without the leading digit (bolt-python); one section (bolt-js); two (slack-cli `install_test.go`). Contradict |

Derivative copies of the gitleaks rule (DataDog dd-trace-js, Checkmarx 2ms,
semgrep-rules, betterleaks) and a GitHub-owned skill file with a four-section
regex were found and not counted. Searched with no anatomy result: every
slackapi SDK (no SDK validates beyond the prefix), slackapi issues (pastes
are redacted), the `apps.connections.open` reference (no example), trufflehog
(no `xapp` detector), Microsoft security-utilities (none), CredSweeper
(loose `xapp-[0-9A-Za-z-]{10,250}`).

## Corroborated-route count

For the four-section digit / alnum / digit / alnum anatomy: #7 (gitleaks),
#8 (Google), #9 (Docker), #3–#5 (Slack, one owner), with #10 and #11
confirming the first two sections. That is at least 4 owners and 2
non-summary classes (peer-scanner-rule, provider-example /
provider-owned-code), plus partial independent-implementation support.

Section widths are not corroborated and stay open, as the contract says:

| Section | Slack placeholders | Docker | osv-scalibr |
| --- | --- | --- | --- |
| 1 (digits) | 1 | 1 | 1–10 |
| 2 (app id) | 4 | 8–16 | 11 |
| 3 (digits) | 3–4 | 8–16 | 13 |
| 4 (secret) | 3–4 | hex 32–128 | hex 64 |

## Contradictions

| Statement | Proposed status | Basis |
| --- | --- | --- |
| Slack's own one-, two- and three-section placeholders (#2, #3 L213, #13) against its four-section placeholders (#3–#5) | bounded | provider sources disagree among themselves and are all illustrative; the contract requires exactly four sections and excludes shorter shapes |
| noseyparker two sections, 12 digits / 24 characters (#12) | bounded | no Slack source shows it; excluded by the four-section contract |
| A third-party three-section validator (intel/AI-Playground, which falls back to any `xapp-` of 30+ characters) | bounded | same bound |

## Maintainer ruling needed

Q-SL: may Slack's four-section placeholders (#3–#5) count as
provider-example corroboration when other Slack placeholders show fewer
sections? If yes, the corroborated route clears with the bound above. If
no, only hands-on issuance can close the family.

## Issuance check (only if Q-SL is refused)

One app-level token from Basic Information > App-Level Tokens, recorded as
structure only: number of `-`-separated sections after `xapp-` (expected 4);
section 1 all digits and its length; section 2 `A` + `[A-Z0-9]` and its
length; section 3 all digits and its length; section 4 alphabet (hex or not)
and length; total length. Revoke afterwards.

## Out of scope

Benign and twin fixture counts, 3 unresolved critical mutation findings,
`mode`, `uncertainty` and `supportedContexts` are ledger and fixture work.
