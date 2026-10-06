# Python

[Documentation home](../README.md) · [Installation](../getting-started.md)

Install with `pip install --only-binary=:all: redact-secret` (the newest beta
while no stable release exists); the [quickstart](../quickstart.md#python) pins
an exact version. Import `redact_secret`; no explicit initialization call is
required.

```python
import redact_secret

result = redact_secret.scan_and_redact("API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE")
assert result.text == "API_KEY=<SECRET_1>"
assert len(result.findings) == 1
```

Use `scan(text)` for findings only, or `redact(text, findings)` with findings
from the same original text. Finding fields are immutable. `start` and `end`
count Unicode code points, so they follow Python `str` indexing. Offsets always
refer to original text, including when redacted text has a different length.

## Policy and formatting

```python
import redact_secret

def redact_every_finding(finding, context):
    return "redact"

result = redact_secret.scan_and_redact(
    "API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE",
    policy=redact_every_finding,
    formatter=redact_secret.typed_placeholder_formatter,
)
assert result.text == "API_KEY=<CONTEXTUAL_SECRET_1>"
```

Callbacks receive safe finding metadata and context, not input or matched text.
The policy returns `redact`, `block`, `warn`, or `allow`. A `block` action must
also be enforced by your application; the library replaces its range without
throwing merely because it found a blocked credential.

## Declarative action policy

To change what a few rules name and keep the default action for every other
finding, pass `action_policy` instead of writing a callback that must copy the
default. The contract and the document format are in the
[action policy guide](action-policy.md).

```python
import redact_secret

result = redact_secret.scan_and_redact(
    "API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE",
    formatter=redact_secret.typed_placeholder_formatter,
    action_policy={
        "actionPolicyRevision": 1,
        "base": "default",
        "rules": [{"id": "warn-contextual", "match": {"type": ["contextual_secret"]}, "action": "warn"}],
    },
)
assert result.text == "API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE"
assert [finding.action for finding in result.findings] == ["warn"]
```

`scan`, `scan_and_redact` and `IncrementalSanitizer` take `action_policy` as a
keyword-only argument. It is a `dict`, or the document as `bytes`, `bytearray`
or `str`; `None` means no overlay. A `dict` is serialized once, when the call or
session is built, with `json.dumps(value, separators=(",", ":"))`, so the
revision must be its first key and a later change to the `dict` affects
nothing.

- A call or session takes a `policy` callback or an `action_policy`, never
  both. Supplying both raises `InvalidOptionsError` before anything is scanned,
  as does a value of any other type. The callback is unchanged: it replaces the
  default entirely, and `PolicyFailureError` and `InvalidPolicyActionError` keep
  their meaning. A declarative policy never raises either.
- The document is validated before any input is read: a whole-input call parses
  it on every call, and an `IncrementalSanitizer` validates it once at
  construction and keeps the compiled policy for its life. A rejected document
  raises `InvalidActionPolicyError` and nothing falls back to the default.
- `error.error_class` is the fixed rejection class (`"INVALID_ACTION"`,
  `"UNKNOWN_FIELD"`, and the others in the
  [error table](action-policy.md#errors)) and `error.rule_index` is the
  zero-based index of the rule being read, or `None` for a document-level
  violation. Neither repeats a byte of the document.
- A policy sees finalized findings only, and the base for an unmatched finding
  is the same evaluation `default_policy` gives, computed by the core. Public
  findings gain no field.

Catch `redact_secret.SecretScanError` for library failures and stop downstream
processing. Do not fall back to the raw input. The binding maps callback
failures to fixed exceptions instead of forwarding the callback's message.

## Request-wide placeholder numbering

Every call numbers its placeholders from 1, so scanning the string leaves of
one request one call at a time gives each leaf its own `<SECRET_1>`. To keep the
numbers unique across the request, give each call a formatter that adds the
number of placeholders already used. The package adds no helper for this: the
formatter already receives `PlaceholderContext.placeholder_index`, and the only
state the host keeps is one integer.

```python
import redact_secret


class RequestNumbering:
    """One per request. Create a new one for the next request."""

    def __init__(self) -> None:
        self.replaced_so_far = 0

    def redact_leaf(self, leaf: str) -> str:
        base = self.replaced_so_far
        used = 0

        def formatter(finding: redact_secret.Finding, context: redact_secret.PlaceholderContext) -> str:
            nonlocal used
            used = context.placeholder_index
            return f"<SECRET_{base + context.placeholder_index}>"

        text = redact_secret.scan_and_redact(leaf, formatter=formatter).text
        self.replaced_so_far = base + used
        return text
```

Call `redact_leaf` for each leaf in the order your traversal visits them. The
tests in `bindings/python/tests/test_request_wide_numbering.py` run this code
against the real extension and prove the following, and nothing more:

- A bare call restarts at `<SECRET_1>`; with the recipe, leaves holding the
  same or different values continue from the previous leaf's last number. A
  second request starts at 1 because it has its own `RequestNumbering`.
- `placeholder_index` is one-based within one call. A leaf with several
  findings uses consecutive numbers, and a leaf with none uses none.
- Each occurrence gets its own number, including two identical values in one
  leaf or in two leaves. Numbers do not identify a value.
- The formatter runs only for findings that are replaced. `redact` and `block`
  take a number; `warn` (for example `password=hunter2xyz` under the default
  policy) keeps its text and takes none. The offset therefore equals the count
  of findings whose `action` is `redact` or `block`, so a host that prefers to
  count `result.findings` gets the same offset.
- A formatter that raises fails the call with `PlaceholderFailureError` and no
  partial text. The offset moves only after a call returns; treat any
  exception as a failure of the whole request and discard the redacted leaves.
- An `IncrementalSanitizer` per streamed leaf works the same way: its
  `placeholder_index` counts across that session's `append` calls, so read the
  offset after `finalize` and give the next leaf's formatter the new base.

The closure holds integers only, never a matched value, and the formatter still
sees no input. To keep key context, record the leaf's path and the first and
last number it used (`base + 1` through `replaced_so_far`) in a host-side list.
Keep the path out of the placeholder text: a key name is caller-controlled
input.

## Exceptions

Every library failure is a `redact_secret.SecretScanError` or one of its
subclasses, with a fixed, input-free message and a `code` class attribute that
equals the core's wire code. There is one subclass per core code, so
`except redact_secret.SecretScanError` catches all of them and a subclass
narrows a handler. The set of codes grows over time: treat any exception you do
not name as a failure, and never fall back to the raw input.

| Exception | `code` | Raised when |
| --- | --- | --- |
| `SecretScanError` | none | Base class of every error below; catch it for any library failure. |
| `InvalidInputError` | `INVALID_INPUT` | The text is not a `str`, or contains an unpaired surrogate. |
| `InvalidOptionsError` | `INVALID_OPTIONS` | An option has the wrong type, such as a `ruleset` that is not `bytes`, `bytearray` or `str` or an `action_policy` that is not a `dict`, `bytes`, `bytearray` or `str`, or a call or session was given both a `policy` callback and an `action_policy`. |
| `InvalidDetectorError` | `INVALID_DETECTOR` | The detector registry is malformed. Not reachable with the detectors this package ships. |
| `DetectorFailureError` | `DETECTOR_FAILURE` | A detector failed while scanning. |
| `InvalidCandidateError` | `INVALID_CANDIDATE` | A detector returned a candidate the core rejects. Not expected with the detectors this package ships. |
| `PolicyFailureError` | `POLICY_FAILURE` | Your policy callback raised. The callback's message is not forwarded. |
| `InvalidPolicyActionError` | `INVALID_POLICY_ACTION` | Your policy returned something other than `redact`, `block`, `warn` or `allow`. |
| `InvalidFindingsError` | `INVALID_FINDINGS` | `redact` was given a finding whose range falls outside the text, is misaligned, or overlaps another finding. |
| `PlaceholderFailureError` | `PLACEHOLDER_FAILURE` | Your formatter callback raised. The callback's message is not forwarded. |
| `InvalidPlaceholderError` | `INVALID_PLACEHOLDER` | Your formatter returned an empty, over-long (more than 256 bytes) or value-reproducing placeholder. |
| `InvalidLimitsError` | `INVALID_LIMITS` | A limit is zero, or `max_buffered_bytes` is below `IncrementalLimits.minimum_buffered_bytes` for the construct limits. |
| `InputLimitExceededError` | `INPUT_LIMIT_EXCEEDED` | The whole-input bound, or an incremental session's `max_input_bytes`, was reached. |
| `FindingLimitExceededError` | `FINDING_LIMIT_EXCEEDED` | A whole-input call found more than `max_findings` findings. |
| `BufferLimitExceededError` | `BUFFER_LIMIT_EXCEEDED` | An incremental session would retain more than `max_buffered_bytes`. |
| `TokenLimitExceededError` | `TOKEN_LIMIT_EXCEEDED` | An open single-line construct exceeded `max_token_bytes`. |
| `MultilineLimitExceededError` | `MULTILINE_LIMIT_EXCEEDED` | An open multiline construct exceeded `max_multiline_bytes`. |
| `InvalidStateError` | `INVALID_STATE` | An incremental session received an operation after it left the `accepting` state. |
| `InvalidRulesetError` | `INVALID_RULESET` | A `ruleset` was rejected while loading; the message ends with the fixed rejection class in parentheses. See [rulesets](rulesets.md). |
| `InvalidActionPolicyError` | `INVALID_ACTION_POLICY` | An `action_policy` was rejected while loading. The message is fixed; `error_class` holds the fixed rejection class and `rule_index` the zero-based rule being read (`None` for a document-level violation). See [action policy](action-policy.md#errors). |
| `PiiSelectorInvalidError` | `PII_SELECTOR_INVALID` | A PII selector given to `initialize` is not valid. |
| `PiiSelectorUnsupportedError` | `PII_SELECTOR_UNSUPPORTED` | A PII jurisdiction or family is unsupported. |
| `PiiSelectorUnavailableError` | `PII_SELECTOR_UNAVAILABLE` | The selection is unavailable in this artifact. |
| `PiiActivationConflictError` | `PII_ACTIVATION_CONFLICT` | A different PII selection was requested after one was activated. |

## Callback context types and default callbacks

A policy or formatter callback receives instances of these classes. They cannot
be constructed from Python, are immutable, and carry positions only: never the
input or a matched value. `redact_secret.__all__` exports them for type
annotations.

| Name | Where it appears | Fields |
| --- | --- | --- |
| `PolicyContext` | Second argument of a `scan`/`scan_and_redact` policy | `finding_index`, `finding_count` |
| `PlaceholderContext` | Second argument of a formatter | `placeholder_index` (one-based among findings actually replaced) |
| `IncrementalPolicyContext` | Second argument of an `IncrementalSanitizer` policy | `finding_index` only: a session cannot know a total count |
| `IncrementalResult` | Return value of `IncrementalSanitizer.append()` and `finalize()` | `text`, `findings` |

`default_policy(finding, context)` and `default_incremental_policy(finding,
context)` are the built-in policies in the callback shapes above. They return
the same action for the same finding, so a custom policy can call one to fall
back to the default for findings it does not want to override.

## Whole-input limits

`scan`, `redact`, and `scan_and_redact` default to a 64 MiB input bound and a
50,000 finding-count bound (`decision-bound-whole-input-operations-by-default`),
raising `InputLimitExceededError`/`FindingLimitExceededError` rather than
returning a truncated result. Pass an explicit `limits` argument to raise or
lower the bound:

```python
import redact_secret

limits = redact_secret.WholeInputLimits(
    max_input_bytes=128 * 1024 * 1024,
    max_findings=100_000,
)
result = redact_secret.scan_and_redact(
    "API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE",
    limits=limits,
)
assert result.text == "API_KEY=<SECRET_1>"
```

A returned value means every detector inspected the whole input; a raised
`SecretScanError` comes with no partial result. These calls cannot be
cancelled and have no deadline. They release the GIL while they scan but do not
check for signals, so use a child process if you need to stop one. See
[Completeness of `Ok`](../reference/api-contract.md#completeness-of-ok) and
[Cancellation and time bounds](../reference/api-contract.md#cancellation-and-time-bounds).

## Incremental input and packaging

Python provides working bounded incremental sessions. See the complete
[streaming example](streaming.md); limits count UTF-8 bytes while finding
positions count Unicode code points.

The package ships type stubs and `py.typed`. CPython abi3 wheels and source
build requirements are documented in [Python packaging](../python-packaging.md).
To require a prebuilt wheel instead of a source build, use
`python -m pip install --only-binary=:all: redact-secret`.
See the [binding README](../../bindings/python/README.md) for development details.

## PII activation

Direct import and scanning remain credential-only. Call `initialize(pii=(...))`
before constructing scans or incremental sessions to select PII explicitly,
and use `pii_activation()` to record the canonical activation identity.
`("pii",)` closes over `pii:global:email`, `pii:global:iban`,
`pii:global:network-address`, `pii:global:payment-card`, and
`pii:global:phone`; each can be
selected exactly with its `pii:family:global:*` selector. `("pii:us",)` closes
over those global families plus `pii:us:ssn`; `("pii:family:us:ssn",)` selects
only SSNs. They require reviewed high-signal context.
Under `pii-v1`, the five global families are `provisional` (not `stable`;
phone covers `+1` / NANP only) and US SSN is `pending`; see
[detection](../reference/detection.md#opt-in-pii-availability-is-not-support).
Equivalent selection is idempotent; a different later selection raises the
fixed, input-free `PiiActivationConflictError`.

```python
import redact_secret

redact_secret.initialize(pii=("pii",))
assert redact_secret.pii_activation() == (
    "credentials=full;selectors=pii:global;families=pii:global:email,pii:global:iban,pii:global:network-address,pii:global:payment-card,pii:global:phone;vocabulary=pii-context/v2"
)
```

`status()` reports whether `initialize()` has fixed the selection and its
public activation, without initializing or changing anything. It takes no
input, never raises, and returns an immutable `CoreStatus` with exactly three
fields, `initialized`, `profile` (always `"full"`) and `activation` (the
`pii_activation()` string once initialized, otherwise `None`). Scanning works
without `initialize()` and is then credential-only, but `status()` reports
`initialized=False` and `activation=None` until a selection was fixed, and
calling it never fixes one. A release that predates `status()` has no such
attribute: use `getattr(redact_secret, "status", None)`.

```python
import redact_secret

assert redact_secret.status().initialized is False
redact_secret.initialize(pii=("pii",))
assert redact_secret.status().activation == redact_secret.pii_activation()
```
