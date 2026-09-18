# Python

[Documentation home](../README.md) · [Installation](../getting-started.md)

Import `redact_secret`; no explicit initialization call is required.

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

Catch `redact_secret.SecretScanError` for library failures and stop downstream
processing. Do not fall back to the raw input. The binding maps callback
failures to fixed exceptions instead of forwarding the callback's message.

## Incremental input and packaging

Python provides working bounded incremental sessions. See the complete
[streaming example](streaming.md); limits count UTF-8 bytes while finding
positions count Unicode code points.

The package ships type stubs and `py.typed`. CPython abi3 wheels and source
build requirements are documented in [Python packaging](../python-packaging.md).
To require a prebuilt wheel instead of a source build, use
`python -m pip install --only-binary=:all: redact-secret`.
See the [binding README](../../bindings/python/README.md) for development details.
