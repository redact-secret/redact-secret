"""The live OpenTelemetry Python integration:

    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from otel_span_processor import create_redacting_span_processor

    exporting_processor = BatchSpanProcessor(otlp_exporter)
    provider = TracerProvider()
    provider.add_span_processor(create_redacting_span_processor(exporting_processor))

There is no init step for the Python bindings (the native extension loads
on `import redact_secret`), unlike the JS package's `await initialize()`.
Not imported by `test_redact_span_attributes.py` -- like
`examples/safe-integration`'s live wrapper files on the JS side, this thin
module is exercised against the real built package, not unit tested with
a fake.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:  # pragma: no cover - type checking only, no runtime dependency
    from opentelemetry.sdk.trace import SpanProcessor

import redact_secret

from redact_span_attributes import RedactingSpanProcessorWith

__all__ = ["RedactingSpanProcessorWith", "create_redacting_span_processor"]


def create_redacting_span_processor(
    next_processor: "SpanProcessor", *, policy: Optional[Any] = None, limits: Optional[dict] = None
) -> RedactingSpanProcessorWith:
    """Wraps `next_processor` with the real `redact_secret.scan_and_redact`."""
    return RedactingSpanProcessorWith(next_processor, redact_secret.scan_and_redact, policy=policy, limits=limits)
