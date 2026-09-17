"""A SpanProcessor (OpenTelemetry Python, pinned against
opentelemetry-sdk==1.44.0 while resolving issue #326:
https://github.com/open-telemetry/opentelemetry-python/blob/main/opentelemetry-sdk/src/opentelemetry/sdk/trace/__init__.py)
that redacts every string and string-sequence attribute -- including
OpenInference and GenAI semantic-convention attributes -- on a span and
its events before handing the span to the next processor. It does not
allowlist those attribute names: every string-shaped attribute value is
scanned, which covers any semantic convention without hardcoding it and
without a dependency on either convention's attribute list.

``ReadableSpan.attributes`` returns a read-only ``MappingProxyType`` in
the pinned SDK version -- there is no public mutation API before export.
This reaches into the private ``_attributes`` field instead (and each
event's ``_attributes``), which is the accepted workaround for OTel
Python redaction processors absent a public API. If a future SDK version
removes or renames that field, ``test_redact_span_attributes.py``'s
exporter assertion fails loudly instead of silently letting plaintext
through -- it does not assume the field is `None`-safe by construction.

This module does not import ``opentelemetry`` at all: ``SpanProcessor``'s
``on_start``/``on_end``/``shutdown``/``force_flush`` are plain (non-
abstract) methods, so Python's duck typing means a class implementing the
same four methods needs no base class, no import, and no dependency --
matching ``redact-span-attributes.mjs``'s JS side. See
``otel_span_processor.py`` for the live factory that wires this to the
real ``redact_secret.scan_and_redact``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:  # pragma: no cover - type checking only, no runtime dependency
    from opentelemetry.context import Context
    from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor

from mask_leaf import mask_leaf_with

__all__ = ["redact_attributes_with", "RedactingSpanProcessorWith"]


def _mask_attribute_value(scan_and_redact, value, *, policy, max_string_length):
    if isinstance(value, str):
        return mask_leaf_with(scan_and_redact, value, policy=policy, max_string_length=max_string_length)
    if isinstance(value, (list, tuple)) and value and all(isinstance(item, str) for item in value):
        masked = [mask_leaf_with(scan_and_redact, item, policy=policy, max_string_length=max_string_length) for item in value]
        return type(value)(masked)
    # Numbers, booleans, and homogeneous number/boolean sequences are the
    # only other attribute value shapes OpenTelemetry allows; none of them
    # can carry a secret as free text, so they pass through unchanged.
    return value


def redact_attributes_with(
    scan_and_redact: Callable[..., Any],
    attributes: Optional[dict],
    *,
    policy: Optional[Any] = None,
    limits: Optional[dict] = None,
) -> None:
    """Mutates `attributes` (a real, mutable dict) in place. A no-op for
    `None`."""
    if attributes is None:
        return
    max_string_length = (limits or {}).get("max_string_length")
    for key in list(attributes.keys()):
        attributes[key] = _mask_attribute_value(
            scan_and_redact, attributes[key], policy=policy, max_string_length=max_string_length
        )


class RedactingSpanProcessorWith:
    """Wraps `next_processor` (any object shaped like a `SpanProcessor`)
    and redacts every span's and event's string attributes before
    delegating to it. `scan_and_redact` is injected so this class is
    testable without the built native extension or a real OpenTelemetry
    dependency."""

    def __init__(
        self,
        next_processor: "SpanProcessor",
        scan_and_redact: Callable[..., Any],
        *,
        policy: Optional[Any] = None,
        limits: Optional[dict] = None,
    ) -> None:
        if not callable(getattr(next_processor, "on_end", None)):
            raise TypeError("RedactingSpanProcessorWith: next_processor must be a SpanProcessor")
        if not callable(scan_and_redact):
            raise TypeError("RedactingSpanProcessorWith: scan_and_redact must be callable")
        self._next = next_processor
        self._scan_and_redact = scan_and_redact
        self._policy = policy
        self._limits = limits

    def on_start(self, span: "Span", parent_context: Optional["Context"] = None) -> None:
        self._next.on_start(span, parent_context)

    def on_end(self, span: "ReadableSpan") -> None:
        redact_attributes_with(
            self._scan_and_redact, getattr(span, "_attributes", None), policy=self._policy, limits=self._limits
        )
        for event in getattr(span, "events", ()) or ():
            redact_attributes_with(
                self._scan_and_redact, getattr(event, "_attributes", None), policy=self._policy, limits=self._limits
            )
        self._next.on_end(span)

    def shutdown(self) -> None:
        self._next.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self._next.force_flush(timeout_millis)
