"""``mask_secrets_with``: the generic masking callback the issue asks for,
shaped exactly like Langfuse Python's legacy ``mask`` hook signature
(``def masking_function(*, data: Any, **kwargs: Any) -> Any``), so
``mask_secrets`` (see ``langfuse_mask.py``) is a drop-in
``Langfuse(mask=mask_secrets)``. This file never imports ``redact_secret``
itself -- ``scan_and_redact`` is injected -- so it is testable without the
built native extension, mirroring ``mask-secrets.mjs``.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from mask_leaf import CYCLE_MARKER, DEFAULT_LIMITS, LIMIT_MARKER, mask_leaf_with

__all__ = ["mask_secrets_with"]


def _is_plain_dict(value: Any) -> bool:
    return type(value) is dict


def _is_plain_list(value: Any) -> bool:
    return type(value) is list


def _mask_value(scan_and_redact, value, *, policy, limits, budget, depth, seen):
    if isinstance(value, str):
        if budget["leaves"] <= 0:
            return LIMIT_MARKER
        budget["leaves"] -= 1
        return mask_leaf_with(
            scan_and_redact, value, policy=policy, max_string_length=limits["max_string_length"]
        )

    if _is_plain_list(value):
        if depth >= limits["max_depth"]:
            return LIMIT_MARKER
        if id(value) in seen:
            return CYCLE_MARKER
        seen.add(id(value))
        try:
            # Elements beyond the limit are dropped, never passed through unmasked.
            bounded = value[: limits["max_array_length"]]
            return [
                _mask_value(scan_and_redact, item, policy=policy, limits=limits, budget=budget, depth=depth + 1, seen=seen)
                for item in bounded
            ]
        finally:
            seen.discard(id(value))

    if _is_plain_dict(value):
        if depth >= limits["max_depth"]:
            return LIMIT_MARKER
        if id(value) in seen:
            return CYCLE_MARKER
        seen.add(id(value))
        try:
            # Keys beyond the limit are dropped, never passed through unmasked.
            keys = list(value.keys())[: limits["max_object_keys"]]
            return {
                key: _mask_value(
                    scan_and_redact, value[key], policy=policy, limits=limits, budget=budget, depth=depth + 1, seen=seen
                )
                for key in keys
            }
        finally:
            seen.discard(id(value))

    # Numbers, booleans, None, and non-plain objects (tuples, dataclasses,
    # ...) are left unchanged: only plain dicts, lists, and strings are
    # walked.
    return value


def mask_secrets_with(
    scan_and_redact: Callable[..., Any],
    data: Any,
    *,
    policy: Optional[Any] = None,
    limits: Optional[dict[str, int]] = None,
) -> Any:
    """Recursively masks every string inside a plain dict/list tree.

    ``scan_and_redact`` is called once per leaf string, so a
    ``<SECRET_1>``-style placeholder index restarts at each leaf --
    identical to calling ``scan_and_redact`` directly on that one string.
    """
    if not callable(scan_and_redact):
        raise TypeError("mask_secrets_with: scan_and_redact must be callable")
    merged_limits = {**DEFAULT_LIMITS, **(limits or {})}
    budget = {"leaves": merged_limits["max_total_leaves"]}
    return _mask_value(scan_and_redact, data, policy=policy, limits=merged_limits, budget=budget, depth=0, seen=set())
