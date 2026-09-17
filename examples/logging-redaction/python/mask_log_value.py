"""Recursively masks every string inside a value tree, including a
``BaseException``'s message and formatted traceback.

Structurally the same walk as ``mask_secrets_with`` in
``examples/tracing-masking/python/mask_secrets.py`` -- dicts, lists, and
string leaves -- plus one addition: a ``BaseException`` is redacted into a
``{"type", "message", "stack"}`` mapping, in the shape
``logging_filter.py`` gives an ``exc_info`` tuple, before its raw
``str(exc)`` or traceback ever reaches a handler.
"""

from __future__ import annotations

import traceback
from typing import Any, Callable, Optional

from mask_leaf import CYCLE_MARKER, DEFAULT_LIMITS, LIMIT_MARKER, mask_leaf_with

__all__ = ["mask_log_value_with"]


def _is_plain_dict(value: Any) -> bool:
    return type(value) is dict


def _is_plain_list(value: Any) -> bool:
    return type(value) is list


def _mask_string(scan_and_redact, value, *, policy, limits, budget):
    if budget["leaves"] <= 0:
        return LIMIT_MARKER
    budget["leaves"] -= 1
    return mask_leaf_with(scan_and_redact, value, policy=policy, max_string_length=limits["max_string_length"])


def _mask_exception(scan_and_redact, exc, *, policy, limits, budget, depth, seen):
    out: dict[str, Any] = {
        "type": type(exc).__name__,
        "message": _mask_string(scan_and_redact, str(exc), policy=policy, limits=limits, budget=budget),
    }
    formatted_stack = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    out["stack"] = _mask_string(scan_and_redact, formatted_stack, policy=policy, limits=limits, budget=budget)
    cause = exc.__cause__
    if cause is not None:
        out["cause"] = _mask_value(
            scan_and_redact, cause, policy=policy, limits=limits, budget=budget, depth=depth + 1, seen=seen
        )
    return out


def _mask_value(scan_and_redact, value, *, policy, limits, budget, depth, seen):
    if isinstance(value, str):
        return _mask_string(scan_and_redact, value, policy=policy, limits=limits, budget=budget)

    if isinstance(value, BaseException):
        if depth >= limits["max_depth"]:
            return LIMIT_MARKER
        if id(value) in seen:
            return CYCLE_MARKER
        seen.add(id(value))
        try:
            return _mask_exception(scan_and_redact, value, policy=policy, limits=limits, budget=budget, depth=depth, seen=seen)
        finally:
            seen.discard(id(value))

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
    # ...) are left unchanged: only plain dicts, lists, exceptions, and
    # strings are walked.
    return value


def mask_log_value_with(
    scan_and_redact: Callable[..., Any],
    data: Any,
    *,
    policy: Optional[Any] = None,
    limits: Optional[dict[str, int]] = None,
) -> Any:
    """Recursively masks every string (and every exception's message/stack)
    inside a dict/list/exception tree. ``scan_and_redact`` is called once
    per leaf string, so a ``<SECRET_1>``-style placeholder index restarts
    at each leaf.
    """
    if not callable(scan_and_redact):
        raise TypeError("mask_log_value_with: scan_and_redact must be callable")
    merged_limits = {**DEFAULT_LIMITS, **(limits or {})}
    budget = {"leaves": merged_limits["max_total_leaves"]}
    return _mask_value(scan_and_redact, data, policy=policy, limits=merged_limits, budget=budget, depth=0, seen=set())
