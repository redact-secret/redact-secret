#!/usr/bin/env python3
"""Narrow host adapter for evaluating an installed ``redact-secret`` package.

The JavaScript command-line runners own the common corpus, generator, scoring,
schema, and report format. This worker owns only Python's public host contract:
it imports the installed distribution, calls whole-input and incremental APIs,
and converts Unicode-code-point ranges to canonical UTF-8 byte ranges.

Requests arrive as JSON on standard input. Responses contain metadata and
measurements only; they never contain fixture input or matched plaintext.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import math
import platform
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any


class WorkerFailure(Exception):
    """A fixed, input-free worker failure."""


def _read_request() -> dict[str, Any]:
    value = json.load(sys.stdin)
    if not isinstance(value, dict):
        raise WorkerFailure("INVALID_REQUEST")
    return value


def _load_package() -> tuple[Any, float, str]:
    started = time.perf_counter_ns()
    api = importlib.import_module("redact_secret")
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    if getattr(api, "RANGE_UNIT", None) != "unicode-code-points":
        raise WorkerFailure("UNEXPECTED_RANGE_UNIT")
    try:
        distribution = importlib.metadata.distribution("redact-secret")
    except importlib.metadata.PackageNotFoundError as error:
        raise WorkerFailure("DISTRIBUTION_NOT_INSTALLED") from error
    installed_module = Path(distribution.locate_file("redact_secret/__init__.py")).resolve()
    imported_module = Path(api.__file__).resolve()
    if installed_module != imported_module:
        raise WorkerFailure("INSTALLED_DISTRIBUTION_SHADOWED")
    return api, elapsed_ms, distribution.version


def _runtime() -> str:
    version = platform.python_version()
    return f"{sys.implementation.name}-{version}"


def _byte_offset(text: str, code_point_offset: int) -> int:
    if not isinstance(code_point_offset, int) or not 0 <= code_point_offset <= len(text):
        raise WorkerFailure("INVALID_NATIVE_RANGE")
    return len(text[:code_point_offset].encode("utf-8"))


def _normalize_finding(text: str, finding: Any) -> dict[str, Any]:
    start = _byte_offset(text, finding.start)
    end = _byte_offset(text, finding.end)
    if end <= start:
        raise WorkerFailure("INVALID_NATIVE_RANGE")
    selected = text[finding.start : finding.end]
    if text.encode("utf-8")[start:end].decode("utf-8") != selected:
        raise WorkerFailure("RANGE_SPAN_MISMATCH")
    return {
        "id": finding.id,
        "detector": finding.detector,
        "type": finding.type,
        "confidence": finding.confidence,
        "start": start,
        "end": end,
        "action": finding.action,
    }


def _limits(api: Any, input_bytes: int) -> Any:
    max_token_bytes = 8_192
    max_multiline_bytes = 32_768
    max_buffered_bytes = api.IncrementalLimits.minimum_buffered_bytes(max_token_bytes, max_multiline_bytes)
    return api.IncrementalLimits(
        max_input_bytes=max(input_bytes + 1, max_buffered_bytes),
        max_buffered_bytes=max_buffered_bytes,
        max_token_bytes=max_token_bytes,
        max_multiline_bytes=max_multiline_bytes,
    )


def _incremental(api: Any, text: str, chunks: list[str]) -> tuple[str, list[Any]]:
    session = api.IncrementalSanitizer(_limits(api, len(text.encode("utf-8"))))
    output: list[str] = []
    findings: list[Any] = []
    for chunk in chunks:
        result = session.append(chunk)
        output.append(result.text)
        findings.extend(result.findings)
    final = session.finalize()
    output.append(final.text)
    findings.extend(final.findings)
    return "".join(output), findings


def _evaluate_fixture(api: Any, fixture: dict[str, Any]) -> list[dict[str, Any]]:
    fixture_id = fixture.get("id")
    text = fixture.get("input")
    if not isinstance(fixture_id, str) or not isinstance(text, str):
        raise WorkerFailure("INVALID_FIXTURE")
    try:
        whole = api.scan_and_redact(text)
        incremental_text, incremental_findings = _incremental(api, text, list(text))
    except Exception as error:
        raise WorkerFailure(f"{fixture_id}:PACKAGE_OPERATION_FAILED") from error
    whole_findings = [_normalize_finding(text, finding) for finding in whole.findings]
    incremental = [_normalize_finding(text, finding) for finding in incremental_findings]
    if whole.text != incremental_text or whole_findings != incremental:
        raise WorkerFailure(f"{fixture_id}:INCREMENTAL_MISMATCH")
    return whole_findings


def run_accuracy(api: Any, request: dict[str, Any]) -> dict[str, Any]:
    fixtures = request.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise WorkerFailure("INVALID_FIXTURES")
    results = []
    for fixture in fixtures:
        if not isinstance(fixture, dict):
            raise WorkerFailure("INVALID_FIXTURE")
        results.append({"id": fixture.get("id"), "findings": _evaluate_fixture(api, fixture)})
    return {"fixturesEvaluated": len(results), "fixtures": results}


def _process_input(api: Any, text: str, chunks: list[str], chunk_profile: str) -> int:
    if chunk_profile == "whole":
        result = api.scan_and_redact(text)
        return len(result.text) + len(result.findings)
    output, findings = _incremental(api, text, chunks)
    return len(output) + len(findings)


def _maximum_rss_bytes() -> int | None:
    try:
        import resource
    except ImportError:
        return None
    observed = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if not isinstance(observed, (int, float)) or observed < 0:
        return None
    # Linux and the BSDs report KiB; macOS reports bytes.
    multiplier = 1 if sys.platform == "darwin" else 1_024
    return int(observed * multiplier)


def run_performance_sample(api: Any, initialization_ms: float, version: str, request: dict[str, Any]) -> dict[str, Any]:
    text = request.get("input")
    chunks = request.get("chunks")
    chunk_profile = request.get("chunkProfile")
    if (
        not isinstance(text, str)
        or not isinstance(chunks, list)
        or any(not isinstance(chunk, str) for chunk in chunks)
        or "".join(chunks) != text
        or not isinstance(chunk_profile, str)
    ):
        raise WorkerFailure("INVALID_WORKLOAD")
    input_bytes = len(text.encode("utf-8"))
    _process_input(api, text, chunks, chunk_profile)

    started = time.perf_counter_ns()
    sink = _process_input(api, text, chunks, chunk_profile)
    processing_ms = (time.perf_counter_ns() - started) / 1_000_000
    if sink < 0 or not math.isfinite(processing_ms) or processing_ms <= 0:
        raise WorkerFailure("PROCESSING_DID_NOT_COMPLETE")

    # Memory is a separate, untimed operation so tracemalloc overhead cannot
    # contaminate the processing distribution.
    tracemalloc.start()
    python_baseline, _ = tracemalloc.get_traced_memory()
    rss_baseline = _maximum_rss_bytes()
    _process_input(api, text, chunks, chunk_profile)
    _, python_peak = tracemalloc.get_traced_memory()
    rss_after = _maximum_rss_bytes()
    tracemalloc.stop()

    response: dict[str, Any] = {
        "initializationMs": initialization_ms,
        "processingMs": processing_ms,
        "throughputBytesPerSecond": input_bytes / (processing_ms / 1_000),
        "pythonHeap": {
            "baselineBytes": python_baseline,
            "maximumObservedBytes": max(python_baseline, python_peak),
        },
        "version": version,
        "runtime": _runtime(),
    }
    if rss_baseline is None or rss_after is None:
        response["processRss"] = None
    else:
        response["processRss"] = {
            "baselineBytes": rss_baseline,
            "maximumObservedBytes": max(rss_baseline, rss_after),
        }
    return response


def run_self_test(api: Any) -> None:
    text = "\U0001f511 AKIASYNTHETICEXAMPLE"
    result = run_accuracy(api, {"fixtures": [{"id": "unicode-known-answer", "input": text}]})
    finding = result["fixtures"][0]["findings"][0]
    if finding["start"] <= text.index("AKIA"):
        raise WorkerFailure("UNICODE_NORMALIZATION_NOT_EXERCISED")

    try:
        api.scan(None)
    except Exception:
        pass
    else:
        raise WorkerFailure("FAILURE_PATH_NOT_EXERCISED")

    session = api.IncrementalSanitizer(_limits(api, len(text.encode("utf-8"))))
    session.append(text[:4])
    session.abort()
    try:
        session.finalize()
    except Exception:
        pass
    else:
        raise WorkerFailure("INCOMPLETE_RUN_NOT_REJECTED")


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"metadata", "accuracy", "performance-sample", "self-test"}:
        print("python assessment worker failed: INVALID_COMMAND", file=sys.stderr)
        return 1
    command = sys.argv[1]
    try:
        request = {} if command in {"metadata", "self-test"} else _read_request()
        api, initialization_ms, version = _load_package()
        if command == "metadata":
            response = {"version": version, "runtime": _runtime()}
        elif command == "accuracy":
            response = run_accuracy(api, request)
        elif command == "performance-sample":
            response = run_performance_sample(api, initialization_ms, version, request)
        else:
            run_self_test(api)
            response = {"ok": True}
        print(json.dumps(response, separators=(",", ":"), sort_keys=True))
        return 0
    except (WorkerFailure, json.JSONDecodeError) as error:
        code = str(error) if isinstance(error, WorkerFailure) else "INVALID_JSON"
        print(f"python assessment worker failed: {code}", file=sys.stderr)
        return 1
    except Exception:
        print("python assessment worker failed: UNEXPECTED_FAILURE", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
