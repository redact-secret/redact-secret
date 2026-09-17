"""Measures the per-call overhead `RedactSecretFilter.filter` adds to a
`logging` call, for a 1 KB and a 64 KB message, against the real,
release-built `redact_secret` extension (issue #328's "measured per-call
cost in a release build, not a debug build"). Requires the built wheel or
an in-place extension on `PYTHONPATH`:

    cd bindings/python && maturin develop --release
    python3 examples/logging-redaction/python/benchmark.py

Prints median and p95 milliseconds per call over many iterations, after a
warmup phase. Numbers are machine-dependent; this script, not a single
frozen number, is the artifact worth trusting.
"""

from __future__ import annotations

import logging
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import redact_secret  # noqa: E402
from logging_filter import RedactSecretFilter  # noqa: E402


class NullHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        pass


def percentile(sorted_ms: list[float], p: float) -> float:
    index = min(len(sorted_ms) - 1, int(len(sorted_ms) * p))
    return sorted_ms[index]


def benchmark(logger: logging.Logger, message: str, *, warmup: int, iterations: int) -> tuple[float, float]:
    for _ in range(warmup):
        logger.info(message)

    samples_ms = []
    for _ in range(iterations):
        start = time.perf_counter()
        logger.info(message)
        samples_ms.append((time.perf_counter() - start) * 1000)
    samples_ms.sort()
    return percentile(samples_ms, 0.5), percentile(samples_ms, 0.95)


def main() -> None:
    logger = logging.getLogger("logging-redaction-benchmark")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.handlers.clear()
    handler = NullHandler()
    handler.addFilter(RedactSecretFilter(redact_secret.scan_and_redact))
    logger.addHandler(handler)

    for label, num_bytes in (("1 KB message", 1024), ("64 KB message", 64 * 1024)):
        # Plain filler text with no findings, matching the issue's request
        # to measure the no-secret-found path most log lines take.
        filler = "the quick brown fox jumps over the lazy dog. "
        message = (filler * (num_bytes // len(filler) + 1))[:num_bytes]
        median_ms, p95_ms = benchmark(logger, message, warmup=200, iterations=2000)
        print(f"{label}: median {median_ms:.4f} ms/call, p95 {p95_ms:.4f} ms/call")


if __name__ == "__main__":
    main()
