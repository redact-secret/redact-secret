"""Tiny known-answer tests for the installed-Python assessment host adapter."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "assessment_python_worker", ROOT / "scripts" / "assessment-python-worker.py"
)
assert SPEC and SPEC.loader
WORKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKER)


class FakeLimits:
    @staticmethod
    def minimum_buffered_bytes(max_token_bytes: int, max_multiline_bytes: int) -> int:
        return max_token_bytes + max_multiline_bytes + 128

    def __init__(self, **values: int) -> None:
        self.values = values


class FakeSession:
    def __init__(self, limits: FakeLimits) -> None:
        self.chunks: list[str] = []
        self.closed = False

    def append(self, chunk: str) -> SimpleNamespace:
        if self.closed:
            raise RuntimeError("closed")
        self.chunks.append(chunk)
        return SimpleNamespace(text="", findings=[])

    def finalize(self) -> SimpleNamespace:
        if self.closed:
            raise RuntimeError("closed")
        self.closed = True
        result = FakeApi.scan_and_redact("".join(self.chunks))
        return SimpleNamespace(text=result.text, findings=result.findings)

    def abort(self) -> None:
        self.closed = True


class FakeApi:
    IncrementalLimits = FakeLimits
    IncrementalSanitizer = FakeSession

    @staticmethod
    def scan_and_redact(text: str) -> SimpleNamespace:
        markers = ["ghp_ASSESSMENTSYNTHETIC0000000000000000", "AKIASYNTHETICEXAMPLE"]
        marker = next(candidate for candidate in markers if candidate in text)
        start = text.index(marker)
        finding = SimpleNamespace(
            id="finding-1",
            detector="github-token",
            type="github_token",
            confidence="high",
            action="redact",
            start=start,
            end=start + len(marker),
        )
        return SimpleNamespace(
            text=text[:start] + "<SECRET_1>" + text[start + len(marker) :],
            findings=[finding],
        )

    @staticmethod
    def scan(text: object) -> list[object]:
        if not isinstance(text, str):
            raise TypeError("invalid input")
        return []


class PythonAssessmentWorkerTests(unittest.TestCase):
    def test_unicode_code_point_ranges_normalize_to_canonical_bytes(self) -> None:
        text = "\U0001f511 ghp_ASSESSMENTSYNTHETIC0000000000000000"
        result = WORKER.run_accuracy(FakeApi, {"fixtures": [{"id": "unicode-known-answer", "input": text}]})
        finding = result["fixtures"][0]["findings"][0]
        self.assertEqual(finding["start"], len("\U0001f511 ".encode("utf-8")))
        self.assertEqual(finding["end"], len(text.encode("utf-8")))
        self.assertEqual(result["fixturesEvaluated"], 1)

    def test_whole_and_incremental_mismatch_fails_without_plaintext(self) -> None:
        class DivergingSession(FakeSession):
            def finalize(self) -> SimpleNamespace:
                result = super().finalize()
                return SimpleNamespace(text="<SECRET_1>", findings=result.findings)

        class DivergingApi(FakeApi):
            IncrementalSanitizer = DivergingSession

        marker = "ghp_ASSESSMENTSYNTHETIC0000000000000000"
        with self.assertRaises(WORKER.WorkerFailure) as raised:
            WORKER.run_accuracy(
                DivergingApi,
                {"fixtures": [{"id": "incomplete-known-answer", "input": f"prefix {marker}"}]},
            )
        self.assertEqual(str(raised.exception), "incomplete-known-answer:INCREMENTAL_MISMATCH")
        self.assertNotIn(marker, str(raised.exception))

    def test_package_failure_stops_incomplete_run(self) -> None:
        class FailingApi(FakeApi):
            calls = 0

            @staticmethod
            def scan_and_redact(text: str) -> SimpleNamespace:
                FailingApi.calls += 1
                if FailingApi.calls >= 2:
                    raise RuntimeError("synthetic input must not escape")
                return FakeApi.scan_and_redact(text)

        marker = "ghp_ASSESSMENTSYNTHETIC0000000000000000"
        with self.assertRaises(WORKER.WorkerFailure) as raised:
            WORKER.run_accuracy(
                FailingApi,
                {
                    "fixtures": [
                        {"id": "first-known-answer", "input": marker},
                        {"id": "second-known-answer", "input": marker},
                    ]
                },
            )
        self.assertEqual(str(raised.exception), "second-known-answer:PACKAGE_OPERATION_FAILED")
        self.assertNotIn(marker, str(raised.exception))

    def test_self_test_exercises_failure_and_aborted_session(self) -> None:
        WORKER.run_self_test(FakeApi)


if __name__ == "__main__":
    unittest.main()
