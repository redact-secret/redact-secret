#!/usr/bin/env python3
"""Verify original qualified artifacts before a partial release is resumed."""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def verify_files(inventory: dict, artifact: str, directory: Path) -> None:
    expected = {item["file"]: item for item in inventory["artifacts"] if item["artifact"] == artifact}
    if not expected:
        raise ValueError("artifact is absent from the original qualification inventory")
    paths = [path for path in directory.rglob("*") if path.is_file()]
    if any(path.is_symlink() for path in directory.rglob("*")):
        raise ValueError("recovery artifact contains a symlink")
    actual = {path.relative_to(directory).as_posix(): path for path in paths}
    if set(actual) != set(expected):
        raise ValueError("recovery artifact file set differs from the qualified inventory")
    for name, path in actual.items():
        if path.stat().st_size != expected[name]["bytes"] or hashlib.sha256(path.read_bytes()).hexdigest() != expected[name]["sha256"]:
            raise ValueError("recovery artifact content differs from the qualified inventory")


@dataclass(frozen=True)
class PypiState:
    status: str
    existing_files: list[str]
    missing_files: list[str]
    conflicting_files: list[str]
    extra_files: list[str]
    reason: str


def _pypi_expected(inventory: dict) -> dict[str, str]:
    expected = {item["file"]: item["sha256"] for item in inventory["artifacts"] if item["file"].endswith((".whl", ".tar.gz"))}
    if not expected:
        raise ValueError("qualified inventory contains no PyPI files")
    return expected


def _pypi_expected_items(inventory: dict) -> dict[str, dict]:
    expected = {item["file"]: item for item in inventory["artifacts"] if item["file"].endswith((".whl", ".tar.gz"))}
    if not expected:
        raise ValueError("qualified inventory contains no PyPI files")
    return expected


def pypi_absent(inventory: dict) -> PypiState:
    expected = _pypi_expected_items(inventory)
    return PypiState(
        status="absent",
        existing_files=[],
        missing_files=sorted(expected),
        conflicting_files=[],
        extra_files=[],
        reason="PyPI version is not published",
    )


def pypi_unobservable(reason: str) -> PypiState:
    return PypiState(
        status="unobservable",
        existing_files=[],
        missing_files=[],
        conflicting_files=[],
        extra_files=[],
        reason=reason,
    )


def verify_pypi(inventory: dict, metadata: dict) -> PypiState:
    expected = _pypi_expected(inventory)
    try:
        actual = {item["filename"]: item["digests"]["sha256"] for item in metadata["urls"]}
    except (KeyError, TypeError) as exc:
        raise ValueError("PyPI metadata is missing filenames or SHA-256 digests") from exc

    expected_names = set(expected)
    actual_names = set(actual)
    existing = sorted(expected_names & actual_names)
    missing = sorted(expected_names - actual_names)
    extra = sorted(actual_names - expected_names)
    conflicts = sorted(name for name in existing if actual[name] != expected[name])

    if conflicts or extra:
        return PypiState(
            status="conflict",
            existing_files=existing,
            missing_files=missing,
            conflicting_files=conflicts,
            extra_files=extra,
            reason="PyPI contains files that do not match the qualified inventory",
        )
    if missing:
        return PypiState(
            status="partial",
            existing_files=existing,
            missing_files=missing,
            conflicting_files=[],
            extra_files=[],
            reason="PyPI contains a matching proper subset of the qualified files",
        )
    return PypiState(
        status="complete",
        existing_files=existing,
        missing_files=[],
        conflicting_files=[],
        extra_files=[],
        reason="PyPI contains the complete qualified file set",
    )


def fetch_pypi_state(inventory: dict, project: str, version: str) -> PypiState:
    request = Request(
        f"https://pypi.org/pypi/{project}/{version}/json",
        headers={"User-Agent": "redact-secret-release-verification"},
    )
    try:
        with urlopen(request, timeout=30) as response:
            return verify_pypi(inventory, json.load(response))
    except HTTPError as exc:
        code = exc.code
        exc.close()
        if code == 404:
            return pypi_absent(inventory)
        return pypi_unobservable(f"PyPI returned HTTP {code}")
    except (TimeoutError, URLError, json.JSONDecodeError) as exc:
        return pypi_unobservable(f"PyPI metadata could not be read: {type(exc).__name__}")


def stage_missing_pypi_files(inventory: dict, state: PypiState, directory: Path) -> None:
    if state.status == "complete":
        return
    if state.status not in {"absent", "partial"}:
        raise ValueError("cannot stage PyPI files from a conflicting or unobservable registry state")

    expected = _pypi_expected_items(inventory)
    missing = set(state.missing_files)
    if not missing:
        raise ValueError("PyPI recovery state names no missing files")
    if any(name not in expected for name in missing):
        raise ValueError("PyPI recovery state names a file outside the qualified inventory")

    paths = [path for path in directory.rglob("*") if path.is_file()]
    if any(path.is_symlink() for path in directory.rglob("*")):
        raise ValueError("recovery artifact contains a symlink")
    actual = {path.relative_to(directory).as_posix(): path for path in paths}

    absent = sorted(missing - set(actual))
    if absent:
        raise ValueError("qualified PyPI recovery artifacts are unavailable")
    extras = sorted(set(actual) - set(expected))
    if extras:
        raise ValueError("recovery artifact file set differs from the qualified inventory")

    for name in missing:
        path = actual[name]
        expected_item = expected[name]
        if path.stat().st_size != expected_item["bytes"] or hashlib.sha256(path.read_bytes()).hexdigest() != expected_item["sha256"]:
            raise ValueError("recovery artifact content differs from the qualified inventory")

    for name, path in actual.items():
        if name not in missing:
            path.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--artifact")
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--pypi")
    parser.add_argument("--version")
    parser.add_argument("--pypi-report", type=Path)
    parser.add_argument("--stage-pypi-missing", type=Path)
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text())
    if args.stage_pypi_missing:
        if not args.pypi_report:
            parser.error("--pypi-report is required with --stage-pypi-missing")
        payload = json.loads(args.pypi_report.read_text())
        stage_missing_pypi_files(inventory, PypiState(**payload), args.stage_pypi_missing)
        print("Missing PyPI files verified and staged.")
        return
    if args.pypi:
        state = fetch_pypi_state(inventory, args.pypi, args.version)
        if args.pypi_report:
            args.pypi_report.write_text(json.dumps(asdict(state), indent=2, sort_keys=True) + "\n")
        if state.status in {"conflict", "unobservable"}:
            raise ValueError(state.reason)
        print(f"PyPI state: {state.status}.")
        if state.missing_files:
            print("Missing PyPI files:")
            for name in state.missing_files:
                print(f"- {name}")
    else:
        if not args.artifact or not args.directory:
            parser.error("--artifact and --directory are required for local artifacts")
        verify_files(inventory, args.artifact, args.directory)
        print("Original qualified artifact verified.")


if __name__ == "__main__":
    main()
