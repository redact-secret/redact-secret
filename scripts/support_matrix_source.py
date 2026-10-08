"""Two pinned evidence schemas, with native provenance and a separate historical PII source."""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VIEW_SCHEMA = "redact-secret/support-matrix-from-view/v1"
HISTORICAL_PII = Path("benchmarks/support-matrix.json")
CURRENT_MATRIX = Path("benchmarks/support-matrix-from-view.json")


def active_matrix_path(root: Path = ROOT) -> Path:
    current = root / CURRENT_MATRIX
    return current if current.is_file() else root / HISTORICAL_PII
REQUIRED_SCANNERS = {"flare-redact", "gitleaks", "redact-secret", "trufflehog"}
POPULATIONS = {"policy-corpus", "public-evidence-snapshot", "regression-corpus"}


def matrix_schema_errors(matrix: dict, root: Path = ROOT) -> list[str]:
    if not is_view_matrix(matrix):
        return ["unsupported support matrix schema"] if "schema" in matrix else []
    path = root / "benchmarks/support-matrix-view-schema.json"
    if not path.is_file():
        return ["canonical support matrix schema has not been pinned"]
    spec = importlib.util.spec_from_file_location("matrix_schema_validator", Path(__file__).with_name("check-scoring-artifact.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    schema = json.loads(path.read_text())
    return module.validate_schema(matrix, schema, schema)


def is_view_matrix(matrix: dict) -> bool:
    return matrix.get("schema") == VIEW_SCHEMA


def benchmark_revision(root: Path = ROOT) -> str:
    value = json.loads((root / "benchmarks/pin-source.json").read_text())["benchmarkCommit"]
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{40}", value):
        raise ValueError("benchmark pin is not an immutable full revision")
    return value


def view_source_errors(matrix: dict) -> list[str]:
    """Extra schema validation never substitutes a local legacy run for the canonical source."""
    if not is_view_matrix(matrix):
        return []
    errors = []
    if matrix.get("mode") != "published" or matrix.get("publication") != "public":
        errors.append("canonical support matrix must be published and public")
    source = matrix.get("source")
    if not isinstance(source, dict):
        return errors + ["canonical support matrix source is missing"]
    view = source.get("view", {})
    if not isinstance(view, dict) or not isinstance(view.get("policyRevision"), str) or not re.fullmatch(r"rs-policy-[0-9]+:sha256:[a-f0-9]{64}", view["policyRevision"]):
        errors.append("canonical support matrix policy identity is missing")
    populations = source.get("populations")
    if not isinstance(populations, list):
        return errors + ["canonical support matrix populations are missing"]
    if any(not isinstance(p, dict) for p in populations):
        return errors + ["canonical support matrix population must be an object"]
    if {p.get("population") for p in populations} != POPULATIONS or len(populations) != len(POPULATIONS):
        errors.append("canonical support matrix population inventory disagrees")
    product_versions = set()
    for population in populations:
        if population.get("runClass") != "public":
            errors.append("canonical support matrix contains an internal population")
        for field in ("semanticDigest", "artifactDigest"):
            if not isinstance(population.get(field), str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", population[field]):
                errors.append(f"canonical support matrix {field} is invalid")
        builds, versions = population.get("scannerBuilds", {}), population.get("scannerVersions", {})
        if not isinstance(builds, dict) or not isinstance(versions, dict):
            errors.append("canonical scanner roster must be an object")
            continue
        if set(builds) != REQUIRED_SCANNERS or set(versions) != REQUIRED_SCANNERS or any(value != "released" for value in builds.values()):
            errors.append("canonical support matrix did not measure the four released required scanners")
        if any(not isinstance(value, str) or not value for value in versions.values()):
            errors.append("canonical support matrix scanner versions are missing")
        product_version = versions.get("redact-secret")
        if isinstance(product_version, str):
            product_versions.add(product_version)
    package = source.get("publishedPackage")
    if (not isinstance(package, dict) or set(package) != {"packageName", "version"} or
            package.get("packageName") != "@redact-secret/core" or not isinstance(package.get("version"), str) or product_versions != {package.get("version")}):
        errors.append("canonical support matrix published package disagrees with recorded scanners")
    return errors


def matrix_source(matrix: dict, root: Path = ROOT) -> dict:
    """Consumer identity, not a fabricated sourceReport or product source commit."""
    if is_view_matrix(matrix):
        errors = view_source_errors(matrix)
        if errors:
            raise ValueError("; ".join(errors))
        source = matrix["source"]
        return {"kind": "qualification-view", "revision": benchmark_revision(root), "generatedAt": None, "runId": None,
                "dirty": None, "productVersion": source["publishedPackage"]["version"], "productRevision": None,
                "policyRevision": source["view"]["policyRevision"], "populations": source["populations"],
                "fixtureCount": None, "fixtureDigest": None, "taxonomyDigest": None}
    report = matrix.get("sourceReport")
    if "schema" in matrix or not isinstance(report, dict):
        raise ValueError("support matrix has neither accepted evidence schema")
    product, package = report.get("product") or {}, report.get("publishedPackage") or {}
    index = report.get("fixtureIndex") or {}
    return {"kind": "legacy", "revision": report.get("revision"), "generatedAt": report.get("generatedAt"), "runId": report.get("runId"),
            "dirty": report.get("dirty"), "productVersion": product.get("declaredVersion") or package.get("version"),
            "productRevision": product.get("sourceCommit"), "policyRevision": None, "populations": [],
            "fixtureCount": index.get("fixtureCount"), "fixtureDigest": index.get("digest"), "taxonomyDigest": report.get("taxonomyDigest")}


def historical_pii_matrix(matrix: dict, root: Path = ROOT) -> dict:
    if not is_view_matrix(matrix):
        return matrix
    historical = json.loads((root / HISTORICAL_PII).read_text())
    if is_view_matrix(historical) or "piiFamilies" not in historical:
        raise ValueError("historical PII snapshot is not the retained legacy qualification")
    return historical
