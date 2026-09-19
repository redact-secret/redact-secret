"""Typing tests: the compiled extension's `.pyi` stub is syntactically
valid, matches its runtime surface, and the public callables carry
introspectable signatures a type checker (and `help()`) can read."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import redact_secret
import redact_secret._native as native

STUB_PATH = Path(native.__file__).with_name("_native.pyi")


def test_native_stub_file_exists_and_parses() -> None:
    assert STUB_PATH.is_file()
    source = STUB_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(STUB_PATH))
    assert isinstance(tree, ast.Module)


def _stub_top_level_names() -> set[str]:
    tree = ast.parse(STUB_PATH.read_text(encoding="utf-8"), filename=str(STUB_PATH))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


def test_every_public_native_name_has_a_stub_declaration() -> None:
    stub_names = _stub_top_level_names()
    for name in redact_secret.__all__:
        if not hasattr(native, name):
            continue  # re-exported from elsewhere, e.g. __version__
        assert name in stub_names, f"{name} is missing from _native.pyi"


def test_package_declares_pep_561_support() -> None:
    package_dir = Path(redact_secret.__file__).parent
    assert (package_dir / "py.typed").is_file()


def test_functions_carry_introspectable_signatures() -> None:
    expected = {
        "scan": {"text", "policy", "limits"},
        "redact": {"text", "findings", "formatter", "limits"},
        "scan_and_redact": {"text", "policy", "formatter", "limits"},
        "default_policy": {"finding", "context"},
        "default_placeholder_formatter": {"finding", "context"},
        "typed_placeholder_formatter": {"finding", "context"},
        "default_incremental_policy": {"finding", "context"},
    }
    for name, params in expected.items():
        signature = inspect.signature(getattr(redact_secret, name))
        assert set(signature.parameters) == params, name


def test_finding_and_context_types_expose_documented_attributes() -> None:
    findings = redact_secret.scan(
        "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000"
    )
    assert findings
    finding = findings[0]
    for attribute in ("id", "type", "detector", "confidence", "action", "start", "end"):
        assert hasattr(finding, attribute)
    assert isinstance(finding.start, int)
    assert isinstance(finding.end, int)
    assert isinstance(finding.confidence, str)
    assert isinstance(finding.action, str)


def test_incremental_session_methods_carry_introspectable_signatures() -> None:
    expected = {
        "append": {"self", "chunk"},
        "finalize": {"self"},
        "abort": {"self"},
    }
    for name, params in expected.items():
        signature = inspect.signature(
            getattr(redact_secret.IncrementalSanitizer, name)
        )
        assert set(signature.parameters) == params, name


def test_incremental_types_expose_documented_attributes() -> None:
    limits = redact_secret.IncrementalLimits(
        max_input_bytes=1_000_000,
        max_buffered_bytes=16_512,
        max_token_bytes=8_192,
        max_multiline_bytes=16_384,
    )
    for attribute in (
        "max_input_bytes",
        "max_buffered_bytes",
        "max_token_bytes",
        "max_multiline_bytes",
    ):
        assert isinstance(getattr(limits, attribute), int)

    session = redact_secret.IncrementalSanitizer(limits)
    assert isinstance(session.state, str)
    assert session.limits.max_input_bytes == limits.max_input_bytes

    result = session.append("api_key=ghp_SYNTHETICREVOKED00000000000000000000\n")
    assert isinstance(result.text, str)
    assert isinstance(result.findings, list)
    assert isinstance(result.findings[0].start, int)
    session.abort()
