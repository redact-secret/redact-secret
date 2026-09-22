"""Import tests: the package imports cleanly and exposes the documented
public surface, with no custom detector callback surface."""

from __future__ import annotations

import inspect

import redact_secret


def test_module_imports_and_declares_all() -> None:
    assert redact_secret.__all__
    for name in redact_secret.__all__:
        assert hasattr(redact_secret, name), name


def test_version_and_range_unit_are_documented_strings() -> None:
    assert isinstance(redact_secret.VERSION, str) and redact_secret.VERSION
    assert redact_secret.RANGE_UNIT == "unicode-code-points"
    assert redact_secret.__version__ == redact_secret.VERSION


def test_exception_hierarchy_is_importable_and_rooted() -> None:
    subclasses = [
        redact_secret.InvalidInputError,
        redact_secret.InvalidOptionsError,
        redact_secret.InvalidDetectorError,
        redact_secret.DetectorFailureError,
        redact_secret.InvalidCandidateError,
        redact_secret.PolicyFailureError,
        redact_secret.InvalidPolicyActionError,
        redact_secret.InvalidFindingsError,
        redact_secret.PlaceholderFailureError,
        redact_secret.InvalidPlaceholderError,
        redact_secret.InvalidRulesetError,
    ]
    for exc_type in subclasses:
        assert issubclass(exc_type, redact_secret.SecretScanError)
        assert issubclass(exc_type, Exception)


def test_no_custom_detector_callback_surface() -> None:
    """`decision-define-runtime-bindings`: the first stable API excludes a
    custom detector *callback* surface. `scan` accepts `text`, `policy`,
    `limits`, and `ruleset`; nothing named after a registry is exported.

    `ruleset` (issue #495,
    `decision-define-declarative-detector-ruleset-contract`) is not a
    callback: it is caller-supplied data the core parses and matches
    itself, never host code running per candidate, so it does not reopen
    the excluded surface."""
    scan_params = set(inspect.signature(redact_secret.scan).parameters)
    assert scan_params <= {"text", "policy", "limits", "ruleset"}
    for name in redact_secret.__all__:
        assert "detector" not in name.lower() or name in {
            "DetectorFailureError",
            "InvalidDetectorError",
        }


def test_unloadable_extension_fails_with_fixed_actionable_message() -> None:
    """Issue #586: a missing or foreign-platform extension module must fail
    the import with one fixed message that names no host path and points to
    the packaging guide, not the loader's own traceback."""
    import subprocess
    import sys

    probe = (
        "import importlib.abc, sys\n"
        "class Block(importlib.abc.MetaPathFinder):\n"
        "    def find_spec(self, name, path, target=None):\n"
        "        if name == 'redact_secret._native':\n"
        "            raise ImportError('synthetic loader failure at /nonexistent/_native.so')\n"
        "sys.meta_path.insert(0, Block())\n"
        "import redact_secret\n"
    )
    first = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True)
    second = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True)
    assert first.returncode != 0
    message = first.stderr.strip().splitlines()[-1]
    assert message == second.stderr.strip().splitlines()[-1]
    assert message.startswith("ImportError: redact-secret could not load its native extension")
    assert "docs/python-packaging.md" in message
    assert "/nonexistent" not in first.stderr
    assert "synthetic loader failure" not in first.stderr
