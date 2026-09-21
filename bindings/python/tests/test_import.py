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
