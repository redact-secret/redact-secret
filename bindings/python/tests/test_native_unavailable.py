"""A wheel whose native extension cannot load fails with one actionable
message that names the reinstall command, not a bare ``ImportError``."""

from __future__ import annotations

import importlib.util
import sys
import types

import pytest
import redact_secret


def test_missing_native_symbols_raise_the_reinstall_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An extension module that imports but lacks the expected names stands in
    # for an ABI-mismatched or incomplete installation.
    monkeypatch.setitem(sys.modules, "redact_secret._native", types.ModuleType("redact_secret._native"))
    spec = importlib.util.spec_from_file_location("redact_secret_unavailable_probe", redact_secret.__file__)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)

    with pytest.raises(ImportError, match="could not load its native extension") as info:
        spec.loader.exec_module(module)

    assert "--only-binary=:all: redact-secret" in str(info.value)
    # `from None` suppresses the chained low-level error.
    assert info.value.__suppress_context__ is True
