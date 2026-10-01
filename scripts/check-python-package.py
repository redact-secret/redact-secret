#!/usr/bin/env python3
"""Enforce the CPython packaging contract declared in the root Cargo.toml.

``[workspace.metadata.redact-secret]`` states the distribution identity, the
abi3 floor, and the wheel matrix once. This script fails when any of the three
places that have to agree with it drifts: ``bindings/python/pyproject.toml``,
``bindings/python/Cargo.toml``, and the wheel workflow.

Checks, in order:

1. Distribution identity: the project name is ``python-distribution``, the
   version is dynamic so maturin takes it from the Cargo workspace
   (``decision-release-bindings-in-lockstep``), and the readme, license
   expression, and license file that a published distribution needs are all
   declared and present.
2. abi3 contract: the extension crate selects ``python-abi3-feature``, and the
   interpreter floor that feature encodes is exactly the ``requires-python``
   floor. One abi3 wheel per platform serves every CPython from that floor
   upward only if those two never drift apart.
3. Extension shape: maturin builds ``python-native-module`` from a ``cdylib``
   whose ``extension-module`` feature is off by default, so
   ``cargo test --workspace`` still links the crate on every host.
4. No pure-Python fallback: the importable package is the thin re-export of
   the native module and nothing else (``decision-define-runtime-bindings``).
   A second detector implementation cannot appear here unnoticed.
5. Typing: the package ships ``py.typed`` and a stub for the native module, so
   the distribution is typed under PEP 561.
6. Wheel matrix: the workflow builds a wheel for exactly the targets in
   ``python-wheel-targets``, and every one of them maps to a platform tag this
   repository knows how to qualify. Its required ``Wheel matrix`` check runs
   on every pull request, without a path filter that can leave merges blocked.

Run ``--recheck-pypi-name`` to also query PyPI for the product name and the
selected distribution name; that is the only check that uses the network and
it is off by default.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Iterable
from pathlib import Path

# `qualify-python-wheel.py` imports this module and runs on the abi3 floor,
# CPython 3.10, where `tomllib` does not exist yet; `tomli` is the same parser.
try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on CPython 3.10
    import tomli as tomllib  # type: ignore[no-redef]


BINDING = Path("bindings") / "python"
WHEEL_WORKFLOW = Path(".github") / "workflows" / "python-wheels.yml"

# `abi3-py310` and the `>=3.10` floor it implies.
ABI3_FEATURE = re.compile(r"^abi3-py3(\d+)$")
REQUIRES_PYTHON = re.compile(r"^>=3\.(\d+)$")

# Every `target:` key in the wheel workflow's build matrix.
WORKFLOW_TARGET = re.compile(r"^\s*(?:-\s+)?target:\s*(\S+)\s*$", re.M)
ON_BLOCK = re.compile(r"^on:\s*\n(?P<body>(?:[ \t]{2,}.*\n|[ \t]*\n)*)", re.M)
PULL_REQUEST_BLOCK = re.compile(
    r"^  pull_request:\s*(?:\{\})?\s*\n(?P<body>(?:[ \t]{4,}.*\n|[ \t]*\n)*)",
    re.M,
)

# A single wheel platform tag each supported target may produce.
# `qualify-python-wheel.py` reads this table too, so a target and the tag it is
# qualified against are one statement.
#
# manylinux has two spellings of the same platform: the PEP 600 `manylinux_x_y`
# form and the legacy aliases, and auditwheel emits both. `manylinux2014_*` is
# `manylinux_2_17_*`, `manylinux2010_*` is `manylinux_2_12_*`, and
# `manylinux1_*` is `manylinux_2_5_*`. musllinux never had aliases.
MANYLINUX = r"(?:manylinux_\d+_\d+|manylinux1|manylinux2010|manylinux2014)"
TARGET_PLATFORM_TAGS = {
    "aarch64-apple-darwin": re.compile(r"^macosx_\d+_\d+_arm64$"),
    "aarch64-pc-windows-msvc": re.compile(r"^win_arm64$"),
    "aarch64-unknown-linux-gnu": re.compile(rf"^{MANYLINUX}_aarch64$"),
    "aarch64-unknown-linux-musl": re.compile(r"^musllinux_\d+_\d+_aarch64$"),
    "x86_64-apple-darwin": re.compile(r"^macosx_\d+_\d+_x86_64$"),
    "x86_64-pc-windows-msvc": re.compile(r"^win_amd64$"),
    "x86_64-unknown-linux-gnu": re.compile(rf"^{MANYLINUX}_x86_64$"),
    "x86_64-unknown-linux-musl": re.compile(r"^musllinux_\d+_\d+_x86_64$"),
}


def targets_for_platform(platform: str, declared: Iterable[str]) -> list[str]:
    """Every declared target whose tag pattern matches this platform tag.

    A wheel filename carries a *compressed tag set*, not one tag: auditwheel
    emits `manylinux_2_17_x86_64.manylinux2014_x86_64`, which is one platform
    written two ways. Each `.`-separated element has to name the same target,
    so a wheel can neither claim two platforms at once nor smuggle an
    unqualified tag in beside a qualified one.
    """
    parts = platform.split(".")
    return [
        target
        for target in declared
        if target in TARGET_PLATFORM_TAGS and all(TARGET_PLATFORM_TAGS[target].match(part) for part in parts)
    ]


# The maturin floor that understands PEP 639 `license-files`, so the license
# actually travels with the wheel.
MINIMUM_MATURIN = (1, 10)
MATURIN_REQUIREMENT = re.compile(r"^maturin\s*>=\s*(\d+)\.(\d+)(?:\.\d+)?\s*,\s*<\s*2$")

USER_AGENT = "redact-secret packaging check (https://github.com/redact-secret/redact-secret)"


def load_policy(root: Path) -> dict:
    """The `[workspace.metadata.redact-secret]` table, or an empty table."""
    with (root / "Cargo.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    return manifest.get("workspace", {}).get("metadata", {}).get("redact-secret", {})


def abi3_floor(feature: str) -> int | None:
    """The CPython minor version `abi3-py3NN` pins, or None if unrecognized."""
    match = ABI3_FEATURE.match(feature)
    return int(match.group(1)) if match else None


def check_identity(binding: Path, project: dict, build_system: dict, policy: dict) -> list[str]:
    errors: list[str] = []
    expected = policy.get("python-distribution")
    if project.get("name") != expected:
        errors.append(f"{BINDING}/pyproject.toml: name {project.get('name')!r} must be {expected!r}")
    if project.get("dynamic") != ["version"]:
        errors.append(f"{BINDING}/pyproject.toml: version must stay dynamic so maturin reads the workspace version")
    if "version" in project:
        errors.append(f"{BINDING}/pyproject.toml: must not pin its own version")
    if project.get("license") != "MIT":
        errors.append(f"{BINDING}/pyproject.toml: license must be the SPDX expression MIT")
    for key in ("readme", "license-files"):
        if not project.get(key):
            errors.append(f"{BINDING}/pyproject.toml: must declare {key}")
    for relative in [project.get("readme")] + list(project.get("license-files") or []):
        if isinstance(relative, str) and not (binding / relative).is_file():
            errors.append(f"{BINDING}/{relative}: declared by pyproject.toml but missing")
    if project.get("dependencies"):
        errors.append(f"{BINDING}/pyproject.toml: the runtime must have no Python dependencies")

    requires = build_system.get("requires") or []
    if len(requires) != 1 or not MATURIN_REQUIREMENT.match(requires[0].replace(" ", "")):
        errors.append(f"{BINDING}/pyproject.toml: build-system requires must be a single 'maturin>=X.Y,<2'")
    else:
        match = MATURIN_REQUIREMENT.match(requires[0].replace(" ", ""))
        assert match
        if (int(match.group(1)), int(match.group(2))) < MINIMUM_MATURIN:
            floor = ".".join(str(part) for part in MINIMUM_MATURIN)
            errors.append(f"{BINDING}/pyproject.toml: maturin floor must be at least {floor} for PEP 639 license files")
    if build_system.get("build-backend") != "maturin":
        errors.append(f"{BINDING}/pyproject.toml: build-backend must be maturin")
    return errors


def check_abi3(project: dict, crate: dict, policy: dict) -> list[str]:
    errors: list[str] = []
    feature = policy.get("python-abi3-feature", "")
    floor = abi3_floor(feature)
    if floor is None:
        return [f"Cargo.toml: python-abi3-feature {feature!r} is not an abi3-py3NN feature"]

    pyo3 = crate.get("dependencies", {}).get("pyo3", {})
    selected = pyo3.get("features") or []
    if feature not in selected:
        errors.append(f"{BINDING}/Cargo.toml: pyo3 must select the {feature} feature, found {selected}")
    if any(other != feature and abi3_floor(other) is not None for other in selected):
        errors.append(f"{BINDING}/Cargo.toml: pyo3 selects more than one abi3 floor: {selected}")

    requires_python = project.get("requires-python", "")
    match = REQUIRES_PYTHON.match(requires_python)
    if not match:
        errors.append(f"{BINDING}/pyproject.toml: requires-python {requires_python!r} must be '>=3.NN'")
    elif int(match.group(1)) != floor:
        errors.append(
            f"{BINDING}/pyproject.toml: requires-python {requires_python} does not match the {feature} floor >=3.{floor}"
        )

    expected_tag = f"cp3{floor}-abi3"
    if policy.get("python-wheel-tag") != expected_tag:
        errors.append(f"Cargo.toml: python-wheel-tag must be {expected_tag} for {feature}")
    return errors


def check_extension_shape(maturin: dict, crate: dict, policy: dict) -> list[str]:
    errors: list[str] = []
    module = policy.get("python-native-module")
    if maturin.get("module-name") != module:
        errors.append(f"{BINDING}/pyproject.toml: [tool.maturin] module-name must be {module!r}")
    if maturin.get("python-source") != "python":
        errors.append(f"{BINDING}/pyproject.toml: [tool.maturin] python-source must be 'python'")
    if maturin.get("features") != ["extension-module"]:
        errors.append(f"{BINDING}/pyproject.toml: [tool.maturin] features must be ['extension-module']")

    crate_type = crate.get("lib", {}).get("crate-type") or []
    if "cdylib" not in crate_type:
        errors.append(f"{BINDING}/Cargo.toml: [lib] crate-type must contain cdylib")
    features = crate.get("features", {})
    if features.get("extension-module") != ["pyo3/extension-module"]:
        errors.append(f"{BINDING}/Cargo.toml: the extension-module feature must enable pyo3/extension-module")
    if features.get("default"):
        errors.append(
            f"{BINDING}/Cargo.toml: default features must stay empty so cargo test --workspace links the crate"
        )
    return errors


def check_no_python_fallback(binding: Path, policy: dict) -> list[str]:
    """The importable package re-exports the native module and does nothing else."""
    errors: list[str] = []
    import_name = policy.get("python-import-name", "")
    native = policy.get("python-native-module", "")
    package = binding / "python" / import_name
    if not package.is_dir():
        return [f"{BINDING}/python/{import_name}: missing importable package"]

    sources = sorted(path for path in package.rglob("*.py"))
    unexpected = [path.relative_to(binding).as_posix() for path in sources if path.name != "__init__.py"]
    if unexpected:
        errors.append(
            f"{BINDING}: only __init__.py may be Python; found {', '.join(unexpected)} "
            "(detection belongs in the Rust core)"
        )

    init = package / "__init__.py"
    if not init.is_file():
        return errors + [f"{BINDING}/python/{import_name}/__init__.py: missing"]
    relative = f"{BINDING}/python/{import_name}/__init__.py"
    try:
        tree = ast.parse(init.read_text(encoding="utf-8"), filename=str(init))
    except SyntaxError as error:
        return errors + [f"{relative}: does not parse ({error})"]

    allowed = {"__future__", native}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module if node.level == 0 else "." * node.level + (node.module or "")
            if module not in allowed:
                errors.append(f"{relative}: may not import from {module!r}, only {native!r}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in allowed:
                    errors.append(f"{relative}: may not import {alias.name!r}, only {native!r}")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            errors.append(
                f"{relative}: defines {node.name!r}; the package re-exports the native module "
                "and never implements behavior"
            )
    return errors


def check_typing(binding: Path, policy: dict) -> list[str]:
    import_name = policy.get("python-import-name", "")
    native = policy.get("python-native-module", "")
    stub = f"{native.rsplit('.', 1)[-1]}.pyi"
    package = binding / "python" / import_name
    return [
        f"{BINDING}/python/{import_name}/{marker}: missing; the distribution must be typed (PEP 561)"
        for marker in ("py.typed", stub)
        if not (package / marker).is_file()
    ]


def check_wheel_matrix(root: Path, policy: dict) -> list[str]:
    errors: list[str] = []
    declared = policy.get("python-wheel-targets") or []
    if not declared:
        return ["Cargo.toml: python-wheel-targets must declare the supported wheel matrix"]

    unknown = [target for target in declared if target not in TARGET_PLATFORM_TAGS]
    if unknown:
        errors.append(
            f"Cargo.toml: python-wheel-targets names {', '.join(unknown)}, "
            "which check-python-package.py cannot map to a wheel platform tag"
        )

    workflow = root / WHEEL_WORKFLOW
    if not workflow.is_file():
        return errors + [f"{WHEEL_WORKFLOW.as_posix()}: missing wheel workflow"]
    workflow_text = workflow.read_text(encoding="utf-8")
    trigger = ON_BLOCK.search(workflow_text)
    pull_request = PULL_REQUEST_BLOCK.search(trigger.group("body")) if trigger else None
    if pull_request is None:
        errors.append(f"{WHEEL_WORKFLOW.as_posix()}: must trigger on every pull_request")
    elif re.search(r"^\s+paths(?:-ignore)?:", pull_request.group("body"), re.M):
        errors.append(
            f"{WHEEL_WORKFLOW.as_posix()}: pull_request trigger must not use path filters; "
            "Wheel matrix is a required check"
        )

    built = set(WORKFLOW_TARGET.findall(workflow_text))
    missing = sorted(set(declared) - built)
    extra = sorted(built - set(declared))
    if missing:
        errors.append(f"{WHEEL_WORKFLOW.as_posix()}: builds no wheel for {', '.join(missing)}")
    if extra:
        errors.append(f"{WHEEL_WORKFLOW.as_posix()}: builds {', '.join(extra)}, which Cargo.toml does not declare")
    return errors


def validate(root: Path) -> list[str]:
    root = root.resolve()
    binding = root / BINDING
    policy = load_policy(root)
    if not policy:
        return ["Cargo.toml: missing [workspace.metadata.redact-secret] policy"]

    pyproject_path = binding / "pyproject.toml"
    crate_path = binding / "Cargo.toml"
    for path in (pyproject_path, crate_path):
        if not path.is_file():
            return [f"{path.relative_to(root).as_posix()}: missing"]
    with pyproject_path.open("rb") as handle:
        pyproject = tomllib.load(handle)
    with crate_path.open("rb") as handle:
        crate = tomllib.load(handle)

    project = pyproject.get("project", {})
    maturin = pyproject.get("tool", {}).get("maturin", {})
    build_system = pyproject.get("build-system", {})

    errors: list[str] = []
    errors.extend(check_identity(binding, project, build_system, policy))
    errors.extend(check_abi3(project, crate, policy))
    errors.extend(check_extension_shape(maturin, crate, policy))
    errors.extend(check_no_python_fallback(binding, policy))
    errors.extend(check_typing(binding, policy))
    errors.extend(check_wheel_matrix(root, policy))
    return errors


class RegistryUnreachable(Exception):
    """PyPI could not be reached, which is not the same as a name being free."""


def distribution_exists(name: str) -> bool:
    request = urllib.request.Request(f"https://pypi.org/pypi/{name}/json", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response) is not None
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return False
        raise RegistryUnreachable(f"PyPI returned HTTP {error.code} for {name}") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise RegistryUnreachable(f"could not reach PyPI for {name}: {error}") from error


def recheck_pypi_name(policy: dict) -> list[str]:
    """Report what the product name and the selected name look like on PyPI.

    The product name being taken is the recorded reason for the fallback, so a
    recheck that found it free would mean the recorded reason no longer holds.
    """
    product = policy["product-name"]
    selected = policy["python-distribution"]
    if distribution_exists(selected):
        return [f"PyPI: {selected} already exists; it cannot be this distribution's name"]
    print(f"PyPI: {selected} is available")
    if product != selected:
        if distribution_exists(product):
            print(f"PyPI: {product} is taken by an unrelated project, as docs/rust-workspace.md records")
        else:
            return [
                f"PyPI: {product} is now available, so the recorded reason for the "
                f"{selected} fallback no longer holds; review the name before publishing"
            ]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", default=Path.cwd(), type=Path)
    parser.add_argument("--recheck-pypi-name", action="store_true", help="query PyPI for the distribution name")
    args = parser.parse_args()

    errors = validate(args.root)
    if args.recheck_pypi_name and not errors:
        try:
            errors.extend(recheck_pypi_name(load_policy(Path(args.root).resolve())))
        except RegistryUnreachable as error:
            # An unreachable registry proves nothing about a name, so it is a
            # failure rather than a silent pass on the path a release runs.
            errors.append(f"PyPI: {error}")
    for error in errors:
        print(f"ERROR {error}")
    print(f"Python package check complete: {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
