#!/usr/bin/env python3
"""Inspect, install, and smoke-test the CPython artifacts.

This is the verification half of the packaging contract that
``scripts/check-python-package.py`` declares. That script reads manifests;
this one reads built artifacts and runs them.

For a wheel it checks the filename tag, the ``WHEEL`` and ``METADATA``
records, and the exact file list, then installs the wheel into a throwaway
virtual environment with ``--no-index --no-deps --only-binary :all:`` -- which
can only succeed if the wheel needs no network, no Python dependency, and no
Rust toolchain -- and runs a self-contained smoke test from a directory
outside the repository. With ``--conformance`` it then runs the repository's
Python suite, including the shared corpus, against that installed wheel.

For a source distribution it checks the file list, then asserts the documented
no-toolchain behavior: with ``MATURIN_NO_INSTALL_RUST=1`` and no ``cargo`` on
``PATH`` the build must fail with a message that names cargo, rather than
silently fetching a toolchain or failing obscurely.

Usage::

    scripts/qualify-python-wheel.py dist/*.whl dist/*.tar.gz
    scripts/qualify-python-wheel.py --python python3.10 --python python3.13 dist/*.whl
    scripts/qualify-python-wheel.py --conformance dist/*.whl
    scripts/qualify-python-wheel.py --inspect-only dist/*.whl
"""

from __future__ import annotations

import argparse
import email.parser
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path

# This tool qualifies wheels for CPython 3.10 and up, so it has to run there
# too: `tomllib` is 3.11+, and `tomli` is the same parser under its old name.
try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on CPython 3.10
    import tomli as tomllib  # type: ignore[no-redef]

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
BINDING = ROOT / "bindings" / "python"

# The supported wheel matrix and its platform tags are declared once, in the
# workspace manifest and its checker. Read them; never restate them.
_SPEC = importlib.util.spec_from_file_location("check_python_package", SCRIPTS / "check-python-package.py")
assert _SPEC and _SPEC.loader
CHECK = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = CHECK
_SPEC.loader.exec_module(CHECK)

WHEEL_NAME = re.compile(r"^(?P<distribution>[^-]+)-(?P<version>[^-]+)-(?P<tag>[^-]+-[^-]+)-(?P<platform>.+)\.whl$")
# `0.1.0-beta.1` is the Cargo spelling of the PEP 440 version `0.1.0b1`.
SEMVER_PRERELEASE = re.compile(r"^(?P<release>\d+\.\d+\.\d+)-(?P<kind>alpha|beta|rc)\.(?P<number>\d+)$")
PRERELEASE_TAG = {"alpha": "a", "beta": "b", "rc": "rc"}
# `cargo` is missing and the backend was told not to fetch one: the failure has
# to say so.
CARGO_FAILURE = re.compile(r"cargo", re.I)

# Run in a temporary directory, against the installed wheel only.
SMOKE = """
import redact_secret
from pathlib import Path

expected_version = {version!r}
assert redact_secret.VERSION == expected_version, (redact_secret.VERSION, expected_version)
assert redact_secret.__version__ == redact_secret.VERSION
assert redact_secret.RANGE_UNIT == "unicode-code-points", redact_secret.RANGE_UNIT

# Typed under PEP 561, from the installed location.
package = Path(redact_secret.__file__).parent
for marker in ("py.typed", "_native.pyi"):
    assert (package / marker).is_file(), marker

# The synchronous API redacts a synthetic, never-valid credential. The leading
# non-ASCII characters are the point: each is two UTF-8 bytes, so this slice
# only lands on the credential if the range really is in Unicode code points.
secret = "SYNTHETIC_REVOKED_QUALIFICATION_VALUE"
text = "\\u00e9\\u00e9 api_key=" + secret + "\\nordinary text"
findings = redact_secret.scan(text)
assert findings, "the smoke input produced no finding"
finding = findings[0]
assert text[finding.start:finding.end] == secret, text[finding.start:finding.end]
assert "SYNTHETIC_REVOKED" not in repr(finding), "a finding must never carry the matched value"

redacted = redact_secret.redact(text, findings)
assert "SYNTHETIC_REVOKED" not in redacted, redacted
assert redacted.endswith("\\nordinary text"), redacted

# scan_and_redact agrees with scan + redact.
result = redact_secret.scan_and_redact(text)
assert result.text == redacted, (result.text, redacted)
assert [(f.start, f.end, f.detector) for f in result.findings] == [
    (f.start, f.end, f.detector) for f in findings
]

# Deterministic across repeated calls.
assert redact_secret.scan_and_redact(text).text == result.text

# A bounded incremental session sanitizes the same input across a boundary
# that falls inside the credential.
limits = redact_secret.IncrementalLimits(
    max_input_bytes=1_000_000,
    max_buffered_bytes=32_896,
    max_token_bytes=8_192,
    max_multiline_bytes=32_768,
)
with redact_secret.IncrementalSanitizer(limits) as session:
    parts = [session.append(text[:30]).text, session.append(text[30:]).text, session.finalize().text]
streamed = "".join(parts)
assert streamed == redacted, (streamed, redacted)

# Errors are the documented sanitized hierarchy, not host exceptions.
try:
    redact_secret.scan(None)
except redact_secret.SecretScanError as error:
    assert "SYNTHETIC_REVOKED" not in str(error)
else:
    raise AssertionError("scan(None) must raise a SecretScanError")

print("smoke ok:", redact_secret.VERSION, redact_secret.RANGE_UNIT)
"""


def policy() -> dict:
    return CHECK.load_policy(ROOT)


def pep440_version(cargo_version: str) -> str:
    """The PEP 440 spelling maturin gives the Cargo workspace version."""
    match = SEMVER_PRERELEASE.match(cargo_version)
    if not match:
        return cargo_version
    return f"{match.group('release')}{PRERELEASE_TAG[match.group('kind')]}{int(match.group('number'))}"


def workspace_version() -> str:
    with (ROOT / "Cargo.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    return manifest["workspace"]["package"]["version"]


def normalized(name: str) -> str:
    """PEP 503 normalization, as used in a wheel filename (with underscores)."""
    return re.sub(r"[-_.]+", "_", name).lower()


def parse_metadata(text: str) -> email.message.Message:
    return email.parser.Parser().parsestr(text)


def inspect_wheel(path: Path, rules: dict) -> list[str]:
    """Filename, WHEEL, METADATA, and the exact file list."""
    errors: list[str] = []
    distribution = rules["python-distribution"]
    import_name = rules["python-import-name"]
    expected_tag = rules["python-wheel-tag"]
    expected_version = pep440_version(workspace_version())

    match = WHEEL_NAME.match(path.name)
    if not match:
        return [f"{path.name}: not a wheel filename"]
    if match.group("distribution") != normalized(distribution):
        errors.append(f"{path.name}: distribution is not {distribution}")
    if match.group("version") != expected_version:
        errors.append(f"{path.name}: version {match.group('version')} is not the workspace version {expected_version}")
    if match.group("tag") != expected_tag:
        errors.append(f"{path.name}: interpreter/ABI tag {match.group('tag')} is not {expected_tag}")

    platform = match.group("platform")
    targets = CHECK.targets_for_platform(platform, rules["python-wheel-targets"])
    if len(targets) != 1:
        errors.append(f"{path.name}: platform tag {platform} matches {targets or 'no'} declared wheel target")

    with zipfile.ZipFile(path) as archive:
        names = sorted(archive.namelist())
        dist_info = f"{normalized(distribution)}-{expected_version}.dist-info"

        wheel_entry = f"{dist_info}/WHEEL"
        if wheel_entry not in names:
            errors.append(f"{path.name}: missing {wheel_entry}")
        else:
            wheel = parse_metadata(archive.read(wheel_entry).decode("utf-8"))
            # A compressed tag set in the filename is one `Tag:` header per
            # element, so read all of them; the first alone would not describe
            # the wheel.
            declared_tags = set(wheel.get_all("Tag") or [])
            expected_tags = {f"{expected_tag}-{part}" for part in platform.split(".")}
            if declared_tags != expected_tags:
                errors.append(
                    f"{path.name}: WHEEL tags {sorted(declared_tags)} disagree with the "
                    f"filename's {sorted(expected_tags)}"
                )
            if (wheel.get("Root-Is-Purelib") or "").lower() != "false":
                errors.append(f"{path.name}: WHEEL must not claim to be pure Python")

        metadata_entry = f"{dist_info}/METADATA"
        if metadata_entry not in names:
            errors.append(f"{path.name}: missing {metadata_entry}")
        else:
            metadata = parse_metadata(archive.read(metadata_entry).decode("utf-8"))
            if metadata.get("Name") != distribution:
                errors.append(f"{path.name}: METADATA Name {metadata.get('Name')} is not {distribution}")
            if metadata.get("Version") != expected_version:
                errors.append(f"{path.name}: METADATA Version {metadata.get('Version')} is not {expected_version}")
            if metadata.get("Requires-Python") != rules["python-requires"]:
                errors.append(
                    f"{path.name}: METADATA Requires-Python {metadata.get('Requires-Python')} "
                    f"is not {rules['python-requires']}"
                )
            if not metadata.get("License-Expression"):
                errors.append(f"{path.name}: METADATA declares no License-Expression")
            if not metadata.get("License-File"):
                errors.append(f"{path.name}: METADATA declares no License-File")
            required = [
                requirement for requirement in metadata.get_all("Requires-Dist") or [] if "extra ==" not in requirement
            ]
            if required:
                errors.append(f"{path.name}: the runtime must have no dependency, found {required}")
            if not (metadata.get_payload() or "").strip():
                errors.append(f"{path.name}: METADATA carries no long description")

        # Exactly the importable package, its typing markers, and one abi3
        # extension. Anything else -- a second native module, a test, a stray
        # source file -- would be shipping something the contract does not name.
        #
        # The one addition is `<distribution>.libs/`: repairing a Linux wheel
        # copies in each non-system shared library the extension links against
        # and rewrites its RPATH, which is how a manylinux or musllinux wheel
        # becomes self-contained. On this build that is libgcc_s for musl. It
        # is a repair artifact, so it may only appear on a Linux wheel and may
        # only hold shared objects.
        payload = [name for name in names if not name.startswith(f"{dist_info}/")]
        libs = f"{normalized(distribution)}.libs/"
        vendored = [name for name in payload if name.startswith(libs)]
        payload = [name for name in payload if not name.startswith(libs)]
        if vendored:
            if not platform.startswith(("manylinux", "musllinux")):
                errors.append(f"{path.name}: only a repaired Linux wheel may vendor libraries, found {vendored}")
            stray_libs = [name for name in vendored if ".so" not in name]
            if stray_libs:
                errors.append(f"{path.name}: {libs} may only hold shared objects, found {stray_libs}")
            print(f"{path.name}: vendors {', '.join(name[len(libs) :] for name in vendored)}")
        natives = [name for name in payload if name.endswith((".so", ".pyd", ".dylib"))]
        # maturin names the limited-API extension `_native.abi3.so` everywhere
        # but Windows, where the suffix is a plain `.pyd`; there the abi3 claim
        # rests on the filename and WHEEL tags checked above. The expected name
        # follows from the platform tag, so a wheel carrying the wrong
        # platform's extension is a mismatch rather than an accepted variant.
        expected_native = (
            f"{import_name}/_native.pyd" if platform.startswith("win") else f"{import_name}/_native.abi3.so"
        )
        if natives != [expected_native]:
            errors.append(f"{path.name}: expected exactly {[expected_native]}, found {natives}")
        expected_payload = sorted(
            [expected_native, f"{import_name}/__init__.py", f"{import_name}/_native.pyi", f"{import_name}/py.typed"]
        )
        if payload != expected_payload:
            errors.append(f"{path.name}: contents {payload} are not {expected_payload}")
        stray = [name for name in names if "test" in name.lower().split("/")[0]]
        if stray:
            errors.append(f"{path.name}: ships test files {stray}")

    return errors


def inspect_sdist(path: Path, rules: dict) -> list[str]:
    """The source distribution carries a buildable workspace and no tests."""
    errors: list[str] = []
    distribution = rules["python-distribution"]
    import_name = rules["python-import-name"]
    expected_version = pep440_version(workspace_version())
    prefix = f"{normalized(distribution)}-{expected_version}"

    if path.name != f"{prefix}.tar.gz":
        errors.append(f"{path.name}: expected {prefix}.tar.gz")
    with tarfile.open(path) as archive:
        names = sorted(archive.getnames())
    relative = [name[len(prefix) + 1 :] for name in names if name.startswith(f"{prefix}/")]
    if len(relative) != len(names):
        errors.append(f"{path.name}: entries outside {prefix}/")

    required = [
        "Cargo.lock",
        "Cargo.toml",
        "PKG-INFO",
        "pyproject.toml",
        "bindings/python/Cargo.toml",
        "bindings/python/src/lib.rs",
        f"python/{import_name}/__init__.py",
        f"python/{import_name}/_native.pyi",
        f"python/{import_name}/py.typed",
    ]
    for entry in required:
        if entry not in relative:
            errors.append(f"{path.name}: missing {entry}")
    # The core crate has to travel with it; a path dependency cannot be
    # resolved from a registry.
    if not any(name.startswith("crates/secret-scan-core/src/") for name in relative):
        errors.append(f"{path.name}: does not vendor the core crate it builds against")
    # The Python tests read the repository's conformance corpus, which is not
    # here, so shipping them would ship a suite that cannot run.
    tests = [name for name in relative if "/tests/" in name or name.startswith("tests/")]
    if tests:
        errors.append(f"{path.name}: ships tests that cannot run from a source distribution: {tests}")
    return errors


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    echo = [argument if len(argument) < 60 else f"{argument[:57]}..." for argument in command]
    print(f"$ {' '.join(echo)}", flush=True)
    return subprocess.run(command, text=True, **kwargs)


def create_environment(directory: Path, base_python: str | None) -> Path:
    """A throwaway virtual environment, and the interpreter inside it."""
    if base_python is None or Path(base_python).resolve() == Path(sys.executable).resolve():
        venv.EnvBuilder(with_pip=True, clear=True).create(directory)
    else:
        run([base_python, "-m", "venv", "--clear", str(directory)], check=True)
    scheme = "nt" if os.name == "nt" else "posix_prefix"
    binaries = Path(sysconfig.get_path("scripts", scheme, vars={"base": str(directory)}))
    interpreter = binaries / ("python.exe" if os.name == "nt" else "python")
    if not interpreter.is_file():
        raise RuntimeError(f"no interpreter at {interpreter}")
    return interpreter


def qualify_wheel(path: Path, rules: dict, pythons: list[str | None], conformance: bool) -> list[str]:
    """Install the wheel and run it, once per requested interpreter."""
    errors: list[str] = []
    for base_python in pythons:
        with tempfile.TemporaryDirectory(prefix="redact-secret-qualify-") as scratch:
            root = Path(scratch)
            try:
                interpreter = create_environment(root / "venv", base_python)
            except (subprocess.CalledProcessError, RuntimeError) as error:
                errors.append(f"{path.name}: could not create an environment for {base_python}: {error}")
                continue

            version = run(
                [str(interpreter), "-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
                capture_output=True,
            ).stdout.strip()

            # No index, no dependency, and no source fallback: an install that
            # succeeds here needed neither the network nor a Rust toolchain.
            install = run(
                [
                    str(interpreter),
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    "--no-deps",
                    "--only-binary",
                    ":all:",
                    "--disable-pip-version-check",
                    str(path),
                ],
                capture_output=True,
            )
            if install.returncode != 0:
                errors.append(f"{path.name}: does not install on CPython {version}\n{install.stderr.strip()}")
                continue

            # Run from outside the repository so nothing resolves from source.
            smoke = run(
                [str(interpreter), "-c", SMOKE.format(version=workspace_version())],
                cwd=scratch,
                capture_output=True,
            )
            if smoke.returncode != 0:
                errors.append(f"{path.name}: smoke test failed on CPython {version}\n{smoke.stderr.strip()}")
                continue
            print(f"{path.name}: CPython {version} {smoke.stdout.strip()}")

            if conformance:
                errors.extend(run_conformance(path, interpreter, version))
    return errors


def run_conformance(path: Path, interpreter: Path, version: str) -> list[str]:
    """The repository's Python suite, against the installed wheel.

    The suite lives in the repository because it reads the shared
    ``conformance/`` corpus, but it imports ``redact_secret`` like any consumer,
    so running it here exercises the artifact rather than the source tree.
    """
    install = run(
        [str(interpreter), "-m", "pip", "install", "--disable-pip-version-check", "pytest>=8"],
        capture_output=True,
    )
    if install.returncode != 0:
        return [f"{path.name}: could not install pytest for the conformance run\n{install.stderr.strip()}"]
    # The suite runs from the repository, and `bindings/python/python/` sits
    # beside it. Prove the interpreter resolves `redact_secret` to the installed
    # wheel before trusting what the suite reports.
    located = run(
        [str(interpreter), "-c", "import redact_secret; print(redact_secret.__file__)"],
        cwd=str(ROOT),
        capture_output=True,
    )
    # Resolve both sides: on macOS a temporary directory is reached as /var/...
    # and reported as /private/var/..., which is the same directory.
    environment = interpreter.parent.parent.resolve()
    resolved = Path(located.stdout.strip()).resolve() if located.returncode == 0 else None
    if resolved is None or environment not in resolved.parents:
        return [f"{path.name}: the conformance run would import {resolved} instead of the installed wheel"]

    result = run(
        [str(interpreter), "-m", "pytest", "-q", str(BINDING / "tests")],
        cwd=str(ROOT),
        capture_output=True,
    )
    print(result.stdout.strip())
    if result.returncode != 0:
        return [f"{path.name}: the conformance suite failed on CPython {version}\n{result.stderr.strip()}"]
    return []


def without_rust(root: Path) -> dict[str, str]:
    """A copy of this environment with every route to a Rust toolchain removed."""
    environment = dict(os.environ)
    environment["MATURIN_NO_INSTALL_RUST"] = "1"
    environment["PATH"] = os.pathsep.join(
        entry
        for entry in environment.get("PATH", "").split(os.pathsep)
        if entry and not shutil.which("cargo", path=entry)
    )
    # cargo is also reachable through these, not only through PATH.
    for name in ("CARGO", "RUSTC", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN"):
        environment.pop(name, None)
    home = root / "home"
    home.mkdir(exist_ok=True)
    environment["HOME"] = str(home)
    environment["USERPROFILE"] = str(home)
    environment["CARGO_HOME"] = str(root / "cargo")
    return environment


def install_sdist(interpreter: Path, path: Path, rules: dict, env: dict[str, str] | None):
    """Install the source distribution, building it.

    Names the distribution rather than `:all:`: `:all:` would also force
    maturin itself to build from source, and maturin's own source build
    bootstraps a Rust toolchain -- which would make a no-toolchain assertion
    pass for a reason that has nothing to do with the artifact under test.
    """
    return run(
        [
            str(interpreter),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-binary",
            rules["python-distribution"],
            str(path),
        ],
        capture_output=True,
        env=env,
    )


def qualify_sdist(path: Path, rules: dict, base_python: str | None, build: bool) -> list[str]:
    """Check the documented no-toolchain behavior, and optionally the build.

    Without a toolchain the backend downloads one, so this pins the opt-out
    that an environment which must not fetch one relies on: with
    `MATURIN_NO_INSTALL_RUST=1` and no cargo, the failure has to name cargo.
    """
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="redact-secret-sdist-") as scratch:
        root = Path(scratch)
        try:
            interpreter = create_environment(root / "venv", base_python)
        except (subprocess.CalledProcessError, RuntimeError) as error:
            return [f"{path.name}: could not create an environment: {error}"]

        result = install_sdist(interpreter, path, rules, without_rust(root))
        if result.returncode == 0:
            errors.append(f"{path.name}: built without a Rust toolchain even with MATURIN_NO_INSTALL_RUST=1")
        else:
            output = result.stdout + result.stderr
            if CARGO_FAILURE.search(output):
                print(f"{path.name}: fails clearly without a Rust toolchain, as documented")
            else:
                errors.append(f"{path.name}: failed without naming cargo, so the cause is not clear:\n{output.strip()}")

    if not build:
        return errors

    # The other branch: with a toolchain the archive has to build on its own,
    # which is only true if it vendored everything the workspace path
    # dependencies point at.
    if shutil.which("cargo") is None:
        return errors + [f"{path.name}: --build-sdist needs cargo on PATH"]
    with tempfile.TemporaryDirectory(prefix="redact-secret-sdist-build-") as scratch:
        root = Path(scratch)
        try:
            interpreter = create_environment(root / "venv", base_python)
        except (subprocess.CalledProcessError, RuntimeError) as error:
            return errors + [f"{path.name}: could not create an environment: {error}"]

        result = install_sdist(interpreter, path, rules, None)
        if result.returncode != 0:
            return errors + [
                f"{path.name}: does not build with a Rust toolchain\n{(result.stdout + result.stderr).strip()}"
            ]
        smoke = run(
            [str(interpreter), "-c", SMOKE.format(version=workspace_version())],
            cwd=scratch,
            capture_output=True,
        )
        if smoke.returncode != 0:
            return errors + [f"{path.name}: the source build failed its smoke test\n{smoke.stderr.strip()}"]
        print(f"{path.name}: builds with a Rust toolchain and {smoke.stdout.strip()}")
    return errors


def check_matrix(artifacts: list[Path], rules: dict) -> list[str]:
    """Exactly one wheel per declared target, and one source distribution.

    A release candidate has to qualify the whole matrix, so a build that
    quietly stopped producing a platform is a failure here rather than a
    missing wheel someone notices on the index.
    """
    declared = list(rules["python-wheel-targets"])
    found: dict[str, list[str]] = {target: [] for target in declared}
    for artifact in artifacts:
        if not artifact.name.endswith(".whl"):
            continue
        match = WHEEL_NAME.match(artifact.name)
        if not match:
            continue
        for target in CHECK.targets_for_platform(match.group("platform"), declared):
            found[target].append(artifact.name)

    errors = [
        f"wheel matrix: no wheel for {target}"
        if not names
        else f"wheel matrix: {len(names)} wheels for {target}: {names}"
        for target, names in found.items()
        if len(names) != 1
    ]
    if not any(artifact.name.endswith(".tar.gz") for artifact in artifacts):
        errors.append("wheel matrix: no source distribution")
    if not errors:
        print(f"wheel matrix: one wheel for each of {len(declared)} targets, plus a source distribution")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("artifacts", nargs="+", type=Path, help="wheels and source distributions to qualify")
    parser.add_argument(
        "--python",
        action="append",
        dest="pythons",
        metavar="EXECUTABLE",
        help="interpreter to qualify a wheel against; repeatable, defaults to this one",
    )
    parser.add_argument("--inspect-only", action="store_true", help="check contents and metadata, install nothing")
    parser.add_argument(
        "--build-sdist",
        action="store_true",
        help="also build a source distribution with this host's Rust toolchain and smoke-test the result",
    )
    parser.add_argument(
        "--require-matrix",
        action="store_true",
        help="also require exactly one wheel per declared target and one source distribution",
    )
    parser.add_argument(
        "--conformance",
        action="store_true",
        help="also run the repository's Python suite against each installed wheel",
    )
    args = parser.parse_args()

    rules = policy()
    if not rules:
        print("ERROR Cargo.toml: missing [workspace.metadata.redact-secret] policy")
        return 1

    pythons: list[str | None] = list(args.pythons) if args.pythons else [None]
    errors: list[str] = []
    wheels = sdists = 0
    for artifact in args.artifacts:
        if not artifact.is_file():
            errors.append(f"{artifact}: not a file")
        elif artifact.name.endswith(".whl"):
            wheels += 1
            found = inspect_wheel(artifact, rules)
            errors.extend(found)
            if not found and not args.inspect_only:
                errors.extend(qualify_wheel(artifact, rules, pythons, args.conformance))
        elif artifact.name.endswith(".tar.gz"):
            sdists += 1
            found = inspect_sdist(artifact, rules)
            errors.extend(found)
            if not found and not args.inspect_only:
                errors.extend(qualify_sdist(artifact, rules, pythons[0], args.build_sdist))
        else:
            errors.append(f"{artifact}: not a wheel or a source distribution")

    if args.require_matrix:
        errors.extend(check_matrix(args.artifacts, rules))

    for error in errors:
        print(f"ERROR {error}")
    print(f"Python artifact qualification complete: {wheels} wheel(s), {sdists} sdist(s), {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
