#!/usr/bin/env python3
"""Report what `pip install` actually placed in a clean-install project, and
which candidate wheel it came from (issues #586, #687).

`scripts/qualify-clean-install.mjs` runs this file's source through the
candidate virtual environment's interpreter (`python -c`) with the candidate
wheel paths as arguments, then asserts on the JSON it prints. It lives here,
rather than inline in that runner, so the wheel-selection rule can be unit
tested without a built wheel or a virtual environment: only `probe()` needs
the installed distribution, and only `main()` imports it.

Wheel filenames carry a *compressed tag set* -- PEP 425 joins each of the
interpreter, ABI, and platform components with `.` -- while the installed
distribution's `WHEEL` metadata expands that set into one `Tag:` line per
combination. A manylinux wheel is the common case where the two spellings
differ:

    redact_secret-0.1.0b6-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

    Tag: cp310-abi3-manylinux_2_17_x86_64
    Tag: cp310-abi3-manylinux2014_x86_64

Matching a `Tag:` line against the end of the filename therefore fails for
exactly the artifacts that carry more than one tag, which is why the Linux
lane -- and only the Linux lane -- reported "the installed wheel is not one
of the candidate wheels" on every run before #687. Selection expands the
filename's tag set instead and intersects it with the installed tags.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys


def wheel_file_tags(name: str) -> set[str]:
    """Every `{python}-{abi}-{platform}` tag a wheel filename declares.

    Returns an empty set for a name that is not a wheel filename, so a stray
    file in the candidate directory can never match an installed tag.
    """
    if not name.endswith(".whl"):
        return set()
    parts = name[: -len(".whl")].split("-")
    # name-version(-build)?-python-abi-platform
    if len(parts) < 5:
        return set()
    python, abi, platform = parts[-3], parts[-2], parts[-1]
    return {
        f"{one}-{two}-{three}"
        for one in python.split(".")
        for two in abi.split(".")
        for three in platform.split(".")
    }


def select_wheel(installed_tags: list[str], names: list[str]) -> str | None:
    """The first candidate filename whose tag set covers an installed tag."""
    wanted = set(installed_tags)
    return next((name for name in names if wanted & wheel_file_tags(name)), None)


def installed_tags(wheel_metadata: str) -> list[str]:
    """The `Tag:` values of an installed distribution's `WHEEL` metadata."""
    return [
        line.split(": ", 1)[1]
        for line in wheel_metadata.splitlines()
        if line.startswith("Tag: ")
    ]


def probe(wheel_paths: list[str]) -> dict:
    """Describe the installed `redact-secret` against the candidate wheels."""
    import sysconfig
    import zipfile
    import importlib.metadata as metadata

    dist = metadata.distribution("redact-secret")
    site = pathlib.Path(sysconfig.get_paths()["purelib"]).resolve()
    tags = installed_tags(dist.read_text("WHEEL") or "")
    wheels = [pathlib.Path(path) for path in wheel_paths]
    selected = select_wheel(tags, [wheel.name for wheel in wheels])
    wheel = next((wheel for wheel in wheels if wheel.name == selected), None)

    mismatched: list[str] = []
    count = 0
    if wheel is not None:
        with zipfile.ZipFile(wheel) as archive:
            for member in archive.namelist():
                if member.endswith("/") or member.endswith(".dist-info/RECORD"):
                    continue
                count += 1
                installed = site / member
                if (
                    not installed.is_file()
                    or hashlib.sha256(installed.read_bytes()).hexdigest()
                    != hashlib.sha256(archive.read(member)).hexdigest()
                ):
                    mismatched.append(member)
    else:
        import base64

        for entry in dist.files or []:
            if entry.hash is None:
                continue
            count += 1
            digest = (
                base64.urlsafe_b64encode(
                    hashlib.new(entry.hash.mode, entry.locate().read_bytes()).digest()
                )
                .rstrip(b"=")
                .decode()
            )
            if digest != entry.hash.value:
                mismatched.append(str(entry))

    import redact_secret
    import redact_secret._native as native

    return {
        "version": dist.version,
        "tags": tags,
        "wheel": wheel.name if wheel else None,
        "files": count,
        "mismatched": mismatched,
        "module": str(pathlib.Path(redact_secret.__file__).resolve()),
        "native": str(pathlib.Path(native.__file__).resolve()),
        "python": sys.version.split()[0],
    }


def main(argv: list[str] | None = None) -> int:
    print(json.dumps(probe(list(sys.argv[1:] if argv is None else argv))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
