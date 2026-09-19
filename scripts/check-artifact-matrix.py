#!/usr/bin/env python3
"""Enforce the cross-platform qualification matrix declared in Cargo.toml.

``[workspace.metadata.redact-secret]`` states, once, every platform and engine
the product is qualified on. This script fails when any of the places that
have to agree with it drifts, so a supported platform cannot be added or
dropped in one file alone.

In the style of ``check-python-package.py``'s ``check_wheel_matrix``: a
declared list and the workflow that consumes it must name exactly the same
entries, in both directions.

Checks, in order:

1. Node addon matrix: ``node-addon-targets`` equals ``napi.targets`` in
   ``bindings/node/package.json``, equals the ``node-addon`` job's matrix in
   ``.github/workflows/artifact-qualification.yml``, and every target maps to
   a platform file name ``scripts/qualify-node-addon.mjs`` knows how to
   verify.
2. CLI release matrix: ``cli-release-targets`` equals the ``cli`` job's
   matrix and the target list in ``scripts/qualify-cli-binary.mjs``. It is a
   subset of the addon's: the CLI ships no musl variant.
3. Node publish matrix: ``node-publish-targets`` (a subset of
   ``node-addon-targets``) equals the platform directories under
   ``bindings/node/npm/``, each directory's ``package.json`` ``name``,
   ``packages/javascript/package.json``'s ``optionalDependencies``, the
   package names ``packages/javascript/src/runtime/node.ts`` maps hosts to,
   the release workflow's publish and registry-install matrices, and the
   reconcile workflow's platform map and registry-install matrix — so a
   target cannot gain or lose a publication, repair, or install-verification
   path in one file alone.
4. Browser engines: ``browser-engines`` equals the ``browser`` job's matrix
   and the engine list in ``scripts/qualify-browser-artifact.mjs``.
5. Node.js support: ``node-support-majors`` equals the ``node-version``
   matrix in ``ci.yml`` and the majors the qualification workflow smoke-tests
   the addon on, so an artifact is proved on every major CI claims.
   ``engines.node`` itself belongs to ``check-rust-workspace.py``, which
   derives the exact majors from ``ci.yml``.
6. Least privilege: every workflow declares a top-level ``permissions`` and
   every job declares its own, and no job takes a write scope outside the
   recorded allowlist.
7. Pinning: every ``uses:`` reference to an action outside this repository is
   pinned to a full 40-character commit SHA. A moving tag is a supply-chain
   dependency on whoever can move it.

    python3 -B scripts/check-artifact-matrix.py
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

WORKFLOWS = Path(".github") / "workflows"
WORKFLOW = WORKFLOWS / "artifact-qualification.yml"
RELEASE_WORKFLOW = WORKFLOWS / "release.yml"
RECONCILE_WORKFLOW = WORKFLOWS / "reconcile-release.yml"
# Every job whose matrix names one leg per published native platform package.
NODE_PUBLISH_JOBS = (
    (RELEASE_WORKFLOW, "publish-native-dependencies"),
    (RELEASE_WORKFLOW, "verify-registry-install"),
    (RECONCILE_WORKFLOW, "verify-registry-install"),
)
CI = WORKFLOWS / "ci.yml"
NODE_PACKAGE = Path("bindings") / "node" / "package.json"
NATIVE_NPM_DIR = Path("bindings") / "node" / "npm"
JS_PACKAGE = Path("packages") / "javascript" / "package.json"
RUNTIME_NODE = Path("packages") / "javascript" / "src" / "runtime" / "node.ts"
ADDON_QUALIFIER = Path("scripts") / "qualify-node-addon.mjs"
CLI_QUALIFIER = Path("scripts") / "qualify-cli-binary.mjs"
BROWSER_QUALIFIER = Path("scripts") / "qualify-browser-artifact.mjs"

# The only write scopes any job in this repository is allowed to take, and
# the job that may take each. `Release` needs `contents: write` to create the
# annotated tag its own workflow documents, and `id-token: write` for PyPI
# Trusted Publishing, which mints a short-lived OIDC token instead of holding
# a long-lived API token as a secret. Every other job is read-only.
WRITE_SCOPE_ALLOWLIST = {
    ("release.yml", "tag-release", "contents"),
    ("release.yml", "publish-pypi", "id-token"),
    ("reconcile-release.yml", "reconcile", "contents"),
    ("reconcile-release.yml", "tag-reconciled-release", "contents"),
    ("reconcile-release.yml", "reconcile", "id-token"),
    # Issue #156: scoped solely to the best-effort SARIF upload step; the
    # gate itself (the scan's own exit code) needs no more than contents:
    # read, and code-scanning upload availability is never the enforcement
    # signal.
    ("sast.yml", "opengrep", "security-events"),
}

# A named top-level job block: `  <job-name>:` through the line before the
# next top-level job (or end of file). Workflow jobs are two-space indented
# directly under `jobs:`; everything inside a job is indented at least three
# spaces (or blank), so the body stops exactly at the next two-space job
# header instead of swallowing it.
JOB_BLOCK = re.compile(r"^  (?P<name>[A-Za-z][\w-]*):\n(?P<body>(?:[ \t]{3,}.*\n|[ \t]*\n)*)", re.M)

# A matrix key either carries its value inline, as `- target: <triple>` in an
# `include:` entry, or introduces a block sequence of bare values.
MATRIX_INLINE = "^[ \t]*(?:-[ \t]+)?{key}:[ \t]*(\\S+)[ \t]*$"
MATRIX_BLOCK = "^[ \t]*{key}:[ \t]*(?:#.*)?$((?:\n[ \t]*(?:#.*)?$|\n[ \t]*-[ \t]*\\S+[ \t]*$)*)"
MATRIX_ITEM = re.compile(r"^[ \t]*-[ \t]*(\S+)[ \t]*$", re.M)

# A `uses:` value: either a local path (`./.github/...`) or `owner/repo@ref`.
USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)\s*$", re.M)
PINNED = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
# One `[<platform>]=<target>` entry of the reconcile job's `PLATFORM_TARGETS`.
PLATFORM_TARGET = re.compile(r"^\s*\[([a-z0-9-]+)\]=([a-z0-9_]+-[a-z0-9_-]+)\s*$", re.M)
TOP_LEVEL_PERMISSIONS = re.compile(r"^permissions:(?P<inline>[^\n]*)$", re.M)
JOB_PERMISSION = re.compile(r"^\s{6}(?P<scope>[a-z-]+):\s*(?P<level>\S+)\s*$", re.M)


def matrix_values(text: str, key: str) -> list[str]:
    """Every value of a matrix key, whether it carries its value inline or
    introduces a sequence."""
    quoted = re.escape(key)
    values = re.findall(MATRIX_INLINE.format(key=quoted), text, re.M)
    for block in re.findall(MATRIX_BLOCK.format(key=quoted), text, re.M):
        values.extend(MATRIX_ITEM.findall(block))
    return values


def job_body(workflow_text: str, job_name: str) -> str | None:
    """One job's body, or ``None`` when the workflow has no such job."""
    for match in JOB_BLOCK.finditer(workflow_text):
        if match.group("name") == job_name:
            return match.group("body")
    return None


def read_text(root: Path, path: Path) -> str | None:
    resolved = root / path
    return resolved.read_text(encoding="utf-8") if resolved.is_file() else None


def read_json(root: Path, path: Path) -> dict | None:
    text = read_text(root, path)
    return json.loads(text) if text is not None else None


def load_policy(root: Path) -> dict:
    with (root / "Cargo.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    return manifest.get("workspace", {}).get("metadata", {}).get("redact-secret", {})


def compare(label: str, declared, found, where: str) -> list[str]:
    """Both directions, so neither side can quietly gain or lose an entry."""
    errors = []
    missing = sorted(set(declared) - set(found))
    extra = sorted(set(found) - set(declared))
    if missing:
        errors.append(f"{where}: {label} omits {', '.join(missing)}")
    if extra:
        errors.append(
            f"{where}: {label} names {', '.join(extra)}, which Cargo.toml does not declare"
        )
    return errors


def check_job_matrix(
    *, label: str, declared: list[str], workflow: str, job_name: str, key: str,
    path: Path = WORKFLOW,
) -> list[str]:
    body = job_body(workflow, job_name)
    if body is None:
        return [f"{path.as_posix()}: missing job {job_name!r}"]
    return compare(
        f"job {job_name!r}'s {key} matrix",
        declared,
        matrix_values(body, key),
        path.as_posix(),
    )


def check_addon_targets(root: Path, policy: dict, workflow: str) -> list[str]:
    declared = policy.get("node-addon-targets") or []
    if not declared:
        return ["Cargo.toml: node-addon-targets must declare the addon matrix"]

    errors: list[str] = []
    manifest = read_json(root, NODE_PACKAGE)
    if manifest is None:
        errors.append(f"{NODE_PACKAGE.as_posix()}: missing")
    else:
        errors.extend(
            compare(
                "napi.targets",
                declared,
                manifest.get("napi", {}).get("targets", []),
                NODE_PACKAGE.as_posix(),
            )
        )

    errors.extend(
        check_job_matrix(
            label="addon", declared=declared, workflow=workflow,
            job_name="node-addon", key="target",
        )
    )

    qualifier = read_text(root, ADDON_QUALIFIER)
    if qualifier is None:
        errors.append(f"{ADDON_QUALIFIER.as_posix()}: missing")
    else:
        known = re.findall(r'^\s*"([a-z0-9_]+-[a-z0-9-]+)":\s*"', qualifier, re.M)
        for target in sorted(set(declared) - set(known)):
            errors.append(
                f"{ADDON_QUALIFIER.as_posix()}: no platform file name for {target}"
            )
    return errors


def platform_names(qualifier_text: str) -> dict[str, str]:
    """The triple-to-platform-directory-name mapping
    ``scripts/qualify-node-addon.mjs`` declares as ``TARGET_PLATFORM_NAMES``,
    e.g. ``"x86_64-unknown-linux-gnu": "linux-x64-gnu"`` — the same names
    ``bindings/node/npm/<platform>/`` directories and
    ``@redact-secret/node-<platform>`` package names use, so every check
    below is keyed off the one place that mapping is spelled out."""
    return dict(re.findall(r'"([a-z0-9_]+-[a-z0-9-]+)":\s*"([a-z0-9-]+)"', qualifier_text))


def check_node_publish_targets(root: Path, policy: dict) -> list[str]:
    declared = policy.get("node-publish-targets") or []
    if not declared:
        return ["Cargo.toml: node-publish-targets must declare the published platform-package matrix"]

    errors: list[str] = []
    addon = policy.get("node-addon-targets") or []
    for extra in sorted(set(declared) - set(addon)):
        errors.append(
            f"Cargo.toml: node-publish-targets names {extra}, which "
            "node-addon-targets does not"
        )

    qualifier = read_text(root, ADDON_QUALIFIER)
    if qualifier is None:
        return errors + [f"{ADDON_QUALIFIER.as_posix()}: missing"]
    names = platform_names(qualifier)
    for target in sorted(set(declared) - set(names)):
        errors.append(f"{ADDON_QUALIFIER.as_posix()}: no platform file name for {target}")
    expected_platforms = {names[target] for target in declared if target in names}
    expected_packages = {f"@redact-secret/node-{platform}" for platform in expected_platforms}

    directory = root / NATIVE_NPM_DIR
    found_platforms = (
        {child.name for child in directory.iterdir() if child.is_dir()} if directory.is_dir() else set()
    )
    errors.extend(compare("published platform packages", expected_platforms, found_platforms, NATIVE_NPM_DIR.as_posix()))
    for platform in sorted(expected_platforms & found_platforms):
        manifest = read_json(root, NATIVE_NPM_DIR / platform / "package.json")
        expected_name = f"@redact-secret/node-{platform}"
        if manifest is None:
            errors.append(f"{(NATIVE_NPM_DIR / platform / 'package.json').as_posix()}: missing or invalid")
        elif manifest.get("name") != expected_name:
            errors.append(
                f"{(NATIVE_NPM_DIR / platform / 'package.json').as_posix()}: name "
                f"{manifest.get('name')!r} must be {expected_name!r}"
            )

    js_manifest = read_json(root, JS_PACKAGE)
    if js_manifest is None:
        errors.append(f"{JS_PACKAGE.as_posix()}: missing")
    else:
        errors.extend(
            compare(
                "optionalDependencies",
                expected_packages,
                (js_manifest.get("optionalDependencies") or {}).keys(),
                JS_PACKAGE.as_posix(),
            )
        )

    runtime = read_text(root, RUNTIME_NODE)
    if runtime is None:
        errors.append(f"{RUNTIME_NODE.as_posix()}: missing")
    else:
        referenced = set(re.findall(r'"(@redact-secret/node-[a-z0-9-]+)"', runtime))
        errors.extend(compare("the platform-package mapping", expected_packages, referenced, RUNTIME_NODE.as_posix()))

    for path, job_name in NODE_PUBLISH_JOBS:
        workflow = read_text(root, path)
        if workflow is None:
            errors.append(f"{path.as_posix()}: missing workflow")
            continue
        errors.extend(
            check_job_matrix(
                label="publish", declared=declared, workflow=workflow,
                job_name=job_name, key="target", path=path,
            )
        )

    reconcile = read_text(root, RECONCILE_WORKFLOW)
    body = job_body(reconcile, "reconcile") if reconcile is not None else None
    if body is not None:
        expected_pairs = {f"{names[target]}={target}" for target in declared if target in names}
        found_pairs = {f"{platform}={target}" for platform, target in PLATFORM_TARGET.findall(body)}
        errors.extend(
            compare("job 'reconcile''s PLATFORM_TARGETS", expected_pairs, found_pairs, RECONCILE_WORKFLOW.as_posix())
        )
    elif reconcile is not None:
        errors.append(f"{RECONCILE_WORKFLOW.as_posix()}: missing job 'reconcile'")

    return errors


def check_cli_targets(root: Path, policy: dict, workflow: str) -> list[str]:
    declared = policy.get("cli-release-targets") or []
    if not declared:
        return ["Cargo.toml: cli-release-targets must declare the CLI matrix"]

    errors = check_job_matrix(
        label="cli", declared=declared, workflow=workflow, job_name="cli", key="target",
    )
    # The CLI ships no musl variant, so its matrix is a subset of the
    # addon's; an entry here that the addon does not build is a mistake.
    addon = policy.get("node-addon-targets") or []
    for extra in sorted(set(declared) - set(addon)):
        errors.append(
            f"Cargo.toml: cli-release-targets names {extra}, which "
            "node-addon-targets does not"
        )

    qualifier = read_text(root, CLI_QUALIFIER)
    if qualifier is None:
        errors.append(f"{CLI_QUALIFIER.as_posix()}: missing")
    else:
        known = re.findall(r'^\s*"([a-z0-9_]+-[a-z0-9-]+)":\s*"', qualifier, re.M)
        for target in sorted(set(declared) - set(known)):
            errors.append(f"{CLI_QUALIFIER.as_posix()}: its target list omits {target}")
    return errors


def check_browser_engines(root: Path, policy: dict, workflow: str) -> list[str]:
    declared = policy.get("browser-engines") or []
    if not declared:
        return ["Cargo.toml: browser-engines must declare the browser matrix"]

    errors = check_job_matrix(
        label="browser", declared=declared, workflow=workflow,
        job_name="browser", key="engine",
    )
    errors.extend(
        check_job_matrix(
            label="installed browser package",
            declared=declared,
            workflow=workflow,
            job_name="package-consumer-browser",
            key="engine",
        )
    )
    qualifier = read_text(root, BROWSER_QUALIFIER)
    if qualifier is None:
        errors.append(f"{BROWSER_QUALIFIER.as_posix()}: missing")
    else:
        match = re.search(r"const ENGINES = \[(.*?)\];", qualifier, re.S)
        known = re.findall(r'"([a-z]+)"', match.group(1)) if match else []
        errors.extend(compare("ENGINES", declared, known, BROWSER_QUALIFIER.as_posix()))
    return errors


def check_node_support(root: Path, policy: dict, workflow: str) -> list[str]:
    declared = policy.get("node-support-majors") or []
    if not declared:
        return ["Cargo.toml: node-support-majors must declare the supported majors"]
    declared_strings = [str(major) for major in declared]

    errors: list[str] = []
    ci = read_text(root, CI)
    if ci is None:
        errors.append(f"{CI.as_posix()}: missing")
    else:
        errors.extend(
            compare(
                "the node-version matrix",
                declared_strings,
                matrix_values(ci, "node-version"),
                CI.as_posix(),
            )
        )

    # Every major the addon is smoke-tested on, from the per-major steps on a
    # host runner and from the musl loop that mirrors them.
    smoked = re.findall(r"^\s*- name: Qualify the addon on Node (\d+)\s*$", workflow, re.M)
    musl = re.search(r"^\s*for major in ([\d ]+); do\s*$", workflow, re.M)
    errors.extend(
        compare(
            "the addon smoke-test majors", declared_strings, smoked, WORKFLOW.as_posix()
        )
    )
    errors.extend(
        compare(
            "the musl smoke-test majors",
            declared_strings,
            musl.group(1).split() if musl else [],
            WORKFLOW.as_posix(),
        )
    )
    errors.extend(
        check_job_matrix(
            label="installed Node package",
            declared=declared_strings,
            workflow=workflow,
            job_name="package-consumer-node",
            key="node-version",
        )
    )

    # `engines.node` itself is checked by `scripts/check-rust-workspace.py`,
    # which derives the exact majors from `ci.yml` and requires every
    # lockstep manifest to enumerate them. Repeating that here with a
    # different spelling would let the two checks contradict each other.
    return errors


def check_workflow_hygiene(root: Path) -> list[str]:
    errors: list[str] = []
    directory = root / WORKFLOWS
    if not directory.is_dir():
        return [f"{WORKFLOWS.as_posix()}: missing"]

    for path in sorted(directory.glob("*.yml")):
        name = path.name
        text = path.read_text(encoding="utf-8")
        relative = (WORKFLOWS / name).as_posix()

        top_level = TOP_LEVEL_PERMISSIONS.search(text)
        if top_level is None:
            errors.append(f"{relative}: declares no top-level permissions")
        elif top_level.group("inline").strip() == "write-all":
            errors.append(f"{relative}: grants write-all at the top level")

        for match in JOB_BLOCK.finditer(text[text.find("\njobs:\n") :]):
            job_name, body = match.group("name"), match.group("body")
            declaration = re.search(
                r"^    permissions:(?P<inline>[^\n]*)$(?P<scopes>(?:\n\s{6}\S.*)*)",
                body,
                re.M,
            )
            if declaration is None:
                errors.append(f"{relative}: job {job_name!r} declares no permissions")
                continue
            inline = declaration.group("inline").strip()
            if inline in ("write-all", "read-all") or inline.startswith("$"):
                errors.append(
                    f"{relative}: job {job_name!r} declares permissions as {inline!r}; "
                    "state each scope it needs instead"
                )
                continue
            for scope, level in JOB_PERMISSION.findall(declaration.group("scopes")):
                if level != "write":
                    continue
                if (name, job_name, scope) not in WRITE_SCOPE_ALLOWLIST:
                    errors.append(
                        f"{relative}: job {job_name!r} takes {scope}: write, "
                        "which the least-privilege allowlist does not permit"
                    )

        for reference in USES.findall(text):
            if reference.startswith("./"):
                continue
            if not PINNED.match(reference):
                errors.append(
                    f"{relative}: uses {reference}, which is not pinned to a commit SHA"
                )
    return errors


def validate(root: Path) -> list[str]:
    root = root.resolve()
    policy = load_policy(root)
    if not policy:
        return ["Cargo.toml: missing [workspace.metadata.redact-secret] policy"]

    workflow = read_text(root, WORKFLOW)
    if workflow is None:
        return [f"{WORKFLOW.as_posix()}: missing workflow"]

    errors: list[str] = []
    errors.extend(check_addon_targets(root, policy, workflow))
    errors.extend(check_node_publish_targets(root, policy))
    errors.extend(check_cli_targets(root, policy, workflow))
    errors.extend(check_browser_engines(root, policy, workflow))
    errors.extend(check_node_support(root, policy, workflow))
    errors.extend(check_workflow_hygiene(root))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", default=Path(__file__).resolve().parents[1], type=Path)
    args = parser.parse_args()

    errors = validate(args.root)
    for error in errors:
        print(f"ERROR {error}")
    print(f"Artifact matrix check complete: {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
