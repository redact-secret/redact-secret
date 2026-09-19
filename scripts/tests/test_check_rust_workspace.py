from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check-rust-workspace.py"
SPEC = importlib.util.spec_from_file_location("check_rust_workspace", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)

VERSION = "0.1.0-beta.1"
MSRV = "1.88"
NODE_ENGINES = "20.x || 22.x"

CORE_LIB = """//! # Public surface
//!
//! | Concern | API |
//! | --- | --- |
//! | Scan | [`scan`], [`Finding`] |
//! | Version | [`VERSION`] |

#![forbid(unsafe_code)]

mod types;

pub use types::{Finding, scan};

/// The shared product version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    pub use types::NotPublic;
}
"""
CORE_API = ["Finding", "VERSION", "scan"]
CORE_MANIFEST = '[package]\nname = "redact-secret"\ninclude = ["src/**/*.rs", "README.md"]\n[lints]\nworkspace = true\n'
PACKAGE_GLOBS = ["Cargo.toml", "README.md", "src/**/*.rs"]
PACKAGE_REQUIRED = ["Cargo.toml", "README.md", "src/lib.rs"]
PACKAGE_LIST = ["Cargo.toml", "README.md", "src/lib.rs", "src/detectors/aws.rs"]


def package(root: Path, name: str, relative: str, deps: list[str], rust_version: str | None = MSRV) -> dict:
    return {
        "id": name,
        "name": name,
        "version": VERSION,
        "rust_version": rust_version,
        "manifest_path": str(root / relative / "Cargo.toml"),
        "_deps": deps,
    }


class Workspace:
    """Builds a minimal repository plus matching ``cargo metadata`` output."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.packages: list[dict] = []
        self.members: list[str] = []
        self.dep_kinds: dict[tuple[str, str], list[dict]] = {}
        self.allowed: list[str] = []
        self.forbidden: list[str] = ["reqwest"]
        self.bindings: list[str] = ["napi", "pyo3", "wasm-bindgen"]
        self.public_api: list[str] = list(CORE_API)
        self.package_globs: list[str] = list(PACKAGE_GLOBS)
        self.package_required: list[str] = list(PACKAGE_REQUIRED)
        self.package_list: list[str] = list(PACKAGE_LIST)
        self.write(
            ".github/workflows/ci.yml",
            f'name: CI\nenv:\n  MSRV: "{MSRV}"\njobs:\n  test:\n    strategy:\n      matrix:\n        node-version:\n          - 20\n          - 22\n',
        )
        self.write("package.json", json.dumps({"private": True, "version": VERSION, "engines": {"node": NODE_ENGINES}}))
        self.write("bindings/node/package.json", json.dumps({"version": VERSION, "engines": {"node": NODE_ENGINES}}))
        self.write("packages/javascript/package.json", json.dumps({"version": VERSION, "engines": {"node": NODE_ENGINES}}))
        self.write("bindings/wasm/npm/package.json", json.dumps({"version": VERSION}))
        for platform in ("darwin-arm64", "linux-x64-gnu"):
            self.write(
                f"bindings/node/npm/{platform}/package.json",
                json.dumps({"version": VERSION, "engines": {"node": NODE_ENGINES}}),
            )
        self.add_member("redact-secret", "crates/secret-scan-core", "src/lib.rs", CORE_LIB, manifest=CORE_MANIFEST)
        self.add_member("redact-secret-cli", "crates/secret-scan-cli", "src/main.rs", "#![forbid(unsafe_code)]\n", deps=["redact-secret"])

    def write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def add_member(self, name: str, relative: str, source: str, content: str, deps: list[str] | None = None, lints: str = "[lints]\nworkspace = true\n", manifest: str | None = None) -> None:
        self.write(f"{relative}/Cargo.toml", manifest or f'[package]\nname = "{name}"\n{lints}')
        self.write(f"{relative}/{source}", content)
        self.packages.append(package(self.root, name, relative, deps or []))
        self.members.append(name)

    def add_dependency(self, name: str, rust_version: str | None = None, deps: list[str] | None = None) -> None:
        self.packages.append(package(self.root, name, f"registry/{name}", deps or [], rust_version))

    def metadata(self) -> dict:
        nodes = []
        for entry in self.packages:
            deps = []
            for dep in entry["_deps"]:
                kinds = self.dep_kinds.get((entry["name"], dep), [{"kind": None}])
                deps.append({"name": dep, "pkg": dep, "dep_kinds": kinds})
            nodes.append({"id": entry["id"], "deps": deps})
        unsafe = 'unsafe_code = "deny"'
        self.write(
            "Cargo.toml",
            f'[workspace]\n[workspace.package]\nversion = "{VERSION}"\nrust-version = "{MSRV}"\n'
            f"[workspace.lints.rust]\n{unsafe}\n",
        )
        return {
            "packages": [{key: value for key, value in entry.items() if key != "_deps"} for entry in self.packages],
            "workspace_members": list(self.members),
            "resolve": {"nodes": nodes},
            "metadata": {
                "redact-secret": {
                    "core-package": "redact-secret",
                    "allowed-dependencies": self.allowed,
                    "forbidden-dependencies": self.forbidden,
                    "binding-dependencies": self.bindings,
                    "core-public-api": self.public_api,
                    "core-package-globs": self.package_globs,
                    "core-package-required": self.package_required,
                }
            },
        }


class RustWorkspaceCheckTests(unittest.TestCase):
    def run_check(self, configure=None) -> list[str]:
        with tempfile.TemporaryDirectory() as temp:
            workspace = Workspace(Path(temp))
            if configure is not None:
                configure(workspace)
            return CHECK.validate(
                workspace.root,
                workspace.metadata(),
                lambda _package: workspace.package_list,
            )

    def test_scaffold_passes(self) -> None:
        self.assertEqual(self.run_check(), [])

    def test_unlisted_core_dependency_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.packages[0]["_deps"].append("memchr")
            workspace.add_dependency("memchr")

        errors = self.run_check(configure)
        self.assertTrue(any("memchr is not in allowed-dependencies" in error for error in errors), errors)

    def test_allowed_core_dependency_is_checked_transitively(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.allowed.append("memchr")
            workspace.packages[0]["_deps"].append("memchr")
            workspace.add_dependency("memchr", deps=["libc"])
            workspace.add_dependency("libc")

        errors = self.run_check(configure)
        self.assertTrue(any("libc is not in allowed-dependencies" in error for error in errors), errors)

    def test_forbidden_dependency_is_rejected_even_when_allowed(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.allowed.append("reqwest")
            workspace.packages[0]["_deps"].append("reqwest")
            workspace.add_dependency("reqwest")

        errors = self.run_check(configure)
        self.assertTrue(any("forbidden dependency reqwest" in error for error in errors), errors)

    def test_core_dev_dependencies_are_outside_the_boundary(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.packages[0]["_deps"].append("proptest")
            workspace.dep_kinds[("redact-secret", "proptest")] = [{"kind": "dev"}]
            workspace.add_dependency("proptest")

        self.assertEqual(self.run_check(configure), [])

    def test_cli_may_depend_on_host_crates(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.packages[1]["_deps"].append("clap")
            workspace.add_dependency("clap", rust_version="1.85")

        self.assertEqual(self.run_check(configure), [])

    def test_missing_forbid_unsafe_in_core_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write("crates/secret-scan-core/src/lib.rs", "pub const VERSION: &str = \"x\";\n")

        errors = self.run_check(configure)
        self.assertTrue(any("must contain #![forbid(unsafe_code)]" in error for error in errors), errors)

    def test_member_without_workspace_lints_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.add_member("redact-secret-wasm", "bindings/wasm", "src/lib.rs", "", lints="")

        errors = self.run_check(configure)
        self.assertTrue(any("must set [lints] workspace = true" in error for error in errors), errors)

    def test_private_root_version_drift_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write("package.json", json.dumps({
                "private": True, "version": "0.2.0", "engines": {"node": NODE_ENGINES},
            }))

        errors = self.run_check(configure)
        self.assertEqual(errors, [f"package.json: version 0.2.0 differs from workspace version {VERSION}"])

    def test_node_package_json_drift_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write("bindings/node/package.json", json.dumps({"version": "0.2.0"}))

        errors = self.run_check(configure)
        self.assertTrue(any("bindings/node/package.json: version 0.2.0" in error for error in errors), errors)

    def test_javascript_package_json_drift_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write("packages/javascript/package.json", json.dumps({"version": "0.2.0"}))

        errors = self.run_check(configure)
        self.assertTrue(any("packages/javascript/package.json: version 0.2.0" in error for error in errors), errors)

    def test_a_stale_runtime_package_pin_is_rejected(self) -> None:
        for field in ("dependencies", "optionalDependencies"):
            with self.subTest(field=field):
                def configure(workspace: Workspace, field: str = field) -> None:
                    workspace.write(
                        "packages/javascript/package.json",
                        json.dumps({
                            "version": VERSION,
                            "engines": {"node": NODE_ENGINES},
                            field: {"@redact-secret/wasm": "0.0.1", "unrelated": "1.0.0"},
                        }),
                    )

                errors = self.run_check(configure)
                self.assertEqual(
                    [error for error in errors if "pins" in error],
                    [f"packages/javascript/package.json: {field} pins @redact-secret/wasm to 0.0.1, "
                     f"not workspace version {VERSION}"],
                )

    def test_member_version_drift_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.packages[1]["version"] = "0.2.0"

        errors = self.run_check(configure)
        self.assertTrue(any("redact-secret-cli: version 0.2.0" in error for error in errors), errors)

    def test_dependency_requiring_newer_rust_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.packages[1]["_deps"].append("newer")
            workspace.add_dependency("newer", rust_version="1.90.0")

        errors = self.run_check(configure)
        self.assertTrue(any("MSRV 1.88 is below 1.90.0 required by newer" in error for error in errors), errors)

    def test_equal_dependency_msrv_with_patch_component_passes(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.packages[1]["_deps"].append("same")
            workspace.add_dependency("same", rust_version="1.88.0")

        self.assertEqual(self.run_check(configure), [])

    def test_ci_msrv_must_match_manifest(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write(".github/workflows/ci.yml", 'name: CI\nenv:\n  MSRV: "1.85"\n')

        errors = self.run_check(configure)
        self.assertTrue(any("expected exactly one MSRV: 1.88" in error for error in errors), errors)

    def test_node_engines_narrower_than_ci_matrix_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write(
                "packages/javascript/package.json",
                json.dumps({"version": VERSION, "engines": {"node": "20.x"}}),
            )

        errors = self.run_check(configure)
        self.assertTrue(
            any(
                "packages/javascript/package.json: engines.node '20.x' must be '20.x || 22.x'" in error
                for error in errors
            ),
            errors,
        )

    def test_node_engines_open_ended_range_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write(
                "packages/javascript/package.json",
                json.dumps({"version": VERSION, "engines": {"node": ">=20"}}),
            )

        errors = self.run_check(configure)
        self.assertTrue(
            any(
                "packages/javascript/package.json: engines.node '>=20' must be '20.x || 22.x'" in error
                for error in errors
            ),
            errors,
        )

    def test_node_engines_drift_is_rejected_in_every_lockstep_manifest(self) -> None:
        for relative in (
            "package.json",
            "bindings/node/package.json",
            "packages/javascript/package.json",
            "bindings/node/npm/darwin-arm64/package.json",
        ):

            def configure(workspace: Workspace, relative: str = relative) -> None:
                workspace.write(relative, json.dumps({"version": VERSION, "engines": {"node": "20.x"}}))

            errors = self.run_check(configure)
            self.assertTrue(any(f"{relative}: engines.node" in error for error in errors), errors)

    def test_wasm_package_json_version_drift_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write("bindings/wasm/npm/package.json", json.dumps({"version": "0.2.0"}))

        errors = self.run_check(configure)
        self.assertTrue(
            any("bindings/wasm/npm/package.json: version 0.2.0" in error for error in errors), errors
        )

    def test_wasm_package_json_declares_no_engines_and_is_not_checked(self) -> None:
        """The WebAssembly package ships no `engines.node` claim, so a
        missing `engines` key there must not be flagged the way a native
        platform package's would be."""
        self.assertEqual(self.run_check(), [])

    def test_native_platform_manifest_version_drift_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write(
                "bindings/node/npm/linux-x64-gnu/package.json",
                json.dumps({"version": "0.2.0", "engines": {"node": NODE_ENGINES}}),
            )

        errors = self.run_check(configure)
        self.assertTrue(
            any(
                "bindings/node/npm/linux-x64-gnu/package.json: version 0.2.0" in error
                for error in errors
            ),
            errors,
        )

    def test_a_newly_added_native_platform_manifest_is_covered_without_a_script_change(self) -> None:
        """`native_platform_manifests` discovers directories rather than
        naming them, so adding a third platform package with drifted version
        or engines is caught the same way the first two are."""

        def configure(workspace: Workspace) -> None:
            workspace.write(
                "bindings/node/npm/win32-x64-msvc/package.json",
                json.dumps({"version": "0.2.0", "engines": {"node": NODE_ENGINES}}),
            )

        errors = self.run_check(configure)
        self.assertTrue(
            any(
                "bindings/node/npm/win32-x64-msvc/package.json: version 0.2.0" in error
                for error in errors
            ),
            errors,
        )

    def test_ci_matrix_without_node_versions_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write(".github/workflows/ci.yml", f'name: CI\nenv:\n  MSRV: "{MSRV}"\n')

        errors = self.run_check(configure)
        self.assertTrue(
            any("no Node major versions found" in error for error in errors),
            errors,
        )

    def test_member_msrv_drift_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.packages[1]["rust_version"] = "1.85"

        errors = self.run_check(configure)
        self.assertTrue(any("redact-secret-cli: rust-version 1.85" in error for error in errors), errors)

    # -- public API -------------------------------------------------------

    def test_an_unlisted_export_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write(
                "crates/secret-scan-core/src/lib.rs",
                CORE_LIB.replace("pub use types::{Finding, scan};", "pub use types::{Finding, scan, sneak};"),
            )

        errors = self.run_check(configure)
        self.assertTrue(any("sneak is public but not in core-public-api" in error for error in errors), errors)

    def test_a_removed_export_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.public_api.append("removed")

        errors = self.run_check(configure)
        self.assertTrue(any("core-public-api lists removed" in error for error in errors), errors)

    def test_a_public_module_counts_as_an_export(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write("crates/secret-scan-core/src/lib.rs", CORE_LIB.replace("mod types;", "pub mod types;"))

        errors = self.run_check(configure)
        self.assertTrue(any("types is public but not in core-public-api" in error for error in errors), errors)

    def test_a_test_module_is_not_part_of_the_public_surface(self) -> None:
        self.assertEqual(self.run_check(), [])
        self.assertNotIn("NotPublic", CHECK.exported_names(CORE_LIB))

    def test_an_export_missing_from_the_documented_table_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write(
                "crates/secret-scan-core/src/lib.rs",
                CORE_LIB.replace("//! | Version | [`VERSION`] |\n", ""),
            )

        errors = self.run_check(configure)
        self.assertTrue(
            any("VERSION is public but absent from the documented public-surface table" in error for error in errors),
            errors,
        )

    def test_a_table_entry_that_is_not_public_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write(
                "crates/secret-scan-core/src/lib.rs",
                CORE_LIB.replace("[`VERSION`] |", "[`VERSION`], [`Gone`] |"),
            )

        errors = self.run_check(configure)
        self.assertTrue(any("table cites Gone" in error for error in errors), errors)

    def test_a_crate_root_without_a_surface_table_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            body = CORE_LIB[CORE_LIB.index("#![forbid") :]
            workspace.write("crates/secret-scan-core/src/lib.rs", body)

        errors = self.run_check(configure)
        self.assertTrue(any("must carry a public-surface table" in error for error in errors), errors)

    def test_missing_public_api_policy_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.public_api = None

        errors = self.run_check(configure)
        self.assertTrue(any("must declare core-public-api" in error for error in errors), errors)

    # -- source boundary --------------------------------------------------

    def test_runtime_io_in_core_sources_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write("crates/secret-scan-core/src/types.rs", "fn read() { std::fs::read(\"x\"); }\n")

        errors = self.run_check(configure)
        self.assertTrue(any("names std::fs (filesystem access)" in error for error in errors), errors)

    def test_compile_time_env_macro_is_allowed_in_core_sources(self) -> None:
        self.assertEqual(self.run_check(), [])

    def test_a_binding_crate_named_in_core_sources_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write("crates/secret-scan-core/src/types.rs", "use wasm_bindgen::prelude::*;\n")

        errors = self.run_check(configure)
        self.assertTrue(any("names the binding crate wasm_bindgen" in error for error in errors), errors)

    # -- core manifest shape ----------------------------------------------

    def test_core_features_are_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write("crates/secret-scan-core/Cargo.toml", CORE_MANIFEST + '[features]\nextra = []\n')

        errors = self.run_check(configure)
        self.assertTrue(any("declares no Cargo features" in error for error in errors), errors)

    def test_optional_core_dependency_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write(
                "crates/secret-scan-core/Cargo.toml",
                CORE_MANIFEST + '[dependencies]\nmemchr = { version = "2", optional = true }\n',
            )

        errors = self.run_check(configure)
        self.assertTrue(any("memchr is optional" in error for error in errors), errors)

    def test_binding_dependency_in_the_core_manifest_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write("crates/secret-scan-core/Cargo.toml", CORE_MANIFEST + '[dependencies]\nnapi = "3"\n')

        errors = self.run_check(configure)
        self.assertTrue(any("napi is a binding dependency" in error for error in errors), errors)

    def test_target_specific_core_dependencies_are_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write(
                "crates/secret-scan-core/Cargo.toml",
                CORE_MANIFEST + '[target."cfg(unix)".dependencies]\nlibc = "0.2"\n',
            )

        errors = self.run_check(configure)
        self.assertTrue(any("no target-specific dependencies" in error for error in errors), errors)

    def test_core_manifest_without_include_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.write("crates/secret-scan-core/Cargo.toml", '[package]\nname = "redact-secret"\n[lints]\nworkspace = true\n')

        errors = self.run_check(configure)
        self.assertTrue(any("must declare include" in error for error in errors), errors)

    # -- package contents -------------------------------------------------

    def test_a_file_outside_the_package_globs_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.package_list.append("tests/support/mod.rs")

        errors = self.run_check(configure)
        self.assertTrue(any("tests/support/mod.rs matches no core-package-globs" in error for error in errors), errors)

    def test_a_missing_required_package_file_is_rejected(self) -> None:
        def configure(workspace: Workspace) -> None:
            workspace.package_list.remove("README.md")

        errors = self.run_check(configure)
        self.assertTrue(any("core-package-required file README.md" in error for error in errors), errors)

    def test_package_globs_do_not_let_a_single_star_span_directories(self) -> None:
        self.assertFalse(CHECK.glob_to_regex("src/*.rs").match("src/detectors/aws.rs"))
        self.assertTrue(CHECK.glob_to_regex("src/**/*.rs").match("src/detectors/aws.rs"))
        self.assertTrue(CHECK.glob_to_regex("src/**/*.rs").match("src/lib.rs"))
        self.assertFalse(CHECK.glob_to_regex("src/**/*.rs").match("src/lib.rs.bak"))

    def test_package_contents_are_not_checked_without_a_lister(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = Workspace(Path(temp))
            self.assertEqual(CHECK.validate(workspace.root, workspace.metadata()), [])


if __name__ == "__main__":
    unittest.main()
