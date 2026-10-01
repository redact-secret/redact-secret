from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-python-package.py"
SPEC = importlib.util.spec_from_file_location("check_python_package", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)

DISTRIBUTION = "redact-secret"
IMPORT_NAME = "redact_secret"
NATIVE = "redact_secret._native"
TARGETS = ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"]

INIT = '''"""Docstring that mentions `import redact_secret` the way a user writes it."""

from __future__ import annotations

from redact_secret._native import VERSION, scan

__all__ = ["VERSION", "scan"]
'''


class Binding:
    """Builds a minimal repository that satisfies every check."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.distribution = DISTRIBUTION
        self.project_name = DISTRIBUTION
        self.import_name = IMPORT_NAME
        self.native = NATIVE
        self.abi3 = "abi3-py310"
        self.requires_python = ">=3.10"
        self.wheel_tag = "cp310-abi3"
        self.targets = list(TARGETS)
        self.maturin = "maturin>=1.10,<2"
        self.pyo3_features = ["abi3-py310"]
        self.project_extra = ""
        self.dependencies = "[]"
        self.init = INIT
        self.package_files = ["py.typed", "_native.pyi"]
        self.pull_request_trigger = "  pull_request:\n"

    def write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def build(self) -> Path:
        self.write(
            "Cargo.toml",
            "[workspace]\n[workspace.metadata.redact-secret]\n"
            'product-name = "Redact Secret"\n'
            f'python-distribution = "{self.distribution}"\n'
            f'python-import-name = "{self.import_name}"\n'
            f'python-native-module = "{self.native}"\n'
            f'python-abi3-feature = "{self.abi3}"\n'
            f'python-requires = "{self.requires_python}"\n'
            f'python-wheel-tag = "{self.wheel_tag}"\n'
            f"python-wheel-targets = {self.targets!r}\n".replace("'", '"'),
        )
        self.write("LICENSE", "MIT License\n")
        self.write("bindings/python/LICENSE", "MIT License\n")
        self.write("bindings/python/README.md", "# readme\n")
        self.write(
            "bindings/python/pyproject.toml",
            "[build-system]\n"
            f'requires = ["{self.maturin}"]\n'
            'build-backend = "maturin"\n'
            "[project]\n"
            f'name = "{self.project_name}"\n'
            'readme = "README.md"\n'
            f'requires-python = "{self.requires_python}"\n'
            'license = "MIT"\n'
            'license-files = ["LICENSE"]\n'
            'dynamic = ["version"]\n'
            f"dependencies = {self.dependencies}\n"
            f"{self.project_extra}"
            "[tool.maturin]\n"
            'features = ["extension-module"]\n'
            f'module-name = "{self.native}"\n'
            'python-source = "python"\n',
        )
        self.write(
            "bindings/python/Cargo.toml",
            '[package]\nname = "redact-secret-python"\n'
            '[lib]\ncrate-type = ["cdylib", "rlib"]\n'
            "[features]\ndefault = []\n"
            'extension-module = ["pyo3/extension-module"]\n'
            "[dependencies]\n"
            f"pyo3 = {{ workspace = true, features = {self.pyo3_features!r} }}\n".replace("'", '"'),
        )
        self.write(f"bindings/python/python/{self.import_name}/__init__.py", self.init)
        for name in self.package_files:
            self.write(f"bindings/python/python/{self.import_name}/{name}", "")
        matrix = "".join(f"          - target: {target}\n" for target in self.targets)
        self.write(
            ".github/workflows/python-wheels.yml",
            "name: Python wheels\non:\n"
            + self.pull_request_trigger
            + "jobs:\n  wheels:\n    strategy:\n      matrix:\n        include:\n"
            + matrix
            + "    steps:\n      - uses: PyO3/maturin-action@abc\n        with:\n          target: ${{ matrix.target }}\n",
        )
        return self.root


class CheckPythonPackageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.binding = Binding(Path(self.directory.name))

    def validate(self) -> list[str]:
        return CHECK.validate(self.binding.build())

    def assertOneError(self, fragment: str) -> None:
        errors = self.validate()
        self.assertEqual(len(errors), 1, errors)
        self.assertIn(fragment, errors[0])

    def test_a_consistent_binding_passes(self) -> None:
        self.assertEqual(self.validate(), [])

    def test_distribution_name_must_match_the_manifest(self) -> None:
        self.binding.project_name = "something-else"
        self.assertOneError("name 'something-else' must be 'redact-secret'")

    def test_a_pinned_version_is_rejected(self) -> None:
        self.binding.project_extra = 'version = "9.9.9"\n'
        self.assertOneError("must not pin its own version")

    def test_a_static_version_is_rejected(self) -> None:
        root = self.binding.build()
        pyproject = root / "bindings" / "python" / "pyproject.toml"
        pyproject.write_text(
            pyproject.read_text(encoding="utf-8").replace('dynamic = ["version"]\n', 'version = "9.9.9"\n'),
            encoding="utf-8",
        )
        errors = CHECK.validate(root)
        self.assertTrue(any("version must stay dynamic" in error for error in errors), errors)

    def test_missing_license_file_is_reported(self) -> None:
        binding = self.binding.build()
        (binding / "bindings" / "python" / "LICENSE").unlink()
        self.assertIn("LICENSE", " ".join(CHECK.validate(binding)))

    def test_runtime_dependencies_are_rejected(self) -> None:
        self.binding.dependencies = '["requests"]'
        self.assertOneError("no Python dependencies")

    def test_maturin_floor_below_pep_639_support_is_rejected(self) -> None:
        self.binding.maturin = "maturin>=1.7,<2"
        self.assertOneError("maturin floor")

    def test_unbounded_maturin_requirement_is_rejected(self) -> None:
        self.binding.maturin = "maturin>=1.10"
        self.assertOneError("single 'maturin>=X.Y,<2'")

    def test_requires_python_must_match_the_abi3_floor(self) -> None:
        self.binding.requires_python = ">=3.9"
        errors = self.validate()
        self.assertTrue(any("does not match the abi3-py310 floor" in error for error in errors), errors)

    def test_abi3_feature_must_be_selected(self) -> None:
        self.binding.pyo3_features = ["extension-module"]
        self.assertOneError("must select the abi3-py310 feature")

    def test_two_abi3_floors_are_rejected(self) -> None:
        self.binding.pyo3_features = ["abi3-py310", "abi3-py311"]
        self.assertOneError("more than one abi3 floor")

    def test_wheel_tag_must_follow_the_abi3_floor(self) -> None:
        self.binding.wheel_tag = "cp311-abi3"
        self.assertOneError("python-wheel-tag must be cp310-abi3")

    def test_default_features_must_stay_empty(self) -> None:
        root = self.binding.build()
        manifest = root / "bindings" / "python" / "Cargo.toml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace("default = []", 'default = ["extension-module"]'),
            encoding="utf-8",
        )
        self.assertIn("default features", " ".join(CHECK.validate(root)))

    def test_a_second_python_module_is_rejected(self) -> None:
        self.binding.package_files = ["py.typed", "_native.pyi", "detectors.py"]
        self.assertOneError("only __init__.py may be Python")

    def test_an_import_outside_the_native_module_is_rejected(self) -> None:
        self.binding.init = "from __future__ import annotations\nimport re\n"
        self.assertOneError("may not import 're'")

    def test_a_docstring_example_is_not_an_import(self) -> None:
        self.binding.init = '"""Use it as::\n\n    import redact_secret\n"""\nfrom redact_secret._native import scan\n'
        self.assertEqual(self.validate(), [])

    def test_defining_behavior_in_the_package_is_rejected(self) -> None:
        self.binding.init = "from redact_secret._native import scan\n\n\ndef scan_twice(text):\n    return scan(text)\n"
        self.assertOneError("defines 'scan_twice'")

    def test_typing_markers_are_required(self) -> None:
        self.binding.package_files = ["_native.pyi"]
        self.assertOneError("py.typed")

    def test_a_target_the_workflow_does_not_build_is_reported(self) -> None:
        root = self.binding.build()
        workflow = root / ".github" / "workflows" / "python-wheels.yml"
        workflow.write_text(
            workflow.read_text(encoding="utf-8").replace("          - target: aarch64-apple-darwin\n", ""),
            encoding="utf-8",
        )
        self.assertIn("builds no wheel for aarch64-apple-darwin", " ".join(CHECK.validate(root)))

    def test_a_target_the_manifest_does_not_declare_is_reported(self) -> None:
        root = self.binding.build()
        workflow = root / ".github" / "workflows" / "python-wheels.yml"
        workflow.write_text(
            workflow.read_text(encoding="utf-8") + "          - target: i686-pc-windows-msvc\n",
            encoding="utf-8",
        )
        self.assertIn("i686-pc-windows-msvc", " ".join(CHECK.validate(root)))

    def test_wheel_workflow_must_trigger_on_pull_requests(self) -> None:
        self.binding.pull_request_trigger = ""
        self.assertOneError("must trigger on every pull_request")

    def test_wheel_workflow_rejects_pull_request_path_filters(self) -> None:
        self.binding.pull_request_trigger = "  pull_request:\n    paths:\n      - bindings/python/**\n"
        self.assertOneError("pull_request trigger must not use path filters")

    def test_an_unmappable_target_is_reported(self) -> None:
        self.binding.targets = TARGETS + ["s390x-unknown-linux-gnu"]
        errors = self.validate()
        self.assertTrue(any("cannot map to a wheel platform tag" in error for error in errors), errors)

    def test_every_declared_target_has_a_platform_tag_pattern(self) -> None:
        """The repository's own matrix stays inside what qualification knows."""
        policy = CHECK.load_policy(Path(__file__).resolve().parents[2])
        for target in policy["python-wheel-targets"]:
            self.assertIn(target, CHECK.TARGET_PLATFORM_TAGS)

    def test_a_compressed_manylinux_tag_set_maps_to_one_target(self) -> None:
        """auditwheel writes one platform as several `.`-joined spellings."""
        declared = list(CHECK.TARGET_PLATFORM_TAGS)
        self.assertEqual(
            CHECK.targets_for_platform("manylinux_2_17_x86_64.manylinux2014_x86_64", declared),
            ["x86_64-unknown-linux-gnu"],
        )
        self.assertEqual(
            CHECK.targets_for_platform("manylinux_2_17_aarch64.manylinux2014_aarch64", declared),
            ["aarch64-unknown-linux-gnu"],
        )

    def test_legacy_manylinux_aliases_are_recognized(self) -> None:
        declared = list(CHECK.TARGET_PLATFORM_TAGS)
        for tag in ("manylinux1_x86_64", "manylinux2010_x86_64", "manylinux2014_x86_64"):
            self.assertEqual(CHECK.targets_for_platform(tag, declared), ["x86_64-unknown-linux-gnu"], tag)

    def test_single_platform_tags_still_map(self) -> None:
        declared = list(CHECK.TARGET_PLATFORM_TAGS)
        for tag, target in [
            ("musllinux_1_2_x86_64", "x86_64-unknown-linux-musl"),
            ("musllinux_1_2_aarch64", "aarch64-unknown-linux-musl"),
            ("macosx_11_0_arm64", "aarch64-apple-darwin"),
            ("macosx_10_12_x86_64", "x86_64-apple-darwin"),
            ("win_amd64", "x86_64-pc-windows-msvc"),
            ("win_arm64", "aarch64-pc-windows-msvc"),
        ]:
            self.assertEqual(CHECK.targets_for_platform(tag, declared), [target], tag)

    def test_a_tag_set_mixing_two_platforms_matches_nothing(self) -> None:
        """Every element has to name the same target, so this claims neither."""
        declared = list(CHECK.TARGET_PLATFORM_TAGS)
        self.assertEqual(CHECK.targets_for_platform("manylinux_2_17_x86_64.win_amd64", declared), [])
        self.assertEqual(CHECK.targets_for_platform("manylinux_2_17_x86_64.musllinux_1_2_x86_64", declared), [])

    def test_an_unknown_tag_matches_nothing(self) -> None:
        declared = list(CHECK.TARGET_PLATFORM_TAGS)
        for tag in ("linux_x86_64", "any", "manylinux_2_17_s390x"):
            self.assertEqual(CHECK.targets_for_platform(tag, declared), [], tag)

    def test_abi3_floor_parsing(self) -> None:
        self.assertEqual(CHECK.abi3_floor("abi3-py310"), 10)
        self.assertEqual(CHECK.abi3_floor("abi3-py314"), 14)
        self.assertIsNone(CHECK.abi3_floor("extension-module"))


if __name__ == "__main__":
    unittest.main()
