from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "generate-detector-families-table.py"
SPEC = importlib.util.spec_from_file_location("generate_detector_families_table", SCRIPT)
assert SPEC and SPEC.loader
GEN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GEN
SPEC.loader.exec_module(GEN)

INVENTORY = {
    "types": [
        {"type": "beta_key", "detector": "beta-token", "policyClass": "always-redact"},
        {"type": "alpha_key", "detector": "alpha-token", "policyClass": "confidence-gated"},
    ]
}


def doc(rows: str) -> str:
    return f"# Families\n\n{GEN.START}\nold intro\n\n| Type | Detector | Policy class | Governing ADR |\n| --- | --- | --- | --- |\n{rows}{GEN.END}\n\n## Rules\n"


class FamiliesTableTests(unittest.TestCase):
    def run_main(self, document: str, inventory: dict, *extra: str) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as temp:
            inv = Path(temp) / "inventory.json"
            spec = Path(temp) / "spec.md"
            inv.write_text(json.dumps(inventory), encoding="utf-8")
            spec.write_text(document, encoding="utf-8")
            code = GEN.main(["--inventory", str(inv), "--doc", str(spec), *extra])
            return code, spec.read_text(encoding="utf-8")

    def test_generation_sorts_rows_and_keeps_the_hand_authored_adr_cell(self) -> None:
        _, text = self.run_main(doc("| `alpha_key` | `alpha-token` | `confidence-gated` | [ADR](x.md) |\n"), INVENTORY)
        self.assertLess(text.index("`alpha_key`"), text.index("`beta_key`"))
        self.assertIn("| [ADR](x.md) |", text)
        self.assertIn(f"| `beta_key` | `beta-token` | `always-redact` | {GEN.DEFAULT_ADR} |", text)

    def test_check_passes_on_a_generated_block(self) -> None:
        _, generated = self.run_main(doc(""), INVENTORY)
        code, _ = self.run_main(generated, INVENTORY, "--check")
        self.assertEqual(code, 0)

    def test_check_fails_when_an_inventory_type_has_no_row(self) -> None:
        _, generated = self.run_main(doc(""), INVENTORY)
        broken = generated.replace(f"| `beta_key` | `beta-token` | `always-redact` | {GEN.DEFAULT_ADR} |\n", "")
        code, _ = self.run_main(broken, INVENTORY, "--check")
        self.assertEqual(code, 1)

    def test_check_fails_when_a_policy_class_is_hand_edited(self) -> None:
        _, generated = self.run_main(doc(""), INVENTORY)
        code, _ = self.run_main(generated.replace("`always-redact`", "`block`"), INVENTORY, "--check")
        self.assertEqual(code, 1)

    def test_check_fails_on_a_row_for_a_type_the_inventory_lacks(self) -> None:
        _, generated = self.run_main(doc(""), INVENTORY)
        extra = generated.replace(GEN.END, f"| `ghost_key` | `ghost` | `block` | x |\n{GEN.END}")
        code, _ = self.run_main(extra, INVENTORY, "--check")
        self.assertEqual(code, 1)

    def test_missing_markers_fail(self) -> None:
        code, _ = self.run_main("# no markers\n", INVENTORY, "--check")
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
