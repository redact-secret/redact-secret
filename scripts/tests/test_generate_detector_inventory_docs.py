from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "generate-detector-inventory-docs.py"
SPEC = importlib.util.spec_from_file_location("generate_detector_inventory_docs", SCRIPT)
assert SPEC and SPEC.loader
GEN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GEN
SPEC.loader.exec_module(GEN)

ROOT = SCRIPT.resolve().parents[1]


def row(detector, type_, policy="always-redact", schemes=None):
    return {"type": type_, "detector": detector, "policyClass": policy, "reconciliationTrigger": "x", "schemes": schemes}


INVENTORY = {
    "types": [
        row("widget-token", "widget_token"),
        row("generic-token", "contextual_secret", "confidence-gated"),
        row("generic-token", "authorization_credential", schemes=["basic", "token"]),
    ]
}

DOC = f"# Detection\n\nIntro.\n\n{GEN.START}\nstale\n{GEN.END}\n\nOutro.\n"


class RenderBlockTests(unittest.TestCase):
    def test_one_row_per_detector_merging_types_policies_and_schemes(self) -> None:
        block = GEN.render_block(INVENTORY)
        self.assertIn("2 built-in detectors emit 3 finding types", block)
        self.assertIn("| `widget-token` | `widget_token` | `always-redact` | — |", block)
        self.assertIn(
            "| `generic-token` | `contextual_secret`, `authorization_credential` | "
            "`confidence-gated`, `always-redact` | `basic`, `token` |",
            block,
        )

    def test_rendering_is_deterministic(self) -> None:
        self.assertEqual(GEN.render_block(INVENTORY), GEN.render_block(INVENTORY))

    def test_inject_replaces_only_the_marked_block(self) -> None:
        text = GEN.inject(DOC, GEN.render_block(INVENTORY))
        self.assertTrue(text.startswith("# Detection\n\nIntro.\n\n"))
        self.assertTrue(text.endswith("\n\nOutro.\n"))
        self.assertNotIn("stale", text)

    def test_inject_requires_markers(self) -> None:
        with self.assertRaises(ValueError):
            GEN.inject("# Detection\n", GEN.render_block(INVENTORY))


class CheckModeTests(unittest.TestCase):
    def run_check(self, doc_text: str, inventory: dict) -> int:
        with tempfile.TemporaryDirectory() as tmp:
            inv = Path(tmp, "inventory.json")
            doc = Path(tmp, "detection.md")
            inv.write_text(json.dumps(inventory), encoding="utf-8")
            doc.write_text(doc_text, encoding="utf-8")
            with redirect_stderr(io.StringIO()):
                code = GEN.main(["--inventory", str(inv), "--doc", str(doc), "--check"])
            self.assertEqual(doc.read_text(encoding="utf-8"), doc_text, "--check must not write")
            return code

    def test_check_fails_when_the_block_drifts_from_the_inventory(self) -> None:
        current = GEN.inject(DOC, GEN.render_block(INVENTORY))
        self.assertEqual(self.run_check(current, INVENTORY), 0)
        grown = {"types": INVENTORY["types"] + [row("gadget-token", "gadget_token")]}
        self.assertEqual(self.run_check(current, grown), 1)

    def test_check_fails_on_a_hand_edited_block(self) -> None:
        current = GEN.inject(DOC, GEN.render_block(INVENTORY))
        edited = current.replace("`widget_token`", "`widget_key`")
        self.assertEqual(self.run_check(edited, INVENTORY), 1)

    def test_the_committed_reference_names_every_inventory_detector(self) -> None:
        inventory = json.loads(GEN.INVENTORY_PATH.read_text(encoding="utf-8"))
        doc = GEN.DOC_PATH.read_text(encoding="utf-8")
        for entry in inventory["types"]:
            self.assertIn(f"`{entry['detector']}`", doc)
            self.assertIn(f"`{entry['type']}`", doc)


if __name__ == "__main__":
    unittest.main()
