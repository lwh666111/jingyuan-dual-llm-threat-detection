import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from seed_lab_review_cache import (  # noqa: E402
    EXPECTED_ATTACK_PRESETS,
    EXPECTED_MODULES,
    EXPECTED_PRESETS,
    EXPECTED_UNIQUE_FINGERPRINTS,
    NORMAL_CONTROLS,
    PRECOMPUTED_MODEL,
    browser_body_text,
    collect_cache_entries,
    lab_fingerprint,
)
from target_multivuln_lab import FULL_CHAIN_SCENARIO, LAB_PAGES  # noqa: E402


class LabReviewCacheSeedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = collect_cache_entries()

    def test_lab_structure_counts_are_pinned(self):
        presets = [p for page in LAB_PAGES.values() for p in page.get("presets", [])]
        self.assertEqual(len(LAB_PAGES), EXPECTED_MODULES)
        self.assertEqual(len(presets), EXPECTED_PRESETS)
        attack = [
            (k, p) for k, page in LAB_PAGES.items() for p in page.get("presets", [])
            if (k, p["name"]) not in NORMAL_CONTROLS
        ]
        self.assertEqual(len(attack), EXPECTED_ATTACK_PRESETS)
        self.assertEqual(len(self.entries), EXPECTED_UNIQUE_FINGERPRINTS)

    def test_module_presets_use_pretty_json_like_browser(self):
        body = {"username": "admin", "password": "123456"}
        text = browser_body_text(body, pretty=True)
        self.assertEqual(text, '{\n  "username": "admin",\n  "password": "123456"\n}')

    def test_full_chain_uses_compact_json_like_browser(self):
        body = {"username": "admin", "password": "123456"}
        text = browser_body_text(body, pretty=False)
        self.assertEqual(text, '{"username":"admin","password":"123456"}')

    def test_pretty_and_compact_bodies_have_distinct_fingerprints(self):
        body = {"username": "admin", "password": "123456"}
        pretty = lab_fingerprint(
            "POST", "/api/auth/login", "application/json",
            browser_body_text(body, pretty=True),
        )
        compact = lab_fingerprint(
            "POST", "/api/auth/login", "application/json",
            browser_body_text(body, pretty=False),
        )
        self.assertNotEqual(pretty, compact)

    def test_normal_controls_are_never_seeded(self):
        labels = [entry["label"] for entry in self.entries]
        for _, name in sorted(NORMAL_CONTROLS):
            self.assertFalse(any(label.endswith("/" + name) for label in labels), name)

    def test_full_chain_adds_exactly_five_extra_fingerprints(self):
        chain_labels = [
            entry["label"] for entry in self.entries if entry["label"].startswith("full-chain/")
        ]
        self.assertEqual(len(chain_labels), 5)
        self.assertEqual(len(FULL_CHAIN_SCENARIO), 7)

    def test_every_entry_has_complete_ui_sections(self):
        required = (
            "verdict", "severity", "confidence", "attack_method", "summary",
            "evidence", "analysis_reasoning", "potential_impact",
            "immediate_actions", "hardening_actions", "false_positive_notes",
            "knowledge_references",
        )
        for entry in self.entries:
            analysis = entry["analysis"]
            for key in required:
                if key == "knowledge_references":
                    self.assertIsInstance(analysis.get(key), list, entry["label"])
                    continue
                self.assertTrue(analysis.get(key), f"{entry['label']} missing {key}")
            self.assertEqual(analysis["verdict"], "attack")
            json.dumps(analysis, ensure_ascii=False)

    def test_families_have_distinct_attack_methods(self):
        methods = {entry["analysis"]["attack_method"] for entry in self.entries}
        self.assertGreaterEqual(len(methods), 15)
        self.assertIn("SQL注入", methods)
        self.assertIn("XSS", methods)
        self.assertIn("命令注入", methods)

    def test_entries_cover_every_module_attack_preset(self):
        covered_labels = {entry["label"] for entry in self.entries}
        for key, page in LAB_PAGES.items():
            for preset in page.get("presets", []):
                if (key, preset["name"]) in NORMAL_CONTROLS:
                    continue
                self.assertIn(f"{key}/{preset['name']}", covered_labels)

    def test_model_name_constant_marks_precomputed_provenance(self):
        self.assertEqual(PRECOMPUTED_MODEL, "precomputed-security-analysis-v1")


if __name__ == "__main__":
    unittest.main()
