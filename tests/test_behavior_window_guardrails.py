from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from security_detection_v2 import BehaviorWindowAnalyzer  # noqa: E402
from situation_core import SecurityAction, SituationCorrelator  # noqa: E402


class BehaviorWindowGuardrailTests(unittest.TestCase):
    def analyzer(self) -> BehaviorWindowAnalyzer:
        return BehaviorWindowAnalyzer(model_path=ROOT / "models" / "does-not-exist.joblib")

    @staticmethod
    def event(uri: str, status_code: int = 200) -> dict:
        return {
            "source_ip": "198.51.100.20",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": "GET",
            "uri": uri,
            "status_code": status_code,
            "user_agent": "normal-browser",
            "body": "",
        }

    def test_single_normal_directory_visit_is_normal(self) -> None:
        result = self.analyzer().observe(self.event("/products/catalog"))
        self.assertEqual(result["type"], "normal")
        self.assertEqual(result["score"], 0.0)

    def test_repeated_use_of_one_normal_directory_is_not_scanning(self) -> None:
        analyzer = self.analyzer()
        result = {}
        for _ in range(40):
            result = analyzer.observe(self.event("/products/catalog"))
        self.assertEqual(result["type"], "normal")
        self.assertEqual(result["features"]["distinct_path_count"], 1)

    def test_busy_successful_portal_session_is_not_high_frequency_attack(self) -> None:
        analyzer = self.analyzer()
        result = {}
        for index in range(350):
            result = analyzer.observe(self.event(f"/api/v1/portal/page-{index % 80}"))
        self.assertEqual(result["type"], "normal")
        self.assertEqual(result["score"], 0.0)
        self.assertEqual(result["features"]["not_found_count"], 0)

    def test_directory_scan_action_alone_cannot_open_auto_defense_situation(self) -> None:
        action = SecurityAction(
            action_id="ACT-DIR-1",
            source_ip="198.51.100.20",
            target_asset="web-server",
            action_type="DIRECTORY_SCAN",
            occurred_at=datetime.now(timezone.utc),
            count=80,
            confidence=0.95,
            severity="high",
        )
        situation = SituationCorrelator(minimum_distinct_actions=3).correlate([action])[0]
        self.assertEqual(situation.status, "observing")
        self.assertEqual(situation.distinct_action_types, 1)
        self.assertNotEqual(situation.risk_level, "critical")


if __name__ == "__main__":
    unittest.main()
