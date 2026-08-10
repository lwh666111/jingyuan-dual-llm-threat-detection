from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from situation_cluster import build_proxy_clusters  # noqa: E402


class SituationClusterTests(unittest.TestCase):
    def test_multiple_ips_are_correlated_without_losing_source_evidence(self) -> None:
        base = datetime.now(timezone.utc) - timedelta(minutes=20)
        rows = [
            self.row("S-1", "203.0.113.10", base, ["PORT_SCAN", "DIRECTORY_SCAN"]),
            self.row("S-2", "198.51.100.20", base + timedelta(minutes=4), ["SSH_BRUTEFORCE", "SQL_INJECTION"]),
            self.row("S-3", "192.0.2.30", base + timedelta(minutes=7), ["XSS"]),
        ]
        clusters = build_proxy_clusters(rows, window_minutes=60, lookback_hours=24)
        self.assertEqual(len(clusters), 1)
        cluster = clusters[0]
        self.assertEqual(len(cluster["source_ips"]), 3)
        self.assertEqual(cluster["distinct_action_types"], 5)
        self.assertTrue(cluster["proxy_rotation_suspected"])
        self.assertEqual({row["source_ip"] for row in cluster["actions"]}, set(cluster["source_ips"]))
        self.assertEqual(len(cluster["graph"]["nodes"]), 5)
        self.assertIn("代理", cluster["ai_report"]["executive_summary"])

    def test_unrelated_target_or_insufficient_diversity_is_not_merged(self) -> None:
        base = datetime.now(timezone.utc) - timedelta(minutes=10)
        rows = [
            self.row("S-1", "203.0.113.1", base, ["PORT_SCAN"], target="server-a"),
            self.row("S-2", "203.0.113.2", base + timedelta(minutes=1), ["PORT_SCAN"], target="server-a"),
            self.row("S-3", "203.0.113.3", base + timedelta(minutes=2), ["SSH_BRUTEFORCE", "SQL_INJECTION"], target="server-b"),
        ]
        self.assertEqual(build_proxy_clusters(rows, window_minutes=60, lookback_hours=24), [])

    def test_continuous_noise_cannot_extend_a_fixed_window_forever(self) -> None:
        base = datetime.now(timezone.utc) - timedelta(hours=3)
        rows = [
            self.row("S-1", "203.0.113.1", base, ["PORT_SCAN", "DIRECTORY_SCAN"]),
            self.row("S-2", "203.0.113.2", base + timedelta(minutes=50), ["SSH_BRUTEFORCE", "SQL_INJECTION"]),
            self.row("S-3", "203.0.113.3", base + timedelta(minutes=100), ["XSS", "COMMAND_INJECTION"]),
        ]
        clusters = build_proxy_clusters(rows, window_minutes=60, lookback_hours=24)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(set(clusters[0]["source_ips"]), {"203.0.113.1", "203.0.113.2"})
        self.assertLessEqual(clusters[0]["duration_seconds"], 60 * 60)

    @staticmethod
    def row(situation_id: str, ip: str, started: datetime, action_types: list[str], target: str = "server-a") -> dict:
        actions = []
        for index, action_type in enumerate(action_types):
            occurred = started + timedelta(seconds=index * 20)
            actions.append(
                {
                    "action_id": f"{situation_id}-A-{index}",
                    "source_ip": ip,
                    "target_asset": target,
                    "action_type": action_type,
                    "occurred_at": occurred,
                    "last_seen_at": occurred,
                    "action_count": index + 1,
                    "confidence": 0.9,
                    "sensor": "test",
                    "evidence_refs": [f"evidence:{situation_id}:{index}"],
                }
            )
        return {
            "situation_id": situation_id,
            "source_ip": ip,
            "target_asset": target,
            "started_at": started,
            "last_action_at": actions[-1]["last_seen_at"],
            "status": "open",
            "risk_score": 0.82,
            "risk_level": "critical",
            "actions": actions,
        }


if __name__ == "__main__":
    unittest.main()
