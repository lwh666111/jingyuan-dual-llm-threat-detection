from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import auto_defense_daemon  # noqa: E402


class AutoDefenseDaemonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = MagicMock()
        self.cursor = self.conn.cursor.return_value.__enter__.return_value
        self.policy = {"enabled": True, "minimum_risk": "critical", "allow_private": False}
        self.row = {
            "source_ip": "8.8.8.8",
            "situation_id": "S-TEST",
            "risk_level": "critical",
            "blocked_id": 7,
        }

    def test_stale_database_record_repairs_missing_firewall_rules(self) -> None:
        with patch.object(auto_defense_daemon, "load_policy", return_value=self.policy), patch.object(
            auto_defense_daemon, "list_candidates", return_value=[self.row]
        ), patch.object(auto_defense_daemon, "firewall_status", return_value={"active": False}), patch.object(
            auto_defense_daemon, "firewall_block_ip", return_value=(True, "")
        ) as block:
            stats = auto_defense_daemon.run_once(self.conn)
        self.assertEqual(stats["blocked"], 1)
        block.assert_called_once_with("8.8.8.8")
        self.assertGreaterEqual(self.conn.commit.call_count, 3)

    def test_active_database_record_is_not_recreated_each_poll(self) -> None:
        with patch.object(auto_defense_daemon, "load_policy", return_value=self.policy), patch.object(
            auto_defense_daemon, "list_candidates", return_value=[self.row]
        ), patch.object(auto_defense_daemon, "firewall_status", return_value={"active": True}), patch.object(
            auto_defense_daemon, "firewall_block_ip"
        ) as block:
            stats = auto_defense_daemon.run_once(self.conn)
        self.assertEqual(stats["skipped"], 1)
        block.assert_not_called()

    def test_disabled_poll_releases_policy_snapshot(self) -> None:
        disabled = {"enabled": False, "minimum_risk": "critical", "allow_private": False}
        with patch.object(auto_defense_daemon, "load_policy", return_value=disabled), patch.object(
            auto_defense_daemon, "list_candidates"
        ) as candidates:
            stats = auto_defense_daemon.run_once(self.conn)
        self.assertEqual(stats["enabled"], 0)
        self.conn.commit.assert_called_once()
        candidates.assert_not_called()

    def test_candidates_ignore_evidence_at_or_before_manual_release(self) -> None:
        self.cursor.fetchall.return_value = []
        auto_defense_daemon.list_candidates(self.conn, self.policy)
        sql = str(self.cursor.execute.call_args.args[0])
        self.assertIn("demo_auto_defense_releases", sql)
        self.assertIn("s.last_action_at > r.released_action_at", sql)

    def test_successful_block_clears_previous_release_watermark(self) -> None:
        with patch.object(auto_defense_daemon, "load_policy", return_value=self.policy), patch.object(
            auto_defense_daemon, "list_candidates", return_value=[self.row]
        ), patch.object(auto_defense_daemon, "firewall_status", return_value={"active": False}), patch.object(
            auto_defense_daemon, "firewall_block_ip", return_value=(True, "")
        ):
            auto_defense_daemon.run_once(self.conn)
        statements = [str(call.args[0]) for call in self.cursor.execute.call_args_list]
        self.assertTrue(any("DELETE FROM demo_auto_defense_releases" in sql for sql in statements))


if __name__ == "__main__":
    unittest.main()
