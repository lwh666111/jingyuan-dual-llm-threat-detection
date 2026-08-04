from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from situation_core import SecurityAction, SituationCorrelator  # noqa: E402
from situation_store import MySQLSettings, MySQLSituationStore  # noqa: E402


class SituationStoreMySQLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.store = MySQLSituationStore(
            MySQLSettings(
                host=os.getenv("TEST_MYSQL_HOST", "127.0.0.1"),
                port=int(os.getenv("TEST_MYSQL_PORT", "3306")),
                user=os.getenv("TEST_MYSQL_USER", "root"),
                password=os.getenv("TEST_MYSQL_PASSWORD", "123456"),
                database=os.getenv("TEST_MYSQL_DATABASE", "traffic_pipeline"),
            )
        )
        try:
            cls.store.ensure_schema()
        except Exception as exc:
            raise unittest.SkipTest(f"MySQL integration unavailable: {exc}")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.clean_test_rows()
        cls.store.close()

    @classmethod
    def clean_test_rows(cls) -> None:
        conn = cls.store.connect()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM situation_outbox WHERE aggregate_id LIKE 'SIT-TEST-%'")
            cur.execute("DELETE FROM attack_situations WHERE situation_id LIKE 'SIT-TEST-%'")
            cur.execute("DELETE FROM security_actions WHERE action_id LIKE 'ACT-TEST-%'")
        conn.commit()

    def setUp(self) -> None:
        self.clean_test_rows()

    def build_situation(self):
        base = datetime(2026, 8, 3, 8, 0, tzinfo=timezone.utc)
        rows = [
            SecurityAction("ACT-TEST-1", "203.0.113.77", "test-server", "PORT_SCAN", base, count=50),
            SecurityAction("ACT-TEST-2", "203.0.113.77", "test-server", "SSH_BRUTEFORCE", base + timedelta(minutes=2), count=8),
            SecurityAction("ACT-TEST-3", "203.0.113.77", "test-server", "SQL_INJECTION", base + timedelta(minutes=5), count=3),
        ]
        situation = SituationCorrelator().correlate(rows)[0]
        situation.situation_id = "SIT-TEST-INTEGRATION"
        return situation

    def test_save_is_idempotent_and_detail_is_ordered(self) -> None:
        situation = self.build_situation()
        first = self.store.save([situation])
        second = self.store.save([situation])
        self.assertEqual(first, {"actions": 3, "situations": 1, "changed": 1})
        self.assertEqual(second, {"actions": 3, "situations": 1, "changed": 0})
        detail = self.store.get_situation(situation.situation_id)
        self.assertIsNotNone(detail)
        self.assertEqual(detail["distinct_action_types"], 3)
        self.assertEqual([x["sequence_no"] for x in detail["actions"]], [1, 2, 3])
        self.assertEqual([x["gap_seconds"] for x in detail["actions"]], [0, 120, 180])

    def test_list_filter_report_and_status(self) -> None:
        situation = self.build_situation()
        self.store.save([situation])
        rows = self.store.list_situations(source_ip="203.0.113.77")
        self.assertEqual(rows[0]["situation_id"], situation.situation_id)
        self.assertTrue(self.store.update_ai_report(situation.situation_id, {"conclusion": "测试结论"}))
        self.assertTrue(self.store.update_status(situation.situation_id, "handled"))
        detail = self.store.get_situation(situation.situation_id)
        self.assertEqual(detail["status"], "handled")
        self.assertEqual(detail["ai_report"]["conclusion"], "测试结论")

    def test_observing_session_is_hidden_by_default_but_can_be_requested(self) -> None:
        base = datetime(2026, 8, 3, 9, 0, tzinfo=timezone.utc)
        rows = [
            SecurityAction("ACT-TEST-OBS-1", "203.0.113.77", "test-server", "PORT_SCAN", base),
            SecurityAction(
                "ACT-TEST-OBS-2",
                "203.0.113.77",
                "test-server",
                "SSH_BRUTEFORCE",
                base + timedelta(minutes=2),
            ),
        ]
        situation = SituationCorrelator().correlate(rows)[0]
        situation.situation_id = "SIT-TEST-OBSERVING"
        self.store.save([situation])
        default_rows = self.store.list_situations(source_ip="203.0.113.77")
        explicit_rows = self.store.list_situations(source_ip="203.0.113.77", status="observing")
        self.assertFalse(any(row["situation_id"] == situation.situation_id for row in default_rows))
        self.assertTrue(any(row["situation_id"] == situation.situation_id for row in explicit_rows))


if __name__ == "__main__":
    unittest.main()
