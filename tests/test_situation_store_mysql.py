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

    def test_ai_queue_position_and_priority_are_real(self) -> None:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        conn = self.store.connect()
        rows = [
            ("SIT-TEST-QUEUE-RUNNING", "processing", 0, now - timedelta(seconds=3)),
            ("SIT-TEST-QUEUE-FIRST", "pending", 0, now - timedelta(seconds=2)),
            ("SIT-TEST-QUEUE-LAST", "pending", 0, now - timedelta(seconds=1)),
        ]
        with conn.cursor() as cur:
            cur.executemany(
                """INSERT INTO attack_situations(
                       situation_id,source_ip,target_asset,started_at,last_action_at,status,
                       distinct_action_types,total_action_count,current_stage,risk_score,
                       risk_level,sequence_hash,ai_status,ai_priority,ai_queued_at
                   ) VALUES(%s,'203.0.113.88','queue-test',%s,%s,'open',3,3,'execution',
                            0.8,'high',%s,%s,%s,%s)""",
                [
                    (situation_id, now, now, situation_id, status, priority, queued_at)
                    for situation_id, status, priority, queued_at in rows
                ],
            )
        conn.commit()

        before = self.store.get_ai_queue_status("SIT-TEST-QUEUE-LAST")
        self.assertEqual(before["queue_ahead"], 2)
        self.assertEqual(before["queue_position"], 3)

        after = self.store.prioritize_ai("SIT-TEST-QUEUE-LAST")
        self.assertTrue(after["prioritized"])
        self.assertEqual(after["queue_ahead"], 1)
        self.assertEqual(after["queue_position"], 2)

        self.assertTrue(self.store.mark_ai_retry("SIT-TEST-QUEUE-RUNNING"))
        promoted = self.store.get_ai_queue_status("SIT-TEST-QUEUE-LAST")
        self.assertEqual(promoted["queue_ahead"], 0)
        self.assertEqual(promoted["queue_position"], 1)


if __name__ == "__main__":
    unittest.main()
