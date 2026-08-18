from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from situation_store import MySQLSettings, MySQLSituationStore  # noqa: E402


class _Cursor:
    def __init__(self, affected: int):
        self.affected = affected
        self.sql = ""
        self.params = ()

    def __enter__(self): return self
    def __exit__(self, *_): return False

    def execute(self, sql, params):
        self.sql = sql
        self.params = params
        return self.affected


class _Connection:
    def __init__(self, affected: int):
        self.cursor_instance = _Cursor(affected)
        self.committed = False

    def cursor(self): return self.cursor_instance
    def commit(self): self.committed = True
    def rollback(self): pass


class SituationReportRecoveryTests(unittest.TestCase):
    def test_cloud_situation_worker_does_not_wait_for_raw_packet_queue(self):
        source = (SCRIPTS / "situation_ai_daemon.py").read_text(encoding="utf-8")
        self.assertNotIn("raw_review_waiting", source)
        self.assertNotIn("FROM raw_http_logs", source)
        self.assertIn('default=1440', source)

    def test_report_update_is_guarded_by_sequence_hash(self):
        store = MySQLSituationStore(MySQLSettings())
        conn = _Connection(1)
        store.connect = lambda: conn

        updated = store.update_ai_report(
            "SIT-1",
            {"conclusion": "latest chain"},
            "complete",
            expected_sequence_hash="HASH-2",
        )

        self.assertTrue(updated)
        self.assertIn("sequence_hash=%s", conn.cursor_instance.sql)
        self.assertEqual(conn.cursor_instance.params[-1], "HASH-2")
        self.assertTrue(conn.committed)

    def test_superseded_report_does_not_overwrite_new_chain(self):
        store = MySQLSituationStore(MySQLSettings())
        conn = _Connection(0)
        store.connect = lambda: conn

        updated = store.update_ai_report(
            "SIT-1",
            {"conclusion": "stale chain"},
            "complete",
            expected_sequence_hash="HASH-OLD",
        )

        self.assertFalse(updated)


if __name__ == "__main__":
    unittest.main()
