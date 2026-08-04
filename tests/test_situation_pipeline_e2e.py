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

from dashboard_api_server import create_app  # noqa: E402
from port_scan_sensor import PortScanDetector  # noqa: E402
from situation_ai import fallback_report  # noqa: E402
from situation_core import SituationCorrelator, action_from_attack_event  # noqa: E402
from situation_store import MySQLSettings, MySQLSituationStore  # noqa: E402


MYSQL = {
    "host": os.getenv("TEST_MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("TEST_MYSQL_PORT", "3306")),
    "user": os.getenv("TEST_MYSQL_USER", "root"),
    "password": os.getenv("TEST_MYSQL_PASSWORD", "123456"),
    "database": os.getenv("TEST_MYSQL_DATABASE", "traffic_pipeline"),
}


class SituationPipelineE2ETests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = MySQLSituationStore(MySQLSettings(**MYSQL))
        try:
            self.store.ensure_schema()
        except Exception as exc:
            raise unittest.SkipTest(f"MySQL integration unavailable: {exc}")
        self.cleanup()

    def tearDown(self) -> None:
        self.cleanup()
        self.store.close()

    def cleanup(self) -> None:
        conn = self.store.connect()
        with conn.cursor() as cur:
            cur.execute(
                """DELETE o FROM situation_outbox o
                   JOIN attack_situations s ON s.situation_id=o.aggregate_id
                   WHERE s.source_ip='203.0.113.222' AND s.target_asset='e2e-server'"""
            )
            cur.execute(
                "DELETE FROM attack_situations WHERE source_ip='203.0.113.222' AND target_asset='e2e-server'"
            )
            cur.execute(
                "DELETE FROM security_actions WHERE source_ip='203.0.113.222' AND target_asset='e2e-server'"
            )
        conn.commit()

    def test_scan_ssh_sql_ai_database_and_api_form_one_traceable_chain(self) -> None:
        base = datetime.now(timezone.utc) - timedelta(minutes=8)
        detector = PortScanDetector(unique_port_threshold=3, window_seconds=60, target_asset="e2e-server")
        for index, port in enumerate([22, 80, 443, 3306]):
            detector.observe(base + timedelta(seconds=index), "203.0.113.222", "10.0.0.8", port)
        scan = detector.actions(now=base + timedelta(seconds=10))[0]
        scan.action_id = "ACT-E2E-SCAN"
        ssh = action_from_attack_event(
            {
                "event_id": "ACT-E2E-SSH",
                "occurred_at": base + timedelta(minutes=2),
                "source_ip": "203.0.113.222",
                "target_interface": "tcp:22",
                "attack_type": "SSH爆破",
                "risk_level": "high",
                "confidence": 0.94,
            },
            target_asset="e2e-server",
        )
        sql = action_from_attack_event(
            {
                "event_id": "ACT-E2E-SQL",
                "occurred_at": base + timedelta(minutes=5),
                "source_ip": "203.0.113.222",
                "target_interface": "/api/login",
                "attack_type": "SQL注入",
                "risk_level": "critical",
                "confidence": 0.98,
            },
            target_asset="e2e-server",
        )
        situation = SituationCorrelator().correlate([sql, scan, ssh], include_observing=False)[0]
        situation.situation_id = "SIT-E2E-CROSS-SENSOR"
        self.store.save([situation])
        report = fallback_report(situation.as_dict())
        self.store.update_ai_report(situation.situation_id, report, "fallback")

        app = create_app(MYSQL, seed_demo=True, jwt_secret="e2e-secret")
        app.config.update(TESTING=True)
        client = app.test_client()
        login = client.post("/api/v2/auth/login", json={"username": "admin", "password": "admin"})
        self.assertEqual(login.status_code, 200)
        detail = client.get(f"/api/v2/situations/{situation.situation_id}").get_json()["item"]
        graph = client.get(f"/api/v2/situations/{situation.situation_id}/graph").get_json()
        self.assertEqual([row["action_type"] for row in detail["actions"]], ["PORT_SCAN", "SSH_BRUTEFORCE", "SQL_INJECTION"])
        self.assertEqual([row["name"] for row in graph["nodes"]], ["端口扫描", "SSH 爆破", "SQL 注入"])
        self.assertEqual(len(graph["edges"]), 2)
        self.assertIn("203.0.113.222", detail["ai_report"]["narrative"])
        self.assertEqual(detail["ai_status"], "fallback")


if __name__ == "__main__":
    unittest.main()
