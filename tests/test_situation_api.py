from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from dashboard_api_server import create_app  # noqa: E402
from situation_core import SecurityAction, SituationCorrelator  # noqa: E402
from situation_store import MySQLSettings, MySQLSituationStore  # noqa: E402


MYSQL = {
    "host": os.getenv("TEST_MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("TEST_MYSQL_PORT", "3306")),
    "user": os.getenv("TEST_MYSQL_USER", "root"),
    "password": os.getenv("TEST_MYSQL_PASSWORD", "123456"),
    "database": os.getenv("TEST_MYSQL_DATABASE", "traffic_pipeline"),
}


class SituationAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls.app = create_app(MYSQL, seed_demo=True, jwt_secret="situation-api-test-secret")
        except Exception as exc:
            raise unittest.SkipTest(f"API integration unavailable: {exc}")
        cls.app.config.update(TESTING=True)
        cls.client = cls.app.test_client()
        response = cls.client.post("/api/v2/auth/login", json={"username": "admin", "password": "admin"})
        if response.status_code != 200:
            raise unittest.SkipTest("default admin account unavailable")
        cls.store = MySQLSituationStore(MySQLSettings(**MYSQL))
        cls.clean_rows()
        base = datetime.now(timezone.utc) - timedelta(minutes=5)
        actions = [
            SecurityAction("ACT-API-1", "203.0.113.66", "api-test", "PORT_SCAN", base, count=20),
            SecurityAction("ACT-API-2", "203.0.113.66", "api-test", "SSH_BRUTEFORCE", base + timedelta(minutes=1), count=8),
            SecurityAction("ACT-API-3", "203.0.113.66", "api-test", "SQL_INJECTION", base + timedelta(minutes=2), count=2),
        ]
        situation = SituationCorrelator().correlate(actions)[0]
        situation.situation_id = "SIT-API-INTEGRATION"
        cls.store.save([situation])

    @classmethod
    def clean_rows(cls) -> None:
        conn = cls.store.connect()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM situation_outbox WHERE aggregate_id='SIT-API-INTEGRATION'")
            cur.execute("DELETE FROM attack_situations WHERE situation_id='SIT-API-INTEGRATION'")
            cur.execute("DELETE FROM security_actions WHERE action_id LIKE 'ACT-API-%'")
        conn.commit()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.clean_rows()
        cls.store.close()

    def test_list_detail_graph_and_evidence(self) -> None:
        listing = self.client.get("/api/v2/situations?source_ip=203.0.113.66")
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.get_json()["items"][0]["situation_id"], "SIT-API-INTEGRATION")
        detail = self.client.get("/api/v2/situations/SIT-API-INTEGRATION")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(len(detail.get_json()["item"]["actions"]), 3)
        graph = self.client.get("/api/v2/situations/SIT-API-INTEGRATION/graph")
        self.assertEqual([node["name"] for node in graph.get_json()["nodes"]], ["端口扫描", "SSH 爆破", "SQL 注入"])
        self.assertEqual(len(graph.get_json()["edges"]), 2)
        evidence = self.client.get("/api/v2/situations/SIT-API-INTEGRATION/evidence")
        self.assertEqual(len(evidence.get_json()["items"]), 3)

    def test_admin_status_and_reanalysis(self) -> None:
        response = self.client.post("/api/v2/situations/SIT-API-INTEGRATION/status", json={"status": "handled"})
        self.assertEqual(response.status_code, 200)
        fake_report = {"conclusion": "API测试研判"}
        with patch("dashboard_api_server.analyze_situation", return_value=(fake_report, "complete")):
            response = self.client.post("/api/v2/situations/SIT-API-INTEGRATION/reanalyze")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["report"]["conclusion"], "API测试研判")

    def test_invalid_ip_and_status_are_rejected(self) -> None:
        self.assertEqual(self.client.get("/api/v2/situations/by-ip/not-an-ip").status_code, 400)
        response = self.client.post("/api/v2/situations/SIT-API-INTEGRATION/status", json={"status": "magic"})
        self.assertEqual(response.status_code, 400)

    def test_admin_can_update_validated_situation_thresholds(self) -> None:
        payload = {
            "situation_minimum_actions": "4",
            "situation_window_minutes": "45",
            "situation_inactivity_minutes": "12",
            "scan_port_threshold": "18",
            "scan_window_seconds": "90",
        }
        try:
            response = self.client.put("/api/v2/admin/config", json=payload)
            self.assertEqual(response.status_code, 200)
            config = self.client.get("/api/v2/admin/config").get_json()["items"]
            values = {row["config_key"]: row["config_value"] for row in config}
            for key, value in payload.items():
                self.assertEqual(values[key], value)
            invalid = self.client.put("/api/v2/admin/config", json={"situation_minimum_actions": "2"})
            self.assertEqual(invalid.status_code, 400)
        finally:
            self.client.put(
                "/api/v2/admin/config",
                json={
                    "situation_minimum_actions": "3",
                    "situation_window_minutes": "30",
                    "situation_inactivity_minutes": "15",
                    "scan_port_threshold": "10",
                    "scan_window_seconds": "60",
                },
            )


if __name__ == "__main__":
    unittest.main()
