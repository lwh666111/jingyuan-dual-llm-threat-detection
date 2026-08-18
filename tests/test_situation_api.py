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
        proxy_actions = [
            SecurityAction("ACT-API-PROXY-1", "198.51.100.77", "api-test", "DIRECTORY_SCAN", base + timedelta(minutes=1), count=12),
            SecurityAction("ACT-API-PROXY-2", "198.51.100.77", "api-test", "XSS", base + timedelta(minutes=2), count=3),
            SecurityAction("ACT-API-PROXY-3", "198.51.100.77", "api-test", "COMMAND_INJECTION", base + timedelta(minutes=3), count=1),
        ]
        proxy_situation = SituationCorrelator().correlate(proxy_actions)[0]
        proxy_situation.situation_id = "SIT-API-PROXY"
        # A proxy can contribute only one action and remain "observing" on its own.
        # Cross-IP correlation must still include it before applying cluster thresholds.
        observing_actions = [
            SecurityAction("ACT-API-OBSERVING-1", "192.0.2.251", "api-test", "SSTI", base + timedelta(minutes=3), count=1),
        ]
        observing_situation = SituationCorrelator().correlate(observing_actions)[0]
        observing_situation.situation_id = "SIT-API-OBSERVING"
        cls.store.save([situation, proxy_situation, observing_situation])
        # Reproduce the server regression: a high-volume, single-action sensor can occupy
        # the latest 500 rows and must not hide an older multi-IP attack cluster.
        conn = cls.store.connect()
        filler_time = base + timedelta(minutes=4)
        filler_rows = []
        for index in range(510):
            filler_rows.append(
                (
                    f"SIT-API-FILLER-{index:04d}",
                    f"192.0.2.{(index % 250) + 1}",
                    f"noise-target-{index:04d}",
                    filler_time,
                    filler_time,
                    "open",
                    1,
                    1,
                    "credential_access",
                    0.5,
                    "medium",
                    f"filler-{index:04d}",
                    "complete",
                )
            )
        with conn.cursor() as cur:
            cur.executemany(
                """INSERT INTO attack_situations(
                       situation_id,source_ip,target_asset,started_at,last_action_at,status,
                       distinct_action_types,total_action_count,current_stage,risk_score,
                       risk_level,sequence_hash,ai_status
                   ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                filler_rows,
            )
        conn.commit()

    @classmethod
    def clean_rows(cls) -> None:
        conn = cls.store.connect()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM situation_outbox WHERE aggregate_id IN ('SIT-API-INTEGRATION','SIT-API-PROXY','SIT-API-OBSERVING')")
            cur.execute("DELETE FROM attack_situations WHERE situation_id IN ('SIT-API-INTEGRATION','SIT-API-PROXY','SIT-API-OBSERVING')")
            cur.execute("DELETE FROM attack_situations WHERE situation_id LIKE 'SIT-API-FILLER-%'")
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

    def test_detail_exposes_ai_queue_and_priority_endpoint(self) -> None:
        conn = self.store.connect()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE attack_situations SET ai_status='pending',ai_priority=0,ai_queued_at=UTC_TIMESTAMP(3) "
                "WHERE situation_id='SIT-API-INTEGRATION'"
            )
        conn.commit()
        detail = self.client.get("/api/v2/situations/SIT-API-INTEGRATION")
        self.assertEqual(detail.status_code, 200)
        self.assertIn("ai_queue", detail.get_json()["item"])

        response = self.client.post("/api/v2/situations/SIT-API-INTEGRATION/prioritize-report", json={})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["queue"]["prioritized"])

    def test_admin_status_and_reanalysis(self) -> None:
        response = self.client.post("/api/v2/situations/SIT-API-INTEGRATION/status", json={"status": "handled"})
        self.assertEqual(response.status_code, 200)
        response = self.client.post("/api/v2/situations/SIT-API-INTEGRATION/reanalyze")
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.get_json()["ai_status"], "retry")
        self.assertTrue(response.get_json()["queue"]["prioritized"])
        detail = self.client.get("/api/v2/situations/SIT-API-INTEGRATION").get_json()["item"]
        self.assertIsNone(detail["ai_report"])
        self.assertEqual(detail["ai_queue"]["queue_position"], 1)

    def test_professional_report_history_remains_visible_after_chain_revision(self) -> None:
        conn = self.store.connect()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM situation_professional_reports WHERE job_id='SPR-API-HISTORY'")
                cur.execute(
                    """INSERT INTO situation_professional_reports(
                           job_id,situation_id,sequence_hash,status,progress,stage,pdf_path,requested_by,completed_at
                       ) VALUES(%s,%s,%s,'completed',100,'报告已生成',%s,'test',NOW(3))""",
                    ("SPR-API-HISTORY", "SIT-API-INTEGRATION", "OLDER-SEQUENCE", "C:/reports/history.pdf"),
                )
            conn.commit()

            response = self.client.get("/api/v2/situations/SIT-API-INTEGRATION/professional-report")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["job"]["job_id"], "SPR-API-HISTORY")
            self.assertEqual(response.get_json()["job"]["status"], "completed")
        finally:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM situation_professional_reports WHERE job_id='SPR-API-HISTORY'")
            conn.commit()

    def test_invalid_ip_and_status_are_rejected(self) -> None:
        self.assertEqual(self.client.get("/api/v2/situations/by-ip/not-an-ip").status_code, 400)
        response = self.client.post("/api/v2/situations/SIT-API-INTEGRATION/status", json={"status": "magic"})
        self.assertEqual(response.status_code, 400)

    def test_cross_ip_cluster_endpoint_preserves_both_sources(self) -> None:
        response = self.client.get("/api/v2/situation-clusters?window_minutes=60&lookback_hours=24")
        self.assertEqual(response.status_code, 200)
        items = response.get_json()["items"]
        expected_sources = {"203.0.113.66", "198.51.100.77", "192.0.2.251"}
        cluster = next(row for row in items if set(row.get("source_ips") or []) == expected_sources)
        detail = self.client.get(f"/api/v2/situation-clusters/{cluster['cluster_id']}?window_minutes=60&lookback_hours=24")
        self.assertEqual(detail.status_code, 200)
        payload = detail.get_json()
        self.assertEqual(len(payload["item"]["source_ips"]), 3)
        self.assertGreaterEqual(len(payload["graph"]["nodes"]), 6)

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
