from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from situation_supervisor import (  # noqa: E402
    ai_command,
    neo4j_command,
    sensor_command,
    situation_command,
    validated_int_text,
)


class SituationSupervisorTests(unittest.TestCase):
    def args(self):
        return argparse.Namespace(
            python_exe=sys.executable,
            scripts_dir=SCRIPTS,
            mysql_host="127.0.0.1",
            mysql_port=3307,
            mysql_user="root",
            mysql_password="secret",
            mysql_database="traffic_pipeline",
            target_asset="server-a",
            minimum_actions=3,
            window_minutes=30,
            inactivity_minutes=15,
            lookback_days=30,
            poll_seconds=10,
            ollama_url="http://127.0.0.1:11434",
            rag_db_path="llm/rag/rag_knowledge.db",
            rag_data_dir="D:/JingyuanTrafficPipelineData/rag",
            rag_api_config="config/ai_api.local.json",
            scan_port_threshold=10,
            scan_window_seconds=60,
            neo4j_url="http://127.0.0.1:7474",
            neo4j_user="neo4j",
            neo4j_password="secret",
            neo4j_database="neo4j",
        )

    def test_commands_propagate_server_specific_config(self) -> None:
        args = self.args()
        self.assertIn("3307", situation_command(args))
        self.assertIn("qwen2.5:3b", ai_command(args, "qwen2.5:3b"))
        sensor = sensor_command(args, "4")
        self.assertIn("4", sensor)
        self.assertIn("server-a", sensor)
        graph = neo4j_command(args)
        self.assertIn("http://127.0.0.1:7474", graph)
        self.assertIn("secret", graph)

    def test_runtime_thresholds_override_cli_defaults(self) -> None:
        args = self.args()
        runtime = {
            "situation_minimum_actions": "4",
            "situation_window_minutes": "45",
            "situation_inactivity_minutes": "12",
            "scan_port_threshold": "18",
            "scan_window_seconds": "90",
        }
        correlation = situation_command(args, runtime)
        sensor = sensor_command(args, "4", runtime)
        self.assertEqual(correlation[correlation.index("--minimum-actions") + 1], "4")
        self.assertEqual(correlation[correlation.index("--window-minutes") + 1], "45")
        self.assertEqual(sensor[sensor.index("--unique-port-threshold") + 1], "18")
        self.assertEqual(sensor[sensor.index("--window-seconds") + 1], "90")

    def test_invalid_manual_database_value_falls_back_safely(self) -> None:
        self.assertEqual(validated_int_text("bad", 10, 3, 100), "10")
        self.assertEqual(validated_int_text("2", 10, 3, 100), "10")
        self.assertEqual(validated_int_text("18", 10, 3, 100), "18")


if __name__ == "__main__":
    unittest.main()
