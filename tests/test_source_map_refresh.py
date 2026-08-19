from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from dashboard_api_server import build_source_map_items  # noqa: E402


class SourceMapRefreshTests(unittest.TestCase):
    @patch("dashboard_api_server.resolve_region_for_event", side_effect=lambda _conn, _ip, region: region)
    def test_distinct_ips_are_not_collapsed_by_region(self, _resolver):
        base = datetime(2026, 8, 19, 12, 0, 0)
        rows = [
            {
                "source_ip": f"203.0.113.{index}",
                "source_region": "美国",
                "total": index,
                "latest_at": base + timedelta(seconds=index),
            }
            for index in range(1, 13)
        ]
        items = build_source_map_items(object(), rows)
        self.assertEqual(len(items), 12)
        self.assertEqual(len({item["source_ip"] for item in items}), 12)
        self.assertEqual(items[0]["source_ip"], "203.0.113.12")

    @patch("dashboard_api_server.resolve_region_for_event", side_effect=lambda _conn, _ip, region: region)
    def test_same_ip_is_merged_without_losing_latest_region(self, _resolver):
        items = build_source_map_items(
            object(),
            [
                {"source_ip": "198.51.100.7", "source_region": "德国", "total": 2, "latest_at": "2026-08-19 10:00:00"},
                {"source_ip": "198.51.100.7", "source_region": "新加坡", "total": 3, "latest_at": "2026-08-19 11:00:00"},
            ],
        )
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["total"], 5)
        self.assertEqual(items[0]["source_region"], "新加坡")
        self.assertEqual(items[0]["latest_at"], "2026-08-19 11:00:00")


if __name__ == "__main__":
    unittest.main()
