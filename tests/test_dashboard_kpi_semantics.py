from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DashboardKpiSemanticsTests(unittest.TestCase):
    def test_frontend_uses_situation_and_defense_latency_metrics(self) -> None:
        source = (ROOT / "frontend_dashboard" / "public" / "app.js").read_text(encoding="utf-8")
        self.assertIn("今日识别态势数", source)
        self.assertIn("自动防御平均封禁时间", source)
        self.assertIn("kpis.today_situation_total", source)
        self.assertIn("kpis.avg_auto_defense_block_seconds", source)
        self.assertNotIn("攻击拦截成功率", source)
        self.assertNotIn("平均攻击响应时间", source)

    def test_api_uses_real_situation_and_firewall_latency_sources(self) -> None:
        source = (ROOT / "scripts" / "dashboard_api_server.py").read_text(encoding="utf-8")
        self.assertIn('"today_situation_total": today_situations', source)
        self.assertIn('"avg_auto_defense_block_seconds": round(avg_defense_seconds, 2)', source)
        self.assertIn("FROM attack_situations WHERE DATE(created_at)=CURDATE()", source)
        self.assertIn("FROM demo_fast_defense_audit", source)
        self.assertIn("decision='silent_block'", source)


if __name__ == "__main__":
    unittest.main()
