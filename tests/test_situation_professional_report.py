from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from situation_professional_report import build_snapshot, render_pdf  # noqa: E402


class ProfessionalSituationReportTests(unittest.TestCase):
    def test_snapshot_keeps_only_report_evidence_fields(self):
        snapshot = build_snapshot(
            {
                "situation_id": "SIT-1",
                "source_ip": "203.0.113.7",
                "actions": [{"action_id": "A1", "action_type": "SQL_INJECTION", "metadata": {"huge": "x" * 10000}}],
            }
        )
        self.assertEqual(snapshot["actions"][0]["action_type"], "SQL_INJECTION")
        self.assertNotIn("metadata", snapshot["actions"][0])

    def test_pdf_supports_chinese_and_escapes_payload_markup(self):
        try:
            import pymupdf
            import reportlab  # noqa: F401
        except ImportError:
            self.skipTest("PDF dependencies are not installed")
        snapshot = build_snapshot(
            {
                "situation_id": "SIT-中文-1",
                "source_ip": "203.0.113.7",
                "target_asset": "北京业务服务器<4000>",
                "risk_level": "critical",
                "risk_score": 0.92,
                "distinct_action_types": 4,
                "total_action_count": 12,
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.pdf"
            digest = render_pdf(output, snapshot, "# 执行摘要\n发现 SQL 注入与 <script>alert(1)</script> 探测。", [])
            self.assertEqual(len(digest), 64)
            doc = pymupdf.open(output)
            try:
                text = "\n".join(page.get_text() for page in doc)
                self.assertIn("专业态势感知分析报告", text)
                self.assertIn("执行摘要", text)
                self.assertGreaterEqual(len(doc), 2)
            finally:
                doc.close()


if __name__ == "__main__":
    unittest.main()
