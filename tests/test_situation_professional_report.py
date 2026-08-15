from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from situation_professional_report import (  # noqa: E402
    _list_item_text,
    _sanitize_pdf_text,
    build_snapshot,
    call_bailian,
    render_pdf,
)


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return json.dumps(
            {"choices": [{"message": {"content": "# 专业报告\n" + "已完成证据分析。" * 100}}]},
            ensure_ascii=False,
        ).encode("utf-8")


class ProfessionalSituationReportTests(unittest.TestCase):
    @patch("urllib.request.urlopen", return_value=FakeResponse())
    def test_professional_api_timeout_is_bounded(self, mocked_urlopen):
        call_bailian(
            {"api_key": "test", "base_url": "https://example.invalid/v1", "timeout_seconds": 999},
            "qwen-plus",
            "system",
            {"situation_id": "SIT-1"},
            [],
        )
        self.assertEqual(mocked_urlopen.call_args.kwargs["timeout"], 240)

    def test_pdf_text_normalizes_emoji_and_circled_sequence_numbers(self):
        normalized = _sanitize_pdf_text("🎯 ① 目标：核查接口 2️⃣ 完成复核")
        self.assertEqual(normalized, "1. 目标：核查接口 2. 完成复核")
        self.assertEqual(_list_item_text("🎯 ① 目标：核查接口"), "目标：核查接口")

    def test_pdf_text_removes_unsupported_bmp_symbols(self):
        normalized = _sanitize_pdf_text("⚠️ 关键风险 ⭐ 当前证据 ✅ 已确认")
        self.assertEqual(normalized, "关键风险 当前证据 已确认")

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
                self.assertIn("附录 A 完整动作序列", text)
                self.assertIn("附录 D 报告生成信息", text)
                self.assertIn("本次报告未启用或未召回 RAG", text)
                self.assertGreaterEqual(len(doc), 2)
            finally:
                doc.close()

    def test_attack_chain_page_has_no_orphan_caption_or_sparse_body_page(self):
        try:
            import pymupdf
            import reportlab  # noqa: F401
        except ImportError:
            self.skipTest("PDF dependencies are not installed")
        snapshot = build_snapshot(
            {
                "situation_id": "SIT-LAYOUT-1",
                "source_ip": "203.0.113.9",
                "risk_level": "high",
                "risk_score": 0.88,
                "distinct_action_types": 4,
                "total_action_count": 20,
                "actions": [
                    {"sequence_no": index, "action_type": action, "stage": "EXPLOITATION", "action_count": 5}
                    for index, action in enumerate(
                        ["PORTSCAN", "SQL_INJECTION", "XSS", "COMMAND_INJECTION"], 1
                    )
                ],
            }
        )
        long_items = "\n".join(
            f"- 🎯 ① 目标：第 {index} 项核查目标接口、原始日志和响应证据。"
            for index in range(1, 28)
        )
        markdown = "\n".join(
            [
                "## 四、攻击态势分析",
                "《攻击链阶段演进示意图》",
                "### 4.1 攻击时间线总览",
                long_items,
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "layout.pdf"
            render_pdf(output, snapshot, markdown, [])
            doc = pymupdf.open(output)
            try:
                all_text = "\n".join(page.get_text() for page in doc)
                self.assertNotIn("《攻击链阶段演进示意图》", all_text)
                self.assertNotIn("\x00", all_text)
                self.assertIn("1. 目标：", all_text)
                self.assertNotIn("1. 1. 目标：", all_text)
                for page_index, page in enumerate(doc, 1):
                    if page_index == 1:
                        continue
                    self.assertGreater(len(page.get_text().strip()), 120, f"page {page_index} is unexpectedly sparse")
            finally:
                doc.close()

    def test_system_tables_replace_duplicate_model_tables_and_have_captions(self):
        try:
            import pymupdf
            import reportlab  # noqa: F401
        except ImportError:
            self.skipTest("PDF dependencies are not installed")
        snapshot = build_snapshot(
            {
                "situation_id": "SIT-TABLE-1",
                "source_ip": "203.0.113.8",
                "actions": [
                    {
                        "sequence_no": 1,
                        "action_type": "SQL_INJECTION",
                        "stage": "EXPLOITATION",
                        "target_interface": "/login",
                        "action_count": 1,
                        "confidence": 0.95,
                    }
                ],
            }
        )
        markdown = """## 一、基本信息
| 基本信息 | 内容说明 | 基本信息 | 内容说明 |
| --- | --- | --- | --- |
| 态势编号 | DUPLICATE_BASIC | 风险评分 | 0.95 |
## 四、攻击态势分析
### 4.1 攻击时间线总览
| 时间 | 攻击行为 | 目标 |
| --- | --- | --- |
| 2026-08-14 | DUPLICATE_TIMELINE | /login |
## 五、证据交叉验证
### 5.1 多源证据总览
| 关键判断 | 当前结论 |
| --- | --- |
| SQL注入 | 已确认 |
## 附录 A 完整动作序列
| 序号 | 攻击动作 | 证据引用 |
| --- | --- | --- |
| 1 | DUPLICATE_APPENDIX | RAW-1 |
"""
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "deduplicated.pdf"
            render_pdf(output, snapshot, markdown, [])
            doc = pymupdf.open(output)
            try:
                text = "\n".join(page.get_text() for page in doc)
                self.assertNotIn("DUPLICATE_BASIC", text)
                self.assertNotIn("DUPLICATE_TIMELINE", text)
                self.assertNotIn("DUPLICATE_APPENDIX", text)
                for caption in ("表1-1 基本信息", "图4-1 攻击链阶段演进示意图", "表4-1 攻击时间线总览", "表5-1 多源证据总览", "表5-2 关键判断交叉验证", "表A-1 完整动作序列"):
                    self.assertEqual(text.count(caption), 1, caption)
            finally:
                doc.close()


if __name__ == "__main__":
    unittest.main()
