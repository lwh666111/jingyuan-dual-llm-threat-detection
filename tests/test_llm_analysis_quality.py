import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from llm_analyzer_daemon import normalize_analysis  # noqa: E402


class LlmAnalysisQualityTests(unittest.TestCase):
    def test_schema_requires_actionable_analysis_sections(self) -> None:
        schema = json.loads((ROOT / "llm/schemas/analysis.schema.json").read_text(encoding="utf-8"))
        required = set(schema["required"])
        self.assertTrue(
            {
                "analysis_reasoning",
                "potential_impact",
                "immediate_actions",
                "hardening_actions",
                "false_positive_notes",
                "knowledge_references",
            }.issubset(required)
        )

    def test_normalization_preserves_detailed_llm_content(self) -> None:
        parsed = {
            "verdict": "attack",
            "severity": "high",
            "confidence": 0.94,
            "summary": "载荷具备反射型 XSS 语义，但尚无浏览器执行证据。",
            "evidence": ["请求载荷：q 参数包含 script 标签", "响应证据：载荷被原样反射"],
            "analysis_reasoning": "请求与响应形成输入反射闭环，支持攻击尝试结论。",
            "potential_impact": ["若在未编码页面渲染，可执行攻击者脚本"],
            "immediate_actions": ["临时拦截 q 参数中的可执行标签"],
            "hardening_actions": ["按 HTML 上下文进行输出编码"],
            "false_positive_notes": "需确认响应字段是否进入 HTML DOM。",
            "knowledge_references": ["RAG#1 反射型 XSS"],
        }
        case = {
            "case_id": "raw:test",
            "method": "GET",
            "uri": "/api/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "source_ip": "203.0.113.10",
            "destination_ip": "192.0.2.10",
            "attack_type": "XSS跨站脚本",
            "v2_risk_level": "high",
            "request_text": "GET /api/search?q=<script>alert(1)</script>",
            "response_text": "<script>alert(1)</script>",
        }
        result = normalize_analysis(parsed, case, "", "", "qwen-test")
        self.assertEqual(result["summary"], parsed["summary"])
        self.assertEqual(result["analysis_reasoning"], parsed["analysis_reasoning"])
        self.assertEqual(result["immediate_actions"], parsed["immediate_actions"])
        self.assertIn(parsed["hardening_actions"][0], result["hardening_actions"])
        self.assertTrue(any("输出编码" in item for item in result["hardening_actions"]))
        self.assertEqual(result["knowledge_references"], parsed["knowledge_references"])

    def test_hallucinated_evidence_is_removed(self) -> None:
        parsed = {
            "verdict": "benign",
            "severity": "low",
            "confidence": 0.85,
            "evidence": ["请求载荷：参数 q 出现可执行 script 标签"],
            "analysis_reasoning": "参数 q 中的 script 标签显示攻击意图。",
            "summary": "正常请求。",
        }
        case = {
            "method": "POST",
            "uri": "/api/profile",
            "source_ip": "203.0.113.11",
            "request_text": '{"nickname":"Alice","bio":"security researcher"}',
            "response_text": '{"ok":true}',
            "detection_context": {
                "payload_models": [{"label": "normal", "score": 0.18}],
                "poc_matches": [],
            },
        }
        result = normalize_analysis(parsed, case, "", "", "qwen-test")
        self.assertNotIn("script", " ".join(result["evidence"]).lower())
        self.assertIn("一致性校验移除", result["analysis_reasoning"])

    def test_packet_facts_cannot_be_overwritten_by_llm(self) -> None:
        parsed = {
            "verdict": "attack",
            "source_ip": "8.8.8.8",
            "attack_interface": "/hallucinated",
            "attack_method": "SQL注入",
            "severity": "high",
            "confidence": 0.8,
            "evidence": [],
        }
        case = {
            "method": "GET",
            "uri": "/real",
            "source_ip": "203.0.113.10",
            "destination_ip": "192.0.2.10",
            "attack_type": "XSS跨站脚本",
        }
        result = normalize_analysis(parsed, case, "", "", "qwen-test")
        self.assertEqual(result["source_ip"], "203.0.113.10")
        self.assertEqual(result["attack_interface"], "/real")
        self.assertEqual(result["attack_method"], "XSS跨站脚本")

    def test_benign_verdict_conflicting_with_strong_evidence_is_not_published(self) -> None:
        parsed = {
            "verdict": "benign",
            "severity": "low",
            "confidence": 0.97,
            "evidence": ["Payload 模型：XSS 0.99", "POC 规则：反射型 XSS 命中"],
            "summary": "正常流量。",
        }
        case = {
            "method": "GET",
            "uri": "/api/search?q=<script>alert(1)</script>",
            "attack_type": "XSS跨站脚本",
            "request_text": "<script>alert(1)</script>",
            "detection_context": {
                "fusion_score": 0.93,
                "payload_models": [{"label": "XSS跨站脚本", "score": 0.99}],
                "poc_matches": [{"rule_id": "web-xss-reflected-001"}],
            },
        }
        result = normalize_analysis(parsed, case, "203.0.113.10", "192.0.2.10", "qwen-test")
        self.assertEqual(result["verdict"], "unknown")
        self.assertLess(result["confidence"], 0.5)
        self.assertIn("转入人工复核", result["summary"])


if __name__ == "__main__":
    unittest.main()
