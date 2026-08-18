from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from security_detection_v2 import BehaviorWindowAnalyzer, DetectionEngineV2, POCRuleEngine, fuse_detection  # noqa: E402
from sync_raw_http_logs import should_aggregate_behavior  # noqa: E402
from llm_analyzer_daemon import normalize_analysis, parse_model_content  # noqa: E402


class FastjsonAutoTypeDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rules = POCRuleEngine(ROOT / "rules" / "poc_rules.json")

    @staticmethod
    def event(type_value: str, uri: str = "/api/auth/login") -> dict:
        return {
            "method": "POST",
            "uri": uri,
            "content_type": "application/json",
            "body": json.dumps({"@type": type_value, "x": 1}, ensure_ascii=False),
            "source_ip": "198.51.100.31",
        }

    def test_user_payload_matches_fastjson_rule_on_any_endpoint(self) -> None:
        event = self.event("jar:file:.proc.self.fd.3!.fd3.pPFJXAm_4db.poc.Exception")
        matches = self.rules.match(event)
        self.assertIn("web-fastjson-autotype-dangerous-001", {item.rule_id for item in matches})
        self.assertIn("Fastjson反序列化探测", {item.attack_type for item in matches})

    def test_dangerous_variants_are_detected(self) -> None:
        values = [
            "jar:file:/tmp/exploit.jar!/demo.poc.Exploit",
            "file:/proc/self/fd/7/demo.poc.Exception",
            "com.sun.rowset.JdbcRowSetImpl;ldap://example.invalid/a",
        ]
        for value in values:
            with self.subTest(value=value):
                matches = self.rules.match(self.event(value))
                self.assertTrue(any(item.attack_type == "Fastjson反序列化探测" for item in matches))

    def test_safe_business_autotype_is_not_flagged(self) -> None:
        matches = self.rules.match(self.event("com.example.SafeDto", "/api/profile/save"))
        self.assertFalse(any(item.rule_id == "web-fastjson-autotype-dangerous-001" for item in matches))

    def test_bruteforce_window_cannot_override_explicit_fastjson_poc(self) -> None:
        event = self.event("jar:file:.proc.self.fd.4!.fd4.demo.poc.Exploit")
        matches = self.rules.match(event)
        behavior = {
            "score": 0.99,
            "type": "暴力破解",
            "features": {"behavior_model_supported": True, "login_fail_count": 80},
            "evidence": ["5分钟内登录失败80次"],
        }
        fusion = fuse_detection(event, {"label": "normal", "score": 0.0}, matches, behavior)
        detection = {
            "payload": {"label": "normal", "score": 0.0},
            "behavior": behavior,
            "poc_matches": [item.__dict__ for item in matches],
            "fusion": fusion,
        }
        self.assertEqual(fusion["decision"], "attack_event")
        self.assertEqual(fusion["attack_type"], "Fastjson反序列化探测")
        self.assertFalse(should_aggregate_behavior(fusion["attack_type"], detection))


class NormalPortalTrafficRegressionTests(unittest.TestCase):
    def test_successful_multi_page_session_is_not_a_scan(self) -> None:
        analyzer = BehaviorWindowAnalyzer(model_path=ROOT / "models" / "behavior_model_v2.joblib")
        result = {}
        for index in range(60):
            result = analyzer.observe(
                {
                    "source_ip": "198.51.100.50",
                    "timestamp": f"2026-08-18T10:{index // 12:02d}:{index % 12:02d}",
                    "method": "GET",
                    "uri": f"/api/v1/portal/page-{index % 20}",
                    "status_code": 200,
                    "body": "",
                },
                payload_or_rule_hit=index < 4,
            )
        self.assertEqual(result["type"], "normal")
        self.assertEqual(result["score"], 0.0)
        self.assertFalse(result["features"]["behavior_model_supported"])

    def test_normal_successful_login_stays_raw_only(self) -> None:
        engine = DetectionEngineV2()
        event = {
            "source_ip": "198.51.100.51",
            "timestamp": "2026-08-18T11:00:00",
            "method": "POST",
            "uri": "/api/v1/auth/login",
            "host": "ctf.ski:9178",
            "content_type": "application/json",
            "status_code": 200,
            "request_text": (
                'METHOD=POST\nURI=/api/v1/auth/login\nHOST=ctf.ski:9178\n'
                'CONTENT_TYPE=application/json\nSTATUS_CODE=200\n'
                'REQUEST_BODY={"email":"user@example.com","password":"ExamplePass123"}\n'
                'RESPONSE_EXCERPT={"accessToken":"jwt-value","user":{"id":"41"}}'
            ),
        }
        result = engine.detect(event)
        self.assertEqual(result["poc_matches"], [])
        self.assertEqual(result["fusion"]["decision"], "raw_only")
        self.assertEqual(result["fusion"]["payload_label"], "normal")
        self.assertTrue(result["fusion"]["successful_authentication"])


class EventCsvExportContractTests(unittest.TestCase):
    def test_csv_uses_current_chinese_fields_and_excel_bom(self) -> None:
        source = (ROOT / "frontend_dashboard" / "public" / "app.js").read_text(encoding="utf-8-sig")
        for label in ("事件ID", "来源地区", "攻击端口", "被攻击接口", "IP封禁情况", "响应耗时(ms)"):
            self.assertIn(label, source)
        self.assertIn('new Blob(["\\ufeff", lines.join("\\r\\n")]', source)

    def test_event_list_api_exposes_export_fields(self) -> None:
        source = (SCRIPTS / "dashboard_api_server.py").read_text(encoding="utf-8-sig")
        for field in ("e.source_region", "e.target_interface", "e.response_ms"):
            self.assertIn(field, source)


class TruncatedLlmRecoveryTests(unittest.TestCase):
    TRUNCATED_ATTACK = (
        '{"verdict":"attack","severity":"high","confidence":90,'
        '"evidence":["危险 AutoType 输入"],"analysis_reasoning":"输出在此处被截断'
    )

    @staticmethod
    def case_obj(*, strong_poc: bool) -> dict:
        poc_matches = []
        if strong_poc:
            poc_matches.append(
                {
                    "rule_id": "web-fastjson-autotype-dangerous-001",
                    "rule_name": "Fastjson 危险 AutoType 载荷",
                    "attack_type": "Fastjson反序列化探测",
                    "severity": "high",
                    "score": 0.96,
                }
            )
        return {
            "case_id": "b.test",
            "file_id": "1.1.test",
            "seq_id": 1,
            "source_ip": "198.51.100.31",
            "destination_ip": "192.0.2.10",
            "method": "POST",
            "uri": "/api/nday/fastjson/parse",
            "attack_type": "Fastjson反序列化探测",
            "request_text": (
                '{"@type":"jar:file:.proc.self.fd.3!.fd3.demo.poc.Exception","x":1}'
            ),
            "detection_context": {
                "fusion_score": 0.96 if strong_poc else 0.2,
                "poc_matches": poc_matches,
                "payload_models": [],
            },
        }

    def test_truncated_core_verdict_is_recovered(self) -> None:
        parsed = parse_model_content(self.TRUNCATED_ATTACK)
        self.assertTrue(parsed["_partial_recovered"])
        self.assertEqual(parsed["verdict"], "attack")
        self.assertEqual(parsed["severity"], "high")
        self.assertEqual(parsed["confidence"], 90.0)

    def test_strong_fastjson_evidence_allows_safe_recovery(self) -> None:
        analysis = normalize_analysis(
            parse_model_content(self.TRUNCATED_ATTACK),
            self.case_obj(strong_poc=True),
            "198.51.100.31",
            "192.0.2.10",
            "qwen2.5:1.5b",
        )
        self.assertEqual(analysis["verdict"], "attack")
        self.assertEqual(analysis["attack_method"], "Fastjson反序列化探测")
        self.assertAlmostEqual(analysis["confidence"], 0.9)

    def test_weak_evidence_cannot_promote_truncated_output(self) -> None:
        analysis = normalize_analysis(
            parse_model_content(self.TRUNCATED_ATTACK),
            self.case_obj(strong_poc=False),
            "198.51.100.31",
            "192.0.2.10",
            "qwen2.5:1.5b",
        )
        self.assertEqual(analysis["verdict"], "unknown")
        self.assertLess(analysis["confidence"], 0.5)

    def test_fastjson_result_filters_unrelated_and_unverified_advice(self) -> None:
        parsed = {
            "verdict": "attack",
            "severity": "high",
            "confidence": 0.92,
            "evidence": ["RCE_OK > exploit succeeded"],
            "analysis_reasoning": "危险 AutoType 类加载路径与 POC 规则一致。",
            "potential_impact": ["可能触发非预期类加载。"],
            "immediate_actions": ["核查 Fastjson 组件版本。"],
            "hardening_actions": ["使用参数化查询防止 SQL 注入", "使用 HTML Sanitizer", "关闭 AutoType"],
            "false_positive_notes": "",
            "knowledge_references": [],
            "summary": "危险 AutoType 请求。",
        }
        analysis = normalize_analysis(
            parsed,
            self.case_obj(strong_poc=True),
            "198.51.100.31",
            "192.0.2.10",
            "qwen2.5:1.5b",
        )
        advice = "\n".join(analysis["hardening_actions"])
        self.assertNotIn("SQL", advice)
        self.assertNotIn("Sanitizer", advice)
        self.assertTrue(any("Fastjson" in item or "AutoType" in item for item in analysis["hardening_actions"]))
        self.assertFalse(any("RCE_OK" in item for item in analysis["evidence"]))


if __name__ == "__main__":
    unittest.main()
