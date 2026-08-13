from __future__ import annotations

import io
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

from situation_ai import analyze_situation, call_bailian, fallback_report  # noqa: E402


SITUATION = {
    "situation_id": "SIT-TEST",
    "source_ip": "203.0.113.8",
    "target_asset": "server-a",
    "risk_score": 0.84,
    "risk_level": "critical",
    "total_action_count": 142,
    "actions": [
        {"sequence_no": 1, "action_type": "PORT_SCAN", "action_label": "端口扫描", "stage": "recon", "action_count": 120},
        {"sequence_no": 2, "action_type": "SSH_BRUTEFORCE", "action_label": "SSH 爆破", "stage": "credential", "action_count": 18},
        {"sequence_no": 3, "action_type": "SQL_INJECTION", "action_label": "SQL 注入", "stage": "exploit", "action_count": 4},
    ],
}


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return json.dumps(self.payload, ensure_ascii=False).encode("utf-8")


class SituationAITests(unittest.TestCase):
    def api_config_path(self, directory: str) -> Path:
        path = Path(directory) / "ai_api.local.json"
        path.write_text(
            json.dumps(
                {
                    "api_key": "test-key",
                    "base_url": "https://workspace.example/compatible-mode/v1",
                    "report_model": "qwen-plus",
                    "situation_report_model": "qwen-turbo",
                    "timeout_seconds": 30,
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_fallback_is_explicit_and_actionable(self) -> None:
        report = fallback_report(SITUATION, "offline")
        self.assertIn("端口扫描 → SSH 爆破 → SQL 注入", report["narrative"])
        self.assertEqual(report["generated_by"], "deterministic_fallback")
        self.assertGreaterEqual(len(report["protection_measures"]), 5)
        self.assertGreaterEqual(len(report["investigation_steps"]), 4)
        self.assertGreaterEqual(len(report["evidence_limitations"]), 2)
        self.assertIn("暂无足以确认成功入侵", report["compromise_assessment"])

    def test_negative_success_wording_is_not_rejected(self) -> None:
        from situation_ai import validate_report

        report = {
            "narrative": "攻击者进行了多阶段尝试。",
            "analysis": "现有证据只证明请求发生。",
            "conclusion": "未发现登录成功，不能确认成功利用。",
            "likely_intent": "尝试获取未授权权限",
            "protection_measures": ["限制来源地址"],
            "improvement_suggestions": ["补充主机审计"],
            "evidence_assessment": ["来源一致", "时间连续"],
            "confidence": 0.9,
        }
        validated = validate_report(report)
        self.assertIn("未发现登录成功", validated["conclusion"])
        self.assertEqual(validated["evidence_assessment"], "来源一致；时间连续")

    @patch("urllib.request.urlopen")
    def test_valid_bailian_json_is_accepted(self, mocked_urlopen) -> None:
        mocked_urlopen.return_value = FakeResponse(
            {
                "choices": [{"message": {"content": json.dumps({
                        "narrative": "先扫描后爆破并尝试注入。",
                        "analysis": "三类证据来自同一来源且时间连续。",
                        "conclusion": "连续攻击尝试，暂无成功入侵证据。",
                        "likely_intent": "获取未授权访问权限",
                        "protection_measures": ["限制来源 IP"],
                        "improvement_suggestions": ["启用 MFA"],
                        "confidence": 0.91,
                    }, ensure_ascii=False)}}]
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            report, status = analyze_situation(
                SITUATION,
                ollama_url="http://127.0.0.1:11434",
                model="unused-local-model",
                rag_db_path=ROOT / "does-not-exist.db",
                rag_api_config=self.api_config_path(tmp),
                rag_enabled=False,
            )
        self.assertEqual(status, "complete")
        self.assertEqual(report["generated_by"], "bailian")
        self.assertEqual(report["model_name"], "qwen-turbo")
        self.assertIn("暂无成功入侵证据", report["conclusion"])
        sent = json.loads(mocked_urlopen.call_args.args[0].data.decode("utf-8"))
        self.assertEqual(sent["model"], "qwen-turbo")
        self.assertIn("/chat/completions", mocked_urlopen.call_args.args[0].full_url)

    @patch("urllib.request.urlopen", side_effect=OSError("offline"))
    def test_bailian_failure_returns_fallback(self, _mocked_urlopen) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report, status = analyze_situation(
                SITUATION,
                ollama_url="http://127.0.0.1:11434",
                model="unused-local-model",
                rag_db_path=ROOT / "does-not-exist.db",
                rag_api_config=self.api_config_path(tmp),
            )
        self.assertEqual(status, "fallback")
        self.assertIn("offline", report["fallback_reason"])

    @patch("urllib.request.urlopen")
    def test_english_bailian_report_falls_back_to_chinese(self, mocked_urlopen) -> None:
        mocked_urlopen.return_value = FakeResponse(
            {
                "choices": [{"message": {"content": json.dumps(
                    {
                        "narrative": "The attacker scanned and attempted injection.",
                        "analysis": "The actions came from one source.",
                        "conclusion": "This is an attack attempt.",
                        "likely_intent": "Gain unauthorized access.",
                        "protection_measures": ["Block the source IP."],
                        "improvement_suggestions": ["Enable MFA."],
                        "confidence": 0.8,
                    }
                )}}]
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            report, status = analyze_situation(
                SITUATION, ollama_url="unused", model="unused",
                rag_db_path=ROOT / "does-not-exist.db", rag_api_config=self.api_config_path(tmp),
            )
        self.assertEqual(status, "fallback")
        self.assertIn("连续攻击态势", report["conclusion"])

    @patch("urllib.request.urlopen")
    def test_unsupported_success_claim_falls_back(self, mocked_urlopen) -> None:
        mocked_urlopen.return_value = FakeResponse(
            {
                "choices": [{"message": {"content": json.dumps(
                    {
                        "narrative": "攻击者成功执行了一次 XSS 攻击。",
                        "analysis": "现有请求证明来源相同。",
                        "conclusion": "攻击成功利用了目标接口。",
                        "likely_intent": "尝试获取未授权访问权限",
                        "protection_measures": ["限制来源 IP"],
                        "improvement_suggestions": ["启用 MFA"],
                        "confidence": 0.8,
                    },
                    ensure_ascii=False,
                )}}]
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            report, status = analyze_situation(
                SITUATION, ollama_url="unused", model="unused",
                rag_db_path=ROOT / "does-not-exist.db", rag_api_config=self.api_config_path(tmp),
            )
        self.assertEqual(status, "fallback")
        self.assertNotIn("成功执行", report["narrative"])


if __name__ == "__main__":
    unittest.main()
