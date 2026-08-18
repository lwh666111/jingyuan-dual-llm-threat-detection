import io
import json
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import llm_analyzer_daemon as daemon  # noqa: E402
import raw_llm_review  # noqa: E402


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload, ensure_ascii=False).encode("utf-8")


class ExternalLlmReviewTests(unittest.TestCase):
    def test_exact_fingerprint_never_calls_external_llm(self):
        class FakeConn:
            def close(self):
                pass

        row = {
            "event_id": "RAW1_1_1",
            "case_id": "raw:1.1.1:1",
            "event_time": datetime.now() - timedelta(seconds=6),
            "file_id": "1.1.1",
            "seq_id": 1,
            "method": "GET",
            "uri": "/api/search?q=test",
            "host": "127.0.0.1:4000",
            "status_code": 200,
            "source_ip": "127.0.0.1",
            "destination_ip": "127.0.0.1",
            "attack_type": "XSS跨站脚本",
            "risk_level": "high",
            "request_text": "METHOD=GET",
            "response_text": "STATUS_CODE=200",
        }
        cached = {
            "fingerprint": "fp-1",
            "model_name": "qwen2.5:3b",
            "analysis": {
                "verdict": "attack",
                "severity": "high",
                "confidence": 0.99,
                "attack_method": "XSS跨站脚本",
                "summary": "指纹预设结果",
            },
        }
        args = SimpleNamespace(raw_review_max_attempts=3, model="qwen2.5:3b")
        with (
            patch.object(daemon, "open_review_conn", return_value=FakeConn()),
            patch.object(raw_llm_review, "claim_next_review", return_value=row),
            patch.object(raw_llm_review, "detection_context", return_value={}),
            patch.object(raw_llm_review, "realtime_llm_enabled", return_value=True),
            patch.object(raw_llm_review, "find_cached_review", return_value=cached),
            patch.object(raw_llm_review, "complete_review", return_value=True) as complete,
            patch.object(raw_llm_review, "mark_cache_hit") as mark_hit,
            patch.object(daemon, "call_openai_compatible_chat") as cloud_call,
        ):
            result = daemon.process_next_raw_review("prompt", {"type": "object"}, args)

        self.assertIn("cached=1", result)
        complete.assert_called_once()
        mark_hit.assert_called_once()
        self.assertEqual(mark_hit.call_args.args[1], "fp-1")
        cloud_call.assert_not_called()

    def test_rag_context_is_sent_in_openai_compatible_request(self):
        captured = {}

        def fake_urlopen(request, timeout):
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["timeout"] = timeout
            return _Response(
                {
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {"verdict": "attack", "summary": "命中知识库证据"},
                                    ensure_ascii=False,
                                )
                            }
                        }
                    ]
                }
            )

        payload = daemon.build_user_payload(
            {"case_id": "case-1", "uri": "/api/login"},
            "REQUEST_BODY={'x':'1'}",
            "STATUS_CODE=500",
            "1.2.3.4",
            "10.0.0.1",
            rag_context="[RAG#1] Fastjson AutoType 风险与升级建议",
            detection_context={"fusion_score": 0.91},
        )
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            parsed, _ = daemon.call_openai_compatible_chat(
                config={
                    "api_key": "test-key",
                    "base_url": "https://example.invalid",
                    "model": "test-model",
                    "timeout_seconds": 12,
                },
                system_prompt="仅返回JSON",
                user_payload=payload,
                schema_obj={"type": "object"},
                temperature=0.1,
                timeout_sec=30,
            )

        self.assertEqual(parsed["verdict"], "attack")
        self.assertEqual(captured["body"]["thinking"], {"type": "disabled"})
        self.assertIn("Fastjson AutoType", captured["body"]["messages"][1]["content"])
        self.assertEqual(captured["body"]["response_format"], {"type": "json_object"})
        self.assertEqual(captured["timeout"], 12)

    def test_private_key_is_never_embedded_in_request_body(self):
        captured = {}

        def fake_urlopen(request, timeout):
            captured["request"] = request
            return _Response({"choices": [{"message": {"content": '{"verdict":"benign"}'}}]})

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            daemon.call_openai_compatible_chat(
                config={"api_key": "private-test-key", "base_url": "https://example.invalid"},
                system_prompt="Return JSON",
                user_payload="{}",
                schema_obj={"type": "object"},
                temperature=0,
                timeout_sec=10,
            )
        self.assertNotIn(b"private-test-key", captured["request"].data)
        self.assertEqual(captured["request"].headers["Authorization"], "Bearer private-test-key")


if __name__ == "__main__":
    unittest.main()
