import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from rag_service import (
    _bm25_scores,
    analyze_security_query,
    chunk_document,
    diversify_candidates,
    evaluate_retrieval_items,
    expand_security_query,
    load_api_config,
    parse_document,
    safe_filename,
    retrieval_gate,
)


class RagServiceTests(unittest.TestCase):
    def test_semantic_chunking_keeps_heading_path(self):
        text = "# SQL 注入\n" + ("参数化查询可以防止 SQL 注入。" * 80) + "\n# XSS\n输出编码与 CSP。"
        chunks = chunk_document(text, method="semantic", size=260, overlap=40)
        self.assertGreater(len(chunks), 2)
        self.assertEqual(chunks[0]["title_path"], "SQL 注入")
        self.assertTrue(any(row["title_path"] == "XSS" for row in chunks))

    def test_fixed_chunking_has_overlap(self):
        chunks = chunk_document("A" * 1000, method="fixed", size=300, overlap=50)
        self.assertGreaterEqual(len(chunks), 4)
        self.assertTrue(all(len(row["content"]) <= 300 for row in chunks))

    def test_markdown_parse_is_utf8_bom_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "知识.md"
            path.write_bytes("\ufeff# 标题\n中文正文".encode("utf-8"))
            self.assertIn("中文正文", parse_document(path))

    def test_bm25_prefers_relevant_security_chunk(self):
        rows = [
            {"id": 1, "title_path": "SQL 注入", "content": "parameterized queries prepared statements SQL injection"},
            {"id": 2, "title_path": "图片上传", "content": "image resize thumbnail jpeg"},
        ]
        scores = _bm25_scores("SQL injection prepared statement", rows)
        self.assertGreater(scores[1], scores.get(2, 0))

    def test_local_api_config_does_not_require_workspace_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "api.json"
            path.write_text(
                json.dumps(
                    {
                        "api_key": "test-key",
                        "base_url": "https://workspace.example/compatible-mode/v1",
                        "rerank_url": "https://workspace.example/compatible-api/v1/reranks",
                    }
                ),
                encoding="utf-8",
            )
            config = load_api_config(path)
        self.assertEqual(config["embedding_model"], "text-embedding-v4")
        self.assertEqual(config["embedding_dimensions"], 1024)

    def test_safe_filename_removes_path_components(self):
        name = safe_filename("../../危险 文档?.md")
        self.assertNotIn("/", name)
        self.assertNotIn("?", name)

    def test_eval_requires_expected_document_and_one_keyword(self):
        items = [{"document_name": "OWASP SQL Injection.md", "content": "使用参数化查询和预编译语句。"}]
        passed = evaluate_retrieval_items(items, "参数化查询,白名单", "OWASP")
        failed = evaluate_retrieval_items(items, "CSP", "MITRE")
        self.assertTrue(passed["passed"])
        self.assertFalse(failed["passed"])
        self.assertIn("期望来源文档", failed["reason"])

    def test_security_query_expands_nmap_syn_evidence(self):
        expanded = expand_security_query("Nmap 向多个端口发送 SYN 探测包")
        self.assertIn("PortScan", expanded)
        self.assertIn("端口扫描", expanded)

    def test_incident_gate_rejects_security_topic_without_evidence(self):
        result = retrieval_gate("账号登录失败应该如何处理", "incident")
        self.assertFalse(result["accepted"])
        self.assertIn("证据", result["reason"])

    def test_incident_gate_accepts_payload_and_request_context(self):
        result = retrieval_gate("POST /login password=' OR 1=1 -- 来源IP 10.0.0.8", "incident")
        self.assertTrue(result["accepted"])
        self.assertGreater(result["profile"]["incident_evidence_count"], 0)

    def test_incident_gate_rejects_normal_http_request(self):
        result = retrieval_gate(
            "POST /login username=alice password=correcthorse Status=200 Source IP 10.0.0.3",
            "incident",
        )
        self.assertFalse(result["accepted"])
        self.assertIn("攻击特征", result["reason"])

    def test_knowledge_gate_rejects_out_of_domain_question(self):
        result = retrieval_gate("明天巴黎天气怎么样", "knowledge")
        self.assertFalse(result["accepted"])

    def test_query_profile_marks_random_noise(self):
        result = analyze_security_query("qzxvblorp9f3kmoonxj77")
        self.assertTrue(result["gibberish"])

    def test_eval_negative_case_requires_no_results(self):
        rejected = evaluate_retrieval_items([], expected_no_match=True)
        leaked = evaluate_retrieval_items([{"content": "irrelevant"}], expected_no_match=True)
        self.assertTrue(rejected["passed"])
        self.assertFalse(leaked["passed"])

    def test_eval_enforces_expected_top_k(self):
        items = [
            {"document_name": "Other.md", "content": "unrelated"},
            {"document_name": "OWASP.md", "content": "SQL 注入参数化查询"},
        ]
        top_one = evaluate_retrieval_items(items, "参数化查询", "OWASP", expected_top_k=1)
        top_three = evaluate_retrieval_items(items, "参数化查询", "OWASP", expected_top_k=3)
        self.assertFalse(top_one["passed"])
        self.assertTrue(top_three["passed"])
        self.assertEqual(top_three["relevant_rank"], 2)

    def test_candidate_diversity_limits_single_document(self):
        rows = [{"id": i, "document_id": 1} for i in range(20)] + [{"id": 100, "document_id": 2}]
        selected = diversify_candidates(rows, per_document=3, limit=10)
        self.assertEqual(sum(1 for row in selected if row["document_id"] == 1), 3)
        self.assertTrue(any(row["document_id"] == 2 for row in selected))


if __name__ == "__main__":
    unittest.main()
