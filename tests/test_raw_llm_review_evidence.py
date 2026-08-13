import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from raw_llm_review import (  # noqa: E402
    claim_next_review,
    complete_review,
    find_cached_review,
    normalize_review_evidence,
    request_fingerprint,
)


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.current = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=None):
        self.current = " ".join(sql.split())
        self.conn.executions.append((self.current, params))
        if self.conn.fail_on and self.conn.fail_on in self.current:
            raise RuntimeError("injected write failure")

    def fetchone(self):
        return self.conn.fetchone_results.pop(0) if self.conn.fetchone_results else None

    def fetchall(self):
        return []


class FakeConnection:
    def __init__(self, fetchone_results=None, fail_on=None):
        self.fetchone_results = list(fetchone_results or [])
        self.fail_on = fail_on
        self.executions = []
        self.begin_count = 0
        self.commit_count = 0
        self.rollback_count = 0

    def cursor(self):
        return FakeCursor(self)

    def begin(self):
        self.begin_count += 1

    def commit(self):
        self.commit_count += 1

    def rollback(self):
        self.rollback_count += 1


class RawLlmReviewEvidenceTests(unittest.TestCase):
    def test_keeps_explicit_llm_evidence(self) -> None:
        result = normalize_review_evidence(
            {"evidence": ["命中反射型 XSS 载荷"]}, row={}, summary="确认攻击"
        )
        self.assertEqual(result, ["命中反射型 XSS 载荷"])

    def test_falls_back_to_fusion_evidence(self) -> None:
        result = normalize_review_evidence(
            {},
            row={"evidence_json": json.dumps(["POC web-xss-reflected-001 命中"], ensure_ascii=False)},
            summary="确认攻击",
        )
        self.assertEqual(result, ["融合证据：POC web-xss-reflected-001 命中"])

    def test_falls_back_to_llm_summary(self) -> None:
        result = normalize_review_evidence({}, row={}, summary="请求包含可执行脚本并被响应反射")
        self.assertEqual(result, ["大模型研判说明：请求包含可执行脚本并被响应反射"])

    def test_historical_cache_lookup_uses_strict_fingerprint_filters(self) -> None:
        row = {
            "host": "127.0.0.1:4000",
            "method": "POST",
            "uri": "/api/search",
            "request_text": "CONTENT_TYPE=text/plain\nREQUEST_BODY=test",
        }
        fingerprint = request_fingerprint(row)
        conn = FakeConnection(
            fetchone_results=[None, {"fingerprint": fingerprint, "template_json": '{"verdict":"attack"}', "model_name": "m"}]
        )

        cached = find_cached_review(conn, row)

        historical_sql, params = conn.executions[1]
        self.assertIn("a.llm_status='done'", historical_sql)
        self.assertIn("a.review_source='realtime_llm'", historical_sql)
        self.assertIn("a.request_fingerprint IS NOT NULL", historical_sql)
        self.assertIn("a.request_fingerprint=%s", historical_sql)
        self.assertNotIn("LIMIT 200", historical_sql)
        self.assertEqual(params, (fingerprint,))
        self.assertEqual(cached["analysis"]["verdict"], "attack")

    def test_stale_claim_recovery_decrements_attempts(self) -> None:
        conn = FakeConnection()

        self.assertIsNone(claim_next_review(conn, max_attempts=3))

        recovery_sql = conn.executions[0][0]
        self.assertIn("attempts=GREATEST(0,attempts-1)", recovery_sql)
        self.assertEqual(conn.begin_count, 1)
        self.assertEqual(conn.commit_count, 1)
        self.assertEqual(conn.rollback_count, 0)

    def test_complete_review_commits_all_final_writes(self) -> None:
        conn = FakeConnection()
        row = {
            "case_id": "case-1", "event_id": "event-1", "host": "127.0.0.1:4000",
            "method": "POST", "uri": "/api/search", "request_text": "REQUEST_BODY=test",
        }

        complete_review(
            conn, row=row, analysis={"verdict": "benign"}, raw_content="ignored",
            model_name="m", rag_enabled=False, rag_hits=0, latency_ms=1,
        )

        self.assertEqual(conn.begin_count, 1)
        self.assertEqual(conn.commit_count, 1)
        self.assertEqual(conn.rollback_count, 0)

    def test_complete_review_rolls_back_on_final_write_failure(self) -> None:
        conn = FakeConnection(fail_on="UPDATE llm_review_jobs")
        row = {
            "case_id": "case-1", "event_id": "event-1", "host": "127.0.0.1:4000",
            "method": "POST", "uri": "/api/search", "request_text": "REQUEST_BODY=test",
        }

        with self.assertRaisesRegex(RuntimeError, "injected write failure"):
            complete_review(
                conn, row=row, analysis={"verdict": "benign"}, raw_content="ignored",
                model_name="m", rag_enabled=False, rag_hits=0, latency_ms=1,
            )

        self.assertEqual(conn.begin_count, 1)
        self.assertEqual(conn.commit_count, 0)
        self.assertEqual(conn.rollback_count, 1)


if __name__ == "__main__":
    unittest.main()
