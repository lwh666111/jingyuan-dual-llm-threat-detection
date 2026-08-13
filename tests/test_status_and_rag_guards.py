import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import dashboard_api_server as api  # noqa: E402
from llm_analyzer_daemon import build_rag_references  # noqa: E402


class StatusAndRagGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        api._CPU_SAMPLE_CACHE.update({"value": None, "sampled_at": 0.0})

    def test_cpu_uses_short_blocking_sample_then_cache(self) -> None:
        fake_psutil = Mock()
        fake_psutil.cpu_percent.return_value = 17.25
        with patch.object(api, "psutil", fake_psutil):
            self.assertEqual(api._read_cpu_percent_cached(), 17.25)
            self.assertEqual(api._read_cpu_percent_cached(), 17.25)
        fake_psutil.cpu_percent.assert_called_once_with(interval=0.15)

    def test_rag_references_come_from_retrieved_rows(self) -> None:
        refs = build_rag_references(
            [
                {"doc_id": "DOC-8-CHUNK-2", "title": "SQL 注入防护"},
                {"doc_id": "DOC-9-CHUNK-1", "title": "XSS 输出编码"},
            ]
        )
        self.assertEqual(
            refs,
            ["RAG#1 SQL 注入防护（DOC-8-CHUNK-2）", "RAG#2 XSS 输出编码（DOC-9-CHUNK-1）"],
        )


if __name__ == "__main__":
    unittest.main()
