from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from situation_neo4j_sync import Neo4jHTTPClient, build_statements  # noqa: E402


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return b'{"results":[],"errors":[]}'


class SituationNeo4jSyncTests(unittest.TestCase):
    def payload(self):
        return {
            "situation_id": "SIT-GRAPH-1",
            "source_ip": "203.0.113.8",
            "target_asset": "server-a",
            "risk_score": 0.87,
            "risk_level": "critical",
            "actions": [
                {"action_id": "A1", "action_type": "PORT_SCAN", "stage": "recon"},
                {"action_id": "A2", "action_type": "SSH_BRUTEFORCE", "stage": "credential"},
                {"action_id": "A3", "action_type": "SQL_INJECTION", "stage": "exploit"},
            ],
        }

    def test_statements_create_source_situation_actions_and_next_edges(self) -> None:
        statements = build_statements(self.payload())
        self.assertEqual(len(statements), 5)
        params = statements[0]["parameters"]
        self.assertEqual(params["source_ip"], "203.0.113.8")
        self.assertEqual(len(params["actions"]), 3)
        self.assertEqual(params["links"], [{"from_id": "A1", "to_id": "A2"}, {"from_id": "A2", "to_id": "A3"}])
        self.assertIn("GENERATED", statements[0]["statement"])
        self.assertIn("NEXT", statements[4]["statement"])

    @patch("urllib.request.urlopen", return_value=FakeResponse())
    def test_http_client_uses_transaction_endpoint_and_basic_auth(self, mocked_open) -> None:
        client = Neo4jHTTPClient("http://127.0.0.1:7474", "neo4j", "secret")
        client.execute(build_statements(self.payload()))
        request = mocked_open.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:7474/db/neo4j/tx/commit")
        self.assertTrue(request.headers["Authorization"].startswith("Basic "))
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(len(body["statements"]), 5)

    def test_non_http_url_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Neo4jHTTPClient("bolt://127.0.0.1:7687", "neo4j", "secret")


if __name__ == "__main__":
    unittest.main()
