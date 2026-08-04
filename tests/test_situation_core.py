from __future__ import annotations

import sys
import unittest
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from situation_core import (  # noqa: E402
    SecurityAction,
    SituationCorrelator,
    action_from_attack_event,
    normalize_action_type,
    parse_timestamp,
)
from security_detection_v2 import POCRuleEngine  # noqa: E402


BASE = datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc)


def action(
    offset_minutes: int,
    action_type: str,
    *,
    source_ip: str = "203.0.113.8",
    target_asset: str = "server-a",
    count: int = 1,
) -> SecurityAction:
    return SecurityAction(
        action_id=f"A-{source_ip}-{offset_minutes}-{action_type}",
        source_ip=source_ip,
        target_asset=target_asset,
        action_type=action_type,
        occurred_at=BASE + timedelta(minutes=offset_minutes),
        confidence=0.9,
        severity="high",
        count=count,
    )


class SituationCoreTests(unittest.TestCase):
    def test_missing_poc_rules_fail_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing_rules.json"
            with self.assertRaisesRegex(FileNotFoundError, "POC rule file is missing"):
                POCRuleEngine(missing)

    def test_three_distinct_actions_form_one_situation(self) -> None:
        rows = [
            action(0, "PORT_SCAN", count=120),
            action(3, "SSH_BRUTEFORCE", count=18),
            action(9, "SQL_INJECTION", count=4),
        ]
        result = SituationCorrelator().correlate(rows, include_observing=False)
        self.assertEqual(len(result), 1)
        situation = result[0]
        self.assertEqual(situation.status, "open")
        self.assertEqual(situation.distinct_action_types, 3)
        self.assertEqual(situation.current_stage, "exploit")
        self.assertEqual([x.action_type for x in situation.actions], ["PORT_SCAN", "SSH_BRUTEFORCE", "SQL_INJECTION"])
        self.assertGreaterEqual(situation.risk_score, 0.68)

    def test_duplicate_actions_aggregate_but_do_not_inflate_diversity(self) -> None:
        rows = [action(0, "PORT_SCAN", count=100), action(1, "PORT_SCAN", count=80), action(2, "SERVICE_PROBE")]
        result = SituationCorrelator().correlate(rows)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].status, "observing")
        self.assertEqual(result[0].distinct_action_types, 2)
        self.assertEqual(result[0].actions[0].count, 180)

    def test_inactivity_splits_sessions(self) -> None:
        rows = [action(0, "PORT_SCAN"), action(2, "SSH_BRUTEFORCE"), action(25, "SQL_INJECTION")]
        result = SituationCorrelator(inactivity_minutes=15).correlate(rows)
        self.assertEqual(len(result), 2)
        self.assertTrue(all(x.status == "observing" for x in result))

    def test_different_ips_are_isolated(self) -> None:
        rows = [
            action(0, "PORT_SCAN", source_ip="203.0.113.8"),
            action(1, "SSH_BRUTEFORCE", source_ip="203.0.113.8"),
            action(2, "SQL_INJECTION", source_ip="203.0.113.8"),
            action(0, "PORT_SCAN", source_ip="198.51.100.9"),
            action(1, "XSS", source_ip="198.51.100.9"),
        ]
        result = SituationCorrelator().correlate(rows)
        self.assertEqual(len(result), 2)
        self.assertEqual({x.source_ip for x in result}, {"203.0.113.8", "198.51.100.9"})

    def test_out_of_order_input_is_sorted(self) -> None:
        rows = [action(8, "SQL_INJECTION"), action(0, "PORT_SCAN"), action(4, "SSH_BRUTEFORCE")]
        situation = SituationCorrelator().correlate(rows)[0]
        graph = situation.as_dict()
        self.assertEqual([x["action_type"] for x in graph["actions"]], ["PORT_SCAN", "SSH_BRUTEFORCE", "SQL_INJECTION"])
        self.assertEqual([x["gap_seconds"] for x in graph["actions"]], [0, 240, 240])

    def test_minimum_action_count_is_configurable(self) -> None:
        rows = [action(0, "PORT_SCAN"), action(1, "SSH_BRUTEFORCE"), action(2, "SQL_INJECTION")]
        situation = SituationCorrelator(minimum_distinct_actions=4).correlate(rows)[0]
        self.assertEqual(situation.status, "observing")

    def test_attack_event_adapter(self) -> None:
        row = {
            "event_id": "EVT100",
            "occurred_at": "2026-08-03T12:00:00Z",
            "source_ip": "203.0.113.8",
            "target_interface": "/api/login",
            "attack_type": "SQL注入",
            "risk_level": "high",
            "confidence": 0.96,
            "evidence_json": '["union select"]',
        }
        converted = action_from_attack_event(row)
        self.assertEqual(converted.action_type, "SQL_INJECTION")
        self.assertEqual(converted.protocol, "HTTP")
        self.assertEqual(converted.evidence_refs, ["EVT100"])
        self.assertEqual(converted.metadata["evidence"], ["union select"])

    def test_alias_normalization(self) -> None:
        self.assertEqual(normalize_action_type("SSH爆破"), "SSH_BRUTEFORCE")
        self.assertEqual(normalize_action_type("疑似扫描探测"), "SERVICE_PROBE")
        self.assertEqual(normalize_action_type("危险文件上传"), "FILE_UPLOAD")

    def test_naive_server_timestamp_is_interpreted_as_shanghai_time(self) -> None:
        parsed = parse_timestamp("2026-08-03 12:00:00")
        self.assertEqual(parsed.isoformat(), "2026-08-03T04:00:00+00:00")

    def test_aggregation_does_not_mutate_original_metadata(self) -> None:
        first = action(0, "PORT_SCAN")
        first.metadata = {"ports": [22]}
        second = action(1, "PORT_SCAN")
        second.metadata = {"ports": [80]}
        situation = SituationCorrelator().correlate([first, second])[0]
        situation.actions[0].metadata["ports"].append(443)
        self.assertEqual(first.metadata, {"ports": [22]})


if __name__ == "__main__":
    unittest.main()
