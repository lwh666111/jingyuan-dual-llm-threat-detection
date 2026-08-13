import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from llm_analyzer_daemon import (  # noqa: E402
    _cached_review_ready_at,
    build_fusion_only_analysis,
)
from raw_llm_review import request_fingerprint  # noqa: E402


def packet(*, port=4000, uri="/api/search?q=test", body="q=test"):
    return {
        "host": f"127.0.0.1:{port}",
        "method": "POST",
        "uri": uri,
        "request_text": (
            "METHOD=POST\n"
            f"URI={uri}\n"
            f"HOST=127.0.0.1:{port}\n"
            "CONTENT_TYPE=application/x-www-form-urlencoded\n"
            f"REQUEST_BODY={body}\n"
        ),
    }


class ReviewFastPathTests(unittest.TestCase):
    def test_identical_request_has_stable_fingerprint(self):
        first = packet()
        second = dict(first, source_ip="203.0.113.10", event_time="2026-08-12 10:00:00")
        self.assertEqual(request_fingerprint(first), request_fingerprint(second))

    def test_port_uri_and_body_changes_all_miss(self):
        baseline = request_fingerprint(packet())
        self.assertNotEqual(baseline, request_fingerprint(packet(port=4001)))
        self.assertNotEqual(baseline, request_fingerprint(packet(uri="/api/login")))
        self.assertNotEqual(baseline, request_fingerprint(packet(body="q=changed")))

    def test_multiline_body_is_part_of_fingerprint(self):
        first = packet(body="<root>\n  <value>one</value>\n</root>")
        second = packet(body="<root>\n  <value>two</value>\n</root>")
        self.assertNotEqual(request_fingerprint(first), request_fingerprint(second))

    def test_content_type_is_part_of_fingerprint(self):
        first = packet()
        second = packet()
        second["request_text"] = second["request_text"].replace(
            "CONTENT_TYPE=application/x-www-form-urlencoded",
            "CONTENT_TYPE=application/json",
        )
        self.assertNotEqual(request_fingerprint(first), request_fingerprint(second))

    def test_cached_review_ready_at_naive(self):
        now = datetime(2026, 8, 13, 10, 0, 0)
        event_time = now - timedelta(seconds=2)
        self.assertEqual(_cached_review_ready_at(event_time, now), event_time + timedelta(seconds=5))

    def test_cached_review_ready_at_aware(self):
        tz = timezone(timedelta(hours=8))
        now = datetime(2026, 8, 13, 10, 0, 0, tzinfo=tz)
        event_time = now - timedelta(seconds=2)
        self.assertEqual(_cached_review_ready_at(event_time.isoformat(), now), event_time + timedelta(seconds=5))

    def test_cached_review_ready_at_future_uses_current_time(self):
        now = datetime(2026, 8, 13, 10, 0, 0)
        self.assertEqual(
            _cached_review_ready_at(now + timedelta(minutes=5), now),
            now + timedelta(seconds=5),
        )

    def test_cached_review_ready_at_old_uses_current_time(self):
        now = datetime(2026, 8, 13, 10, 0, 0)
        self.assertEqual(
            _cached_review_ready_at(now - timedelta(minutes=20), now),
            now + timedelta(seconds=5),
        )

    def test_cached_review_ready_at_invalid(self):
        self.assertIsNone(_cached_review_ready_at("not-an-iso-time"))

    def test_fusion_only_result_keeps_complete_detail_sections(self):
        row = {
            **packet(),
            "preliminary_decision": "attack_event",
            "attack_type": "SQL注入",
            "risk_level": "high",
            "final_score": 0.91,
            "source_ip": "203.0.113.10",
            "destination_ip": "192.0.2.20",
            "event_time": "2026-08-12 10:00:00",
        }
        context = {
            "fusion_evidence": ["SQL注入特征命中"],
            "poc_matches": [{"rule_name": "SQL注入布尔条件"}],
            "payload_models": [{"label": "SQL注入", "score": 0.98}],
        }
        result = build_fusion_only_analysis(row, {}, context)
        for key in (
            "verdict", "evidence", "analysis_reasoning", "potential_impact",
            "immediate_actions", "hardening_actions", "false_positive_notes", "summary",
        ):
            self.assertTrue(result.get(key), key)
        self.assertEqual(result["verdict"], "attack")


if __name__ == "__main__":
    unittest.main()
