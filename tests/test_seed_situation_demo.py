import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from seed_situation_demo import SCENARIOS, build_actions  # noqa: E402
from situation_core import SituationCorrelator  # noqa: E402


class SituationDemoSeedTests(unittest.TestCase):
    def test_all_scenarios_form_comprehensive_attack_chains(self) -> None:
        now = datetime(2026, 8, 3, 9, 45, 12, 123000, tzinfo=timezone.utc)
        correlator = SituationCorrelator(3, 30, 15)

        situations = []
        for index, scenario in enumerate(SCENARIOS, start=1):
            actions = build_actions(index, scenario, now)
            linked = correlator.correlate(actions, include_observing=False)
            self.assertEqual(1, len(linked))
            self.assertGreaterEqual(linked[0].distinct_action_types, 3)
            situations.append(linked[0])

        self.assertEqual(6, len(situations))
        self.assertEqual(6, len({item.source_ip for item in situations}))

    def test_mysql_millisecond_round_trip_keeps_situation_id(self) -> None:
        now = datetime(2026, 8, 3, 9, 45, 12, 123000, tzinfo=timezone.utc)
        correlator = SituationCorrelator(3, 30, 15)
        actions = build_actions(1, SCENARIOS[0], now)
        before = correlator.correlate(actions, include_observing=False)[0]

        for action in actions:
            action.occurred_at = action.occurred_at.replace(
                microsecond=(action.occurred_at.microsecond // 1000) * 1000
            )
            action.last_seen_at = action.last_seen_at.replace(
                microsecond=(action.last_seen_at.microsecond // 1000) * 1000
            )
        after = correlator.correlate(actions, include_observing=False)[0]

        self.assertEqual(before.situation_id, after.situation_id)
        self.assertEqual(before.sequence_hash, after.sequence_hash)


if __name__ == "__main__":
    unittest.main()
