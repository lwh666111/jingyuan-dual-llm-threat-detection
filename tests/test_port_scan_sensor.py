from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from port_scan_sensor import PortScanDetector, parse_packet_line, tshark_command  # noqa: E402


BASE = datetime(2026, 8, 3, 8, 0, tzinfo=timezone.utc)


class PortScanSensorTests(unittest.TestCase):
    def test_unique_ports_trigger_one_aggregated_action(self) -> None:
        detector = PortScanDetector(unique_port_threshold=5, window_seconds=60)
        for index, port in enumerate([22, 80, 443, 3306, 4000, 80, 443]):
            detector.observe(BASE + timedelta(seconds=index), "203.0.113.9", "10.0.0.5", port)
        rows = detector.actions(now=BASE + timedelta(seconds=20))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].action_type, "PORT_SCAN")
        self.assertEqual(rows[0].count, 7)
        self.assertEqual(rows[0].metadata["unique_port_count"], 5)

    def test_scan_crossing_fixed_minute_boundary_stays_in_one_window(self) -> None:
        detector = PortScanDetector(unique_port_threshold=3, window_seconds=60)
        base = datetime(2026, 8, 3, 8, 0, 58, tzinfo=timezone.utc)
        for index, port in enumerate([22, 80, 443, 3306]):
            detector.observe(base + timedelta(seconds=index), "203.0.113.44", "10.0.0.8", port)

        rows = detector.actions(now=base + timedelta(seconds=10))

        self.assertEqual(1, len(rows))
        self.assertEqual(4, rows[0].metadata["unique_port_count"])

    def test_repeated_single_port_does_not_trigger(self) -> None:
        detector = PortScanDetector(unique_port_threshold=5, window_seconds=60)
        for index in range(100):
            detector.observe(BASE + timedelta(milliseconds=index), "203.0.113.9", "10.0.0.5", 443)
        self.assertEqual(detector.actions(), [])

    def test_sources_and_targets_are_isolated(self) -> None:
        detector = PortScanDetector(unique_port_threshold=3, window_seconds=60)
        for port in [22, 80, 443]:
            detector.observe(BASE, "203.0.113.9", "10.0.0.5", port)
        for port in [22, 80]:
            detector.observe(BASE, "198.51.100.2", "10.0.0.5", port)
        self.assertEqual(len(detector.actions()), 1)

    def test_packet_parser(self) -> None:
        row = parse_packet_line("1775203200.125\t203.0.113.9\t10.0.0.5\t443")
        self.assertIsNotNone(row)
        self.assertEqual(row[1:], ("203.0.113.9", "10.0.0.5", 443))
        self.assertIsNone(parse_packet_line("broken"))

    def test_tshark_command_uses_syn_without_ack(self) -> None:
        command = tshark_command("tshark.exe", "4")
        self.assertIn("tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src && ip.dst", command)
        self.assertIn("frame.time_epoch", command)


if __name__ == "__main__":
    unittest.main()
