from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import firewall_control  # noqa: E402


class FirewallControlTests(unittest.TestCase):
    def test_block_requires_verified_inbound_and_outbound_rules(self) -> None:
        with patch.object(firewall_control, "_run_powershell", return_value=(True, "")) as run:
            ok, detail = firewall_control.firewall_block_ip("203.0.113.250")
        self.assertTrue(ok, detail)
        self.assertIn("$verified", run.call_args.args[0])

    def test_unblock_requires_both_rules_to_be_absent(self) -> None:
        with patch.object(firewall_control, "_run_powershell", return_value=(True, "")) as run:
            ok, detail = firewall_control.firewall_unblock_ip("203.0.113.250")
        self.assertTrue(ok, detail)
        self.assertIn("$remaining", run.call_args.args[0])

    def test_unblock_is_idempotent_when_rules_are_already_absent(self) -> None:
        with patch.object(firewall_control, "_run_powershell", return_value=(True, "")) as run:
            ok, detail = firewall_control.firewall_unblock_ip("203.0.113.10")
        self.assertTrue(ok)
        self.assertEqual(detail, "")
        run.assert_called_once()

    def test_unblock_reports_atomic_verification_failure(self) -> None:
        with patch.object(
            firewall_control,
            "_run_powershell",
            return_value=(False, "firewall_rule_removal_verification_failed: TP_BLOCK_IP_OUT_203.0.113.250"),
        ):
            ok, detail = firewall_control.firewall_unblock_ip("203.0.113.250")
        self.assertFalse(ok)
        self.assertIn("firewall_rule_removal_verification_failed", detail)

    def test_automatic_policy_never_blocks_loopback(self) -> None:
        self.assertFalse(firewall_control.is_safe_automatic_target("127.0.0.1"))
        self.assertFalse(firewall_control.is_safe_automatic_target("10.0.0.8"))
        self.assertTrue(firewall_control.is_safe_automatic_target("8.8.8.8"))


if __name__ == "__main__":
    unittest.main()
