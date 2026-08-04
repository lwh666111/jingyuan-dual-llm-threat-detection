from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from dashboard_api_server import sanitize_evidence_text  # noqa: E402
from ssh_bruteforce_monitor import extract_source_ip, summarize_failure_event  # noqa: E402


class SSHBruteforceEvidenceTests(unittest.TestCase):
    def test_windows_event_is_reduced_to_readable_summary(self) -> None:
        item = {"ProviderName": "Microsoft-Windows-Security-Auditing", "Id": 4625}
        message = "Account Name:\tADMINISTRATOR\nSource Network Address:\t95.214.53.243"
        summary = summarize_failure_event(item, message, "95.214.53.243")
        self.assertEqual(
            summary,
            "Windows 安全日志登录失败；来源IP=95.214.53.243；目标账户=ADMINISTRATOR；事件ID=4625",
        )

    def test_historical_mojibake_is_hidden_but_ip_is_retained(self) -> None:
        text = "���?�?�?�?�?�?�?�?�?�? 95.214.53.216 NTLM"
        cleaned = sanitize_evidence_text(text)
        self.assertNotIn("�", cleaned)
        self.assertIn("历史原始消息编码异常", cleaned)
        self.assertIn("95.214.53.216", cleaned)

    def test_plain_hex_word_is_not_treated_as_ipv6(self) -> None:
        self.assertEqual(extract_source_ip("invalid user bad from unknown host"), "")
        self.assertEqual(extract_source_ip("failed password from 95.214.53.243 port 22"), "95.214.53.243")


if __name__ == "__main__":
    unittest.main()
