import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from security_detection_v2 import DetectionEngineV2  # noqa: E402
from web_attack_rules import detect_request_attack  # noqa: E402


def upload_record(filename: str, content: str) -> dict:
    body = f'{{"filename":"{filename}","content":"{content}"}}'
    return {
        "file_id": "test.upload",
        "seq_id": 1,
        "method": "POST",
        "uri": "/api/upload",
        "host": "localhost:4000",
        "content_type": "application/json",
        "request_text": (
            "METHOD=POST\nURI=/api/upload\nHOST=localhost:4000\n"
            f"CONTENT_TYPE=application/json\nREQUEST_BODY={body}\nRESPONSE_EXCERPT={{}}"
        ),
        "raw_request_block": (
            "POST /api/upload HTTP/1.1\nHost: localhost:4000\n"
            f"Content-Type: application/json\nBody:\n{body}"
        ),
    }


class DangerousUploadDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = DetectionEngineV2()

    def test_json_php_webshell_reaches_attack_gate(self) -> None:
        record = upload_record("shell.php", "<?php system($_GET['cmd']); ?>")
        result = self.engine.detect(record)
        self.assertEqual(result["fusion"]["decision"], "attack_event")
        self.assertEqual(result["fusion"]["attack_type"], "危险文件上传")
        self.assertTrue(any(x["rule_id"] == "web-dangerous-upload-001" for x in result["poc_matches"]))
        self.assertEqual(detect_request_attack(record)["attack_type"], "危险文件上传")

    def test_json_jsp_webshell_reaches_attack_gate(self) -> None:
        record = upload_record("cmd.jsp", '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>')
        result = self.engine.detect(record)
        self.assertEqual(result["fusion"]["decision"], "attack_event")
        self.assertEqual(result["fusion"]["attack_type"], "危险文件上传")

    def test_benign_image_upload_stays_raw_only(self) -> None:
        record = upload_record("avatar.png", "PNG_IMAGE_BYTES")
        result = self.engine.detect(record)
        self.assertEqual(result["fusion"]["decision"], "raw_only")
        self.assertIsNone(detect_request_attack(record))

    def test_upload_page_view_stays_raw_only(self) -> None:
        record = {"method": "GET", "uri": "/upload", "request_text": "METHOD=GET\nURI=/upload"}
        result = self.engine.detect(record)
        self.assertEqual(result["fusion"]["decision"], "raw_only")
        self.assertIsNone(detect_request_attack(record))


if __name__ == "__main__":
    unittest.main()
