import tempfile
import unittest
from pathlib import Path

from scripts.capture_http_request_batches import (
    MAX_CAPTURE_PAYLOAD_CHARS,
    decode_http_file_data,
    next_file_index,
    read_capture_sequence,
    truncate_capture_text,
    write_capture_sequence,
    write_canonical_batch,
)


class CaptureSizeLimitTests(unittest.TestCase):
    def test_capture_sequence_survives_input_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "input"
            input_dir.mkdir()
            state_path = root / "output" / "capture_sequence.json"
            write_capture_sequence(state_path, 42)

            self.assertEqual(read_capture_sequence(state_path), 42)
            self.assertEqual(next_file_index(input_dir, state_path=state_path), 43)

    def test_capture_sequence_uses_largest_file_or_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "input"
            input_dir.mkdir()
            state_path = root / "output" / "capture_sequence.json"
            (input_dir / "1.1.57.txt").write_text("test", encoding="utf-8")
            write_capture_sequence(state_path, 42)

            self.assertEqual(next_file_index(input_dir, state_path=state_path), 58)

    def test_capture_sequence_can_resume_from_database_maximum(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir) / "input"
            input_dir.mkdir()
            self.assertEqual(next_file_index(input_dir, minimum_last_index=13925), 13926)

    def test_plain_payload_is_truncated_with_evidence_marker(self) -> None:
        value = "A" * (MAX_CAPTURE_PAYLOAD_CHARS * 8)
        result = decode_http_file_data(value)
        self.assertLess(len(result), MAX_CAPTURE_PAYLOAD_CHARS + 100)
        self.assertIn("截断", result)

    def test_hex_payload_is_decoded_then_truncated(self) -> None:
        value = ("hello-security-evidence" * 2000).encode().hex()
        result = decode_http_file_data(value)
        self.assertTrue(result.startswith("hello-security-evidence"))
        self.assertLess(len(result), MAX_CAPTURE_PAYLOAD_CHARS + 150)

    def test_batch_file_cannot_repeat_an_unbounded_body(self) -> None:
        oversized = "Z" * (MAX_CAPTURE_PAYLOAD_CHARS * 10)
        body = truncate_capture_text(oversized)
        case = {
            "request": {
                "method": "POST",
                "uri": "/upload",
                "host": "example.test",
                "content_type": "text/plain",
                "request_body": body,
            },
            "response": {
                "status_code": 200,
                "response_phrase": "OK",
                "response_body_excerpt": body,
            },
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "1.1.1.txt"
            write_canonical_batch(target, "1.1.1", 1, "80", [case])
            self.assertLess(target.stat().st_size, 200 * 1024)


if __name__ == "__main__":
    unittest.main()
