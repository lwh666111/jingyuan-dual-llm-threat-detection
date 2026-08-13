import sys
import threading
import time
import unittest
import uuid
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from pipeline_events import DB_READY_EVENT, DETECTION_READY_EVENT, append_input_ready, notify_event, read_input_ready, wait_event  # noqa: E402


class PipelineEventTests(unittest.TestCase):
    def test_notification_wakes_waiter_on_windows(self) -> None:
        if sys.platform != "win32":
            self.skipTest("Windows named event test")
        name = "Local\\JingyuanTest." + uuid.uuid4().hex
        result = []
        started = threading.Event()

        def waiter() -> None:
            started.set()
            result.append(wait_event(name, 2.0))

        thread = threading.Thread(target=waiter)
        thread.start()
        started.wait(1)
        time.sleep(0.05)
        self.assertTrue(notify_event(name))
        thread.join(1)
        self.assertEqual(result, [True])

    def test_timeout_remains_available_as_fallback(self) -> None:
        name = "Local\\JingyuanTest." + uuid.uuid4().hex
        started = time.perf_counter()
        self.assertFalse(wait_event(name, 0.05))
        self.assertGreaterEqual(time.perf_counter() - started, 0.03)

    def test_repeated_waits_do_not_leave_a_notification_gap(self) -> None:
        if sys.platform != "win32":
            self.skipTest("Windows named event test")
        name = "Local\\JingyuanTest." + uuid.uuid4().hex
        self.assertFalse(wait_event(name, 0.01))
        self.assertTrue(notify_event(name))
        self.assertTrue(wait_event(name, 0.2))

    def test_detection_and_database_have_independent_events(self) -> None:
        self.assertNotEqual(DETECTION_READY_EVENT, DB_READY_EVENT)

    def test_durable_input_queue_resumes_from_byte_offset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            queue = root / "input_ready.jsonl"
            first = root / "1.1.1.txt"
            second = root / "1.1.2.txt"
            append_input_ready(queue, first)
            items, offset = read_input_ready(queue, 0)
            self.assertEqual(items, [first.resolve()])
            append_input_ready(queue, second)
            items, next_offset = read_input_ready(queue, offset)
            self.assertEqual(items, [second.resolve()])
            self.assertGreater(next_offset, offset)


if __name__ == "__main__":
    unittest.main()
