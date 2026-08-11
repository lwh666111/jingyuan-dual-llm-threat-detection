import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from result_db_daemon import changed_work_items, collect_watch_index  # noqa: E402


class ResultDbDaemonIncrementalTests(unittest.TestCase):
    def test_changed_files_are_reduced_to_cases_and_inputs(self):
        root = Path("C:/project")
        previous = {
            "input/1.1.1.txt": "1:10",
            "result/b.1/case.json": "1:20",
            "result/manifest.jsonl": "1:30",
        }
        current = {
            "input/1.1.1.txt": "2:11",
            "result/b.1/case.json": "2:21",
            "result/manifest.jsonl": "2:31",
        }

        cases, inputs = changed_work_items(previous, current, root)

        self.assertEqual(cases, {"b.1"})
        self.assertEqual(inputs, [root / "input/1.1.1.txt"])

    def test_manifest_only_change_does_not_rescan_historical_cases(self):
        root = Path("C:/project")
        cases, inputs = changed_work_items(
            {"result/manifest.jsonl": "1:10"},
            {"result/manifest.jsonl": "2:11"},
            root,
        )
        self.assertEqual(cases, set())
        self.assertEqual(inputs, [])

    def test_watch_index_detects_file_content_metadata_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir = root / "input"
            result_dir = root / "result"
            input_dir.mkdir()
            (result_dir / "b.1").mkdir(parents=True)
            input_file = input_dir / "1.1.1.txt"
            case_file = result_dir / "b.1" / "case.json"
            input_file.write_text("one", encoding="utf-8")
            case_file.write_text("{}", encoding="utf-8")

            before = collect_watch_index(result_dir, input_dir)
            input_file.write_text("longer", encoding="utf-8")
            after = collect_watch_index(result_dir, input_dir)

            self.assertIn("input/1.1.1.txt", before)
            self.assertIn("result/b.1/case.json", before)
            self.assertNotEqual(before["input/1.1.1.txt"], after["input/1.1.1.txt"])


if __name__ == "__main__":
    unittest.main()
