import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "export_demo_candidates_to_result.py"


def load_module():
    scripts_dir = str(SCRIPT_PATH.parent)
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location("export_demo_candidates_to_result", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ExportManifestRecoveryTests(unittest.TestCase):
    def test_load_manifest_skips_partial_disk_full_line(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = Path(temp_dir) / "manifest.jsonl"
            manifest.write_text(
                '{"case_id":"b.7","file_id":"1.1.2","seq_id":3}\n'
                '{"case_id":"b.8","file_id":',
                encoding="utf-8",
            )

            records, keys, key_to_idx, max_case_num = module.load_manifest(manifest)

            self.assertEqual(len(records), 1)
            self.assertEqual(keys, {("1.1.2", 3)})
            self.assertEqual(key_to_idx[("1.1.2", 3)], 0)
            self.assertEqual(max_case_num, 7)


if __name__ == "__main__":
    unittest.main()
