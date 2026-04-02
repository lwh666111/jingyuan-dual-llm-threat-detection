import argparse
import json
from pathlib import Path
from typing import Optional, Dict, Any


def lookup_record(jsonl_path: Path, file_id: str, seq_id: int) -> Optional[Dict[str, Any]]:
    with jsonl_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("file_id") == file_id and record.get("seq_id") == seq_id:
                return record
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="按 file_id + seq_id 查询解析记录")
    parser.add_argument("--jsonl", required=True, help="parsed jsonl 文件路径")
    parser.add_argument("--file-id", required=True, help="文件编号")
    parser.add_argument("--seq-id", required=True, type=int, help="记录序号")
    args = parser.parse_args()

    jsonl_path = Path(args.jsonl)
    if not jsonl_path.exists():
        raise FileNotFoundError(f"jsonl 文件不存在: {jsonl_path}")

    record = lookup_record(jsonl_path, args.file_id, args.seq_id)
    if not record:
        print("未找到对应记录")
        return

    print("=" * 60)
    print(f"file_id: {record.get('file_id')}")
    print(f"seq_id: {record.get('seq_id')}")
    print(f"method: {record.get('method')}")
    print(f"uri: {record.get('uri')}")
    print(f"host: {record.get('host')}")
    print(f"request_body: {record.get('request_body')}")
    print(f"status_code: {record.get('status_code')}")
    print(f"response_body_excerpt: {record.get('response_body_excerpt')}")
    print("-" * 60)
    print("raw_request_block:")
    print(record.get("raw_request_block", ""))
    print("-" * 60)
    print("raw_response_block:")
    print(record.get("raw_response_block", ""))


if __name__ == "__main__":
    main()
