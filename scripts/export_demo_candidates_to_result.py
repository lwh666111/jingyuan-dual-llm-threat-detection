import argparse
import json
from datetime import datetime
from pathlib import Path

DEFAULT_LLM_TASK = (
    "\u8bf7\u5224\u65ad\u8be5\u8bf7\u6c42\u662f\u5426\u4e3a\u653b\u51fb\u884c\u4e3a\uff0c"
    "\u5982\u662f\u8bf7\u7ed9\u51fa\u653b\u51fb\u7c7b\u578b\u3001\u5224\u5b9a\u4f9d\u636e\u3001"
    "\u98ce\u9669\u7b49\u7ea7\u548c\u5904\u7f6e\u5efa\u8bae\u3002"
)


def read_jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_jsonl_append(path: Path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_jsonl(path: Path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def load_manifest(manifest_path: Path):
    records = list(read_jsonl(manifest_path)) if manifest_path.exists() else []
    existing_keys = set()
    key_to_idx = {}
    max_case_num = 0

    for idx, r in enumerate(records):
        try:
            key = (str(r.get("file_id")), int(r.get("seq_id")))
            existing_keys.add(key)
            key_to_idx[key] = idx
        except Exception:
            pass

        case_id = str(r.get("case_id", ""))
        if case_id.startswith("b."):
            try:
                num = int(case_id.split(".", 1)[1])
                max_case_num = max(max_case_num, num)
            except Exception:
                pass
    return records, existing_keys, key_to_idx, max_case_num


def ensure_text(path: Path, text: str):
    path.write_text(text or "", encoding="utf-8")


def get_candidate_score(cand: dict) -> float:
    for key in ("raw_score", "score", "norm_score"):
        try:
            value = cand.get(key)
            if value is None:
                continue
            return float(value)
        except Exception:
            continue
    return 0.0


def main():
    parser = argparse.ArgumentParser(description="将 demo_candidates 导出到 result 目录")
    parser.add_argument("--input", required=True, help="demo_candidates.jsonl 路径")
    parser.add_argument("--result-dir", default="result", help="result 根目录")
    parser.add_argument("--min-score", type=float, default=0.3, help="最低导出分数阈值（基于 raw_score/score）")
    parser.add_argument("--update-existing", action="store_true", help="若 file_id+seq_id 已存在则覆盖更新现有 case")
    args = parser.parse_args()

    input_path = Path(args.input)
    result_dir = Path(args.result_dir)
    result_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = result_dir / "manifest.jsonl"

    candidates = list(read_jsonl(input_path))
    manifest_records, existing_keys, key_to_idx, max_case_num = load_manifest(manifest_path)

    exported = []
    skipped = 0
    filtered_low_score = 0
    updated_existing = 0
    updated_case_ids = []
    new_case_ids = []
    next_case_num = max_case_num + 1

    for cand in candidates:
        score_value = get_candidate_score(cand)
        if score_value < args.min_score:
            filtered_low_score += 1
            continue

        try:
            file_id = str(cand.get("file_id"))
            seq_id = int(cand.get("seq_id"))
        except Exception:
            skipped += 1
            continue

        key = (file_id, seq_id)
        if key in existing_keys:
            if not args.update_existing:
                skipped += 1
                continue
            idx = key_to_idx.get(key)
            existing_row = manifest_records[idx] if idx is not None else {}
            case_id = str(existing_row.get("case_id", ""))
            case_dir_from_manifest = str(existing_row.get("case_dir", "")).strip()
            if case_dir_from_manifest:
                case_dir = Path(case_dir_from_manifest)
            elif case_id:
                case_dir = result_dir / case_id
            else:
                case_id = f"b.{next_case_num}"
                case_dir = result_dir / case_id
                next_case_num += 1
            case_dir.mkdir(parents=True, exist_ok=True)
            is_update = True
        else:
            case_id = f"b.{next_case_num}"
            case_dir = result_dir / case_id
            case_dir.mkdir(parents=True, exist_ok=True)
            is_update = False

        export_time = datetime.now().isoformat(timespec="seconds")

        case_json = {
            "case_id": case_id,
            "file_id": file_id,
            "seq_id": seq_id,
            "rank": cand.get("rank"),
            "raw_score": cand.get("raw_score"),
            "norm_score": cand.get("norm_score"),
            "label": cand.get("label"),
            "model_name": cand.get("model_name"),
            "method": cand.get("method"),
            "uri": cand.get("uri"),
            "host": cand.get("host"),
            "status_code": cand.get("status_code"),
            "request_text": cand.get("request_text"),
            "llm_task": cand.get("llm_task") or DEFAULT_LLM_TASK,
            "export_time": export_time,
            "status": "pending",
            "llm_status": "pending",
        }

        ensure_text(case_dir / "request.txt", cand.get("raw_request_block", ""))
        ensure_text(case_dir / "response.txt", cand.get("raw_response_block", ""))
        ensure_text(case_dir / "case.json", json.dumps(case_json, ensure_ascii=False, indent=2))

        manifest_row = {
            "case_id": case_id,
            "file_id": file_id,
            "seq_id": seq_id,
            "uri": cand.get("uri"),
            "raw_score": cand.get("raw_score"),
            "norm_score": cand.get("norm_score"),
            "label": cand.get("label"),
            "status": "pending",
            "case_dir": str(case_dir.resolve()).replace("\\", "/"),
        }

        if is_update:
            idx = key_to_idx.get(key)
            if idx is not None:
                manifest_records[idx] = manifest_row
            else:
                manifest_records.append(manifest_row)
                key_to_idx[key] = len(manifest_records) - 1
            updated_existing += 1
            updated_case_ids.append(case_id)
        else:
            manifest_records.append(manifest_row)
            key_to_idx[key] = len(manifest_records) - 1
            existing_keys.add(key)
            exported.append(manifest_row)
            new_case_ids.append(case_id)
            next_case_num += 1

    if exported or updated_existing:
        write_jsonl(manifest_path, manifest_records)

    print("=" * 80)
    print("输入 candidate 数量:", len(candidates))
    print("低于阈值过滤数量:", filtered_low_score)
    print("已存在跳过数量:", skipped)
    print("新导出数量:", len(exported))
    print("更新已有数量:", updated_existing)
    print("导出分数阈值:", args.min_score)
    print("result 目录路径:", result_dir.resolve())
    print("新生成的 case_id 列表:", new_case_ids if new_case_ids else "无")
    print("更新的 case_id 列表:", updated_case_ids if updated_case_ids else "无")
    print("manifest 路径:", manifest_path.resolve())
    print("=" * 80)


if __name__ == "__main__":
    main()
