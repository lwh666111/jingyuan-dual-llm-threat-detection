import argparse
import csv
import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

DEFAULT_LLM_TASK = (
    "\u8bf7\u5224\u65ad\u8be5\u8bf7\u6c42\u662f\u5426\u4e3a\u653b\u51fb\u884c\u4e3a\uff0c"
    "\u5982\u662f\u8bf7\u7ed9\u51fa\u653b\u51fb\u7c7b\u578b\u3001\u5224\u5b9a\u4f9d\u636e\u3001"
    "\u98ce\u9669\u7b49\u7ea7\u548c\u5904\u7f6e\u5efa\u8bae\u3002"
)


def read_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def make_key(record: dict):
    return str(record.get("file_id")), int(record.get("seq_id"))


def index_records(path: Path):
    data = {}
    for record in read_jsonl(path):
        try:
            data[make_key(record)] = record
        except Exception as e:  # noqa: BLE001
            logging.warning("索引失败: %s | %s", e, record)
    return data


def should_send_to_llm(record: dict, threshold: float = 0.7) -> bool:
    label = str(record.get("label", "")).lower()
    try:
        score = float(record.get("score", 0))
    except Exception:
        score = 0.0
    return score >= threshold or label == "suspicious"


def build_llm_candidate(record: dict):
    return {
        "file_id": record.get("file_id"),
        "seq_id": record.get("seq_id"),
        "score": record.get("score"),
        "label": record.get("label"),
        "method": record.get("method"),
        "uri": record.get("uri"),
        "host": record.get("host"),
        "status_code": record.get("status_code"),
        "request_text": record.get("request_text"),
        "raw_request_block": record.get("raw_request_block"),
        "raw_response_block": record.get("raw_response_block"),
        "llm_task": DEFAULT_LLM_TASK,
    }


def write_jsonl(records, path: Path):
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_csv(records, path: Path):
    if not records:
        with path.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["empty"])
        return

    fieldnames = sorted({k for r in records for k in r.keys()})
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for record in records:
            writer.writerow(record)


def main():
    parser = argparse.ArgumentParser(description="合并模型输出并生成 LLM 候选列表")
    parser.add_argument("--parsed", required=True)
    parser.add_argument("--model-input", required=True)
    parser.add_argument("--model-result", required=True)
    parser.add_argument("--output-dir", default="output")
    parser.add_argument("--threshold", type=float, default=0.7)
    args = parser.parse_args()

    parsed_path = Path(args.parsed)
    model_input_path = Path(args.model_input)
    model_result_path = Path(args.model_result)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    file_id = parsed_path.stem.replace(".parsed", "")

    parsed_map = index_records(parsed_path)
    model_input_map = index_records(model_input_path)
    model_result_map = index_records(model_result_path)

    logging.info("parsed 记录数: %d", len(parsed_map))
    logging.info("model_input 记录数: %d", len(model_input_map))
    logging.info("model_result 记录数: %d", len(model_result_map))

    all_keys = sorted(
        set(parsed_map.keys()) | set(model_input_map.keys()) | set(model_result_map.keys()),
        key=lambda x: (x[0], x[1]),
    )

    merged_results = []
    llm_candidates = []

    for key in all_keys:
        merged = {}
        if key in parsed_map:
            merged.update(parsed_map[key])
        if key in model_input_map:
            merged.update(model_input_map[key])
        if key in model_result_map:
            merged.update(model_result_map[key])

        merged["file_id"] = key[0]
        merged["seq_id"] = key[1]

        merged_results.append(merged)

        if should_send_to_llm(merged, threshold=args.threshold):
            llm_candidates.append(build_llm_candidate(merged))

    merged_jsonl = output_dir / f"{file_id}.merged_results.jsonl"
    merged_csv = output_dir / f"{file_id}.merged_results.csv"
    llm_jsonl = output_dir / f"{file_id}.llm_candidates.jsonl"

    write_jsonl(merged_results, merged_jsonl)
    write_csv(merged_results, merged_csv)
    write_jsonl(llm_candidates, llm_jsonl)

    logging.info("成功合并数: %d", len(merged_results))
    logging.info("llm_candidates 数: %d", len(llm_candidates))
    logging.info("merged_results.jsonl: %s", merged_jsonl)
    logging.info("merged_results.csv: %s", merged_csv)
    logging.info("llm_candidates.jsonl: %s", llm_jsonl)

    for item in llm_candidates[:3]:
        logging.info(
            "candidate seq=%s score=%s label=%s uri=%s",
            item.get("seq_id"),
            item.get("score"),
            item.get("label"),
            item.get("uri"),
        )


if __name__ == "__main__":
    main()
