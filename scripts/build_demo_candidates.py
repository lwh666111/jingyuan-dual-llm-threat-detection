import argparse
import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def read_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def write_jsonl(records, path: Path):
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def make_key(record: dict):
    return str(record.get("file_id")), int(record.get("seq_id"))


def index_by_key(path: Path):
    mapping = {}
    for rec in read_jsonl(path):
        try:
            mapping[make_key(rec)] = rec
        except Exception as exc:  # noqa: BLE001
            logging.warning("跳过异常记录: %s | %s", exc, rec)
    return mapping


def main():
    parser = argparse.ArgumentParser(description="根据 reranked 结果构建 demo 候选")
    parser.add_argument("--parsed", required=True, help="parsed.jsonl")
    parser.add_argument("--model-input", required=True, help="model_input.jsonl")
    parser.add_argument("--reranked-result", required=True, help="reranked model_result.jsonl")
    parser.add_argument("--output", required=True, help="demo_candidates.jsonl")
    parser.add_argument("--top-k", type=int, default=3, help="选取前K条")
    args = parser.parse_args()

    parsed_map = index_by_key(Path(args.parsed))
    input_map = index_by_key(Path(args.model_input))
    reranked = list(read_jsonl(Path(args.reranked_result)))
    reranked.sort(key=lambda x: int(x.get("rank", 10**9)))

    selected = reranked[: max(args.top_k, 0)]
    candidates = []

    for item in selected:
        try:
            key = make_key(item)
        except Exception:
            continue
        parsed_rec = parsed_map.get(key, {})
        input_rec = input_map.get(key, {})

        candidate = {
            "file_id": key[0],
            "seq_id": key[1],
            "rank": item.get("rank"),
            "raw_score": item.get("raw_score", item.get("score")),
            "norm_score": item.get("norm_score"),
            "label": item.get("label"),
            "model_name": item.get("model_name"),
            "method": parsed_rec.get("method", input_rec.get("method")),
            "uri": parsed_rec.get("uri", input_rec.get("uri")),
            "host": parsed_rec.get("host", input_rec.get("host")),
            "status_code": parsed_rec.get("status_code", input_rec.get("status_code")),
            "request_text": input_rec.get("request_text"),
            "raw_request_block": parsed_rec.get("raw_request_block"),
            "raw_response_block": parsed_rec.get("raw_response_block"),
        }
        candidates.append(candidate)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(candidates, output_path)

    logging.info("parsed 记录数: %d", len(parsed_map))
    logging.info("model_input 记录数: %d", len(input_map))
    logging.info("reranked 记录数: %d", len(reranked))
    logging.info("top_k: %d", args.top_k)
    logging.info("demo_candidates 数量: %d", len(candidates))
    logging.info("输出文件: %s", output_path)
    for c in candidates[:5]:
        logging.info(
            "rank=%s seq=%s raw_score=%s norm_score=%s uri=%s",
            c.get("rank"),
            c.get("seq_id"),
            c.get("raw_score"),
            c.get("norm_score"),
            c.get("uri"),
        )


if __name__ == "__main__":
    main()
