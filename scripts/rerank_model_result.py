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


def main():
    parser = argparse.ArgumentParser(description="对模型结果进行排序与归一化打分")
    parser.add_argument("--input", required=True, help="model_result.jsonl")
    parser.add_argument("--output", required=True, help="输出 reranked jsonl")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    records = list(read_jsonl(input_path))
    if not records:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        write_jsonl([], output_path)
        logging.info("输入为空，已写出空结果: %s", output_path)
        return

    scores = []
    for r in records:
        try:
            scores.append(float(r.get("score", 0.0)))
        except Exception:
            scores.append(0.0)

    s_min = min(scores)
    s_max = max(scores)
    denom = s_max - s_min

    enriched = []
    for r, raw_score in zip(records, scores):
        if denom <= 1e-12:
            norm_score = 0.0
        else:
            norm_score = (raw_score - s_min) / denom
        item = dict(r)
        item["raw_score"] = float(raw_score)
        item["norm_score"] = float(round(norm_score, 6))
        enriched.append(item)

    enriched.sort(key=lambda x: x.get("raw_score", 0.0), reverse=True)
    for idx, item in enumerate(enriched, start=1):
        item["rank"] = idx

    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(enriched, output_path)

    logging.info("输入记录数: %d", len(records))
    logging.info("输出记录数: %d", len(enriched))
    logging.info("score min=%.6f max=%.6f", s_min, s_max)
    logging.info("输出文件: %s", output_path)
    for item in enriched[:5]:
        logging.info(
            "rank=%s seq=%s raw_score=%.6f norm_score=%.6f label=%s",
            item.get("rank"),
            item.get("seq_id"),
            float(item.get("raw_score", 0.0)),
            float(item.get("norm_score", 0.0)),
            item.get("label"),
        )


if __name__ == "__main__":
    main()
