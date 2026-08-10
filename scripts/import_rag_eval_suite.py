"""Import or replace a UTF-8 RAG retrieval evaluation suite."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from rag_service import ensure_schema, list_eval_cases, list_kbs, mysql_connect, save_eval_case


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def read_mysql_config(path: Path):
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    return payload.get("mysql") if isinstance(payload.get("mysql"), dict) else payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Import RAG retrieval evaluation cases")
    parser.add_argument("--db-config", default="config/db_config.json")
    parser.add_argument("--suite", default="examples/rag_retrieval_evaluation.json")
    parser.add_argument("--kb-id", type=int, default=0)
    parser.add_argument("--replace", action="store_true", help="Delete existing cases before importing")
    args = parser.parse_args()
    suite_path = (PROJECT_ROOT / args.suite).resolve()
    cases = json.loads(suite_path.read_text(encoding="utf-8-sig"))
    if not isinstance(cases, list) or not cases:
        raise SystemExit("Evaluation suite must be a non-empty JSON array")
    with mysql_connect(read_mysql_config((PROJECT_ROOT / args.db_config).resolve()), autocommit=False) as conn:
        ensure_schema(conn)
        kbs = list_kbs(conn)
        kb_id = args.kb_id or int(max(kbs, key=lambda row: int(row.get("chunk_count") or 0))["id"])
        if args.replace:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM rag_eval_cases WHERE kb_id=%s", (kb_id,))
            conn.commit()
        existing = {str(row["question"]): int(row["id"]) for row in list_eval_cases(conn, kb_id)}
        for case in cases:
            question = str(case.get("question") or "").strip()
            save_eval_case(conn, kb_id, case, case_id=existing.get(question, 0))
        print(json.dumps({"ok": True, "kb_id": kb_id, "imported": len(cases), "source": str(suite_path)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
