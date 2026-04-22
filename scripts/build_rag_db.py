import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List


def read_seed(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"seed file not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("seed JSON must be an array")
    rows: List[Dict[str, Any]] = []
    for idx, row in enumerate(data, start=1):
        if not isinstance(row, dict):
            continue
        doc_id = str(row.get("doc_id") or f"DOC-{idx:04d}")
        rows.append(
            {
                "doc_id": doc_id,
                "title": str(row.get("title") or ""),
                "tags": str(row.get("tags") or ""),
                "attack_type": str(row.get("attack_type") or ""),
                "content": str(row.get("content") or ""),
                "evidence": str(row.get("evidence") or ""),
                "mitigation": str(row.get("mitigation") or ""),
                "severity": str(row.get("severity") or "medium"),
                "source": str(row.get("source") or "local_seed"),
            }
        )
    return rows


def build_rag_db(db_path: Path, seed_rows: List[Dict[str, Any]]) -> int:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(db_path)) as conn:
        cur = conn.cursor()
        cur.execute("DROP TABLE IF EXISTS rag_docs")
        cur.execute(
            """
            CREATE VIRTUAL TABLE rag_docs USING fts5(
              doc_id UNINDEXED,
              title,
              tags,
              attack_type,
              content,
              evidence,
              mitigation,
              severity UNINDEXED,
              source UNINDEXED,
              tokenize='unicode61'
            )
            """
        )
        cur.executemany(
            """
            INSERT INTO rag_docs(doc_id, title, tags, attack_type, content, evidence, mitigation, severity, source)
            VALUES(:doc_id, :title, :tags, :attack_type, :content, :evidence, :mitigation, :severity, :source)
            """,
            seed_rows,
        )
        conn.commit()
    return len(seed_rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build SQLite FTS5 RAG knowledge database")
    parser.add_argument("--seed-file", default="llm/rag/rag_seed.json", help="RAG seed JSON file path")
    parser.add_argument("--db-path", default="llm/rag/rag_knowledge.db", help="output sqlite db path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    project_root = Path(__file__).resolve().parent.parent
    seed_path = (project_root / args.seed_file).resolve()
    db_path = (project_root / args.db_path).resolve()
    rows = read_seed(seed_path)
    count = build_rag_db(db_path, rows)
    print(f"RAG DB built: {db_path} rows={count}", flush=True)


if __name__ == "__main__":
    main()
