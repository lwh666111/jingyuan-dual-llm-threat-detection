from __future__ import annotations

import argparse
import time
from datetime import datetime
from pathlib import Path

from situation_ai import analyze_situation
from situation_store import MySQLSettings, MySQLSituationStore


def log(message: str, path: Path) -> None:
    line = f"[{datetime.now().isoformat(timespec='seconds')}] {message}"
    print(line, flush=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate explainable Ollama/RAG reports for attack situations")
    parser.add_argument("--mysql-host", default="127.0.0.1")
    parser.add_argument("--mysql-port", type=int, default=3306)
    parser.add_argument("--mysql-user", default="root")
    parser.add_argument("--mysql-password", default="123456")
    parser.add_argument("--mysql-database", default="traffic_pipeline")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    parser.add_argument("--model", default="qwen2.5:3b")
    parser.add_argument("--rag-db-path", default="llm/rag/rag_knowledge.db")
    parser.add_argument("--rag-top-k", type=int, default=4)
    parser.add_argument("--timeout-sec", type=int, default=120)
    parser.add_argument("--poll-seconds", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=3)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--log-file", default="output/situation_ai_daemon.log")
    args = parser.parse_args()

    store = MySQLSituationStore(MySQLSettings(args.mysql_host, args.mysql_port, args.mysql_user, args.mysql_password, args.mysql_database))
    store.ensure_schema()
    log_file = Path(args.log_file)
    rag_path = Path(args.rag_db_path).resolve()
    try:
        while True:
            pending = store.list_pending_ai(args.batch_size)
            for situation in pending:
                report, status = analyze_situation(
                    situation,
                    ollama_url=args.ollama_url,
                    model=args.model,
                    rag_db_path=rag_path,
                    rag_top_k=args.rag_top_k,
                    timeout_sec=args.timeout_sec,
                )
                store.update_ai_report(str(situation["situation_id"]), report, status)
                log(f"analyzed {situation['situation_id']} status={status}", log_file)
            if args.once:
                break
            time.sleep(max(2, args.poll_seconds))
    finally:
        store.close()


if __name__ == "__main__":
    main()
