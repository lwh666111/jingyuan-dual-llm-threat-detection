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


def raw_review_waiting(store: MySQLSituationStore) -> bool:
    """Yield Ollama to real-time packet review before generating reports."""
    try:
        with store.connect().cursor() as cur:
            cur.execute(
                "SELECT config_value FROM demo_system_config WHERE config_key='llm_realtime_enabled' LIMIT 1"
            )
            config = cur.fetchone() or {}
            realtime = str(config.get("config_value", "1")).strip().lower() in {"1", "true", "yes", "on"}
            if realtime:
                cur.execute(
                    """SELECT
                         (SELECT COUNT(*) FROM llm_review_jobs WHERE status IN ('pending','processing'))
                         + (SELECT COUNT(*) FROM raw_http_logs WHERE event_time >= NOW() - INTERVAL 20 SECOND) AS c"""
                )
            else:
                cur.execute(
                    "SELECT COUNT(*) AS c FROM llm_review_jobs WHERE status IN ('pending','processing')"
                )
            row = cur.fetchone() or {}
        return int(row.get("c") or 0) > 0
    except Exception:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate explainable Bailian/RAG reports for attack situations")
    parser.add_argument("--mysql-host", default="127.0.0.1")
    parser.add_argument("--mysql-port", type=int, default=3306)
    parser.add_argument("--mysql-user", default="root")
    parser.add_argument("--mysql-password", default="123456")
    parser.add_argument("--mysql-database", default="traffic_pipeline")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    parser.add_argument("--model", default="qwen2.5:3b")
    parser.add_argument("--rag-db-path", default="llm/rag/rag_knowledge.db")
    parser.add_argument("--rag-data-dir", default="D:/JingyuanTrafficPipelineData/rag")
    parser.add_argument("--rag-api-config", default="config/ai_api.local.json")
    parser.add_argument("--rag-top-k", type=int, default=4)
    parser.add_argument("--timeout-sec", type=int, default=120)
    parser.add_argument("--poll-seconds", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--idle-grace-seconds", type=int, default=8)
    parser.add_argument("--report-cooldown-seconds", type=int, default=5)
    parser.add_argument("--recent-minutes", type=int, default=60)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--log-file", default="output/situation_ai_daemon.log")
    args = parser.parse_args()

    store = MySQLSituationStore(MySQLSettings(args.mysql_host, args.mysql_port, args.mysql_user, args.mysql_password, args.mysql_database))
    store.ensure_schema()
    log_file = Path(args.log_file)
    rag_path = Path(args.rag_db_path).resolve()
    rag_data_dir = Path(args.rag_data_dir).resolve()
    rag_api_config = Path(args.rag_api_config).resolve()
    rag_mysql_conf = {
        "host": args.mysql_host,
        "port": args.mysql_port,
        "user": args.mysql_user,
        "password": args.mysql_password,
        "database": args.mysql_database,
    }
    idle_since = time.monotonic()
    next_report_at = 0.0
    try:
        while True:
            rag_enabled = True
            try:
                with store.connect().cursor() as cur:
                    cur.execute("SELECT config_value FROM demo_system_config WHERE config_key='rag_enabled' LIMIT 1")
                    row = cur.fetchone() or {}
                rag_enabled = str(row.get("config_value", "1")).strip().lower() in {"1", "true", "yes", "on"}
            except Exception:
                rag_enabled = True
            if raw_review_waiting(store):
                idle_since = time.monotonic()
                if args.once:
                    break
                time.sleep(2)
                continue
            now = time.monotonic()
            if now < next_report_at or now - idle_since < max(0, args.idle_grace_seconds):
                if args.once:
                    break
                time.sleep(2)
                continue
            # Do not spend the single CPU-only Ollama worker backfilling old
            # reports after every restart. Historical situations remain
            # queryable; only newly formed chains enter the live AI queue.
            pending = store.list_pending_ai(
                args.batch_size,
                recent_minutes=args.recent_minutes,
            )
            for situation in pending:
                if raw_review_waiting(store):
                    break
                report, status = analyze_situation(
                    situation,
                    ollama_url=args.ollama_url,
                    model=args.model,
                    rag_db_path=rag_path,
                    rag_mysql_conf=rag_mysql_conf,
                    rag_data_dir=rag_data_dir,
                    rag_api_config=rag_api_config,
                    rag_enabled=rag_enabled,
                    rag_top_k=args.rag_top_k,
                    timeout_sec=args.timeout_sec,
                )
                store.update_ai_report(str(situation["situation_id"]), report, status)
                log(f"analyzed {situation['situation_id']} status={status}", log_file)
                next_report_at = time.monotonic() + max(0, args.report_cooldown_seconds)
                idle_since = time.monotonic()
            if args.once:
                break
            time.sleep(max(2, args.poll_seconds))
    finally:
        store.close()


if __name__ == "__main__":
    main()
