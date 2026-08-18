from __future__ import annotations

import argparse
import os
import time
import json
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
    parser.add_argument("--recent-minutes", type=int, default=1440)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--heartbeat-file", default="output/situation_ai_heartbeat.json")
    parser.add_argument("--log-file", default="output/situation_ai_daemon.log")
    args = parser.parse_args()

    store = MySQLSituationStore(MySQLSettings(args.mysql_host, args.mysql_port, args.mysql_user, args.mysql_password, args.mysql_database))
    store.ensure_schema()
    log_file = Path(args.log_file)
    heartbeat_file = Path(args.heartbeat_file)
    recovered = store.recover_interrupted_ai()
    if recovered:
        log(f"recovered {recovered} interrupted AI report task(s)", log_file)

    def heartbeat(status: str, **extra: object) -> None:
        heartbeat_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "pid": os.getpid(),
            "updated_at": datetime.now().isoformat(timespec="seconds"),
            "status": status,
            **extra,
        }
        temporary = heartbeat_file.with_suffix(heartbeat_file.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        temporary.replace(heartbeat_file)
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
            heartbeat("polling")
            rag_enabled = True
            try:
                with store.connect().cursor() as cur:
                    cur.execute("SELECT config_value FROM demo_system_config WHERE config_key='rag_enabled' LIMIT 1")
                    row = cur.fetchone() or {}
                rag_enabled = str(row.get("config_value", "1")).strip().lower() in {"1", "true", "yes", "on"}
            except Exception:
                rag_enabled = True
            now = time.monotonic()
            if now < next_report_at or now - idle_since < max(0, args.idle_grace_seconds):
                if args.once:
                    break
                time.sleep(2)
                continue
            # Situation reports use the external Bailian endpoint and therefore
            # run independently from the local packet-review Ollama worker.
            # Keep a one-day recovery window so a transient outage cannot leave
            # a visible situation permanently labelled as queued.
            pending = store.list_pending_ai(
                args.batch_size,
                recent_minutes=args.recent_minutes,
            )
            for situation in pending:
                situation_id = str(situation["situation_id"])
                sequence_hash = str(situation.get("sequence_hash") or "")
                if not store.mark_ai_processing(situation_id, sequence_hash):
                    continue
                heartbeat("analyzing", situation_id=situation_id)
                try:
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
                except Exception as exc:
                    store.mark_ai_retry(situation_id, sequence_hash)
                    heartbeat("retry", situation_id=situation_id, error=str(exc))
                    log(f"AI report failed {situation_id}: {exc}", log_file)
                    continue
                updated = store.update_ai_report(
                    situation_id,
                    report,
                    status,
                    expected_sequence_hash=sequence_hash,
                )
                if not updated:
                    heartbeat("superseded", situation_id=str(situation["situation_id"]))
                    log(f"discarded stale report {situation['situation_id']} because the attack chain changed", log_file)
                    idle_since = time.monotonic()
                    continue
                heartbeat("completed", situation_id=str(situation["situation_id"]), result=status)
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
