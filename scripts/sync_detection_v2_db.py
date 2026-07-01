from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

try:
    import pymysql
except Exception:  # pragma: no cover
    pymysql = None

from build_result_db import MySQLConfig


def read_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def iter_case_dirs(result_dir: Path) -> Iterable[Path]:
    for p in sorted(result_dir.glob("b.*"), key=lambda x: int(x.name.split(".", 1)[1]) if x.name.split(".", 1)[1].isdigit() else 10**9):
        if p.is_dir():
            yield p


def mysql_connect(cfg: MySQLConfig):
    if pymysql is None:
        raise RuntimeError("PyMySQL is not installed")
    return pymysql.connect(host=cfg.host, port=cfg.port, user=cfg.user, password=cfg.password, database=cfg.database, charset="utf8mb4", autocommit=True)


MYSQL_DDL = [
    """
    CREATE TABLE IF NOT EXISTS raw_http_logs (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      case_id VARCHAR(64) NULL,
      file_id VARCHAR(128) NULL,
      seq_id INT NULL,
      event_time VARCHAR(64) NULL,
      source_ip VARCHAR(64) NULL,
      destination_ip VARCHAR(64) NULL,
      method VARCHAR(16) NULL,
      uri TEXT NULL,
      host VARCHAR(255) NULL,
      status_code INT NULL,
      request_text LONGTEXT NULL,
      response_text LONGTEXT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uniq_raw_case (case_id),
      KEY idx_raw_file_seq (file_id, seq_id),
      KEY idx_raw_source_ip (source_ip)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS detection_candidates (
      event_id VARCHAR(64) PRIMARY KEY,
      case_id VARCHAR(64) NULL,
      file_id VARCHAR(128) NULL,
      seq_id INT NULL,
      decision VARCHAR(32) NULL,
      final_score DOUBLE NULL,
      risk_level VARCHAR(32) NULL,
      attack_type VARCHAR(128) NULL,
      source_ip VARCHAR(64) NULL,
      target_interface VARCHAR(255) NULL,
      evidence_json LONGTEXT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      KEY idx_candidate_decision (decision),
      KEY idx_candidate_type (attack_type)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS attack_events (
      event_id VARCHAR(64) PRIMARY KEY,
      case_id VARCHAR(64) NULL,
      occurred_at VARCHAR(64) NULL,
      source_ip VARCHAR(64) NULL,
      target_interface VARCHAR(255) NULL,
      attack_type VARCHAR(128) NULL,
      risk_level VARCHAR(32) NULL,
      confidence DOUBLE NULL,
      status VARCHAR(32) NOT NULL DEFAULT 'unprocessed',
      evidence_json LONGTEXT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      KEY idx_attack_time (occurred_at),
      KEY idx_attack_type (attack_type),
      KEY idx_attack_source_ip (source_ip)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS model_predictions (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      case_id VARCHAR(64) NULL,
      model_name VARCHAR(128) NULL,
      label VARCHAR(128) NULL,
      score DOUBLE NULL,
      proba_json LONGTEXT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      KEY idx_model_case (case_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS poc_matches (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      case_id VARCHAR(64) NULL,
      rule_id VARCHAR(128) NULL,
      rule_name VARCHAR(255) NULL,
      attack_type VARCHAR(128) NULL,
      severity VARCHAR(32) NULL,
      score DOUBLE NULL,
      evidence_json LONGTEXT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      KEY idx_poc_case (case_id),
      KEY idx_poc_rule (rule_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS behavior_windows (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      case_id VARCHAR(64) NULL,
      source_ip VARCHAR(64) NULL,
      behavior_type VARCHAR(128) NULL,
      score DOUBLE NULL,
      features_json LONGTEXT NULL,
      evidence_json LONGTEXT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      KEY idx_behavior_case (case_id),
      KEY idx_behavior_source_ip (source_ip)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
]


def ensure_mysql(conn):
    with conn.cursor() as cur:
        for ddl in MYSQL_DDL:
            cur.execute(ddl)


def upsert_mysql(conn, table: str, row: Dict[str, Any]) -> None:
    keys = list(row.keys())
    cols = ",".join(f"`{k}`" for k in keys)
    vals = ",".join(["%s"] * len(keys))
    updates = ",".join(f"`{k}`=VALUES(`{k}`)" for k in keys if k not in {"id", "created_at"})
    sql = f"INSERT INTO `{table}` ({cols}) VALUES ({vals}) ON DUPLICATE KEY UPDATE {updates}"
    with conn.cursor() as cur:
        cur.execute(sql, tuple(row[k] for k in keys))


def sync_case_mysql(conn, case_dir: Path) -> Dict[str, int]:
    case = read_json(case_dir / "case.json")
    if not case:
        return {"raw": 0, "candidate": 0, "attack": 0, "model": 0, "poc": 0, "behavior": 0}
    case_id = str(case.get("case_id") or case_dir.name)
    event_id = case_id.replace("b.", "EVT", 1)
    request_text = read_text(case_dir / "request.txt") or str(case.get("request_text") or "")
    response_text = read_text(case_dir / "response.txt")
    evidence = case.get("v2_evidence") or []
    poc_matches = case.get("v2_poc_matches") or []
    decision = str(case.get("v2_decision") or "attack_event")
    final_score = case.get("v2_final_score") if case.get("v2_final_score") is not None else case.get("raw_score")
    attack_type = case.get("attack_type") or "可疑流量"
    risk_level = case.get("v2_risk_level") or ("high" if float(final_score or 0) >= 0.75 else "medium")

    upsert_mysql(conn, "raw_http_logs", {
        "case_id": case_id,
        "file_id": case.get("file_id"),
        "seq_id": case.get("seq_id"),
        "event_time": case.get("export_time"),
        "source_ip": case.get("source_ip"),
        "destination_ip": case.get("destination_ip"),
        "method": case.get("method"),
        "uri": case.get("uri"),
        "host": case.get("host"),
        "status_code": case.get("status_code"),
        "request_text": request_text,
        "response_text": response_text,
    })
    upsert_mysql(conn, "detection_candidates", {
        "event_id": event_id,
        "case_id": case_id,
        "file_id": case.get("file_id"),
        "seq_id": case.get("seq_id"),
        "decision": decision,
        "final_score": final_score,
        "risk_level": risk_level,
        "attack_type": attack_type,
        "source_ip": case.get("source_ip"),
        "target_interface": case.get("uri"),
        "evidence_json": json.dumps(evidence, ensure_ascii=False),
    })
    attack_count = 0
    if decision == "attack_event":
        upsert_mysql(conn, "attack_events", {
            "event_id": event_id,
            "case_id": case_id,
            "occurred_at": case.get("export_time"),
            "source_ip": case.get("source_ip"),
            "target_interface": case.get("uri"),
            "attack_type": attack_type,
            "risk_level": risk_level,
            "confidence": final_score,
            "status": "unprocessed",
            "evidence_json": json.dumps(evidence, ensure_ascii=False),
        })
        attack_count = 1
    upsert_mysql(conn, "model_predictions", {
        "case_id": case_id,
        "model_name": "payload_model_v2",
        "label": case.get("v2_payload_label"),
        "score": case.get("v2_payload_score"),
        "proba_json": json.dumps({}, ensure_ascii=False),
    })
    poc_count = 0
    with conn.cursor() as cur:
        cur.execute("DELETE FROM poc_matches WHERE case_id=%s", (case_id,))
        cur.execute("DELETE FROM behavior_windows WHERE case_id=%s", (case_id,))
    for m in poc_matches:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO poc_matches(case_id,rule_id,rule_name,attack_type,severity,score,evidence_json)
                   VALUES(%s,%s,%s,%s,%s,%s,%s)""",
                (case_id, m.get("rule_id"), m.get("name"), m.get("attack_type"), m.get("severity"), m.get("score"), json.dumps(m.get("evidence") or [], ensure_ascii=False)),
            )
        poc_count += 1
    if case.get("v2_behavior_score") is not None:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO behavior_windows(case_id,source_ip,behavior_type,score,features_json,evidence_json)
                   VALUES(%s,%s,%s,%s,%s,%s)""",
                (case_id, case.get("source_ip"), case.get("v2_behavior_type"), case.get("v2_behavior_score"), json.dumps({}, ensure_ascii=False), json.dumps(evidence, ensure_ascii=False)),
            )
    return {"raw": 1, "candidate": 1, "attack": attack_count, "model": 1, "poc": poc_count, "behavior": 1 if case.get("v2_behavior_score") is not None else 0}


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync v2 detection result cases into layered DB tables")
    parser.add_argument("--result-dir", default="result")
    parser.add_argument("--mysql-host", default="127.0.0.1")
    parser.add_argument("--mysql-port", type=int, default=3306)
    parser.add_argument("--mysql-user", default="root")
    parser.add_argument("--mysql-password", default="123456")
    parser.add_argument("--mysql-database", default="traffic_pipeline")
    args = parser.parse_args()
    project_root = Path(__file__).resolve().parent.parent
    result_dir = (project_root / args.result_dir).resolve()
    cfg = MySQLConfig(args.mysql_host, args.mysql_port, args.mysql_user, args.mysql_password, args.mysql_database)
    conn = mysql_connect(cfg)
    ensure_mysql(conn)
    totals = {"raw": 0, "candidate": 0, "attack": 0, "model": 0, "poc": 0, "behavior": 0, "cases": 0}
    for case_dir in iter_case_dirs(result_dir):
        stats = sync_case_mysql(conn, case_dir)
        totals["cases"] += 1 if stats.get("raw") else 0
        for k in stats:
            totals[k] += stats[k]
    conn.close()
    print(json.dumps(totals, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
