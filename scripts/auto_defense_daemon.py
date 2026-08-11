from __future__ import annotations

import argparse
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import pymysql
from pymysql.cursors import DictCursor

from firewall_control import firewall_block_ip, firewall_status, is_safe_automatic_target, normalize_ip_literal


def log(message: str, path: Path) -> None:
    line = f"[{datetime.now().isoformat(timespec='seconds')}] {message}"
    print(line, flush=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def ensure_schema(conn: Any) -> None:
    with conn.cursor() as cur:
        cur.execute("SHOW COLUMNS FROM demo_blocked_ips LIKE 'defense_latency_ms'")
        if not cur.fetchone():
            cur.execute(
                "ALTER TABLE demo_blocked_ips "
                "ADD COLUMN defense_latency_ms DOUBLE NULL AFTER blocked_role"
            )
    conn.commit()


def load_policy(conn: Any) -> Dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute(
            """SELECT config_key,config_value FROM demo_system_config
               WHERE config_key IN ('auto_defense_enabled','auto_defense_min_risk','auto_defense_allow_private')"""
        )
        values = {str(row["config_key"]): str(row["config_value"] or "") for row in cur.fetchall()}
    return {
        "enabled": values.get("auto_defense_enabled", "0") == "1",
        "minimum_risk": values.get("auto_defense_min_risk", "critical") if values.get("auto_defense_min_risk") in {"high", "critical"} else "critical",
        "allow_private": values.get("auto_defense_allow_private", "0") == "1",
    }


def list_candidates(conn: Any, policy: Dict[str, Any], limit: int = 100) -> List[Dict[str, Any]]:
    levels = ("critical", "high") if policy["minimum_risk"] == "high" else ("critical",)
    placeholders = ",".join(["%s"] * len(levels))
    with conn.cursor() as cur:
        cur.execute(
            f"""SELECT s.source_ip,s.situation_id,s.risk_level,s.risk_score,s.last_action_at,b.id AS blocked_id
                FROM attack_situations s
                LEFT JOIN demo_blocked_ips b ON b.ip_address=s.source_ip
                LEFT JOIN demo_auto_defense_releases r ON r.ip_address=s.source_ip
                WHERE s.status = 'open' AND s.risk_level IN ({placeholders})
                  AND s.last_action_at >= UTC_TIMESTAMP(3) - INTERVAL 24 HOUR
                  AND (r.ip_address IS NULL OR r.released_action_at IS NULL
                       OR s.last_action_at > r.released_action_at)
                ORDER BY s.risk_score DESC,s.last_action_at DESC LIMIT %s""",
            (*levels, max(1, min(500, int(limit)))),
        )
        return list(cur.fetchall())


def run_once(conn: Any) -> Dict[str, int]:
    policy = load_policy(conn)
    # End the read-only transaction so a long-running daemon observes policy
    # changes made by the API instead of retaining MySQL's REPEATABLE READ snapshot.
    conn.commit()
    if not policy["enabled"]:
        return {"enabled": 0, "candidates": 0, "blocked": 0, "skipped": 0, "failed": 0}
    rows = list_candidates(conn, policy)
    # Candidate reads also open a transaction. Release it before the next poll.
    conn.commit()
    stats = {"enabled": 1, "candidates": len(rows), "blocked": 0, "skipped": 0, "failed": 0}
    seen_ips = set()
    for row in rows:
        ip_value = normalize_ip_literal(row.get("source_ip"))
        if ip_value in seen_ips:
            continue
        seen_ips.add(ip_value)
        if not is_safe_automatic_target(ip_value, allow_private=policy["allow_private"]):
            stats["skipped"] += 1
            continue
        if row.get("blocked_id") and firewall_status(ip_value).get("active"):
            stats["skipped"] += 1
            continue
        defense_started = time.perf_counter()
        ok, detail = firewall_block_ip(ip_value)
        defense_latency_ms = (time.perf_counter() - defense_started) * 1000.0
        if not ok:
            stats["failed"] += 1
            continue
        with conn.cursor() as cur:
            cur.execute("DELETE FROM demo_auto_defense_releases WHERE ip_address=%s", (ip_value,))
            cur.execute(
                """INSERT INTO demo_blocked_ips(
                     ip_address,source_event_id,reason,blocked_by,blocked_role,defense_latency_ms
                   ) VALUES(%s,%s,%s,'auto-defense','system',%s)
                   ON DUPLICATE KEY UPDATE source_event_id=VALUES(source_event_id),reason=VALUES(reason),
                     blocked_by='auto-defense',blocked_role='system',
                     defense_latency_ms=VALUES(defense_latency_ms),blocked_at=CURRENT_TIMESTAMP""",
                (
                    ip_value,
                    str(row.get("situation_id") or ""),
                    f"auto_{row.get('risk_level')}_situation",
                    defense_latency_ms,
                ),
            )
        conn.commit()
        stats["blocked"] += 1
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Continuously enforce automatic bidirectional IP blocking")
    parser.add_argument("--mysql-host", default="127.0.0.1")
    parser.add_argument("--mysql-port", type=int, default=3306)
    parser.add_argument("--mysql-user", default="root")
    parser.add_argument("--mysql-password", default="123456")
    parser.add_argument("--mysql-database", default="traffic_pipeline")
    parser.add_argument("--poll-seconds", type=int, default=5)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--log-file", default="output/auto_defense_daemon.log")
    args = parser.parse_args()
    log_path = Path(args.log_file)
    conn = None
    try:
        while True:
            try:
                if conn is None or not conn.open:
                    conn = pymysql.connect(
                        host=args.mysql_host, port=args.mysql_port, user=args.mysql_user,
                        password=args.mysql_password, database=args.mysql_database,
                        charset="utf8mb4", cursorclass=DictCursor, autocommit=False,
                    )
                    ensure_schema(conn)
                stats = run_once(conn)
                if stats["blocked"] or stats["failed"]:
                    log(json.dumps(stats, ensure_ascii=False), log_path)
            except Exception as exc:
                log(f"auto defense failed: {type(exc).__name__}: {exc}", log_path)
                try:
                    if conn:
                        conn.close()
                except Exception:
                    pass
                conn = None
            if args.once:
                break
            time.sleep(max(2, int(args.poll_seconds)))
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    main()
