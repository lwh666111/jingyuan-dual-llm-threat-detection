from __future__ import annotations

import argparse
import json
import socket
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

from situation_core import SituationCorrelator, action_from_attack_event
from situation_store import MySQLSettings, MySQLSituationStore


def now_text() -> str:
    return datetime.now().isoformat(timespec="seconds")


def log(message: str, path: Path) -> None:
    line = f"[{now_text()}] {message}"
    print(line, flush=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def load_attack_events(store: MySQLSituationStore, lookback_days: int, target_asset: str) -> List[Any]:
    conn = store.connect()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT event_id,case_id,occurred_at,source_ip,target_interface,
                   attack_type,risk_level,confidence,status,evidence_json,created_at
            FROM attack_events
            WHERE created_at >= UTC_TIMESTAMP() - INTERVAL %s DAY
              AND source_ip IS NOT NULL AND source_ip <> ''
            ORDER BY created_at ASC LIMIT 200000
            """,
            (max(1, int(lookback_days)),),
        )
        rows: List[Dict[str, Any]] = list(cur.fetchall())
    actions = []
    for row in rows:
        try:
            actions.append(action_from_attack_event(row, target_asset=target_asset))
        except Exception as exc:
            log_path = Path("output") / "situation_daemon_bad_rows.log"
            log(f"skip event={row.get('event_id')}: {exc}", log_path)
    return actions


def run_once(
    store: MySQLSituationStore,
    correlator: SituationCorrelator,
    *,
    lookback_days: int,
    target_asset: str,
) -> Dict[str, int]:
    imported = load_attack_events(store, lookback_days, target_asset)
    store.upsert_actions(imported)
    actions = store.list_actions(lookback_days=lookback_days)
    situations = correlator.correlate(actions, include_observing=True)
    stale_before = datetime.now(timezone.utc) - correlator.inactivity
    for situation in situations:
        if situation.last_action_at < stale_before:
            situation.status = "closed" if situation.distinct_action_types >= correlator.minimum_distinct_actions else "observing"
    saved = store.save(situations)
    return {
        "imported_events": len(imported),
        "actions": len(actions),
        "situations": saved["situations"],
        "changed": saved["changed"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Correlate normalized security actions into attacker situations")
    parser.add_argument("--mysql-host", default="127.0.0.1")
    parser.add_argument("--mysql-port", type=int, default=3306)
    parser.add_argument("--mysql-user", default="root")
    parser.add_argument("--mysql-password", default="123456")
    parser.add_argument("--mysql-database", default="traffic_pipeline")
    parser.add_argument("--target-asset", default=socket.gethostname())
    parser.add_argument("--minimum-actions", type=int, default=3)
    parser.add_argument("--window-minutes", type=int, default=30)
    parser.add_argument("--inactivity-minutes", type=int, default=15)
    parser.add_argument("--lookback-days", type=int, default=30)
    parser.add_argument("--poll-seconds", type=int, default=10)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--log-file", default="output/situation_daemon.log")
    args = parser.parse_args()

    log_file = Path(args.log_file)
    store = MySQLSituationStore(
        MySQLSettings(args.mysql_host, args.mysql_port, args.mysql_user, args.mysql_password, args.mysql_database)
    )
    correlator = SituationCorrelator(args.minimum_actions, args.window_minutes, args.inactivity_minutes)
    store.ensure_schema()
    log(
        f"started target={args.target_asset} minimum={correlator.minimum_distinct_actions} "
        f"window={args.window_minutes}m inactivity={args.inactivity_minutes}m",
        log_file,
    )
    try:
        while True:
            started = time.monotonic()
            try:
                stats = run_once(
                    store,
                    correlator,
                    lookback_days=args.lookback_days,
                    target_asset=args.target_asset,
                )
                log("sync " + json.dumps(stats, ensure_ascii=False), log_file)
            except Exception as exc:
                log(f"sync failed: {type(exc).__name__}: {exc}", log_file)
                try:
                    store.close()
                except Exception:
                    pass
            if args.once:
                break
            elapsed = time.monotonic() - started
            time.sleep(max(1.0, float(args.poll_seconds) - elapsed))
    finally:
        store.close()


if __name__ == "__main__":
    main()
