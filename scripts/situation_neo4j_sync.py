from __future__ import annotations

import argparse
import base64
import json
import time
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Sequence

from situation_store import MySQLSettings, MySQLSituationStore, json_value


def log(message: str) -> None:
    print(f"[{datetime.now().isoformat(timespec='seconds')}] {message}", flush=True)


class Neo4jHTTPClient:
    def __init__(self, url: str, user: str, password: str, database: str = "neo4j", timeout: int = 15) -> None:
        base = str(url or "").strip().rstrip("/")
        if not base.startswith(("http://", "https://")):
            raise ValueError("Neo4j 地址必须以 http:// 或 https:// 开头")
        self.endpoint = f"{base}/db/{database or 'neo4j'}/tx/commit"
        token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        self.headers = {"Content-Type": "application/json", "Authorization": f"Basic {token}"}
        self.timeout = max(3, int(timeout))

    def execute(self, statements: Sequence[Dict[str, Any]]) -> None:
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps({"statements": list(statements)}, ensure_ascii=False, default=str).encode("utf-8"),
            headers=self.headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            result = json.loads(response.read().decode("utf-8"))
        errors = result.get("errors") if isinstance(result, dict) else None
        if errors:
            first = errors[0] if isinstance(errors, list) else errors
            raise RuntimeError(f"Neo4j 写入失败: {first}")


def build_statements(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    actions = list(payload.get("actions") or [])
    normalized_actions: List[Dict[str, Any]] = []
    for index, row in enumerate(actions, start=1):
        normalized_actions.append(
            {
                "action_id": str(row.get("action_id") or f"{payload.get('situation_id')}:action:{index}"),
                "action_type": str(row.get("action_type") or "UNKNOWN"),
                "stage": str(row.get("stage") or "unknown"),
                "sensor": str(row.get("sensor") or "unknown"),
                "occurred_at": str(row.get("occurred_at") or ""),
                "last_seen_at": str(row.get("last_seen_at") or row.get("occurred_at") or ""),
                "count": int(row.get("count") or row.get("action_count") or 1),
                "confidence": float(row.get("confidence") or 0),
                "sequence": index,
            }
        )
    links = [
        {"from_id": normalized_actions[i]["action_id"], "to_id": normalized_actions[i + 1]["action_id"]}
        for i in range(max(0, len(normalized_actions) - 1))
    ]
    common = {
        "situation_id": str(payload.get("situation_id") or ""),
        "source_ip": str(payload.get("source_ip") or ""),
        "target_asset": str(payload.get("target_asset") or "local-server"),
        "started_at": str(payload.get("started_at") or ""),
        "last_action_at": str(payload.get("last_action_at") or ""),
        "status": str(payload.get("status") or "observing"),
        "current_stage": str(payload.get("current_stage") or "unknown"),
        "risk_score": float(payload.get("risk_score") or 0),
        "risk_level": str(payload.get("risk_level") or "low"),
        "total_action_count": int(payload.get("total_action_count") or 0),
        "distinct_action_types": int(payload.get("distinct_action_types") or 0),
        "actions": normalized_actions,
        "links": links,
    }
    return [
        {
            "statement": """
                MERGE (src:SourceIP {address:$source_ip})
                MERGE (asset:Asset {name:$target_asset})
                MERGE (s:Situation {id:$situation_id})
                SET s.started_at=$started_at, s.last_action_at=$last_action_at,
                    s.status=$status, s.current_stage=$current_stage,
                    s.risk_score=$risk_score, s.risk_level=$risk_level,
                    s.total_action_count=$total_action_count,
                    s.distinct_action_types=$distinct_action_types
                MERGE (src)-[:GENERATED]->(s)
                MERGE (s)-[:TARGETED]->(asset)
            """,
            "parameters": common,
        },
        {
            "statement": """
                MATCH (s:Situation {id:$situation_id})
                MATCH (s)-[:HAS_ACTION]->(a:Action)
                OPTIONAL MATCH (a)-[next:NEXT]->()
                DELETE next
            """,
            "parameters": common,
        },
        {
            "statement": """
                MATCH (s:Situation {id:$situation_id})
                OPTIONAL MATCH (s)-[r:HAS_ACTION]->(:Action)
                DELETE r
            """,
            "parameters": common,
        },
        {
            "statement": """
                MATCH (s:Situation {id:$situation_id})
                UNWIND $actions AS row
                MERGE (a:Action {id:row.action_id})
                SET a.action_type=row.action_type, a.stage=row.stage, a.sensor=row.sensor,
                    a.occurred_at=row.occurred_at, a.last_seen_at=row.last_seen_at,
                    a.count=row.count, a.confidence=row.confidence
                MERGE (s)-[:HAS_ACTION {sequence:row.sequence}]->(a)
            """,
            "parameters": common,
        },
        {
            "statement": """
                UNWIND $links AS link
                MATCH (a:Action {id:link.from_id}), (b:Action {id:link.to_id})
                MERGE (a)-[:NEXT]->(b)
            """,
            "parameters": common,
        },
    ]


def claim_outbox(store: MySQLSituationStore, limit: int) -> List[Dict[str, Any]]:
    conn = store.connect()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE situation_outbox SET status='retry' WHERE status='processing' AND created_at < UTC_TIMESTAMP() - INTERVAL 10 MINUTE"
            )
            cur.execute(
                """
                SELECT id,aggregate_id,payload_json,retry_count
                FROM situation_outbox
                WHERE status IN ('pending','retry') AND retry_count < 10
                ORDER BY id LIMIT %s FOR UPDATE
                """,
                (max(1, min(100, int(limit))),),
            )
            rows = list(cur.fetchall())
            if rows:
                cur.executemany(
                    "UPDATE situation_outbox SET status='processing' WHERE id=%s",
                    [(row["id"],) for row in rows],
                )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    for row in rows:
        row["payload"] = json_value(row.pop("payload_json", None), {})
    return rows


def finish_outbox(store: MySQLSituationStore, outbox_id: int, error: str = "") -> None:
    conn = store.connect()
    try:
        with conn.cursor() as cur:
            if error:
                cur.execute(
                    """UPDATE situation_outbox
                       SET status='retry',retry_count=retry_count+1,last_error=%s
                       WHERE id=%s""",
                    (error[:2000], outbox_id),
                )
            else:
                cur.execute(
                    """UPDATE situation_outbox
                       SET status='processed',processed_at=UTC_TIMESTAMP(3),last_error=NULL
                       WHERE id=%s""",
                    (outbox_id,),
                )
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def sync_once(store: MySQLSituationStore, client: Neo4jHTTPClient, batch_size: int = 20) -> Dict[str, int]:
    rows = claim_outbox(store, batch_size)
    success = 0
    failed = 0
    for row in rows:
        try:
            client.execute(build_statements(row["payload"]))
            finish_outbox(store, int(row["id"]))
            success += 1
        except Exception as exc:
            finish_outbox(store, int(row["id"]), f"{type(exc).__name__}: {exc}")
            failed += 1
    return {"claimed": len(rows), "success": success, "failed": failed}


def main() -> None:
    parser = argparse.ArgumentParser(description="Mirror MySQL attack situations to optional Neo4j")
    parser.add_argument("--mysql-host", default="127.0.0.1")
    parser.add_argument("--mysql-port", type=int, default=3306)
    parser.add_argument("--mysql-user", default="root")
    parser.add_argument("--mysql-password", default="123456")
    parser.add_argument("--mysql-database", default="traffic_pipeline")
    parser.add_argument("--neo4j-url", required=True)
    parser.add_argument("--neo4j-user", default="neo4j")
    parser.add_argument("--neo4j-password", required=True)
    parser.add_argument("--neo4j-database", default="neo4j")
    parser.add_argument("--batch-size", type=int, default=20)
    parser.add_argument("--poll-seconds", type=int, default=10)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    store = MySQLSituationStore(
        MySQLSettings(args.mysql_host, args.mysql_port, args.mysql_user, args.mysql_password, args.mysql_database)
    )
    client = Neo4jHTTPClient(args.neo4j_url, args.neo4j_user, args.neo4j_password, args.neo4j_database)
    store.ensure_schema()
    try:
        while True:
            stats = sync_once(store, client, args.batch_size)
            if stats["claimed"] or stats["failed"]:
                log("neo4j sync " + json.dumps(stats, ensure_ascii=False))
            if args.once:
                break
            time.sleep(max(1, int(args.poll_seconds)))
    finally:
        store.close()


if __name__ == "__main__":
    main()
