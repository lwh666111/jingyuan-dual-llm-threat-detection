from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

try:
    import pymysql
    from pymysql.cursors import DictCursor
except Exception:  # pragma: no cover - handled with a clear runtime error
    pymysql = None
    DictCursor = None

from situation_core import SecurityAction, Situation, parse_timestamp


MYSQL_DDL = [
    """
    CREATE TABLE IF NOT EXISTS security_actions (
      action_id VARCHAR(80) PRIMARY KEY,
      source_ip VARCHAR(64) NOT NULL,
      target_asset VARCHAR(255) NOT NULL,
      target_port INT NULL,
      target_interface VARCHAR(512) NULL,
      protocol VARCHAR(24) NULL,
      action_type VARCHAR(64) NOT NULL,
      stage VARCHAR(32) NOT NULL,
      sensor VARCHAR(64) NOT NULL,
      occurred_at DATETIME(3) NOT NULL,
      last_seen_at DATETIME(3) NOT NULL,
      action_count INT NOT NULL DEFAULT 1,
      confidence DOUBLE NOT NULL DEFAULT 0,
      severity VARCHAR(24) NOT NULL DEFAULT 'medium',
      evidence_json LONGTEXT NULL,
      metadata_json LONGTEXT NULL,
      created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
      KEY idx_security_action_source_time (source_ip, occurred_at),
      KEY idx_security_action_type_time (action_type, occurred_at),
      KEY idx_security_action_target_time (target_asset, occurred_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS attack_situations (
      situation_id VARCHAR(80) PRIMARY KEY,
      source_ip VARCHAR(64) NOT NULL,
      target_asset VARCHAR(255) NOT NULL,
      started_at DATETIME(3) NOT NULL,
      last_action_at DATETIME(3) NOT NULL,
      closed_at DATETIME(3) NULL,
      status VARCHAR(24) NOT NULL DEFAULT 'observing',
      distinct_action_types INT NOT NULL DEFAULT 0,
      total_action_count INT NOT NULL DEFAULT 0,
      current_stage VARCHAR(32) NOT NULL DEFAULT 'unknown',
      risk_score DOUBLE NOT NULL DEFAULT 0,
      risk_level VARCHAR(24) NOT NULL DEFAULT 'low',
      sequence_hash VARCHAR(64) NOT NULL,
      ai_status VARCHAR(24) NOT NULL DEFAULT 'pending',
      ai_report_json LONGTEXT NULL,
      created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
      KEY idx_situation_source_time (source_ip, last_action_at),
      KEY idx_situation_status_time (status, last_action_at),
      KEY idx_situation_risk_time (risk_level, last_action_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS situation_actions (
      situation_id VARCHAR(80) NOT NULL,
      action_id VARCHAR(80) NOT NULL,
      sequence_no INT NOT NULL,
      gap_seconds INT NOT NULL DEFAULT 0,
      created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      PRIMARY KEY (situation_id, action_id),
      UNIQUE KEY uniq_situation_sequence (situation_id, sequence_no),
      KEY idx_situation_action_id (action_id),
      CONSTRAINT fk_situation_action_situation FOREIGN KEY (situation_id)
        REFERENCES attack_situations(situation_id) ON DELETE CASCADE,
      CONSTRAINT fk_situation_action_action FOREIGN KEY (action_id)
        REFERENCES security_actions(action_id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS situation_outbox (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      aggregate_type VARCHAR(32) NOT NULL,
      aggregate_id VARCHAR(80) NOT NULL,
      event_type VARCHAR(64) NOT NULL,
      event_key VARCHAR(160) NOT NULL,
      payload_json LONGTEXT NOT NULL,
      status VARCHAR(24) NOT NULL DEFAULT 'pending',
      retry_count INT NOT NULL DEFAULT 0,
      last_error TEXT NULL,
      created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      processed_at DATETIME(3) NULL,
      UNIQUE KEY uniq_situation_outbox_event (event_key),
      KEY idx_situation_outbox_status (status, created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
]


@dataclass(frozen=True)
class MySQLSettings:
    host: str = "127.0.0.1"
    port: int = 3306
    user: str = "root"
    password: str = "123456"
    database: str = "traffic_pipeline"


def utc_naive(value: datetime) -> datetime:
    return parse_timestamp(value).astimezone(timezone.utc).replace(tzinfo=None)


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def json_value(value: Any, default: Any) -> Any:
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


class MySQLSituationStore:
    def __init__(self, settings: MySQLSettings, connection: Any = None) -> None:
        self.settings = settings
        self._connection = connection

    def connect(self) -> Any:
        if self._connection is not None:
            return self._connection
        if pymysql is None:
            raise RuntimeError("PyMySQL 未安装，无法使用态势数据库")
        self._connection = pymysql.connect(
            host=self.settings.host,
            port=int(self.settings.port),
            user=self.settings.user,
            password=self.settings.password,
            database=self.settings.database,
            charset="utf8mb4",
            autocommit=False,
            cursorclass=DictCursor,
            connect_timeout=5,
            read_timeout=15,
            write_timeout=15,
        )
        return self._connection

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def ensure_schema(self) -> None:
        conn = self.connect()
        try:
            with conn.cursor() as cur:
                for ddl in MYSQL_DDL:
                    cur.execute(ddl)
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def upsert_actions(self, actions: Iterable[SecurityAction]) -> int:
        rows = list(actions)
        if not rows:
            return 0
        sql = """
            INSERT INTO security_actions (
              action_id, source_ip, target_asset, target_port, target_interface,
              protocol, action_type, stage, sensor, occurred_at, last_seen_at,
              action_count, confidence, severity, evidence_json, metadata_json
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
              source_ip=VALUES(source_ip), target_asset=VALUES(target_asset),
              target_port=VALUES(target_port), target_interface=VALUES(target_interface),
              protocol=VALUES(protocol), action_type=VALUES(action_type), stage=VALUES(stage),
              sensor=VALUES(sensor), occurred_at=VALUES(occurred_at),
              last_seen_at=VALUES(last_seen_at), action_count=VALUES(action_count),
              confidence=VALUES(confidence), severity=VALUES(severity),
              evidence_json=VALUES(evidence_json), metadata_json=VALUES(metadata_json)
        """
        values = [
            (
                row.action_id,
                row.source_ip,
                row.target_asset,
                row.target_port,
                row.target_interface,
                row.protocol,
                row.action_type,
                row.stage,
                row.sensor,
                utc_naive(row.occurred_at),
                utc_naive(row.last_seen_at or row.occurred_at),
                row.count,
                row.confidence,
                row.severity,
                json_text(row.evidence_refs),
                json_text(row.metadata),
            )
            for row in rows
        ]
        conn = self.connect()
        try:
            with conn.cursor() as cur:
                cur.executemany(sql, values)
            conn.commit()
            return len(rows)
        except Exception:
            conn.rollback()
            raise

    def upsert_situation(self, situation: Situation, emit_outbox: bool = True) -> bool:
        conn = self.connect()
        changed = True
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT sequence_hash FROM attack_situations WHERE situation_id=%s FOR UPDATE",
                    (situation.situation_id,),
                )
                existing = cur.fetchone()
                changed = not existing or existing.get("sequence_hash") != situation.sequence_hash
                cur.execute(
                    """
                    INSERT INTO attack_situations (
                      situation_id, source_ip, target_asset, started_at, last_action_at,
                      status, distinct_action_types, total_action_count, current_stage,
                      risk_score, risk_level, sequence_hash, ai_status
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON DUPLICATE KEY UPDATE
                      source_ip=VALUES(source_ip), target_asset=VALUES(target_asset),
                      started_at=VALUES(started_at), last_action_at=VALUES(last_action_at),
                      status=IF(status='handled','handled',VALUES(status)),
                      distinct_action_types=VALUES(distinct_action_types),
                      total_action_count=VALUES(total_action_count),
                      current_stage=VALUES(current_stage), risk_score=VALUES(risk_score),
                      risk_level=VALUES(risk_level),
                      ai_status=IF(sequence_hash<>VALUES(sequence_hash),'pending',ai_status),
                      sequence_hash=VALUES(sequence_hash)
                    """,
                    (
                        situation.situation_id,
                        situation.source_ip,
                        situation.target_asset,
                        utc_naive(situation.started_at),
                        utc_naive(situation.last_action_at),
                        situation.status,
                        situation.distinct_action_types,
                        situation.total_action_count,
                        situation.current_stage,
                        situation.risk_score,
                        situation.risk_level,
                        situation.sequence_hash,
                        "pending",
                    ),
                )
                cur.execute("DELETE FROM situation_actions WHERE situation_id=%s", (situation.situation_id,))
                previous: Optional[SecurityAction] = None
                for sequence_no, action in enumerate(situation.actions, start=1):
                    gap_seconds = 0
                    if previous is not None:
                        gap_seconds = max(
                            0,
                            int((action.occurred_at - (previous.last_seen_at or previous.occurred_at)).total_seconds()),
                        )
                    cur.execute(
                        """INSERT INTO situation_actions(situation_id,action_id,sequence_no,gap_seconds)
                           VALUES(%s,%s,%s,%s)""",
                        (situation.situation_id, action.action_id, sequence_no, gap_seconds),
                    )
                    previous = action
                if changed and emit_outbox:
                    event_key = f"situation:{situation.situation_id}:{situation.sequence_hash}"
                    cur.execute(
                        """
                        INSERT IGNORE INTO situation_outbox(
                          aggregate_type,aggregate_id,event_type,event_key,payload_json
                        ) VALUES('situation',%s,'situation.changed',%s,%s)
                        """,
                        (situation.situation_id, event_key, json_text(situation.as_dict())),
                    )
            conn.commit()
            return changed
        except Exception:
            conn.rollback()
            raise

    def save(self, situations: Sequence[Situation], emit_outbox: bool = True) -> Dict[str, int]:
        actions = {action.action_id: action for situation in situations for action in situation.actions}
        action_count = self.upsert_actions(actions.values())
        changed = sum(1 for item in situations if self.upsert_situation(item, emit_outbox=emit_outbox))
        return {"actions": action_count, "situations": len(situations), "changed": changed}

    def list_situations(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        source_ip: str = "",
        status: str = "",
        minimum_risk: float = 0.0,
    ) -> List[Dict[str, Any]]:
        where = ["risk_score >= %s"]
        values: List[Any] = [max(0.0, min(1.0, float(minimum_risk)))]
        if source_ip:
            where.append("source_ip = %s")
            values.append(source_ip)
        if status:
            where.append("status = %s")
            values.append(status)
        else:
            where.append("status <> 'observing'")
        values.extend([max(1, min(500, int(limit))), max(0, int(offset))])
        sql = f"""
            SELECT situation_id,source_ip,target_asset,started_at,last_action_at,status,
                   distinct_action_types,total_action_count,current_stage,risk_score,
                   risk_level,sequence_hash,ai_status,ai_report_json
            FROM attack_situations WHERE {' AND '.join(where)}
            ORDER BY last_action_at DESC LIMIT %s OFFSET %s
        """
        conn = self.connect()
        with conn.cursor() as cur:
            cur.execute(sql, tuple(values))
            rows = list(cur.fetchall())
        # PyMySQL starts a transaction for SELECT when autocommit is disabled.
        # End it explicitly so long-running daemons never retain metadata locks.
        conn.commit()
        for row in rows:
            row["ai_report"] = json_value(row.pop("ai_report_json", None), None)
        return rows

    def list_actions(self, *, lookback_days: int = 30, limit: int = 100000) -> List[SecurityAction]:
        conn = self.connect()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM security_actions
                WHERE occurred_at >= UTC_TIMESTAMP(3) - INTERVAL %s DAY
                ORDER BY occurred_at ASC LIMIT %s
                """,
                (max(1, int(lookback_days)), max(1, min(500000, int(limit)))),
            )
            rows = list(cur.fetchall())
        conn.commit()
        return [self._action_from_db(row) for row in rows]

    @staticmethod
    def _action_from_db(row: Dict[str, Any]) -> SecurityAction:
        occurred_at = row.get("occurred_at")
        last_seen_at = row.get("last_seen_at")
        if isinstance(occurred_at, datetime) and occurred_at.tzinfo is None:
            occurred_at = occurred_at.replace(tzinfo=timezone.utc)
        if isinstance(last_seen_at, datetime) and last_seen_at.tzinfo is None:
            last_seen_at = last_seen_at.replace(tzinfo=timezone.utc)
        return SecurityAction(
            action_id=str(row.get("action_id") or ""),
            source_ip=str(row.get("source_ip") or ""),
            target_asset=str(row.get("target_asset") or "local-server"),
            target_port=row.get("target_port"),
            target_interface=str(row.get("target_interface") or ""),
            protocol=str(row.get("protocol") or ""),
            action_type=str(row.get("action_type") or "UNKNOWN"),
            occurred_at=occurred_at,
            last_seen_at=last_seen_at,
            sensor=str(row.get("sensor") or "unknown"),
            count=int(row.get("action_count") or 1),
            confidence=float(row.get("confidence") or 0),
            severity=str(row.get("severity") or "medium"),
            evidence_refs=json_value(row.get("evidence_json"), []),
            metadata=json_value(row.get("metadata_json"), {}),
        )

    def get_situation(self, situation_id: str) -> Optional[Dict[str, Any]]:
        conn = self.connect()
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM attack_situations WHERE situation_id=%s", (situation_id,))
            situation = cur.fetchone()
            if not situation:
                conn.commit()
                return None
            cur.execute(
                """
                SELECT sa.sequence_no,sa.gap_seconds,a.*
                FROM situation_actions sa
                JOIN security_actions a ON a.action_id=sa.action_id
                WHERE sa.situation_id=%s ORDER BY sa.sequence_no
                """,
                (situation_id,),
            )
            actions = list(cur.fetchall())
        conn.commit()
        situation["ai_report"] = json_value(situation.pop("ai_report_json", None), None)
        for action in actions:
            action["evidence_refs"] = json_value(action.pop("evidence_json", None), [])
            action["metadata"] = json_value(action.pop("metadata_json", None), {})
        situation["actions"] = actions
        return situation

    def list_pending_ai(self, limit: int = 10) -> List[Dict[str, Any]]:
        conn = self.connect()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT situation_id FROM attack_situations
                WHERE ai_status IN ('pending','retry')
                  AND status IN ('open','closed')
                ORDER BY risk_score DESC,last_action_at DESC LIMIT %s
                """,
                (max(1, min(100, int(limit))),),
            )
            ids = [str(row["situation_id"]) for row in cur.fetchall()]
        conn.commit()
        return [row for row in (self.get_situation(item_id) for item_id in ids) if row]

    def update_ai_report(self, situation_id: str, report: Dict[str, Any], status: str = "complete") -> bool:
        conn = self.connect()
        try:
            with conn.cursor() as cur:
                affected = cur.execute(
                    "UPDATE attack_situations SET ai_status=%s,ai_report_json=%s WHERE situation_id=%s",
                    (status, json_text(report), situation_id),
                )
            conn.commit()
            return bool(affected)
        except Exception:
            conn.rollback()
            raise

    def update_status(self, situation_id: str, status: str) -> bool:
        allowed = {"observing", "open", "closed", "handled", "ignored"}
        if status not in allowed:
            raise ValueError(f"不支持的态势状态: {status}")
        conn = self.connect()
        try:
            with conn.cursor() as cur:
                affected = cur.execute(
                    """UPDATE attack_situations
                       SET status=%s,closed_at=IF(%s IN ('closed','handled','ignored'),UTC_TIMESTAMP(3),NULL)
                       WHERE situation_id=%s""",
                    (status, status, situation_id),
                )
            conn.commit()
            return bool(affected)
        except Exception:
            conn.rollback()
            raise
