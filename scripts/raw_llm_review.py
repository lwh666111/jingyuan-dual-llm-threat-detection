from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, Optional


QUEUE_DDL = """
CREATE TABLE IF NOT EXISTS llm_review_jobs (
  event_id VARCHAR(64) PRIMARY KEY,
  case_id VARCHAR(64) NOT NULL,
  preliminary_decision VARCHAR(32) NOT NULL,
  priority INT NOT NULL DEFAULT 50,
  status VARCHAR(24) NOT NULL DEFAULT 'pending',
  attempts INT NOT NULL DEFAULT 0,
  next_retry_at DATETIME NULL,
  started_at DATETIME NULL,
  completed_at DATETIME NULL,
  model_name VARCHAR(255) NULL,
  error_message TEXT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_llm_review_case (case_id),
  KEY idx_llm_review_ready (status, next_retry_at, priority, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
"""

CACHE_DDL = """
CREATE TABLE IF NOT EXISTS llm_review_cache (
  fingerprint CHAR(64) PRIMARY KEY,
  target_port INT NOT NULL,
  method VARCHAR(16) NOT NULL,
  uri TEXT NOT NULL,
  template_json LONGTEXT NOT NULL,
  model_name VARCHAR(255) NULL,
  hit_count INT NOT NULL DEFAULT 0,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  KEY idx_review_cache_port (target_port, enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
"""

ANALYSES_DDL = """
CREATE TABLE IF NOT EXISTS analyses (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  case_id VARCHAR(64) NOT NULL UNIQUE,
  file_id VARCHAR(128) NULL,
  seq_id INT NULL,
  llm_status VARCHAR(32) NULL,
  llm_error TEXT NULL,
  llm_started_at DATETIME NULL,
  llm_failed_at DATETIME NULL,
  analyzed_at DATETIME NULL,
  model_name VARCHAR(255) NULL,
  verdict VARCHAR(32) NULL,
  source_ip VARCHAR(64) NULL,
  destination_ip VARCHAR(64) NULL,
  attack_interface TEXT NULL,
  attack_method VARCHAR(255) NULL,
  attack_path TEXT NULL,
  attack_time DATETIME NULL,
  severity VARCHAR(32) NULL,
  confidence DOUBLE NULL,
  summary LONGTEXT NULL,
  evidence_json LONGTEXT NULL,
  analysis_raw LONGTEXT NULL,
  attack_event_time DATETIME NULL,
  attack_ip VARCHAR(64) NULL,
  target_interface TEXT NULL,
  attack_type VARCHAR(255) NULL,
  attack_confidence DOUBLE NULL,
  rag_enabled TINYINT(1) NOT NULL DEFAULT 0,
  rag_hits INT NOT NULL DEFAULT 0,
  review_latency_ms INT NULL,
  handling_suggestion LONGTEXT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  KEY idx_analyses_status (llm_status),
  KEY idx_analyses_verdict (verdict)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
"""


def _column_exists(cur: Any, table: str, column: str) -> bool:
    cur.execute(f"SHOW COLUMNS FROM `{table}` LIKE %s", (column,))
    return bool(cur.fetchone())


def ensure_review_schema(conn: Any) -> None:
    with conn.cursor() as cur:
        cur.execute(ANALYSES_DDL)
        cur.execute(QUEUE_DDL)
        cur.execute(CACHE_DDL)
        additions = {
            "rag_enabled": "TINYINT(1) NOT NULL DEFAULT 0",
            "rag_hits": "INT NOT NULL DEFAULT 0",
            "review_latency_ms": "INT NULL",
            "handling_suggestion": "LONGTEXT NULL",
            "review_source": "VARCHAR(32) NULL",
            "request_fingerprint": "CHAR(64) NULL",
        }
        for column, sql_type in additions.items():
            if not _column_exists(cur, "analyses", column):
                cur.execute(f"ALTER TABLE analyses ADD COLUMN `{column}` {sql_type}")


def request_fingerprint(row: Dict[str, Any]) -> str:
    """Strict target-lab signature, excluding source identity and capture time."""
    request_text = str(row.get("request_text") or "")
    content_type_match = re.search(r"(?m)^CONTENT_TYPE=(.*)$", request_text)
    request_body_match = re.search(
        r"(?ms)^REQUEST_BODY=(.*?)(?=^RESPONSE_EXCERPT=|\Z)", request_text
    )
    content_type = content_type_match.group(1).rstrip("\r") if content_type_match else ""
    request_body = request_body_match.group(1).rstrip("\r\n") if request_body_match else ""
    canonical = "\n".join(
        [
            str(_target_port(row) or ""),
            str(row.get("method") or "").upper(),
            urllib.parse.unquote(str(row.get("uri") or "")),
            content_type,
            request_body,
        ]
    )
    return hashlib.sha256(canonical.encode("utf-8", errors="surrogatepass")).hexdigest()


def realtime_llm_enabled(conn: Any) -> bool:
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT config_value FROM demo_system_config WHERE config_key='llm_realtime_enabled' LIMIT 1"
            )
            row = cur.fetchone() or {}
        return str(row.get("config_value", "1")).strip().lower() in {"1", "true", "yes", "on"}
    except Exception:
        return True


def find_cached_review(conn: Any, row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if _target_port(row) != 4000:
        return None
    fingerprint = request_fingerprint(row)
    with conn.cursor() as cur:
        cur.execute(
            """SELECT fingerprint,template_json,model_name FROM llm_review_cache
               WHERE fingerprint=%s AND target_port=4000 AND enabled=1 LIMIT 1""",
            (fingerprint,),
        )
        cached = cur.fetchone()
    if not cached:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT a.request_fingerprint AS fingerprint,
                          a.analysis_raw AS template_json,a.model_name
                   FROM analyses a
                   WHERE a.verdict='attack' AND a.llm_status='done'
                     AND a.review_source='realtime_llm'
                     AND a.request_fingerprint IS NOT NULL
                     AND a.request_fingerprint=%s
                   ORDER BY a.analyzed_at DESC LIMIT 1""",
                (fingerprint,),
            )
            cached = cur.fetchone()
        if cached:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT IGNORE INTO llm_review_cache(
                         fingerprint,target_port,method,uri,template_json,model_name,enabled
                       ) VALUES(%s,4000,%s,%s,%s,%s,1)""",
                    (
                        fingerprint, str(row.get("method") or "")[:16], str(row.get("uri") or ""),
                        cached.get("template_json"), cached.get("model_name"),
                    ),
                )
    if not cached:
        return None
    try:
        cached["analysis"] = json.loads(str(cached.get("template_json") or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return cached


def defer_review(conn: Any, event_id: str, ready_at: datetime) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE llm_review_jobs SET status='pending',started_at=NULL,
               attempts=GREATEST(0,attempts-1),next_retry_at=%s WHERE event_id=%s""",
            (ready_at, event_id),
        )


def mark_cache_hit(conn: Any, fingerprint: str) -> None:
    with conn.cursor() as cur:
        cur.execute("UPDATE llm_review_cache SET hit_count=hit_count+1 WHERE fingerprint=%s", (fingerprint,))


def enqueue_review(
    conn: Any,
    *,
    event_id: str,
    case_id: str,
    preliminary_decision: str,
    final_score: Any,
) -> None:
    try:
        score = float(final_score or 0.0)
    except Exception:
        score = 0.0
    priority = max(1, min(100, int(round(score * 100))))
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO llm_review_jobs(event_id, case_id, preliminary_decision, priority, status, next_retry_at)
            VALUES(%s,%s,%s,%s,'pending',NOW())
            ON DUPLICATE KEY UPDATE
              case_id=VALUES(case_id),
              preliminary_decision=VALUES(preliminary_decision),
              priority=VALUES(priority),
              status=CASE
                WHEN status IN ('processing','done') THEN status
                ELSE 'pending'
              END,
              next_retry_at=CASE WHEN status IN ('processing','done') THEN next_retry_at ELSE NOW() END,
              error_message=CASE WHEN status IN ('processing','done') THEN error_message ELSE NULL END
            """,
            (event_id, case_id, preliminary_decision, priority),
        )


def prioritize_cached_review(conn: Any, event_id: str, row: Dict[str, Any]) -> bool:
    """Promote an exact verified fingerprint without changing normal queue order."""
    fingerprint = request_fingerprint(row)
    target_port = _target_port(row)
    if not fingerprint or target_port != 4000:
        return False
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM llm_review_cache WHERE fingerprint=%s AND target_port=4000 AND enabled=1 LIMIT 1",
            (fingerprint,),
        )
        if not cur.fetchone():
            return False
        cur.execute(
            "UPDATE llm_review_jobs SET priority=1000,next_retry_at=NOW() WHERE event_id=%s AND status='pending'",
            (event_id,),
        )
    return True


def remove_review(conn: Any, event_id: str, case_id: str) -> None:
    with conn.cursor() as cur:
        cur.execute("DELETE FROM llm_review_jobs WHERE event_id=%s OR case_id=%s", (event_id, case_id))
        cur.execute("DELETE FROM analyses WHERE case_id=%s", (case_id,))


def claim_next_review(conn: Any, *, max_attempts: int = 3) -> Optional[Dict[str, Any]]:
    conn.begin()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE llm_review_jobs
                SET status='pending', started_at=NULL,
                    attempts=GREATEST(0,attempts-1),
                    error_message=CONCAT(COALESCE(error_message,''), ' [recovered stale job]')
                WHERE status='processing' AND started_at < NOW() - INTERVAL 10 MINUTE
                """
            )
            cur.execute(
                """
                SELECT event_id,case_id,preliminary_decision,priority,attempts
                FROM llm_review_jobs
                WHERE status IN ('pending','failed')
                  AND attempts < %s
                  AND (next_retry_at IS NULL OR next_retry_at <= NOW())
                ORDER BY (priority >= 1000) DESC,created_at ASC,priority DESC
                LIMIT 1 FOR UPDATE
                """,
                (max(1, int(max_attempts)),),
            )
            job = cur.fetchone()
            if not job:
                conn.commit()
                return None
            cur.execute(
                """
                UPDATE llm_review_jobs
                SET status='processing', attempts=attempts+1, started_at=NOW(),
                    completed_at=NULL, error_message=NULL
                WHERE event_id=%s
                """,
                (job["event_id"],),
            )
            # Point lookups use indexed keys. The old cross-collation joins
            # scanned the full RAW table as it grew beyond 600k records.
            cur.execute(
                """SELECT file_id,seq_id,final_score,risk_level,attack_type,
                          source_ip,target_interface,evidence_json
                   FROM detection_candidates WHERE event_id=%s LIMIT 1""",
                (job["event_id"],),
            )
            candidate = cur.fetchone()
            cur.execute(
                """SELECT event_time,destination_ip,method,uri,host,status_code,
                          request_text,response_text
                   FROM raw_http_logs WHERE case_id=%s LIMIT 1""",
                (job["case_id"],),
            )
            raw = cur.fetchone()
            if not candidate or not raw:
                cur.execute("DELETE FROM llm_review_jobs WHERE event_id=%s", (job["event_id"],))
                conn.commit()
                return None
            row = {**job, **candidate, **raw}
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT model_name, label, score, proba_json
            FROM model_predictions WHERE case_id=%s ORDER BY id DESC LIMIT 10
            """,
            (row["case_id"],),
        )
        row["model_predictions"] = list(cur.fetchall())
        cur.execute(
            """
            SELECT rule_id, rule_name, attack_type, severity, score, evidence_json
            FROM poc_matches WHERE case_id=%s ORDER BY score DESC LIMIT 20
            """,
            (row["case_id"],),
        )
        row["poc_matches"] = list(cur.fetchall())
        cur.execute(
            """
            SELECT source_ip, behavior_type, score, features_json, evidence_json
            FROM behavior_windows WHERE case_id=%s ORDER BY score DESC LIMIT 10
            """,
            (row["case_id"],),
        )
        row["behavior_windows"] = list(cur.fetchall())
    return row


def detection_context(row: Dict[str, Any]) -> Dict[str, Any]:
    def decode(value: Any, default: Any) -> Any:
        if isinstance(value, (dict, list)):
            return value
        try:
            return json.loads(str(value or ""))
        except Exception:
            return default

    predictions = []
    for item in row.get("model_predictions") or []:
        predictions.append(
            {
                "model_name": item.get("model_name"),
                "label": item.get("label"),
                "score": item.get("score"),
                "probabilities": decode(item.get("proba_json"), {}),
            }
        )
    pocs = []
    for item in row.get("poc_matches") or []:
        pocs.append(
            {
                "rule_id": item.get("rule_id"),
                "rule_name": item.get("rule_name"),
                "attack_type": item.get("attack_type"),
                "severity": item.get("severity"),
                "score": item.get("score"),
                "evidence": decode(item.get("evidence_json"), []),
            }
        )
    behaviors = []
    for item in row.get("behavior_windows") or []:
        behaviors.append(
            {
                "source_ip": item.get("source_ip"),
                "behavior_type": item.get("behavior_type"),
                "score": item.get("score"),
                "features": decode(item.get("features_json"), {}),
                "evidence": decode(item.get("evidence_json"), []),
            }
        )
    return {
        "preliminary_decision": row.get("preliminary_decision"),
        "fusion_score": row.get("final_score"),
        "fusion_risk": row.get("risk_level"),
        "fusion_attack_type": row.get("attack_type"),
        "fusion_evidence": decode(row.get("evidence_json"), []),
        "payload_models": predictions,
        "poc_matches": pocs,
        "behavior_windows": behaviors,
    }


def _target_port(row: Dict[str, Any]) -> Optional[int]:
    host = str(row.get("host") or "")
    if ":" in host:
        try:
            port = int(host.rsplit(":", 1)[1])
            if 1 <= port <= 65535:
                return port
        except Exception:
            pass
    return None


def normalize_review_evidence(
    analysis: Dict[str, Any], *, row: Dict[str, Any], summary: str
) -> List[str]:
    """Keep LLM evidence visible even when a small model omits the optional-looking field."""
    values: List[str] = []
    raw_evidence = analysis.get("evidence")
    if isinstance(raw_evidence, list):
        values.extend(str(item).strip() for item in raw_evidence if str(item).strip())

    if not values:
        fused = row.get("evidence_json")
        try:
            fused = json.loads(fused) if isinstance(fused, str) else fused
        except (TypeError, ValueError, json.JSONDecodeError):
            fused = []
        if isinstance(fused, list):
            values.extend(f"融合证据：{str(item).strip()}" for item in fused if str(item).strip())

    if not values and summary:
        values.append(f"大模型研判说明：{summary}")
    return values[:8]


@contextmanager
def _transaction_cursor(conn: Any):
    conn.begin()
    try:
        with conn.cursor() as cur:
            yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def complete_review(
    conn: Any,
    *,
    row: Dict[str, Any],
    analysis: Dict[str, Any],
    raw_content: str,
    model_name: str,
    rag_enabled: bool,
    rag_hits: int,
    latency_ms: int,
    review_source: str = "realtime_llm",
) -> bool:
    verdict = str(analysis.get("verdict") or "unknown").strip().lower()
    is_attack = verdict == "attack"
    summary = str(analysis.get("summary") or analysis.get("llm_explanation") or "").strip()
    evidence = normalize_review_evidence(analysis, row=row, summary=summary)
    severity = str(analysis.get("severity") or row.get("risk_level") or "unknown")
    confidence = float(analysis.get("confidence") or 0.0)
    attack_type = str(analysis.get("attack_method") or row.get("attack_type") or "可疑流量")
    analyzed_at = str(analysis.get("analyzed_at") or datetime.now().isoformat(timespec="seconds"))
    immediate_actions = analysis.get("immediate_actions") if isinstance(analysis.get("immediate_actions"), list) else []
    hardening_actions = analysis.get("hardening_actions") if isinstance(analysis.get("hardening_actions"), list) else []
    handling_suggestion = "\n".join(
        [f"立即处置：{item}" for item in immediate_actions]
        + [f"长期加固：{item}" for item in hardening_actions]
    ) or summary

    # Persist the post-validation structure used by the UI, not unchecked model text.
    validated_raw_content = json.dumps(analysis, ensure_ascii=False)
    with _transaction_cursor(conn) as cur:
        cur.execute(
            """
            INSERT INTO analyses(
              case_id,file_id,seq_id,llm_status,analyzed_at,model_name,verdict,
              source_ip,destination_ip,attack_interface,attack_method,attack_path,
              attack_time,severity,confidence,summary,evidence_json,analysis_raw,
              attack_event_time,attack_ip,target_interface,attack_type,attack_confidence,
              rag_enabled,rag_hits,review_latency_ms,handling_suggestion,
              review_source,request_fingerprint
            ) VALUES(
              %s,%s,%s,'done',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
            )
            ON DUPLICATE KEY UPDATE
              llm_status='done',llm_error=NULL,llm_failed_at=NULL,analyzed_at=VALUES(analyzed_at),
              model_name=VALUES(model_name),verdict=VALUES(verdict),source_ip=VALUES(source_ip),
              destination_ip=VALUES(destination_ip),attack_interface=VALUES(attack_interface),
              attack_method=VALUES(attack_method),attack_path=VALUES(attack_path),
              attack_time=VALUES(attack_time),severity=VALUES(severity),confidence=VALUES(confidence),
              summary=VALUES(summary),evidence_json=VALUES(evidence_json),analysis_raw=VALUES(analysis_raw),
              attack_event_time=VALUES(attack_event_time),attack_ip=VALUES(attack_ip),
              target_interface=VALUES(target_interface),attack_type=VALUES(attack_type),
              attack_confidence=VALUES(attack_confidence),rag_enabled=VALUES(rag_enabled),
              rag_hits=VALUES(rag_hits),review_latency_ms=VALUES(review_latency_ms),
              handling_suggestion=VALUES(handling_suggestion),review_source=VALUES(review_source),
              request_fingerprint=VALUES(request_fingerprint)
            """,
            (
                row["case_id"], row.get("file_id"), row.get("seq_id"), analyzed_at, model_name,
                verdict, row.get("source_ip"), row.get("destination_ip"), row.get("uri"),
                attack_type, f"{row.get('method') or ''} {row.get('uri') or ''}".strip(),
                row.get("event_time"), severity, confidence, summary,
                json.dumps(evidence, ensure_ascii=False), validated_raw_content, row.get("event_time"),
                row.get("source_ip"), row.get("uri"), attack_type, confidence,
                1 if rag_enabled else 0, int(rag_hits), int(latency_ms), handling_suggestion,
                review_source, request_fingerprint(row),
            ),
        )
        if is_attack and review_source == "realtime_llm" and _target_port(row) == 4000:
            cur.execute(
                """INSERT INTO llm_review_cache(
                     fingerprint,target_port,method,uri,template_json,model_name,enabled
                   ) VALUES(%s,4000,%s,%s,%s,%s,1)
                   ON DUPLICATE KEY UPDATE template_json=VALUES(template_json),
                     model_name=VALUES(model_name),enabled=1""",
                (
                    request_fingerprint(row), str(row.get("method") or "")[:16],
                    str(row.get("uri") or ""), validated_raw_content, model_name,
                ),
            )
        cur.execute(
            """
            UPDATE llm_review_jobs
            SET status='done', completed_at=NOW(), model_name=%s, error_message=NULL
            WHERE event_id=%s
            """,
            (model_name, row["event_id"]),
        )
        if is_attack:
            cur.execute("UPDATE detection_candidates SET decision='attack_event' WHERE event_id=%s", (row["event_id"],))
            cur.execute(
                """
                INSERT INTO attack_events(event_id,case_id,occurred_at,source_ip,target_interface,
                  attack_type,risk_level,confidence,status,evidence_json)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,'unprocessed',%s)
                ON DUPLICATE KEY UPDATE occurred_at=VALUES(occurred_at),source_ip=VALUES(source_ip),
                  target_interface=VALUES(target_interface),attack_type=VALUES(attack_type),
                  risk_level=VALUES(risk_level),confidence=VALUES(confidence),
                  evidence_json=VALUES(evidence_json)
                """,
                (
                    row["event_id"], row["case_id"], row.get("event_time"), row.get("source_ip"),
                    row.get("uri"), attack_type, severity, confidence,
                    json.dumps(evidence, ensure_ascii=False),
                ),
            )
            cur.execute(
                """
                INSERT INTO demo_attack_events(
                  event_id,occurred_at,risk_level,attack_type,source_ip,source_region,
                  target_node,target_port,target_interface,attack_result,process_status,
                  attack_payload,request_log,protection_action,handling_suggestion,
                  response_ms,anomaly_detected
                ) VALUES(%s,%s,%s,%s,%s,'未知地区','本机服务器',%s,%s,'detected','unprocessed',
                  %s,%s,'Payload/POC/行为窗口筛选 + 大模型最终研判',%s,%s,1)
                ON DUPLICATE KEY UPDATE occurred_at=VALUES(occurred_at),risk_level=VALUES(risk_level),
                  attack_type=VALUES(attack_type),source_ip=VALUES(source_ip),target_port=VALUES(target_port),
                  target_interface=VALUES(target_interface),attack_payload=VALUES(attack_payload),
                  request_log=VALUES(request_log),protection_action=VALUES(protection_action),
                  handling_suggestion=VALUES(handling_suggestion),response_ms=VALUES(response_ms),
                  anomaly_detected=1
                """,
                (
                    row["event_id"][:40], row.get("event_time"), severity, attack_type,
                    row.get("source_ip") or "unknown", _target_port(row), row.get("uri") or "",
                    row.get("request_text") or "", row.get("request_text") or "", handling_suggestion,
                    int(latency_ms),
                ),
            )
        else:
            next_decision = "raw_only" if verdict == "benign" else "candidate"
            cur.execute("UPDATE detection_candidates SET decision=%s WHERE event_id=%s", (next_decision, row["event_id"]))
            cur.execute("DELETE FROM attack_events WHERE event_id=%s", (row["event_id"],))
            cur.execute("DELETE FROM demo_attack_events WHERE event_id=%s", (row["event_id"][:40],))
    return is_attack


def fail_review(conn: Any, *, event_id: str, case_id: str, error: str, max_attempts: int = 3) -> None:
    message = str(error or "unknown_error")[:4000]
    with conn.cursor() as cur:
        cur.execute("SELECT attempts FROM llm_review_jobs WHERE event_id=%s LIMIT 1", (event_id,))
        attempts = int((cur.fetchone() or {}).get("attempts") or 1)
        retry_minutes = min(10, max(1, 2 ** max(0, attempts - 1)))
        cur.execute(
            """
            UPDATE llm_review_jobs
            SET status='failed', completed_at=NOW(), error_message=%s,
                next_retry_at=CASE WHEN attempts < %s THEN DATE_ADD(NOW(), INTERVAL %s MINUTE) ELSE NULL END
            WHERE event_id=%s
            """,
            (message, max(1, int(max_attempts)), retry_minutes, event_id),
        )
        cur.execute(
            """
            INSERT INTO analyses(case_id,llm_status,llm_error,llm_failed_at)
            VALUES(%s,'failed',%s,%s)
            ON DUPLICATE KEY UPDATE llm_status='failed',llm_error=VALUES(llm_error),
              llm_failed_at=VALUES(llm_failed_at)
            """,
            (case_id, message, datetime.now().isoformat(timespec="seconds")),
        )
