from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

try:
    import pymysql
except Exception:  # pragma: no cover
    pymysql = None

from build_result_db import MySQLConfig
from extract_old_model_features_from_txt import build_request_text, parse_records, read_text_file
from security_detection_v2 import DetectionEngineV2
from sync_detection_v2_db import ensure_mysql, mysql_connect, upsert_mysql

BEHAVIOR_AGG_BUCKET_MINUTES = 10
AGGREGATED_BEHAVIOR_KEYWORDS = (
    "扫描",
    "探测",
    "目录",
    "高频",
    "暴力破解",
    "爆破",
    "Payload异常突增",
)


DEMO_ATTACK_EVENTS_DDL = """
CREATE TABLE IF NOT EXISTS demo_attack_events (
  event_id VARCHAR(40) PRIMARY KEY,
  occurred_at DATETIME(3) NOT NULL,
  risk_level VARCHAR(16) NOT NULL,
  attack_type VARCHAR(64) NOT NULL,
  source_ip VARCHAR(64) NOT NULL,
  source_region VARCHAR(64) NOT NULL,
  target_node VARCHAR(64) NOT NULL,
  target_interface VARCHAR(255) NOT NULL,
  attack_result VARCHAR(16) NOT NULL,
  process_status VARCHAR(16) NOT NULL,
  acked TINYINT(1) NOT NULL DEFAULT 0,
  attack_payload LONGTEXT,
  request_log LONGTEXT,
  protection_action TEXT,
  handling_suggestion TEXT,
  note TEXT,
  response_ms INT NOT NULL DEFAULT 0,
  anomaly_detected TINYINT(1) NOT NULL DEFAULT 0,
  machine_id INT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  KEY idx_event_time (occurred_at),
  KEY idx_event_risk (risk_level),
  KEY idx_event_type (attack_type),
  KEY idx_event_node (target_node)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
"""


def iter_input_files(input_dir: Path) -> Iterable[Path]:
    def key(path: Path) -> int:
        try:
            return int(path.stem.split(".")[-1])
        except Exception:
            return 10**9

    for path in sorted(input_dir.glob("1.1.*.txt"), key=key):
        if path.is_file():
            yield path


def epoch_to_iso(value: Any) -> str:
    try:
        ts = float(value)
    except Exception:
        return ""
    try:
        return datetime.fromtimestamp(ts).isoformat(timespec="seconds")
    except Exception:
        return ""


def to_int(value: Any) -> Optional[int]:
    try:
        if value is None or value == "":
            return None
        return int(float(value))
    except Exception:
        return None


def clean_layered_case_rows(conn: Any, case_id: str) -> None:
    with conn.cursor() as cur:
        cur.execute("DELETE FROM model_predictions WHERE case_id=%s", (case_id,))
        cur.execute("DELETE FROM poc_matches WHERE case_id=%s", (case_id,))
        cur.execute("DELETE FROM behavior_windows WHERE case_id=%s", (case_id,))


def ensure_demo_attack_events(conn: Any) -> None:
    with conn.cursor() as cur:
        cur.execute(DEMO_ATTACK_EVENTS_DDL)


def mysql_datetime(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return text.replace("T", " ").replace("Z", "")[:23]


def parse_dt(value: Any) -> datetime:
    text = str(value or "").strip()
    if not text:
        return datetime.now()
    text = text.replace("Z", "").replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text[:26], fmt)
        except Exception:
            continue
    try:
        return datetime.fromisoformat(text)
    except Exception:
        return datetime.now()


def bucket_start(value: Any, minutes: int = BEHAVIOR_AGG_BUCKET_MINUTES) -> datetime:
    dt = parse_dt(value)
    minute = (dt.minute // minutes) * minutes
    return dt.replace(minute=minute, second=0, microsecond=0)


def should_aggregate_behavior(attack_type: str, detection: Dict[str, Any]) -> bool:
    behavior = detection.get("behavior") or {}
    behavior_type = str(behavior.get("type") or "")
    text = f"{attack_type} {behavior_type}"
    score = float(behavior.get("score") or 0.0)
    if score < 0.72:
        return False
    return any(x in text for x in AGGREGATED_BEHAVIOR_KEYWORDS)


def aggregate_event_id(record: Dict[str, Any], attack_type: str) -> str:
    source_ip = str(record.get("source_ip") or "unknown")
    start = bucket_start(record.get("event_time"))
    key = f"{source_ip}|{attack_type}|{start.isoformat()}|{BEHAVIOR_AGG_BUCKET_MINUTES}"
    digest = hashlib.sha1(key.encode("utf-8", errors="ignore")).hexdigest()[:22].upper()
    return f"AGG{digest}"


def aggregate_evidence(record: Dict[str, Any], detection: Dict[str, Any], evidence: Iterable[str]) -> list[str]:
    behavior = detection.get("behavior") or {}
    features = behavior.get("features") or {}
    start = bucket_start(record.get("event_time"))
    end = start + timedelta(minutes=BEHAVIOR_AGG_BUCKET_MINUTES)
    lines = [
        f"聚合窗口：{start.strftime('%Y-%m-%d %H:%M:%S')} ~ {end.strftime('%H:%M:%S')}",
        f"来源IP：{record.get('source_ip') or 'unknown'}",
        f"窗口请求数：{features.get('request_count', 0)}",
        f"不同路径数：{features.get('distinct_path_count', 0)}",
        f"404次数：{features.get('not_found_count', 0)}",
        f"登录失败次数：{features.get('login_fail_count', 0)}",
    ]
    lines.extend(str(x) for x in evidence)
    deduped: list[str] = []
    seen = set()
    for line in lines:
        if line in seen:
            continue
        seen.add(line)
        deduped.append(line)
    return deduped[:20]


def delete_demo_event(conn: Any, event_id: str) -> None:
    with conn.cursor() as cur:
        cur.execute("DELETE FROM demo_attack_events WHERE event_id=%s", (event_id[:40],))


def upsert_demo_event(
    conn: Any,
    event_id: str,
    record: Dict[str, Any],
    attack_type: str,
    risk_level: str,
    evidence: Iterable[str],
) -> None:
    request_log = record.get("request_text") or record.get("raw_request_block") or ""
    payload = record.get("request_body") or request_log
    suggestion = "V2\u878d\u5408\u68c0\u6d4b\u547d\u4e2d\uff0c\u8bf7\u7ed3\u5408\u8bf7\u6c42\u8f7d\u8377\u3001POC\u8bc1\u636e\u548c\u884c\u4e3a\u7a97\u53e3\u590d\u6838\u5904\u7f6e\u3002"
    source_region = "\u672a\u77e5\u5730\u533a"
    target_node = record.get("host") or "\u672c\u673a\u8282\u70b9"
    target_interface = record.get("target_interface_override") or record.get("uri") or ""
    protection_action = "V2\u878d\u5408\u68c0\u6d4b\uff1aPayload\u6a21\u578b + POC\u89c4\u5219 + \u884c\u4e3a\u7a97\u53e3"
    evidence_text = "\uff1b".join(str(x) for x in evidence)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO demo_attack_events(
              event_id, occurred_at, risk_level, attack_type, source_ip, source_region,
              target_node, target_interface, attack_result, process_status,
              attack_payload, request_log, protection_action, handling_suggestion,
              response_ms, anomaly_detected
            )
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
              occurred_at=VALUES(occurred_at),
              risk_level=VALUES(risk_level),
              attack_type=VALUES(attack_type),
              source_ip=VALUES(source_ip),
              source_region=VALUES(source_region),
              target_node=VALUES(target_node),
              target_interface=VALUES(target_interface),
              attack_result=VALUES(attack_result),
              attack_payload=VALUES(attack_payload),
              request_log=VALUES(request_log),
              protection_action=VALUES(protection_action),
              handling_suggestion=VALUES(handling_suggestion),
              response_ms=VALUES(response_ms),
              anomaly_detected=VALUES(anomaly_detected)
            """,
            (
                event_id[:40],
                mysql_datetime(record.get("event_time")),
                risk_level,
                attack_type,
                record.get("source_ip") or "unknown",
                source_region,
                target_node,
                target_interface,
                "\u5df2\u62e6\u622a",
                "unprocessed",
                payload,
                request_log,
                protection_action,
                suggestion + "\n\u8bc1\u636e\uff1a" + evidence_text,
                0,
                1,
            ),
        )


def sync_detection_rows_mysql(
    conn: Any,
    case_id: str,
    event_id: str,
    record: Dict[str, Any],
    detection: Dict[str, Any],
) -> Dict[str, int]:
    fusion = detection.get("fusion") or {}
    payload = detection.get("payload") or {}
    behavior = detection.get("behavior") or {}
    poc_matches = fusion.get("poc_matches") or detection.get("poc_matches") or []
    decision = str(fusion.get("decision") or "raw_only")
    if decision == "raw_only":
        clean_layered_case_rows(conn, case_id)
        with conn.cursor() as cur:
            cur.execute("DELETE FROM detection_candidates WHERE event_id=%s", (event_id,))
            cur.execute("DELETE FROM attack_events WHERE event_id=%s", (event_id,))
        delete_demo_event(conn, event_id)
        return {"candidate": 0, "attack": 0, "model": 0, "poc": 0, "behavior": 0}

    final_score = fusion.get("final_score")
    risk_level = fusion.get("risk_level") or "medium"
    attack_type = fusion.get("attack_type") or payload.get("label") or "可疑流量"
    evidence = fusion.get("evidence") or []
    raw_event_id = event_id
    is_aggregated = decision == "attack_event" and should_aggregate_behavior(str(attack_type), detection)
    if is_aggregated:
        event_id = aggregate_event_id(record, str(attack_type))
        evidence = aggregate_evidence(record, detection, evidence)
        record = dict(record)
        record["event_time"] = bucket_start(record.get("event_time")).isoformat(timespec="seconds")
        record["target_interface_override"] = "聚合行为窗口"
        with conn.cursor() as cur:
            cur.execute("DELETE FROM detection_candidates WHERE event_id=%s", (raw_event_id,))
            cur.execute("DELETE FROM attack_events WHERE event_id=%s", (raw_event_id,))
        delete_demo_event(conn, raw_event_id)

    upsert_mysql(
        conn,
        "detection_candidates",
        {
            "event_id": event_id,
            "case_id": case_id,
            "file_id": record.get("file_id"),
            "seq_id": record.get("seq_id"),
            "decision": decision,
            "final_score": final_score,
            "risk_level": risk_level,
            "attack_type": attack_type,
            "source_ip": record.get("source_ip"),
            "target_interface": record.get("target_interface_override") or record.get("uri"),
            "evidence_json": json.dumps(evidence, ensure_ascii=False),
        },
    )

    clean_layered_case_rows(conn, case_id)
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO model_predictions(case_id,model_name,label,score,proba_json)
               VALUES(%s,%s,%s,%s,%s)""",
            (
                case_id,
                "payload_model_v2",
                payload.get("label"),
                payload.get("score"),
                json.dumps(payload.get("proba") or {}, ensure_ascii=False),
            ),
        )

    poc_count = 0
    for match in poc_matches:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO poc_matches(case_id,rule_id,rule_name,attack_type,severity,score,evidence_json)
                   VALUES(%s,%s,%s,%s,%s,%s,%s)""",
                (
                    case_id,
                    match.get("rule_id"),
                    match.get("name"),
                    match.get("attack_type"),
                    match.get("severity"),
                    match.get("score"),
                    json.dumps(match.get("evidence") or [], ensure_ascii=False),
                ),
            )
        poc_count += 1

    behavior_count = 0
    if behavior.get("score") is not None:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO behavior_windows(case_id,source_ip,behavior_type,score,features_json,evidence_json)
                   VALUES(%s,%s,%s,%s,%s,%s)""",
                (
                    case_id,
                    record.get("source_ip"),
                    behavior.get("type"),
                    behavior.get("score"),
                    json.dumps(behavior.get("features") or {}, ensure_ascii=False),
                    json.dumps(behavior.get("evidence") or [], ensure_ascii=False),
                ),
            )
        behavior_count = 1

    attack_count = 0
    if decision == "attack_event":
        upsert_mysql(
            conn,
            "attack_events",
            {
                "event_id": event_id,
                "case_id": case_id,
                "occurred_at": record.get("event_time"),
                "source_ip": record.get("source_ip"),
                "target_interface": record.get("target_interface_override") or record.get("uri"),
                "attack_type": attack_type,
                "risk_level": risk_level,
                "confidence": final_score,
                "status": "unprocessed",
                "evidence_json": json.dumps(evidence, ensure_ascii=False),
            },
        )
        upsert_demo_event(conn, event_id, record, attack_type, risk_level, evidence)
        attack_count = 1
    else:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM attack_events WHERE event_id=%s", (event_id,))
        delete_demo_event(conn, event_id)

    return {"candidate": 1, "attack": attack_count, "model": 1, "poc": poc_count, "behavior": behavior_count}


def sync_input_file_mysql(conn: Any, input_file: Path, engine: DetectionEngineV2) -> Dict[str, int]:
    text = read_text_file(input_file)
    file_id = input_file.stem
    requests, responses, mode = parse_records(text, file_id)
    response_by_req = {r.get("request_frame"): r for r in responses.values() if r.get("request_frame") is not None}
    totals = {"files": 1, "raw": 0, "candidate": 0, "attack": 0, "model": 0, "poc": 0, "behavior": 0}

    for seq_id, frame_req in enumerate(sorted(requests.keys()), start=1):
        req = requests[frame_req]
        resp = response_by_req.get(frame_req)
        request_text = req.get("_request_text") or build_request_text(req, resp)
        response_text = resp.get("_response_text", "") if resp else ""
        case_id = f"raw:{file_id}:{seq_id}"
        event_id = f"RAW{file_id.replace('.', '_')}_{seq_id}"
        event_time = epoch_to_iso(req.get("time"))
        record = {
            "case_id": case_id,
            "file_id": file_id,
            "seq_id": seq_id,
            "event_time": event_time,
            "time": event_time,
            "source_ip": req.get("src_ip"),
            "destination_ip": req.get("dst_ip"),
            "source_port": req.get("src_port"),
            "destination_port": req.get("dst_port"),
            "method": req.get("method"),
            "uri": req.get("uri"),
            "host": req.get("host"),
            "status_code": to_int(resp.get("status_code") if resp else None),
            "request_text": request_text,
            "response_text": response_text,
            "raw_request_block": req.get("raw_block"),
            "raw_response_block": resp.get("raw_block") if resp else "",
        }
        upsert_mysql(
            conn,
            "raw_http_logs",
            {
                "case_id": case_id,
                "file_id": file_id,
                "seq_id": seq_id,
                "event_time": event_time,
                "source_ip": record.get("source_ip"),
                "destination_ip": record.get("destination_ip"),
                "method": record.get("method"),
                "uri": record.get("uri"),
                "host": record.get("host"),
                "status_code": record.get("status_code"),
                "request_text": request_text,
                "response_text": response_text,
            },
        )
        totals["raw"] += 1
        detection = engine.detect(record)
        row_stats = sync_detection_rows_mysql(conn, case_id, event_id, record, detection)
        for key in ("candidate", "attack", "model", "poc", "behavior"):
            totals[key] += int(row_stats.get(key, 0))

    totals["mode"] = mode  # type: ignore[assignment]
    return totals


def sync_input_dir_mysql(conn: Any, input_dir: Path) -> Dict[str, int]:
    ensure_mysql(conn)
    ensure_demo_attack_events(conn)
    engine = DetectionEngineV2()
    totals = {"files": 0, "raw": 0, "candidate": 0, "attack": 0, "model": 0, "poc": 0, "behavior": 0, "errors": 0}
    for input_file in iter_input_files(input_dir):
        try:
            stats = sync_input_file_mysql(conn, input_file, engine)
            for key in ("files", "raw", "candidate", "attack", "model", "poc", "behavior"):
                totals[key] += int(stats.get(key, 0))
        except Exception as exc:  # noqa: BLE001
            totals["errors"] += 1
            print(f"[warn] raw sync failed file={input_file}: {exc}", file=sys.stderr)
    return totals


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync input/1.1.n.txt into raw_http_logs")
    parser.add_argument("--input-dir", default="input")
    parser.add_argument("--mysql-host", default="127.0.0.1")
    parser.add_argument("--mysql-port", type=int, default=3306)
    parser.add_argument("--mysql-user", default="root")
    parser.add_argument("--mysql-password", default="123456")
    parser.add_argument("--mysql-database", default="traffic_pipeline")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    input_dir = (project_root / args.input_dir).resolve()
    cfg = MySQLConfig(args.mysql_host, args.mysql_port, args.mysql_user, args.mysql_password, args.mysql_database)
    conn = mysql_connect(cfg)
    try:
        totals = sync_input_dir_mysql(conn, input_dir)
    finally:
        conn.close()
    print(json.dumps(totals, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
