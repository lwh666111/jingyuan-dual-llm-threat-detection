import argparse
import csv
import json
import io
import random
import re
import secrets
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, Response, g, jsonify, request
import pymysql
from pymysql.cursors import DictCursor


ROLE_NORMAL = "normal"
ROLE_PRO = "pro"
ROLE_ADMIN = "admin"

PROCESS_STATUS_SET = {"unprocessed", "processing", "done", "ignored"}
RISK_LEVEL_SET = {"high", "medium", "low"}
RAG_SEVERITY_SET = {"low", "medium", "high", "critical"}

TOKEN_TTL_SECONDS = 12 * 3600
SESSIONS: Dict[str, Dict[str, Any]] = {}

DEMO_ACCOUNTS = [
    {"username": "admin", "password": "admin", "role": ROLE_NORMAL, "display_name": "普通用户"},
    {"username": "admin", "password": "admin", "role": ROLE_PRO, "display_name": "专业用户"},
    {"username": "admin", "password": "admin", "role": ROLE_ADMIN, "display_name": "管理员"},
]

DEMO_SEED_USERS = [
    {"username": "demo_normal", "password": "admin", "role": ROLE_NORMAL, "display_name": "普通用户"},
    {"username": "demo_pro", "password": "admin", "role": ROLE_PRO, "display_name": "专业用户"},
    {"username": "demo_admin", "password": "admin", "role": ROLE_ADMIN, "display_name": "管理员"},
]


def find_demo_account(username: str, password: str, role_hint: str = "") -> Optional[Dict[str, Any]]:
    candidates = [x for x in DEMO_ACCOUNTS if x["username"] == username and x["password"] == password]
    if not candidates:
        return None
    if role_hint:
        for row in candidates:
            if row["role"] == role_hint:
                return row
    if len(candidates) == 1:
        return candidates[0]
    for row in candidates:
        if row["role"] == ROLE_ADMIN:
            return row
    return candidates[0]


ATTACK_TYPES = [
    "SQL娉ㄥ叆",
    "XSS",
    "鏆村姏鐮磋В",
    "DDoS",
    "绔彛鎵弿",
    "鍛戒护娉ㄥ叆",
    "璺緞閬嶅巻",
    "鏂囦欢涓婁紶",
    "SSRF",
    "RCE",
]

SOURCE_REGIONS = [
    "鍖椾含",
    "涓婃捣",
    "骞夸笢",
    "娴欐睙",
    "姹熻嫃",
    "灞变笢",
    "娌冲崡",
    "鍥涘窛",
    "棣欐腐",
    "缇庡浗",
    "寰峰浗",
    "新加坡",
]

TARGET_INTERFACES = [
    "/api/auth/login",
    "/api/v1/user/profile",
    "/api/v1/order/create",
    "/admin/config/update",
    "/gateway/payment/callback",
    "/search/query",
    "/upload/file",
    "/api/v2/token/refresh",
]


def now_dt() -> datetime:
    return datetime.now()


def dt_to_str(dt: Optional[datetime], ms: bool = True) -> Optional[str]:
    if dt is None:
        return None
    if ms:
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def normalize_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return dt_to_str(value)
    return value


def normalize_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {k: normalize_value(v) for k, v in row.items()}


def normalize_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [normalize_row(r) for r in rows]


def get_rag_conn(rag_db_path: str):
    conn = sqlite3.connect(rag_db_path)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_rag_schema(rag_db_path: str) -> None:
    with closing(get_rag_conn(rag_db_path)) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS rag_docs USING fts5(
              doc_id UNINDEXED,
              title,
              tags,
              attack_type,
              content,
              evidence,
              mitigation,
              severity UNINDEXED,
              source UNINDEXED,
              tokenize='unicode61'
            )
            """
        )
        conn.commit()


def read_rag_seed(seed_path: str) -> List[Dict[str, Any]]:
    p = Path(seed_path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    rows: List[Dict[str, Any]] = []
    for idx, row in enumerate(data, start=1):
        if not isinstance(row, dict):
            continue
        rows.append(
            {
                "doc_id": str(row.get("doc_id") or f"RAG-{idx:04d}"),
                "title": str(row.get("title") or ""),
                "tags": str(row.get("tags") or ""),
                "attack_type": str(row.get("attack_type") or ""),
                "content": str(row.get("content") or ""),
                "evidence": str(row.get("evidence") or ""),
                "mitigation": str(row.get("mitigation") or ""),
                "severity": str(row.get("severity") or "medium").lower(),
                "source": str(row.get("source") or "local_seed"),
            }
        )
    return rows


def rag_upsert_doc(rag_db_path: str, row: Dict[str, Any]) -> None:
    with closing(get_rag_conn(rag_db_path)) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM rag_docs WHERE doc_id=?", (row["doc_id"],))
        cur.execute(
            """
            INSERT INTO rag_docs(doc_id, title, tags, attack_type, content, evidence, mitigation, severity, source)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["doc_id"],
                row["title"],
                row["tags"],
                row["attack_type"],
                row["content"],
                row["evidence"],
                row["mitigation"],
                row["severity"],
                row["source"],
            ),
        )
        conn.commit()


def rag_rebuild_from_seed(rag_db_path: str, seed_path: str) -> int:
    rows = read_rag_seed(seed_path)
    with closing(get_rag_conn(rag_db_path)) as conn:
        cur = conn.cursor()
        cur.execute("DROP TABLE IF EXISTS rag_docs")
        conn.commit()
    ensure_rag_schema(rag_db_path)
    for row in rows:
        rag_upsert_doc(rag_db_path, row)
    return len(rows)


def rag_build_match_query(text: str, max_terms: int = 12) -> str:
    terms = re.findall(r"[a-zA-Z0-9_./:-]{2,}", (text or "").lower())
    uniq: List[str] = []
    seen = set()
    for t in terms:
        if t in seen:
            continue
        seen.add(t)
        uniq.append(t)
        if len(uniq) >= max_terms:
            break
    if not uniq:
        return ""
    escaped = [f"\"{x.replace('\"', '')}\"" for x in uniq if x.strip()]
    return " OR ".join(escaped)


def rag_list_docs(rag_db_path: str, q: str, attack_type: str, page: int, page_size: int) -> Dict[str, Any]:
    where_sql = ""
    params: List[Any] = []
    q = q.strip()
    attack_type = attack_type.strip()

    with closing(get_rag_conn(rag_db_path)) as conn:
        cur = conn.cursor()
        if q:
            match_q = rag_build_match_query(q, max_terms=14)
            if match_q:
                where_sql = "WHERE rag_docs MATCH ?"
                params.append(match_q)
            else:
                where_sql = "WHERE title LIKE ? OR tags LIKE ? OR content LIKE ?"
                like = f"%{q}%"
                params.extend([like, like, like])
        if attack_type:
            if where_sql:
                where_sql += " AND attack_type=?"
            else:
                where_sql = "WHERE attack_type=?"
            params.append(attack_type)

        cur.execute(f"SELECT COUNT(*) AS c FROM rag_docs {where_sql}", tuple(params))
        total = int((cur.fetchone() or {"c": 0})["c"])

        offset = (page - 1) * page_size
        cur.execute(
            f"""
            SELECT rowid, doc_id, title, tags, attack_type, content, evidence, mitigation, severity, source
            FROM rag_docs
            {where_sql}
            ORDER BY rowid DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params + [page_size, offset]),
        )
        items = [dict(x) for x in cur.fetchall()]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


def rag_delete_doc(rag_db_path: str, doc_id: str) -> int:
    with closing(get_rag_conn(rag_db_path)) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM rag_docs WHERE doc_id=?", (doc_id,))
        changed = int(cur.rowcount)
        conn.commit()
    return changed


def get_conn(mysql_conf: Dict[str, Any], autocommit: bool = False):
    return pymysql.connect(
        host=mysql_conf["host"],
        port=mysql_conf["port"],
        user=mysql_conf["user"],
        password=mysql_conf["password"],
        database=mysql_conf["database"],
        charset="utf8mb4",
        cursorclass=DictCursor,
        autocommit=autocommit,
    )


def ensure_schema(conn: Any) -> None:
    ddl_list = [
        """
        CREATE TABLE IF NOT EXISTS demo_users (
          id INT AUTO_INCREMENT PRIMARY KEY,
          username VARCHAR(64) NOT NULL UNIQUE,
          password VARCHAR(128) NOT NULL,
          role VARCHAR(16) NOT NULL,
          display_name VARCHAR(64) NOT NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """,
        """
        CREATE TABLE IF NOT EXISTS demo_machines (
          id INT AUTO_INCREMENT PRIMARY KEY,
          machine_name VARCHAR(64) NOT NULL UNIQUE,
          ip_address VARCHAR(64) NOT NULL,
          deploy_location VARCHAR(128) NOT NULL,
          online_status VARCHAR(16) NOT NULL DEFAULT 'online',
          today_attack_count INT NOT NULL DEFAULT 0,
          current_alert_count INT NOT NULL DEFAULT 0,
          last_heartbeat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          cpu_usage DOUBLE NOT NULL DEFAULT 0,
          memory_usage DOUBLE NOT NULL DEFAULT 0,
          gpu_usage DOUBLE NOT NULL DEFAULT 0,
          model_status VARCHAR(32) NOT NULL DEFAULT 'running',
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """,
        """
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
        """,
        """
        CREATE TABLE IF NOT EXISTS demo_model_metrics (
          id INT AUTO_INCREMENT PRIMARY KEY,
          metric_time DATETIME NOT NULL,
          node_name VARCHAR(64) NOT NULL,
          drift_score DOUBLE NOT NULL,
          accuracy DOUBLE NOT NULL,
          recall_rate DOUBLE NOT NULL,
          inference_ms DOUBLE NOT NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          KEY idx_metric_time (metric_time)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """,
        """
        CREATE TABLE IF NOT EXISTS demo_user_action_logs (
          id BIGINT AUTO_INCREMENT PRIMARY KEY,
          username VARCHAR(64) NOT NULL,
          role VARCHAR(16) NOT NULL,
          action VARCHAR(64) NOT NULL,
          target VARCHAR(128) NOT NULL,
          detail TEXT NOT NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          KEY idx_log_time (created_at),
          KEY idx_log_user (username)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """,
        """
        CREATE TABLE IF NOT EXISTS demo_system_config (
          config_key VARCHAR(64) PRIMARY KEY,
          config_value VARCHAR(256) NOT NULL,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """,
    ]
    with conn.cursor() as cur:
        for ddl in ddl_list:
            cur.execute(ddl)


def log_action(conn: Any, username: str, role: str, action: str, target: str, detail: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO demo_user_action_logs(username, role, action, target, detail)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (username, role, action, target, detail),
        )


def seed_demo_data(conn: Any, force_seed: bool = False) -> None:
    with conn.cursor() as cur:
        for row in DEMO_SEED_USERS:
            cur.execute(
                """
                INSERT INTO demo_users(username, password, role, display_name)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                  password=VALUES(password),
                  role=VALUES(role),
                  display_name=VALUES(display_name)
                """,
                (row["username"], row["password"], row["role"], row["display_name"]),
            )

        defaults = {
            "alert_threshold_high": "10",
            "auto_refresh_seconds": "5",
            "sound_alert_enabled": "1",
        }
        for k, v in defaults.items():
            cur.execute(
                """
                INSERT INTO demo_system_config(config_key, config_value)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)
                """,
                (k, v),
            )

        machines = [
            ("node-bj-01", "10.30.1.11", "鍖椾含鏈烘埧A", "online"),
            ("node-sh-01", "10.30.2.11", "涓婃捣鏈烘埧B", "online"),
            ("node-gz-01", "10.30.3.11", "骞垮窞鏈烘埧C", "online"),
            ("node-hz-01", "10.30.4.11", "鏉窞鏈烘埧D", "online"),
            ("node-cd-01", "10.30.5.11", "鎴愰兘鏈烘埧E", "online"),
            ("node-sg-01", "10.30.6.11", "新加坡机房F", "online"),
            ("node-us-01", "10.30.7.11", "缇庡浗瑗块儴", "offline"),
            ("node-de-01", "10.30.8.11", "寰峰浗娉曞叞鍏嬬", "online"),
        ]
        for machine_name, ip_addr, location, online_status in machines:
            cur.execute(
                """
                INSERT INTO demo_machines(machine_name, ip_address, deploy_location, online_status, cpu_usage, memory_usage, gpu_usage, model_status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'running')
                ON DUPLICATE KEY UPDATE
                  ip_address=VALUES(ip_address),
                  deploy_location=VALUES(deploy_location),
                  online_status=VALUES(online_status)
                """,
                (
                    machine_name,
                    ip_addr,
                    location,
                    online_status,
                    round(random.uniform(10, 70), 2),
                    round(random.uniform(20, 75), 2),
                    round(random.uniform(10, 70), 2),
                ),
            )

        if force_seed:
            cur.execute("DELETE FROM demo_attack_events")
            cur.execute("DELETE FROM demo_model_metrics")

        cur.execute("SELECT COUNT(*) AS c FROM demo_attack_events")
        event_count = int(cur.fetchone()["c"])
        if event_count == 0:
            cur.execute("SELECT id, machine_name FROM demo_machines")
            machine_rows = cur.fetchall()
            rows: List[Tuple[Any, ...]] = []
            begin = now_dt() - timedelta(days=30)
            for idx in range(1500):
                occurred = begin + timedelta(seconds=random.randint(0, 30 * 24 * 3600))
                risk_level = random.choices(["high", "medium", "low"], weights=[0.2, 0.35, 0.45], k=1)[0]
                attack_type = random.choice(ATTACK_TYPES)
                source_region = random.choice(SOURCE_REGIONS)
                source_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                machine = random.choice(machine_rows)
                target_node = machine["machine_name"]
                target_interface = random.choice(TARGET_INTERFACES)
                block_prob = 0.72 if risk_level == "high" else (0.84 if risk_level == "medium" else 0.93)
                attack_result = "blocked" if random.random() < block_prob else "success"
                process_status = random.choices(
                    ["unprocessed", "processing", "done", "ignored"],
                    weights=[0.15, 0.15, 0.55, 0.15],
                    k=1,
                )[0]
                acked = 1 if process_status in {"done", "ignored"} else 0
                response_ms = random.randint(30, 2800)
                anomaly = 1 if (risk_level == "high" and random.random() < 0.85) else (1 if random.random() < 0.18 else 0)
                payload = demo_payload_by_type(attack_type)
                request_log = f"{dt_to_str(occurred)} {source_ip} -> {target_interface} {payload}"
                protection_action = f"Applied strategy for {attack_type}, result={attack_result}"
                suggestion = f"Review rule set and strengthen policy for {attack_type}"
                event_id = f"EVT{occurred.strftime('%Y%m%d')}{idx:06d}"
                rows.append(
                    (
                        event_id,
                        occurred,
                        risk_level,
                        attack_type,
                        source_ip,
                        source_region,
                        target_node,
                        target_interface,
                        attack_result,
                        process_status,
                        acked,
                        payload,
                        request_log,
                        protection_action,
                        suggestion,
                        "",
                        response_ms,
                        anomaly,
                        machine["id"],
                    )
                )
            cur.executemany(
                """
                INSERT INTO demo_attack_events(
                  event_id, occurred_at, risk_level, attack_type, source_ip, source_region, target_node, target_interface,
                  attack_result, process_status, acked, attack_payload, request_log, protection_action, handling_suggestion,
                  note, response_ms, anomaly_detected, machine_id
                ) VALUES(
                  %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                rows,
            )

        cur.execute("SELECT COUNT(*) AS c FROM demo_model_metrics")
        metric_count = int(cur.fetchone()["c"])
        if metric_count == 0:
            metric_rows: List[Tuple[Any, ...]] = []
            for day_idx in range(30):
                metric_time = (now_dt() - timedelta(days=29 - day_idx)).replace(hour=1, minute=0, second=0, microsecond=0)
                metric_rows.append(
                    (
                        metric_time,
                        "global",
                        round(random.uniform(0.02, 0.21), 4),
                        round(random.uniform(0.90, 0.98), 4),
                        round(random.uniform(0.86, 0.97), 4),
                        round(random.uniform(55, 250), 2),
                    )
                )
            cur.executemany(
                """
                INSERT INTO demo_model_metrics(metric_time, node_name, drift_score, accuracy, recall_rate, inference_ms)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                metric_rows,
            )
    refresh_machine_stats(conn)


def demo_payload_by_type(attack_type: str) -> str:
    mapping = {
        "SQL娉ㄥ叆": "username=admin' OR 1=1 --",
        "XSS": "<script>alert('xss')</script>",
        "鏆村姏鐮磋В": "POST /login retry=120 user=admin",
        "DDoS": "High frequency requests burst detected",
        "绔彛鎵弿": "SYN scan to 22,80,443,3306",
        "鍛戒护娉ㄥ叆": "cmd=ping 127.0.0.1 && whoami",
        "璺緞閬嶅巻": "../../etc/passwd",
        "鏂囦欢涓婁紶": "multipart payload with executable signature",
        "SSRF": "url=http://169.254.169.254/latest/meta-data",
        "RCE": "template={{7*7}} runtime command chain",
    }
    return mapping.get(attack_type, "suspicious payload")


def refresh_machine_stats(conn: Any) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE demo_machines m
            LEFT JOIN (
              SELECT
                target_node,
                SUM(CASE WHEN DATE(occurred_at)=CURDATE() THEN 1 ELSE 0 END) AS today_cnt,
                SUM(CASE WHEN DATE(occurred_at)=CURDATE() AND risk_level='high' AND process_status IN ('unprocessed','processing') THEN 1 ELSE 0 END) AS alert_cnt,
                MAX(occurred_at) AS last_attack_time
              FROM demo_attack_events
              GROUP BY target_node
            ) s ON m.machine_name = s.target_node
            SET
              m.today_attack_count = COALESCE(s.today_cnt, 0),
              m.current_alert_count = COALESCE(s.alert_cnt, 0),
              m.last_heartbeat = CASE
                WHEN m.online_status='online' THEN DATE_SUB(NOW(), INTERVAL FLOOR(RAND()*90) SECOND)
                ELSE DATE_SUB(NOW(), INTERVAL FLOOR(300 + RAND()*1800) SECOND)
              END,
              m.cpu_usage = CASE WHEN m.online_status='online' THEN ROUND(15 + RAND()*70, 2) ELSE 0 END,
              m.memory_usage = CASE WHEN m.online_status='online' THEN ROUND(20 + RAND()*65, 2) ELSE 0 END,
              m.gpu_usage = CASE WHEN m.online_status='online' THEN ROUND(5 + RAND()*80, 2) ELSE 0 END
            """
        )


def create_session(user_row: Dict[str, Any]) -> str:
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = {
        "username": user_row["username"],
        "role": user_row["role"],
        "display_name": user_row["display_name"],
        "expires_at": now_dt() + timedelta(seconds=TOKEN_TTL_SECONDS),
    }
    return token


def get_session(token: str) -> Optional[Dict[str, Any]]:
    session = SESSIONS.get(token)
    if not session:
        return None
    if now_dt() > session["expires_at"]:
        SESSIONS.pop(token, None)
        return None
    return session


def require_roles(*roles: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "").strip()
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "unauthorized", "message": "Missing Bearer token"}), 401
            token = auth_header.split(" ", 1)[1].strip()
            session = get_session(token)
            if not session:
                return jsonify({"error": "unauthorized", "message": "Invalid or expired token"}), 401
            if roles and session["role"] not in set(roles):
                return jsonify({"error": "forbidden", "message": "Role not allowed"}), 403
            g.session = session
            g.token = token
            return func(*args, **kwargs)

        return wrapper

    return decorator


def build_time_range() -> Tuple[datetime, datetime]:
    now = now_dt()
    time_range = request.args.get("time_range", "24h").strip().lower()
    if time_range == "1h":
        return now - timedelta(hours=1), now
    if time_range == "6h":
        return now - timedelta(hours=6), now
    if time_range == "24h":
        return now - timedelta(hours=24), now
    if time_range == "7d":
        return now - timedelta(days=7), now
    if time_range == "30d":
        return now - timedelta(days=30), now
    if time_range == "custom":
        start_text = request.args.get("start_time", "").strip()
        end_text = request.args.get("end_time", "").strip()
        if not start_text or not end_text:
            raise ValueError("custom range requires start_time and end_time")
        start_dt = datetime.fromisoformat(start_text.replace("Z", "+00:00")).replace(tzinfo=None)
        end_dt = datetime.fromisoformat(end_text.replace("Z", "+00:00")).replace(tzinfo=None)
        if start_dt >= end_dt:
            raise ValueError("start_time must be earlier than end_time")
        return start_dt, end_dt
    return now - timedelta(hours=24), now


def create_app(
    mysql_conf: Dict[str, Any],
    seed_demo: bool = True,
    force_seed: bool = False,
    rag_db_path: str = "llm/rag/rag_knowledge.db",
    rag_seed_path: str = "llm/rag/rag_seed.json",
    rag_force_seed: bool = False,
) -> Flask:
    app = Flask(__name__)
    app.config["MYSQL_CONF"] = mysql_conf
    app.config["RAG_DB_PATH"] = str(Path(rag_db_path).resolve())
    app.config["RAG_SEED_PATH"] = str(Path(rag_seed_path).resolve())

    with closing(get_conn(mysql_conf, autocommit=False)) as conn:
        ensure_schema(conn)
        if seed_demo:
            seed_demo_data(conn, force_seed=force_seed)
        conn.commit()

    ensure_rag_schema(app.config["RAG_DB_PATH"])
    if rag_force_seed:
        rag_rebuild_from_seed(app.config["RAG_DB_PATH"], app.config["RAG_SEED_PATH"])
    elif seed_demo:
        with closing(get_rag_conn(app.config["RAG_DB_PATH"])) as rag_conn:
            cur = rag_conn.cursor()
            cur.execute("SELECT COUNT(*) AS c FROM rag_docs")
            count = int((cur.fetchone() or {"c": 0})["c"])
        if count == 0:
            rag_rebuild_from_seed(app.config["RAG_DB_PATH"], app.config["RAG_SEED_PATH"])

    @app.after_request
    def add_cors_headers(resp):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, OPTIONS"
        return resp

    @app.route("/api/v1/screen/ping", methods=["GET"])
    def ping():
        return jsonify({"ok": True})

    @app.route("/api/v2/auth/demo-accounts", methods=["GET"])
    def demo_accounts():
        rows = [{"username": x["username"], "password": x["password"], "role": x["role"]} for x in DEMO_ACCOUNTS]
        return jsonify({"accounts": rows})

    @app.route("/api/v2/auth/login", methods=["POST"])
    def login():
        body = request.get_json(silent=True) or {}
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", "")).strip()
        role_hint = str(body.get("role", "")).strip().lower()
        if role_hint and role_hint not in {ROLE_NORMAL, ROLE_PRO, ROLE_ADMIN}:
            return jsonify({"error": "invalid_role"}), 400
        account = find_demo_account(username, password, role_hint)
        if not account:
            return jsonify({"error": "invalid_credentials"}), 401
        token = create_session(account)
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            log_action(conn, account["username"], account["role"], "login", "auth", "login_success")
        return jsonify(
            {
                "token": token,
                "expires_in": TOKEN_TTL_SECONDS,
                "role": account["role"],
                "display_name": account["display_name"],
            }
        )

    @app.route("/api/v2/auth/logout", methods=["POST"])
    @require_roles(ROLE_NORMAL, ROLE_PRO, ROLE_ADMIN)
    def logout():
        SESSIONS.pop(g.token, None)
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            log_action(conn, g.session["username"], g.session["role"], "logout", "auth", "logout_success")
        return jsonify({"ok": True})

    @app.route("/api/v2/auth/profile", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_PRO, ROLE_ADMIN)
    def profile():
        session = dict(g.session)
        session["expires_at"] = dt_to_str(session["expires_at"])
        return jsonify(session)

    @app.route("/api/v2/common/system-status", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_PRO, ROLE_ADMIN)
    def system_status():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            refresh_machine_stats(conn)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                      MAX(occurred_at) AS latest_event_time,
                      SUM(CASE WHEN risk_level='high' AND occurred_at >= DATE_SUB(NOW(), INTERVAL 10 MINUTE) THEN 1 ELSE 0 END) AS high_10m
                    FROM demo_attack_events
                    """
                )
                base = cur.fetchone() or {}
                cur.execute("SELECT COUNT(*) AS offline_count FROM demo_machines WHERE online_status <> 'online'")
                offline_count = int((cur.fetchone() or {}).get("offline_count", 0))
                cur.execute(
                    "SELECT config_value FROM demo_system_config WHERE config_key='auto_refresh_seconds' LIMIT 1"
                )
                cfg = cur.fetchone() or {}
            conn.commit()

        high_10m = int(base.get("high_10m") or 0)
        if offline_count > 0:
            state = {"level": "error", "color": "red"}
        elif high_10m >= 8:
            state = {"level": "warning", "color": "yellow"}
        else:
            state = {"level": "normal", "color": "green"}
        return jsonify(
            {
                "server_time": dt_to_str(now_dt()),
                "latest_data_time": dt_to_str(base.get("latest_event_time")),
                "state": state,
                "refresh_interval_seconds": int(cfg.get("config_value") or 5),
                "high_risk_last_10m": high_10m,
                "offline_machine_count": offline_count,
            }
        )

    @app.route("/api/v2/common/alerts/ticker", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_PRO, ROLE_ADMIN)
    def alerts_ticker():
        limit = max(1, min(int(request.args.get("limit", "3")), 10))
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT event_id, occurred_at, risk_level, attack_type, source_ip, target_node, target_interface
                    FROM demo_attack_events
                    WHERE risk_level='high'
                    ORDER BY occurred_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                rows = cur.fetchall()
        return jsonify({"items": normalize_rows(rows)})

    @app.route("/api/v2/common/alerts/popup", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_PRO, ROLE_ADMIN)
    def alerts_popup():
        limit = max(1, min(int(request.args.get("limit", "5")), 20))
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT event_id, occurred_at, attack_type, source_ip, target_node, target_interface
                    FROM demo_attack_events
                    WHERE risk_level='high' AND acked=0
                    ORDER BY occurred_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                rows = cur.fetchall()
        return jsonify({"items": normalize_rows(rows)})

    @app.route("/api/v2/common/alerts/<event_id>/ack", methods=["POST"])
    @require_roles(ROLE_NORMAL, ROLE_PRO, ROLE_ADMIN)
    def alert_ack(event_id: str):
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE demo_attack_events
                    SET acked=1,
                        process_status=CASE WHEN process_status='unprocessed' THEN 'processing' ELSE process_status END
                    WHERE event_id=%s
                    """,
                    (event_id,),
                )
                changed = cur.rowcount
                refresh_machine_stats(conn)
                log_action(conn, g.session["username"], g.session["role"], "ack_alert", event_id, "acked")
            conn.commit()
        if changed == 0:
            return jsonify({"error": "event_not_found"}), 404
        return jsonify({"ok": True, "event_id": event_id})

    @app.route("/api/v2/rag/docs", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_PRO, ROLE_ADMIN)
    def rag_docs_list():
        page = max(1, int(request.args.get("page", "1")))
        page_size = max(1, min(int(request.args.get("page_size", "20")), 200))
        q = request.args.get("q", "").strip()
        attack_type = request.args.get("attack_type", "").strip()
        payload = rag_list_docs(
            app.config["RAG_DB_PATH"],
            q=q,
            attack_type=attack_type,
            page=page,
            page_size=page_size,
        )
        return jsonify(payload)

    @app.route("/api/v2/rag/docs", methods=["POST"])
    @require_roles(ROLE_NORMAL, ROLE_PRO, ROLE_ADMIN)
    def rag_docs_add():
        body = request.get_json(silent=True) or {}
        title = str(body.get("title", "")).strip()
        tags = str(body.get("tags", "")).strip()
        attack_type = str(body.get("attack_type", "")).strip()
        content = str(body.get("content", "")).strip()
        evidence = str(body.get("evidence", "")).strip()
        mitigation = str(body.get("mitigation", "")).strip()
        severity = str(body.get("severity", "medium")).strip().lower() or "medium"
        source = str(body.get("source", "")).strip() or f"user:{g.session['username']}"

        if not title or not content:
            return jsonify({"error": "title_and_content_required"}), 400
        if severity not in RAG_SEVERITY_SET:
            return jsonify({"error": "invalid_severity"}), 400

        doc_id = str(body.get("doc_id", "")).strip() or f"USR-{uuid.uuid4().hex[:10].upper()}"
        row = {
            "doc_id": doc_id,
            "title": title,
            "tags": tags,
            "attack_type": attack_type,
            "content": content,
            "evidence": evidence,
            "mitigation": mitigation,
            "severity": severity,
            "source": source,
        }
        rag_upsert_doc(app.config["RAG_DB_PATH"], row)
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            log_action(
                conn,
                g.session["username"],
                g.session["role"],
                "rag_add_doc",
                doc_id,
                f"title={title[:60]}",
            )
        return jsonify({"ok": True, "doc_id": doc_id})

    @app.route("/api/v2/rag/docs/<doc_id>/delete", methods=["POST"])
    @require_roles(ROLE_NORMAL, ROLE_PRO, ROLE_ADMIN)
    def rag_docs_delete(doc_id: str):
        changed = rag_delete_doc(app.config["RAG_DB_PATH"], doc_id=doc_id)
        if changed == 0:
            return jsonify({"error": "doc_not_found"}), 404
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            log_action(conn, g.session["username"], g.session["role"], "rag_delete_doc", doc_id, "deleted")
        return jsonify({"ok": True, "doc_id": doc_id})

    @app.route("/api/v2/rag/rebuild", methods=["POST"])
    @require_roles(ROLE_PRO, ROLE_ADMIN)
    def rag_rebuild_api():
        count = rag_rebuild_from_seed(app.config["RAG_DB_PATH"], app.config["RAG_SEED_PATH"])
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            log_action(conn, g.session["username"], g.session["role"], "rag_rebuild", "seed", f"count={count}")
        return jsonify({"ok": True, "rows": count})

    @app.route("/api/v2/user/dashboard/kpis", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_PRO, ROLE_ADMIN)
    def user_kpis():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            refresh_machine_stats(conn)
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS c FROM demo_attack_events WHERE DATE(occurred_at)=CURDATE()")
                today_total = int((cur.fetchone() or {}).get("c", 0))
                cur.execute("SELECT COUNT(*) AS c FROM demo_attack_events WHERE DATE(occurred_at)=DATE_SUB(CURDATE(), INTERVAL 1 DAY)")
                yesterday_total = int((cur.fetchone() or {}).get("c", 0))
                cur.execute(
                    """
                    SELECT COUNT(*) AS c
                    FROM demo_attack_events
                    WHERE risk_level='high' AND process_status IN ('unprocessed','processing')
                    """
                )
                high_active = int((cur.fetchone() or {}).get("c", 0))
                cur.execute(
                    """
                    SELECT
                      SUM(CASE WHEN attack_result='blocked' THEN 1 ELSE 0 END) AS blocked_cnt,
                      COUNT(*) AS total_cnt
                    FROM demo_attack_events
                    WHERE DATE(occurred_at)=CURDATE()
                    """
                )
                rate_obj = cur.fetchone() or {}
                blocked_cnt = int(rate_obj.get("blocked_cnt") or 0)
                total_cnt = int(rate_obj.get("total_cnt") or 0)
                cur.execute("SELECT AVG(response_ms) AS avg_ms FROM demo_attack_events WHERE DATE(occurred_at)=CURDATE()")
                avg_response_ms = float((cur.fetchone() or {}).get("avg_ms") or 0)
                cur.execute("SELECT COUNT(*) AS c FROM demo_attack_events WHERE DATE(occurred_at)=CURDATE() AND anomaly_detected=1")
                anomaly_cnt = int((cur.fetchone() or {}).get("c", 0))
                cur.execute("SELECT COUNT(*) AS c FROM demo_machines WHERE online_status='online'")
                online_nodes = int((cur.fetchone() or {}).get("c", 0))
            conn.commit()

        yoy = 0.0 if yesterday_total == 0 else ((today_total - yesterday_total) / yesterday_total) * 100.0
        success_rate = 0.0 if total_cnt == 0 else (blocked_cnt / total_cnt) * 100.0
        return jsonify(
            {
                "today_attack_total": today_total,
                "yoy_percent": round(yoy, 2),
                "active_high_alerts": high_active,
                "intercept_success_rate": round(success_rate, 2),
                "avg_attack_response_ms": round(avg_response_ms, 2),
                "today_anomaly_detected": anomaly_cnt,
                "online_protection_nodes": online_nodes,
            }
        )

    @app.route("/api/v2/user/dashboard/trend7d", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_PRO, ROLE_ADMIN)
    def trend7d():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                      DATE(occurred_at) AS d,
                      COUNT(*) AS total,
                      SUM(CASE WHEN attack_result='blocked' THEN 1 ELSE 0 END) AS blocked
                    FROM demo_attack_events
                    WHERE occurred_at >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
                    GROUP BY DATE(occurred_at)
                    ORDER BY d
                    """
                )
                rows = cur.fetchall()
        by_day = {row["d"]: row for row in rows}
        items = []
        max_total = 0
        for i in range(6, -1, -1):
            day = (now_dt() - timedelta(days=i)).date()
            row = by_day.get(day)
            total = int((row or {}).get("total") or 0)
            blocked = int((row or {}).get("blocked") or 0)
            max_total = max(max_total, total)
            items.append({"date": str(day), "total_attack": total, "blocked_attack": blocked, "is_peak": False})
        for row in items:
            if row["total_attack"] == max_total and max_total > 0:
                row["is_peak"] = True
        return jsonify({"items": items})

    @app.route("/api/v2/user/dashboard/top-attack-types", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_PRO, ROLE_ADMIN)
    def top_attack_types():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT attack_type, COUNT(*) AS total
                    FROM demo_attack_events
                    WHERE occurred_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                    GROUP BY attack_type
                    ORDER BY total DESC
                    LIMIT 10
                    """
                )
                rows = cur.fetchall()
        return jsonify({"items": normalize_rows(rows)})

    @app.route("/api/v2/user/dashboard/source-distribution", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_PRO, ROLE_ADMIN)
    def source_distribution():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT source_region, COUNT(*) AS total
                    FROM demo_attack_events
                    WHERE occurred_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                    GROUP BY source_region
                    ORDER BY total DESC
                    """
                )
                rows = cur.fetchall()
        return jsonify({"items": normalize_rows(rows)})

    @app.route("/api/v2/user/dashboard/heatmap", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_PRO, ROLE_ADMIN)
    def heatmap():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                      WEEKDAY(occurred_at) AS weekday_idx,
                      HOUR(occurred_at) AS hour_idx,
                      COUNT(*) AS total
                    FROM demo_attack_events
                    WHERE occurred_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                    GROUP BY WEEKDAY(occurred_at), HOUR(occurred_at)
                    ORDER BY weekday_idx, hour_idx
                    """
                )
                rows = cur.fetchall()
        return jsonify({"items": normalize_rows(rows)})

    @app.route("/api/v2/user/dashboard/method-share", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_PRO, ROLE_ADMIN)
    def method_share():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT attack_type, COUNT(*) AS total
                    FROM demo_attack_events
                    WHERE occurred_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                    GROUP BY attack_type
                    ORDER BY total DESC
                    """
                )
                rows = cur.fetchall()
        total = sum(int(r.get("total") or 0) for r in rows)
        items = []
        for r in rows:
            count = int(r.get("total") or 0)
            ratio = 0.0 if total == 0 else (count / total) * 100.0
            items.append({"attack_type": r["attack_type"], "total": count, "ratio_percent": round(ratio, 2)})
        return jsonify({"items": items})

    @app.route("/api/v2/pro/events", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_PRO, ROLE_ADMIN)
    def pro_events():
        try:
            start_dt, end_dt = build_time_range()
        except ValueError as exc:
            return jsonify({"error": "invalid_time_range", "message": str(exc)}), 400

        risk_level = request.args.get("risk_level", "all").strip().lower()
        attack_type = request.args.get("attack_type", "all").strip()
        target_node = request.args.get("target_node", "all").strip()
        process_status = request.args.get("process_status", "all").strip().lower()
        keyword = request.args.get("keyword", "").strip()
        page = max(1, int(request.args.get("page", "1")))
        page_size = max(1, min(int(request.args.get("page_size", "20")), 200))
        offset = (page - 1) * page_size

        where = ["occurred_at BETWEEN %s AND %s"]
        params: List[Any] = [start_dt, end_dt]
        if risk_level != "all":
            where.append("risk_level=%s")
            params.append(risk_level)
        if attack_type != "all":
            where.append("attack_type=%s")
            params.append(attack_type)
        if target_node != "all":
            where.append("target_node=%s")
            params.append(target_node)
        if process_status != "all":
            where.append("process_status=%s")
            params.append(process_status)
        if keyword:
            where.append("(event_id LIKE %s OR source_ip LIKE %s OR target_interface LIKE %s)")
            like = f"%{keyword}%"
            params.extend([like, like, like])
        where_sql = " AND ".join(where)

        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) AS c FROM demo_attack_events WHERE {where_sql}", tuple(params))
                total = int((cur.fetchone() or {}).get("c", 0))
                cur.execute(
                    f"""
                    SELECT
                      event_id,
                      occurred_at,
                      risk_level,
                      attack_type,
                      source_ip,
                      target_node,
                      attack_result,
                      process_status
                    FROM demo_attack_events
                    WHERE {where_sql}
                    ORDER BY occurred_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    tuple(params + [page_size, offset]),
                )
                rows = cur.fetchall()
        return jsonify({"items": normalize_rows(rows), "page": page, "page_size": page_size, "total": total})

    @app.route("/api/v2/pro/events/<event_id>", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_PRO, ROLE_ADMIN)
    def pro_event_detail(event_id: str):
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                      event_id, occurred_at, risk_level, attack_type, source_ip, source_region,
                      target_node, target_interface, attack_result, process_status, attack_payload,
                      request_log, protection_action, handling_suggestion, note, response_ms, anomaly_detected
                    FROM demo_attack_events
                    WHERE event_id=%s
                    LIMIT 1
                    """,
                    (event_id,),
                )
                row = cur.fetchone()
        if not row:
            return jsonify({"error": "event_not_found"}), 404
        return jsonify(normalize_row(row))

    @app.route("/api/v2/pro/events/batch-status", methods=["POST"])
    @require_roles(ROLE_PRO, ROLE_ADMIN)
    def pro_batch_status():
        body = request.get_json(silent=True) or {}
        event_ids = body.get("event_ids", [])
        new_status = str(body.get("process_status", "")).strip().lower()
        if not isinstance(event_ids, list) or not event_ids:
            return jsonify({"error": "event_ids_required"}), 400
        if new_status not in PROCESS_STATUS_SET:
            return jsonify({"error": "invalid_process_status"}), 400
        placeholders = ",".join(["%s"] * len(event_ids))
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"UPDATE demo_attack_events SET process_status=%s, acked=CASE WHEN %s IN ('done','ignored') THEN 1 ELSE acked END WHERE event_id IN ({placeholders})",
                    tuple([new_status, new_status] + event_ids),
                )
                affected = cur.rowcount
                refresh_machine_stats(conn)
                log_action(
                    conn,
                    g.session["username"],
                    g.session["role"],
                    "batch_status_update",
                    "events",
                    f"count={len(event_ids)},status={new_status}",
                )
            conn.commit()
        return jsonify({"ok": True, "affected": affected})

    @app.route("/api/v2/pro/events/<event_id>/note", methods=["POST"])
    @require_roles(ROLE_PRO, ROLE_ADMIN)
    def pro_event_note(event_id: str):
        body = request.get_json(silent=True) or {}
        note = str(body.get("note", "")).strip()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE demo_attack_events SET note=%s WHERE event_id=%s", (note, event_id))
                changed = cur.rowcount
                log_action(conn, g.session["username"], g.session["role"], "event_note", event_id, note[:120])
            conn.commit()
        if changed == 0:
            return jsonify({"error": "event_not_found"}), 404
        return jsonify({"ok": True, "event_id": event_id})

    @app.route("/api/v2/pro/model/performance", methods=["GET"])
    @require_roles(ROLE_PRO, ROLE_ADMIN)
    def pro_model_performance():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                      DATE(metric_time) AS d,
                      AVG(drift_score) AS drift_score,
                      AVG(accuracy) AS accuracy,
                      AVG(recall_rate) AS recall_rate,
                      AVG(inference_ms) AS inference_ms
                    FROM demo_model_metrics
                    WHERE metric_time >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
                    GROUP BY DATE(metric_time)
                    ORDER BY d
                    """
                )
                trend = cur.fetchall()
                cur.execute(
                    """
                    SELECT
                      SUM(CASE WHEN response_ms < 100 THEN 1 ELSE 0 END) AS lt_100,
                      SUM(CASE WHEN response_ms >= 100 AND response_ms < 300 THEN 1 ELSE 0 END) AS b100_300,
                      SUM(CASE WHEN response_ms >= 300 AND response_ms < 800 THEN 1 ELSE 0 END) AS b300_800,
                      SUM(CASE WHEN response_ms >= 800 THEN 1 ELSE 0 END) AS ge_800
                    FROM demo_attack_events
                    WHERE occurred_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                    """
                )
                dist = cur.fetchone() or {}
        return jsonify(
            {
                "trend": normalize_rows(trend),
                "inference_distribution": [
                    {"bucket": "<100ms", "count": int(dist.get("lt_100") or 0)},
                    {"bucket": "100-300ms", "count": int(dist.get("b100_300") or 0)},
                    {"bucket": "300-800ms", "count": int(dist.get("b300_800") or 0)},
                    {"bucket": ">=800ms", "count": int(dist.get("ge_800") or 0)},
                ],
            }
        )

    @app.route("/api/v2/pro/nodes/<node_name>/detail", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_PRO, ROLE_ADMIN)
    def pro_node_detail(node_name: str):
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM demo_machines WHERE machine_name=%s LIMIT 1", (node_name,))
                machine = cur.fetchone()
                if not machine:
                    return jsonify({"error": "node_not_found"}), 404
                cur.execute(
                    """
                    SELECT COUNT(*) AS total_7d,
                           SUM(CASE WHEN attack_result='blocked' THEN 1 ELSE 0 END) AS blocked_7d,
                           SUM(CASE WHEN risk_level='high' THEN 1 ELSE 0 END) AS high_7d
                    FROM demo_attack_events
                    WHERE target_node=%s AND occurred_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                    """,
                    (node_name,),
                )
                stats = cur.fetchone() or {}
                cur.execute(
                    """
                    SELECT event_id, occurred_at, risk_level, attack_type, source_ip, attack_result, process_status
                    FROM demo_attack_events
                    WHERE target_node=%s
                    ORDER BY occurred_at DESC
                    LIMIT 50
                    """,
                    (node_name,),
                )
                events = cur.fetchall()
        return jsonify({"machine": normalize_row(machine), "stats": normalize_row(stats), "recent_events": normalize_rows(events)})

    @app.route("/api/v2/admin/summary", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def admin_summary():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            refresh_machine_stats(conn)
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS c FROM demo_machines WHERE online_status='online'")
                online_count = int((cur.fetchone() or {}).get("c", 0))
                cur.execute("SELECT COUNT(*) AS c FROM demo_attack_events WHERE DATE(occurred_at)=CURDATE()")
                today_attacks = int((cur.fetchone() or {}).get("c", 0))
                cur.execute("SELECT COUNT(*) AS c FROM demo_machines WHERE current_alert_count > 0")
                alert_machine_count = int((cur.fetchone() or {}).get("c", 0))
                cur.execute("SELECT COUNT(*) AS c FROM demo_machines WHERE online_status <> 'online'")
                offline_count = int((cur.fetchone() or {}).get("c", 0))
            conn.commit()
        return jsonify(
            {
                "online_machine_total": online_count,
                "today_attack_total": today_attacks,
                "alert_machine_count": alert_machine_count,
                "offline_machine_count": offline_count,
            }
        )

    @app.route("/api/v2/admin/machines/ranking", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def admin_machine_ranking():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT target_node AS machine_name, COUNT(*) AS attack_total
                    FROM demo_attack_events
                    WHERE DATE(occurred_at)=CURDATE()
                    GROUP BY target_node
                    ORDER BY attack_total DESC
                    """
                )
                rows = cur.fetchall()
        return jsonify({"items": normalize_rows(rows)})

    @app.route("/api/v2/admin/trend7d", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def admin_trend7d():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT DATE(occurred_at) AS d, COUNT(*) AS total
                    FROM demo_attack_events
                    WHERE occurred_at >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
                    GROUP BY DATE(occurred_at)
                    ORDER BY d
                    """
                )
                rows = cur.fetchall()
        return jsonify({"items": normalize_rows(rows)})

    @app.route("/api/v2/admin/machines", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def admin_machines():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            refresh_machine_stats(conn)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, machine_name, ip_address, deploy_location, online_status,
                           today_attack_count, current_alert_count, last_heartbeat,
                           cpu_usage, memory_usage, gpu_usage, model_status
                    FROM demo_machines
                    ORDER BY machine_name
                    """
                )
                rows = cur.fetchall()
            conn.commit()
        return jsonify({"items": normalize_rows(rows)})

    @app.route("/api/v2/admin/machines/<int:machine_id>", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def admin_machine_detail(machine_id: int):
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM demo_machines WHERE id=%s LIMIT 1", (machine_id,))
                machine = cur.fetchone()
                if not machine:
                    return jsonify({"error": "machine_not_found"}), 404
                cur.execute(
                    """
                    SELECT event_id, occurred_at, risk_level, attack_type, source_ip, target_interface, attack_result, process_status
                    FROM demo_attack_events
                    WHERE machine_id=%s
                    ORDER BY occurred_at DESC
                    LIMIT 100
                    """,
                    (machine_id,),
                )
                rows = cur.fetchall()
        return jsonify({"machine": normalize_row(machine), "events": normalize_rows(rows)})

    @app.route("/api/v2/admin/machines/<int:machine_id>/restart-service", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def admin_restart_service(machine_id: int):
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE demo_machines
                    SET model_status='running', last_heartbeat=NOW(), online_status='online'
                    WHERE id=%s
                    """,
                    (machine_id,),
                )
                changed = cur.rowcount
                log_action(conn, g.session["username"], g.session["role"], "restart_service", f"machine:{machine_id}", "demo_restart")
            conn.commit()
        if changed == 0:
            return jsonify({"error": "machine_not_found"}), 404
        return jsonify({"ok": True, "machine_id": machine_id, "message": "service restarted (demo)"})

    @app.route("/api/v2/admin/user-op-logs", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def admin_user_op_logs():
        page = max(1, int(request.args.get("page", "1")))
        page_size = max(1, min(int(request.args.get("page_size", "30")), 200))
        username = request.args.get("username", "").strip()
        offset = (page - 1) * page_size
        where_sql = "WHERE username=%s" if username else ""
        params: List[Any] = [username] if username else []

        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) AS c FROM demo_user_action_logs {where_sql}", tuple(params))
                total = int((cur.fetchone() or {}).get("c", 0))
                cur.execute(
                    f"""
                    SELECT id, username, role, action, target, detail, created_at
                    FROM demo_user_action_logs
                    {where_sql}
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    tuple(params + [page_size, offset]),
                )
                rows = cur.fetchall()
        return jsonify({"items": normalize_rows(rows), "page": page, "page_size": page_size, "total": total})

    @app.route("/api/v2/admin/config", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def admin_config_get():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT config_key, config_value, updated_at FROM demo_system_config ORDER BY config_key")
                rows = cur.fetchall()
        return jsonify({"items": normalize_rows(rows)})

    @app.route("/api/v2/admin/config", methods=["PUT"])
    @require_roles(ROLE_ADMIN)
    def admin_config_put():
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict) or not body:
            return jsonify({"error": "invalid_payload"}), 400
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                for key, value in body.items():
                    cur.execute(
                        """
                        INSERT INTO demo_system_config(config_key, config_value)
                        VALUES (%s, %s)
                        ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)
                        """,
                        (str(key), str(value)),
                    )
                log_action(conn, g.session["username"], g.session["role"], "update_config", "system_config", str(body))
            conn.commit()
        return jsonify({"ok": True})

    @app.route("/api/v2/admin/reports/export", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def admin_report_export():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT DATE(occurred_at) AS day,
                           COUNT(*) AS attack_total,
                           SUM(CASE WHEN attack_result='blocked' THEN 1 ELSE 0 END) AS blocked_total,
                           SUM(CASE WHEN risk_level='high' THEN 1 ELSE 0 END) AS high_total
                    FROM demo_attack_events
                    WHERE occurred_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
                    GROUP BY DATE(occurred_at)
                    ORDER BY day
                    """
                )
                rows = cur.fetchall()
                log_action(conn, g.session["username"], g.session["role"], "export_report", "platform_30d", "csv_export")
            conn.commit()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["day", "attack_total", "blocked_total", "high_total"])
        for row in rows:
            writer.writerow([row["day"], row["attack_total"], row["blocked_total"], row["high_total"]])
        csv_text = output.getvalue()
        return Response(
            csv_text,
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=platform_report_30d.csv"},
        )

    # compatibility endpoints for previous dashboard
    @app.route("/api/v1/screen/attacks", methods=["GET"])
    def list_attacks_v1():
        limit = max(1, min(int(request.args.get("limit", "100")), 500))
        offset = max(0, int(request.args.get("offset", "0")))
        llm_status = request.args.get("llm_status", "").strip()
        where_clause = ""
        params: List[Any] = []
        if llm_status:
            where_clause = "WHERE llm_status = %s"
            params.append(llm_status)
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT
                      case_id,
                      file_id,
                      seq_id,
                      attack_event_time AS event_time,
                      attack_ip,
                      target_interface,
                      attack_type,
                      attack_confidence AS confidence,
                      llm_status
                    FROM analyses
                    {where_clause}
                    ORDER BY
                      CASE WHEN attack_event_time IS NULL OR attack_event_time = '' THEN 1 ELSE 0 END,
                      attack_event_time DESC,
                      updated_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    tuple(params + [limit, offset]),
                )
                rows = cur.fetchall()
        return jsonify({"items": normalize_rows(rows), "limit": limit, "offset": offset})

    @app.route("/api/v1/screen/request-body", methods=["GET"])
    def request_body_v1():
        filters = build_case_filters()
        if filters["error"]:
            return jsonify({"error": filters["error"]}), 400
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT case_id, file_id, seq_id, request_content
                    FROM requests
                    {filters['where']}
                    LIMIT 1
                    """,
                    filters["params"],
                )
                row = cur.fetchone()
        if not row:
            return jsonify({"error": "record_not_found"}), 404
        return jsonify(normalize_row(row))

    @app.route("/api/v1/screen/response-body", methods=["GET"])
    def response_body_v1():
        filters = build_case_filters()
        if filters["error"]:
            return jsonify({"error": filters["error"]}), 400
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT case_id, file_id, seq_id, response_content
                    FROM responses
                    {filters['where']}
                    LIMIT 1
                    """,
                    filters["params"],
                )
                row = cur.fetchone()
        if not row:
            return jsonify({"error": "record_not_found"}), 404
        return jsonify(normalize_row(row))

    @app.route("/api/v1/screen/ping", methods=["OPTIONS"])
    @app.route("/api/v2/<path:_subpath>", methods=["OPTIONS"])
    def options_handler(_subpath: str = ""):
        return ("", 204)

    return app


def build_case_filters() -> Dict[str, Any]:
    case_id = request.args.get("case_id", "").strip()
    file_id = request.args.get("file_id", "").strip()
    seq_id_raw = request.args.get("seq_id", "").strip()
    seq_id: Optional[int] = None
    if seq_id_raw:
        try:
            seq_id = int(seq_id_raw)
        except ValueError:
            return {"where": "", "params": (), "error": "seq_id must be integer"}
    if case_id:
        return {"where": "WHERE case_id=%s", "params": (case_id,), "error": ""}
    if file_id and seq_id is not None:
        return {"where": "WHERE file_id=%s AND seq_id=%s", "params": (file_id, seq_id), "error": ""}
    return {"where": "", "params": (), "error": "provide case_id OR (file_id and seq_id)"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI attack situation awareness API server")
    parser.add_argument("--host", default="0.0.0.0", help="Flask bind host")
    parser.add_argument("--port", type=int, default=3049, help="Flask bind port")
    parser.add_argument("--mysql-host", default="127.0.0.1", help="MySQL host")
    parser.add_argument("--mysql-port", type=int, default=3306, help="MySQL port")
    parser.add_argument("--mysql-user", default="root", help="MySQL user")
    parser.add_argument("--mysql-password", default="123456", help="MySQL password")
    parser.add_argument("--mysql-database", default="traffic_pipeline", help="MySQL database")
    parser.add_argument("--rag-db-path", default="llm/rag/rag_knowledge.db", help="RAG sqlite db path")
    parser.add_argument("--rag-seed-file", default="llm/rag/rag_seed.json", help="RAG seed json path")
    parser.add_argument("--rag-force-seed", action="store_true", help="Force rebuild RAG db from seed on startup")
    parser.add_argument("--seed-demo", action="store_true", help="Seed demo data if tables are empty")
    parser.add_argument("--force-seed", action="store_true", help="Force regenerate demo data")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    mysql_conf = {
        "host": args.mysql_host,
        "port": args.mysql_port,
        "user": args.mysql_user,
        "password": args.mysql_password,
        "database": args.mysql_database,
    }
    app = create_app(
        mysql_conf=mysql_conf,
        seed_demo=args.seed_demo or args.force_seed,
        force_seed=args.force_seed,
        rag_db_path=args.rag_db_path,
        rag_seed_path=args.rag_seed_file,
        rag_force_seed=args.rag_force_seed,
    )
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()





