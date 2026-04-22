import argparse
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Literal

try:
    import pymysql
    from pymysql.cursors import DictCursor
except Exception:  # noqa: BLE001
    pymysql = None
    DictCursor = None

Backend = Literal["sqlite", "mysql"]


@dataclass
class MySQLConfig:
    host: str = "127.0.0.1"
    port: int = 3306
    user: str = "root"
    password: str = "123456"
    database: str = "traffic_pipeline"


def read_text(path: Path, default: str = "") -> str:
    if not path.exists():
        return default
    for enc in ("utf-8", "utf-8-sig", "gbk", "latin1"):
        try:
            return path.read_text(encoding=enc)
        except Exception:
            continue
    return path.read_text(encoding="utf-8", errors="replace")


def read_json(path: Path, default: Dict[str, Any] | None = None) -> Dict[str, Any]:
    if default is None:
        default = {}
    text = read_text(path, default="")
    if not text.strip():
        return default
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else default
    except Exception:
        return default


def load_manifest(path: Path) -> Dict[str, Dict[str, Any]]:
    mapping: Dict[str, Dict[str, Any]] = {}
    text = read_text(path, default="")
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        case_id = obj.get("case_id")
        if isinstance(case_id, str) and case_id:
            mapping[case_id] = obj
    return mapping


def first_non_none(*vals: Any) -> Any:
    for v in vals:
        if v is not None:
            return v
    return None


def to_int(v: Any) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except Exception:
        return None


def to_float(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except Exception:
        return None


def normalize_attack_event_time(case_obj: Dict[str, Any], analysis_obj: Dict[str, Any]) -> str | None:
    val = first_non_none(
        analysis_obj.get("attack_time"),
        analysis_obj.get("analyzed_at"),
        case_obj.get("analyzed_at"),
        case_obj.get("export_time"),
    )
    if val is None:
        return None
    text = str(val).strip()
    return text or None


def normalize_attack_ip(case_obj: Dict[str, Any], analysis_obj: Dict[str, Any]) -> str | None:
    val = first_non_none(
        analysis_obj.get("source_ip"),
        case_obj.get("source_ip"),
    )
    if val is None:
        return None
    text = str(val).strip()
    return text or None


def normalize_target_interface(case_obj: Dict[str, Any], analysis_obj: Dict[str, Any]) -> str | None:
    val = first_non_none(
        analysis_obj.get("attack_interface"),
        case_obj.get("uri"),
    )
    if val is None:
        return None
    text = str(val).strip()
    return text or None


def normalize_attack_type(analysis_obj: Dict[str, Any]) -> str | None:
    val = first_non_none(
        analysis_obj.get("attack_method"),
        analysis_obj.get("verdict"),
    )
    if val is None:
        return None
    text = str(val).strip()
    return text or None


def parse_mysql_datetime(v: Any) -> datetime:
    if v is None:
        return datetime.now()
    text = str(v).strip()
    if not text:
        return datetime.now()

    normalized = text.replace("T", " ").replace("Z", "")
    normalized = re.sub(r"[+-]\d{2}:\d{2}$", "", normalized).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(normalized, fmt)
        except Exception:
            continue
    return datetime.now()


def infer_attack_type_text(analysis_obj: Dict[str, Any], request_row: Dict[str, Any], request_content: str) -> str:
    for key in ("attack_type", "attack_method", "verdict"):
        val = str(analysis_obj.get(key) or "").strip()
        if val:
            return val

    text = "\n".join(
        [
            str(request_row.get("uri") or ""),
            str(request_row.get("request_text_summary") or ""),
            str(request_content or ""),
        ]
    ).lower()
    rules = [
        (r"(?:\bor\b\s+1=1|union\s+select|information_schema|sleep\()", "SQL注入"),
        (r"(<script|javascript:|onerror=|onload=)", "XSS"),
        (r"(\.\./|\.\.\\|/etc/passwd|\\windows\\system32)", "路径遍历"),
        (r"(cmd\.exe|/bin/sh|powershell|;\s*cat\s+)", "命令注入"),
        (r"(multipart/form-data|\.php|\.jsp|\.aspx)", "文件上传"),
        (r"(scan|masscan|nmap)", "端口扫描"),
    ]
    for pattern, label in rules:
        if re.search(pattern, text, re.I):
            return label
    return "可疑流量"


def infer_risk_level(analysis_obj: Dict[str, Any], request_row: Dict[str, Any]) -> str:
    sev = str(analysis_obj.get("severity") or "").strip().lower()
    if sev in {"critical", "high", "medium", "low"}:
        return "high" if sev == "critical" else sev

    conf = to_float(analysis_obj.get("confidence"))
    if conf is None:
        conf = to_float(request_row.get("raw_score"))
    if conf is None:
        conf = 0.0

    label = str(request_row.get("label") or "").strip().lower()
    if conf >= 0.8:
        return "high"
    if conf >= 0.45 or label == "suspicious":
        return "medium"
    return "low"


def infer_attack_result(status_code: int | None) -> str:
    if status_code is None:
        return "success"
    if status_code in {401, 403, 404, 406, 409, 429}:
        return "blocked"
    if status_code >= 500:
        return "blocked"
    return "success"


def validate_mysql_identifier(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_]+", name):
        raise ValueError(f"invalid mysql database name: {name}")
    return name


def ensure_pymysql_available() -> None:
    if pymysql is None:
        raise RuntimeError("PyMySQL is required for MySQL backend. Run: python -m pip install PyMySQL")


def connect_sqlite(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def connect_mysql(cfg: MySQLConfig):
    ensure_pymysql_available()
    db_name = validate_mysql_identifier(cfg.database)

    bootstrap_conn = pymysql.connect(
        host=cfg.host,
        port=cfg.port,
        user=cfg.user,
        password=cfg.password,
        charset="utf8mb4",
        autocommit=False,
    )
    try:
        with bootstrap_conn.cursor() as cur:
            cur.execute(
                f"CREATE DATABASE IF NOT EXISTS `{db_name}` "
                "DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
        bootstrap_conn.commit()
    finally:
        bootstrap_conn.close()

    return pymysql.connect(
        host=cfg.host,
        port=cfg.port,
        user=cfg.user,
        password=cfg.password,
        database=db_name,
        charset="utf8mb4",
        cursorclass=DictCursor,
        autocommit=False,
    )


def ensure_schema_sqlite(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        PRAGMA journal_mode = WAL;

        CREATE TABLE IF NOT EXISTS requests (
          case_id TEXT PRIMARY KEY,
          file_id TEXT,
          seq_id INTEGER,
          rank_no INTEGER,
          raw_score REAL,
          norm_score REAL,
          label TEXT,
          method TEXT,
          uri TEXT,
          host TEXT,
          status_code INTEGER,
          request_text_summary TEXT,
          request_content TEXT,
          export_time TEXT,
          created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
          updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS responses (
          case_id TEXT PRIMARY KEY,
          file_id TEXT,
          seq_id INTEGER,
          status_code INTEGER,
          response_content TEXT,
          export_time TEXT,
          created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
          updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS analyses (
          case_id TEXT PRIMARY KEY,
          file_id TEXT,
          seq_id INTEGER,
          llm_status TEXT,
          llm_error TEXT,
          llm_started_at TEXT,
          llm_failed_at TEXT,
          analyzed_at TEXT,
          model_name TEXT,
          verdict TEXT,
          source_ip TEXT,
          destination_ip TEXT,
          attack_interface TEXT,
          attack_method TEXT,
          attack_path TEXT,
          attack_time TEXT,
          severity TEXT,
          confidence REAL,
          summary TEXT,
          evidence_json TEXT,
          analysis_raw TEXT,
          attack_event_time TEXT,
          attack_ip TEXT,
          target_interface TEXT,
          attack_type TEXT,
          attack_confidence REAL,
          created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
          updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        );

        CREATE INDEX IF NOT EXISTS idx_requests_file_seq ON requests(file_id, seq_id);
        CREATE INDEX IF NOT EXISTS idx_responses_file_seq ON responses(file_id, seq_id);
        CREATE INDEX IF NOT EXISTS idx_analyses_file_seq ON analyses(file_id, seq_id);
        CREATE INDEX IF NOT EXISTS idx_analyses_llm_status ON analyses(llm_status);
        """
    )
    _ensure_sqlite_columns(
        conn,
        "analyses",
        [
            ("attack_event_time", "TEXT"),
            ("attack_ip", "TEXT"),
            ("target_interface", "TEXT"),
            ("attack_type", "TEXT"),
            ("attack_confidence", "REAL"),
        ],
    )


def _ensure_sqlite_columns(conn: sqlite3.Connection, table: str, column_defs: List[tuple[str, str]]) -> None:
    existing = {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    for col_name, col_type in column_defs:
        if col_name in existing:
            continue
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}")


def ensure_schema_mysql(conn: Any) -> None:
    ddl_list = [
        """
        CREATE TABLE IF NOT EXISTS requests (
          case_id VARCHAR(64) PRIMARY KEY,
          file_id VARCHAR(128) NULL,
          seq_id INT NULL,
          rank_no INT NULL,
          raw_score DOUBLE NULL,
          norm_score DOUBLE NULL,
          label VARCHAR(64) NULL,
          method VARCHAR(16) NULL,
          uri TEXT NULL,
          host VARCHAR(255) NULL,
          status_code INT NULL,
          request_text_summary LONGTEXT NULL,
          request_content LONGTEXT NULL,
          export_time VARCHAR(64) NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          KEY idx_requests_file_seq (file_id, seq_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """,
        """
        CREATE TABLE IF NOT EXISTS responses (
          case_id VARCHAR(64) PRIMARY KEY,
          file_id VARCHAR(128) NULL,
          seq_id INT NULL,
          status_code INT NULL,
          response_content LONGTEXT NULL,
          export_time VARCHAR(64) NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          KEY idx_responses_file_seq (file_id, seq_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """,
        """
        CREATE TABLE IF NOT EXISTS analyses (
          case_id VARCHAR(64) PRIMARY KEY,
          file_id VARCHAR(128) NULL,
          seq_id INT NULL,
          llm_status VARCHAR(32) NULL,
          llm_error TEXT NULL,
          llm_started_at VARCHAR(64) NULL,
          llm_failed_at VARCHAR(64) NULL,
          analyzed_at VARCHAR(64) NULL,
          model_name VARCHAR(255) NULL,
          verdict VARCHAR(64) NULL,
          source_ip VARCHAR(64) NULL,
          destination_ip VARCHAR(64) NULL,
          attack_interface VARCHAR(255) NULL,
          attack_method VARCHAR(255) NULL,
          attack_path TEXT NULL,
          attack_time VARCHAR(64) NULL,
          severity VARCHAR(64) NULL,
          confidence DOUBLE NULL,
          summary LONGTEXT NULL,
          evidence_json LONGTEXT NULL,
          analysis_raw LONGTEXT NULL,
          attack_event_time VARCHAR(64) NULL,
          attack_ip VARCHAR(64) NULL,
          target_interface VARCHAR(255) NULL,
          attack_type VARCHAR(255) NULL,
          attack_confidence DOUBLE NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          KEY idx_analyses_file_seq (file_id, seq_id),
          KEY idx_analyses_llm_status (llm_status)
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
          process_status VARCHAR(16) NOT NULL DEFAULT 'unprocessed',
          acked TINYINT(1) NOT NULL DEFAULT 0,
          attack_payload LONGTEXT NULL,
          request_log LONGTEXT NULL,
          protection_action TEXT NULL,
          handling_suggestion TEXT NULL,
          note TEXT NULL,
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
    ]
    with conn.cursor() as cur:
        for ddl in ddl_list:
            cur.execute(ddl)
        cur.execute("SHOW COLUMNS FROM analyses")
        existing = {str(row["Field"]) for row in cur.fetchall()}
        if "attack_event_time" not in existing:
            cur.execute("ALTER TABLE analyses ADD COLUMN attack_event_time VARCHAR(64) NULL")
        if "attack_ip" not in existing:
            cur.execute("ALTER TABLE analyses ADD COLUMN attack_ip VARCHAR(64) NULL")
        if "target_interface" not in existing:
            cur.execute("ALTER TABLE analyses ADD COLUMN target_interface VARCHAR(255) NULL")
        if "attack_type" not in existing:
            cur.execute("ALTER TABLE analyses ADD COLUMN attack_type VARCHAR(255) NULL")
        if "attack_confidence" not in existing:
            cur.execute("ALTER TABLE analyses ADD COLUMN attack_confidence DOUBLE NULL")


def upsert_requests_sqlite(conn: sqlite3.Connection, row: Dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO requests(
          case_id,file_id,seq_id,rank_no,raw_score,norm_score,label,method,uri,host,status_code,
          request_text_summary,request_content,export_time,updated_at
        ) VALUES(
          :case_id,:file_id,:seq_id,:rank_no,:raw_score,:norm_score,:label,:method,:uri,:host,:status_code,
          :request_text_summary,:request_content,:export_time,datetime('now','localtime')
        )
        ON CONFLICT(case_id) DO UPDATE SET
          file_id=excluded.file_id,
          seq_id=excluded.seq_id,
          rank_no=excluded.rank_no,
          raw_score=excluded.raw_score,
          norm_score=excluded.norm_score,
          label=excluded.label,
          method=excluded.method,
          uri=excluded.uri,
          host=excluded.host,
          status_code=excluded.status_code,
          request_text_summary=excluded.request_text_summary,
          request_content=excluded.request_content,
          export_time=excluded.export_time,
          updated_at=datetime('now','localtime');
        """,
        row,
    )


def upsert_requests_mysql(conn: Any, row: Dict[str, Any]) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO requests(
              case_id,file_id,seq_id,rank_no,raw_score,norm_score,label,method,uri,host,status_code,
              request_text_summary,request_content,export_time
            ) VALUES(
              %(case_id)s,%(file_id)s,%(seq_id)s,%(rank_no)s,%(raw_score)s,%(norm_score)s,%(label)s,%(method)s,%(uri)s,%(host)s,%(status_code)s,
              %(request_text_summary)s,%(request_content)s,%(export_time)s
            )
            ON DUPLICATE KEY UPDATE
              file_id=VALUES(file_id),
              seq_id=VALUES(seq_id),
              rank_no=VALUES(rank_no),
              raw_score=VALUES(raw_score),
              norm_score=VALUES(norm_score),
              label=VALUES(label),
              method=VALUES(method),
              uri=VALUES(uri),
              host=VALUES(host),
              status_code=VALUES(status_code),
              request_text_summary=VALUES(request_text_summary),
              request_content=VALUES(request_content),
              export_time=VALUES(export_time)
            """,
            row,
        )


def upsert_responses_sqlite(conn: sqlite3.Connection, row: Dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO responses(
          case_id,file_id,seq_id,status_code,response_content,export_time,updated_at
        ) VALUES(
          :case_id,:file_id,:seq_id,:status_code,:response_content,:export_time,datetime('now','localtime')
        )
        ON CONFLICT(case_id) DO UPDATE SET
          file_id=excluded.file_id,
          seq_id=excluded.seq_id,
          status_code=excluded.status_code,
          response_content=excluded.response_content,
          export_time=excluded.export_time,
          updated_at=datetime('now','localtime');
        """,
        row,
    )


def upsert_responses_mysql(conn: Any, row: Dict[str, Any]) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO responses(
              case_id,file_id,seq_id,status_code,response_content,export_time
            ) VALUES(
              %(case_id)s,%(file_id)s,%(seq_id)s,%(status_code)s,%(response_content)s,%(export_time)s
            )
            ON DUPLICATE KEY UPDATE
              file_id=VALUES(file_id),
              seq_id=VALUES(seq_id),
              status_code=VALUES(status_code),
              response_content=VALUES(response_content),
              export_time=VALUES(export_time)
            """,
            row,
        )


def upsert_analyses_sqlite(conn: sqlite3.Connection, row: Dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO analyses(
          case_id,file_id,seq_id,llm_status,llm_error,llm_started_at,llm_failed_at,analyzed_at,model_name,
          verdict,source_ip,destination_ip,attack_interface,attack_method,attack_path,attack_time,severity,
          confidence,summary,evidence_json,analysis_raw,attack_event_time,attack_ip,target_interface,attack_type,attack_confidence,updated_at
        ) VALUES(
          :case_id,:file_id,:seq_id,:llm_status,:llm_error,:llm_started_at,:llm_failed_at,:analyzed_at,:model_name,
          :verdict,:source_ip,:destination_ip,:attack_interface,:attack_method,:attack_path,:attack_time,:severity,
          :confidence,:summary,:evidence_json,:analysis_raw,:attack_event_time,:attack_ip,:target_interface,:attack_type,:attack_confidence,datetime('now','localtime')
        )
        ON CONFLICT(case_id) DO UPDATE SET
          file_id=excluded.file_id,
          seq_id=excluded.seq_id,
          llm_status=excluded.llm_status,
          llm_error=excluded.llm_error,
          llm_started_at=excluded.llm_started_at,
          llm_failed_at=excluded.llm_failed_at,
          analyzed_at=excluded.analyzed_at,
          model_name=excluded.model_name,
          verdict=excluded.verdict,
          source_ip=excluded.source_ip,
          destination_ip=excluded.destination_ip,
          attack_interface=excluded.attack_interface,
          attack_method=excluded.attack_method,
          attack_path=excluded.attack_path,
          attack_time=excluded.attack_time,
          severity=excluded.severity,
          confidence=excluded.confidence,
          summary=excluded.summary,
          evidence_json=excluded.evidence_json,
          analysis_raw=excluded.analysis_raw,
          attack_event_time=excluded.attack_event_time,
          attack_ip=excluded.attack_ip,
          target_interface=excluded.target_interface,
          attack_type=excluded.attack_type,
          attack_confidence=excluded.attack_confidence,
          updated_at=datetime('now','localtime');
        """,
        row,
    )


def upsert_analyses_mysql(conn: Any, row: Dict[str, Any]) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO analyses(
              case_id,file_id,seq_id,llm_status,llm_error,llm_started_at,llm_failed_at,analyzed_at,model_name,
              verdict,source_ip,destination_ip,attack_interface,attack_method,attack_path,attack_time,severity,
              confidence,summary,evidence_json,analysis_raw,attack_event_time,attack_ip,target_interface,attack_type,attack_confidence
            ) VALUES(
              %(case_id)s,%(file_id)s,%(seq_id)s,%(llm_status)s,%(llm_error)s,%(llm_started_at)s,%(llm_failed_at)s,%(analyzed_at)s,%(model_name)s,
              %(verdict)s,%(source_ip)s,%(destination_ip)s,%(attack_interface)s,%(attack_method)s,%(attack_path)s,%(attack_time)s,%(severity)s,
              %(confidence)s,%(summary)s,%(evidence_json)s,%(analysis_raw)s,%(attack_event_time)s,%(attack_ip)s,%(target_interface)s,%(attack_type)s,%(attack_confidence)s
            )
            ON DUPLICATE KEY UPDATE
              file_id=VALUES(file_id),
              seq_id=VALUES(seq_id),
              llm_status=VALUES(llm_status),
              llm_error=VALUES(llm_error),
              llm_started_at=VALUES(llm_started_at),
              llm_failed_at=VALUES(llm_failed_at),
              analyzed_at=VALUES(analyzed_at),
              model_name=VALUES(model_name),
              verdict=VALUES(verdict),
              source_ip=VALUES(source_ip),
              destination_ip=VALUES(destination_ip),
              attack_interface=VALUES(attack_interface),
              attack_method=VALUES(attack_method),
              attack_path=VALUES(attack_path),
              attack_time=VALUES(attack_time),
              severity=VALUES(severity),
              confidence=VALUES(confidence),
              summary=VALUES(summary),
              evidence_json=VALUES(evidence_json),
              analysis_raw=VALUES(analysis_raw),
              attack_event_time=VALUES(attack_event_time),
              attack_ip=VALUES(attack_ip),
              target_interface=VALUES(target_interface),
              attack_type=VALUES(attack_type),
              attack_confidence=VALUES(attack_confidence)
            """,
            row,
        )


def upsert_demo_attack_event_mysql(conn: Any, row: Dict[str, Any]) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO demo_attack_events(
              event_id, occurred_at, risk_level, attack_type, source_ip, source_region,
              target_node, target_interface, attack_result, process_status, acked,
              attack_payload, request_log, protection_action, handling_suggestion, note,
              response_ms, anomaly_detected, machine_id
            ) VALUES (
              %(event_id)s, %(occurred_at)s, %(risk_level)s, %(attack_type)s, %(source_ip)s, %(source_region)s,
              %(target_node)s, %(target_interface)s, %(attack_result)s, %(process_status)s, %(acked)s,
              %(attack_payload)s, %(request_log)s, %(protection_action)s, %(handling_suggestion)s, %(note)s,
              %(response_ms)s, %(anomaly_detected)s, %(machine_id)s
            )
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
              anomaly_detected=VALUES(anomaly_detected),
              machine_id=VALUES(machine_id)
            """,
            row,
        )


def count_rows(conn: Any, backend: Backend, table: str) -> int:
    if table not in {"requests", "responses", "analyses", "demo_attack_events"}:
        raise ValueError(f"unsupported table: {table}")

    if backend == "sqlite":
        row = conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()
        return int(row["c"])

    with conn.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) AS c FROM `{table}`")
        row = cur.fetchone() or {}
    return int(row.get("c", 0))


def sync_result_to_db(
    result_dir: Path,
    backend: Backend = "mysql",
    db_path: Path | None = None,
    mysql_config: MySQLConfig | None = None,
) -> Dict[str, Any]:
    manifest_map = load_manifest(result_dir / "manifest.jsonl")

    case_dirs: List[Path] = sorted(
        [p for p in result_dir.glob("b.*") if p.is_dir()],
        key=lambda p: int(p.name.split(".", 1)[1]) if p.name.split(".", 1)[1].isdigit() else 10**9,
    )

    if backend == "sqlite":
        if db_path is None:
            raise ValueError("db_path is required when backend=sqlite")
        conn = connect_sqlite(db_path)
        ensure_schema_sqlite(conn)
        target = str(db_path)
    else:
        cfg = mysql_config or MySQLConfig()
        conn = connect_mysql(cfg)
        ensure_schema_mysql(conn)
        target = f"mysql://{cfg.user}@{cfg.host}:{cfg.port}/{cfg.database}"

    machine_targets: List[Dict[str, Any]] = []
    if backend == "mysql":
        with conn.cursor() as cur:
            try:
                cur.execute("SELECT id, machine_name FROM demo_machines ORDER BY id")
                machine_targets = [x for x in cur.fetchall() if x.get("machine_name")]
            except Exception:
                machine_targets = []
    if not machine_targets:
        machine_targets = [{"id": None, "machine_name": "node-local-01"}]

    total = 0
    with_analysis = 0
    for case_dir in case_dirs:
        case_id = case_dir.name
        case_obj = read_json(case_dir / "case.json", default={})
        manifest_obj = manifest_map.get(case_id, {})
        analysis_obj = read_json(case_dir / "analysis.json", default={})

        file_id = first_non_none(case_obj.get("file_id"), manifest_obj.get("file_id"))
        seq_id = to_int(first_non_none(case_obj.get("seq_id"), manifest_obj.get("seq_id")))

        request_content = read_text(case_dir / "request.txt", default="")
        response_content = read_text(case_dir / "response.txt", default="")
        analysis_raw = read_text(case_dir / "analysis_raw.txt", default="")

        request_row = {
            "case_id": case_id,
            "file_id": file_id,
            "seq_id": seq_id,
            "rank_no": to_int(case_obj.get("rank")),
            "raw_score": to_float(first_non_none(case_obj.get("raw_score"), manifest_obj.get("raw_score"))),
            "norm_score": to_float(first_non_none(case_obj.get("norm_score"), manifest_obj.get("norm_score"))),
            "label": first_non_none(case_obj.get("label"), manifest_obj.get("label")),
            "method": case_obj.get("method"),
            "uri": first_non_none(case_obj.get("uri"), manifest_obj.get("uri")),
            "host": case_obj.get("host"),
            "status_code": to_int(case_obj.get("status_code")),
            "request_text_summary": case_obj.get("request_text"),
            "request_content": request_content,
            "export_time": case_obj.get("export_time"),
        }
        if backend == "sqlite":
            upsert_requests_sqlite(conn, request_row)
        else:
            upsert_requests_mysql(conn, request_row)

        response_row = {
            "case_id": case_id,
            "file_id": file_id,
            "seq_id": seq_id,
            "status_code": to_int(case_obj.get("status_code")),
            "response_content": response_content,
            "export_time": case_obj.get("export_time"),
        }
        if backend == "sqlite":
            upsert_responses_sqlite(conn, response_row)
        else:
            upsert_responses_mysql(conn, response_row)

        evidence = analysis_obj.get("evidence")
        if isinstance(evidence, list):
            evidence_json = json.dumps(evidence, ensure_ascii=False)
        else:
            evidence_json = "[]"

        analysis_row = {
            "case_id": case_id,
            "file_id": file_id,
            "seq_id": seq_id,
            "llm_status": case_obj.get("llm_status"),
            "llm_error": case_obj.get("llm_error"),
            "llm_started_at": case_obj.get("llm_started_at"),
            "llm_failed_at": case_obj.get("llm_failed_at"),
            "analyzed_at": first_non_none(case_obj.get("analyzed_at"), analysis_obj.get("analyzed_at")),
            "model_name": first_non_none(analysis_obj.get("model_name"), case_obj.get("model_name")),
            "verdict": analysis_obj.get("verdict"),
            "source_ip": analysis_obj.get("source_ip"),
            "destination_ip": analysis_obj.get("destination_ip"),
            "attack_interface": analysis_obj.get("attack_interface"),
            "attack_method": analysis_obj.get("attack_method"),
            "attack_path": analysis_obj.get("attack_path"),
            "attack_time": analysis_obj.get("attack_time"),
            "severity": analysis_obj.get("severity"),
            "confidence": to_float(analysis_obj.get("confidence")),
            "summary": analysis_obj.get("summary"),
            "evidence_json": evidence_json,
            "analysis_raw": analysis_raw,
            "attack_event_time": normalize_attack_event_time(case_obj, analysis_obj),
            "attack_ip": normalize_attack_ip(case_obj, analysis_obj),
            "target_interface": normalize_target_interface(case_obj, analysis_obj),
            "attack_type": normalize_attack_type(analysis_obj),
            "attack_confidence": to_float(analysis_obj.get("confidence")),
        }
        if backend == "sqlite":
            upsert_analyses_sqlite(conn, analysis_row)
        else:
            upsert_analyses_mysql(conn, analysis_row)
            src_ip_match = re.search(r"(?mi)^src_ip=([^\r\n]+)", request_content or "")
            source_ip = (
                normalize_attack_ip(case_obj, analysis_obj)
                or (src_ip_match.group(1).strip() if src_ip_match else "")
                or "unknown"
            )
            target_interface = normalize_target_interface(case_obj, analysis_obj) or str(request_row.get("uri") or "-")
            attack_type = infer_attack_type_text(analysis_obj, request_row, request_content)
            risk_level = infer_risk_level(analysis_obj, request_row)
            status_code = to_int(request_row.get("status_code"))
            machine = machine_targets[hash(case_id) % len(machine_targets)]
            event_row = {
                "event_id": str(case_id)[:40],
                "occurred_at": parse_mysql_datetime(analysis_row.get("attack_event_time") or case_obj.get("export_time")),
                "risk_level": risk_level,
                "attack_type": str(attack_type)[:64] if attack_type else "可疑流量",
                "source_ip": str(source_ip)[:64],
                "source_region": "未知",
                "target_node": str(machine.get("machine_name") or "node-local-01")[:64],
                "target_interface": str(target_interface)[:255],
                "attack_result": infer_attack_result(status_code),
                "process_status": "unprocessed",
                "acked": 0,
                "attack_payload": str(request_row.get("request_text_summary") or "")[:20000],
                "request_log": request_content,
                "protection_action": str(analysis_obj.get("summary") or "自动识别到可疑流量，已进入人工复核流程。")[:4000],
                "handling_suggestion": "核查登录接口参数化与WAF规则，限制异常重试并记录审计日志。",
                "note": "",
                "response_ms": 0,
                "anomaly_detected": 1 if risk_level == "high" else 0,
                "machine_id": machine.get("id"),
            }
            upsert_demo_attack_event_mysql(conn, event_row)

        total += 1
        if analysis_obj:
            with_analysis += 1

    conn.commit()

    req_count = count_rows(conn, backend, "requests")
    rsp_count = count_rows(conn, backend, "responses")
    an_count = count_rows(conn, backend, "analyses")
    demo_count = count_rows(conn, backend, "demo_attack_events") if backend == "mysql" else 0
    conn.close()

    return {
        "backend": backend,
        "target": target,
        "cases_scanned": total,
        "cases_with_analysis_json": with_analysis,
        "requests_rows": req_count,
        "responses_rows": rsp_count,
        "analyses_rows": an_count,
        "demo_event_rows": demo_count,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build DB from result/b.* directories")
    parser.add_argument("--result-dir", default="result", help="Directory containing b.* case folders")
    parser.add_argument("--backend", choices=["sqlite", "mysql"], default="mysql", help="Database backend")

    parser.add_argument("--db-path", default="result/result_cases.db", help="SQLite db path")

    parser.add_argument("--mysql-host", default="127.0.0.1", help="MySQL host")
    parser.add_argument("--mysql-port", type=int, default=3306, help="MySQL port")
    parser.add_argument("--mysql-user", default="root", help="MySQL user")
    parser.add_argument("--mysql-password", default="123456", help="MySQL password")
    parser.add_argument("--mysql-database", default="traffic_pipeline", help="MySQL database name")

    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    result_dir = (project_root / args.result_dir).resolve()
    db_path = (project_root / args.db_path).resolve()

    mysql_cfg = MySQLConfig(
        host=args.mysql_host,
        port=args.mysql_port,
        user=args.mysql_user,
        password=args.mysql_password,
        database=args.mysql_database,
    )

    stats = sync_result_to_db(
        result_dir=result_dir,
        backend=args.backend,
        db_path=db_path,
        mysql_config=mysql_cfg,
    )

    print(f"backend: {stats['backend']}")
    print(f"target: {stats['target']}")
    print(f"cases scanned: {stats['cases_scanned']}")
    print(f"cases with analysis.json: {stats['cases_with_analysis_json']}")
    print(f"requests rows: {stats['requests_rows']}")
    print(f"responses rows: {stats['responses_rows']}")
    print(f"analyses rows: {stats['analyses_rows']}")
    if "demo_event_rows" in stats:
        print(f"demo_attack_events rows: {stats['demo_event_rows']}")


if __name__ == "__main__":
    main()
