import argparse
import base64
import csv
import hashlib
import hmac
import ipaddress
import io
import json
import os
import platform
import random
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
import uuid
import urllib.parse
import urllib.request
import urllib.error
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, Response, current_app, g, jsonify, request, send_file
import pymysql
from pymysql.cursors import DictCursor

from situation_ai import analyze_situation
from situation_cluster import build_proxy_clusters
from situation_core import ACTION_CATALOG, STAGE_LABELS, STAGE_ORDER
from situation_store import MySQLSettings, MySQLSituationStore
from raw_llm_review import ensure_review_schema
from situation_professional_report import (
    ProfessionalReportManager,
    create_job as create_professional_report_job,
    ensure_schema as ensure_professional_report_schema,
    find_job as find_professional_report_job,
    get_job as get_professional_report_job,
    public_job as public_professional_report_job,
)
from firewall_control import (
    firewall_block_ip as verified_firewall_block_ip,
    firewall_status_many as verified_firewall_status_many,
    firewall_unblock_ip as verified_firewall_unblock_ip,
)
from rag_service import (
    MAX_UPLOAD_BYTES as RAG_MAX_UPLOAD_BYTES,
    SUPPORTED_EXTENSIONS as RAG_SUPPORTED_EXTENSIONS,
    delete_document as rag2_delete_document,
    delete_kb as rag2_delete_kb,
    ensure_default_kb as rag2_ensure_default_kb,
    ensure_schema as rag2_ensure_schema,
    get_kb as rag2_get_kb,
    hybrid_search as rag2_hybrid_search,
    index_pending_document as rag2_index_pending_document,
    ingest_file as rag2_ingest_file,
    list_chunks as rag2_list_chunks,
    list_documents as rag2_list_documents,
    list_eval_cases as rag2_list_eval_cases,
    list_eval_runs as rag2_list_eval_runs,
    list_kbs as rag2_list_kbs,
    list_test_history as rag2_list_test_history,
    load_api_config as rag2_load_api_config,
    migrate_legacy_sqlite as rag2_migrate_legacy_sqlite,
    delete_eval_case as rag2_delete_eval_case,
    run_eval_suite as rag2_run_eval_suite,
    save_eval_case as rag2_save_eval_case,
    save_kb as rag2_save_kb,
    update_chunk as rag2_update_chunk,
)

try:
    import psutil  # type: ignore
except Exception:
    psutil = None


_CPU_SAMPLE_LOCK = threading.Lock()
_CPU_SAMPLE_CACHE: Dict[str, Any] = {"value": None, "sampled_at": 0.0}


ROLE_NORMAL = "normal"
ROLE_ADMIN = "admin"

PROCESS_STATUS_SET = {"unprocessed", "processing", "done", "ignored"}
RISK_LEVEL_SET = {"critical", "high", "medium", "low"}
RAG_SEVERITY_SET = {"low", "medium", "high", "critical"}

TOKEN_TTL_SECONDS = 12 * 3600
JWT_ALGORITHM = "HS256"
JWT_HEADER = {"alg": JWT_ALGORITHM, "typ": "JWT"}
JWT_REVOKED_JTIS: Dict[str, int] = {}
AUTH_COOKIE_NAME = "tp_auth_token"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DASHBOARD_PUBLIC_DIR = PROJECT_ROOT / "frontend_dashboard" / "public"
DASHBOARD_UPLOAD_DIR = DASHBOARD_PUBLIC_DIR / "uploads"
AVATAR_UPLOAD_DIR = DASHBOARD_UPLOAD_DIR / "avatars"
DEFAULT_HOMEPAGE_BACKGROUND = "/assets/bg-main.jpg"
ALLOWED_BACKGROUND_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
MAX_BACKGROUND_BYTES = 10 * 1024 * 1024
ALLOWED_AVATAR_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
MAX_AVATAR_BYTES = 2 * 1024 * 1024
DEFAULT_JWT_SECRET_PATH = PROJECT_ROOT / "config" / "jwt_secret.txt"
DEFAULT_LLM_PROMPT_PATH = PROJECT_ROOT / "llm" / "prompts" / "system_prompt.txt"
DEFAULT_PROFESSIONAL_REPORT_PROMPT_PATH = PROJECT_ROOT / "llm" / "prompts" / "professional_situation_report_prompt.txt"
MAX_LLM_PROMPT_CHARS = 30000
MAX_PROFESSIONAL_REPORT_PROMPT_CHARS = 60000

DEMO_ACCOUNTS = [
    {"username": "user", "password": "admin", "role": ROLE_NORMAL, "display_name": "普通用户"},
    {"username": "admin", "password": "admin", "role": ROLE_ADMIN, "display_name": "管理员"},
]

DEMO_SEED_USERS = [
    {"username": "user", "password": "admin", "role": ROLE_NORMAL, "display_name": "普通用户"},
    {"username": "admin", "password": "admin", "role": ROLE_ADMIN, "display_name": "管理员"},
]


def find_demo_account(conn: Any, username: str, password: str, role_hint: str = "") -> Optional[Dict[str, Any]]:
    with conn.cursor() as cur:
        if role_hint:
            cur.execute(
                """
                SELECT id, username, password, role, display_name, nickname, avatar_url
                FROM demo_users
                WHERE username=%s AND password=%s AND role=%s
                LIMIT 1
                """,
                (username, password, role_hint),
            )
            return cur.fetchone()
        cur.execute(
            """
            SELECT id, username, password, role, display_name, nickname, avatar_url
            FROM demo_users
            WHERE username=%s AND password=%s
              AND role IN (%s, %s)
            ORDER BY CASE WHEN role=%s THEN 0 ELSE 1 END
            LIMIT 1
            """,
            (username, password, ROLE_NORMAL, ROLE_ADMIN, ROLE_ADMIN),
        )
        return cur.fetchone()


def list_demo_accounts(conn: Any) -> List[Dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT username, password, role
            FROM demo_users
            WHERE role IN (%s, %s)
            ORDER BY CASE role
                WHEN %s THEN 1
                WHEN %s THEN 2
                ELSE 3
            END, username
            """,
            (ROLE_NORMAL, ROLE_ADMIN, ROLE_NORMAL, ROLE_ADMIN),
        )
        return cur.fetchall()


ATTACK_TYPES = [
    "SQL注入",
    "XSS",
    "暴力破解",
    "DDoS",
    "端口扫描",
    "命令注入",
    "路径遍历",
    "文件上传",
    "危险文件上传",
    "SSRF",
    "RCE",
    "XXE",
    "SSTI",
    "反序列化",
    "GraphQL探测",
]

SOURCE_REGIONS = [
    "北京",
    "上海",
    "广东",
    "浙江",
    "江苏",
    "山东",
    "河南",
    "四川",
    "香港",
    "美国",
    "德国",
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


def resolve_project_path(path_text: str, default_path: Path) -> Path:
    raw = str(path_text or "").strip()
    if not raw:
        return default_path.resolve()
    path = Path(raw)
    if path.is_absolute():
        return path.resolve()
    return (PROJECT_ROOT / path).resolve()


def display_project_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except Exception:
        return str(path.resolve())


def load_or_create_jwt_secret(path: Path = DEFAULT_JWT_SECRET_PATH) -> str:
    path = path.resolve()
    if path.exists():
        secret = path.read_text(encoding="utf-8-sig", errors="replace").strip()
        if secret:
            return secret
    path.parent.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_urlsafe(48)
    path.write_text(secret, encoding="utf-8")
    return secret


def read_llm_prompt_file(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8-sig", errors="replace")


def write_llm_prompt_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def build_llm_prompt_payload(path: Path) -> Dict[str, Any]:
    content = read_llm_prompt_file(path)
    updated_at = None
    exists = path.exists()
    if exists:
        try:
            updated_at = dt_to_str(datetime.fromtimestamp(path.stat().st_mtime), ms=False)
        except Exception:
            updated_at = None
    return {
        "prompt": content,
        "path": display_project_path(path),
        "exists": exists,
        "updated_at": updated_at,
        "max_chars": MAX_LLM_PROMPT_CHARS,
        "chars": len(content),
    }


def normalize_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return dt_to_str(value)
    return value


def normalize_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {k: normalize_value(v) for k, v in row.items()}


def normalize_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [normalize_row(r) for r in rows]


DISPLAY_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def sanitize_evidence_text(value: Any) -> str:
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(value or "")).strip()
    if not text:
        return ""
    replacement_count = text.count("�")
    question_runs = sum(len(match.group(0)) for match in re.finditer(r"\?{4,}", text))
    if replacement_count or question_runs >= 8:
        ips = list(dict.fromkeys(DISPLAY_IPV4_RE.findall(text)))[:5]
        suffix = f"；关联IP：{'、'.join(ips)}" if ips else ""
        return f"Windows 登录失败事件（历史原始消息编码异常，乱码内容已隐藏）{suffix}"
    return text


def sanitize_evidence_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: sanitize_evidence_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_evidence_value(item) for item in value]
    if isinstance(value, str):
        return sanitize_evidence_text(value)
    return value


def normalize_situation_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat(timespec="milliseconds") + ("Z" if value.tzinfo is None else "")
    if isinstance(value, dict):
        return {
            key: normalize_situation_value(sanitize_evidence_value(item) if key in {"evidence", "metadata"} else item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [normalize_situation_value(item) for item in value]
    return value


def safe_json_loads(text: Any, default: Any = None) -> Any:
    if default is None:
        default = []
    if text is None:
        return default
    if isinstance(text, (dict, list)):
        return text
    raw = str(text or "").strip()
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:
        return default


def db_table_exists(cur: Any, table_name: str) -> bool:
    try:
        cur.execute("SHOW TABLES LIKE %s", (table_name,))
        return bool(cur.fetchone())
    except Exception:
        return False


def db_column_exists(cur: Any, table_name: str, column_name: str) -> bool:
    try:
        cur.execute(f"SHOW COLUMNS FROM `{table_name}` LIKE %s", (column_name,))
        return bool(cur.fetchone())
    except Exception:
        return False


def event_id_to_v2_candidates(event_id: str) -> Tuple[List[str], List[str]]:
    event = str(event_id or "").strip()
    event_ids = [event] if event else []
    case_ids = [event] if event else []
    if event.startswith("b."):
        event_ids.append(event.replace("b.", "EVT", 1))
    if event.startswith("EVT"):
        suffix = event[3:]
        if suffix:
            case_ids.append(f"b.{suffix}")
    return list(dict.fromkeys(event_ids)), list(dict.fromkeys(case_ids))


def load_v2_detection_detail(cur: Any, event_id: str) -> Optional[Dict[str, Any]]:
    required_tables = [
        "detection_candidates",
        "raw_http_logs",
        "model_predictions",
        "poc_matches",
        "behavior_windows",
    ]
    if not any(db_table_exists(cur, t) for t in required_tables):
        return None

    event_ids, case_ids = event_id_to_v2_candidates(event_id)
    candidate = None
    if db_table_exists(cur, "detection_candidates"):
        for eid in event_ids:
            cur.execute(
                """
                SELECT event_id, case_id, file_id, seq_id, decision, final_score, risk_level,
                       attack_type, source_ip, target_interface, evidence_json, created_at
                FROM detection_candidates
                WHERE event_id=%s
                LIMIT 1
                """,
                (eid,),
            )
            candidate = cur.fetchone()
            if candidate:
                break
        if not candidate:
            for cid in case_ids:
                cur.execute(
                    """
                    SELECT event_id, case_id, file_id, seq_id, decision, final_score, risk_level,
                           attack_type, source_ip, target_interface, evidence_json, created_at
                    FROM detection_candidates
                    WHERE case_id=%s
                    LIMIT 1
                    """,
                    (cid,),
                )
                candidate = cur.fetchone()
                if candidate:
                    break

    attack_event = None
    if db_table_exists(cur, "attack_events"):
        for eid in event_ids + ([str(candidate.get("event_id"))] if candidate else []):
            if not eid:
                continue
            cur.execute(
                """
                SELECT event_id, case_id, occurred_at, source_ip, target_interface, attack_type,
                       risk_level, confidence, status, evidence_json, created_at
                FROM attack_events
                WHERE event_id=%s
                LIMIT 1
                """,
                (eid,),
            )
            attack_event = cur.fetchone()
            if attack_event:
                break

    case_id = ""
    if candidate:
        case_id = str(candidate.get("case_id") or "")
    if not case_id and attack_event:
        case_id = str(attack_event.get("case_id") or "")
    if not case_id:
        for cid in case_ids:
            if cid.startswith("b."):
                case_id = cid
                break
    if not case_id:
        return None

    raw_http = None
    if db_table_exists(cur, "raw_http_logs"):
        cur.execute(
            """
            SELECT case_id, file_id, seq_id, event_time, source_ip, destination_ip, method,
                   uri, host, status_code, request_text, response_text, created_at
            FROM raw_http_logs
            WHERE case_id=%s
            LIMIT 1
            """,
            (case_id,),
        )
        raw_http = cur.fetchone()

    model_predictions: List[Dict[str, Any]] = []
    if db_table_exists(cur, "model_predictions"):
        cur.execute(
            """
            SELECT model_name, label, score, proba_json, created_at
            FROM model_predictions
            WHERE case_id=%s
            ORDER BY id DESC
            LIMIT 10
            """,
            (case_id,),
        )
        model_predictions = normalize_rows(cur.fetchall())
        for pred in model_predictions:
            pred["label"] = normalize_attack_type_label(pred.get("label"))
            pred["proba"] = safe_json_loads(pred.pop("proba_json", None), {})

    poc_matches: List[Dict[str, Any]] = []
    if db_table_exists(cur, "poc_matches"):
        cur.execute(
            """
            SELECT rule_id, rule_name, attack_type, severity, score, evidence_json, created_at
            FROM poc_matches
            WHERE case_id=%s
            ORDER BY score DESC, id ASC
            LIMIT 20
            """,
            (case_id,),
        )
        poc_matches = normalize_rows(cur.fetchall())
        for match in poc_matches:
            match["attack_type"] = normalize_attack_type_label(match.get("attack_type"))
            match["evidence"] = safe_json_loads(match.pop("evidence_json", None), [])

    behavior_windows: List[Dict[str, Any]] = []
    if db_table_exists(cur, "behavior_windows"):
        cur.execute(
            """
            SELECT source_ip, behavior_type, score, features_json, evidence_json, created_at
            FROM behavior_windows
            WHERE case_id=%s
            ORDER BY score DESC, id ASC
            LIMIT 10
            """,
            (case_id,),
        )
        behavior_windows = normalize_rows(cur.fetchall())
        for win in behavior_windows:
            win["features"] = safe_json_loads(win.pop("features_json", None), {})
            win["evidence"] = safe_json_loads(win.pop("evidence_json", None), [])

    evidence: List[Any] = []
    if candidate:
        evidence = sanitize_evidence_value(safe_json_loads(candidate.get("evidence_json"), []))
    if not evidence and attack_event:
        evidence = sanitize_evidence_value(safe_json_loads(attack_event.get("evidence_json"), []))

    llm_review: Dict[str, Any] = {}
    if db_table_exists(cur, "analyses"):
        cur.execute(
            """
            SELECT llm_status,llm_error,analyzed_at,model_name,verdict,severity,confidence,
                   summary,evidence_json,analysis_raw,rag_enabled,rag_hits,review_latency_ms,
                   handling_suggestion,review_source
            FROM analyses WHERE case_id=%s LIMIT 1
            """,
            (case_id,),
        )
        llm_review = normalize_row(cur.fetchone() or {})
        if llm_review:
            llm_raw = safe_json_loads(llm_review.pop("analysis_raw", None), {})
            llm_review["evidence"] = sanitize_evidence_value(
                safe_json_loads(llm_review.pop("evidence_json", None), [])
            )
            if isinstance(llm_raw, dict):
                for key in (
                    "analysis_reasoning",
                    "potential_impact",
                    "immediate_actions",
                    "hardening_actions",
                    "false_positive_notes",
                    "knowledge_references",
                ):
                    value = llm_raw.get(key)
                    if value not in (None, "", []):
                        llm_review[key] = sanitize_evidence_value(value)
            # Old/model-generated references must never look like active RAG
            # evidence when retrieval was disabled for this review.
            if int(llm_review.get("rag_enabled") or 0) != 1:
                llm_review.pop("knowledge_references", None)
            if not llm_review["evidence"] and str(llm_review.get("summary") or "").strip():
                llm_review["evidence"] = [
                    f"大模型研判说明：{str(llm_review['summary']).strip()}"
                ]
    if db_table_exists(cur, "llm_review_jobs"):
        cur.execute(
            """
            SELECT status,preliminary_decision,attempts,error_message,created_at,started_at,completed_at
            FROM llm_review_jobs WHERE case_id=%s LIMIT 1
            """,
            (case_id,),
        )
        job = normalize_row(cur.fetchone() or {})
        if job:
            llm_review["queue"] = job
            if not llm_review.get("llm_status"):
                llm_review["llm_status"] = job.get("status")

    item: Dict[str, Any] = {
        "case_id": case_id,
        "event_id": str((candidate or attack_event or {}).get("event_id") or event_id),
        "decision": str((candidate or {}).get("decision") or ("attack_event" if attack_event else "candidate")),
        "final_score": (candidate or attack_event or {}).get("final_score")
        if candidate
        else (attack_event or {}).get("confidence"),
        "risk_level": (candidate or attack_event or {}).get("risk_level"),
        "attack_type": normalize_attack_type_label((candidate or attack_event or {}).get("attack_type")),
        "source_ip": (candidate or attack_event or raw_http or {}).get("source_ip"),
        "target_interface": (candidate or attack_event or raw_http or {}).get("target_interface") or (raw_http or {}).get("uri"),
        "evidence": evidence,
        "candidate": normalize_row(candidate) if candidate else None,
        "attack_event": normalize_row(attack_event) if attack_event else None,
        "raw_http": normalize_row(raw_http) if raw_http else None,
        "model_predictions": model_predictions,
        "poc_matches": poc_matches,
        "behavior_windows": behavior_windows,
        "llm_review": llm_review or None,
    }
    if item["candidate"]:
        item["candidate"]["evidence_json"] = None
    if item["attack_event"]:
        item["attack_event"]["evidence_json"] = None
    return item


def normalize_attack_type_label(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "可疑流量"
    t = raw.lower().replace(" ", "").replace("_", "").replace("-", "")

    if any(x in t for x in ["sql", "sqli", "unionselect", "or1=1", "informationschema", "sleep("]):
        return "SQL注入"
    if "sql娉" in t or "sql??" in t:
        return "SQL注入"
    if "xss" in t or "<script" in t:
        return "XSS"
    if "ddos" in t:
        return "DDoS"
    if "ssrf" in t:
        return "SSRF"
    if "rce" in t or "remotecode" in t or "远程代码" in raw:
        return "RCE"
    if any(x in raw for x in ["暴力破解", "爆破", "鏆村姏鐮磋В"]) or "bruteforce" in t:
        return "暴力破解"
    if any(x in raw for x in ["端口扫描", "绔彛鎵弿"]) or "portscan" in t or "nmap" in t:
        return "端口扫描"
    if any(x in raw for x in ["路径遍历", "璺緞閬嶅巻"]) or "traversal" in t:
        return "路径遍历"
    if any(x in raw for x in ["危险文件上传", "危險文件上傳", "鍗遍櫓鏂囦欢涓婁紶"]) or "dangerousfileupload" in t:
        return "危险文件上传"
    if any(x in raw for x in ["文件上传", "鏂囦欢涓婁紶"]) or "upload" in t:
        return "文件上传"
    if any(x in raw for x in ["命令注入", "鍛戒护娉ㄥ叆"]) or "cmd" in t or "commandinject" in t:
        return "命令注入"
    if "xxe" in t or "外部实体" in raw:
        return "XXE"
    if "ssti" in t or "模板注入" in raw:
        return "SSTI"
    if "反序列化" in raw or "deserialization" in t:
        return "反序列化"
    if "graphql" in t:
        return "GraphQL探测"
    return "可疑流量"


def normalize_source_region_label(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "未知"
    mapping = {
        "鍖椾含": "北京",
        "涓婃捣": "上海",
        "骞夸笢": "广东",
        "娴欐睙": "浙江",
        "姹熻嫃": "江苏",
        "灞变笢": "山东",
        "娌冲崡": "河南",
        "鍥涘窛": "四川",
        "棣欐腐": "香港",
        "缇庡浗": "美国",
        "寰峰浗": "德国",
    }
    if raw in mapping:
        return mapping[raw]
    low = raw.lower()
    if low in {"unknown", "n/a", "none", "null", "-", "--"} or "未知" in raw:
        return "未知"
    if "内网" in raw or any(x in low for x in ["private", "loopback", "localhost"]):
        return "内网"
    return raw


CHINA_REGION_ALIASES = {
    "beijing",
    "tianjin",
    "shanghai",
    "chongqing",
    "hebei",
    "shanxi",
    "liaoning",
    "jilin",
    "heilongjiang",
    "jiangsu",
    "zhejiang",
    "anhui",
    "fujian",
    "jiangxi",
    "shandong",
    "henan",
    "hubei",
    "hunan",
    "guangdong",
    "hainan",
    "sichuan",
    "guizhou",
    "yunnan",
    "shaanxi",
    "gansu",
    "qinghai",
    "taiwan",
    "inner mongolia",
    "guangxi",
    "tibet",
    "ningxia",
    "xinjiang",
    "hong kong",
    "macau",
}


def simplify_source_region_for_dashboard(value: Any) -> str:
    region = normalize_source_region_label(value)
    if region in {"未知", "内网"}:
        return region
    parts = [x.strip() for x in re.split(r"[/|,，]+", region) if x.strip()]
    if not parts:
        return "未知"
    first = parts[0]
    first_low = first.lower()
    if first in {"中国", "中华人民共和国"} or first_low in {"china", "cn", "prc", "people's republic of china"}:
        return normalize_source_region_label(parts[1]) if len(parts) > 1 else "中国"
    if (
        first_low in CHINA_REGION_ALIASES
        or first.endswith(("省", "市", "自治区", "特别行政区"))
        or " province" in first_low
        or " autonomous" in first_low
    ):
        return first.replace(" Province", "").replace(" province", "").strip()
    return first


def aggregate_counts_by_label(rows: List[Dict[str, Any]], label_key: str, total_key: str = "total") -> List[Dict[str, Any]]:
    bucket: Dict[str, int] = {}
    for row in rows:
        if label_key == "attack_type":
            label = normalize_attack_type_label(row.get(label_key))
        else:
            label = normalize_source_region_label(row.get(label_key))
        count = int(row.get(total_key) or 0)
        bucket[label] = bucket.get(label, 0) + count
    items = [{label_key: k, total_key: v} for k, v in bucket.items()]
    items.sort(key=lambda x: int(x.get(total_key) or 0), reverse=True)
    return items


def attack_type_aliases(label: str) -> List[str]:
    canonical = normalize_attack_type_label(label)
    aliases = {
        "SQL注入": ["SQL注入", "SQL娉ㄥ叆", "SQL??", "sqli", "sql injection"],
        "XSS": ["XSS", "xss"],
        "暴力破解": ["暴力破解", "鏆村姏鐮磋В", "brute force", "bruteforce"],
        "DDoS": ["DDoS", "ddos"],
        "端口扫描": ["端口扫描", "绔彛鎵弿", "port scan", "nmap"],
        "命令注入": ["命令注入", "鍛戒护娉ㄥ叆", "command injection"],
        "路径遍历": ["路径遍历", "璺緞閬嶅巻", "path traversal"],
        "文件上传": ["文件上传", "鏂囦欢涓婁紶", "file upload"],
        "SSRF": ["SSRF", "ssrf"],
        "RCE": ["RCE", "rce"],
        "可疑流量": ["可疑流量", "鍙枒娴侀噺", "suspicious"],
    }
    return aliases.get(canonical, [canonical])


def visible_attack_event_clause(alias: str = "") -> str:
    prefix = f"{alias}." if alias else ""
    # Older SSH monitor versions wrote one high-risk row per source IP. Keep those
    # records in MySQL, but hide them from default dashboards so web attacks are
    # not drowned out. New SSH aggregate events use the SSHAGG prefix and remain visible.
    return f"NOT ({prefix}event_id LIKE 'SSH%%' AND {prefix}event_id NOT LIKE 'SSHAGG%%')"


def is_public_ip(ip_text: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(str(ip_text))
    except Exception:
        return False
    return bool(ip_obj.is_global)


def _geo_http_get_json(url: str, timeout_sec: float = 2.5) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": "traffic-pipeline/1.0"})
    with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
        charset = "utf-8"
        try:
            charset = resp.headers.get_content_charset() or "utf-8"
        except Exception:
            charset = "utf-8"
        text = resp.read().decode(charset, errors="replace")
    try:
        obj = json.loads(text)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _join_region(country: str, region: str, city: str) -> str:
    c = str(country or "").strip()
    r = str(region or "").strip()
    ct = str(city or "").strip()
    if not c and not r and not ct:
        return "未知"
    if c.lower() in {"cn", "china"} or c == "中国":
        if r and ct:
            return f"{r}/{ct}"
        return r or ct or "中国"
    parts = [x for x in [c, r, ct] if x]
    return "/".join(parts) if parts else "未知"


def fetch_region_remote(ip_text: str) -> str:
    ip_norm = normalize_ip_literal(ip_text)
    if not ip_norm:
        return "未知"
    if not is_public_ip(ip_norm):
        return "内网"

    try:
        data = _geo_http_get_json(f"https://ipwho.is/{ip_norm}")
        if data.get("success") is True:
            return normalize_source_region_label(
                _join_region(data.get("country"), data.get("region"), data.get("city"))
            )
    except Exception:
        pass

    try:
        data = _geo_http_get_json(f"http://ip-api.com/json/{ip_norm}?lang=zh-CN")
        if str(data.get("status", "")).lower() == "success":
            return normalize_source_region_label(
                _join_region(data.get("country"), data.get("regionName"), data.get("city"))
            )
    except Exception:
        pass

    return "未知"


def resolve_region_for_event(conn: Any, source_ip: str, source_region: str = "") -> str:
    ip_norm = normalize_ip_literal(source_ip)
    current = normalize_source_region_label(source_region)
    if current not in {"未知", "TEST"}:
        return current
    if not ip_norm:
        return "未知"
    if not is_public_ip(ip_norm):
        return "内网"

    with conn.cursor() as cur:
        cur.execute("SELECT region FROM ip_geo_cache WHERE ip=%s LIMIT 1", (ip_norm,))
        row = cur.fetchone() or {}
    cached = normalize_source_region_label(row.get("region"))
    if cached != "未知":
        return cached

    region = fetch_region_remote(ip_norm)
    source = "remote" if region not in {"未知", "内网"} else "fallback"
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ip_geo_cache(ip, region, source)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE
              region=VALUES(region),
              source=VALUES(source),
              updated_at=CURRENT_TIMESTAMP
            """,
            (ip_norm, region, source),
        )
    return region


def _read_windows_cpu_percent() -> Optional[float]:
    candidates = [
        ["wmic", "cpu", "get", "loadpercentage", "/value"],
        ["powershell", "-NoProfile", "-Command", "(Get-Counter '\\Processor(_Total)\\% Processor Time').CounterSamples[0].CookedValue"],
    ]
    for cmd in candidates:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=4,
            )
        except Exception:
            continue
        text = f"{result.stdout or ''}\n{result.stderr or ''}".strip()
        if not text:
            continue
        m = re.search(r"([0-9]+(?:\.[0-9]+)?)", text)
        if m:
            try:
                return round(float(m.group(1)), 2)
            except Exception:
                continue
    return None


def _read_cpu_percent_cached(max_age_seconds: float = 1.0) -> Optional[float]:
    """Return a real short-window CPU sample without slowing every API call."""
    if psutil is None:
        return _read_windows_cpu_percent() if os.name == "nt" else None

    now_mono = time.monotonic()
    cached = _CPU_SAMPLE_CACHE.get("value")
    sampled_at = float(_CPU_SAMPLE_CACHE.get("sampled_at") or 0.0)
    if cached is not None and now_mono - sampled_at <= max_age_seconds:
        return float(cached)

    with _CPU_SAMPLE_LOCK:
        now_mono = time.monotonic()
        cached = _CPU_SAMPLE_CACHE.get("value")
        sampled_at = float(_CPU_SAMPLE_CACHE.get("sampled_at") or 0.0)
        if cached is not None and now_mono - sampled_at <= max_age_seconds:
            return float(cached)
        try:
            # interval=None can return a meaningless 0.0 on the first call.
            value = round(float(psutil.cpu_percent(interval=0.15)), 2)
        except Exception:
            value = _read_windows_cpu_percent() if os.name == "nt" else None
        if value is not None:
            _CPU_SAMPLE_CACHE["value"] = value
            _CPU_SAMPLE_CACHE["sampled_at"] = time.monotonic()
        return value


def _read_windows_memory_status() -> Tuple[int, int]:
    try:
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        statex = MEMORYSTATUSEX()
        statex.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(statex)):  # type: ignore[attr-defined]
            return int(statex.ullTotalPhys), int(statex.ullAvailPhys)
    except Exception:
        pass
    return 0, 0


def _read_uptime_seconds_fallback() -> Optional[int]:
    if os.name == "nt":
        try:
            import ctypes

            ms = int(ctypes.windll.kernel32.GetTickCount64())  # type: ignore[attr-defined]
            return int(ms / 1000)
        except Exception:
            return None
    return None


def collect_local_system_status() -> Dict[str, Any]:
    now = now_dt()
    host = socket.gethostname()
    os_name = f"{platform.system()} {platform.release()}".strip()
    local_ip = ""
    try:
        # The address selected by the default route represents the NIC that
        # actually carries protected traffic; hostname lookup often returns a
        # VirtualBox/Hyper-V host-only adapter on Windows servers.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route_probe:
            route_probe.connect(("1.1.1.1", 80))
            local_ip = str(route_probe.getsockname()[0])
    except Exception:
        try:
            local_ip = socket.gethostbyname(host)
        except Exception:
            local_ip = ""

    cpu_percent: Optional[float] = None
    mem_total = mem_used = mem_free = 0
    uptime_seconds: Optional[int] = None

    if psutil is not None:
        cpu_percent = _read_cpu_percent_cached()
        try:
            vm = psutil.virtual_memory()
            mem_total = int(vm.total)
            mem_free = int(vm.available)
            mem_used = int(vm.total - vm.available)
        except Exception:
            pass
        try:
            uptime_seconds = int(max(0, now.timestamp() - float(psutil.boot_time())))
        except Exception:
            uptime_seconds = None
    else:
        if os.name == "nt":
            cpu_percent = _read_windows_cpu_percent()
            total, free = _read_windows_memory_status()
            mem_total = int(total)
            mem_free = int(free)
            mem_used = max(0, mem_total - mem_free)
            uptime_seconds = _read_uptime_seconds_fallback()

    disk_anchor = str(Path.cwd().anchor or "/")
    disk_total = disk_used = disk_free = 0
    try:
        usage = shutil.disk_usage(disk_anchor)
        disk_total = int(usage.total)
        disk_used = int(usage.used)
        disk_free = int(usage.free)
    except Exception:
        pass

    def _pct(used: int, total: int) -> float:
        return 0.0 if total <= 0 else round((used / total) * 100.0, 2)

    return {
        "hostname": host,
        "local_ip": local_ip,
        "os": os_name,
        "collected_at": dt_to_str(now, ms=True),
        "uptime_seconds": uptime_seconds,
        "uptime_hours": None if uptime_seconds is None else round(uptime_seconds / 3600.0, 2),
        "cpu_percent": cpu_percent,
        "memory": {
            "total_bytes": mem_total,
            "used_bytes": mem_used,
            "free_bytes": mem_free,
            "used_percent": _pct(mem_used, mem_total),
        },
        "disk": {
            "path": disk_anchor,
            "total_bytes": disk_total,
            "used_bytes": disk_used,
            "free_bytes": disk_free,
            "used_percent": _pct(disk_used, disk_total),
        },
    }


def normalize_ip_for_rule(ip_text: str) -> str:
    value = str(ip_text or "").strip()
    return re.sub(r"[^A-Za-z0-9_.:-]", "_", value)


def firewall_rule_names(ip_text: str) -> Tuple[str, str]:
    suffix = normalize_ip_for_rule(ip_text)
    return (f"TP_BLOCK_IP_IN_{suffix}", f"TP_BLOCK_IP_OUT_{suffix}")


def run_netsh(args: List[str]) -> Tuple[bool, str, str]:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=12,
        )
    except Exception as exc:
        return False, "", str(exc)
    ok = result.returncode == 0
    return ok, result.stdout or "", result.stderr or ""


def ps_quote(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def run_powershell(command: str) -> Tuple[bool, str, str]:
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
    except Exception as exc:
        return False, "", str(exc)
    return result.returncode == 0, result.stdout or "", result.stderr or ""


def firewall_delete_rule(rule_name: str) -> Tuple[bool, str]:
    ok1, out1, err1 = run_netsh(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
    ps_cmd = (
        f"$r = Get-NetFirewallRule -Name {ps_quote(rule_name)} -ErrorAction SilentlyContinue; "
        "if ($r) { $r | Remove-NetFirewallRule -ErrorAction Stop }; "
        "Write-Output 'deleted_or_missing'"
    )
    ok2, out2, err2 = run_powershell(ps_cmd)
    text = f"{out1}\n{err1}\n{out2}\n{err2}"
    return ok1 or ok2 or "no rules match" in text.lower() or "deleted_or_missing" in text, text.strip()


def firewall_create_rule(rule_name: str, direction: str, ip_val: str) -> Tuple[bool, str]:
    dir_arg = "in" if direction == "in" else "out"
    ps_direction = "Inbound" if direction == "in" else "Outbound"
    ok1, out1, err1 = run_netsh(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            f"dir={dir_arg}",
            "action=block",
            f"remoteip={ip_val}",
            "enable=yes",
            "profile=any",
        ]
    )
    if ok1:
        return True, out1 or err1
    ps_cmd = (
        f"New-NetFirewallRule -Name {ps_quote(rule_name)} "
        f"-DisplayName {ps_quote(rule_name)} "
        f"-Direction {ps_direction} -Action Block "
        f"-RemoteAddress {ps_quote(ip_val)} -Profile Any -Enabled True "
        "-ErrorAction Stop | Out-Null; Write-Output 'created'"
    )
    ok2, out2, err2 = run_powershell(ps_cmd)
    return ok2, f"netsh: {out1 or err1}; powershell: {out2 or err2}".strip()


def firewall_block_ip(ip_text: str) -> Tuple[bool, str]:
    return verified_firewall_block_ip(ip_text)


def firewall_unblock_ip(ip_text: str) -> Tuple[bool, str]:
    return verified_firewall_unblock_ip(ip_text)


def normalize_ip_literal(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except Exception:
        return ""


def normalize_host_text(text: str) -> str:
    raw = str(text or "").strip()
    if not raw:
        return ""
    host = raw
    if "://" in host:
        host = urllib.parse.urlsplit(host).hostname or host
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if ":" in host and host.count(":") == 1:
        left, right = host.rsplit(":", 1)
        if right.isdigit():
            host = left
    return host.strip().lower()


def extract_host_candidates(request_log: str) -> List[str]:
    text = str(request_log or "")
    hosts: List[str] = []
    for pat in [r"(?mi)^HOST=([^\r\n]+)", r"(?mi)^Host:\s*([^\r\n]+)"]:
        for m in re.finditer(pat, text):
            host = normalize_host_text(m.group(1))
            if host and host not in hosts:
                hosts.append(host)
    return hosts


def resolve_host_ips(host: str) -> List[str]:
    target = normalize_host_text(host)
    if not target:
        return []
    out: List[str] = []
    try:
        infos = socket.getaddrinfo(target, None)
    except Exception:
        return []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_text = normalize_ip_literal(sockaddr[0])
        if ip_text and ip_text not in out:
            out.append(ip_text)
    return out


def collect_event_block_ips(
    cur: Any, event_id: str, source_ip: str, request_log: str, block_mode: str = "source"
) -> Tuple[List[str], Dict[str, Any]]:
    mode = str(block_mode or "source").strip().lower()
    if mode not in {"source", "target", "both"}:
        mode = "source"
    ips: List[str] = []

    source_candidates: List[str] = []
    first_source = normalize_ip_literal(source_ip)
    if first_source:
        source_candidates.append(first_source)

    for pat in [r"(?mi)^src_ip=([^\r\n]+)", r"(?mi)\bsrc(?:_| )?ip[:=]\s*([0-9a-fA-F:.]+)"]:
        for m in re.finditer(pat, str(request_log or "")):
            src = normalize_ip_literal(m.group(1))
            if src and src not in source_candidates:
                source_candidates.append(src)
    for m in re.finditer(r"((?:\d{1,3}\.){3}\d{1,3})\s*->", str(request_log or "")):
        src = normalize_ip_literal(m.group(1))
        if src and src not in source_candidates:
            source_candidates.append(src)

    destination_ip_norm = ""
    cur.execute("SELECT source_ip, attack_ip, destination_ip FROM analyses WHERE case_id=%s LIMIT 1", (event_id,))
    ana = cur.fetchone() or {}
    for v in [ana.get("source_ip"), ana.get("attack_ip")]:
        src = normalize_ip_literal(v)
        if src and src not in source_candidates:
            source_candidates.append(src)
    destination_ip_norm = normalize_ip_literal(ana.get("destination_ip"))
    if mode in {"source", "both"}:
        for src in source_candidates:
            if src not in ips:
                ips.append(src)
    if destination_ip_norm and mode in {"target", "both"} and destination_ip_norm not in ips:
        ips.append(destination_ip_norm)

    host_candidates = extract_host_candidates(request_log)
    host_resolved: Dict[str, List[str]] = {}
    if mode in {"target", "both"}:
        for host in host_candidates:
            rs = resolve_host_ips(host)
            if rs:
                host_resolved[host] = rs
            for ip_text in rs:
                if ip_text not in ips:
                    ips.append(ip_text)

    meta = {
        "mode": mode,
        "source_ip": source_candidates[0] if source_candidates else "",
        "source_candidates": source_candidates,
        "destination_ip": destination_ip_norm,
        "hosts": host_candidates,
        "host_resolved": host_resolved,
    }
    return ips, meta


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


def rag_get_doc(rag_db_path: str, doc_id: str) -> Optional[Dict[str, Any]]:
    with closing(get_rag_conn(rag_db_path)) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT rowid, doc_id, title, tags, attack_type, content, evidence, mitigation, severity, source
            FROM rag_docs
            WHERE doc_id=?
            LIMIT 1
            """,
            (doc_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None


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


def load_system_config_map(conn: Any) -> Dict[str, str]:
    with conn.cursor() as cur:
        cur.execute("SELECT config_key, config_value FROM demo_system_config")
        rows = cur.fetchall()
    return {str(x.get("config_key", "")).strip(): str(x.get("config_value", "")).strip() for x in rows}


def normalize_homepage_background_url(value: str) -> str:
    url = str(value or "").strip()
    if not url or not url.startswith("/") or url.startswith("//") or "\\" in url or '"' in url:
        return DEFAULT_HOMEPAGE_BACKGROUND
    return url[:240]


def detect_background_extension(filename: str, content_type: str, data: bytes) -> str:
    suffix = Path(filename or "").suffix.lower().lstrip(".")
    if suffix == "jpeg":
        suffix = "jpg"
    content_type = str(content_type or "").lower()
    if suffix not in ALLOWED_BACKGROUND_EXTENSIONS:
        if "png" in content_type:
            suffix = "png"
        elif "webp" in content_type:
            suffix = "webp"
        elif "jpeg" in content_type or "jpg" in content_type:
            suffix = "jpg"
    if suffix not in ALLOWED_BACKGROUND_EXTENSIONS:
        return ""
    if suffix == "png" and data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if suffix == "jpg" and data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if suffix == "webp" and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "webp"
    return ""


def normalize_ollama_url(raw_url: str) -> str:
    text = str(raw_url or "").strip()
    if not text:
        return "http://127.0.0.1:11434"
    return text.rstrip("/")


def list_ollama_models(ollama_url: str, timeout: int = 5) -> Dict[str, Any]:
    base = normalize_ollama_url(ollama_url)
    endpoint = f"{base}/api/tags"
    req = urllib.request.Request(endpoint, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(body or "{}")
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "models": [], "error": str(exc), "ollama_url": base}

    raw_models = data.get("models", [])
    items: List[Dict[str, Any]] = []
    seen = set()
    if isinstance(raw_models, list):
        for row in raw_models:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name", "")).strip()
            if not name or name in seen:
                continue
            seen.add(name)
            items.append(
                {
                    "name": name,
                    "size": int(row.get("size") or 0),
                    "modified_at": str(row.get("modified_at") or ""),
                }
            )
    items.sort(key=lambda x: x["name"])
    return {"ok": True, "models": items, "error": "", "ollama_url": base}


def resolve_legacy_model_artifacts() -> Tuple[Path, Path]:
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent
    local_models = project_root / "models"
    local_pre = local_models / "preprocessor.joblib"
    local_mdl = local_models / "best_mlp.pth"
    if local_pre.exists() and local_mdl.exists():
        return local_pre, local_mdl
    fallback_models = project_root.parent / "traffic_mlp" / "models"
    return fallback_models / "preprocessor.joblib", fallback_models / "best_mlp.pth"


def list_tshark_interfaces(timeout: int = 12) -> Dict[str, Any]:
    tshark_path = shutil.which("tshark")
    if not tshark_path:
        return {"ok": False, "path": "", "items": [], "error": "tshark_not_found"}
    try:
        result = subprocess.run(
            [tshark_path, "-D"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "path": tshark_path, "items": [], "error": str(exc)}
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        return {"ok": False, "path": tshark_path, "items": [], "error": detail or f"returncode={result.returncode}"}

    items: List[Dict[str, str]] = []
    for raw_line in (result.stdout or "").splitlines():
        line = str(raw_line or "").strip()
        if not line:
            continue
        m = re.match(r"^(\d+)\.\s+(.+)$", line)
        if not m:
            continue
        items.append({"index": m.group(1), "name": m.group(2), "raw": line})
    return {"ok": True, "path": tshark_path, "items": items, "error": ""}


def resolve_capture_interface(
    configured_interface: str,
    interface_items: List[Dict[str, str]],
) -> Tuple[str, str]:
    cfg = str(configured_interface or "").strip()
    if not interface_items:
        return "", ""
    if not cfg or cfg.lower() in {"auto", "default", "自动"}:
        return str(interface_items[0].get("index", "")).strip(), str(interface_items[0].get("name", "")).strip()

    for row in interface_items:
        idx = str(row.get("index", "")).strip()
        if cfg == idx:
            return idx, str(row.get("name", "")).strip()

    cfg_lower = cfg.lower()
    for row in interface_items:
        raw = str(row.get("raw", "")).lower()
        if cfg_lower and cfg_lower in raw:
            return str(row.get("index", "")).strip(), str(row.get("name", "")).strip()

    return "", ""


def probe_capture_on_interface(interface_index: str, monitor_ports: str, timeout: int = 10) -> Dict[str, Any]:
    tshark_path = shutil.which("tshark")
    if not tshark_path:
        return {"ok": False, "error": "tshark_not_found", "detail": ""}
    iface = str(interface_index or "").strip()
    if not iface:
        return {"ok": False, "error": "empty_interface", "detail": ""}

    cmd = [tshark_path, "-i", iface, "-a", "duration:1", "-Q", "-c", "1"]
    raw_parts = [x for x in re.split(r"[\s,]+", str(monitor_ports or "").strip()) if x]
    ports: List[str] = [x for x in raw_parts if x.isdigit() and 1 <= int(x) <= 65535][:6]
    if ports:
        expr = " or ".join(f"tcp port {p}" for p in ports)
        cmd.extend(["-f", expr])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": "probe_exception", "detail": str(exc), "cmd": cmd}

    mix = f"{result.stdout or ''}\n{result.stderr or ''}".lower()
    if result.returncode == 0:
        return {"ok": True, "error": "", "detail": "短时抓包探测成功", "cmd": cmd}
    if any(
        token in mix
        for token in [
            "permission",
            "you don't have permission",
            "access is denied",
            "could not be initiated",
            "cannot open adapter",
        ]
    ):
        return {
            "ok": False,
            "error": "permission_denied",
            "detail": "抓包权限不足，请使用管理员权限运行 app.py 或检查 Npcap AdminOnly",
            "cmd": cmd,
        }
    detail = (result.stderr or result.stdout or "").strip()
    return {"ok": False, "error": f"probe_failed_rc_{result.returncode}", "detail": detail, "cmd": cmd}


def ensure_schema(conn: Any) -> None:
    ddl_list = [
        """
        CREATE TABLE IF NOT EXISTS demo_users (
          id INT AUTO_INCREMENT PRIMARY KEY,
          username VARCHAR(64) NOT NULL UNIQUE,
          password VARCHAR(128) NOT NULL,
          role VARCHAR(16) NOT NULL,
          display_name VARCHAR(64) NOT NULL,
          nickname VARCHAR(64) NOT NULL DEFAULT '',
          avatar_url VARCHAR(512) NOT NULL DEFAULT '',
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
          target_port INT NULL,
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
        CREATE TABLE IF NOT EXISTS ip_geo_cache (
          ip VARCHAR(64) PRIMARY KEY,
          region VARCHAR(128) NOT NULL,
          source VARCHAR(32) NOT NULL DEFAULT 'fallback',
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
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
        CREATE TABLE IF NOT EXISTS demo_blocked_ips (
          id BIGINT AUTO_INCREMENT PRIMARY KEY,
          ip_address VARCHAR(64) NOT NULL UNIQUE,
          source_event_id VARCHAR(40) NOT NULL DEFAULT '',
          reason VARCHAR(255) NOT NULL DEFAULT '',
          blocked_by VARCHAR(64) NOT NULL DEFAULT '',
          blocked_role VARCHAR(16) NOT NULL DEFAULT '',
          defense_latency_ms DOUBLE NULL,
          blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          KEY idx_blocked_at (blocked_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """,
        """
        CREATE TABLE IF NOT EXISTS demo_auto_defense_releases (
          ip_address VARCHAR(64) PRIMARY KEY,
          released_action_at DATETIME(3) NULL,
          released_by VARCHAR(64) NOT NULL DEFAULT '',
          released_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """,
        """
        CREATE TABLE IF NOT EXISTS demo_fast_defense_audit (
          id BIGINT AUTO_INCREMENT PRIMARY KEY,
          request_fingerprint CHAR(64) NOT NULL,
          source_ip VARCHAR(64) NOT NULL,
          destination_ip VARCHAR(64) NOT NULL DEFAULT '',
          method VARCHAR(16) NOT NULL DEFAULT '',
          uri TEXT NOT NULL,
          category VARCHAR(64) NOT NULL,
          score INT NOT NULL,
          rule_ids_json TEXT NOT NULL,
          decision VARCHAR(32) NOT NULL,
          firewall_success TINYINT(1) NOT NULL DEFAULT 0,
          firewall_detail TEXT NOT NULL,
          defense_latency_ms DOUBLE NULL,
          request_time DATETIME(3) NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          KEY idx_fast_ip_time (source_ip, created_at),
          KEY idx_fast_category_time (category, created_at)
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
        if not db_column_exists(cur, "demo_users", "nickname"):
            cur.execute("ALTER TABLE demo_users ADD COLUMN nickname VARCHAR(64) NOT NULL DEFAULT '' AFTER display_name")
        if not db_column_exists(cur, "demo_users", "avatar_url"):
            cur.execute("ALTER TABLE demo_users ADD COLUMN avatar_url VARCHAR(512) NOT NULL DEFAULT '' AFTER nickname")
        if not db_column_exists(cur, "demo_blocked_ips", "defense_latency_ms"):
            cur.execute("ALTER TABLE demo_blocked_ips ADD COLUMN defense_latency_ms DOUBLE NULL AFTER blocked_role")
        if not db_column_exists(cur, "demo_fast_defense_audit", "defense_latency_ms"):
            cur.execute(
                "ALTER TABLE demo_fast_defense_audit ADD COLUMN defense_latency_ms DOUBLE NULL AFTER firewall_detail"
            )
        if not db_column_exists(cur, "demo_attack_events", "target_port"):
            cur.execute("ALTER TABLE demo_attack_events ADD COLUMN target_port INT NULL AFTER target_node")
        cur.execute(
            """
            UPDATE demo_users
            SET nickname=display_name
            WHERE (nickname IS NULL OR nickname='')
            """
        )


def log_action(conn: Any, username: str, role: str, action: str, target: str, detail: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO demo_user_action_logs(username, role, action, target, detail)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (username, role, action, target, detail),
        )


def record_auto_defense_release(cur: Any, ip_address: str, username: str) -> None:
    """Prevent old situation evidence from immediately undoing a manual release."""
    cur.execute(
        """
        INSERT INTO demo_auto_defense_releases(ip_address, released_action_at, released_by)
        SELECT %s, MAX(last_action_at), %s
        FROM attack_situations
        WHERE source_ip=%s
        ON DUPLICATE KEY UPDATE
          released_action_at=VALUES(released_action_at),
          released_by=VALUES(released_by),
          released_at=CURRENT_TIMESTAMP
        """,
        (ip_address, username, ip_address),
    )


def seed_demo_data(conn: Any, force_seed: bool = False) -> None:
    with conn.cursor() as cur:
        for row in DEMO_SEED_USERS:
            if force_seed:
                cur.execute(
                    """
                    INSERT INTO demo_users(username, password, role, display_name, nickname)
                    VALUES (%s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                      password=VALUES(password),
                      role=VALUES(role),
                      display_name=VALUES(display_name),
                      nickname=CASE WHEN nickname='' THEN VALUES(nickname) ELSE nickname END
                    """,
                    (row["username"], row["password"], row["role"], row["display_name"], row["display_name"]),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO demo_users(username, password, role, display_name, nickname)
                    VALUES (%s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                      role=VALUES(role),
                      display_name=VALUES(display_name),
                      nickname=CASE WHEN nickname='' THEN VALUES(nickname) ELSE nickname END
                    """,
                    (row["username"], row["password"], row["role"], row["display_name"], row["display_name"]),
                )
        cur.execute(
            """
            UPDATE demo_users
            SET role=%s
            WHERE role NOT IN (%s, %s)
            """,
            (ROLE_NORMAL, ROLE_NORMAL, ROLE_ADMIN),
        )

        defaults = {
            "alert_threshold_high": "10",
            "auto_refresh_seconds": "5",
            "sound_alert_enabled": "1",
            "capture_batch_size": "4",
            "monitor_ports": "80,443,8080",
            "capture_interface": "auto",
            "llm_model": "qwen3:8b",
            "rag_enabled": "1",
            "llm_realtime_enabled": "1",
            "situation_minimum_actions": "3",
            "situation_window_minutes": "30",
            "situation_inactivity_minutes": "15",
            "scan_port_threshold": "10",
            "scan_window_seconds": "60",
            "proxy_cluster_window_minutes": "60",
            "auto_defense_enabled": "0",
            "auto_defense_min_risk": "critical",
            "auto_defense_allow_private": "0",
            "homepage_background_url": DEFAULT_HOMEPAGE_BACKGROUND,
        }
        for k, v in defaults.items():
            cur.execute(
                """
                INSERT INTO demo_system_config(config_key, config_value)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE config_value=config_value
                """,
                (k, v),
            )

        system = collect_local_system_status()
        machine_name = str(system.get("hostname") or socket.gethostname() or "local-server")[:64]
        ip_addr = str(system.get("local_ip") or "127.0.0.1")[:64]
        cpu_usage = float(system.get("cpu_percent") or 0)
        memory_usage = float((system.get("memory") or {}).get("used_percent") or 0)
        cur.execute(
            """
            INSERT INTO demo_machines(machine_name, ip_address, deploy_location, online_status, cpu_usage, memory_usage, gpu_usage, model_status)
            VALUES (%s, %s, '本机服务器', 'online', %s, %s, 0, 'running')
            ON DUPLICATE KEY UPDATE
              ip_address=VALUES(ip_address), deploy_location=VALUES(deploy_location),
              online_status='online', cpu_usage=VALUES(cpu_usage), memory_usage=VALUES(memory_usage), gpu_usage=0
            """,
            (machine_name, ip_addr, cpu_usage, memory_usage),
        )
        cur.execute("SELECT id FROM demo_machines WHERE machine_name=%s LIMIT 1", (machine_name,))
        local_machine_id = int((cur.fetchone() or {}).get("id") or 0)
        if local_machine_id:
            cur.execute(
                "UPDATE demo_attack_events SET machine_id=%s, target_node=%s",
                (local_machine_id, machine_name),
            )
            cur.execute("DELETE FROM demo_machines WHERE id<>%s", (local_machine_id,))

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


def ensure_builtin_admin(conn: Any) -> None:
    # Keep a deterministic bootstrap admin account for first login/recovery.
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO demo_users(username, password, role, display_name, nickname)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
              password=VALUES(password),
              role=VALUES(role),
              display_name=VALUES(display_name),
              nickname=CASE WHEN nickname='' THEN VALUES(nickname) ELSE nickname END
            """,
            ("admin", "admin", ROLE_ADMIN, "管理员", "管理员"),
        )


def demo_payload_by_type(attack_type: str) -> str:
    attack_type = normalize_attack_type_label(attack_type)
    mapping = {
        "SQL注入": "username=admin' OR 1=1 --",
        "XSS": "<script>alert('xss')</script>",
        "暴力破解": "POST /login retry=120 user=admin",
        "DDoS": "High frequency requests burst detected",
        "端口扫描": "SYN scan to 22,80,443,3306",
        "命令注入": "cmd=ping 127.0.0.1 && whoami",
        "路径遍历": "../../etc/passwd",
        "文件上传": "multipart payload with executable signature",
        "SSRF": "url=http://169.254.169.254/latest/meta-data",
        "RCE": "template={{7*7}} runtime command chain",
    }
    return mapping.get(attack_type, "suspicious payload")


def refresh_machine_stats(conn: Any) -> None:
    visible_sql = visible_attack_event_clause()
    system = collect_local_system_status()
    machine_name = str(system.get("hostname") or socket.gethostname() or "local-server")[:64]
    ip_addr = str(system.get("local_ip") or "127.0.0.1")[:64]
    cpu_usage = float(system.get("cpu_percent") or 0)
    memory_usage = float((system.get("memory") or {}).get("used_percent") or 0)
    with conn.cursor() as cur:
        cur.execute(
            f"""
            UPDATE demo_machines
            SET machine_name=%s, ip_address=%s, deploy_location='本机服务器', online_status='online',
                today_attack_count=(SELECT COUNT(*) FROM demo_attack_events WHERE DATE(occurred_at)=CURDATE() AND {visible_sql}),
                current_alert_count=(SELECT COUNT(*) FROM demo_attack_events WHERE DATE(occurred_at)=CURDATE() AND risk_level IN ('critical','high') AND process_status IN ('unprocessed','processing') AND {visible_sql}),
                last_heartbeat=NOW(), cpu_usage=%s, memory_usage=%s, gpu_usage=0
            """
            , (machine_name, ip_addr, cpu_usage, memory_usage)
        )


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(raw: str) -> bytes:
    padding = "=" * ((4 - len(raw) % 4) % 4)
    return base64.urlsafe_b64decode((raw + padding).encode("ascii"))


def _jwt_signing_input(header: Dict[str, Any], payload: Dict[str, Any]) -> str:
    header_seg = _b64url_encode(json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    payload_seg = _b64url_encode(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    return f"{header_seg}.{payload_seg}"


def _jwt_sign(signing_input: str, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return _b64url_encode(digest)


def create_jwt_token(user_row: Dict[str, Any], secret: str, ttl_seconds: int = TOKEN_TTL_SECONDS) -> str:
    now_ts = int(now_dt().timestamp())
    exp_ts = now_ts + max(60, int(ttl_seconds))
    payload = {
        "sub": str(user_row.get("username") or ""),
        "role": str(user_row.get("role") or ""),
        "display_name": str(user_row.get("display_name") or ""),
        "nickname": str(user_row.get("nickname") or user_row.get("display_name") or ""),
        "avatar_url": str(user_row.get("avatar_url") or ""),
        "iat": now_ts,
        "exp": exp_ts,
        "jti": uuid.uuid4().hex,
    }
    signing_input = _jwt_signing_input(JWT_HEADER, payload)
    return f"{signing_input}.{_jwt_sign(signing_input, secret)}"


def decode_jwt_token(token: str, secret: str) -> Tuple[Optional[Dict[str, Any]], str]:
    parts = token.split(".")
    if len(parts) != 3:
        return None, "token_malformed"
    header_seg, payload_seg, sign_seg = parts
    try:
        header = json.loads(_b64url_decode(header_seg).decode("utf-8"))
        payload = json.loads(_b64url_decode(payload_seg).decode("utf-8"))
    except Exception:
        return None, "token_malformed"
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None, "token_malformed"
    if str(header.get("alg") or "") != JWT_ALGORITHM:
        return None, "unsupported_alg"
    expected_sign = _jwt_sign(f"{header_seg}.{payload_seg}", secret)
    if not hmac.compare_digest(expected_sign, sign_seg):
        return None, "bad_signature"
    try:
        exp_ts = int(payload.get("exp") or 0)
        iat_ts = int(payload.get("iat") or 0)
    except Exception:
        return None, "invalid_claims"
    now_ts = int(now_dt().timestamp())
    if exp_ts <= now_ts:
        return None, "token_expired"
    if iat_ts > now_ts + 300:
        return None, "token_not_yet_valid"
    if not str(payload.get("sub") or "") or not str(payload.get("role") or ""):
        return None, "invalid_claims"
    return payload, ""


def read_jwt_exp_unverified(token: str) -> Optional[int]:
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return None
    try:
        payload_raw = _b64url_decode(parts[1]).decode("utf-8")
        payload = json.loads(payload_raw)
        if not isinstance(payload, dict):
            return None
        exp_ts = payload.get("exp")
        if exp_ts is None:
            return None
        return int(exp_ts)
    except Exception:
        return None


def prune_revoked_jtis() -> None:
    now_ts = int(now_dt().timestamp())
    expired = [k for k, exp in JWT_REVOKED_JTIS.items() if exp <= now_ts]
    for key in expired:
        JWT_REVOKED_JTIS.pop(key, None)


def revoke_jwt(payload: Dict[str, Any]) -> None:
    try:
        exp_ts = int(payload.get("exp") or 0)
    except Exception:
        exp_ts = 0
    jti = str(payload.get("jti") or "").strip()
    if jti and exp_ts > 0:
        JWT_REVOKED_JTIS[jti] = exp_ts


def is_jwt_revoked(payload: Dict[str, Any]) -> bool:
    prune_revoked_jtis()
    jti = str(payload.get("jti") or "").strip()
    if not jti:
        return False
    return jti in JWT_REVOKED_JTIS


def build_session_from_claims(payload: Dict[str, Any]) -> Dict[str, Any]:
    exp_ts = int(payload.get("exp") or 0)
    expires_at = datetime.fromtimestamp(exp_ts) if exp_ts > 0 else now_dt()
    return {
        "username": str(payload.get("sub") or ""),
        "role": str(payload.get("role") or ""),
        "display_name": str(payload.get("display_name") or ""),
        "nickname": str(payload.get("nickname") or payload.get("display_name") or ""),
        "avatar_url": normalize_avatar_url(payload.get("avatar_url") or ""),
        "expires_at": expires_at,
    }


def is_valid_username(username: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,32}", username))


def normalize_profile_text(value: Any, fallback: str = "", max_len: int = 64) -> str:
    text = re.sub(r"\s+", " ", str(value or "").strip())
    if not text:
        text = fallback
    return text[:max_len]


def normalize_avatar_url(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) > 512 or any(x in text for x in ['"', "'", "\\", "\r", "\n"]):
        return ""
    if text.startswith("/uploads/avatars/"):
        return text
    if text.startswith("https://") or text.startswith("http://"):
        return text
    return ""


def profile_public_fields(row: Dict[str, Any]) -> Dict[str, Any]:
    display_name = str(row.get("display_name") or row.get("username") or "")
    nickname = str(row.get("nickname") or display_name)
    avatar_url = normalize_avatar_url(row.get("avatar_url") or "")
    return {
        "id": row.get("id"),
        "username": str(row.get("username") or ""),
        "role": str(row.get("role") or ""),
        "display_name": display_name,
        "nickname": nickname,
        "avatar_url": avatar_url,
    }


def get_auth_token_from_request() -> str:
    auth_header = request.headers.get("Authorization", "").strip()
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        if token:
            return token
    cookie_name = str(current_app.config.get("AUTH_COOKIE_NAME") or AUTH_COOKIE_NAME).strip() or AUTH_COOKIE_NAME
    cookie_token = str(request.cookies.get(cookie_name, "")).strip()
    if cookie_token:
        return cookie_token
    return ""


def set_auth_cookie(resp: Response, token: str) -> Response:
    cookie_name = str(current_app.config.get("AUTH_COOKIE_NAME") or AUTH_COOKIE_NAME).strip() or AUTH_COOKIE_NAME
    cookie_secure = bool(current_app.config.get("AUTH_COOKIE_SECURE", False))
    cookie_domain = str(current_app.config.get("AUTH_COOKIE_DOMAIN") or "").strip() or None
    max_age = int(current_app.config.get("JWT_TTL_SECONDS") or TOKEN_TTL_SECONDS)
    resp.set_cookie(
        cookie_name,
        token,
        max_age=max_age,
        httponly=True,
        secure=cookie_secure,
        samesite="Lax",
        path="/",
        domain=cookie_domain,
    )
    return resp


def clear_auth_cookie(resp: Response) -> Response:
    cookie_name = str(current_app.config.get("AUTH_COOKIE_NAME") or AUTH_COOKIE_NAME).strip() or AUTH_COOKIE_NAME
    cookie_secure = bool(current_app.config.get("AUTH_COOKIE_SECURE", False))
    cookie_domain = str(current_app.config.get("AUTH_COOKIE_DOMAIN") or "").strip() or None
    resp.set_cookie(
        cookie_name,
        "",
        max_age=0,
        expires=0,
        httponly=True,
        secure=cookie_secure,
        samesite="Lax",
        path="/",
        domain=cookie_domain,
    )
    return resp


def require_roles(*roles: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            token = get_auth_token_from_request()
            if not token:
                return jsonify({"error": "unauthorized", "message": "Missing auth token"}), 401
            jwt_secret = str(current_app.config.get("JWT_SECRET") or "").strip()
            if not jwt_secret:
                return jsonify({"error": "server_error", "message": "JWT secret not configured"}), 500
            claims, err = decode_jwt_token(token, jwt_secret)
            if not claims:
                return jsonify({"error": "unauthorized", "message": err or "Invalid token"}), 401
            if is_jwt_revoked(claims):
                return jsonify({"error": "unauthorized", "message": "Token revoked"}), 401
            session = build_session_from_claims(claims)
            if roles and session["role"] not in set(roles):
                return jsonify({"error": "forbidden", "message": "Role not allowed"}), 403
            g.session = session
            g.token_claims = claims
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
    jwt_secret: str = "",
    jwt_ttl_seconds: int = TOKEN_TTL_SECONDS,
    ollama_url: str = "http://127.0.0.1:11434",
    llm_prompt_path: str = "llm/prompts/system_prompt.txt",
    professional_report_prompt_path: str = "llm/prompts/professional_situation_report_prompt.txt",
    rag_data_dir: str = "",
    rag_api_config: str = "config/ai_api.local.json",
) -> Flask:
    app = Flask(__name__)
    app.url_map.strict_slashes = False
    app.config["MYSQL_CONF"] = mysql_conf
    app.config["RAG_DB_PATH"] = str(Path(rag_db_path).resolve())
    app.config["RAG_SEED_PATH"] = str(Path(rag_seed_path).resolve())
    app.config["OLLAMA_URL"] = normalize_ollama_url(ollama_url)
    app.config["LLM_PROMPT_PATH"] = str(resolve_project_path(llm_prompt_path, DEFAULT_LLM_PROMPT_PATH))
    app.config["PROFESSIONAL_REPORT_PROMPT_PATH"] = str(resolve_project_path(professional_report_prompt_path, DEFAULT_PROFESSIONAL_REPORT_PROMPT_PATH))
    default_rag_data = Path(os.environ.get("RAG_DATA_DIR") or rag_data_dir or (PROJECT_ROOT / "llm" / "rag" / "runtime"))
    app.config["RAG_DATA_DIR"] = str(default_rag_data.resolve())
    app.config["RAG_API_CONFIG_PATH"] = str(resolve_project_path(rag_api_config, PROJECT_ROOT / "config" / "ai_api.local.json"))
    app.config["AUTH_COOKIE_NAME"] = os.environ.get("TP_AUTH_COOKIE_NAME", AUTH_COOKIE_NAME)
    app.config["AUTH_COOKIE_SECURE"] = str(os.environ.get("TP_AUTH_COOKIE_SECURE", "0")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    app.config["AUTH_COOKIE_DOMAIN"] = os.environ.get("TP_AUTH_COOKIE_DOMAIN", "")
    final_jwt_secret = (jwt_secret or os.environ.get("TP_JWT_SECRET", "")).strip()
    if not final_jwt_secret:
        final_jwt_secret = load_or_create_jwt_secret()
        print(f"[info] JWT secret loaded from {display_project_path(DEFAULT_JWT_SECRET_PATH)}")
    app.config["JWT_SECRET"] = final_jwt_secret
    app.config["JWT_TTL_SECONDS"] = max(300, int(jwt_ttl_seconds))

    with closing(get_conn(mysql_conf, autocommit=False)) as conn:
        ensure_schema(conn)
        ensure_review_schema(conn)
        rag2_ensure_schema(conn)
        rag2_ensure_default_kb(conn)
        MySQLSituationStore(MySQLSettings(**mysql_conf), connection=conn).ensure_schema()
        ensure_professional_report_schema(conn)
        ensure_builtin_admin(conn)
        if seed_demo:
            seed_demo_data(conn, force_seed=force_seed)
        conn.commit()

    Path(app.config["RAG_DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    preferred_report_root = Path(os.environ.get("SITUATION_REPORT_DIR") or "D:/JingyuanTrafficPipelineData/reports")
    if not preferred_report_root.drive or not Path(f"{preferred_report_root.drive}/").exists():
        preferred_report_root = PROJECT_ROOT / "output" / "professional_reports"
    preferred_report_root.mkdir(parents=True, exist_ok=True)
    app.config["PROFESSIONAL_REPORT_DIR"] = str(preferred_report_root.resolve())
    app.config["PROFESSIONAL_REPORT_MANAGER"] = ProfessionalReportManager(
        mysql_conf,
        preferred_report_root.resolve(),
        Path(app.config["PROFESSIONAL_REPORT_PROMPT_PATH"]),
        Path(app.config["RAG_DATA_DIR"]),
        Path(app.config["RAG_API_CONFIG_PATH"]),
    )
    with closing(get_conn(mysql_conf, autocommit=False)) as conn:
        migration = rag2_migrate_legacy_sqlite(conn, Path(app.config["RAG_DB_PATH"]))
        if migration.get("document_id"):
            print(f"[info] legacy RAG metadata migrated: {migration}")

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
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            rows = list_demo_accounts(conn)
        return jsonify({"accounts": rows})

    @app.route("/api/v2/auth/register", methods=["POST"])
    def register():
        body = request.get_json(silent=True) or {}
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", "")).strip()
        display_name = str(body.get("display_name", "")).strip()
        role_hint = str(body.get("role", "")).strip().lower()
        if role_hint and role_hint != ROLE_NORMAL:
            return jsonify({"error": "only_normal_role_can_register"}), 400
        if not is_valid_username(username):
            return jsonify({"error": "invalid_username", "message": "username must be 3-32 chars: letters/numbers/_"}), 400
        if len(password) < 6:
            return jsonify({"error": "password_too_short", "message": "password length must be >= 6"}), 400
        if len(password) > 128:
            return jsonify({"error": "password_too_long"}), 400
        if not display_name:
            display_name = username
        if len(display_name) > 64:
            return jsonify({"error": "display_name_too_long"}), 400

        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM demo_users WHERE username=%s LIMIT 1", (username,))
                exists = cur.fetchone()
                if exists:
                    return jsonify({"error": "username_already_exists"}), 409
                cur.execute(
                    """
                    INSERT INTO demo_users(username, password, role, display_name, nickname)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (username, password, ROLE_NORMAL, display_name, display_name),
                )
                cur.execute(
                    """
                    SELECT id, username, role, display_name, nickname, avatar_url
                    FROM demo_users
                    WHERE username=%s
                    LIMIT 1
                    """,
                    (username,),
                )
                account = cur.fetchone()
                if not account:
                    return jsonify({"error": "register_failed"}), 500
                token = create_jwt_token(account, app.config["JWT_SECRET"], app.config["JWT_TTL_SECONDS"])
                log_action(conn, account["username"], account["role"], "register", "auth", "register_success")
            conn.commit()

        resp = jsonify(
            {
                "token": token,
                "expires_in": int(app.config["JWT_TTL_SECONDS"]),
                "role": account["role"],
                "display_name": account["display_name"],
                "nickname": account.get("nickname") or account["display_name"],
                "avatar_url": normalize_avatar_url(account.get("avatar_url") or ""),
                "username": account["username"],
            }
        )
        return set_auth_cookie(resp, token)

    @app.route("/api/v2/auth/login", methods=["POST"])
    def login():
        body = request.get_json(silent=True) or {}
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", "")).strip()
        role_hint = str(body.get("role", "")).strip().lower()
        if role_hint and role_hint not in {ROLE_NORMAL, ROLE_ADMIN}:
            return jsonify({"error": "invalid_role"}), 400
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            account = find_demo_account(conn, username, password, role_hint)
            if not account:
                return jsonify({"error": "invalid_credentials"}), 401
            token = create_jwt_token(account, app.config["JWT_SECRET"], app.config["JWT_TTL_SECONDS"])
            log_action(conn, account["username"], account["role"], "login", "auth", "login_success")
            conn.commit()
        resp = jsonify(
            {
                "token": token,
                "expires_in": int(app.config["JWT_TTL_SECONDS"]),
                "role": account["role"],
                "display_name": account["display_name"],
                "nickname": account.get("nickname") or account["display_name"],
                "avatar_url": normalize_avatar_url(account.get("avatar_url") or ""),
                "username": account["username"],
            }
        )
        return set_auth_cookie(resp, token)

    @app.route("/api/v2/auth/logout", methods=["POST"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def logout():
        revoke_jwt(g.token_claims)
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            log_action(conn, g.session["username"], g.session["role"], "logout", "auth", "logout_success")
        return clear_auth_cookie(jsonify({"ok": True}))

    @app.route("/api/v2/auth/profile", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def profile():
        session = dict(g.session)
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, username, role, display_name, nickname, avatar_url
                    FROM demo_users
                    WHERE username=%s
                    LIMIT 1
                    """,
                    (g.session["username"],),
                )
                row = cur.fetchone()
        if row:
            session.update(profile_public_fields(row))
        session["expires_at"] = dt_to_str(session["expires_at"])
        return jsonify(session)

    @app.route("/api/v2/auth/profile", methods=["PUT"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def update_profile():
        body = request.get_json(silent=True) or {}
        display_name = normalize_profile_text(body.get("display_name"), g.session["display_name"], 64)
        nickname = normalize_profile_text(body.get("nickname"), display_name, 64)
        avatar_url = normalize_avatar_url(body.get("avatar_url") or "")
        if not display_name:
            display_name = g.session["username"]
        if not nickname:
            nickname = display_name
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE demo_users
                    SET display_name=%s, nickname=%s, avatar_url=%s
                    WHERE username=%s
                    """,
                    (display_name, nickname, avatar_url, g.session["username"]),
                )
                cur.execute(
                    """
                    SELECT id, username, role, display_name, nickname, avatar_url
                    FROM demo_users
                    WHERE username=%s
                    LIMIT 1
                    """,
                    (g.session["username"],),
                )
                row = cur.fetchone()
                log_action(conn, g.session["username"], g.session["role"], "update_profile", "self", "profile_updated")
            conn.commit()
        if not row:
            return jsonify({"error": "user_not_found"}), 404
        payload = profile_public_fields(row)
        payload["ok"] = True
        return jsonify(payload)

    @app.route("/api/v2/auth/avatar", methods=["POST"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def upload_avatar():
        file_obj = request.files.get("avatar")
        if not file_obj or not file_obj.filename:
            return jsonify({"error": "avatar_required", "message": "请选择头像图片"}), 400
        ext = file_obj.filename.rsplit(".", 1)[-1].lower() if "." in file_obj.filename else ""
        if ext not in ALLOWED_AVATAR_EXTENSIONS:
            return jsonify({"error": "invalid_avatar_type", "message": "头像仅支持 jpg、png、webp"}), 400
        raw = file_obj.read(MAX_AVATAR_BYTES + 1)
        if len(raw) > MAX_AVATAR_BYTES:
            return jsonify({"error": "avatar_too_large", "message": "头像图片不能超过 2MB"}), 400
        AVATAR_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        safe_name = f"{g.session['username']}_{uuid.uuid4().hex[:12]}.{ext}"
        target = AVATAR_UPLOAD_DIR / safe_name
        target.write_bytes(raw)
        url = f"/uploads/avatars/{safe_name}"
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE demo_users SET avatar_url=%s WHERE username=%s", (url, g.session["username"]))
                log_action(conn, g.session["username"], g.session["role"], "upload_avatar", "self", url)
            conn.commit()
        return jsonify({"ok": True, "avatar_url": url})

    @app.route("/api/v2/auth/change-password", methods=["POST"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def auth_change_password():
        body = request.get_json(silent=True) or {}
        old_password = str(body.get("old_password", "")).strip()
        new_password = str(body.get("new_password", "")).strip()
        if not old_password or not new_password:
            return jsonify({"error": "old_password_and_new_password_required"}), 400
        if len(new_password) < 4:
            return jsonify({"error": "new_password_too_short"}), 400
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT password FROM demo_users WHERE username=%s LIMIT 1", (g.session["username"],))
                row = cur.fetchone()
                if not row:
                    return jsonify({"error": "user_not_found"}), 404
                if str(row.get("password", "")) != old_password:
                    return jsonify({"error": "old_password_incorrect"}), 400
                cur.execute("UPDATE demo_users SET password=%s WHERE username=%s", (new_password, g.session["username"]))
                log_action(conn, g.session["username"], g.session["role"], "change_password", "self", "self_password_updated")
            conn.commit()
        return jsonify({"ok": True})

    @app.route("/api/v2/common/system-status", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def system_status():
        visible_sql = visible_attack_event_clause()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            refresh_machine_stats(conn)
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT
                      MAX(occurred_at) AS latest_event_time,
                      SUM(CASE WHEN risk_level IN ('critical','high') AND occurred_at >= DATE_SUB(NOW(), INTERVAL 10 MINUTE) THEN 1 ELSE 0 END) AS high_10m
                    FROM demo_attack_events
                    WHERE {visible_sql}
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
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def alerts_ticker():
        limit = max(1, min(int(request.args.get("limit", "3")), 10))
        visible_sql = visible_attack_event_clause()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT event_id, occurred_at, risk_level, attack_type, source_ip, target_node, target_interface
                    FROM demo_attack_events
                    WHERE risk_level IN ('critical','high') AND {visible_sql}
                    ORDER BY occurred_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                rows = cur.fetchall()
        return jsonify({"items": normalize_rows(rows)})

    @app.route("/api/v2/common/alerts/popup", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def alerts_popup():
        limit = max(1, min(int(request.args.get("limit", "5")), 20))
        visible_sql = visible_attack_event_clause()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT event_id, occurred_at, attack_type, source_ip, target_node, target_interface
                    FROM demo_attack_events
                    WHERE risk_level IN ('critical','high') AND acked=0 AND {visible_sql}
                    ORDER BY occurred_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                rows = cur.fetchall()
        return jsonify({"items": normalize_rows(rows)})

    @app.route("/api/v2/common/alerts/<event_id>/ack", methods=["POST"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
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

    @app.route("/api/v2/llm/prompt", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def llm_prompt_get():
        prompt_path = Path(app.config["LLM_PROMPT_PATH"])
        return jsonify(build_llm_prompt_payload(prompt_path))

    @app.route("/api/v2/llm/prompt", methods=["PUT"])
    @require_roles(ROLE_ADMIN)
    def llm_prompt_update():
        body = request.get_json(silent=True) or {}
        prompt = str(body.get("prompt", ""))
        if not prompt.strip():
            return jsonify({"error": "prompt_required", "message": "提示词不能为空"}), 400
        if len(prompt) > MAX_LLM_PROMPT_CHARS:
            return (
                jsonify(
                    {
                        "error": "prompt_too_long",
                        "message": f"提示词不能超过 {MAX_LLM_PROMPT_CHARS} 个字符",
                        "max_chars": MAX_LLM_PROMPT_CHARS,
                    }
                ),
                400,
            )

        prompt_path = Path(app.config["LLM_PROMPT_PATH"])
        write_llm_prompt_file(prompt_path, prompt)
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            log_action(
                conn,
                g.session["username"],
                g.session["role"],
                "llm_prompt_update",
                display_project_path(prompt_path),
                f"chars={len(prompt)}",
            )
        payload = build_llm_prompt_payload(prompt_path)
        payload["ok"] = True
        return jsonify(payload)

    @app.route("/api/v2/llm/professional-report-prompt", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def professional_report_prompt_get():
        prompt_path = Path(app.config["PROFESSIONAL_REPORT_PROMPT_PATH"])
        payload = build_llm_prompt_payload(prompt_path)
        payload["max_chars"] = MAX_PROFESSIONAL_REPORT_PROMPT_CHARS
        return jsonify(payload)

    @app.route("/api/v2/llm/professional-report-prompt", methods=["PUT"])
    @require_roles(ROLE_ADMIN)
    def professional_report_prompt_update():
        body = request.get_json(silent=True) or {}
        prompt = str(body.get("prompt", ""))
        if not prompt.strip():
            return jsonify({"error": "prompt_required", "message": "专业报告提示词不能为空"}), 400
        if len(prompt) > MAX_PROFESSIONAL_REPORT_PROMPT_CHARS:
            return jsonify({"error": "prompt_too_long", "message": f"专业报告提示词不能超过 {MAX_PROFESSIONAL_REPORT_PROMPT_CHARS} 个字符"}), 400
        prompt_path = Path(app.config["PROFESSIONAL_REPORT_PROMPT_PATH"])
        write_llm_prompt_file(prompt_path, prompt)
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            log_action(conn, g.session["username"], g.session["role"], "professional_report_prompt_update", display_project_path(prompt_path), f"chars={len(prompt)}")
        payload = build_llm_prompt_payload(prompt_path)
        payload.update({"ok": True, "max_chars": MAX_PROFESSIONAL_REPORT_PROMPT_CHARS})
        return jsonify(payload)

    def rag2_runtime() -> Tuple[Path, Dict[str, Any]]:
        return Path(app.config["RAG_DATA_DIR"]), rag2_load_api_config(Path(app.config["RAG_API_CONFIG_PATH"]))

    def rag2_is_enabled() -> bool:
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            config_map = load_system_config_map(conn)
        return str(config_map.get("rag_enabled", "1")).strip().lower() in {"1", "true", "yes", "on"}

    @app.route("/api/v3/rag/status", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def rag2_status():
        data_dir, api_config = rag2_runtime()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            kbs = rag2_list_kbs(conn)
            config_map = load_system_config_map(conn)
        return jsonify(
            {
                "ok": True,
                "enabled": str(config_map.get("rag_enabled", "1")).strip().lower() in {"1", "true", "yes", "on"},
                "cloud_configured": bool(api_config.get("api_key")),
                "embedding_model": api_config["embedding_model"],
                "rerank_model": api_config["rerank_model"],
                "embedding_dimensions": api_config["embedding_dimensions"],
                "data_dir": display_project_path(data_dir),
                "knowledge_base_count": len(kbs),
                "document_count": sum(int(row.get("document_count") or 0) for row in kbs),
                "chunk_count": sum(int(row.get("chunk_count") or 0) for row in kbs),
                "supported_extensions": sorted(RAG_SUPPORTED_EXTENSIONS),
                "max_upload_mb": RAG_MAX_UPLOAD_BYTES // 1024 // 1024,
            }
        )

    @app.route("/api/v3/rag/knowledge-bases", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def rag2_kb_list():
        q = str(request.args.get("q") or "").strip()
        include_disabled = str(request.args.get("include_disabled", "1")).lower() not in {"0", "false", "no"}
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            rows = rag2_list_kbs(conn, q=q, include_disabled=include_disabled)
        return jsonify({"items": rows, "total": len(rows)})

    @app.route("/api/v3/rag/knowledge-bases", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def rag2_kb_create():
        body = request.get_json(silent=True) or {}
        try:
            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
                kb_id = rag2_save_kb(conn, body, g.session["username"])
                item = rag2_get_kb(conn, kb_id)
                log_action(conn, g.session["username"], g.session["role"], "rag_kb_create", str(kb_id), str(body.get("name") or ""))
        except (ValueError, pymysql.IntegrityError) as exc:
            return jsonify({"error": "invalid_knowledge_base", "message": str(exc)}), 400
        return jsonify({"ok": True, "item": item}), 201

    @app.route("/api/v3/rag/knowledge-bases/<int:kb_id>", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def rag2_kb_detail(kb_id: int):
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            item = rag2_get_kb(conn, kb_id)
        if not item:
            return jsonify({"error": "knowledge_base_not_found"}), 404
        return jsonify({"item": item})

    @app.route("/api/v3/rag/knowledge-bases/<int:kb_id>", methods=["PUT"])
    @require_roles(ROLE_ADMIN)
    def rag2_kb_update(kb_id: int):
        body = request.get_json(silent=True) or {}
        try:
            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
                rag2_save_kb(conn, body, g.session["username"], kb_id=kb_id)
                item = rag2_get_kb(conn, kb_id)
                log_action(conn, g.session["username"], g.session["role"], "rag_kb_update", str(kb_id), str(body.get("name") or ""))
        except KeyError:
            return jsonify({"error": "knowledge_base_not_found"}), 404
        except (ValueError, pymysql.IntegrityError) as exc:
            return jsonify({"error": "invalid_knowledge_base", "message": str(exc)}), 400
        return jsonify({"ok": True, "item": item})

    @app.route("/api/v3/rag/knowledge-bases/<int:kb_id>/toggle", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def rag2_kb_toggle(kb_id: int):
        body = request.get_json(silent=True) or {}
        enabled = bool(body.get("enabled", True))
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            item = rag2_get_kb(conn, kb_id)
            if not item:
                return jsonify({"error": "knowledge_base_not_found"}), 404
            item["enabled"] = enabled
            rag2_save_kb(conn, item, g.session["username"], kb_id=kb_id)
        return jsonify({"ok": True, "enabled": enabled})

    @app.route("/api/v3/rag/knowledge-bases/<int:kb_id>/delete", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def rag2_kb_delete(kb_id: int):
        data_dir, _ = rag2_runtime()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            changed = rag2_delete_kb(conn, data_dir, kb_id)
            if changed:
                log_action(conn, g.session["username"], g.session["role"], "rag_kb_delete", str(kb_id), "deleted")
        if not changed:
            return jsonify({"error": "knowledge_base_not_found"}), 404
        return jsonify({"ok": True})

    @app.route("/api/v3/rag/knowledge-bases/<int:kb_id>/documents", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def rag2_documents(kb_id: int):
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            if not rag2_get_kb(conn, kb_id):
                return jsonify({"error": "knowledge_base_not_found"}), 404
            rows = rag2_list_documents(conn, kb_id)
        return jsonify({"items": rows, "total": len(rows)})

    @app.route("/api/v3/rag/knowledge-bases/<int:kb_id>/documents/upload", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def rag2_upload(kb_id: int):
        if not rag2_is_enabled():
            return jsonify({"error": "rag_disabled", "message": "RAG 已关闭，未调用云端向量 API"}), 409
        upload = request.files.get("file")
        if not upload or not upload.filename:
            return jsonify({"error": "file_required", "message": "请选择要上传的文件"}), 400
        data_dir, api_config = rag2_runtime()
        temp_dir = data_dir / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        temp_path = temp_dir / f"{uuid.uuid4().hex}_{Path(upload.filename).name}"
        upload.save(temp_path)
        try:
            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
                item = rag2_ingest_file(conn, data_dir, api_config, kb_id, temp_path, upload.filename, g.session["username"])
                log_action(conn, g.session["username"], g.session["role"], "rag_document_upload", str(item["id"]), upload.filename)
            return jsonify({"ok": True, "item": item}), 201
        except (ValueError, KeyError, RuntimeError) as exc:
            return jsonify({"error": "document_ingest_failed", "message": str(exc)}), 400
        finally:
            temp_path.unlink(missing_ok=True)

    @app.route("/api/v3/rag/knowledge-bases/<int:kb_id>/documents/text", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def rag2_add_text(kb_id: int):
        if not rag2_is_enabled():
            return jsonify({"error": "rag_disabled", "message": "RAG 已关闭，未调用云端向量 API"}), 409
        body = request.get_json(silent=True) or {}
        title = str(body.get("title") or "在线知识.txt").strip()
        content = str(body.get("content") or "").strip()
        if not content:
            return jsonify({"error": "content_required", "message": "知识正文不能为空"}), 400
        data_dir, api_config = rag2_runtime()
        temp_dir = data_dir / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        name = title if Path(title).suffix else f"{title}.txt"
        temp_path = temp_dir / f"{uuid.uuid4().hex}_{Path(name).name}"
        temp_path.write_text(content, encoding="utf-8")
        try:
            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
                item = rag2_ingest_file(conn, data_dir, api_config, kb_id, temp_path, name, g.session["username"], source_type="text")
            return jsonify({"ok": True, "item": item}), 201
        except (ValueError, KeyError, RuntimeError) as exc:
            return jsonify({"error": "document_ingest_failed", "message": str(exc)}), 400
        finally:
            temp_path.unlink(missing_ok=True)

    @app.route("/api/v3/rag/documents/<int:document_id>/delete", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def rag2_document_delete(document_id: int):
        data_dir, _ = rag2_runtime()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            changed = rag2_delete_document(conn, data_dir, document_id)
        if not changed:
            return jsonify({"error": "document_not_found"}), 404
        return jsonify({"ok": True})

    @app.route("/api/v3/rag/documents/<int:document_id>/index", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def rag2_document_index(document_id: int):
        if not rag2_is_enabled():
            return jsonify({"error": "rag_disabled", "message": "RAG 已关闭，未调用云端向量 API"}), 409
        data_dir, api_config = rag2_runtime()
        try:
            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
                item = rag2_index_pending_document(conn, data_dir, api_config, document_id)
            return jsonify({"ok": True, "item": item})
        except (KeyError, RuntimeError) as exc:
            return jsonify({"error": "document_index_failed", "message": str(exc)}), 400

    @app.route("/api/v3/rag/knowledge-bases/<int:kb_id>/chunks", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def rag2_chunks(kb_id: int):
        document_id = int(request.args.get("document_id") or 0) or None
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            rows = rag2_list_chunks(conn, kb_id, document_id=document_id)
        return jsonify({"items": rows, "total": len(rows)})

    @app.route("/api/v3/rag/chunks/<int:chunk_id>", methods=["PUT"])
    @require_roles(ROLE_ADMIN)
    def rag2_chunk_update(chunk_id: int):
        if not rag2_is_enabled():
            return jsonify({"error": "rag_disabled", "message": "RAG 已关闭，未调用云端向量 API"}), 409
        body = request.get_json(silent=True) or {}
        data_dir, api_config = rag2_runtime()
        try:
            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
                rag2_update_chunk(conn, data_dir, api_config, chunk_id, str(body.get("content") or ""), bool(body.get("enabled", True)))
        except (ValueError, KeyError, RuntimeError) as exc:
            return jsonify({"error": "chunk_update_failed", "message": str(exc)}), 400
        return jsonify({"ok": True})

    @app.route("/api/v3/rag/knowledge-bases/<int:kb_id>/recall", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def rag2_recall(kb_id: int):
        if not rag2_is_enabled():
            return jsonify({"error": "rag_disabled", "message": "RAG 已关闭，未调用云端召回 API"}), 409
        body = request.get_json(silent=True) or {}
        data_dir, api_config = rag2_runtime()
        try:
            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
                result = rag2_hybrid_search(conn, data_dir, api_config, kb_id, str(body.get("query") or ""), g.session["username"], save_test=True)
        except (ValueError, KeyError, RuntimeError) as exc:
            return jsonify({"error": "recall_failed", "message": str(exc)}), 400
        return jsonify(result)

    @app.route("/api/v3/rag/knowledge-bases/<int:kb_id>/recall-history", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def rag2_recall_history(kb_id: int):
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            rows = rag2_list_test_history(conn, kb_id)
        return jsonify({"items": rows, "total": len(rows)})

    @app.route("/api/v3/rag/knowledge-bases/<int:kb_id>/eval-cases", methods=["GET", "POST"])
    @require_roles(ROLE_ADMIN)
    def rag2_eval_cases(kb_id: int):
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=request.method == "GET")) as conn:
            if request.method == "GET":
                rows = rag2_list_eval_cases(conn, kb_id)
                return jsonify({"items": rows, "total": len(rows)})
            try:
                item = rag2_save_eval_case(conn, kb_id, request.get_json(silent=True) or {})
            except (ValueError, KeyError) as exc:
                return jsonify({"error": "eval_case_save_failed", "message": str(exc)}), 400
        return jsonify({"ok": True, "item": item}), 201

    @app.route("/api/v3/rag/knowledge-bases/<int:kb_id>/eval-cases/<int:case_id>", methods=["PUT", "POST"])
    @require_roles(ROLE_ADMIN)
    def rag2_eval_case_update(kb_id: int, case_id: int):
        body = request.get_json(silent=True) or {}
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            try:
                if request.method == "POST" and body.get("action") == "delete":
                    changed = rag2_delete_eval_case(conn, kb_id, case_id)
                    if not changed:
                        return jsonify({"error": "eval_case_not_found"}), 404
                    return jsonify({"ok": True})
                item = rag2_save_eval_case(conn, kb_id, body, case_id=case_id)
            except (ValueError, KeyError) as exc:
                return jsonify({"error": "eval_case_save_failed", "message": str(exc)}), 400
        return jsonify({"ok": True, "item": item})

    @app.route("/api/v3/rag/knowledge-bases/<int:kb_id>/eval-runs", methods=["GET", "POST"])
    @require_roles(ROLE_ADMIN)
    def rag2_eval_runs(kb_id: int):
        if request.method == "POST" and not rag2_is_enabled():
            return jsonify({"error": "rag_disabled", "message": "RAG 已关闭，未调用云端评估 API"}), 409
        data_dir, api_config = rag2_runtime()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=request.method == "GET")) as conn:
            if request.method == "GET":
                rows = rag2_list_eval_runs(conn, kb_id)
                return jsonify({"items": rows, "total": len(rows)})
            try:
                result = rag2_run_eval_suite(conn, data_dir, api_config, kb_id, g.session["username"])
            except (ValueError, KeyError, RuntimeError) as exc:
                return jsonify({"error": "eval_run_failed", "message": str(exc)}), 400
        return jsonify({"ok": True, **result})

    @app.route("/api/v2/rag/docs", methods=["GET"])
    @require_roles(ROLE_ADMIN)
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
    @require_roles(ROLE_ADMIN)
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

    @app.route("/api/v2/rag/docs/<doc_id>", methods=["GET"])
    @app.route("/api/v2/rag/docs/<doc_id>/", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def rag_docs_detail(doc_id: str):
        row = rag_get_doc(app.config["RAG_DB_PATH"], doc_id=doc_id)
        if not row:
            return jsonify({"error": "doc_not_found"}), 404
        return jsonify({"item": row})

    @app.route("/api/v2/rag/docs/<doc_id>", methods=["PUT"])
    @app.route("/api/v2/rag/docs/<doc_id>/update", methods=["POST"])
    @app.route("/api/v2/rag/docs/<doc_id>/update/", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def rag_docs_update(doc_id: str):
        old = rag_get_doc(app.config["RAG_DB_PATH"], doc_id=doc_id)
        if not old:
            return jsonify({"error": "doc_not_found"}), 404

        body = request.get_json(silent=True) or {}
        title = str(body.get("title", old.get("title", ""))).strip()
        tags = str(body.get("tags", old.get("tags", ""))).strip()
        attack_type = str(body.get("attack_type", old.get("attack_type", ""))).strip()
        content = str(body.get("content", old.get("content", ""))).strip()
        evidence = str(body.get("evidence", old.get("evidence", ""))).strip()
        mitigation = str(body.get("mitigation", old.get("mitigation", ""))).strip()
        severity = str(body.get("severity", old.get("severity", "medium"))).strip().lower() or "medium"
        source = str(body.get("source", old.get("source", ""))).strip() or old.get("source", "")

        if not title or not content:
            return jsonify({"error": "title_and_content_required"}), 400
        if severity not in RAG_SEVERITY_SET:
            return jsonify({"error": "invalid_severity"}), 400

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
                "rag_update_doc",
                doc_id,
                f"title={title[:60]}",
            )
        return jsonify({"ok": True, "doc_id": doc_id, "item": row})

    @app.route("/api/v2/rag/docs/<doc_id>/delete", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def rag_docs_delete(doc_id: str):
        changed = rag_delete_doc(app.config["RAG_DB_PATH"], doc_id=doc_id)
        if changed == 0:
            return jsonify({"error": "doc_not_found"}), 404
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            log_action(conn, g.session["username"], g.session["role"], "rag_delete_doc", doc_id, "deleted")
        return jsonify({"ok": True, "doc_id": doc_id})

    @app.route("/api/v2/rag/rebuild", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def rag_rebuild_api():
        count = rag_rebuild_from_seed(app.config["RAG_DB_PATH"], app.config["RAG_SEED_PATH"])
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            log_action(conn, g.session["username"], g.session["role"], "rag_rebuild", "seed", f"count={count}")
        return jsonify({"ok": True, "rows": count})

    @app.route("/api/v2/plugins/phishing/check", methods=["POST"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def plugin_phishing_check():
        body = request.get_json(silent=True) or {}
        url_text = str(body.get("url", "")).strip()
        token = str(body.get("token", "")).strip()
        if not url_text or not token:
            return jsonify({"error": "url_and_token_required"}), 400
        if not re.match(r"^https?://", url_text, flags=re.IGNORECASE):
            return jsonify({"error": "invalid_url", "message": "url must start with http:// or https://"}), 400
        exp_ts = read_jwt_exp_unverified(token)
        if exp_ts is not None and exp_ts <= int(now_dt().timestamp()):
            return (
                jsonify(
                    {
                        "error": "token_expired",
                        "message": "token已过期，请更换新的token",
                        "expired_at": dt_to_str(datetime.fromtimestamp(exp_ts), ms=False),
                    }
                ),
                400,
            )

        upstream = "http://ctf.ski:9898/?" + urllib.parse.urlencode({"url": url_text, "token": token})
        req = urllib.request.Request(upstream, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                payload = resp.read().decode("utf-8", errors="replace")
                data = json.loads(payload)
        except urllib.error.HTTPError as exc:
            detail = ""
            message = ""
            try:
                detail = exc.read().decode("utf-8", errors="replace").strip()
                if detail:
                    body_obj = json.loads(detail)
                    if isinstance(body_obj, dict):
                        message = str(body_obj.get("msg") or body_obj.get("message") or body_obj.get("error") or "").strip()
            except Exception:
                detail = ""
            if not message and int(exc.code) == 401:
                message = "上游鉴权失败，token可能无效或已过期"
            resp_obj: Dict[str, Any] = {"error": "upstream_http_error", "status": int(exc.code)}
            if message:
                resp_obj["message"] = message
            if detail:
                resp_obj["detail"] = detail[:400]
            return jsonify(resp_obj), 502
        except urllib.error.URLError as exc:
            return jsonify({"error": "upstream_unreachable", "detail": str(exc.reason)}), 502
        except Exception as exc:
            return jsonify({"error": "upstream_parse_error", "detail": str(exc)}), 502

        result = {
            "action": data.get("action"),
            "verdict": data.get("verdict"),
            "confidence": data.get("confidence"),
            "reason": data.get("reason"),
            "evidence": data.get("evidence") if isinstance(data.get("evidence"), list) else [],
        }
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            log_action(
                conn,
                g.session["username"],
                g.session["role"],
                "plugin_phishing_check",
                url_text[:120],
                f"verdict={result.get('verdict')},confidence={result.get('confidence')}",
            )
        return jsonify(result)

    @app.route("/api/v2/plugins/ip-analyze", methods=["POST"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def plugin_ip_analyze():
        body = request.get_json(silent=True) or {}
        ip_raw = str(body.get("ip", "")).strip()
        ip_norm = normalize_ip_literal(ip_raw)
        if not ip_norm:
            return jsonify({"error": "invalid_ip", "message": "请输入合法的 IPv4/IPv6 地址"}), 400

        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            region = resolve_region_for_event(conn, ip_norm, "")
            cache_source = ""
            updated_at = None
            with conn.cursor() as cur:
                cur.execute("SELECT source, updated_at FROM ip_geo_cache WHERE ip=%s LIMIT 1", (ip_norm,))
                row = cur.fetchone() or {}
                cache_source = str(row.get("source") or "")
                updated_at = row.get("updated_at")
            log_action(
                conn,
                g.session["username"],
                g.session["role"],
                "plugin_ip_analyze",
                ip_norm,
                f"region={region}",
            )
            conn.commit()

        if not cache_source:
            cache_source = "private" if region == "内网" else ("fallback" if region == "未知" else "remote")

        return jsonify(
            {
                "ip": ip_norm,
                "region": region,
                "is_public": bool(is_public_ip(ip_norm)),
                "source": cache_source,
                "updated_at": dt_to_str(updated_at, ms=True) if isinstance(updated_at, datetime) else normalize_value(updated_at),
            }
        )

    @app.route("/api/v2/plugins/local-status", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def plugin_local_status():
        snapshot = collect_local_system_status()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            log_action(
                conn,
                g.session["username"],
                g.session["role"],
                "plugin_local_status",
                snapshot.get("hostname") or "",
                f"cpu={snapshot.get('cpu_percent')}",
            )
        return jsonify(snapshot)

    @app.route("/api/v2/user/dashboard/kpis", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def user_kpis():
        visible_sql = visible_attack_event_clause()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            refresh_machine_stats(conn)
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) AS c FROM demo_attack_events WHERE DATE(occurred_at)=CURDATE() AND {visible_sql}")
                today_total = int((cur.fetchone() or {}).get("c", 0))
                cur.execute(
                    f"""
                    SELECT COUNT(*) AS c
                    FROM demo_attack_events
                    WHERE DATE(occurred_at)=DATE_SUB(CURDATE(), INTERVAL 1 DAY) AND {visible_sql}
                    """
                )
                yesterday_total = int((cur.fetchone() or {}).get("c", 0))
                cur.execute(
                    f"""
                    SELECT COUNT(*) AS c
                    FROM demo_attack_events
                    WHERE risk_level IN ('critical','high') AND process_status IN ('unprocessed','processing') AND {visible_sql}
                    """
                )
                high_active = int((cur.fetchone() or {}).get("c", 0))
                today_situations = 0
                if db_table_exists(cur, "attack_situations"):
                    cur.execute("SELECT COUNT(*) AS c FROM attack_situations WHERE DATE(created_at)=CURDATE()")
                    today_situations = int((cur.fetchone() or {}).get("c") or 0)
                cur.execute(
                    """
                    SELECT AVG(defense_latency_ms) / 1000.0 AS avg_seconds, COUNT(*) AS sample_count
                    FROM demo_fast_defense_audit
                    WHERE DATE(created_at)=CURDATE()
                      AND decision='silent_block'
                      AND firewall_success=1
                      AND defense_latency_ms IS NOT NULL
                      AND defense_latency_ms >= 0
                    """
                )
                defense_obj = cur.fetchone() or {}
                avg_defense_seconds = float(defense_obj.get("avg_seconds") or 0)
                defense_samples = int(defense_obj.get("sample_count") or 0)
                cur.execute(
                    f"""
                    SELECT COUNT(*) AS c
                    FROM demo_attack_events
                    WHERE DATE(occurred_at)=CURDATE() AND anomaly_detected=1 AND {visible_sql}
                    """
                )
                anomaly_cnt = int((cur.fetchone() or {}).get("c", 0))
                cur.execute("SELECT COUNT(*) AS c FROM demo_machines WHERE online_status='online'")
                online_nodes = int((cur.fetchone() or {}).get("c", 0))
            conn.commit()

        yoy = 0.0 if yesterday_total == 0 else ((today_total - yesterday_total) / yesterday_total) * 100.0
        return jsonify(
            {
                "today_attack_total": today_total,
                "yoy_percent": round(yoy, 2),
                "active_high_alerts": high_active,
                "today_situation_total": today_situations,
                "avg_auto_defense_block_seconds": round(avg_defense_seconds, 2),
                "auto_defense_block_samples": defense_samples,
                "today_anomaly_detected": anomaly_cnt,
                "online_protection_nodes": online_nodes,
            }
        )

    @app.route("/api/v2/user/dashboard/trend7d", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def trend7d():
        visible_sql = visible_attack_event_clause()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT
                      DATE(occurred_at) AS d,
                      COUNT(*) AS total,
                      SUM(CASE WHEN attack_result='blocked' THEN 1 ELSE 0 END) AS blocked
                    FROM demo_attack_events
                    WHERE occurred_at >= DATE_SUB(CURDATE(), INTERVAL 6 DAY) AND {visible_sql}
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
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def top_attack_types():
        visible_sql = visible_attack_event_clause()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT attack_type, COUNT(*) AS total
                    FROM demo_attack_events
                    WHERE occurred_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) AND {visible_sql}
                    GROUP BY attack_type
                    ORDER BY total DESC
                    """
                )
                rows = cur.fetchall()
        items = aggregate_counts_by_label(rows, "attack_type")[:10]
        return jsonify({"items": normalize_rows(items)})

    @app.route("/api/v2/user/dashboard/source-distribution", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def source_distribution():
        visible_sql = visible_attack_event_clause()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT source_ip, source_region, COUNT(*) AS total
                    FROM demo_attack_events
                    WHERE occurred_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) AND {visible_sql}
                    GROUP BY source_ip, source_region
                    """
                )
                rows = cur.fetchall()
            region_bucket: Dict[str, int] = {}
            for row in rows:
                count = int(row.get("total") or 0)
                region = resolve_region_for_event(
                    conn,
                    str(row.get("source_ip") or ""),
                    str(row.get("source_region") or ""),
                )
                region = simplify_source_region_for_dashboard(region)
                region_bucket[region] = region_bucket.get(region, 0) + count
        items = [{"source_region": k, "total": v} for k, v in region_bucket.items()]
        items.sort(key=lambda x: int(x.get("total") or 0), reverse=True)
        items = items[:7]
        return jsonify({"items": normalize_rows(items)})

    @app.route("/api/v2/user/dashboard/source-map", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def source_map():
        visible_sql = visible_attack_event_clause()
        try:
            days = max(1, min(90, int(request.args.get("days", 30))))
        except ValueError:
            days = 30
        try:
            limit = max(1, min(20, int(request.args.get("limit", 10))))
        except ValueError:
            limit = 10

        def collect_rows(time_filter_sql: str) -> List[Dict[str, Any]]:
            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        SELECT source_ip, source_region, COUNT(*) AS total
                        FROM demo_attack_events
                        WHERE {time_filter_sql} AND {visible_sql}
                        GROUP BY source_ip, source_region
                        """
                    )
                    rows = cur.fetchall()
                region_bucket: Dict[str, int] = {}
                for row in rows:
                    count = int(row.get("total") or 0)
                    region = resolve_region_for_event(
                        conn,
                        str(row.get("source_ip") or ""),
                        str(row.get("source_region") or ""),
                    )
                    region = simplify_source_region_for_dashboard(region)
                    region_bucket[region] = region_bucket.get(region, 0) + count
            items = [{"source_region": k, "total": v} for k, v in region_bucket.items()]
            items.sort(key=lambda x: int(x.get("total") or 0), reverse=True)
            return items

        items = collect_rows(f"occurred_at >= DATE_SUB(NOW(), INTERVAL {days} DAY)")
        fallback_all_time = False
        if not items:
            # Local demos may not have traffic in the current month; use historical data so the animation still works.
            items = collect_rows("1=1")
            fallback_all_time = bool(items)
        return jsonify(
            {
                "items": normalize_rows(items[:limit]),
                "period_days": days,
                "limit": limit,
                "fallback_all_time": fallback_all_time,
                "server_region": "北京",
                "server_coord": [116.4074, 39.9042],
            }
        )

    @app.route("/api/v2/user/dashboard/heatmap", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def heatmap():
        visible_sql = visible_attack_event_clause()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT
                      WEEKDAY(occurred_at) AS weekday_idx,
                      HOUR(occurred_at) AS hour_idx,
                      COUNT(*) AS total
                    FROM demo_attack_events
                    WHERE occurred_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) AND {visible_sql}
                    GROUP BY WEEKDAY(occurred_at), HOUR(occurred_at)
                    ORDER BY weekday_idx, hour_idx
                    """
                )
                rows = cur.fetchall()
        return jsonify({"items": normalize_rows(rows)})

    @app.route("/api/v2/user/dashboard/method-share", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def method_share():
        visible_sql = visible_attack_event_clause()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT attack_type, COUNT(*) AS total
                    FROM demo_attack_events
                    WHERE occurred_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) AND {visible_sql}
                    GROUP BY attack_type
                    ORDER BY total DESC
                    """
                )
                rows = cur.fetchall()
        merged = aggregate_counts_by_label(rows, "attack_type")
        total = sum(int(r.get("total") or 0) for r in merged)
        items = []
        for r in merged:
            count = int(r.get("total") or 0)
            ratio = 0.0 if total == 0 else (count / total) * 100.0
            items.append({"attack_type": r["attack_type"], "total": count, "ratio_percent": round(ratio, 2)})
        return jsonify({"items": items})

    def open_situation_store() -> MySQLSituationStore:
        return MySQLSituationStore(MySQLSettings(**app.config["MYSQL_CONF"]))

    def load_proxy_cluster_rows(window_minutes: int, lookback_hours: int, status: str = "") -> List[Dict[str, Any]]:
        store = open_situation_store()
        try:
            full_rows = store.list_situation_details(
                limit=5000,
                status=status,
                lookback_hours=lookback_hours,
                include_observing=True,
            )
            return build_proxy_clusters(full_rows, window_minutes=window_minutes, lookback_hours=lookback_hours)
        finally:
            store.close()

    @app.route("/api/v2/situation-clusters", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def situation_clusters():
        try:
            window_minutes = max(5, min(1440, int(request.args.get("window_minutes", "60"))))
            lookback_hours = max(1, min(720, int(request.args.get("lookback_hours", "24"))))
        except ValueError:
            return jsonify({"error": "invalid_time_range"}), 400
        status = request.args.get("status", "").strip()
        if status and status not in {"open", "closed", "handled", "ignored", "observing"}:
            return jsonify({"error": "invalid_status"}), 400
        clusters = load_proxy_cluster_rows(window_minutes, lookback_hours, status=status)
        items = []
        for cluster in clusters:
            summary = {key: value for key, value in cluster.items() if key not in {"actions", "graph", "ai_report"}}
            summary["ai_status"] = cluster.get("ai_status")
            items.append(summary)
        return jsonify(
            {
                "items": normalize_rows(items),
                "total": len(items),
                "window_minutes": window_minutes,
                "lookback_hours": lookback_hours,
                "correlation_rule": "same_target + time_window + multiple_ips + at_least_3_action_types",
            }
        )

    @app.route("/api/v3/rag/enabled", methods=["PUT"])
    @require_roles(ROLE_ADMIN)
    def rag2_enabled_update():
        body = request.get_json(silent=True) or {}
        enabled = bool(body.get("enabled", False))
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO demo_system_config(config_key, config_value)
                    VALUES ('rag_enabled', %s)
                    ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)
                    """,
                    ("1" if enabled else "0",),
                )
                log_action(conn, g.session["username"], g.session["role"], "rag_toggle", "rag", "enabled" if enabled else "disabled")
            conn.commit()
        return jsonify({"ok": True, "enabled": enabled})
    @app.route("/api/v2/situation-clusters/<cluster_id>", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def situation_cluster_detail(cluster_id: str):
        try:
            window_minutes = max(5, min(1440, int(request.args.get("window_minutes", "60"))))
            lookback_hours = max(1, min(720, int(request.args.get("lookback_hours", "24"))))
        except ValueError:
            return jsonify({"error": "invalid_time_range"}), 400
        cluster = next(
            (row for row in load_proxy_cluster_rows(window_minutes, lookback_hours) if row.get("cluster_id") == cluster_id),
            None,
        )
        if not cluster:
            return jsonify({"error": "cluster_not_found"}), 404
        graph = cluster.pop("graph", {"nodes": [], "edges": []})
        return jsonify({"item": normalize_rows([cluster])[0], "graph": normalize_rows([graph])[0]})

    @app.route("/api/v2/situation-clusters/<cluster_id>/reanalyze", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def situation_cluster_reanalyze(cluster_id: str):
        body = request.get_json(silent=True) or {}
        window_minutes = max(5, min(1440, int(body.get("window_minutes", 60))))
        lookback_hours = max(1, min(720, int(body.get("lookback_hours", 24))))
        cluster = next(
            (row for row in load_proxy_cluster_rows(window_minutes, lookback_hours) if row.get("cluster_id") == cluster_id),
            None,
        )
        if not cluster:
            return jsonify({"error": "cluster_not_found"}), 404
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            config_map = load_system_config_map(conn)
        ai_input = dict(cluster)
        ai_input["source_ip"] = f"多个代理来源：{', '.join(cluster.get('source_ips') or [])}"
        report, ai_status = analyze_situation(
            ai_input,
            ollama_url=app.config["OLLAMA_URL"],
            model=config_map.get("llm_model", "qwen3:8b"),
            rag_db_path=Path(app.config["RAG_DB_PATH"]),
            rag_mysql_conf=app.config["MYSQL_CONF"],
            rag_data_dir=Path(app.config["RAG_DATA_DIR"]),
            rag_api_config=Path(app.config["RAG_API_CONFIG_PATH"]),
            rag_enabled=str(config_map.get("rag_enabled", "1")).strip().lower() in {"1", "true", "yes", "on"},
            rag_top_k=4,
            timeout_sec=120,
        )
        return jsonify({"ok": True, "cluster_id": cluster_id, "ai_status": ai_status, "report": report})

    @app.route("/api/v2/situations", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def situation_list():
        source_ip = request.args.get("source_ip", "").strip()
        status = request.args.get("status", "").strip().lower()
        limit = max(1, min(200, int(request.args.get("limit", "50"))))
        offset = max(0, int(request.args.get("offset", "0")))
        minimum_risk = max(0.0, min(1.0, float(request.args.get("minimum_risk", "0"))))
        store = open_situation_store()
        try:
            items = store.list_situations(
                limit=limit,
                offset=offset,
                source_ip=source_ip,
                status=status,
                minimum_risk=minimum_risk,
            )
        finally:
            store.close()
        return jsonify({"items": normalize_situation_value(items), "limit": limit, "offset": offset})

    @app.route("/api/v2/situations/by-ip/<source_ip>", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def situations_by_ip(source_ip: str):
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            return jsonify({"error": "invalid_source_ip", "message": "来源 IP 格式不正确"}), 400
        store = open_situation_store()
        try:
            items = store.list_situations(limit=200, source_ip=source_ip)
        finally:
            store.close()
        return jsonify({"source_ip": source_ip, "items": normalize_situation_value(items)})

    @app.route("/api/v2/situations/<situation_id>", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def situation_detail(situation_id: str):
        store = open_situation_store()
        try:
            item = store.get_situation(situation_id)
        finally:
            store.close()
        if not item:
            return jsonify({"error": "situation_not_found"}), 404
        return jsonify({"item": normalize_situation_value(item)})

    def load_professional_report_situation(situation_id: str) -> Optional[Dict[str, Any]]:
        store = open_situation_store()
        try:
            return store.get_situation(situation_id)
        finally:
            store.close()

    @app.route("/api/v2/situations/<situation_id>/professional-report", methods=["POST"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def professional_report_create(situation_id: str):
        item = load_professional_report_situation(situation_id)
        if not item:
            return jsonify({"error": "situation_not_found"}), 404
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            job = create_professional_report_job(conn, item, str(g.session.get("username") or "unknown"))
        manager: ProfessionalReportManager = app.config["PROFESSIONAL_REPORT_MANAGER"]
        if job.get("status") in {"queued", "running"}:
            manager.start(str(job["job_id"]))
        return jsonify({"job": normalize_situation_value(public_professional_report_job(job))}), 202

    @app.route("/api/v2/situations/<situation_id>/professional-report", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def professional_report_status(situation_id: str):
        item = load_professional_report_situation(situation_id)
        if not item:
            return jsonify({"error": "situation_not_found"}), 404
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            job = find_professional_report_job(conn, situation_id, str(item.get("sequence_hash") or ""))
        return jsonify({"job": normalize_situation_value(public_professional_report_job(job))})

    @app.route("/api/v2/situations/<situation_id>/professional-report/download", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def professional_report_download(situation_id: str):
        job_id = request.args.get("job_id", "").strip()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            job = get_professional_report_job(conn, job_id) if job_id else find_professional_report_job(conn, situation_id)
        if not job or str(job.get("situation_id")) != situation_id:
            return jsonify({"error": "report_not_found", "message": "尚未生成专业态势报告"}), 404
        if job.get("status") != "completed" or not job.get("pdf_path"):
            return jsonify({"error": "report_not_ready", "message": "专业态势报告仍在生成中"}), 409
        path = Path(str(job["pdf_path"])).resolve()
        report_root = Path(app.config["PROFESSIONAL_REPORT_DIR"]).resolve()
        if report_root not in path.parents or not path.is_file():
            return jsonify({"error": "report_file_missing", "message": "报告文件不存在"}), 404
        return send_file(path, mimetype="application/pdf", as_attachment=True, download_name=f"{situation_id}_专业态势感知报告.pdf")

    @app.route("/api/v2/situations/<situation_id>/graph", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def situation_graph(situation_id: str):
        store = open_situation_store()
        try:
            item = store.get_situation(situation_id)
        finally:
            store.close()
        if not item:
            return jsonify({"error": "situation_not_found"}), 404
        nodes = []
        edges = []
        for index, action in enumerate(item.get("actions") or []):
            action_type = str(action.get("action_type") or "UNKNOWN")
            catalog = ACTION_CATALOG.get(action_type, ACTION_CATALOG["UNKNOWN"])
            node_id = str(action.get("action_id") or f"node-{index + 1}")
            nodes.append(
                {
                    "id": node_id,
                    "sequence": int(action.get("sequence_no") or index + 1),
                    "name": catalog["label"],
                    "action_type": action_type,
                    "stage": action.get("stage") or catalog["stage"],
                    "stage_label": STAGE_LABELS.get(str(action.get("stage") or catalog["stage"]), "其他行为"),
                    "occurred_at": action.get("occurred_at"),
                    "last_seen_at": action.get("last_seen_at"),
                    "count": int(action.get("action_count") or 1),
                    "confidence": float(action.get("confidence") or 0),
                    "gap_seconds": int(action.get("gap_seconds") or 0),
                    "target_interface": action.get("target_interface") or "",
                }
            )
            if index:
                edges.append(
                    {
                        "source": nodes[index - 1]["id"],
                        "target": node_id,
                        "gap_seconds": nodes[index]["gap_seconds"],
                    }
                )
        stages = [
            {"id": key, "name": STAGE_LABELS[key], "order": STAGE_ORDER[key]}
            for key in sorted(STAGE_LABELS, key=lambda value: STAGE_ORDER.get(value, 0))
        ]
        return jsonify(
            normalize_situation_value(
                {
                    "situation_id": situation_id,
                    "source_ip": item.get("source_ip"),
                    "risk_score": item.get("risk_score"),
                    "risk_level": item.get("risk_level"),
                    "nodes": nodes,
                    "edges": edges,
                    "stages": stages,
                }
            )
        )

    @app.route("/api/v2/situations/<situation_id>/evidence", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def situation_evidence(situation_id: str):
        store = open_situation_store()
        try:
            item = store.get_situation(situation_id)
        finally:
            store.close()
        if not item:
            return jsonify({"error": "situation_not_found"}), 404
        evidence = [
            {
                "sequence": action.get("sequence_no"),
                "action_id": action.get("action_id"),
                "action_type": action.get("action_type"),
                "sensor": action.get("sensor"),
                "evidence_refs": action.get("evidence_refs") or [],
                "metadata": action.get("metadata") or {},
            }
            for action in item.get("actions") or []
        ]
        return jsonify(normalize_situation_value({"situation_id": situation_id, "items": evidence}))

    @app.route("/api/v2/situations/<situation_id>/reanalyze", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def situation_reanalyze(situation_id: str):
        store = open_situation_store()
        try:
            item = store.get_situation(situation_id)
            if not item:
                return jsonify({"error": "situation_not_found"}), 404
            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
                config_map = load_system_config_map(conn)
            model = str(config_map.get("llm_model", "qwen2.5:3b")).strip() or "qwen2.5:3b"
            report, ai_status = analyze_situation(
                item,
                ollama_url=app.config["OLLAMA_URL"],
                model=model,
                rag_db_path=Path(app.config["RAG_DB_PATH"]),
                rag_mysql_conf=app.config["MYSQL_CONF"],
                rag_data_dir=Path(app.config["RAG_DATA_DIR"]),
                rag_api_config=Path(app.config["RAG_API_CONFIG_PATH"]),
                rag_enabled=str(config_map.get("rag_enabled", "1")).strip().lower() in {"1", "true", "yes", "on"},
                rag_top_k=4,
                timeout_sec=120,
            )
            store.update_ai_report(situation_id, report, ai_status)
        finally:
            store.close()
        return jsonify({"ok": True, "ai_status": ai_status, "report": report})

    @app.route("/api/v2/situations/<situation_id>/status", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def situation_update_status(situation_id: str):
        body = request.get_json(silent=True) or {}
        status = str(body.get("status") or "").strip().lower()
        store = open_situation_store()
        try:
            changed = store.update_status(situation_id, status)
        except ValueError as exc:
            return jsonify({"error": "invalid_status", "message": str(exc)}), 400
        finally:
            store.close()
        if not changed:
            return jsonify({"error": "situation_not_found"}), 404
        return jsonify({"ok": True, "situation_id": situation_id, "status": status})

    @app.route("/api/v2/situations/stream", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def situation_stream():
        store = open_situation_store()
        try:
            latest = store.list_situations(limit=1)
        finally:
            store.close()
        payload = json.dumps(normalize_situation_value({"items": latest}), ensure_ascii=False)
        return Response(f"retry: 5000\nevent: situations\ndata: {payload}\n\n", mimetype="text/event-stream")

    @app.route("/api/v2/pro/events", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def pro_events():
        try:
            start_dt, end_dt = build_time_range()
        except ValueError as exc:
            return jsonify({"error": "invalid_time_range", "message": str(exc)}), 400

        risk_level = request.args.get("risk_level", "all").strip().lower()
        attack_type = request.args.get("attack_type", "all").strip()
        target_port = request.args.get("target_port", "all").strip()
        process_status = request.args.get("process_status", "all").strip().lower()
        keyword = request.args.get("keyword", "").strip()
        page = max(1, int(request.args.get("page", "1")))
        page_size = max(1, min(int(request.args.get("page_size", "20")), 200))
        offset = (page - 1) * page_size

        where = ["e.occurred_at BETWEEN %s AND %s", visible_attack_event_clause("e")]
        params: List[Any] = [start_dt, end_dt]
        if risk_level != "all":
            where.append("e.risk_level=%s")
            params.append(risk_level)
        if attack_type != "all":
            aliases = attack_type_aliases(attack_type)
            placeholders = ", ".join(["%s"] * len(aliases))
            where.append(f"e.attack_type IN ({placeholders})")
            params.extend(aliases)
        if target_port != "all":
            if not target_port.isdigit() or not 1 <= int(target_port) <= 65535:
                return jsonify({"error": "invalid_target_port"}), 400
            where.append("e.target_port=%s")
            params.append(int(target_port))
        if process_status != "all":
            where.append("e.process_status=%s")
            params.append(process_status)
        if keyword:
            where.append("(e.event_id LIKE %s OR e.source_ip LIKE %s OR e.target_interface LIKE %s)")
            like = f"%{keyword}%"
            params.extend([like, like, like])
        where_sql = " AND ".join(where)

        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) AS c FROM demo_attack_events e WHERE {where_sql}", tuple(params))
                total = int((cur.fetchone() or {}).get("c", 0))
                cur.execute(
                    f"""
                    SELECT
                      e.event_id,
                      e.occurred_at,
                      e.risk_level,
                      e.attack_type,
                      e.source_ip,
                      e.target_port,
                      e.process_status,
                      CASE WHEN b.ip_address IS NULL THEN 0 ELSE 1 END AS ip_blocked
                    FROM demo_attack_events e
                    LEFT JOIN (
                      SELECT ip_address, MAX(blocked_at) AS blocked_at
                      FROM demo_blocked_ips
                      GROUP BY ip_address
                    ) b ON b.ip_address = e.source_ip
                    WHERE {where_sql}
                    ORDER BY e.occurred_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    tuple(params + [page_size, offset]),
                )
                rows = cur.fetchall()
        items = []
        for row in normalize_rows(rows):
            row["attack_type"] = normalize_attack_type_label(row.get("attack_type"))
            row["ip_blocked"] = 1 if row.get("ip_blocked") else 0
            items.append(row)
        return jsonify({"items": items, "page": page, "page_size": page_size, "total": total})

    @app.route("/api/v2/pro/candidates", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def pro_candidates():
        page = max(1, int(request.args.get("page", "1")))
        page_size = max(1, min(int(request.args.get("page_size", "10")), 100))
        q = request.args.get("q", "").strip()
        offset = (page - 1) * page_size
        where = ["c.decision='candidate'"]
        params: List[Any] = []
        if q:
            where.append("(c.event_id LIKE %s OR c.case_id LIKE %s OR c.source_ip LIKE %s OR c.target_interface LIKE %s)")
            like = f"%{q}%"
            params.extend([like, like, like, like])
        where_sql = " AND ".join(where)

        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                if not db_table_exists(cur, "detection_candidates"):
                    return jsonify({"items": [], "page": page, "page_size": page_size, "total": 0})
                cur.execute(f"SELECT COUNT(*) AS c FROM detection_candidates c WHERE {where_sql}", tuple(params))
                total = int((cur.fetchone() or {}).get("c", 0))
                cur.execute(
                    f"""
                    SELECT
                      c.event_id, c.case_id, c.file_id, c.seq_id, c.decision, c.final_score,
                      c.risk_level, c.attack_type, c.source_ip, c.target_interface, c.created_at,
                      r.method, r.host, r.status_code
                    FROM detection_candidates c
                    LEFT JOIN raw_http_logs r ON r.case_id = c.case_id
                    WHERE {where_sql}
                    ORDER BY c.final_score DESC, c.created_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    tuple(params + [page_size, offset]),
                )
                rows = cur.fetchall()
        items = []
        for row in normalize_rows(rows):
            row["attack_type"] = normalize_attack_type_label(row.get("attack_type"))
            items.append(row)
        return jsonify({"items": items, "page": page, "page_size": page_size, "total": total})

    @app.route("/api/v2/pro/candidates/<event_id>", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def pro_candidate_detail(event_id: str):
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                detail = load_v2_detection_detail(cur, event_id)
            if not detail:
                return jsonify({"error": "candidate_not_found"}), 404
            raw = detail.get("raw_http") or {}
            source_region = resolve_region_for_event(conn, str(detail.get("source_ip") or ""), "")
        item = {
            "event_id": detail.get("event_id") or event_id,
            "occurred_at": raw.get("event_time") or raw.get("created_at") or "-",
            "risk_level": detail.get("risk_level") or "medium",
            "attack_type": normalize_attack_type_label(detail.get("attack_type")),
            "source_ip": detail.get("source_ip") or raw.get("source_ip") or "-",
            "source_region": source_region,
            "target_node": "candidate-review",
            "target_interface": detail.get("target_interface") or raw.get("uri") or "-",
            "attack_result": "pending",
            "process_status": "unprocessed",
            "attack_payload": raw.get("request_text") or "",
            "request_log": raw.get("request_text") or "",
            "protection_action": "候选事件暂未进入大屏告警，等待人工复核。",
            "handling_suggestion": "查看 Payload/POC/行为证据，确认后可提升为攻击事件，误报则忽略候选。",
            "note": "",
            "response_ms": 0,
            "ip_blocked": 0,
            "v2_detection": detail,
        }
        return jsonify(item)

    @app.route("/api/v2/pro/candidates/<event_id>/ignore", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def pro_candidate_ignore(event_id: str):
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                if not db_table_exists(cur, "detection_candidates"):
                    return jsonify({"error": "candidate_not_found"}), 404
                cur.execute("SELECT event_id, case_id FROM detection_candidates WHERE event_id=%s LIMIT 1", (event_id,))
                row = cur.fetchone()
                if not row:
                    return jsonify({"error": "candidate_not_found"}), 404
                cur.execute(
                    "UPDATE detection_candidates SET decision='raw_only', risk_level='info' WHERE event_id=%s",
                    (event_id,),
                )
                cur.execute("DELETE FROM attack_events WHERE event_id=%s", (event_id,))
                log_action(conn, g.session["username"], g.session["role"], "candidate_ignore", event_id, str(row.get("case_id") or ""))
            conn.commit()
        return jsonify({"ok": True, "event_id": event_id})

    @app.route("/api/v2/pro/candidates/<event_id>/promote", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def pro_candidate_promote(event_id: str):
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                detail = load_v2_detection_detail(cur, event_id)
                if not detail:
                    return jsonify({"error": "candidate_not_found"}), 404
                raw = detail.get("raw_http") or {}
                event_key = str(detail.get("event_id") or event_id)[:40]
                risk_level = str(detail.get("risk_level") or "medium")[:16]
                attack_type = normalize_attack_type_label(detail.get("attack_type"))[:64]
                source_ip = str(detail.get("source_ip") or raw.get("source_ip") or "unknown")[:64]
                source_region = resolve_region_for_event(conn, source_ip, "")
                target_interface = str(detail.get("target_interface") or raw.get("uri") or "-")[:255]
                occurred_at = raw.get("event_time") or raw.get("created_at") or dt_to_str(now_dt())
                cur.execute(
                    """
                    INSERT INTO attack_events(event_id, case_id, occurred_at, source_ip, target_interface, attack_type,
                                              risk_level, confidence, status, evidence_json)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON DUPLICATE KEY UPDATE
                      attack_type=VALUES(attack_type),
                      risk_level=VALUES(risk_level),
                      confidence=VALUES(confidence),
                      evidence_json=VALUES(evidence_json)
                    """,
                    (
                        event_key,
                        detail.get("case_id"),
                        occurred_at,
                        source_ip,
                        target_interface,
                        attack_type,
                        risk_level,
                        detail.get("final_score"),
                        "unprocessed",
                        json.dumps(detail.get("evidence") or [], ensure_ascii=False),
                    ),
                )
                cur.execute(
                    "UPDATE detection_candidates SET decision='attack_event' WHERE event_id=%s",
                    (event_key,),
                )
                cur.execute(
                    """
                    INSERT INTO demo_attack_events(
                      event_id, occurred_at, risk_level, attack_type, source_ip, source_region, target_node, target_interface,
                      attack_result, process_status, acked, attack_payload, request_log, protection_action, handling_suggestion,
                      note, response_ms, anomaly_detected, machine_id
                    )
                    VALUES(
                      %s, COALESCE(STR_TO_DATE(%s, '%%Y-%%m-%%dT%%H:%%i:%%s'), NOW(3)), %s, %s, %s, %s, %s, %s,
                      %s, %s, 0, %s, %s, %s, %s, '', 0, 1, NULL
                    )
                    ON DUPLICATE KEY UPDATE
                      risk_level=VALUES(risk_level),
                      attack_type=VALUES(attack_type),
                      source_ip=VALUES(source_ip),
                      source_region=VALUES(source_region),
                      target_interface=VALUES(target_interface),
                      attack_payload=VALUES(attack_payload),
                      request_log=VALUES(request_log),
                      protection_action=VALUES(protection_action),
                      handling_suggestion=VALUES(handling_suggestion),
                      anomaly_detected=1
                    """,
                    (
                        event_key,
                        str(occurred_at or ""),
                        risk_level,
                        attack_type,
                        source_ip,
                        source_region,
                        "candidate-review",
                        target_interface,
                        "blocked",
                        "unprocessed",
                        str(raw.get("request_text") or "")[:20000],
                        str(raw.get("request_text") or "")[:20000],
                        "候选事件已由管理员提升为攻击事件。",
                        "建议进一步核查来源 IP、请求载荷和业务接口日志。",
                    ),
                )
                log_action(conn, g.session["username"], g.session["role"], "candidate_promote", event_key, str(detail.get("case_id") or ""))
            conn.commit()
        return jsonify({"ok": True, "event_id": event_id})

    @app.route("/api/v2/pro/events/<event_id>", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def pro_event_detail(event_id: str):
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                      e.event_id, e.occurred_at, e.risk_level, e.attack_type, e.source_ip, e.source_region,
                      e.target_port, e.target_interface, e.process_status, e.attack_payload,
                      e.request_log, e.protection_action, e.handling_suggestion, e.note, e.response_ms, e.anomaly_detected,
                      CASE WHEN b.ip_address IS NULL THEN 0 ELSE 1 END AS ip_blocked,
                      b.blocked_at AS ip_blocked_at
                    FROM demo_attack_events e
                    LEFT JOIN (
                      SELECT ip_address, MAX(blocked_at) AS blocked_at
                      FROM demo_blocked_ips
                      GROUP BY ip_address
                    ) b ON b.ip_address = e.source_ip
                    WHERE e.event_id=%s
                    LIMIT 1
                    """,
                    (event_id,),
                )
                row = cur.fetchone()
        if not row:
            return jsonify({"error": "event_not_found"}), 404
        item = normalize_row(row)
        item["attack_type"] = normalize_attack_type_label(item.get("attack_type"))
        item["ip_blocked"] = 1 if item.get("ip_blocked") else 0
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            item["source_region"] = resolve_region_for_event(
                conn,
                str(item.get("source_ip") or ""),
                str(item.get("source_region") or ""),
            )
            with conn.cursor() as cur:
                item["v2_detection"] = load_v2_detection_detail(cur, event_id)
        return jsonify(item)

    @app.route("/api/v2/pro/events/<event_id>/block-ip", methods=["POST"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def pro_block_ip(event_id: str):
        body = request.get_json(silent=True) or {}
        reason = str(body.get("reason", "")).strip()
        if not reason:
            reason = "manual_block_from_ui"
        block_mode = str(body.get("block_mode", "source") or "source").strip().lower()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT source_ip, request_log FROM demo_attack_events WHERE event_id=%s LIMIT 1", (event_id,))
                row = cur.fetchone()
                if not row:
                    return jsonify({"error": "event_not_found"}), 404
                source_ip = str(row.get("source_ip") or "").strip()
                request_log = str(row.get("request_log") or "")
                block_ips, block_meta = collect_event_block_ips(cur, event_id, source_ip, request_log, block_mode)
                if not block_ips:
                    return jsonify({"error": "source_ip_not_found", "message": "未识别到可封禁的来源IP"}), 400
                applied: List[str] = []
                existed_count = 0
                for ip_text in block_ips:
                    fw_ok, fw_detail = firewall_block_ip(ip_text)
                    if not fw_ok:
                        for rollback_ip in applied:
                            firewall_unblock_ip(rollback_ip)
                        return jsonify(
                            {
                                "error": "firewall_block_failed",
                                "message": "系统防火墙封禁失败，请使用管理员权限启动服务后重试",
                                "detail": fw_detail,
                                "failed_ip": ip_text,
                                "source_ip": block_meta.get("source_ip") or source_ip,
                                "blocked_ips": block_ips,
                                "block_mode": block_meta.get("mode"),
                            }
                        ), 500
                    applied.append(ip_text)
                for ip_text in block_ips:
                    cur.execute("SELECT id FROM demo_blocked_ips WHERE ip_address=%s LIMIT 1", (ip_text,))
                    if cur.fetchone():
                        existed_count += 1
                    cur.execute(
                        """
                        INSERT INTO demo_blocked_ips(ip_address, source_event_id, reason, blocked_by, blocked_role)
                        VALUES (%s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                          source_event_id=VALUES(source_event_id),
                          reason=VALUES(reason),
                          blocked_by=VALUES(blocked_by),
                          blocked_role=VALUES(blocked_role),
                          blocked_at=CURRENT_TIMESTAMP
                        """,
                        (ip_text, event_id, reason[:255], g.session["username"], g.session["role"]),
                    )
                log_action(
                    conn,
                    g.session["username"],
                    g.session["role"],
                    "block_ip",
                    ",".join(block_ips),
                    f"event_id={event_id},mode={block_meta.get('mode')},reason={reason[:120]}",
                )
            conn.commit()
        return jsonify(
            {
                "ok": True,
                "event_id": event_id,
                "source_ip": block_meta.get("source_ip") or source_ip,
                "blocked_ips": block_ips,
                "blocked_count": len(block_ips),
                "block_mode": block_meta.get("mode"),
                "already_blocked_count": existed_count,
            }
        )

    @app.route("/api/v2/pro/events/<event_id>/unblock-ip", methods=["POST"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def pro_unblock_ip(event_id: str):
        body = request.get_json(silent=True) or {}
        reason = str(body.get("reason", "")).strip()
        if not reason:
            reason = "manual_unblock_from_ui"
        block_mode = str(body.get("block_mode", "source") or "source").strip().lower()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT source_ip, request_log FROM demo_attack_events WHERE event_id=%s LIMIT 1", (event_id,))
                row = cur.fetchone()
                if not row:
                    return jsonify({"error": "event_not_found"}), 404
                source_ip = str(row.get("source_ip") or "").strip()
                request_log = str(row.get("request_log") or "")
                event_ips, block_meta = collect_event_block_ips(cur, event_id, source_ip, request_log, block_mode)
                cur.execute("SELECT ip_address FROM demo_blocked_ips WHERE source_event_id=%s", (event_id,))
                db_rows = cur.fetchall() or []
                unblock_ips: List[str] = []
                for ip_text in [*(r.get("ip_address") for r in db_rows), *event_ips]:
                    ip_norm = normalize_ip_literal(ip_text)
                    if ip_norm and ip_norm not in unblock_ips:
                        unblock_ips.append(ip_norm)
                if not unblock_ips:
                    return jsonify(
                        {
                            "ok": True,
                            "event_id": event_id,
                            "source_ip": block_meta.get("source_ip") or source_ip,
                            "unblocked_ips": [],
                            "deleted_rows": 0,
                            "block_mode": block_meta.get("mode"),
                        }
                    )
                failed: List[Dict[str, str]] = []
                for ip_text in unblock_ips:
                    fw_ok, fw_detail = firewall_unblock_ip(ip_text)
                    if not fw_ok:
                        failed.append({"ip": ip_text, "detail": fw_detail})
                if failed:
                    return jsonify(
                        {
                            "error": "firewall_unblock_failed",
                            "message": "系统防火墙解封失败，请使用管理员权限启动服务后重试",
                            "failed": failed,
                            "source_ip": block_meta.get("source_ip") or source_ip,
                            "unblocked_ips": unblock_ips,
                            "block_mode": block_meta.get("mode"),
                        }
                    ), 500
                placeholders = ",".join(["%s"] * len(unblock_ips))
                cur.execute(f"DELETE FROM demo_blocked_ips WHERE ip_address IN ({placeholders})", tuple(unblock_ips))
                changed = int(cur.rowcount or 0)
                for ip_text in unblock_ips:
                    record_auto_defense_release(cur, ip_text, g.session["username"])
                log_action(
                    conn,
                    g.session["username"],
                    g.session["role"],
                    "unblock_ip",
                    ",".join(unblock_ips),
                    f"event_id={event_id},mode={block_meta.get('mode')},reason={reason[:120]}",
                )
            conn.commit()
        return jsonify(
            {
                "ok": True,
                "event_id": event_id,
                "source_ip": block_meta.get("source_ip") or source_ip,
                "unblocked_ips": unblock_ips,
                "unblocked_count": len(unblock_ips),
                "deleted_rows": changed,
                "block_mode": block_meta.get("mode"),
            }
        )

    @app.route("/api/v2/defense/status", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def defense_status():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            config = load_system_config_map(conn)
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS c FROM demo_blocked_ips")
                blocked_count = int((cur.fetchone() or {}).get("c", 0))
        return jsonify(
            {
                "enabled": config.get("auto_defense_enabled", "0") == "1",
                "minimum_risk": config.get("auto_defense_min_risk", "critical"),
                "allow_private": config.get("auto_defense_allow_private", "0") == "1",
                "blocked_count": blocked_count,
                "enforcement": "windows_firewall_bidirectional",
                "platform_supported": os.name == "nt",
                "poll_seconds": 5,
            }
        )

    @app.route("/api/v2/defense/config", methods=["PUT"])
    @require_roles(ROLE_ADMIN)
    def defense_config_update():
        body = request.get_json(silent=True) or {}
        enabled = bool(body.get("enabled"))
        minimum_risk = str(body.get("minimum_risk", "critical")).strip().lower()
        allow_private = bool(body.get("allow_private", False))
        if minimum_risk not in {"high", "critical"}:
            return jsonify({"error": "invalid_minimum_risk"}), 400
        values = {
            "auto_defense_enabled": "1" if enabled else "0",
            "auto_defense_min_risk": minimum_risk,
            "auto_defense_allow_private": "1" if allow_private else "0",
        }
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                for key, value in values.items():
                    cur.execute(
                        """INSERT INTO demo_system_config(config_key,config_value)
                           VALUES(%s,%s) ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)""",
                        (key, value),
                    )
                log_action(
                    conn,
                    g.session["username"],
                    g.session["role"],
                    "update_auto_defense",
                    "windows_firewall",
                    json.dumps(values, ensure_ascii=False),
                )
            conn.commit()
        return jsonify({"ok": True, "enabled": enabled, "minimum_risk": minimum_risk, "allow_private": allow_private})

    @app.route("/api/v2/pro/blocked-ips", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def pro_blocked_ips():
        q = request.args.get("q", "").strip()
        page = max(1, int(request.args.get("page", "1")))
        page_size = max(1, min(int(request.args.get("page_size", "20")), 200))
        offset = (page - 1) * page_size

        where: List[str] = []
        params: List[Any] = []
        if q:
            where.append("(b.ip_address LIKE %s OR b.source_event_id LIKE %s OR b.reason LIKE %s OR b.blocked_by LIKE %s)")
            like = f"%{q}%"
            params.extend([like, like, like, like])
        where_sql = ("WHERE " + " AND ".join(where)) if where else ""

        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) AS c FROM demo_blocked_ips b {where_sql}", tuple(params))
                total = int((cur.fetchone() or {}).get("c", 0))
                cur.execute(
                    f"""
                    SELECT
                      b.id,
                      b.ip_address,
                      b.source_event_id,
                      b.reason,
                      b.blocked_by,
                      b.blocked_role,
                      b.blocked_at
                    FROM demo_blocked_ips b
                    {where_sql}
                    ORDER BY b.blocked_at DESC, b.id DESC
                    LIMIT %s OFFSET %s
                    """,
                    tuple(params + [page_size, offset]),
                )
                rows = list(cur.fetchall())
        firewall_states = verified_firewall_status_many([str(row.get("ip_address") or "") for row in rows])
        for row in rows:
            status = firewall_states.get(str(row.get("ip_address") or ""), {})
            row["firewall_active"] = bool(status.get("active"))
            row["inbound_active"] = bool(status.get("inbound"))
            row["outbound_active"] = bool(status.get("outbound"))
        return jsonify({"items": normalize_rows(rows), "page": page, "page_size": page_size, "total": total})

    @app.route("/api/v2/pro/blocked-ips/unblock", methods=["POST"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def pro_blocked_ips_unblock():
        body = request.get_json(silent=True) or {}
        ip_text = normalize_ip_literal(body.get("ip_address"))
        reason = str(body.get("reason", "")).strip() or "manual_unblock_from_blocked_list"
        if not ip_text:
            return jsonify({"error": "invalid_ip_address"}), 400
        fw_ok, fw_detail = firewall_unblock_ip(ip_text)
        if not fw_ok:
            return jsonify(
                {
                    "error": "firewall_unblock_failed",
                    "message": "系统防火墙解封失败，请使用管理员权限启动服务后重试",
                    "detail": fw_detail,
                    "ip_address": ip_text,
                }
            ), 500
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM demo_blocked_ips WHERE ip_address=%s", (ip_text,))
                changed = int(cur.rowcount or 0)
                record_auto_defense_release(cur, ip_text, g.session["username"])
                log_action(
                    conn,
                    g.session["username"],
                    g.session["role"],
                    "unblock_ip_direct",
                    ip_text,
                    f"reason={reason[:120]}",
                )
            conn.commit()
        return jsonify({"ok": True, "ip_address": ip_text, "deleted_rows": changed})

    @app.route("/api/v2/pro/events/batch-status", methods=["POST"])
    @require_roles(ROLE_ADMIN)
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
    @require_roles(ROLE_ADMIN)
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
    @require_roles(ROLE_ADMIN)
    def pro_model_performance():
        visible_sql = visible_attack_event_clause()
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
                    f"""
                    SELECT
                      SUM(CASE WHEN response_ms < 100 THEN 1 ELSE 0 END) AS lt_100,
                      SUM(CASE WHEN response_ms >= 100 AND response_ms < 300 THEN 1 ELSE 0 END) AS b100_300,
                      SUM(CASE WHEN response_ms >= 300 AND response_ms < 800 THEN 1 ELSE 0 END) AS b300_800,
                      SUM(CASE WHEN response_ms >= 800 THEN 1 ELSE 0 END) AS ge_800
                    FROM demo_attack_events
                    WHERE occurred_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) AND {visible_sql}
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
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def pro_node_detail(node_name: str):
        visible_sql = visible_attack_event_clause()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM demo_machines WHERE machine_name=%s LIMIT 1", (node_name,))
                machine = cur.fetchone()
                if not machine:
                    return jsonify({"error": "node_not_found"}), 404
                cur.execute(
                    f"""
                    SELECT COUNT(*) AS total_7d,
                           SUM(CASE WHEN attack_result='blocked' THEN 1 ELSE 0 END) AS blocked_7d,
                           SUM(CASE WHEN risk_level IN ('critical','high') THEN 1 ELSE 0 END) AS high_7d
                    FROM demo_attack_events
                    WHERE target_node=%s AND occurred_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) AND {visible_sql}
                    """,
                    (node_name,),
                )
                stats = cur.fetchone() or {}
                cur.execute(
                    f"""
                    SELECT event_id, occurred_at, risk_level, attack_type, source_ip, attack_result, process_status
                    FROM demo_attack_events
                    WHERE target_node=%s AND {visible_sql}
                    ORDER BY occurred_at DESC
                    LIMIT 50
                    """,
                    (node_name,),
                )
                events = cur.fetchall()
        return jsonify({"machine": normalize_row(machine), "stats": normalize_row(stats), "recent_events": normalize_rows(events)})

    @app.route("/api/v2/admin/users", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def admin_users_list():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, username, role, display_name, nickname, avatar_url, created_at, updated_at
                    FROM demo_users
                    WHERE role IN (%s, %s)
                    ORDER BY CASE role
                        WHEN %s THEN 1
                        WHEN %s THEN 2
                        ELSE 3
                    END, username
                    """,
                    (ROLE_NORMAL, ROLE_ADMIN, ROLE_ADMIN, ROLE_NORMAL),
                )
                rows = cur.fetchall()
        return jsonify({"items": normalize_rows(rows)})

    @app.route("/api/v2/admin/users/<username>/profile", methods=["PUT"])
    @require_roles(ROLE_ADMIN)
    def admin_user_update_profile(username: str):
        body = request.get_json(silent=True) or {}
        display_name = normalize_profile_text(body.get("display_name"), username, 64)
        nickname = normalize_profile_text(body.get("nickname"), display_name, 64)
        avatar_url = normalize_avatar_url(body.get("avatar_url") or "")
        role = str(body.get("role", "")).strip().lower()
        if role and role not in {ROLE_NORMAL, ROLE_ADMIN}:
            return jsonify({"error": "invalid_role", "message": "角色只能设置为普通用户或管理员"}), 400
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, role FROM demo_users WHERE username=%s AND role IN (%s, %s) LIMIT 1",
                    (username, ROLE_NORMAL, ROLE_ADMIN),
                )
                exists = cur.fetchone()
                if not exists:
                    return jsonify({"error": "user_not_found"}), 404
                next_role = role or str(exists.get("role") or ROLE_NORMAL)
                if username == g.session["username"] and next_role != g.session["role"]:
                    return jsonify({"error": "self_role_change_not_allowed", "message": "不能修改当前登录账号自己的角色"}), 400
                cur.execute(
                    """
                    UPDATE demo_users
                    SET display_name=%s, nickname=%s, avatar_url=%s, role=%s
                    WHERE username=%s AND role IN (%s, %s)
                    """,
                    (display_name, nickname, avatar_url, next_role, username, ROLE_NORMAL, ROLE_ADMIN),
                )
                log_action(
                    conn,
                    g.session["username"],
                    g.session["role"],
                    "admin_update_user_profile",
                    username,
                    f"profile_updated role={next_role}",
                )
            conn.commit()
        return jsonify({"ok": True, "username": username})

    @app.route("/api/v2/admin/users/<username>/password", methods=["PUT"])
    @require_roles(ROLE_ADMIN)
    def admin_user_change_password(username: str):
        body = request.get_json(silent=True) or {}
        new_password = str(body.get("new_password", "")).strip()
        if not new_password:
            return jsonify({"error": "new_password_required"}), 400
        if len(new_password) < 4:
            return jsonify({"error": "new_password_too_short"}), 400
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM demo_users WHERE username=%s AND role IN (%s, %s) LIMIT 1",
                    (username, ROLE_NORMAL, ROLE_ADMIN),
                )
                exists = cur.fetchone()
                if not exists:
                    return jsonify({"error": "user_not_found"}), 404
                cur.execute("UPDATE demo_users SET password=%s WHERE username=%s", (new_password, username))
                log_action(
                    conn,
                    g.session["username"],
                    g.session["role"],
                    "admin_change_user_password",
                    username,
                    "updated",
                )
            conn.commit()
        return jsonify({"ok": True, "username": username})

    @app.route("/api/v2/admin/summary", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def admin_summary():
        visible_sql = visible_attack_event_clause()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            refresh_machine_stats(conn)
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS c FROM demo_machines WHERE online_status='online'")
                online_count = int((cur.fetchone() or {}).get("c", 0))
                cur.execute(f"SELECT COUNT(*) AS c FROM demo_attack_events WHERE DATE(occurred_at)=CURDATE() AND {visible_sql}")
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
        visible_sql = visible_attack_event_clause()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT target_node AS machine_name, COUNT(*) AS attack_total
                    FROM demo_attack_events
                    WHERE DATE(occurred_at)=CURDATE() AND {visible_sql}
                    GROUP BY target_node
                    ORDER BY attack_total DESC
                    """
                )
                rows = cur.fetchall()
        return jsonify({"items": normalize_rows(rows)})

    @app.route("/api/v2/admin/trend7d", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def admin_trend7d():
        visible_sql = visible_attack_event_clause()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT DATE(occurred_at) AS d, COUNT(*) AS total
                    FROM demo_attack_events
                    WHERE occurred_at >= DATE_SUB(CURDATE(), INTERVAL 6 DAY) AND {visible_sql}
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
        visible_sql = visible_attack_event_clause()
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM demo_machines WHERE id=%s LIMIT 1", (machine_id,))
                machine = cur.fetchone()
                if not machine:
                    return jsonify({"error": "machine_not_found"}), 404
                cur.execute(
                    f"""
                    SELECT event_id, occurred_at, risk_level, attack_type, source_ip, target_interface, attack_result, process_status
                    FROM demo_attack_events
                    WHERE machine_id=%s AND {visible_sql}
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

    @app.route("/api/v2/common/home-background", methods=["GET"])
    def common_home_background():
        url = DEFAULT_HOMEPAGE_BACKGROUND
        try:
            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
                cfg = load_system_config_map(conn)
                url = normalize_homepage_background_url(cfg.get("homepage_background_url", DEFAULT_HOMEPAGE_BACKGROUND))
        except Exception:
            url = DEFAULT_HOMEPAGE_BACKGROUND
        return jsonify({"url": url})

    @app.route("/api/v2/admin/home-background", methods=["POST"])
    @require_roles(ROLE_ADMIN)
    def admin_home_background_upload():
        upload = request.files.get("file")
        if upload is None:
            return jsonify({"error": "missing_file", "message": "请选择要上传的背景图片"}), 400
        data = upload.read()
        if not data:
            return jsonify({"error": "empty_file", "message": "图片文件为空"}), 400
        if len(data) > MAX_BACKGROUND_BYTES:
            return jsonify({"error": "file_too_large", "message": "图片不能超过 10MB"}), 413
        ext = detect_background_extension(upload.filename or "", upload.content_type or "", data[:64])
        if not ext:
            return jsonify({"error": "invalid_image", "message": "仅支持 JPG、PNG、WebP 图片"}), 400

        DASHBOARD_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        filename = f"homepage_background_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}.{ext}"
        target = DASHBOARD_UPLOAD_DIR / filename
        target.write_bytes(data)
        url = f"/uploads/{filename}"

        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO demo_system_config(config_key, config_value)
                    VALUES ('homepage_background_url', %s)
                    ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)
                    """,
                    (url,),
                )
                log_action(conn, g.session["username"], g.session["role"], "update_background", "homepage", url)
            conn.commit()
        return jsonify({"ok": True, "url": url})

    @app.route("/api/v2/admin/ollama/models", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def admin_ollama_models():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            cfg = load_system_config_map(conn)
        current_model = str(cfg.get("llm_model", "qwen3:8b")).strip() or "qwen3:8b"
        model_info = list_ollama_models(app.config.get("OLLAMA_URL", "http://127.0.0.1:11434"))
        return jsonify(
            {
                "ok": bool(model_info.get("ok")),
                "items": model_info.get("models", []),
                "current_model": current_model,
                "ollama_url": model_info.get("ollama_url"),
                "error": model_info.get("error", ""),
            }
        )

    @app.route("/api/v2/admin/capture-interfaces", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def admin_capture_interfaces():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            cfg = load_system_config_map(conn)
        configured = str(cfg.get("capture_interface", "auto")).strip() or "auto"
        info = list_tshark_interfaces()
        items = info.get("items", [])
        resolved_index, resolved_name = resolve_capture_interface(configured, items)
        return jsonify(
            {
                "ok": bool(info.get("ok")),
                "items": items,
                "configured_interface": configured,
                "resolved_interface_index": resolved_index,
                "resolved_interface_name": resolved_name,
                "tshark_path": info.get("path", ""),
                "error": info.get("error", ""),
            }
        )

    @app.route("/api/v2/admin/runtime-check", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def admin_runtime_check():
        checks: List[Dict[str, Any]] = []
        errors = 0
        warnings = 0
        config_map: Dict[str, str] = {}

        try:
            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
                config_map = load_system_config_map(conn)
                with conn.cursor() as cur:
                    cur.execute("SELECT 1 AS ok")
                    cur.fetchone()
                    cur.execute("SHOW TABLES")
                    table_rows = cur.fetchall()
            table_count = len(table_rows)
            checks.append({"name": "MySQL连接", "status": "ok", "message": "连接成功", "detail": f"已检测到 {table_count} 张表"})
        except Exception as exc:  # noqa: BLE001
            errors += 1
            checks.append({"name": "MySQL连接", "status": "error", "message": "连接失败", "detail": str(exc)})

        tshark_info = list_tshark_interfaces()
        tshark_path = str(tshark_info.get("path") or "")
        interface_items = tshark_info.get("items") if isinstance(tshark_info.get("items"), list) else []
        if not tshark_info.get("ok"):
            errors += 1
            checks.append(
                {
                    "name": "抓包依赖",
                    "status": "error",
                    "message": "tshark 不可用",
                    "detail": str(tshark_info.get("error") or "请安装 Wireshark + Npcap，并确保 tshark 在 PATH 中"),
                }
            )
        else:
            checks.append({"name": "抓包依赖", "status": "ok", "message": "tshark可用", "detail": tshark_path})
            checks.append(
                {
                    "name": "抓包网卡",
                    "status": "ok" if interface_items else "warn",
                    "message": f"检测到 {len(interface_items)} 个网卡",
                    "detail": "；".join([f"{x.get('index')}. {x.get('name')}" for x in interface_items[:8]]) or "未检测到网卡",
                }
            )

        ollama_exe = shutil.which("ollama")
        if not ollama_exe:
            errors += 1
            checks.append(
                {
                    "name": "Ollama客户端",
                    "status": "error",
                    "message": "未找到 ollama 命令",
                    "detail": "请先安装 Ollama 客户端",
                }
            )
        else:
            checks.append({"name": "Ollama客户端", "status": "ok", "message": "ollama可用", "detail": ollama_exe})

        selected_model = str(config_map.get("llm_model", "qwen3:8b")).strip() or "qwen3:8b"
        model_info = list_ollama_models(app.config.get("OLLAMA_URL", "http://127.0.0.1:11434"))
        if not model_info.get("ok"):
            errors += 1
            checks.append(
                {
                    "name": "Ollama服务",
                    "status": "error",
                    "message": "服务不可达",
                    "detail": str(model_info.get("error") or "unknown error"),
                }
            )
        else:
            names = {str(x.get("name", "")).strip() for x in model_info.get("models", [])}
            if selected_model in names:
                checks.append(
                    {
                        "name": "LLM模型",
                        "status": "ok",
                        "message": "模型已安装",
                        "detail": f"当前模型：{selected_model}",
                    }
                )
            else:
                warnings += 1
                checks.append(
                    {
                        "name": "LLM模型",
                        "status": "warn",
                        "message": "当前模型未安装",
                        "detail": f"配置模型：{selected_model}，请执行：ollama pull {selected_model}",
                    }
                )
            checks.append(
                {
                    "name": "Ollama服务",
                    "status": "ok",
                    "message": "服务正常",
                    "detail": f"地址：{model_info.get('ollama_url')}，已发现 {len(model_info.get('models', []))} 个模型",
                }
            )

        pre_path, mdl_path = resolve_legacy_model_artifacts()
        if pre_path.exists() and mdl_path.exists():
            checks.append(
                {
                    "name": "检测模型文件",
                    "status": "ok",
                    "message": "兼容模型文件可用",
                    "detail": f"pre={pre_path} ; model={mdl_path}",
                }
            )
        else:
            errors += 1
            missing = []
            if not pre_path.exists():
                missing.append(str(pre_path))
            if not mdl_path.exists():
                missing.append(str(mdl_path))
            checks.append(
                {
                    "name": "检测模型文件",
                    "status": "error",
                    "message": "缺少兼容模型文件",
                    "detail": " ; ".join(missing),
                }
            )

        monitor_ports = str(config_map.get("monitor_ports", "80,443,8080")).strip()
        batch_size = str(config_map.get("capture_batch_size", "4")).strip()
        configured_interface = str(config_map.get("capture_interface", "auto")).strip() or "auto"
        resolved_idx, resolved_name = resolve_capture_interface(configured_interface, interface_items)
        if tshark_info.get("ok"):
            if configured_interface not in {"", "auto", "default", "自动"} and not resolved_idx:
                warnings += 1
                checks.append(
                    {
                        "name": "抓包配置",
                        "status": "warn",
                        "message": "当前网卡配置未匹配到可用网卡",
                        "detail": f"capture_interface={configured_interface}",
                    }
                )
            elif resolved_idx:
                probe = probe_capture_on_interface(resolved_idx, monitor_ports)
                if probe.get("ok"):
                    checks.append(
                        {
                            "name": "抓包检测",
                            "status": "ok",
                            "message": "短时抓包探测成功",
                            "detail": f"网卡={resolved_idx}. {resolved_name}，端口={monitor_ports}",
                        }
                    )
                else:
                    errors += 1
                    checks.append(
                        {
                            "name": "抓包检测",
                            "status": "error",
                            "message": "短时抓包探测失败",
                            "detail": str(probe.get("detail") or probe.get("error") or "unknown"),
                        }
                    )
        checks.append(
            {
                "name": "系统配置",
                "status": "ok",
                "message": "读取成功",
                "detail": (
                    f"监测端口={monitor_ports}，分组数量={batch_size}，网卡={configured_interface}，模型={selected_model}；"
                    f"态势动作阈值={config_map.get('situation_minimum_actions', '3')}，"
                    f"关联窗口={config_map.get('situation_window_minutes', '30')}分钟，"
                    f"扫描端口阈值={config_map.get('scan_port_threshold', '10')}"
                ),
            }
        )

        overall = "ok"
        if errors > 0:
            overall = "error"
        elif warnings > 0:
            overall = "warn"
        return jsonify(
            {
                "overall": overall,
                "errors": errors,
                "warnings": warnings,
                "checks": checks,
                "selected_model": selected_model,
                "ollama_url": model_info.get("ollama_url", app.config.get("OLLAMA_URL")),
            }
        )

    @app.route("/api/v2/admin/config", methods=["PUT"])
    @require_roles(ROLE_ADMIN)
    def admin_config_put():
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict) or not body:
            return jsonify({"error": "invalid_payload"}), 400
        normalized: Dict[str, str] = {}
        for key, value in body.items():
            cfg_key = str(key).strip()
            cfg_val = str(value).strip()
            if not cfg_key:
                continue
            if cfg_key == "capture_batch_size":
                try:
                    v = int(cfg_val)
                except ValueError:
                    return jsonify({"error": "invalid_capture_batch_size"}), 400
                if v < 1 or v > 128:
                    return jsonify({"error": "invalid_capture_batch_size"}), 400
                cfg_val = str(v)
            elif cfg_key == "monitor_ports":
                raw_parts = [x for x in re.split(r"[\s,]+", cfg_val) if x]
                if not raw_parts:
                    return jsonify({"error": "invalid_monitor_ports"}), 400
                seen = set()
                ports: List[int] = []
                for item in raw_parts:
                    if not item.isdigit():
                        return jsonify({"error": "invalid_monitor_ports"}), 400
                    port = int(item)
                    if port < 1 or port > 65535:
                        return jsonify({"error": "invalid_monitor_ports"}), 400
                    if port not in seen:
                        seen.add(port)
                        ports.append(port)
                cfg_val = ",".join(str(p) for p in ports)
            elif cfg_key == "auto_refresh_seconds":
                try:
                    v = int(cfg_val)
                except ValueError:
                    return jsonify({"error": "invalid_auto_refresh_seconds"}), 400
                if v < 1 or v > 3600:
                    return jsonify({"error": "invalid_auto_refresh_seconds"}), 400
                cfg_val = str(v)
            elif cfg_key == "alert_threshold_high":
                try:
                    v = int(cfg_val)
                except ValueError:
                    return jsonify({"error": "invalid_alert_threshold_high"}), 400
                if v < 1 or v > 100000:
                    return jsonify({"error": "invalid_alert_threshold_high"}), 400
                cfg_val = str(v)
            elif cfg_key in {"sound_alert_enabled", "llm_realtime_enabled"}:
                if cfg_val not in {"0", "1"}:
                    return jsonify({"error": f"invalid_{cfg_key}"}), 400
            elif cfg_key == "llm_model":
                cfg_val = cfg_val.strip()
                if not cfg_val or len(cfg_val) > 128:
                    return jsonify({"error": "invalid_llm_model"}), 400
                if not re.match(r"^[A-Za-z0-9._:-]+$", cfg_val):
                    return jsonify({"error": "invalid_llm_model"}), 400
            elif cfg_key == "capture_interface":
                if not cfg_val:
                    cfg_val = "auto"
                if cfg_val.lower() in {"default", "自动"}:
                    cfg_val = "auto"
                if len(cfg_val) > 128:
                    return jsonify({"error": "invalid_capture_interface"}), 400
            elif cfg_key == "situation_minimum_actions":
                try:
                    v = int(cfg_val)
                except ValueError:
                    return jsonify({"error": "invalid_situation_minimum_actions"}), 400
                if v < 3 or v > 12:
                    return jsonify({"error": "invalid_situation_minimum_actions"}), 400
                cfg_val = str(v)
            elif cfg_key in {"situation_window_minutes", "situation_inactivity_minutes"}:
                try:
                    v = int(cfg_val)
                except ValueError:
                    return jsonify({"error": f"invalid_{cfg_key}"}), 400
                if v < 1 or v > 1440:
                    return jsonify({"error": f"invalid_{cfg_key}"}), 400
                cfg_val = str(v)
            elif cfg_key == "scan_port_threshold":
                try:
                    v = int(cfg_val)
                except ValueError:
                    return jsonify({"error": "invalid_scan_port_threshold"}), 400
                if v < 3 or v > 65535:
                    return jsonify({"error": "invalid_scan_port_threshold"}), 400
                cfg_val = str(v)
            elif cfg_key == "scan_window_seconds":
                try:
                    v = int(cfg_val)
                except ValueError:
                    return jsonify({"error": "invalid_scan_window_seconds"}), 400
                if v < 10 or v > 3600:
                    return jsonify({"error": "invalid_scan_window_seconds"}), 400
                cfg_val = str(v)
            elif cfg_key == "homepage_background_url":
                cfg_val = normalize_homepage_background_url(cfg_val)
                if not (cfg_val == DEFAULT_HOMEPAGE_BACKGROUND or cfg_val.startswith("/uploads/homepage_background_")):
                    return jsonify({"error": "invalid_homepage_background_url"}), 400
            normalized[cfg_key] = cfg_val
        if not normalized:
            return jsonify({"error": "invalid_payload"}), 400
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:
            with conn.cursor() as cur:
                for key, value in normalized.items():
                    cur.execute(
                        """
                        INSERT INTO demo_system_config(config_key, config_value)
                        VALUES (%s, %s)
                        ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)
                        """,
                        (str(key), str(value)),
                    )
                log_action(conn, g.session["username"], g.session["role"], "update_config", "system_config", str(normalized))
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
                           SUM(CASE WHEN risk_level IN ('critical','high') THEN 1 ELSE 0 END) AS high_total
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
    parser.add_argument("--rag-data-dir", default="", help="Advanced RAG runtime data directory; RAG_DATA_DIR env has priority")
    parser.add_argument("--rag-api-config", default="config/ai_api.local.json", help="DashScope local config JSON")
    parser.add_argument("--llm-prompt", default="llm/prompts/system_prompt.txt", help="LLM system prompt file path")
    parser.add_argument("--professional-report-prompt", default="llm/prompts/professional_situation_report_prompt.txt", help="Professional situation report prompt file path")
    parser.add_argument("--jwt-secret", default="", help="JWT secret, fallback to env TP_JWT_SECRET")
    parser.add_argument("--jwt-ttl-seconds", type=int, default=TOKEN_TTL_SECONDS, help="JWT token TTL seconds")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434", help="Ollama base URL")
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
        jwt_secret=args.jwt_secret,
        jwt_ttl_seconds=args.jwt_ttl_seconds,
        ollama_url=args.ollama_url,
        llm_prompt_path=args.llm_prompt,
        professional_report_prompt_path=args.professional_report_prompt,
        rag_data_dir=args.rag_data_dir,
        rag_api_config=args.rag_api_config,
    )
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()






