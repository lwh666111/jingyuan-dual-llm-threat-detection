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
import uuid
import urllib.parse
import urllib.request
import urllib.error
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, Response, current_app, g, jsonify, request
import pymysql
from pymysql.cursors import DictCursor

try:
    import psutil  # type: ignore
except Exception:
    psutil = None


ROLE_NORMAL = "normal"
ROLE_ADMIN = "admin"

PROCESS_STATUS_SET = {"unprocessed", "processing", "done", "ignored"}
RISK_LEVEL_SET = {"high", "medium", "low"}
RAG_SEVERITY_SET = {"low", "medium", "high", "critical"}

TOKEN_TTL_SECONDS = 12 * 3600
JWT_ALGORITHM = "HS256"
JWT_HEADER = {"alg": JWT_ALGORITHM, "typ": "JWT"}
JWT_REVOKED_JTIS: Dict[str, int] = {}
AUTH_COOKIE_NAME = "tp_auth_token"

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
                SELECT id, username, password, role, display_name
                FROM demo_users
                WHERE username=%s AND password=%s AND role=%s
                LIMIT 1
                """,
                (username, password, role_hint),
            )
            return cur.fetchone()
        cur.execute(
            """
            SELECT id, username, password, role, display_name
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
    "SSRF",
    "RCE",
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


def normalize_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return dt_to_str(value)
    return value


def normalize_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {k: normalize_value(v) for k, v in row.items()}


def normalize_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [normalize_row(r) for r in rows]


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
    if any(x in raw for x in ["文件上传", "鏂囦欢涓婁紶"]) or "upload" in t:
        return "文件上传"
    if any(x in raw for x in ["命令注入", "鍛戒护娉ㄥ叆"]) or "cmd" in t or "commandinject" in t:
        return "命令注入"
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
        local_ip = socket.gethostbyname(host)
    except Exception:
        local_ip = ""

    cpu_percent: Optional[float] = None
    mem_total = mem_used = mem_free = 0
    uptime_seconds: Optional[int] = None

    if psutil is not None:
        try:
            cpu_percent = round(float(psutil.cpu_percent(interval=0.3)), 2)
        except Exception:
            cpu_percent = None
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


def firewall_block_ip(ip_text: str) -> Tuple[bool, str]:
    if os.name != "nt":
        return False, "firewall_block_supported_only_on_windows"
    ip_val = str(ip_text or "").strip()
    if not ip_val:
        return False, "empty_ip"
    in_rule, out_rule = firewall_rule_names(ip_val)
    # make command idempotent
    run_netsh(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={in_rule}"])
    run_netsh(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={out_rule}"])
    ok1, out1, err1 = run_netsh(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={in_rule}",
            "dir=in",
            "action=block",
            f"remoteip={ip_val}",
            "enable=yes",
            "profile=any",
        ]
    )
    ok2, out2, err2 = run_netsh(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={out_rule}",
            "dir=out",
            "action=block",
            f"remoteip={ip_val}",
            "enable=yes",
            "profile=any",
        ]
    )
    if ok1 and ok2:
        return True, ""
    detail = f"in: {out1 or err1}; out: {out2 or err2}"
    return False, detail.strip()


def firewall_unblock_ip(ip_text: str) -> Tuple[bool, str]:
    if os.name != "nt":
        return False, "firewall_unblock_supported_only_on_windows"
    ip_val = str(ip_text or "").strip()
    if not ip_val:
        return False, "empty_ip"
    in_rule, out_rule = firewall_rule_names(ip_val)
    # delete rule no matter exists or not; if both return non-zero we still regard as success if "No rules match"
    ok1, out1, err1 = run_netsh(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={in_rule}"])
    ok2, out2, err2 = run_netsh(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={out_rule}"])

    text1 = f"{out1}\n{err1}".lower()
    text2 = f"{out2}\n{err2}".lower()
    no_match1 = "no rules match" in text1
    no_match2 = "no rules match" in text2
    if (ok1 or no_match1) and (ok2 or no_match2):
        return True, ""
    detail = f"in: {out1 or err1}; out: {out2 or err2}"
    return False, detail.strip()


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
          blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          KEY idx_blocked_at (blocked_at)
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
            if force_seed:
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
            else:
                cur.execute(
                    """
                    INSERT INTO demo_users(username, password, role, display_name)
                    VALUES (%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                      role=VALUES(role),
                      display_name=VALUES(display_name)
                    """,
                    (row["username"], row["password"], row["role"], row["display_name"]),
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

        machines = [
            ("node-bj-01", "10.30.1.11", "北京机房A", "online"),
            ("node-sh-01", "10.30.2.11", "上海机房B", "online"),
            ("node-gz-01", "10.30.3.11", "广州机房C", "online"),
            ("node-hz-01", "10.30.4.11", "杭州机房D", "online"),
            ("node-cd-01", "10.30.5.11", "成都机房E", "online"),
            ("node-sg-01", "10.30.6.11", "新加坡机房F", "online"),
            ("node-us-01", "10.30.7.11", "美国西部", "online"),
            ("node-de-01", "10.30.8.11", "德国法兰克福", "online"),
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


def ensure_builtin_admin(conn: Any) -> None:
    # Keep a deterministic bootstrap admin account for first login/recovery.
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO demo_users(username, password, role, display_name)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
              password=VALUES(password),
              role=VALUES(role),
              display_name=VALUES(display_name)
            """,
            ("admin", "admin", ROLE_ADMIN, "管理员"),
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
        "expires_at": expires_at,
    }


def is_valid_username(username: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,32}", username))


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
) -> Flask:
    app = Flask(__name__)
    app.url_map.strict_slashes = False
    app.config["MYSQL_CONF"] = mysql_conf
    app.config["RAG_DB_PATH"] = str(Path(rag_db_path).resolve())
    app.config["RAG_SEED_PATH"] = str(Path(rag_seed_path).resolve())
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
        final_jwt_secret = secrets.token_urlsafe(48)
        print("[warn] JWT secret not set, generated ephemeral secret for this runtime.")
    app.config["JWT_SECRET"] = final_jwt_secret
    app.config["JWT_TTL_SECONDS"] = max(300, int(jwt_ttl_seconds))

    with closing(get_conn(mysql_conf, autocommit=False)) as conn:
        ensure_schema(conn)
        ensure_builtin_admin(conn)
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
                    INSERT INTO demo_users(username, password, role, display_name)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (username, password, ROLE_NORMAL, display_name),
                )
                cur.execute(
                    """
                    SELECT id, username, role, display_name
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
        session["expires_at"] = dt_to_str(session["expires_at"])
        return jsonify(session)

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
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
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
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
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

        upstream = "http://ctf.ski:9898/?" + urllib.parse.urlencode({"url": url_text, "token": token})
        req = urllib.request.Request(upstream, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                payload = resp.read().decode("utf-8", errors="replace")
                data = json.loads(payload)
        except urllib.error.HTTPError as exc:
            return jsonify({"error": "upstream_http_error", "status": int(exc.code)}), 502
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
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
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
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
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
                    """
                )
                rows = cur.fetchall()
        items = aggregate_counts_by_label(rows, "attack_type")[:10]
        return jsonify({"items": normalize_rows(items)})

    @app.route("/api/v2/user/dashboard/source-distribution", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def source_distribution():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT source_ip, source_region, COUNT(*) AS total
                    FROM demo_attack_events
                    WHERE occurred_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
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
                region_bucket[region] = region_bucket.get(region, 0) + count
        items = [{"source_region": k, "total": v} for k, v in region_bucket.items()]
        items.sort(key=lambda x: int(x.get("total") or 0), reverse=True)
        return jsonify({"items": normalize_rows(items)})

    @app.route("/api/v2/user/dashboard/heatmap", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
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
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
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
        merged = aggregate_counts_by_label(rows, "attack_type")
        total = sum(int(r.get("total") or 0) for r in merged)
        items = []
        for r in merged:
            count = int(r.get("total") or 0)
            ratio = 0.0 if total == 0 else (count / total) * 100.0
            items.append({"attack_type": r["attack_type"], "total": count, "ratio_percent": round(ratio, 2)})
        return jsonify({"items": items})

    @app.route("/api/v2/pro/events", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
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

        where = ["e.occurred_at BETWEEN %s AND %s"]
        params: List[Any] = [start_dt, end_dt]
        if risk_level != "all":
            where.append("e.risk_level=%s")
            params.append(risk_level)
        if attack_type != "all":
            aliases = attack_type_aliases(attack_type)
            placeholders = ", ".join(["%s"] * len(aliases))
            where.append(f"e.attack_type IN ({placeholders})")
            params.extend(aliases)
        if target_node != "all":
            where.append("e.target_node=%s")
            params.append(target_node)
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
                      e.target_node,
                      e.attack_result,
                      e.process_status,
                      CASE WHEN b.source_event_id IS NULL THEN 0 ELSE 1 END AS ip_blocked
                    FROM demo_attack_events e
                    LEFT JOIN (
                      SELECT source_event_id, MAX(blocked_at) AS blocked_at
                      FROM demo_blocked_ips
                      GROUP BY source_event_id
                    ) b ON b.source_event_id = e.event_id
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
            items.append(row)
        return jsonify({"items": items, "page": page, "page_size": page_size, "total": total})

    @app.route("/api/v2/pro/events/<event_id>", methods=["GET"])
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
    def pro_event_detail(event_id: str):
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                      e.event_id, e.occurred_at, e.risk_level, e.attack_type, e.source_ip, e.source_region,
                      e.target_node, e.target_interface, e.attack_result, e.process_status, e.attack_payload,
                      e.request_log, e.protection_action, e.handling_suggestion, e.note, e.response_ms, e.anomaly_detected,
                      CASE WHEN b.source_event_id IS NULL THEN 0 ELSE 1 END AS ip_blocked,
                      b.blocked_at AS ip_blocked_at
                    FROM demo_attack_events e
                    LEFT JOIN (
                      SELECT source_event_id, MAX(blocked_at) AS blocked_at
                      FROM demo_blocked_ips
                      GROUP BY source_event_id
                    ) b ON b.source_event_id = e.event_id
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
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            item["source_region"] = resolve_region_for_event(
                conn,
                str(item.get("source_ip") or ""),
                str(item.get("source_region") or ""),
            )
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
                rows = cur.fetchall()
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
    @require_roles(ROLE_NORMAL, ROLE_ADMIN)
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

    @app.route("/api/v2/admin/users", methods=["GET"])
    @require_roles(ROLE_ADMIN)
    def admin_users_list():
        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, username, role, display_name, created_at, updated_at
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
                cur.execute("UPDATE demo_users SET password=%s WHERE username=%s", (new_password, username))
                changed = int(cur.rowcount)
                if changed:
                    log_action(
                        conn,
                        g.session["username"],
                        g.session["role"],
                        "admin_change_user_password",
                        username,
                        "updated",
                    )
            conn.commit()
        if changed == 0:
            return jsonify({"error": "user_not_found"}), 404
        return jsonify({"ok": True, "username": username})

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
            elif cfg_key == "sound_alert_enabled":
                if cfg_val not in {"0", "1"}:
                    return jsonify({"error": "invalid_sound_alert_enabled"}), 400
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
    parser.add_argument("--jwt-secret", default="", help="JWT secret, fallback to env TP_JWT_SECRET")
    parser.add_argument("--jwt-ttl-seconds", type=int, default=TOKEN_TTL_SECONDS, help="JWT token TTL seconds")
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
    )
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()





