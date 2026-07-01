from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from build_result_db import MySQLConfig
from sync_detection_v2_db import ensure_mysql, mysql_connect, upsert_mysql
from sync_raw_http_logs import ensure_demo_attack_events


IP_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3}|[a-fA-F0-9:]{3,})(?![\w.])")
SOURCE_PATTERNS = [
    re.compile(r"(?i)Source\s+Network\s+Address\s*:\s*([^\r\n]+)"),
    re.compile(r"源网络地址\s*[:：]\s*([^\r\n]+)"),
    re.compile(r"来源网络地址\s*[:：]\s*([^\r\n]+)"),
    re.compile(r"(?i)\bfrom\s+((?:\d{1,3}\.){3}\d{1,3}|[a-fA-F0-9:]{3,})\s+port\b"),
    re.compile(r"(?i)remote\s+host\s*[:=]\s*((?:\d{1,3}\.){3}\d{1,3}|[a-fA-F0-9:]{3,})"),
]


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def log(message: str, log_file: Path) -> None:
    line = f"[{now_iso()}] {message}"
    print(line, flush=True)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def run_powershell_json(script: str, timeout: int = 30) -> List[Dict[str, Any]]:
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except Exception:
        return []
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    return []


def get_windows_security_failures(window_minutes: int) -> List[Dict[str, Any]]:
    script = rf"""
$start=(Get-Date).AddMinutes(-{int(window_minutes)})
Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4625; StartTime=$start}} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, ProviderName, Message |
  ConvertTo-Json -Compress -Depth 3
"""
    return run_powershell_json(script)


def get_openssh_failures(window_minutes: int) -> List[Dict[str, Any]]:
    script = rf"""
$start=(Get-Date).AddMinutes(-{int(window_minutes)})
Get-WinEvent -FilterHashtable @{{LogName='OpenSSH/Operational'; StartTime=$start}} -ErrorAction SilentlyContinue |
  Where-Object {{ $_.Message -match 'fail|invalid|Unable to negotiate|authentication|password' }} |
  Select-Object TimeCreated, Id, ProviderName, Message |
  ConvertTo-Json -Compress -Depth 3
"""
    return run_powershell_json(script)


def normalize_event_time(value: Any) -> datetime:
    text = str(value or "").strip()
    if not text:
        return datetime.now()
    text = text.replace("Z", "")
    if text.startswith("/Date("):
        m = re.search(r"/Date\((\d+)", text)
        if m:
            return datetime.fromtimestamp(int(m.group(1)) / 1000)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text[:26], fmt)
        except Exception:
            continue
    try:
        return datetime.fromisoformat(text)
    except Exception:
        return datetime.now()


def is_public_or_lan_ip(ip: str) -> bool:
    ip = str(ip or "").strip()
    if not ip or ip in {"-", "::1", "127.0.0.1", "0.0.0.0"}:
        return False
    if ip.lower().startswith("fe80:"):
        return False
    return True


def extract_source_ip(message: str) -> str:
    text = str(message or "")
    for pattern in SOURCE_PATTERNS:
        m = pattern.search(text)
        if m:
            ip = m.group(1).strip()
            if is_public_or_lan_ip(ip):
                return ip
    for ip in IP_RE.findall(text):
        if is_public_or_lan_ip(ip):
            return ip
    return ""


def collect_ssh_failures(window_minutes: int) -> List[Tuple[datetime, str, str]]:
    rows: List[Tuple[datetime, str, str]] = []
    for item in get_windows_security_failures(window_minutes) + get_openssh_failures(window_minutes):
        message = str(item.get("Message") or "")
        ip = extract_source_ip(message)
        if not ip:
            continue
        t = normalize_event_time(item.get("TimeCreated"))
        rows.append((t, ip, message[:500]))
    return rows


def bucket_start(dt: datetime, minutes: int) -> datetime:
    minute = (dt.minute // minutes) * minutes
    return dt.replace(minute=minute, second=0, microsecond=0)


def event_id_for(ip: str, bucket: datetime) -> str:
    digest = hashlib.sha1(f"ssh|{ip}|{bucket.isoformat()}".encode("utf-8")).hexdigest()[:22].upper()
    return f"SSH{digest}"


def write_ssh_event(conn: Any, ip: str, bucket: datetime, count: int, samples: Iterable[str]) -> None:
    event_id = event_id_for(ip, bucket)
    case_id = f"ssh:{ip}:{bucket.strftime('%Y%m%d%H%M')}"
    evidence = [
        f"聚合窗口：{bucket.strftime('%Y-%m-%d %H:%M:%S')} ~ {(bucket + timedelta(minutes=10)).strftime('%H:%M:%S')}",
        f"来源IP：{ip}",
        f"SSH登录失败次数：{count}",
    ]
    evidence.extend([x for x in samples if x][:3])
    evidence_json = json.dumps(evidence, ensure_ascii=False)
    occurred_at = bucket.isoformat(timespec="seconds")
    confidence = min(0.99, 0.72 + count * 0.025)
    risk_level = "critical" if count >= 20 else "high"

    upsert_mysql(
        conn,
        "detection_candidates",
        {
            "event_id": event_id,
            "case_id": case_id,
            "file_id": "ssh-auth-log",
            "seq_id": count,
            "decision": "attack_event",
            "final_score": confidence,
            "risk_level": risk_level,
            "attack_type": "SSH爆破",
            "source_ip": ip,
            "target_interface": "ssh:22",
            "evidence_json": evidence_json,
        },
    )
    upsert_mysql(
        conn,
        "attack_events",
        {
            "event_id": event_id,
            "case_id": case_id,
            "occurred_at": occurred_at,
            "source_ip": ip,
            "target_interface": "ssh:22",
            "attack_type": "SSH爆破",
            "risk_level": risk_level,
            "confidence": confidence,
            "status": "unprocessed",
            "evidence_json": evidence_json,
        },
    )
    with conn.cursor() as cur:
        cur.execute("DELETE FROM behavior_windows WHERE case_id=%s", (case_id,))
        cur.execute(
            """INSERT INTO behavior_windows(case_id,source_ip,behavior_type,score,features_json,evidence_json)
               VALUES(%s,%s,%s,%s,%s,%s)""",
            (
                case_id,
                ip,
                "SSH爆破",
                confidence,
                json.dumps({"ssh_fail_count": count, "window_minutes": 10}, ensure_ascii=False),
                evidence_json,
            ),
        )
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
              source_ip=VALUES(source_ip),
              attack_payload=VALUES(attack_payload),
              request_log=VALUES(request_log),
              handling_suggestion=VALUES(handling_suggestion),
              updated_at=CURRENT_TIMESTAMP
            """,
            (
                event_id[:40],
                occurred_at.replace("T", " "),
                risk_level,
                "SSH爆破",
                ip,
                "未知地区",
                "本机节点",
                "ssh:22",
                "已拦截",
                "unprocessed",
                f"SSH failed login x{count}",
                "\n".join(evidence),
                "SSH行为窗口检测",
                "检测到同一来源IP短时间内多次SSH登录失败，建议封禁来源IP并检查弱口令。",
                0,
                1,
            ),
        )


def sync_once(conn: Any, window_minutes: int, threshold: int, bucket_minutes: int) -> Dict[str, int]:
    rows = collect_ssh_failures(window_minutes)
    grouped: Dict[Tuple[str, datetime], List[str]] = defaultdict(list)
    counter: Counter[Tuple[str, datetime]] = Counter()
    for t, ip, message in rows:
        bucket = bucket_start(t, bucket_minutes)
        key = (ip, bucket)
        counter[key] += 1
        if len(grouped[key]) < 3:
            grouped[key].append(message)

    written = 0
    for (ip, bucket), count in counter.items():
        if count < threshold:
            continue
        write_ssh_event(conn, ip, bucket, count, grouped[(ip, bucket)])
        written += 1
    return {"observed": len(rows), "written": written}


def main() -> None:
    parser = argparse.ArgumentParser(description="Monitor Windows SSH/login failures and aggregate SSH brute-force events into MySQL")
    parser.add_argument("--mysql-host", default="127.0.0.1")
    parser.add_argument("--mysql-port", type=int, default=3306)
    parser.add_argument("--mysql-user", default="root")
    parser.add_argument("--mysql-password", default="123456")
    parser.add_argument("--mysql-database", default="traffic_pipeline")
    parser.add_argument("--window-minutes", type=int, default=10)
    parser.add_argument("--bucket-minutes", type=int, default=10)
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--poll-seconds", type=int, default=20)
    parser.add_argument("--log-file", default="output/ssh_bruteforce_monitor.log")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    log_file = (project_root / args.log_file).resolve()
    cfg = MySQLConfig(
        host=args.mysql_host,
        port=args.mysql_port,
        user=args.mysql_user,
        password=args.mysql_password,
        database=args.mysql_database,
    )

    while True:
        try:
            conn = mysql_connect(cfg)
            ensure_mysql(conn)
            ensure_demo_attack_events(conn)
            stats = sync_once(conn, args.window_minutes, args.threshold, args.bucket_minutes)
            conn.close()
            log(f"ssh monitor sync observed={stats['observed']} written={stats['written']}", log_file)
        except Exception as exc:  # noqa: BLE001
            log(f"ssh monitor failed: {exc}", log_file)
            if args.once:
                raise
        if args.once:
            return
        time.sleep(max(5, int(args.poll_seconds)))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
