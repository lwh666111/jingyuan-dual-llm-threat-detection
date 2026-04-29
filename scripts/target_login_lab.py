import argparse
import ipaddress
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Set, Tuple

from flask import Flask, jsonify, request

import pymysql
from pymysql.cursors import DictCursor


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DB_PATH = PROJECT_ROOT / "output" / "target_lab" / "target_login_lab.db"
BLOCK_CACHE_TTL_SECONDS = 2.0

MYSQL_CONF: Dict[str, Any] = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "root",
    "password": "123456",
    "database": "traffic_pipeline",
}
_BLOCK_CACHE: Dict[str, Any] = {"ts": 0.0, "ips": set()}
_WARNED_DB_ERR = False


def get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_mysql_conn():
    return pymysql.connect(
        host=MYSQL_CONF["host"],
        port=int(MYSQL_CONF["port"]),
        user=MYSQL_CONF["user"],
        password=MYSQL_CONF["password"],
        database=MYSQL_CONF["database"],
        charset="utf8mb4",
        cursorclass=DictCursor,
        autocommit=True,
        connect_timeout=2,
        read_timeout=2,
        write_timeout=2,
    )


def normalize_ip(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except Exception:
        return ""


def read_client_ip() -> str:
    xff = str(request.headers.get("X-Forwarded-For", "")).strip()
    if xff:
        first = xff.split(",", 1)[0].strip()
        ip = normalize_ip(first)
        if ip:
            return ip
    real_ip = str(request.headers.get("X-Real-IP", "")).strip()
    ip = normalize_ip(real_ip)
    if ip:
        return ip
    return normalize_ip(request.remote_addr)


def refresh_blocked_ips() -> Set[str]:
    global _WARNED_DB_ERR
    ips: Set[str] = set()
    try:
        with get_mysql_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT ip_address FROM demo_blocked_ips")
                rows = cur.fetchall() or []
        for row in rows:
            ip_text = normalize_ip(row.get("ip_address"))
            if ip_text:
                ips.add(ip_text)
        _WARNED_DB_ERR = False
    except Exception as exc:
        if not _WARNED_DB_ERR:
            print(f"[target-login-lab] warn: cannot load blocked ip list from mysql: {exc}")
            _WARNED_DB_ERR = True
    return ips


def is_client_ip_blocked(ip_text: str) -> bool:
    if not ip_text:
        return False
    now_ts = time.time()
    last_ts = float(_BLOCK_CACHE.get("ts") or 0.0)
    if now_ts - last_ts >= BLOCK_CACHE_TTL_SECONDS:
        _BLOCK_CACHE["ips"] = refresh_blocked_ips()
        _BLOCK_CACHE["ts"] = now_ts
    return ip_text in (_BLOCK_CACHE.get("ips") or set())


def init_db() -> None:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
            )
            """
        )
        seed_users: Tuple[Tuple[str, str, str], ...] = (
            ("admin", "admin", "admin"),
            ("user", "admin", "user"),
            ("test", "admin", "user"),
        )
        for username, password, role in seed_users:
            cur.execute(
                """
                INSERT INTO users(username, password, role)
                VALUES (?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                  password=excluded.password,
                  role=excluded.role
                """,
                (username, password, role),
            )
        conn.commit()


app = Flask(__name__)


@app.before_request
def deny_blocked_clients():
    if request.path in {"/health"}:
        return None
    client_ip = read_client_ip()
    if client_ip and is_client_ip_blocked(client_ip):
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "ip_blocked",
                    "message": "该IP已被防护系统封禁，访问被拒绝",
                    "client_ip": client_ip,
                }
            ),
            403,
        )
    return None


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "target-login-lab"})


@app.get("/")
def index():
    return """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>登录靶场页面</title>
  <style>
    body{margin:0;font-family:Segoe UI,Microsoft YaHei,sans-serif;background:#0f172a;color:#e2e8f0;display:grid;min-height:100vh;place-items:center}
    .card{width:min(420px,92vw);background:#111827;border:1px solid #334155;border-radius:14px;padding:22px;box-shadow:0 20px 50px rgba(0,0,0,.45)}
    h1{margin:0 0 8px;font-size:24px}
    p{margin:0 0 16px;color:#94a3b8}
    label{display:block;margin:10px 0 6px;color:#cbd5e1}
    input{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #475569;background:#0b1220;color:#e2e8f0;box-sizing:border-box}
    button{margin-top:14px;width:100%;padding:10px 12px;border:0;border-radius:10px;background:#2563eb;color:#fff;font-weight:600;cursor:pointer}
    pre{margin-top:12px;white-space:pre-wrap;word-break:break-word;background:#020617;border:1px solid #1e293b;border-radius:10px;padding:10px;min-height:52px}
  </style>
</head>
<body>
  <div class="card">
    <h1>登录靶场环境</h1>
    <p>用于 SQL 注入/暴力破解流量测试（默认监听 3000 端口）</p>
    <label>用户名</label>
    <input id="username" placeholder="例如：admin">
    <label>密码</label>
    <input id="password" placeholder="例如：admin 或 ' or 1=1 -- ">
    <button id="submit">登录</button>
    <pre id="output">等待请求...</pre>
  </div>
  <script>
    const out = document.getElementById("output");
    document.getElementById("submit").addEventListener("click", async () => {
      const username = document.getElementById("username").value;
      const password = document.getElementById("password").value;
      out.textContent = "请求中...";
      try {
        const resp = await fetch("/api/auth/login", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({username, password})
        });
        const data = await resp.json().catch(() => ({}));
        out.textContent = "HTTP " + resp.status + "\\n" + JSON.stringify(data, null, 2);
      } catch (e) {
        out.textContent = "请求失败: " + String(e);
      }
    });
  </script>
</body>
</html>"""


@app.post("/api/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))

    # Simulate time-based payload behavior to make traffic features obvious.
    lp = password.lower()
    if "sleep(" in lp or "benchmark(" in lp or "waitfor delay" in lp:
        time.sleep(2.2)

    vuln_sql = (
        "SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}' LIMIT 1"
    )

    try:
        with get_conn() as conn:
            row = conn.execute(vuln_sql).fetchone()
    except Exception as exc:  # intentionally expose sql errors in lab
        return jsonify({"ok": False, "error": "sql_error", "message": str(exc), "query": vuln_sql}), 500

    if row:
        return jsonify(
            {
                "ok": True,
                "message": "login success",
                "user": {"id": row["id"], "username": row["username"], "role": row["role"]},
            }
        )

    return jsonify({"ok": False, "message": "invalid username or password"}), 401


def main() -> None:
    parser = argparse.ArgumentParser(description="Vulnerable login lab target for traffic pipeline testing")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=3000)
    parser.add_argument("--mysql-host", default=os.environ.get("TP_MYSQL_HOST", "127.0.0.1"))
    parser.add_argument("--mysql-port", type=int, default=int(os.environ.get("TP_MYSQL_PORT", "3306")))
    parser.add_argument("--mysql-user", default=os.environ.get("TP_MYSQL_USER", "root"))
    parser.add_argument("--mysql-password", default=os.environ.get("TP_MYSQL_PASSWORD", "123456"))
    parser.add_argument("--mysql-database", default=os.environ.get("TP_MYSQL_DATABASE", "traffic_pipeline"))
    args = parser.parse_args()

    MYSQL_CONF["host"] = args.mysql_host
    MYSQL_CONF["port"] = args.mysql_port
    MYSQL_CONF["user"] = args.mysql_user
    MYSQL_CONF["password"] = args.mysql_password
    MYSQL_CONF["database"] = args.mysql_database

    init_db()
    print(f"[target-login-lab] running on http://{args.host}:{args.port}")
    print(f"[target-login-lab] sqlite db: {DB_PATH}")
    print(
        f"[target-login-lab] mysql blocked-ip source: {MYSQL_CONF['host']}:{MYSQL_CONF['port']}/{MYSQL_CONF['database']}"
    )
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
