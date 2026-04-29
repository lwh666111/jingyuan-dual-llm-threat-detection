import argparse
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict
from urllib.parse import unquote

from flask import Flask, jsonify, make_response, request


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DB_PATH = PROJECT_ROOT / "output" / "target_lab" / "target_multivuln_lab.db"


def get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


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
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS comments (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              author TEXT NOT NULL,
              content TEXT NOT NULL,
              created_at REAL NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS orders (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              sku TEXT NOT NULL,
              amount INTEGER NOT NULL,
              created_at REAL NOT NULL
            )
            """
        )
        seed_users = [
            ("admin", "admin", "admin"),
            ("alice", "alice123", "user"),
            ("bob", "bob123", "user"),
            ("guest", "guest", "user"),
        ]
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


def has_any(text: str, patterns: list[str]) -> bool:
    low = (text or "").lower()
    return any(p.lower() in low for p in patterns)


app = Flask(__name__)


MOCK_FILES: Dict[str, str] = {
    "notes/todo.txt": "deploy patch; rotate token; review logs",
    "public/readme.txt": "welcome to multivuln test lab",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:/var/www:/usr/sbin/nologin",
    "c:/windows/win.ini": "[fonts]\n[extensions]\n[MCI Extensions]",
}


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "target-multivuln-lab"})


@app.get("/")
def home():
    return (
        "<h2>Target Multi-Vuln Lab</h2>"
        "<p>Use /health, /api/auth/login, /api/search, /api/file/read, /api/system/ping, "
        "/api/fetch, /api/template/render, /api/xml/import, /api/deserialize, /api/upload, "
        "/api/graphql, /api/admin/reset, /api/eval, /api/orders.</p>"
    )


@app.get("/api/products")
def products():
    items = [
        {"id": 1001, "name": "WAF Appliance", "price": 2999},
        {"id": 1002, "name": "Threat Sensor", "price": 899},
        {"id": 1003, "name": "SIEM License", "price": 5999},
    ]
    return jsonify({"ok": True, "items": items})


@app.get("/api/news")
def news():
    return jsonify(
        {
            "ok": True,
            "items": [
                {"id": 1, "title": "platform update"},
                {"id": 2, "title": "new plugin released"},
            ],
        }
    )


@app.post("/api/auth/login")
def auth_login():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))
    vuln_sql = (
        "SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}' LIMIT 1"
    )
    if has_any(password, ["sleep(", "benchmark(", "waitfor delay"]):
        time.sleep(0.08)
    try:
        with get_conn() as conn:
            row = conn.execute(vuln_sql).fetchone()
    except Exception as exc:
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


@app.get("/api/search")
def search():
    q = str(request.args.get("q", ""))
    if has_any(q, ["<script", "onerror=", "javascript:"]):
        return jsonify({"ok": True, "query": q, "hits": 1, "note": "reflected"}), 200
    return jsonify({"ok": True, "query": q, "hits": 3}), 200


@app.post("/api/comment")
def add_comment():
    body = request.get_json(silent=True) or {}
    author = str(body.get("author", "guest"))[:64]
    content = str(body.get("content", ""))[:4096]
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO comments(author, content, created_at) VALUES (?, ?, ?)",
            (author, content, time.time()),
        )
        cid = int(cur.lastrowid)
        conn.commit()
    return jsonify({"ok": True, "comment_id": cid, "content": content})


@app.get("/api/file/read")
def file_read():
    path_text = str(request.args.get("path", "")).strip()
    decoded = unquote(path_text).lower()
    if has_any(decoded, ["../", "..\\", "/etc/passwd", "win.ini", "system32"]):
        if "win.ini" in decoded:
            return jsonify({"ok": True, "path": path_text, "content": MOCK_FILES["c:/windows/win.ini"]})
        return jsonify({"ok": True, "path": path_text, "content": MOCK_FILES["/etc/passwd"]})
    if path_text in MOCK_FILES:
        return jsonify({"ok": True, "path": path_text, "content": MOCK_FILES[path_text]})
    return jsonify({"ok": False, "error": "file_not_found"}), 404


@app.post("/api/system/ping")
def system_ping():
    body = request.get_json(silent=True) or {}
    host = str(body.get("host", "")).strip()
    if has_any(host, [";", "&&", "|", "`", "$(", "cat ", "whoami", "powershell"]):
        return jsonify(
            {
                "ok": True,
                "host": host,
                "output": "uid=0(root) gid=0(root) groups=0(root)",
                "exec": "shell",
            }
        )
    return jsonify({"ok": True, "host": host, "output": "pong", "latency_ms": 7})


@app.get("/api/fetch")
def fetch_url():
    url = str(request.args.get("url", "")).strip().lower()
    if has_any(url, ["169.254.169.254", "127.0.0.1", "localhost", "redis://", "file://"]):
        return jsonify(
            {
                "ok": True,
                "url": url,
                "data": "instance-id:i-abcd1234\niam-role:admin",
                "source": "internal",
            }
        )
    return jsonify({"ok": True, "url": url, "data": "public-content", "source": "external"})


@app.post("/api/template/render")
def template_render():
    body = request.get_json(silent=True) or {}
    tpl = str(body.get("template", ""))[:4096]
    if has_any(tpl, ["{{", "}}", "__class__", "config", "cycler"]):
        return jsonify({"ok": True, "rendered": "49", "engine": "jinja2"})
    return jsonify({"ok": True, "rendered": tpl.replace("${name}", "guest"), "engine": "safe"})


@app.post("/api/xml/import")
def xml_import():
    body_text = request.get_data(cache=False, as_text=True) or ""
    low = body_text.lower()
    if "<!entity" in low or "system " in low or "file://" in low:
        return jsonify({"ok": True, "items": 1, "leak": MOCK_FILES["/etc/passwd"]})
    return jsonify({"ok": True, "items": 2, "message": "xml parsed"})


@app.post("/api/deserialize")
def deserialize():
    body = request.get_json(silent=True) or {}
    payload = str(body.get("data", ""))[:8192]
    if has_any(payload, ["rO0AB", "pickle", "__reduce__", "java.lang.runtime"]):
        return jsonify({"ok": True, "result": "object loaded", "side_effect": "command executed"})
    return jsonify({"ok": True, "result": "object loaded"})


@app.post("/api/upload")
def upload():
    body = request.get_json(silent=True) or {}
    filename = str(body.get("filename", "unknown.bin")).strip()
    content = str(body.get("content", ""))[:12000]
    is_shell = has_any(filename, [".php", ".jsp", ".aspx", ".war"]) or has_any(
        content, ["<?php", "<%=", "jsp:scriptlet", "Runtime.getRuntime()"]
    )
    return jsonify({"ok": True, "stored": f"/uploads/{filename}", "risk": "shell" if is_shell else "low"}), 201


@app.post("/api/graphql")
def graphql():
    body = request.get_json(silent=True) or {}
    query = str(body.get("query", ""))
    if has_any(query, ["__schema", "union select", " or 1=1", "sleep("]):
        return jsonify({"ok": True, "data": {"debug": "enabled", "rows": [{"id": 1}, {"id": 2}]}})
    return jsonify({"ok": True, "data": {"viewer": {"id": 1001, "name": "guest"}}})


@app.route("/api/admin/reset", methods=["GET", "POST"])
def admin_reset():
    token = str(request.values.get("token", "")).strip()
    if has_any(token, ["none", "000000", "weak", "bypass", "admin"]):
        return jsonify({"ok": True, "changed": 3, "note": "token accepted"})
    return jsonify({"ok": False, "error": "unauthorized"}), 403


@app.route("/api/eval", methods=["GET", "POST"])
def eval_expr():
    code = str(request.values.get("code", "") or (request.get_json(silent=True) or {}).get("code", ""))
    if has_any(code, ["__import__", "os.system", "subprocess", "Runtime.getRuntime"]):
        return jsonify({"ok": True, "result": "uid=0(root)"})
    if code.strip() == "1+1":
        return jsonify({"ok": True, "result": 2})
    return jsonify({"ok": True, "result": "noop"})


@app.get("/api/orders")
def list_orders():
    with get_conn() as conn:
        rows = [dict(x) for x in conn.execute("SELECT id, user_id, sku, amount, created_at FROM orders ORDER BY id DESC LIMIT 30")]
    return jsonify({"ok": True, "items": rows})


@app.post("/api/orders")
def create_order():
    body = request.get_json(silent=True) or {}
    sku = str(body.get("sku", "SKU-000"))[:64]
    amount = int(body.get("amount", 1))
    user_id = int(body.get("user_id", 1001))
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO orders(user_id, sku, amount, created_at) VALUES (?, ?, ?, ?)",
            (user_id, sku, amount, time.time()),
        )
        oid = int(cur.lastrowid)
        conn.commit()
    return jsonify({"ok": True, "order_id": oid}), 201


@app.get("/api/redirect")
def open_redirect():
    nxt = str(request.args.get("next", "/"))
    resp = make_response(jsonify({"ok": True, "next": nxt}), 302)
    resp.headers["Location"] = nxt
    return resp


@app.get("/.git/config")
def git_config():
    return "[core]\nrepositoryformatversion = 0\nbare = false\n", 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.get("/wp-admin/install.php")
def wp_install():
    return "<html><body>WordPress setup</body></html>", 200, {"Content-Type": "text/html; charset=utf-8"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-vulnerability Flask lab for traffic pipeline testing")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=3000)
    args = parser.parse_args()

    init_db()
    print(f"[target-multivuln-lab] running on http://{args.host}:{args.port}")
    print(f"[target-multivuln-lab] sqlite db: {DB_PATH}")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()

