# `scripts/dashboard_api_server.py` 逐行注释

**脚本用途：** Flask 后端主服务：JWT 鉴权、用户与管理员接口、态势大屏、RAG 管理、自动防御、报告任务和数据库查询。

**源码行数：** 5669　**函数/类数量：** 221

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0002 | 导入后续逻辑所需的模块、类或函数：&#96;import base64&#96;。 | <code>import base64</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import csv&#96;。 | <code>import csv</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import hashlib&#96;。 | <code>import hashlib</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import hmac&#96;。 | <code>import hmac</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;import ipaddress&#96;。 | <code>import ipaddress</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;import io&#96;。 | <code>import io</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;import os&#96;。 | <code>import os</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;import platform&#96;。 | <code>import platform</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;import random&#96;。 | <code>import random</code> |
| L0012 | 导入后续逻辑所需的模块、类或函数：&#96;import re&#96;。 | <code>import re</code> |
| L0013 | 导入后续逻辑所需的模块、类或函数：&#96;import secrets&#96;。 | <code>import secrets</code> |
| L0014 | 导入后续逻辑所需的模块、类或函数：&#96;import shutil&#96;。 | <code>import shutil</code> |
| L0015 | 导入后续逻辑所需的模块、类或函数：&#96;import socket&#96;。 | <code>import socket</code> |
| L0016 | 导入后续逻辑所需的模块、类或函数：&#96;import sqlite3&#96;。 | <code>import sqlite3</code> |
| L0017 | 导入后续逻辑所需的模块、类或函数：&#96;import subprocess&#96;。 | <code>import subprocess</code> |
| L0018 | 导入后续逻辑所需的模块、类或函数：&#96;import threading&#96;。 | <code>import threading</code> |
| L0019 | 导入后续逻辑所需的模块、类或函数：&#96;import time&#96;。 | <code>import time</code> |
| L0020 | 导入后续逻辑所需的模块、类或函数：&#96;import uuid&#96;。 | <code>import uuid</code> |
| L0021 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.parse&#96;。 | <code>import urllib.parse</code> |
| L0022 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.request&#96;。 | <code>import urllib.request</code> |
| L0023 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.error&#96;。 | <code>import urllib.error</code> |
| L0024 | 导入后续逻辑所需的模块、类或函数：&#96;from contextlib import closing&#96;。 | <code>from contextlib import closing</code> |
| L0025 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime, timedelta&#96;。 | <code>from datetime import datetime, timedelta</code> |
| L0026 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0027 | 导入后续逻辑所需的模块、类或函数：&#96;from functools import wraps&#96;。 | <code>from functools import wraps</code> |
| L0028 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, List, Optional, Tuple&#96;。 | <code>from typing import Any, Dict, List, Optional, Tuple</code> |
| L0029 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0030 | 导入后续逻辑所需的模块、类或函数：&#96;from flask import Flask, Response, current_app, g, jsonify, request, send_file&#96;。 | <code>from flask import Flask, Response, current_app, g, jsonify, request, send_file</code> |
| L0031 | 导入后续逻辑所需的模块、类或函数：&#96;import pymysql&#96;。 | <code>import pymysql</code> |
| L0032 | 导入后续逻辑所需的模块、类或函数：&#96;from pymysql.cursors import DictCursor&#96;。 | <code>from pymysql.cursors import DictCursor</code> |
| L0033 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0034 | 导入后续逻辑所需的模块、类或函数：&#96;from situation_ai import analyze_situation&#96;。 | <code>from situation_ai import analyze_situation</code> |
| L0035 | 导入后续逻辑所需的模块、类或函数：&#96;from situation_cluster import build_proxy_clusters&#96;。 | <code>from situation_cluster import build_proxy_clusters</code> |
| L0036 | 导入后续逻辑所需的模块、类或函数：&#96;from situation_core import ACTION_CATALOG, STAGE_LABELS, STAGE_ORDER&#96;。 | <code>from situation_core import ACTION_CATALOG, STAGE_LABELS, STAGE_ORDER</code> |
| L0037 | 导入后续逻辑所需的模块、类或函数：&#96;from situation_store import MySQLSettings, MySQLSituationStore&#96;。 | <code>from situation_store import MySQLSettings, MySQLSituationStore</code> |
| L0038 | 导入后续逻辑所需的模块、类或函数：&#96;from raw_llm_review import ensure_review_schema&#96;。 | <code>from raw_llm_review import ensure_review_schema</code> |
| L0039 | 导入后续逻辑所需的模块、类或函数：&#96;from situation_professional_report import (&#96;。 | <code>from situation_professional_report import (</code> |
| L0040 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ProfessionalReportManager,</code> |
| L0041 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    create_job as create_professional_report_job,</code> |
| L0042 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    expire_stale_jobs as expire_professional_report_jobs,</code> |
| L0043 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ensure_schema as ensure_professional_report_schema,</code> |
| L0044 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    find_job as find_professional_report_job,</code> |
| L0045 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    find_latest_completed_job as find_latest_completed_professional_report_job,</code> |
| L0046 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    get_job as get_professional_report_job,</code> |
| L0047 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    public_job as public_professional_report_job,</code> |
| L0048 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>)</code> |
| L0049 | 导入后续逻辑所需的模块、类或函数：&#96;from firewall_control import (&#96;。 | <code>from firewall_control import (</code> |
| L0050 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    firewall_block_ip as verified_firewall_block_ip,</code> |
| L0051 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    firewall_status_many as verified_firewall_status_many,</code> |
| L0052 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    firewall_unblock_ip as verified_firewall_unblock_ip,</code> |
| L0053 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>)</code> |
| L0054 | 导入后续逻辑所需的模块、类或函数：&#96;from rag_service import (&#96;。 | <code>from rag_service import (</code> |
| L0055 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    MAX_UPLOAD_BYTES as RAG_MAX_UPLOAD_BYTES,</code> |
| L0056 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    SUPPORTED_EXTENSIONS as RAG_SUPPORTED_EXTENSIONS,</code> |
| L0057 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    delete_document as rag2_delete_document,</code> |
| L0058 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    delete_kb as rag2_delete_kb,</code> |
| L0059 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ensure_default_kb as rag2_ensure_default_kb,</code> |
| L0060 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ensure_schema as rag2_ensure_schema,</code> |
| L0061 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    get_chunk as rag2_get_chunk,</code> |
| L0062 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    get_kb as rag2_get_kb,</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    hybrid_search as rag2_hybrid_search,</code> |
| L0064 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    index_pending_document as rag2_index_pending_document,</code> |
| L0065 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ingest_file as rag2_ingest_file,</code> |
| L0066 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    list_chunks as rag2_list_chunks,</code> |
| L0067 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    list_documents as rag2_list_documents,</code> |
| L0068 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    list_eval_cases as rag2_list_eval_cases,</code> |
| L0069 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    list_eval_runs as rag2_list_eval_runs,</code> |
| L0070 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    list_kbs as rag2_list_kbs,</code> |
| L0071 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    list_test_history as rag2_list_test_history,</code> |
| L0072 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    load_api_config as rag2_load_api_config,</code> |
| L0073 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    migrate_legacy_sqlite as rag2_migrate_legacy_sqlite,</code> |
| L0074 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    delete_eval_case as rag2_delete_eval_case,</code> |
| L0075 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    run_eval_suite as rag2_run_eval_suite,</code> |
| L0076 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    save_eval_case as rag2_save_eval_case,</code> |
| L0077 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    save_kb as rag2_save_kb,</code> |
| L0078 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    update_chunk as rag2_update_chunk,</code> |
| L0079 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>)</code> |
| L0080 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0081 | 开始受保护操作，异常会交给后续分支处理。 | <code>try:</code> |
| L0082 | 导入后续逻辑所需的模块、类或函数：&#96;import psutil  # type: ignore&#96;。 | <code>    import psutil  # type: ignore</code> |
| L0083 | 捕获异常，避免单次错误导致整个服务退出。 | <code>except Exception:</code> |
| L0084 | 计算并保存 &#96;psutil&#96;（psutil），供后续逻辑使用。 | <code>    psutil = None</code> |
| L0085 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0086 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0087 | 计算并保存 &#96;_CPU_SAMPLE_LOCK&#96;（CPUSAMPLELOCK），供后续逻辑使用。 | <code>_CPU_SAMPLE_LOCK = threading.Lock()</code> |
| L0088 | 计算并保存 &#96;_CPU_SAMPLE_CACHE&#96;（CPUSAMPLECACHE），供后续逻辑使用。 | <code>_CPU_SAMPLE_CACHE: Dict[str, Any] = {"value": None, "sampled_at": 0.0}</code> |
| L0089 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0090 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0091 | 计算并保存 &#96;ROLE_NORMAL&#96;（ROLENORMAL），供后续逻辑使用。 | <code>ROLE_NORMAL = "normal"</code> |
| L0092 | 计算并保存 &#96;ROLE_ADMIN&#96;（ROLEADMIN），供后续逻辑使用。 | <code>ROLE_ADMIN = "admin"</code> |
| L0093 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0094 | 计算并保存 &#96;PROCESS_STATUS_SET&#96;（PROCESS状态SET），供后续逻辑使用。 | <code>PROCESS_STATUS_SET = {"unprocessed", "processing", "done", "ignored"}</code> |
| L0095 | 计算并保存 &#96;RISK_LEVEL_SET&#96;（RISKLEVELSET），供后续逻辑使用。 | <code>RISK_LEVEL_SET = {"critical", "high", "medium", "low"}</code> |
| L0096 | 计算并保存 &#96;RAG_SEVERITY_SET&#96;（RAGSEVERITYSET），供后续逻辑使用。 | <code>RAG_SEVERITY_SET = {"low", "medium", "high", "critical"}</code> |
| L0097 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0098 | 计算并保存 &#96;TOKEN_TTL_SECONDS&#96;（TOKENTTLSECONDS），供后续逻辑使用。 | <code>TOKEN_TTL_SECONDS = 12 * 3600</code> |
| L0099 | 计算并保存 &#96;JWT_ALGORITHM&#96;（JWTALGORITHM），供后续逻辑使用。 | <code>JWT_ALGORITHM = "HS256"</code> |
| L0100 | 计算并保存 &#96;JWT_HEADER&#96;（JWTHEADER），供后续逻辑使用。 | <code>JWT_HEADER = {"alg": JWT_ALGORITHM, "typ": "JWT"}</code> |
| L0101 | 计算并保存 &#96;JWT_REVOKED_JTIS&#96;（JWTREVOKEDJTIS），供后续逻辑使用。 | <code>JWT_REVOKED_JTIS: Dict[str, int] = {}</code> |
| L0102 | 计算并保存 &#96;AUTH_COOKIE_NAME&#96;（AUTHCOOKIENAME），供后续逻辑使用。 | <code>AUTH_COOKIE_NAME = "tp_auth_token"</code> |
| L0103 | 计算并保存 &#96;PROJECT_ROOT&#96;（PROJECTROOT），供后续逻辑使用。 | <code>PROJECT_ROOT = Path(__file__).resolve().parent.parent</code> |
| L0104 | 计算并保存 &#96;DASHBOARD_PUBLIC_DIR&#96;（DASHBOARDPUBLICDIR），供后续逻辑使用。 | <code>DASHBOARD_PUBLIC_DIR = PROJECT_ROOT / "frontend_dashboard" / "public"</code> |
| L0105 | 计算并保存 &#96;DASHBOARD_UPLOAD_DIR&#96;（DASHBOARDUPLOADDIR），供后续逻辑使用。 | <code>DASHBOARD_UPLOAD_DIR = DASHBOARD_PUBLIC_DIR / "uploads"</code> |
| L0106 | 计算并保存 &#96;AVATAR_UPLOAD_DIR&#96;（AVATARUPLOADDIR），供后续逻辑使用。 | <code>AVATAR_UPLOAD_DIR = DASHBOARD_UPLOAD_DIR / "avatars"</code> |
| L0107 | 计算并保存 &#96;DEFAULT_HOMEPAGE_BACKGROUND&#96;（DEFAULTHOMEPAGEBACKGROUND），供后续逻辑使用。 | <code>DEFAULT_HOMEPAGE_BACKGROUND = "/assets/bg-alt.jpg"</code> |
| L0108 | 计算并保存 &#96;ALLOWED_BACKGROUND_EXTENSIONS&#96;（ALLOWEDBACKGROUNDEXTENSIONS），供后续逻辑使用。 | <code>ALLOWED_BACKGROUND_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}</code> |
| L0109 | 计算并保存 &#96;MAX_BACKGROUND_BYTES&#96;（MAXBACKGROUNDBYTES），供后续逻辑使用。 | <code>MAX_BACKGROUND_BYTES = 10 * 1024 * 1024</code> |
| L0110 | 计算并保存 &#96;ALLOWED_AVATAR_EXTENSIONS&#96;（ALLOWEDAVATAREXTENSIONS），供后续逻辑使用。 | <code>ALLOWED_AVATAR_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}</code> |
| L0111 | 计算并保存 &#96;MAX_AVATAR_BYTES&#96;（MAXAVATARBYTES），供后续逻辑使用。 | <code>MAX_AVATAR_BYTES = 2 * 1024 * 1024</code> |
| L0112 | 计算并保存 &#96;DEFAULT_JWT_SECRET_PATH&#96;（DEFAULTJWTSECRETPATH），供后续逻辑使用。 | <code>DEFAULT_JWT_SECRET_PATH = PROJECT_ROOT / "config" / "jwt_secret.txt"</code> |
| L0113 | 计算并保存 &#96;DEFAULT_LLM_PROMPT_PATH&#96;（DEFAULTLLMPROMPTPATH），供后续逻辑使用。 | <code>DEFAULT_LLM_PROMPT_PATH = PROJECT_ROOT / "llm" / "prompts" / "system_prompt.txt"</code> |
| L0114 | 计算并保存 &#96;DEFAULT_PROFESSIONAL_REPORT_PROMPT_PATH&#96;（DEFAULTPROFESSIONAL报告PROMPTPATH），供后续逻辑使用。 | <code>DEFAULT_PROFESSIONAL_REPORT_PROMPT_PATH = PROJECT_ROOT / "llm" / "prompts" / "professional_situation_report_prompt.txt"</code> |
| L0115 | 计算并保存 &#96;MAX_LLM_PROMPT_CHARS&#96;（MAXLLMPROMPTCHARS），供后续逻辑使用。 | <code>MAX_LLM_PROMPT_CHARS = 30000</code> |
| L0116 | 计算并保存 &#96;MAX_PROFESSIONAL_REPORT_PROMPT_CHARS&#96;（MAXPROFESSIONAL报告PROMPTCHARS），供后续逻辑使用。 | <code>MAX_PROFESSIONAL_REPORT_PROMPT_CHARS = 60000</code> |
| L0117 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0118 | 计算并保存 &#96;DEMO_ACCOUNTS&#96;（DEMOACCOUNTS），供后续逻辑使用。 | <code>DEMO_ACCOUNTS = [</code> |
| L0119 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    {"username": "user", "password": "admin", "role": ROLE_NORMAL, "display_name": "普通用户"},</code> |
| L0120 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    {"username": "admin", "password": "admin", "role": ROLE_ADMIN, "display_name": "管理员"},</code> |
| L0121 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>]</code> |
| L0122 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0123 | 计算并保存 &#96;DEMO_SEED_USERS&#96;（DEMOSEEDUSERS），供后续逻辑使用。 | <code>DEMO_SEED_USERS = [</code> |
| L0124 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    {"username": "user", "password": "admin", "role": ROLE_NORMAL, "display_name": "普通用户"},</code> |
| L0125 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    {"username": "admin", "password": "admin", "role": ROLE_ADMIN, "display_name": "管理员"},</code> |
| L0126 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>]</code> |
| L0127 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0128 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0129 | 定义finddemoaccount函数 &#96;find_demo_account&#96;，封装可复用业务逻辑。 | <code>def find_demo_account(conn: Any, username: str, password: str, role_hint: str = "") -&gt; Optional[Dict[str, Any]]:</code> |
| L0130 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 find_demo_account。 | <code>    with conn.cursor() as cur:</code> |
| L0131 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 find_demo_account。 | <code>        if role_hint:</code> |
| L0132 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 find_demo_account。 | <code>            cur.execute(</code> |
| L0133 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_demo_account。 | <code>                """</code> |
| L0134 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 find_demo_account。 | <code>                SELECT id, username, password, role, display_name, nickname, avatar_url</code> |
| L0135 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_demo_account。 | <code>                FROM demo_users</code> |
| L0136 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_demo_account。 | <code>                WHERE username=%s AND password=%s AND role=%s</code> |
| L0137 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_demo_account。 | <code>                LIMIT 1</code> |
| L0138 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_demo_account。 | <code>                """,</code> |
| L0139 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_demo_account。 | <code>                (username, password, role_hint),</code> |
| L0140 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 find_demo_account。 | <code>            )</code> |
| L0141 | 结束当前函数并把结果返回给调用方，当前位于函数 find_demo_account。 | <code>            return cur.fetchone()</code> |
| L0142 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 find_demo_account。 | <code>        cur.execute(</code> |
| L0143 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_demo_account。 | <code>            """</code> |
| L0144 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 find_demo_account。 | <code>            SELECT id, username, password, role, display_name, nickname, avatar_url</code> |
| L0145 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_demo_account。 | <code>            FROM demo_users</code> |
| L0146 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_demo_account。 | <code>            WHERE username=%s AND password=%s</code> |
| L0147 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_demo_account。 | <code>              AND role IN (%s, %s)</code> |
| L0148 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_demo_account。 | <code>            ORDER BY CASE WHEN role=%s THEN 0 ELSE 1 END</code> |
| L0149 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_demo_account。 | <code>            LIMIT 1</code> |
| L0150 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_demo_account。 | <code>            """,</code> |
| L0151 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_demo_account。 | <code>            (username, password, ROLE_NORMAL, ROLE_ADMIN, ROLE_ADMIN),</code> |
| L0152 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 find_demo_account。 | <code>        )</code> |
| L0153 | 结束当前函数并把结果返回给调用方，当前位于函数 find_demo_account。 | <code>        return cur.fetchone()</code> |
| L0154 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0155 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0156 | 定义列出demoaccounts函数 &#96;list_demo_accounts&#96;，封装可复用业务逻辑。 | <code>def list_demo_accounts(conn: Any) -&gt; List[Dict[str, Any]]:</code> |
| L0157 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 list_demo_accounts。 | <code>    with conn.cursor() as cur:</code> |
| L0158 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 list_demo_accounts。 | <code>        cur.execute(</code> |
| L0159 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_demo_accounts。 | <code>            """</code> |
| L0160 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 list_demo_accounts。 | <code>            SELECT username, password, role</code> |
| L0161 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_demo_accounts。 | <code>            FROM demo_users</code> |
| L0162 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_demo_accounts。 | <code>            WHERE role IN (%s, %s)</code> |
| L0163 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_demo_accounts。 | <code>            ORDER BY CASE role</code> |
| L0164 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_demo_accounts。 | <code>                WHEN %s THEN 1</code> |
| L0165 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_demo_accounts。 | <code>                WHEN %s THEN 2</code> |
| L0166 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_demo_accounts。 | <code>                ELSE 3</code> |
| L0167 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_demo_accounts。 | <code>            END, username</code> |
| L0168 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_demo_accounts。 | <code>            """,</code> |
| L0169 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_demo_accounts。 | <code>            (ROLE_NORMAL, ROLE_ADMIN, ROLE_NORMAL, ROLE_ADMIN),</code> |
| L0170 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 list_demo_accounts。 | <code>        )</code> |
| L0171 | 结束当前函数并把结果返回给调用方，当前位于函数 list_demo_accounts。 | <code>        return cur.fetchall()</code> |
| L0172 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0173 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0174 | 计算并保存 &#96;ATTACK_TYPES&#96;（攻击TYPES），供后续逻辑使用。 | <code>ATTACK_TYPES = [</code> |
| L0175 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SQL注入",</code> |
| L0176 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "XSS",</code> |
| L0177 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "暴力破解",</code> |
| L0178 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "DDoS",</code> |
| L0179 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "端口扫描",</code> |
| L0180 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "命令注入",</code> |
| L0181 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "路径遍历",</code> |
| L0182 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "文件上传",</code> |
| L0183 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "危险文件上传",</code> |
| L0184 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SSRF",</code> |
| L0185 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "RCE",</code> |
| L0186 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "XXE",</code> |
| L0187 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SSTI",</code> |
| L0188 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "反序列化",</code> |
| L0189 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "GraphQL探测",</code> |
| L0190 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>]</code> |
| L0191 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0192 | 计算并保存 &#96;SOURCE_REGIONS&#96;（来源REGIONS），供后续逻辑使用。 | <code>SOURCE_REGIONS = [</code> |
| L0193 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "北京",</code> |
| L0194 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "上海",</code> |
| L0195 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "广东",</code> |
| L0196 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "浙江",</code> |
| L0197 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "江苏",</code> |
| L0198 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "山东",</code> |
| L0199 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "河南",</code> |
| L0200 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "四川",</code> |
| L0201 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "香港",</code> |
| L0202 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "美国",</code> |
| L0203 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "德国",</code> |
| L0204 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "新加坡",</code> |
| L0205 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>]</code> |
| L0206 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0207 | 计算并保存 &#96;TARGET_INTERFACES&#96;（TARGETINTERFACES），供后续逻辑使用。 | <code>TARGET_INTERFACES = [</code> |
| L0208 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/api/auth/login",</code> |
| L0209 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/api/v1/user/profile",</code> |
| L0210 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/api/v1/order/create",</code> |
| L0211 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/admin/config/update",</code> |
| L0212 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/gateway/payment/callback",</code> |
| L0213 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/search/query",</code> |
| L0214 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/upload/file",</code> |
| L0215 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/api/v2/token/refresh",</code> |
| L0216 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>]</code> |
| L0217 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0218 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0219 | 定义nowdt函数 &#96;now_dt&#96;，封装可复用业务逻辑。 | <code>def now_dt() -&gt; datetime:</code> |
| L0220 | 结束当前函数并把结果返回给调用方，当前位于函数 now_dt。 | <code>    return datetime.now()</code> |
| L0221 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0222 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0223 | 定义dttostr函数 &#96;dt_to_str&#96;，封装可复用业务逻辑。 | <code>def dt_to_str(dt: Optional[datetime], ms: bool = True) -&gt; Optional[str]:</code> |
| L0224 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 dt_to_str。 | <code>    if dt is None:</code> |
| L0225 | 结束当前函数并把结果返回给调用方，当前位于函数 dt_to_str。 | <code>        return None</code> |
| L0226 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 dt_to_str。 | <code>    if ms:</code> |
| L0227 | 结束当前函数并把结果返回给调用方，当前位于函数 dt_to_str。 | <code>        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]</code> |
| L0228 | 结束当前函数并把结果返回给调用方，当前位于函数 dt_to_str。 | <code>    return dt.strftime("%Y-%m-%d %H:%M:%S")</code> |
| L0229 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0230 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0231 | 定义解析并确定projectpath函数 &#96;resolve_project_path&#96;，封装可复用业务逻辑。 | <code>def resolve_project_path(path_text: str, default_path: Path) -&gt; Path:</code> |
| L0232 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 resolve_project_path。 | <code>    raw = str(path_text or "").strip()</code> |
| L0233 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_project_path。 | <code>    if not raw:</code> |
| L0234 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_project_path。 | <code>        return default_path.resolve()</code> |
| L0235 | 计算并保存 &#96;path&#96;（path），供后续逻辑使用，当前位于函数 resolve_project_path。 | <code>    path = Path(raw)</code> |
| L0236 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_project_path。 | <code>    if path.is_absolute():</code> |
| L0237 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_project_path。 | <code>        return path.resolve()</code> |
| L0238 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_project_path。 | <code>    return (PROJECT_ROOT / path).resolve()</code> |
| L0239 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0240 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0241 | 定义displayprojectpath函数 &#96;display_project_path&#96;，封装可复用业务逻辑。 | <code>def display_project_path(path: Path) -&gt; str:</code> |
| L0242 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 display_project_path。 | <code>    try:</code> |
| L0243 | 结束当前函数并把结果返回给调用方，当前位于函数 display_project_path。 | <code>        return str(path.resolve().relative_to(PROJECT_ROOT))</code> |
| L0244 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 display_project_path。 | <code>    except Exception:</code> |
| L0245 | 结束当前函数并把结果返回给调用方，当前位于函数 display_project_path。 | <code>        return str(path.resolve())</code> |
| L0246 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0247 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0248 | 定义加载or创建jwtsecret函数 &#96;load_or_create_jwt_secret&#96;，封装可复用业务逻辑。 | <code>def load_or_create_jwt_secret(path: Path = DEFAULT_JWT_SECRET_PATH) -&gt; str:</code> |
| L0249 | 计算并保存 &#96;path&#96;（path），供后续逻辑使用，当前位于函数 load_or_create_jwt_secret。 | <code>    path = path.resolve()</code> |
| L0250 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_or_create_jwt_secret。 | <code>    if path.exists():</code> |
| L0251 | 计算并保存 &#96;secret&#96;（secret），供后续逻辑使用，当前位于函数 load_or_create_jwt_secret。 | <code>        secret = path.read_text(encoding="utf-8-sig", errors="replace").strip()</code> |
| L0252 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_or_create_jwt_secret。 | <code>        if secret:</code> |
| L0253 | 结束当前函数并把结果返回给调用方，当前位于函数 load_or_create_jwt_secret。 | <code>            return secret</code> |
| L0254 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_or_create_jwt_secret。 | <code>    path.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0255 | 计算并保存 &#96;secret&#96;（secret），供后续逻辑使用，当前位于函数 load_or_create_jwt_secret。 | <code>    secret = secrets.token_urlsafe(48)</code> |
| L0256 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_or_create_jwt_secret。 | <code>    path.write_text(secret, encoding="utf-8")</code> |
| L0257 | 结束当前函数并把结果返回给调用方，当前位于函数 load_or_create_jwt_secret。 | <code>    return secret</code> |
| L0258 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0259 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0260 | 定义读取llmpromptfile函数 &#96;read_llm_prompt_file&#96;，封装可复用业务逻辑。 | <code>def read_llm_prompt_file(path: Path) -&gt; str:</code> |
| L0261 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_llm_prompt_file。 | <code>    if not path.exists():</code> |
| L0262 | 结束当前函数并把结果返回给调用方，当前位于函数 read_llm_prompt_file。 | <code>        return ""</code> |
| L0263 | 结束当前函数并把结果返回给调用方，当前位于函数 read_llm_prompt_file。 | <code>    return path.read_text(encoding="utf-8-sig", errors="replace")</code> |
| L0264 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0265 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0266 | 定义写入llmpromptfile函数 &#96;write_llm_prompt_file&#96;，封装可复用业务逻辑。 | <code>def write_llm_prompt_file(path: Path, content: str) -&gt; None:</code> |
| L0267 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_llm_prompt_file。 | <code>    path.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0268 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_llm_prompt_file。 | <code>    path.write_text(content, encoding="utf-8")</code> |
| L0269 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0270 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0271 | 定义构建llmpromptpayload函数 &#96;build_llm_prompt_payload&#96;，封装可复用业务逻辑。 | <code>def build_llm_prompt_payload(path: Path) -&gt; Dict[str, Any]:</code> |
| L0272 | 计算并保存 &#96;content&#96;（content），供后续逻辑使用，当前位于函数 build_llm_prompt_payload。 | <code>    content = read_llm_prompt_file(path)</code> |
| L0273 | 计算并保存 &#96;updated_at&#96;（updatedat），供后续逻辑使用，当前位于函数 build_llm_prompt_payload。 | <code>    updated_at = None</code> |
| L0274 | 计算并保存 &#96;exists&#96;（exists），供后续逻辑使用，当前位于函数 build_llm_prompt_payload。 | <code>    exists = path.exists()</code> |
| L0275 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_llm_prompt_payload。 | <code>    if exists:</code> |
| L0276 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 build_llm_prompt_payload。 | <code>        try:</code> |
| L0277 | 计算并保存 &#96;updated_at&#96;（updatedat），供后续逻辑使用，当前位于函数 build_llm_prompt_payload。 | <code>            updated_at = dt_to_str(datetime.fromtimestamp(path.stat().st_mtime), ms=False)</code> |
| L0278 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 build_llm_prompt_payload。 | <code>        except Exception:</code> |
| L0279 | 计算并保存 &#96;updated_at&#96;（updatedat），供后续逻辑使用，当前位于函数 build_llm_prompt_payload。 | <code>            updated_at = None</code> |
| L0280 | 结束当前函数并把结果返回给调用方，当前位于函数 build_llm_prompt_payload。 | <code>    return {</code> |
| L0281 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_llm_prompt_payload。 | <code>        "prompt": content,</code> |
| L0282 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_llm_prompt_payload。 | <code>        "path": display_project_path(path),</code> |
| L0283 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_llm_prompt_payload。 | <code>        "exists": exists,</code> |
| L0284 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_llm_prompt_payload。 | <code>        "updated_at": updated_at,</code> |
| L0285 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_llm_prompt_payload。 | <code>        "max_chars": MAX_LLM_PROMPT_CHARS,</code> |
| L0286 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_llm_prompt_payload。 | <code>        "chars": len(content),</code> |
| L0287 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_llm_prompt_payload。 | <code>    }</code> |
| L0288 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0289 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0290 | 定义标准化value函数 &#96;normalize_value&#96;，封装可复用业务逻辑。 | <code>def normalize_value(value: Any) -&gt; Any:</code> |
| L0291 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_value。 | <code>    if isinstance(value, datetime):</code> |
| L0292 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_value。 | <code>        return dt_to_str(value)</code> |
| L0293 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_value。 | <code>    return value</code> |
| L0294 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0295 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0296 | 定义标准化row函数 &#96;normalize_row&#96;，封装可复用业务逻辑。 | <code>def normalize_row(row: Dict[str, Any]) -&gt; Dict[str, Any]:</code> |
| L0297 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_row。 | <code>    return {k: normalize_value(v) for k, v in row.items()}</code> |
| L0298 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0299 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0300 | 定义标准化数据库记录函数 &#96;normalize_rows&#96;，封装可复用业务逻辑。 | <code>def normalize_rows(rows: List[Dict[str, Any]]) -&gt; List[Dict[str, Any]]:</code> |
| L0301 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_rows。 | <code>    return [normalize_row(r) for r in rows]</code> |
| L0302 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0303 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0304 | 计算并保存 &#96;DISPLAY_IPV4_RE&#96;（DISPLAYIPV4RE），供后续逻辑使用。 | <code>DISPLAY_IPV4_RE = re.compile(r"(?&lt;![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")</code> |
| L0305 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0306 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0307 | 定义sanitizeevidencetext函数 &#96;sanitize_evidence_text&#96;，封装可复用业务逻辑。 | <code>def sanitize_evidence_text(value: Any) -&gt; str:</code> |
| L0308 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 sanitize_evidence_text。 | <code>    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(value or "")).strip()</code> |
| L0309 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sanitize_evidence_text。 | <code>    if not text:</code> |
| L0310 | 结束当前函数并把结果返回给调用方，当前位于函数 sanitize_evidence_text。 | <code>        return ""</code> |
| L0311 | 计算并保存 &#96;replacement_count&#96;（replacementcount），供后续逻辑使用，当前位于函数 sanitize_evidence_text。 | <code>    replacement_count = text.count("�")</code> |
| L0312 | 计算并保存 &#96;question_runs&#96;（questionruns），供后续逻辑使用，当前位于函数 sanitize_evidence_text。 | <code>    question_runs = sum(len(match.group(0)) for match in re.finditer(r"\?{4,}", text))</code> |
| L0313 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sanitize_evidence_text。 | <code>    if replacement_count or question_runs &gt;= 8:</code> |
| L0314 | 计算并保存 &#96;ips&#96;（ips），供后续逻辑使用，当前位于函数 sanitize_evidence_text。 | <code>        ips = list(dict.fromkeys(DISPLAY_IPV4_RE.findall(text)))[:5]</code> |
| L0315 | 计算并保存 &#96;suffix&#96;（suffix），供后续逻辑使用，当前位于函数 sanitize_evidence_text。 | <code>        suffix = f"；关联IP：{'、'.join(ips)}" if ips else ""</code> |
| L0316 | 结束当前函数并把结果返回给调用方，当前位于函数 sanitize_evidence_text。 | <code>        return f"Windows 登录失败事件（历史原始消息编码异常，乱码内容已隐藏）{suffix}"</code> |
| L0317 | 结束当前函数并把结果返回给调用方，当前位于函数 sanitize_evidence_text。 | <code>    return text</code> |
| L0318 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0319 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0320 | 定义sanitizeevidencevalue函数 &#96;sanitize_evidence_value&#96;，封装可复用业务逻辑。 | <code>def sanitize_evidence_value(value: Any) -&gt; Any:</code> |
| L0321 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sanitize_evidence_value。 | <code>    if isinstance(value, dict):</code> |
| L0322 | 结束当前函数并把结果返回给调用方，当前位于函数 sanitize_evidence_value。 | <code>        return {key: sanitize_evidence_value(item) for key, item in value.items()}</code> |
| L0323 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sanitize_evidence_value。 | <code>    if isinstance(value, list):</code> |
| L0324 | 结束当前函数并把结果返回给调用方，当前位于函数 sanitize_evidence_value。 | <code>        return [sanitize_evidence_value(item) for item in value]</code> |
| L0325 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sanitize_evidence_value。 | <code>    if isinstance(value, str):</code> |
| L0326 | 结束当前函数并把结果返回给调用方，当前位于函数 sanitize_evidence_value。 | <code>        return sanitize_evidence_text(value)</code> |
| L0327 | 结束当前函数并把结果返回给调用方，当前位于函数 sanitize_evidence_value。 | <code>    return value</code> |
| L0328 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0329 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0330 | 定义标准化态势value函数 &#96;normalize_situation_value&#96;，封装可复用业务逻辑。 | <code>def normalize_situation_value(value: Any) -&gt; Any:</code> |
| L0331 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_situation_value。 | <code>    if isinstance(value, datetime):</code> |
| L0332 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_situation_value。 | <code>        return value.isoformat(timespec="milliseconds") + ("Z" if value.tzinfo is None else "")</code> |
| L0333 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_situation_value。 | <code>    if isinstance(value, dict):</code> |
| L0334 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_situation_value。 | <code>        return {</code> |
| L0335 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_situation_value。 | <code>            key: normalize_situation_value(sanitize_evidence_value(item) if key in {"evidence", "metadata"} else item)</code> |
| L0336 | 遍历集合中的数据项并逐项处理，当前位于函数 normalize_situation_value。 | <code>            for key, item in value.items()</code> |
| L0337 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_situation_value。 | <code>        }</code> |
| L0338 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_situation_value。 | <code>    if isinstance(value, list):</code> |
| L0339 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_situation_value。 | <code>        return [normalize_situation_value(item) for item in value]</code> |
| L0340 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_situation_value。 | <code>    return value</code> |
| L0341 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0342 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0343 | 定义safejsonloads函数 &#96;safe_json_loads&#96;，封装可复用业务逻辑。 | <code>def safe_json_loads(text: Any, default: Any = None) -&gt; Any:</code> |
| L0344 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 safe_json_loads。 | <code>    if default is None:</code> |
| L0345 | 计算并保存 &#96;default&#96;（default），供后续逻辑使用，当前位于函数 safe_json_loads。 | <code>        default = []</code> |
| L0346 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 safe_json_loads。 | <code>    if text is None:</code> |
| L0347 | 结束当前函数并把结果返回给调用方，当前位于函数 safe_json_loads。 | <code>        return default</code> |
| L0348 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 safe_json_loads。 | <code>    if isinstance(text, (dict, list)):</code> |
| L0349 | 结束当前函数并把结果返回给调用方，当前位于函数 safe_json_loads。 | <code>        return text</code> |
| L0350 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 safe_json_loads。 | <code>    raw = str(text or "").strip()</code> |
| L0351 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 safe_json_loads。 | <code>    if not raw:</code> |
| L0352 | 结束当前函数并把结果返回给调用方，当前位于函数 safe_json_loads。 | <code>        return default</code> |
| L0353 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 safe_json_loads。 | <code>    try:</code> |
| L0354 | 结束当前函数并把结果返回给调用方，当前位于函数 safe_json_loads。 | <code>        return json.loads(raw)</code> |
| L0355 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 safe_json_loads。 | <code>    except Exception:</code> |
| L0356 | 结束当前函数并把结果返回给调用方，当前位于函数 safe_json_loads。 | <code>        return default</code> |
| L0357 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0358 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0359 | 定义数据库tableexists函数 &#96;db_table_exists&#96;，封装可复用业务逻辑。 | <code>def db_table_exists(cur: Any, table_name: str) -&gt; bool:</code> |
| L0360 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 db_table_exists。 | <code>    try:</code> |
| L0361 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 db_table_exists。 | <code>        cur.execute("SHOW TABLES LIKE %s", (table_name,))</code> |
| L0362 | 结束当前函数并把结果返回给调用方，当前位于函数 db_table_exists。 | <code>        return bool(cur.fetchone())</code> |
| L0363 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 db_table_exists。 | <code>    except Exception:</code> |
| L0364 | 结束当前函数并把结果返回给调用方，当前位于函数 db_table_exists。 | <code>        return False</code> |
| L0365 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0366 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0367 | 定义数据库columnexists函数 &#96;db_column_exists&#96;，封装可复用业务逻辑。 | <code>def db_column_exists(cur: Any, table_name: str, column_name: str) -&gt; bool:</code> |
| L0368 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 db_column_exists。 | <code>    try:</code> |
| L0369 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 db_column_exists。 | <code>        cur.execute(f"SHOW COLUMNS FROM &#96;{table_name}&#96; LIKE %s", (column_name,))</code> |
| L0370 | 结束当前函数并把结果返回给调用方，当前位于函数 db_column_exists。 | <code>        return bool(cur.fetchone())</code> |
| L0371 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 db_column_exists。 | <code>    except Exception:</code> |
| L0372 | 结束当前函数并把结果返回给调用方，当前位于函数 db_column_exists。 | <code>        return False</code> |
| L0373 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0374 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0375 | 定义事件idtov2candidates函数 &#96;event_id_to_v2_candidates&#96;，封装可复用业务逻辑。 | <code>def event_id_to_v2_candidates(event_id: str) -&gt; Tuple[List[str], List[str]]:</code> |
| L0376 | 计算并保存 &#96;event&#96;（事件），供后续逻辑使用，当前位于函数 event_id_to_v2_candidates。 | <code>    event = str(event_id or "").strip()</code> |
| L0377 | 计算并保存 &#96;event_ids&#96;（事件ids），供后续逻辑使用，当前位于函数 event_id_to_v2_candidates。 | <code>    event_ids = [event] if event else []</code> |
| L0378 | 计算并保存 &#96;case_ids&#96;（caseids），供后续逻辑使用，当前位于函数 event_id_to_v2_candidates。 | <code>    case_ids = [event] if event else []</code> |
| L0379 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 event_id_to_v2_candidates。 | <code>    if event.startswith("b."):</code> |
| L0380 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 event_id_to_v2_candidates。 | <code>        event_ids.append(event.replace("b.", "EVT", 1))</code> |
| L0381 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 event_id_to_v2_candidates。 | <code>    if event.startswith("EVT"):</code> |
| L0382 | 计算并保存 &#96;suffix&#96;（suffix），供后续逻辑使用，当前位于函数 event_id_to_v2_candidates。 | <code>        suffix = event[3:]</code> |
| L0383 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 event_id_to_v2_candidates。 | <code>        if suffix:</code> |
| L0384 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 event_id_to_v2_candidates。 | <code>            case_ids.append(f"b.{suffix}")</code> |
| L0385 | 结束当前函数并把结果返回给调用方，当前位于函数 event_id_to_v2_candidates。 | <code>    return list(dict.fromkeys(event_ids)), list(dict.fromkeys(case_ids))</code> |
| L0386 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0387 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0388 | 定义加载v2detectiondetail函数 &#96;load_v2_detection_detail&#96;，封装可复用业务逻辑。 | <code>def load_v2_detection_detail(cur: Any, event_id: str) -&gt; Optional[Dict[str, Any]]:</code> |
| L0389 | 计算并保存 &#96;required_tables&#96;（requiredtables），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>    required_tables = [</code> |
| L0390 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "detection_candidates",</code> |
| L0391 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "raw_http_logs",</code> |
| L0392 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "model_predictions",</code> |
| L0393 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "poc_matches",</code> |
| L0394 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "behavior_windows",</code> |
| L0395 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_v2_detection_detail。 | <code>    ]</code> |
| L0396 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>    if not any(db_table_exists(cur, t) for t in required_tables):</code> |
| L0397 | 结束当前函数并把结果返回给调用方，当前位于函数 load_v2_detection_detail。 | <code>        return None</code> |
| L0398 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0399 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>    event_ids, case_ids = event_id_to_v2_candidates(event_id)</code> |
| L0400 | 计算并保存 &#96;candidate&#96;（candidate），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>    candidate = None</code> |
| L0401 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>    if db_table_exists(cur, "detection_candidates"):</code> |
| L0402 | 遍历集合中的数据项并逐项处理，当前位于函数 load_v2_detection_detail。 | <code>        for eid in event_ids:</code> |
| L0403 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 load_v2_detection_detail。 | <code>            cur.execute(</code> |
| L0404 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                """</code> |
| L0405 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 load_v2_detection_detail。 | <code>                SELECT event_id, case_id, file_id, seq_id, decision, final_score, risk_level,</code> |
| L0406 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                       attack_type, source_ip, target_interface, evidence_json, created_at</code> |
| L0407 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                FROM detection_candidates</code> |
| L0408 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                WHERE event_id=%s</code> |
| L0409 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                LIMIT 1</code> |
| L0410 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                """,</code> |
| L0411 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>                (eid,),</code> |
| L0412 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_v2_detection_detail。 | <code>            )</code> |
| L0413 | 计算并保存 &#96;candidate&#96;（candidate），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>            candidate = cur.fetchone()</code> |
| L0414 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>            if candidate:</code> |
| L0415 | 控制当前循环或占位分支的执行流程，当前位于函数 load_v2_detection_detail。 | <code>                break</code> |
| L0416 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>        if not candidate:</code> |
| L0417 | 遍历集合中的数据项并逐项处理，当前位于函数 load_v2_detection_detail。 | <code>            for cid in case_ids:</code> |
| L0418 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 load_v2_detection_detail。 | <code>                cur.execute(</code> |
| L0419 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                    """</code> |
| L0420 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 load_v2_detection_detail。 | <code>                    SELECT event_id, case_id, file_id, seq_id, decision, final_score, risk_level,</code> |
| L0421 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                           attack_type, source_ip, target_interface, evidence_json, created_at</code> |
| L0422 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                    FROM detection_candidates</code> |
| L0423 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                    WHERE case_id=%s</code> |
| L0424 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                    LIMIT 1</code> |
| L0425 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                    """,</code> |
| L0426 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>                    (cid,),</code> |
| L0427 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_v2_detection_detail。 | <code>                )</code> |
| L0428 | 计算并保存 &#96;candidate&#96;（candidate），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>                candidate = cur.fetchone()</code> |
| L0429 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>                if candidate:</code> |
| L0430 | 控制当前循环或占位分支的执行流程，当前位于函数 load_v2_detection_detail。 | <code>                    break</code> |
| L0431 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0432 | 计算并保存 &#96;attack_event&#96;（攻击事件），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>    attack_event = None</code> |
| L0433 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>    if db_table_exists(cur, "attack_events"):</code> |
| L0434 | 遍历集合中的数据项并逐项处理，当前位于函数 load_v2_detection_detail。 | <code>        for eid in event_ids + ([str(candidate.get("event_id"))] if candidate else []):</code> |
| L0435 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>            if not eid:</code> |
| L0436 | 控制当前循环或占位分支的执行流程，当前位于函数 load_v2_detection_detail。 | <code>                continue</code> |
| L0437 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 load_v2_detection_detail。 | <code>            cur.execute(</code> |
| L0438 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                """</code> |
| L0439 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 load_v2_detection_detail。 | <code>                SELECT event_id, case_id, occurred_at, source_ip, target_interface, attack_type,</code> |
| L0440 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                       risk_level, confidence, status, evidence_json, created_at</code> |
| L0441 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                FROM attack_events</code> |
| L0442 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                WHERE event_id=%s</code> |
| L0443 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                LIMIT 1</code> |
| L0444 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                """,</code> |
| L0445 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>                (eid,),</code> |
| L0446 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_v2_detection_detail。 | <code>            )</code> |
| L0447 | 计算并保存 &#96;attack_event&#96;（攻击事件），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>            attack_event = cur.fetchone()</code> |
| L0448 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>            if attack_event:</code> |
| L0449 | 控制当前循环或占位分支的执行流程，当前位于函数 load_v2_detection_detail。 | <code>                break</code> |
| L0450 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0451 | 计算并保存 &#96;case_id&#96;（caseid），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>    case_id = ""</code> |
| L0452 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>    if candidate:</code> |
| L0453 | 计算并保存 &#96;case_id&#96;（caseid），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>        case_id = str(candidate.get("case_id") or "")</code> |
| L0454 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>    if not case_id and attack_event:</code> |
| L0455 | 计算并保存 &#96;case_id&#96;（caseid），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>        case_id = str(attack_event.get("case_id") or "")</code> |
| L0456 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>    if not case_id:</code> |
| L0457 | 遍历集合中的数据项并逐项处理，当前位于函数 load_v2_detection_detail。 | <code>        for cid in case_ids:</code> |
| L0458 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>            if cid.startswith("b."):</code> |
| L0459 | 计算并保存 &#96;case_id&#96;（caseid），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>                case_id = cid</code> |
| L0460 | 控制当前循环或占位分支的执行流程，当前位于函数 load_v2_detection_detail。 | <code>                break</code> |
| L0461 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>    if not case_id:</code> |
| L0462 | 结束当前函数并把结果返回给调用方，当前位于函数 load_v2_detection_detail。 | <code>        return None</code> |
| L0463 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0464 | 计算并保存 &#96;raw_http&#96;（rawhttp），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>    raw_http = None</code> |
| L0465 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>    if db_table_exists(cur, "raw_http_logs"):</code> |
| L0466 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 load_v2_detection_detail。 | <code>        cur.execute(</code> |
| L0467 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            """</code> |
| L0468 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 load_v2_detection_detail。 | <code>            SELECT case_id, file_id, seq_id, event_time, source_ip, destination_ip, method,</code> |
| L0469 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                   uri, host, status_code, request_text, response_text, created_at</code> |
| L0470 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            FROM raw_http_logs</code> |
| L0471 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            WHERE case_id=%s</code> |
| L0472 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            LIMIT 1</code> |
| L0473 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            """,</code> |
| L0474 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>            (case_id,),</code> |
| L0475 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_v2_detection_detail。 | <code>        )</code> |
| L0476 | 计算并保存 &#96;raw_http&#96;（rawhttp），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>        raw_http = cur.fetchone()</code> |
| L0477 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0478 | 计算并保存 &#96;model_predictions&#96;（模型predictions），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>    model_predictions: List[Dict[str, Any]] = []</code> |
| L0479 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>    if db_table_exists(cur, "model_predictions"):</code> |
| L0480 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 load_v2_detection_detail。 | <code>        cur.execute(</code> |
| L0481 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            """</code> |
| L0482 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 load_v2_detection_detail。 | <code>            SELECT model_name, label, score, proba_json, created_at</code> |
| L0483 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            FROM model_predictions</code> |
| L0484 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            WHERE case_id=%s</code> |
| L0485 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            ORDER BY id DESC</code> |
| L0486 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            LIMIT 10</code> |
| L0487 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            """,</code> |
| L0488 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>            (case_id,),</code> |
| L0489 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_v2_detection_detail。 | <code>        )</code> |
| L0490 | 计算并保存 &#96;model_predictions&#96;（模型predictions），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>        model_predictions = normalize_rows(cur.fetchall())</code> |
| L0491 | 遍历集合中的数据项并逐项处理，当前位于函数 load_v2_detection_detail。 | <code>        for pred in model_predictions:</code> |
| L0492 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>            pred["label"] = normalize_attack_type_label(pred.get("label"))</code> |
| L0493 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>            pred["proba"] = safe_json_loads(pred.pop("proba_json", None), {})</code> |
| L0494 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0495 | 计算并保存 &#96;poc_matches&#96;（pocmatches），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>    poc_matches: List[Dict[str, Any]] = []</code> |
| L0496 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>    if db_table_exists(cur, "poc_matches"):</code> |
| L0497 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 load_v2_detection_detail。 | <code>        cur.execute(</code> |
| L0498 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            """</code> |
| L0499 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 load_v2_detection_detail。 | <code>            SELECT rule_id, rule_name, attack_type, severity, score, evidence_json, created_at</code> |
| L0500 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            FROM poc_matches</code> |
| L0501 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            WHERE case_id=%s</code> |
| L0502 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            ORDER BY score DESC, id ASC</code> |
| L0503 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            LIMIT 20</code> |
| L0504 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            """,</code> |
| L0505 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>            (case_id,),</code> |
| L0506 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_v2_detection_detail。 | <code>        )</code> |
| L0507 | 计算并保存 &#96;poc_matches&#96;（pocmatches），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>        poc_matches = normalize_rows(cur.fetchall())</code> |
| L0508 | 遍历集合中的数据项并逐项处理，当前位于函数 load_v2_detection_detail。 | <code>        for match in poc_matches:</code> |
| L0509 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>            match["attack_type"] = normalize_attack_type_label(match.get("attack_type"))</code> |
| L0510 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>            match["evidence"] = safe_json_loads(match.pop("evidence_json", None), [])</code> |
| L0511 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0512 | 计算并保存 &#96;behavior_windows&#96;（behaviorwindows），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>    behavior_windows: List[Dict[str, Any]] = []</code> |
| L0513 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>    if db_table_exists(cur, "behavior_windows"):</code> |
| L0514 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 load_v2_detection_detail。 | <code>        cur.execute(</code> |
| L0515 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            """</code> |
| L0516 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 load_v2_detection_detail。 | <code>            SELECT source_ip, behavior_type, score, features_json, evidence_json, created_at</code> |
| L0517 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            FROM behavior_windows</code> |
| L0518 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            WHERE case_id=%s</code> |
| L0519 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            ORDER BY score DESC, id ASC</code> |
| L0520 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            LIMIT 10</code> |
| L0521 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            """,</code> |
| L0522 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>            (case_id,),</code> |
| L0523 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_v2_detection_detail。 | <code>        )</code> |
| L0524 | 计算并保存 &#96;behavior_windows&#96;（behaviorwindows），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>        behavior_windows = normalize_rows(cur.fetchall())</code> |
| L0525 | 遍历集合中的数据项并逐项处理，当前位于函数 load_v2_detection_detail。 | <code>        for win in behavior_windows:</code> |
| L0526 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>            win["features"] = safe_json_loads(win.pop("features_json", None), {})</code> |
| L0527 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>            win["evidence"] = safe_json_loads(win.pop("evidence_json", None), [])</code> |
| L0528 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0529 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>    evidence: List[Any] = []</code> |
| L0530 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>    if candidate:</code> |
| L0531 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>        evidence = sanitize_evidence_value(safe_json_loads(candidate.get("evidence_json"), []))</code> |
| L0532 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>    if not evidence and attack_event:</code> |
| L0533 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>        evidence = sanitize_evidence_value(safe_json_loads(attack_event.get("evidence_json"), []))</code> |
| L0534 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0535 | 计算并保存 &#96;llm_review&#96;（llmreview），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>    llm_review: Dict[str, Any] = {}</code> |
| L0536 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>    if db_table_exists(cur, "analyses"):</code> |
| L0537 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 load_v2_detection_detail。 | <code>        cur.execute(</code> |
| L0538 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            """</code> |
| L0539 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 load_v2_detection_detail。 | <code>            SELECT llm_status,llm_error,analyzed_at,model_name,verdict,severity,confidence,</code> |
| L0540 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                   summary,evidence_json,analysis_raw,rag_enabled,rag_hits,review_latency_ms,</code> |
| L0541 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>                   handling_suggestion,review_source</code> |
| L0542 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            FROM analyses WHERE case_id=%s LIMIT 1</code> |
| L0543 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            """,</code> |
| L0544 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>            (case_id,),</code> |
| L0545 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_v2_detection_detail。 | <code>        )</code> |
| L0546 | 计算并保存 &#96;llm_review&#96;（llmreview），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>        llm_review = normalize_row(cur.fetchone() or {})</code> |
| L0547 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>        if llm_review:</code> |
| L0548 | 计算并保存 &#96;llm_raw&#96;（llmraw），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>            llm_raw = safe_json_loads(llm_review.pop("analysis_raw", None), {})</code> |
| L0549 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>            llm_review["evidence"] = sanitize_evidence_value(</code> |
| L0550 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>                safe_json_loads(llm_review.pop("evidence_json", None), [])</code> |
| L0551 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_v2_detection_detail。 | <code>            )</code> |
| L0552 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>            if isinstance(llm_raw, dict):</code> |
| L0553 | 遍历集合中的数据项并逐项处理，当前位于函数 load_v2_detection_detail。 | <code>                for key in (</code> |
| L0554 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>                    "analysis_reasoning",</code> |
| L0555 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>                    "potential_impact",</code> |
| L0556 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>                    "immediate_actions",</code> |
| L0557 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>                    "hardening_actions",</code> |
| L0558 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>                    "false_positive_notes",</code> |
| L0559 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>                    "knowledge_references",</code> |
| L0560 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_v2_detection_detail。 | <code>                ):</code> |
| L0561 | 计算并保存 &#96;value&#96;（value），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>                    value = llm_raw.get(key)</code> |
| L0562 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>                    if value not in (None, "", []):</code> |
| L0563 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>                        llm_review[key] = sanitize_evidence_value(value)</code> |
| L0564 | 源码原注释：Old/model-generated references must never look like active RAG | <code>            # Old/model-generated references must never look like active RAG</code> |
| L0565 | 源码原注释：evidence when retrieval was disabled for this review. | <code>            # evidence when retrieval was disabled for this review.</code> |
| L0566 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>            if int(llm_review.get("rag_enabled") or 0) != 1:</code> |
| L0567 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>                llm_review.pop("knowledge_references", None)</code> |
| L0568 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>            if not llm_review["evidence"] and str(llm_review.get("summary") or "").strip():</code> |
| L0569 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>                llm_review["evidence"] = [</code> |
| L0570 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>                    f"大模型研判说明：{str(llm_review['summary']).strip()}"</code> |
| L0571 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_v2_detection_detail。 | <code>                ]</code> |
| L0572 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>    if db_table_exists(cur, "llm_review_jobs"):</code> |
| L0573 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 load_v2_detection_detail。 | <code>        cur.execute(</code> |
| L0574 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            """</code> |
| L0575 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 load_v2_detection_detail。 | <code>            SELECT status,preliminary_decision,attempts,error_message,created_at,started_at,completed_at</code> |
| L0576 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            FROM llm_review_jobs WHERE case_id=%s LIMIT 1</code> |
| L0577 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_v2_detection_detail。 | <code>            """,</code> |
| L0578 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>            (case_id,),</code> |
| L0579 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_v2_detection_detail。 | <code>        )</code> |
| L0580 | 计算并保存 &#96;job&#96;（job），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>        job = normalize_row(cur.fetchone() or {})</code> |
| L0581 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>        if job:</code> |
| L0582 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>            llm_review["queue"] = job</code> |
| L0583 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>            if not llm_review.get("llm_status"):</code> |
| L0584 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>                llm_review["llm_status"] = job.get("status")</code> |
| L0585 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0586 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 load_v2_detection_detail。 | <code>    item: Dict[str, Any] = {</code> |
| L0587 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "case_id": case_id,</code> |
| L0588 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "event_id": str((candidate or attack_event or {}).get("event_id") or event_id),</code> |
| L0589 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "decision": str((candidate or {}).get("decision") or ("attack_event" if attack_event else "candidate")),</code> |
| L0590 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "final_score": (candidate or attack_event or {}).get("final_score")</code> |
| L0591 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>        if candidate</code> |
| L0592 | 处理前述条件均未命中的情况，当前位于函数 load_v2_detection_detail。 | <code>        else (attack_event or {}).get("confidence"),</code> |
| L0593 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "risk_level": (candidate or attack_event or {}).get("risk_level"),</code> |
| L0594 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "attack_type": normalize_attack_type_label((candidate or attack_event or {}).get("attack_type")),</code> |
| L0595 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "source_ip": (candidate or attack_event or raw_http or {}).get("source_ip"),</code> |
| L0596 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "target_interface": (candidate or attack_event or raw_http or {}).get("target_interface") or (raw_http or {}).get("uri"),</code> |
| L0597 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "evidence": evidence,</code> |
| L0598 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "candidate": normalize_row(candidate) if candidate else None,</code> |
| L0599 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "attack_event": normalize_row(attack_event) if attack_event else None,</code> |
| L0600 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "raw_http": normalize_row(raw_http) if raw_http else None,</code> |
| L0601 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "model_predictions": model_predictions,</code> |
| L0602 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "poc_matches": poc_matches,</code> |
| L0603 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "behavior_windows": behavior_windows,</code> |
| L0604 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        "llm_review": llm_review or None,</code> |
| L0605 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_v2_detection_detail。 | <code>    }</code> |
| L0606 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>    if item["candidate"]:</code> |
| L0607 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        item["candidate"]["evidence_json"] = None</code> |
| L0608 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_v2_detection_detail。 | <code>    if item["attack_event"]:</code> |
| L0609 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_v2_detection_detail。 | <code>        item["attack_event"]["evidence_json"] = None</code> |
| L0610 | 结束当前函数并把结果返回给调用方，当前位于函数 load_v2_detection_detail。 | <code>    return item</code> |
| L0611 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0612 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0613 | 定义标准化攻击typelabel函数 &#96;normalize_attack_type_label&#96;，封装可复用业务逻辑。 | <code>def normalize_attack_type_label(value: Any) -&gt; str:</code> |
| L0614 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 normalize_attack_type_label。 | <code>    raw = str(value or "").strip()</code> |
| L0615 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if not raw:</code> |
| L0616 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "可疑流量"</code> |
| L0617 | 计算并保存 &#96;t&#96;（t），供后续逻辑使用，当前位于函数 normalize_attack_type_label。 | <code>    t = raw.lower().replace(" ", "").replace("_", "").replace("-", "")</code> |
| L0618 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0619 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if any(x in t for x in ["sql", "sqli", "unionselect", "or1=1", "informationschema", "sleep("]):</code> |
| L0620 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "SQL注入"</code> |
| L0621 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if "sql娉" in t or "sql??" in t:</code> |
| L0622 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "SQL注入"</code> |
| L0623 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if "xss" in t or "&lt;script" in t:</code> |
| L0624 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "XSS"</code> |
| L0625 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if "ddos" in t:</code> |
| L0626 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "DDoS"</code> |
| L0627 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if "ssrf" in t:</code> |
| L0628 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "SSRF"</code> |
| L0629 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if "rce" in t or "remotecode" in t or "远程代码" in raw:</code> |
| L0630 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "RCE"</code> |
| L0631 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if any(x in raw for x in ["暴力破解", "爆破", "鏆村姏鐮磋В"]) or "bruteforce" in t:</code> |
| L0632 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "暴力破解"</code> |
| L0633 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if any(x in raw for x in ["端口扫描", "绔彛鎵弿"]) or "portscan" in t or "nmap" in t:</code> |
| L0634 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "端口扫描"</code> |
| L0635 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if any(x in raw for x in ["路径遍历", "璺緞閬嶅巻"]) or "traversal" in t:</code> |
| L0636 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "路径遍历"</code> |
| L0637 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if any(x in raw for x in ["危险文件上传", "危險文件上傳", "鍗遍櫓鏂囦欢涓婁紶"]) or "dangerousfileupload" in t:</code> |
| L0638 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "危险文件上传"</code> |
| L0639 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if any(x in raw for x in ["文件上传", "鏂囦欢涓婁紶"]) or "upload" in t:</code> |
| L0640 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "文件上传"</code> |
| L0641 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if any(x in raw for x in ["命令注入", "鍛戒护娉ㄥ叆"]) or "cmd" in t or "commandinject" in t:</code> |
| L0642 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "命令注入"</code> |
| L0643 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if "xxe" in t or "外部实体" in raw:</code> |
| L0644 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "XXE"</code> |
| L0645 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if "ssti" in t or "模板注入" in raw:</code> |
| L0646 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "SSTI"</code> |
| L0647 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if "fastjson" in t and ("反序列化" in raw or "autotype" in t or "deserial" in t):</code> |
| L0648 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "Fastjson反序列化探测"</code> |
| L0649 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if "反序列化" in raw or "deserialization" in t:</code> |
| L0650 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "反序列化"</code> |
| L0651 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if "graphql" in t:</code> |
| L0652 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "GraphQL探测"</code> |
| L0653 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>    return "可疑流量"</code> |
| L0654 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0655 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0656 | 定义标准化来源regionlabel函数 &#96;normalize_source_region_label&#96;，封装可复用业务逻辑。 | <code>def normalize_source_region_label(value: Any) -&gt; str:</code> |
| L0657 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 normalize_source_region_label。 | <code>    raw = str(value or "").strip()</code> |
| L0658 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_source_region_label。 | <code>    if not raw:</code> |
| L0659 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_source_region_label。 | <code>        return "未知"</code> |
| L0660 | 计算并保存 &#96;mapping&#96;（mapping），供后续逻辑使用，当前位于函数 normalize_source_region_label。 | <code>    mapping = {</code> |
| L0661 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_source_region_label。 | <code>        "鍖椾含": "北京",</code> |
| L0662 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_source_region_label。 | <code>        "涓婃捣": "上海",</code> |
| L0663 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_source_region_label。 | <code>        "骞夸笢": "广东",</code> |
| L0664 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_source_region_label。 | <code>        "娴欐睙": "浙江",</code> |
| L0665 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_source_region_label。 | <code>        "姹熻嫃": "江苏",</code> |
| L0666 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_source_region_label。 | <code>        "灞变笢": "山东",</code> |
| L0667 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_source_region_label。 | <code>        "娌冲崡": "河南",</code> |
| L0668 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_source_region_label。 | <code>        "鍥涘窛": "四川",</code> |
| L0669 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_source_region_label。 | <code>        "棣欐腐": "香港",</code> |
| L0670 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_source_region_label。 | <code>        "缇庡浗": "美国",</code> |
| L0671 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_source_region_label。 | <code>        "寰峰浗": "德国",</code> |
| L0672 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_source_region_label。 | <code>    }</code> |
| L0673 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_source_region_label。 | <code>    if raw in mapping:</code> |
| L0674 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_source_region_label。 | <code>        return mapping[raw]</code> |
| L0675 | 计算并保存 &#96;low&#96;（low），供后续逻辑使用，当前位于函数 normalize_source_region_label。 | <code>    low = raw.lower()</code> |
| L0676 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_source_region_label。 | <code>    if low in {"unknown", "n/a", "none", "null", "-", "--"} or "未知" in raw:</code> |
| L0677 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_source_region_label。 | <code>        return "未知"</code> |
| L0678 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_source_region_label。 | <code>    if "内网" in raw or any(x in low for x in ["private", "loopback", "localhost"]):</code> |
| L0679 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_source_region_label。 | <code>        return "内网"</code> |
| L0680 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_source_region_label。 | <code>    return raw</code> |
| L0681 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0682 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0683 | 计算并保存 &#96;CHINA_REGION_ALIASES&#96;（CHINAREGIONALIASES），供后续逻辑使用。 | <code>CHINA_REGION_ALIASES = {</code> |
| L0684 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "beijing",</code> |
| L0685 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "tianjin",</code> |
| L0686 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "shanghai",</code> |
| L0687 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "chongqing",</code> |
| L0688 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "hebei",</code> |
| L0689 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "shanxi",</code> |
| L0690 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "liaoning",</code> |
| L0691 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "jilin",</code> |
| L0692 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "heilongjiang",</code> |
| L0693 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "jiangsu",</code> |
| L0694 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "zhejiang",</code> |
| L0695 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "anhui",</code> |
| L0696 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "fujian",</code> |
| L0697 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "jiangxi",</code> |
| L0698 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "shandong",</code> |
| L0699 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "henan",</code> |
| L0700 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "hubei",</code> |
| L0701 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "hunan",</code> |
| L0702 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "guangdong",</code> |
| L0703 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "hainan",</code> |
| L0704 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "sichuan",</code> |
| L0705 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "guizhou",</code> |
| L0706 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "yunnan",</code> |
| L0707 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "shaanxi",</code> |
| L0708 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "gansu",</code> |
| L0709 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "qinghai",</code> |
| L0710 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "taiwan",</code> |
| L0711 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "inner mongolia",</code> |
| L0712 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "guangxi",</code> |
| L0713 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "tibet",</code> |
| L0714 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "ningxia",</code> |
| L0715 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "xinjiang",</code> |
| L0716 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "hong kong",</code> |
| L0717 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "macau",</code> |
| L0718 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>}</code> |
| L0719 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0720 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0721 | 定义simplify来源regionfordashboard函数 &#96;simplify_source_region_for_dashboard&#96;，封装可复用业务逻辑。 | <code>def simplify_source_region_for_dashboard(value: Any) -&gt; str:</code> |
| L0722 | 计算并保存 &#96;region&#96;（region），供后续逻辑使用，当前位于函数 simplify_source_region_for_dashboard。 | <code>    region = normalize_source_region_label(value)</code> |
| L0723 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 simplify_source_region_for_dashboard。 | <code>    if region in {"未知", "内网"}:</code> |
| L0724 | 结束当前函数并把结果返回给调用方，当前位于函数 simplify_source_region_for_dashboard。 | <code>        return region</code> |
| L0725 | 计算并保存 &#96;parts&#96;（parts），供后续逻辑使用，当前位于函数 simplify_source_region_for_dashboard。 | <code>    parts = [x.strip() for x in re.split(r"[/&#124;,，]+", region) if x.strip()]</code> |
| L0726 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 simplify_source_region_for_dashboard。 | <code>    if not parts:</code> |
| L0727 | 结束当前函数并把结果返回给调用方，当前位于函数 simplify_source_region_for_dashboard。 | <code>        return "未知"</code> |
| L0728 | 计算并保存 &#96;first&#96;（first），供后续逻辑使用，当前位于函数 simplify_source_region_for_dashboard。 | <code>    first = parts[0]</code> |
| L0729 | 计算并保存 &#96;first_low&#96;（firstlow），供后续逻辑使用，当前位于函数 simplify_source_region_for_dashboard。 | <code>    first_low = first.lower()</code> |
| L0730 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 simplify_source_region_for_dashboard。 | <code>    if first in {"中国", "中华人民共和国"} or first_low in {"china", "cn", "prc", "people's republic of china"}:</code> |
| L0731 | 结束当前函数并把结果返回给调用方，当前位于函数 simplify_source_region_for_dashboard。 | <code>        return normalize_source_region_label(parts[1]) if len(parts) &gt; 1 else "中国"</code> |
| L0732 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 simplify_source_region_for_dashboard。 | <code>    if (</code> |
| L0733 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 simplify_source_region_for_dashboard。 | <code>        first_low in CHINA_REGION_ALIASES</code> |
| L0734 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 simplify_source_region_for_dashboard。 | <code>        or first.endswith(("省", "市", "自治区", "特别行政区"))</code> |
| L0735 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 simplify_source_region_for_dashboard。 | <code>        or " province" in first_low</code> |
| L0736 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 simplify_source_region_for_dashboard。 | <code>        or " autonomous" in first_low</code> |
| L0737 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 simplify_source_region_for_dashboard。 | <code>    ):</code> |
| L0738 | 结束当前函数并把结果返回给调用方，当前位于函数 simplify_source_region_for_dashboard。 | <code>        return first.replace(" Province", "").replace(" province", "").strip()</code> |
| L0739 | 结束当前函数并把结果返回给调用方，当前位于函数 simplify_source_region_for_dashboard。 | <code>    return first</code> |
| L0740 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0741 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0742 | 定义来源cityfordashboard函数 &#96;source_city_for_dashboard&#96;，封装可复用业务逻辑。 | <code>def source_city_for_dashboard(value: Any) -&gt; str:</code> |
| L0743 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_city_for_dashboard。 | <code>    """Return the most specific available locality for the TOP10 source map."""</code> |
| L0744 | 计算并保存 &#96;region&#96;（region），供后续逻辑使用，当前位于函数 source_city_for_dashboard。 | <code>    region = normalize_source_region_label(value)</code> |
| L0745 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 source_city_for_dashboard。 | <code>    if region in {"未知", "内网"}:</code> |
| L0746 | 结束当前函数并把结果返回给调用方，当前位于函数 source_city_for_dashboard。 | <code>        return region</code> |
| L0747 | 计算并保存 &#96;parts&#96;（parts），供后续逻辑使用，当前位于函数 source_city_for_dashboard。 | <code>    parts = [normalize_source_region_label(x.strip()) for x in re.split(r"[/&#124;,，]+", region) if x.strip()]</code> |
| L0748 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 source_city_for_dashboard。 | <code>    if not parts:</code> |
| L0749 | 结束当前函数并把结果返回给调用方，当前位于函数 source_city_for_dashboard。 | <code>        return "未知"</code> |
| L0750 | 计算并保存 &#96;city&#96;（city），供后续逻辑使用，当前位于函数 source_city_for_dashboard。 | <code>    city = parts[-1]</code> |
| L0751 | 结束当前函数并把结果返回给调用方，当前位于函数 source_city_for_dashboard。 | <code>    return city.replace(" City", "").replace(" city", "").strip() or "未知"</code> |
| L0752 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0753 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0754 | 定义聚合countsbylabel函数 &#96;aggregate_counts_by_label&#96;，封装可复用业务逻辑。 | <code>def aggregate_counts_by_label(rows: List[Dict[str, Any]], label_key: str, total_key: str = "total") -&gt; List[Dict[str, Any]]:</code> |
| L0755 | 计算并保存 &#96;bucket&#96;（bucket），供后续逻辑使用，当前位于函数 aggregate_counts_by_label。 | <code>    bucket: Dict[str, int] = {}</code> |
| L0756 | 遍历集合中的数据项并逐项处理，当前位于函数 aggregate_counts_by_label。 | <code>    for row in rows:</code> |
| L0757 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 aggregate_counts_by_label。 | <code>        if label_key == "attack_type":</code> |
| L0758 | 计算并保存 &#96;label&#96;（label），供后续逻辑使用，当前位于函数 aggregate_counts_by_label。 | <code>            label = normalize_attack_type_label(row.get(label_key))</code> |
| L0759 | 处理前述条件均未命中的情况，当前位于函数 aggregate_counts_by_label。 | <code>        else:</code> |
| L0760 | 计算并保存 &#96;label&#96;（label），供后续逻辑使用，当前位于函数 aggregate_counts_by_label。 | <code>            label = normalize_source_region_label(row.get(label_key))</code> |
| L0761 | 计算并保存 &#96;count&#96;（count），供后续逻辑使用，当前位于函数 aggregate_counts_by_label。 | <code>        count = int(row.get(total_key) or 0)</code> |
| L0762 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_counts_by_label。 | <code>        bucket[label] = bucket.get(label, 0) + count</code> |
| L0763 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 aggregate_counts_by_label。 | <code>    items = [{label_key: k, total_key: v} for k, v in bucket.items()]</code> |
| L0764 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_counts_by_label。 | <code>    items.sort(key=lambda x: int(x.get(total_key) or 0), reverse=True)</code> |
| L0765 | 结束当前函数并把结果返回给调用方，当前位于函数 aggregate_counts_by_label。 | <code>    return items</code> |
| L0766 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0767 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0768 | 定义构建来源map数据项函数 &#96;build_source_map_items&#96;，封装可复用业务逻辑。 | <code>def build_source_map_items(conn: Any, rows: List[Dict[str, Any]]) -&gt; List[Dict[str, Any]]:</code> |
| L0769 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>    """Aggregate attack sources by city for the TOP10 source map."""</code> |
| L0770 | 计算并保存 &#96;city_bucket&#96;（citybucket），供后续逻辑使用，当前位于函数 build_source_map_items。 | <code>    city_bucket: Dict[str, Dict[str, Any]] = {}</code> |
| L0771 | 遍历集合中的数据项并逐项处理，当前位于函数 build_source_map_items。 | <code>    for row in rows:</code> |
| L0772 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 build_source_map_items。 | <code>        source_ip = normalize_ip_literal(str(row.get("source_ip") or ""))</code> |
| L0773 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_source_map_items。 | <code>        if not source_ip:</code> |
| L0774 | 控制当前循环或占位分支的执行流程，当前位于函数 build_source_map_items。 | <code>            continue</code> |
| L0775 | 计算并保存 &#96;total&#96;（total），供后续逻辑使用，当前位于函数 build_source_map_items。 | <code>        total = max(0, int(row.get("total") or 0))</code> |
| L0776 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_source_map_items。 | <code>        if not total:</code> |
| L0777 | 控制当前循环或占位分支的执行流程，当前位于函数 build_source_map_items。 | <code>            continue</code> |
| L0778 | 计算并保存 &#96;source_location&#96;（来源location），供后续逻辑使用，当前位于函数 build_source_map_items。 | <code>        source_location = resolve_region_for_event(</code> |
| L0779 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>            conn,</code> |
| L0780 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>            source_ip,</code> |
| L0781 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>            str(row.get("source_region") or ""),</code> |
| L0782 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_source_map_items。 | <code>        )</code> |
| L0783 | 计算并保存 &#96;source_location&#96;（来源location），供后续逻辑使用，当前位于函数 build_source_map_items。 | <code>        source_location = normalize_source_region_label(source_location)</code> |
| L0784 | 计算并保存 &#96;city&#96;（city），供后续逻辑使用，当前位于函数 build_source_map_items。 | <code>        city = source_city_for_dashboard(source_location)</code> |
| L0785 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_source_map_items。 | <code>        if city in {"未知", "内网"}:</code> |
| L0786 | 控制当前循环或占位分支的执行流程，当前位于函数 build_source_map_items。 | <code>            continue</code> |
| L0787 | 计算并保存 &#96;latest_at&#96;（latestat），供后续逻辑使用，当前位于函数 build_source_map_items。 | <code>        latest_at = row.get("latest_at")</code> |
| L0788 | 计算并保存 &#96;existing&#96;（existing），供后续逻辑使用，当前位于函数 build_source_map_items。 | <code>        existing = city_bucket.get(city.casefold())</code> |
| L0789 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_source_map_items。 | <code>        if not existing:</code> |
| L0790 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>            city_bucket[city.casefold()] = {</code> |
| L0791 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>                "source_region": city,</code> |
| L0792 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>                "source_city": city,</code> |
| L0793 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>                "source_location": source_location,</code> |
| L0794 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>                "source_ip_count": 1,</code> |
| L0795 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>                "_source_ips": {source_ip},</code> |
| L0796 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>                "total": total,</code> |
| L0797 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>                "latest_at": latest_at,</code> |
| L0798 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_source_map_items。 | <code>            }</code> |
| L0799 | 控制当前循环或占位分支的执行流程，当前位于函数 build_source_map_items。 | <code>            continue</code> |
| L0800 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>        existing["total"] = int(existing.get("total") or 0) + total</code> |
| L0801 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_source_map_items。 | <code>        existing["_source_ips"].add(source_ip)</code> |
| L0802 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>        existing["source_ip_count"] = len(existing["_source_ips"])</code> |
| L0803 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_source_map_items。 | <code>        if str(latest_at or "") &gt; str(existing.get("latest_at") or ""):</code> |
| L0804 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>            existing["latest_at"] = latest_at</code> |
| L0805 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>            existing["source_location"] = source_location</code> |
| L0806 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0807 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 build_source_map_items。 | <code>    items = list(city_bucket.values())</code> |
| L0808 | 遍历集合中的数据项并逐项处理，当前位于函数 build_source_map_items。 | <code>    for item in items:</code> |
| L0809 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>        item.pop("_source_ips", None)</code> |
| L0810 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>    items.sort(</code> |
| L0811 | 计算并保存 &#96;key&#96;（key），供后续逻辑使用，当前位于函数 build_source_map_items。 | <code>        key=lambda item: (</code> |
| L0812 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>            int(item.get("total") or 0),</code> |
| L0813 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>            str(item.get("latest_at") or ""),</code> |
| L0814 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_source_map_items。 | <code>            str(item.get("source_city") or ""),</code> |
| L0815 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_source_map_items。 | <code>        ),</code> |
| L0816 | 计算并保存 &#96;reverse&#96;（reverse），供后续逻辑使用，当前位于函数 build_source_map_items。 | <code>        reverse=True,</code> |
| L0817 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_source_map_items。 | <code>    )</code> |
| L0818 | 结束当前函数并把结果返回给调用方，当前位于函数 build_source_map_items。 | <code>    return items</code> |
| L0819 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0820 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0821 | 定义攻击typealiases函数 &#96;attack_type_aliases&#96;，封装可复用业务逻辑。 | <code>def attack_type_aliases(label: str) -&gt; List[str]:</code> |
| L0822 | 计算并保存 &#96;canonical&#96;（canonical），供后续逻辑使用，当前位于函数 attack_type_aliases。 | <code>    canonical = normalize_attack_type_label(label)</code> |
| L0823 | 计算并保存 &#96;aliases&#96;（aliases），供后续逻辑使用，当前位于函数 attack_type_aliases。 | <code>    aliases = {</code> |
| L0824 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 attack_type_aliases。 | <code>        "SQL注入": ["SQL注入", "SQL娉ㄥ叆", "SQL??", "sqli", "sql injection"],</code> |
| L0825 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 attack_type_aliases。 | <code>        "XSS": ["XSS", "xss"],</code> |
| L0826 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 attack_type_aliases。 | <code>        "暴力破解": ["暴力破解", "鏆村姏鐮磋В", "brute force", "bruteforce"],</code> |
| L0827 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 attack_type_aliases。 | <code>        "DDoS": ["DDoS", "ddos"],</code> |
| L0828 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 attack_type_aliases。 | <code>        "端口扫描": ["端口扫描", "绔彛鎵弿", "port scan", "nmap"],</code> |
| L0829 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 attack_type_aliases。 | <code>        "命令注入": ["命令注入", "鍛戒护娉ㄥ叆", "command injection"],</code> |
| L0830 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 attack_type_aliases。 | <code>        "路径遍历": ["路径遍历", "璺緞閬嶅巻", "path traversal"],</code> |
| L0831 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 attack_type_aliases。 | <code>        "文件上传": ["文件上传", "鏂囦欢涓婁紶", "file upload"],</code> |
| L0832 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 attack_type_aliases。 | <code>        "SSRF": ["SSRF", "ssrf"],</code> |
| L0833 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 attack_type_aliases。 | <code>        "RCE": ["RCE", "rce"],</code> |
| L0834 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 attack_type_aliases。 | <code>        "可疑流量": ["可疑流量", "鍙枒娴侀噺", "suspicious"],</code> |
| L0835 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 attack_type_aliases。 | <code>    }</code> |
| L0836 | 结束当前函数并把结果返回给调用方，当前位于函数 attack_type_aliases。 | <code>    return aliases.get(canonical, [canonical])</code> |
| L0837 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0838 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0839 | 定义visible攻击事件clause函数 &#96;visible_attack_event_clause&#96;，封装可复用业务逻辑。 | <code>def visible_attack_event_clause(alias: str = "") -&gt; str:</code> |
| L0840 | 计算并保存 &#96;prefix&#96;（prefix），供后续逻辑使用，当前位于函数 visible_attack_event_clause。 | <code>    prefix = f"{alias}." if alias else ""</code> |
| L0841 | 源码原注释：Older SSH monitor versions wrote one high-risk row per source IP. Keep those | <code>    # Older SSH monitor versions wrote one high-risk row per source IP. Keep those</code> |
| L0842 | 源码原注释：records in MySQL, but hide them from default dashboards so web attacks are | <code>    # records in MySQL, but hide them from default dashboards so web attacks are</code> |
| L0843 | 源码原注释：not drowned out. New SSH aggregate events use the SSHAGG prefix and remain visible. | <code>    # not drowned out. New SSH aggregate events use the SSHAGG prefix and remain visible.</code> |
| L0844 | 结束当前函数并把结果返回给调用方，当前位于函数 visible_attack_event_clause。 | <code>    return f"NOT ({prefix}event_id LIKE 'SSH%%' AND {prefix}event_id NOT LIKE 'SSHAGG%%')"</code> |
| L0845 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0846 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0847 | 定义ispublicip函数 &#96;is_public_ip&#96;，封装可复用业务逻辑。 | <code>def is_public_ip(ip_text: str) -&gt; bool:</code> |
| L0848 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 is_public_ip。 | <code>    try:</code> |
| L0849 | 计算并保存 &#96;ip_obj&#96;（ipobj），供后续逻辑使用，当前位于函数 is_public_ip。 | <code>        ip_obj = ipaddress.ip_address(str(ip_text))</code> |
| L0850 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 is_public_ip。 | <code>    except Exception:</code> |
| L0851 | 结束当前函数并把结果返回给调用方，当前位于函数 is_public_ip。 | <code>        return False</code> |
| L0852 | 结束当前函数并把结果返回给调用方，当前位于函数 is_public_ip。 | <code>    return bool(ip_obj.is_global)</code> |
| L0853 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0854 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0855 | 定义geohttp读取json函数 &#96;_geo_http_get_json&#96;，封装可复用业务逻辑。 | <code>def _geo_http_get_json(url: str, timeout_sec: float = 2.5) -&gt; Dict[str, Any]:</code> |
| L0856 | 计算并保存 &#96;req&#96;（req），供后续逻辑使用，当前位于函数 _geo_http_get_json。 | <code>    req = urllib.request.Request(url, headers={"User-Agent": "traffic-pipeline/1.0"})</code> |
| L0857 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 _geo_http_get_json。 | <code>    with urllib.request.urlopen(req, timeout=timeout_sec) as resp:</code> |
| L0858 | 计算并保存 &#96;charset&#96;（charset），供后续逻辑使用，当前位于函数 _geo_http_get_json。 | <code>        charset = "utf-8"</code> |
| L0859 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _geo_http_get_json。 | <code>        try:</code> |
| L0860 | 计算并保存 &#96;charset&#96;（charset），供后续逻辑使用，当前位于函数 _geo_http_get_json。 | <code>            charset = resp.headers.get_content_charset() or "utf-8"</code> |
| L0861 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _geo_http_get_json。 | <code>        except Exception:</code> |
| L0862 | 计算并保存 &#96;charset&#96;（charset），供后续逻辑使用，当前位于函数 _geo_http_get_json。 | <code>            charset = "utf-8"</code> |
| L0863 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 _geo_http_get_json。 | <code>        text = resp.read().decode(charset, errors="replace")</code> |
| L0864 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _geo_http_get_json。 | <code>    try:</code> |
| L0865 | 计算并保存 &#96;obj&#96;（obj），供后续逻辑使用，当前位于函数 _geo_http_get_json。 | <code>        obj = json.loads(text)</code> |
| L0866 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _geo_http_get_json。 | <code>    except Exception:</code> |
| L0867 | 结束当前函数并把结果返回给调用方，当前位于函数 _geo_http_get_json。 | <code>        return {}</code> |
| L0868 | 结束当前函数并把结果返回给调用方，当前位于函数 _geo_http_get_json。 | <code>    return obj if isinstance(obj, dict) else {}</code> |
| L0869 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0870 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0871 | 定义joinregion函数 &#96;_join_region&#96;，封装可复用业务逻辑。 | <code>def _join_region(country: str, region: str, city: str) -&gt; str:</code> |
| L0872 | 计算并保存 &#96;c&#96;（c），供后续逻辑使用，当前位于函数 _join_region。 | <code>    c = str(country or "").strip()</code> |
| L0873 | 计算并保存 &#96;r&#96;（r），供后续逻辑使用，当前位于函数 _join_region。 | <code>    r = str(region or "").strip()</code> |
| L0874 | 计算并保存 &#96;ct&#96;（ct），供后续逻辑使用，当前位于函数 _join_region。 | <code>    ct = str(city or "").strip()</code> |
| L0875 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _join_region。 | <code>    if not c and not r and not ct:</code> |
| L0876 | 结束当前函数并把结果返回给调用方，当前位于函数 _join_region。 | <code>        return "未知"</code> |
| L0877 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _join_region。 | <code>    if c.lower() in {"cn", "china"} or c == "中国":</code> |
| L0878 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _join_region。 | <code>        if r and ct:</code> |
| L0879 | 结束当前函数并把结果返回给调用方，当前位于函数 _join_region。 | <code>            return f"{r}/{ct}"</code> |
| L0880 | 结束当前函数并把结果返回给调用方，当前位于函数 _join_region。 | <code>        return r or ct or "中国"</code> |
| L0881 | 计算并保存 &#96;parts&#96;（parts），供后续逻辑使用，当前位于函数 _join_region。 | <code>    parts = [x for x in [c, r, ct] if x]</code> |
| L0882 | 结束当前函数并把结果返回给调用方，当前位于函数 _join_region。 | <code>    return "/".join(parts) if parts else "未知"</code> |
| L0883 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0884 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0885 | 定义获取regionremote函数 &#96;fetch_region_remote&#96;，封装可复用业务逻辑。 | <code>def fetch_region_remote(ip_text: str) -&gt; str:</code> |
| L0886 | 计算并保存 &#96;ip_norm&#96;（ipnorm），供后续逻辑使用，当前位于函数 fetch_region_remote。 | <code>    ip_norm = normalize_ip_literal(ip_text)</code> |
| L0887 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 fetch_region_remote。 | <code>    if not ip_norm:</code> |
| L0888 | 结束当前函数并把结果返回给调用方，当前位于函数 fetch_region_remote。 | <code>        return "未知"</code> |
| L0889 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 fetch_region_remote。 | <code>    if not is_public_ip(ip_norm):</code> |
| L0890 | 结束当前函数并把结果返回给调用方，当前位于函数 fetch_region_remote。 | <code>        return "内网"</code> |
| L0891 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0892 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 fetch_region_remote。 | <code>    try:</code> |
| L0893 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 fetch_region_remote。 | <code>        data = _geo_http_get_json(f"https://ipwho.is/{ip_norm}")</code> |
| L0894 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 fetch_region_remote。 | <code>        if data.get("success") is True:</code> |
| L0895 | 结束当前函数并把结果返回给调用方，当前位于函数 fetch_region_remote。 | <code>            return normalize_source_region_label(</code> |
| L0896 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fetch_region_remote。 | <code>                _join_region(data.get("country"), data.get("region"), data.get("city"))</code> |
| L0897 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fetch_region_remote。 | <code>            )</code> |
| L0898 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 fetch_region_remote。 | <code>    except Exception:</code> |
| L0899 | 控制当前循环或占位分支的执行流程，当前位于函数 fetch_region_remote。 | <code>        pass</code> |
| L0900 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0901 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 fetch_region_remote。 | <code>    try:</code> |
| L0902 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 fetch_region_remote。 | <code>        data = _geo_http_get_json(f"http://ip-api.com/json/{ip_norm}?lang=zh-CN")</code> |
| L0903 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 fetch_region_remote。 | <code>        if str(data.get("status", "")).lower() == "success":</code> |
| L0904 | 结束当前函数并把结果返回给调用方，当前位于函数 fetch_region_remote。 | <code>            return normalize_source_region_label(</code> |
| L0905 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fetch_region_remote。 | <code>                _join_region(data.get("country"), data.get("regionName"), data.get("city"))</code> |
| L0906 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fetch_region_remote。 | <code>            )</code> |
| L0907 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 fetch_region_remote。 | <code>    except Exception:</code> |
| L0908 | 控制当前循环或占位分支的执行流程，当前位于函数 fetch_region_remote。 | <code>        pass</code> |
| L0909 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0910 | 结束当前函数并把结果返回给调用方，当前位于函数 fetch_region_remote。 | <code>    return "未知"</code> |
| L0911 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0912 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0913 | 定义解析并确定regionfor事件函数 &#96;resolve_region_for_event&#96;，封装可复用业务逻辑。 | <code>def resolve_region_for_event(conn: Any, source_ip: str, source_region: str = "") -&gt; str:</code> |
| L0914 | 计算并保存 &#96;ip_norm&#96;（ipnorm），供后续逻辑使用，当前位于函数 resolve_region_for_event。 | <code>    ip_norm = normalize_ip_literal(source_ip)</code> |
| L0915 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 resolve_region_for_event。 | <code>    current = normalize_source_region_label(source_region)</code> |
| L0916 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_region_for_event。 | <code>    if current not in {"未知", "TEST"}:</code> |
| L0917 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_region_for_event。 | <code>        return current</code> |
| L0918 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_region_for_event。 | <code>    if not ip_norm:</code> |
| L0919 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_region_for_event。 | <code>        return "未知"</code> |
| L0920 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_region_for_event。 | <code>    if not is_public_ip(ip_norm):</code> |
| L0921 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_region_for_event。 | <code>        return "内网"</code> |
| L0922 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0923 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 resolve_region_for_event。 | <code>    with conn.cursor() as cur:</code> |
| L0924 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 resolve_region_for_event。 | <code>        cur.execute("SELECT region FROM ip_geo_cache WHERE ip=%s LIMIT 1", (ip_norm,))</code> |
| L0925 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 resolve_region_for_event。 | <code>        row = cur.fetchone() or {}</code> |
| L0926 | 计算并保存 &#96;cached&#96;（cached），供后续逻辑使用，当前位于函数 resolve_region_for_event。 | <code>    cached = normalize_source_region_label(row.get("region"))</code> |
| L0927 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_region_for_event。 | <code>    if cached != "未知":</code> |
| L0928 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_region_for_event。 | <code>        return cached</code> |
| L0929 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0930 | 计算并保存 &#96;region&#96;（region），供后续逻辑使用，当前位于函数 resolve_region_for_event。 | <code>    region = fetch_region_remote(ip_norm)</code> |
| L0931 | 计算并保存 &#96;source&#96;（来源），供后续逻辑使用，当前位于函数 resolve_region_for_event。 | <code>    source = "remote" if region not in {"未知", "内网"} else "fallback"</code> |
| L0932 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 resolve_region_for_event。 | <code>    with conn.cursor() as cur:</code> |
| L0933 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 resolve_region_for_event。 | <code>        cur.execute(</code> |
| L0934 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 resolve_region_for_event。 | <code>            """</code> |
| L0935 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 resolve_region_for_event。 | <code>            INSERT INTO ip_geo_cache(ip, region, source)</code> |
| L0936 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 resolve_region_for_event。 | <code>            VALUES (%s, %s, %s)</code> |
| L0937 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 resolve_region_for_event。 | <code>            ON DUPLICATE KEY UPDATE</code> |
| L0938 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 resolve_region_for_event。 | <code>              region=VALUES(region),</code> |
| L0939 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 resolve_region_for_event。 | <code>              source=VALUES(source),</code> |
| L0940 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 resolve_region_for_event。 | <code>              updated_at=CURRENT_TIMESTAMP</code> |
| L0941 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 resolve_region_for_event。 | <code>            """,</code> |
| L0942 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 resolve_region_for_event。 | <code>            (ip_norm, region, source),</code> |
| L0943 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 resolve_region_for_event。 | <code>        )</code> |
| L0944 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_region_for_event。 | <code>    return region</code> |
| L0945 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0946 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0947 | 定义读取windowscpupercent函数 &#96;_read_windows_cpu_percent&#96;，封装可复用业务逻辑。 | <code>def _read_windows_cpu_percent() -&gt; Optional[float]:</code> |
| L0948 | 计算并保存 &#96;candidates&#96;（candidates），供后续逻辑使用，当前位于函数 _read_windows_cpu_percent。 | <code>    candidates = [</code> |
| L0949 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _read_windows_cpu_percent。 | <code>        ["wmic", "cpu", "get", "loadpercentage", "/value"],</code> |
| L0950 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _read_windows_cpu_percent。 | <code>        ["powershell", "-NoProfile", "-Command", "(Get-Counter '\\Processor(_Total)\\% Processor Time').CounterSamples[0].CookedValue"],</code> |
| L0951 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _read_windows_cpu_percent。 | <code>    ]</code> |
| L0952 | 遍历集合中的数据项并逐项处理，当前位于函数 _read_windows_cpu_percent。 | <code>    for cmd in candidates:</code> |
| L0953 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _read_windows_cpu_percent。 | <code>        try:</code> |
| L0954 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 _read_windows_cpu_percent。 | <code>            result = subprocess.run(</code> |
| L0955 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _read_windows_cpu_percent。 | <code>                cmd,</code> |
| L0956 | 计算并保存 &#96;capture_output&#96;（captureoutput），供后续逻辑使用，当前位于函数 _read_windows_cpu_percent。 | <code>                capture_output=True,</code> |
| L0957 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 _read_windows_cpu_percent。 | <code>                text=True,</code> |
| L0958 | 计算并保存 &#96;encoding&#96;（encoding），供后续逻辑使用，当前位于函数 _read_windows_cpu_percent。 | <code>                encoding="utf-8",</code> |
| L0959 | 计算并保存 &#96;errors&#96;（errors），供后续逻辑使用，当前位于函数 _read_windows_cpu_percent。 | <code>                errors="replace",</code> |
| L0960 | 计算并保存 &#96;timeout&#96;（timeout），供后续逻辑使用，当前位于函数 _read_windows_cpu_percent。 | <code>                timeout=4,</code> |
| L0961 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _read_windows_cpu_percent。 | <code>            )</code> |
| L0962 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _read_windows_cpu_percent。 | <code>        except Exception:</code> |
| L0963 | 控制当前循环或占位分支的执行流程，当前位于函数 _read_windows_cpu_percent。 | <code>            continue</code> |
| L0964 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 _read_windows_cpu_percent。 | <code>        text = f"{result.stdout or ''}\n{result.stderr or ''}".strip()</code> |
| L0965 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _read_windows_cpu_percent。 | <code>        if not text:</code> |
| L0966 | 控制当前循环或占位分支的执行流程，当前位于函数 _read_windows_cpu_percent。 | <code>            continue</code> |
| L0967 | 计算并保存 &#96;m&#96;（m），供后续逻辑使用，当前位于函数 _read_windows_cpu_percent。 | <code>        m = re.search(r"([0-9]+(?:\.[0-9]+)?)", text)</code> |
| L0968 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _read_windows_cpu_percent。 | <code>        if m:</code> |
| L0969 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _read_windows_cpu_percent。 | <code>            try:</code> |
| L0970 | 结束当前函数并把结果返回给调用方，当前位于函数 _read_windows_cpu_percent。 | <code>                return round(float(m.group(1)), 2)</code> |
| L0971 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _read_windows_cpu_percent。 | <code>            except Exception:</code> |
| L0972 | 控制当前循环或占位分支的执行流程，当前位于函数 _read_windows_cpu_percent。 | <code>                continue</code> |
| L0973 | 结束当前函数并把结果返回给调用方，当前位于函数 _read_windows_cpu_percent。 | <code>    return None</code> |
| L0974 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0975 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0976 | 定义读取cpupercentcached函数 &#96;_read_cpu_percent_cached&#96;，封装可复用业务逻辑。 | <code>def _read_cpu_percent_cached(max_age_seconds: float = 1.0) -&gt; Optional[float]:</code> |
| L0977 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _read_cpu_percent_cached。 | <code>    """Return a real short-window CPU sample without slowing every API call."""</code> |
| L0978 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _read_cpu_percent_cached。 | <code>    if psutil is None:</code> |
| L0979 | 结束当前函数并把结果返回给调用方，当前位于函数 _read_cpu_percent_cached。 | <code>        return _read_windows_cpu_percent() if os.name == "nt" else None</code> |
| L0980 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0981 | 计算并保存 &#96;now_mono&#96;（nowmono），供后续逻辑使用，当前位于函数 _read_cpu_percent_cached。 | <code>    now_mono = time.monotonic()</code> |
| L0982 | 计算并保存 &#96;cached&#96;（cached），供后续逻辑使用，当前位于函数 _read_cpu_percent_cached。 | <code>    cached = _CPU_SAMPLE_CACHE.get("value")</code> |
| L0983 | 计算并保存 &#96;sampled_at&#96;（sampledat），供后续逻辑使用，当前位于函数 _read_cpu_percent_cached。 | <code>    sampled_at = float(_CPU_SAMPLE_CACHE.get("sampled_at") or 0.0)</code> |
| L0984 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _read_cpu_percent_cached。 | <code>    if cached is not None and now_mono - sampled_at &lt;= max_age_seconds:</code> |
| L0985 | 结束当前函数并把结果返回给调用方，当前位于函数 _read_cpu_percent_cached。 | <code>        return float(cached)</code> |
| L0986 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0987 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 _read_cpu_percent_cached。 | <code>    with _CPU_SAMPLE_LOCK:</code> |
| L0988 | 计算并保存 &#96;now_mono&#96;（nowmono），供后续逻辑使用，当前位于函数 _read_cpu_percent_cached。 | <code>        now_mono = time.monotonic()</code> |
| L0989 | 计算并保存 &#96;cached&#96;（cached），供后续逻辑使用，当前位于函数 _read_cpu_percent_cached。 | <code>        cached = _CPU_SAMPLE_CACHE.get("value")</code> |
| L0990 | 计算并保存 &#96;sampled_at&#96;（sampledat），供后续逻辑使用，当前位于函数 _read_cpu_percent_cached。 | <code>        sampled_at = float(_CPU_SAMPLE_CACHE.get("sampled_at") or 0.0)</code> |
| L0991 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _read_cpu_percent_cached。 | <code>        if cached is not None and now_mono - sampled_at &lt;= max_age_seconds:</code> |
| L0992 | 结束当前函数并把结果返回给调用方，当前位于函数 _read_cpu_percent_cached。 | <code>            return float(cached)</code> |
| L0993 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _read_cpu_percent_cached。 | <code>        try:</code> |
| L0994 | 源码原注释：interval=None can return a meaningless 0.0 on the first call. | <code>            # interval=None can return a meaningless 0.0 on the first call.</code> |
| L0995 | 计算并保存 &#96;value&#96;（value），供后续逻辑使用，当前位于函数 _read_cpu_percent_cached。 | <code>            value = round(float(psutil.cpu_percent(interval=0.15)), 2)</code> |
| L0996 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _read_cpu_percent_cached。 | <code>        except Exception:</code> |
| L0997 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _read_cpu_percent_cached。 | <code>            value = _read_windows_cpu_percent() if os.name == "nt" else None</code> |
| L0998 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _read_cpu_percent_cached。 | <code>        if value is not None:</code> |
| L0999 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _read_cpu_percent_cached。 | <code>            _CPU_SAMPLE_CACHE["value"] = value</code> |
| L1000 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _read_cpu_percent_cached。 | <code>            _CPU_SAMPLE_CACHE["sampled_at"] = time.monotonic()</code> |
| L1001 | 结束当前函数并把结果返回给调用方，当前位于函数 _read_cpu_percent_cached。 | <code>        return value</code> |
| L1002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1003 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1004 | 定义读取windowsmemory状态函数 &#96;_read_windows_memory_status&#96;，封装可复用业务逻辑。 | <code>def _read_windows_memory_status() -&gt; Tuple[int, int]:</code> |
| L1005 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _read_windows_memory_status。 | <code>    try:</code> |
| L1006 | 导入后续逻辑所需的模块、类或函数：&#96;import ctypes&#96;。 | <code>        import ctypes</code> |
| L1007 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1008 | 定义类 &#96;MEMORYSTATUSEX&#96;，集中保存相关状态与操作。 | <code>        class MEMORYSTATUSEX(ctypes.Structure):</code> |
| L1009 | 计算并保存 &#96;_fields_&#96;（fields），供后续逻辑使用，当前位于类 MEMORYSTATUSEX。 | <code>            _fields_ = [</code> |
| L1010 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 MEMORYSTATUSEX。 | <code>                ("dwLength", ctypes.c_ulong),</code> |
| L1011 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 MEMORYSTATUSEX。 | <code>                ("dwMemoryLoad", ctypes.c_ulong),</code> |
| L1012 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 MEMORYSTATUSEX。 | <code>                ("ullTotalPhys", ctypes.c_ulonglong),</code> |
| L1013 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 MEMORYSTATUSEX。 | <code>                ("ullAvailPhys", ctypes.c_ulonglong),</code> |
| L1014 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 MEMORYSTATUSEX。 | <code>                ("ullTotalPageFile", ctypes.c_ulonglong),</code> |
| L1015 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 MEMORYSTATUSEX。 | <code>                ("ullAvailPageFile", ctypes.c_ulonglong),</code> |
| L1016 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 MEMORYSTATUSEX。 | <code>                ("ullTotalVirtual", ctypes.c_ulonglong),</code> |
| L1017 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 MEMORYSTATUSEX。 | <code>                ("ullAvailVirtual", ctypes.c_ulonglong),</code> |
| L1018 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 MEMORYSTATUSEX。 | <code>                ("sullAvailExtendedVirtual", ctypes.c_ulonglong),</code> |
| L1019 | 结束前面开始的字典、列表、参数或表达式结构，当前位于类 MEMORYSTATUSEX。 | <code>            ]</code> |
| L1020 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1021 | 计算并保存 &#96;statex&#96;（statex），供后续逻辑使用，当前位于函数 _read_windows_memory_status。 | <code>        statex = MEMORYSTATUSEX()</code> |
| L1022 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _read_windows_memory_status。 | <code>        statex.dwLength = ctypes.sizeof(MEMORYSTATUSEX)</code> |
| L1023 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _read_windows_memory_status。 | <code>        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(statex)):  # type: ignore[attr-defined]</code> |
| L1024 | 结束当前函数并把结果返回给调用方，当前位于函数 _read_windows_memory_status。 | <code>            return int(statex.ullTotalPhys), int(statex.ullAvailPhys)</code> |
| L1025 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _read_windows_memory_status。 | <code>    except Exception:</code> |
| L1026 | 控制当前循环或占位分支的执行流程，当前位于函数 _read_windows_memory_status。 | <code>        pass</code> |
| L1027 | 结束当前函数并把结果返回给调用方，当前位于函数 _read_windows_memory_status。 | <code>    return 0, 0</code> |
| L1028 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1029 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1030 | 定义读取uptimesecondsfallback函数 &#96;_read_uptime_seconds_fallback&#96;，封装可复用业务逻辑。 | <code>def _read_uptime_seconds_fallback() -&gt; Optional[int]:</code> |
| L1031 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _read_uptime_seconds_fallback。 | <code>    if os.name == "nt":</code> |
| L1032 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _read_uptime_seconds_fallback。 | <code>        try:</code> |
| L1033 | 导入后续逻辑所需的模块、类或函数：&#96;import ctypes&#96;。 | <code>            import ctypes</code> |
| L1034 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1035 | 计算并保存 &#96;ms&#96;（ms），供后续逻辑使用，当前位于函数 _read_uptime_seconds_fallback。 | <code>            ms = int(ctypes.windll.kernel32.GetTickCount64())  # type: ignore[attr-defined]</code> |
| L1036 | 结束当前函数并把结果返回给调用方，当前位于函数 _read_uptime_seconds_fallback。 | <code>            return int(ms / 1000)</code> |
| L1037 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _read_uptime_seconds_fallback。 | <code>        except Exception:</code> |
| L1038 | 结束当前函数并把结果返回给调用方，当前位于函数 _read_uptime_seconds_fallback。 | <code>            return None</code> |
| L1039 | 结束当前函数并把结果返回给调用方，当前位于函数 _read_uptime_seconds_fallback。 | <code>    return None</code> |
| L1040 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1041 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1042 | 定义collectlocalsystem状态函数 &#96;collect_local_system_status&#96;，封装可复用业务逻辑。 | <code>def collect_local_system_status() -&gt; Dict[str, Any]:</code> |
| L1043 | 计算并保存 &#96;now&#96;（now），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>    now = now_dt()</code> |
| L1044 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>    host = socket.gethostname()</code> |
| L1045 | 计算并保存 &#96;os_name&#96;（osname），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>    os_name = f"{platform.system()} {platform.release()}".strip()</code> |
| L1046 | 计算并保存 &#96;local_ip&#96;（localip），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>    local_ip = ""</code> |
| L1047 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 collect_local_system_status。 | <code>    try:</code> |
| L1048 | 源码原注释：The address selected by the default route represents the NIC that | <code>        # The address selected by the default route represents the NIC that</code> |
| L1049 | 源码原注释：actually carries protected traffic; hostname lookup often returns a | <code>        # actually carries protected traffic; hostname lookup often returns a</code> |
| L1050 | 源码原注释：VirtualBox/Hyper-V host-only adapter on Windows servers. | <code>        # VirtualBox/Hyper-V host-only adapter on Windows servers.</code> |
| L1051 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 collect_local_system_status。 | <code>        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route_probe:</code> |
| L1052 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>            route_probe.connect(("1.1.1.1", 80))</code> |
| L1053 | 计算并保存 &#96;local_ip&#96;（localip），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>            local_ip = str(route_probe.getsockname()[0])</code> |
| L1054 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 collect_local_system_status。 | <code>    except Exception:</code> |
| L1055 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 collect_local_system_status。 | <code>        try:</code> |
| L1056 | 计算并保存 &#96;local_ip&#96;（localip），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>            local_ip = socket.gethostbyname(host)</code> |
| L1057 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 collect_local_system_status。 | <code>        except Exception:</code> |
| L1058 | 计算并保存 &#96;local_ip&#96;（localip），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>            local_ip = ""</code> |
| L1059 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1060 | 计算并保存 &#96;cpu_percent&#96;（cpupercent），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>    cpu_percent: Optional[float] = None</code> |
| L1061 | 计算并保存 &#96;mem_total&#96;（memtotal），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>    mem_total = mem_used = mem_free = 0</code> |
| L1062 | 计算并保存 &#96;uptime_seconds&#96;（uptimeseconds），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>    uptime_seconds: Optional[int] = None</code> |
| L1063 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1064 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 collect_local_system_status。 | <code>    if psutil is not None:</code> |
| L1065 | 计算并保存 &#96;cpu_percent&#96;（cpupercent），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>        cpu_percent = _read_cpu_percent_cached()</code> |
| L1066 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 collect_local_system_status。 | <code>        try:</code> |
| L1067 | 计算并保存 &#96;vm&#96;（vm），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>            vm = psutil.virtual_memory()</code> |
| L1068 | 计算并保存 &#96;mem_total&#96;（memtotal），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>            mem_total = int(vm.total)</code> |
| L1069 | 计算并保存 &#96;mem_free&#96;（memfree），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>            mem_free = int(vm.available)</code> |
| L1070 | 计算并保存 &#96;mem_used&#96;（memused），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>            mem_used = int(vm.total - vm.available)</code> |
| L1071 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 collect_local_system_status。 | <code>        except Exception:</code> |
| L1072 | 控制当前循环或占位分支的执行流程，当前位于函数 collect_local_system_status。 | <code>            pass</code> |
| L1073 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 collect_local_system_status。 | <code>        try:</code> |
| L1074 | 计算并保存 &#96;uptime_seconds&#96;（uptimeseconds），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>            uptime_seconds = int(max(0, now.timestamp() - float(psutil.boot_time())))</code> |
| L1075 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 collect_local_system_status。 | <code>        except Exception:</code> |
| L1076 | 计算并保存 &#96;uptime_seconds&#96;（uptimeseconds），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>            uptime_seconds = None</code> |
| L1077 | 处理前述条件均未命中的情况，当前位于函数 collect_local_system_status。 | <code>    else:</code> |
| L1078 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 collect_local_system_status。 | <code>        if os.name == "nt":</code> |
| L1079 | 计算并保存 &#96;cpu_percent&#96;（cpupercent），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>            cpu_percent = _read_windows_cpu_percent()</code> |
| L1080 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>            total, free = _read_windows_memory_status()</code> |
| L1081 | 计算并保存 &#96;mem_total&#96;（memtotal），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>            mem_total = int(total)</code> |
| L1082 | 计算并保存 &#96;mem_free&#96;（memfree），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>            mem_free = int(free)</code> |
| L1083 | 计算并保存 &#96;mem_used&#96;（memused），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>            mem_used = max(0, mem_total - mem_free)</code> |
| L1084 | 计算并保存 &#96;uptime_seconds&#96;（uptimeseconds），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>            uptime_seconds = _read_uptime_seconds_fallback()</code> |
| L1085 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1086 | 计算并保存 &#96;disk_anchor&#96;（diskanchor），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>    disk_anchor = str(Path.cwd().anchor or "/")</code> |
| L1087 | 计算并保存 &#96;disk_total&#96;（disktotal），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>    disk_total = disk_used = disk_free = 0</code> |
| L1088 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 collect_local_system_status。 | <code>    try:</code> |
| L1089 | 计算并保存 &#96;usage&#96;（usage），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>        usage = shutil.disk_usage(disk_anchor)</code> |
| L1090 | 计算并保存 &#96;disk_total&#96;（disktotal），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>        disk_total = int(usage.total)</code> |
| L1091 | 计算并保存 &#96;disk_used&#96;（diskused），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>        disk_used = int(usage.used)</code> |
| L1092 | 计算并保存 &#96;disk_free&#96;（diskfree），供后续逻辑使用，当前位于函数 collect_local_system_status。 | <code>        disk_free = int(usage.free)</code> |
| L1093 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 collect_local_system_status。 | <code>    except Exception:</code> |
| L1094 | 控制当前循环或占位分支的执行流程，当前位于函数 collect_local_system_status。 | <code>        pass</code> |
| L1095 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1096 | 定义pct函数 &#96;_pct&#96;，封装可复用业务逻辑。 | <code>    def _pct(used: int, total: int) -&gt; float:</code> |
| L1097 | 结束当前函数并把结果返回给调用方，当前位于函数 _pct。 | <code>        return 0.0 if total &lt;= 0 else round((used / total) * 100.0, 2)</code> |
| L1098 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1099 | 结束当前函数并把结果返回给调用方，当前位于函数 collect_local_system_status。 | <code>    return {</code> |
| L1100 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>        "hostname": host,</code> |
| L1101 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>        "local_ip": local_ip,</code> |
| L1102 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>        "os": os_name,</code> |
| L1103 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>        "collected_at": dt_to_str(now, ms=True),</code> |
| L1104 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>        "uptime_seconds": uptime_seconds,</code> |
| L1105 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>        "uptime_hours": None if uptime_seconds is None else round(uptime_seconds / 3600.0, 2),</code> |
| L1106 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>        "cpu_percent": cpu_percent,</code> |
| L1107 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>        "memory": {</code> |
| L1108 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>            "total_bytes": mem_total,</code> |
| L1109 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>            "used_bytes": mem_used,</code> |
| L1110 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>            "free_bytes": mem_free,</code> |
| L1111 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>            "used_percent": _pct(mem_used, mem_total),</code> |
| L1112 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 collect_local_system_status。 | <code>        },</code> |
| L1113 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>        "disk": {</code> |
| L1114 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>            "path": disk_anchor,</code> |
| L1115 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>            "total_bytes": disk_total,</code> |
| L1116 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>            "used_bytes": disk_used,</code> |
| L1117 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>            "free_bytes": disk_free,</code> |
| L1118 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_local_system_status。 | <code>            "used_percent": _pct(disk_used, disk_total),</code> |
| L1119 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 collect_local_system_status。 | <code>        },</code> |
| L1120 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 collect_local_system_status。 | <code>    }</code> |
| L1121 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1122 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1123 | 定义标准化ipforrule函数 &#96;normalize_ip_for_rule&#96;，封装可复用业务逻辑。 | <code>def normalize_ip_for_rule(ip_text: str) -&gt; str:</code> |
| L1124 | 计算并保存 &#96;value&#96;（value），供后续逻辑使用，当前位于函数 normalize_ip_for_rule。 | <code>    value = str(ip_text or "").strip()</code> |
| L1125 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_ip_for_rule。 | <code>    return re.sub(r"[^A-Za-z0-9_.:-]", "_", value)</code> |
| L1126 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1127 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1128 | 定义firewallrulenames函数 &#96;firewall_rule_names&#96;，封装可复用业务逻辑。 | <code>def firewall_rule_names(ip_text: str) -&gt; Tuple[str, str]:</code> |
| L1129 | 计算并保存 &#96;suffix&#96;（suffix），供后续逻辑使用，当前位于函数 firewall_rule_names。 | <code>    suffix = normalize_ip_for_rule(ip_text)</code> |
| L1130 | 结束当前函数并把结果返回给调用方，当前位于函数 firewall_rule_names。 | <code>    return (f"TP_BLOCK_IP_IN_{suffix}", f"TP_BLOCK_IP_OUT_{suffix}")</code> |
| L1131 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1132 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1133 | 定义运行netsh函数 &#96;run_netsh&#96;，封装可复用业务逻辑。 | <code>def run_netsh(args: List[str]) -&gt; Tuple[bool, str, str]:</code> |
| L1134 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 run_netsh。 | <code>    try:</code> |
| L1135 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 run_netsh。 | <code>        result = subprocess.run(</code> |
| L1136 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_netsh。 | <code>            args,</code> |
| L1137 | 计算并保存 &#96;capture_output&#96;（captureoutput），供后续逻辑使用，当前位于函数 run_netsh。 | <code>            capture_output=True,</code> |
| L1138 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 run_netsh。 | <code>            text=True,</code> |
| L1139 | 计算并保存 &#96;encoding&#96;（encoding），供后续逻辑使用，当前位于函数 run_netsh。 | <code>            encoding="utf-8",</code> |
| L1140 | 计算并保存 &#96;errors&#96;（errors），供后续逻辑使用，当前位于函数 run_netsh。 | <code>            errors="replace",</code> |
| L1141 | 计算并保存 &#96;timeout&#96;（timeout），供后续逻辑使用，当前位于函数 run_netsh。 | <code>            timeout=12,</code> |
| L1142 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_netsh。 | <code>        )</code> |
| L1143 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 run_netsh。 | <code>    except Exception as exc:</code> |
| L1144 | 结束当前函数并把结果返回给调用方，当前位于函数 run_netsh。 | <code>        return False, "", str(exc)</code> |
| L1145 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_netsh。 | <code>    ok = result.returncode == 0</code> |
| L1146 | 结束当前函数并把结果返回给调用方，当前位于函数 run_netsh。 | <code>    return ok, result.stdout or "", result.stderr or ""</code> |
| L1147 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1148 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1149 | 定义psquote函数 &#96;ps_quote&#96;，封装可复用业务逻辑。 | <code>def ps_quote(value: str) -&gt; str:</code> |
| L1150 | 结束当前函数并把结果返回给调用方，当前位于函数 ps_quote。 | <code>    return "'" + str(value).replace("'", "''") + "'"</code> |
| L1151 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1152 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1153 | 定义运行powershell函数 &#96;run_powershell&#96;，封装可复用业务逻辑。 | <code>def run_powershell(command: str) -&gt; Tuple[bool, str, str]:</code> |
| L1154 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 run_powershell。 | <code>    try:</code> |
| L1155 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 run_powershell。 | <code>        result = subprocess.run(</code> |
| L1156 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_powershell。 | <code>            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],</code> |
| L1157 | 计算并保存 &#96;capture_output&#96;（captureoutput），供后续逻辑使用，当前位于函数 run_powershell。 | <code>            capture_output=True,</code> |
| L1158 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 run_powershell。 | <code>            text=True,</code> |
| L1159 | 计算并保存 &#96;encoding&#96;（encoding），供后续逻辑使用，当前位于函数 run_powershell。 | <code>            encoding="utf-8",</code> |
| L1160 | 计算并保存 &#96;errors&#96;（errors），供后续逻辑使用，当前位于函数 run_powershell。 | <code>            errors="replace",</code> |
| L1161 | 计算并保存 &#96;timeout&#96;（timeout），供后续逻辑使用，当前位于函数 run_powershell。 | <code>            timeout=15,</code> |
| L1162 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_powershell。 | <code>        )</code> |
| L1163 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 run_powershell。 | <code>    except Exception as exc:</code> |
| L1164 | 结束当前函数并把结果返回给调用方，当前位于函数 run_powershell。 | <code>        return False, "", str(exc)</code> |
| L1165 | 结束当前函数并把结果返回给调用方，当前位于函数 run_powershell。 | <code>    return result.returncode == 0, result.stdout or "", result.stderr or ""</code> |
| L1166 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1167 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1168 | 定义firewall删除rule函数 &#96;firewall_delete_rule&#96;，封装可复用业务逻辑。 | <code>def firewall_delete_rule(rule_name: str) -&gt; Tuple[bool, str]:</code> |
| L1169 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_delete_rule。 | <code>    ok1, out1, err1 = run_netsh(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])</code> |
| L1170 | 计算并保存 &#96;ps_cmd&#96;（pscmd），供后续逻辑使用，当前位于函数 firewall_delete_rule。 | <code>    ps_cmd = (</code> |
| L1171 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_delete_rule。 | <code>        f"$r = Get-NetFirewallRule -Name {ps_quote(rule_name)} -ErrorAction SilentlyContinue; "</code> |
| L1172 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_delete_rule。 | <code>        "if ($r) { $r &#124; Remove-NetFirewallRule -ErrorAction Stop }; "</code> |
| L1173 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_delete_rule。 | <code>        "Write-Output 'deleted_or_missing'"</code> |
| L1174 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 firewall_delete_rule。 | <code>    )</code> |
| L1175 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_delete_rule。 | <code>    ok2, out2, err2 = run_powershell(ps_cmd)</code> |
| L1176 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 firewall_delete_rule。 | <code>    text = f"{out1}\n{err1}\n{out2}\n{err2}"</code> |
| L1177 | 结束当前函数并把结果返回给调用方，当前位于函数 firewall_delete_rule。 | <code>    return ok1 or ok2 or "no rules match" in text.lower() or "deleted_or_missing" in text, text.strip()</code> |
| L1178 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1179 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1180 | 定义firewall创建rule函数 &#96;firewall_create_rule&#96;，封装可复用业务逻辑。 | <code>def firewall_create_rule(rule_name: str, direction: str, ip_val: str) -&gt; Tuple[bool, str]:</code> |
| L1181 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>    dir_arg = "in" if direction == "in" else "out"</code> |
| L1182 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>    ps_direction = "Inbound" if direction == "in" else "Outbound"</code> |
| L1183 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>    ok1, out1, err1 = run_netsh(</code> |
| L1184 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>        [</code> |
| L1185 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>            "netsh",</code> |
| L1186 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>            "advfirewall",</code> |
| L1187 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>            "firewall",</code> |
| L1188 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>            "add",</code> |
| L1189 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>            "rule",</code> |
| L1190 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>            f"name={rule_name}",</code> |
| L1191 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>            f"dir={dir_arg}",</code> |
| L1192 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>            "action=block",</code> |
| L1193 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>            f"remoteip={ip_val}",</code> |
| L1194 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>            "enable=yes",</code> |
| L1195 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>            "profile=any",</code> |
| L1196 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 firewall_create_rule。 | <code>        ]</code> |
| L1197 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 firewall_create_rule。 | <code>    )</code> |
| L1198 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 firewall_create_rule。 | <code>    if ok1:</code> |
| L1199 | 结束当前函数并把结果返回给调用方，当前位于函数 firewall_create_rule。 | <code>        return True, out1 or err1</code> |
| L1200 | 计算并保存 &#96;ps_cmd&#96;（pscmd），供后续逻辑使用，当前位于函数 firewall_create_rule。 | <code>    ps_cmd = (</code> |
| L1201 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>        f"New-NetFirewallRule -Name {ps_quote(rule_name)} "</code> |
| L1202 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>        f"-DisplayName {ps_quote(rule_name)} "</code> |
| L1203 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>        f"-Direction {ps_direction} -Action Block "</code> |
| L1204 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>        f"-RemoteAddress {ps_quote(ip_val)} -Profile Any -Enabled True "</code> |
| L1205 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>        "-ErrorAction Stop &#124; Out-Null; Write-Output 'created'"</code> |
| L1206 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 firewall_create_rule。 | <code>    )</code> |
| L1207 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_create_rule。 | <code>    ok2, out2, err2 = run_powershell(ps_cmd)</code> |
| L1208 | 结束当前函数并把结果返回给调用方，当前位于函数 firewall_create_rule。 | <code>    return ok2, f"netsh: {out1 or err1}; powershell: {out2 or err2}".strip()</code> |
| L1209 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1210 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1211 | 定义firewall封禁ip函数 &#96;firewall_block_ip&#96;，封装可复用业务逻辑。 | <code>def firewall_block_ip(ip_text: str) -&gt; Tuple[bool, str]:</code> |
| L1212 | 结束当前函数并把结果返回给调用方，当前位于函数 firewall_block_ip。 | <code>    return verified_firewall_block_ip(ip_text)</code> |
| L1213 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1214 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1215 | 定义firewall解封ip函数 &#96;firewall_unblock_ip&#96;，封装可复用业务逻辑。 | <code>def firewall_unblock_ip(ip_text: str) -&gt; Tuple[bool, str]:</code> |
| L1216 | 结束当前函数并把结果返回给调用方，当前位于函数 firewall_unblock_ip。 | <code>    return verified_firewall_unblock_ip(ip_text)</code> |
| L1217 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1218 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1219 | 定义标准化ipliteral函数 &#96;normalize_ip_literal&#96;，封装可复用业务逻辑。 | <code>def normalize_ip_literal(value: Any) -&gt; str:</code> |
| L1220 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 normalize_ip_literal。 | <code>    text = str(value or "").strip()</code> |
| L1221 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_ip_literal。 | <code>    if not text:</code> |
| L1222 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_ip_literal。 | <code>        return ""</code> |
| L1223 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 normalize_ip_literal。 | <code>    try:</code> |
| L1224 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_ip_literal。 | <code>        return str(ipaddress.ip_address(text))</code> |
| L1225 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 normalize_ip_literal。 | <code>    except Exception:</code> |
| L1226 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_ip_literal。 | <code>        return ""</code> |
| L1227 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1228 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1229 | 定义标准化hosttext函数 &#96;normalize_host_text&#96;，封装可复用业务逻辑。 | <code>def normalize_host_text(text: str) -&gt; str:</code> |
| L1230 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 normalize_host_text。 | <code>    raw = str(text or "").strip()</code> |
| L1231 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_host_text。 | <code>    if not raw:</code> |
| L1232 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_host_text。 | <code>        return ""</code> |
| L1233 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 normalize_host_text。 | <code>    host = raw</code> |
| L1234 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_host_text。 | <code>    if "://" in host:</code> |
| L1235 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 normalize_host_text。 | <code>        host = urllib.parse.urlsplit(host).hostname or host</code> |
| L1236 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_host_text。 | <code>    if host.startswith("[") and host.endswith("]"):</code> |
| L1237 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 normalize_host_text。 | <code>        host = host[1:-1]</code> |
| L1238 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_host_text。 | <code>    if ":" in host and host.count(":") == 1:</code> |
| L1239 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_host_text。 | <code>        left, right = host.rsplit(":", 1)</code> |
| L1240 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_host_text。 | <code>        if right.isdigit():</code> |
| L1241 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 normalize_host_text。 | <code>            host = left</code> |
| L1242 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_host_text。 | <code>    return host.strip().lower()</code> |
| L1243 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1244 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1245 | 定义extracthostcandidates函数 &#96;extract_host_candidates&#96;，封装可复用业务逻辑。 | <code>def extract_host_candidates(request_log: str) -&gt; List[str]:</code> |
| L1246 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 extract_host_candidates。 | <code>    text = str(request_log or "")</code> |
| L1247 | 计算并保存 &#96;hosts&#96;（hosts），供后续逻辑使用，当前位于函数 extract_host_candidates。 | <code>    hosts: List[str] = []</code> |
| L1248 | 遍历集合中的数据项并逐项处理，当前位于函数 extract_host_candidates。 | <code>    for pat in [r"(?mi)^HOST=([^\r\n]+)", r"(?mi)^Host:\s*([^\r\n]+)"]:</code> |
| L1249 | 遍历集合中的数据项并逐项处理，当前位于函数 extract_host_candidates。 | <code>        for m in re.finditer(pat, text):</code> |
| L1250 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 extract_host_candidates。 | <code>            host = normalize_host_text(m.group(1))</code> |
| L1251 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 extract_host_candidates。 | <code>            if host and host not in hosts:</code> |
| L1252 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 extract_host_candidates。 | <code>                hosts.append(host)</code> |
| L1253 | 结束当前函数并把结果返回给调用方，当前位于函数 extract_host_candidates。 | <code>    return hosts</code> |
| L1254 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1255 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1256 | 定义解析并确定hostips函数 &#96;resolve_host_ips&#96;，封装可复用业务逻辑。 | <code>def resolve_host_ips(host: str) -&gt; List[str]:</code> |
| L1257 | 计算并保存 &#96;target&#96;（target），供后续逻辑使用，当前位于函数 resolve_host_ips。 | <code>    target = normalize_host_text(host)</code> |
| L1258 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_host_ips。 | <code>    if not target:</code> |
| L1259 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_host_ips。 | <code>        return []</code> |
| L1260 | 计算并保存 &#96;out&#96;（out），供后续逻辑使用，当前位于函数 resolve_host_ips。 | <code>    out: List[str] = []</code> |
| L1261 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 resolve_host_ips。 | <code>    try:</code> |
| L1262 | 计算并保存 &#96;infos&#96;（infos），供后续逻辑使用，当前位于函数 resolve_host_ips。 | <code>        infos = socket.getaddrinfo(target, None)</code> |
| L1263 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 resolve_host_ips。 | <code>    except Exception:</code> |
| L1264 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_host_ips。 | <code>        return []</code> |
| L1265 | 遍历集合中的数据项并逐项处理，当前位于函数 resolve_host_ips。 | <code>    for info in infos:</code> |
| L1266 | 计算并保存 &#96;sockaddr&#96;（sockaddr），供后续逻辑使用，当前位于函数 resolve_host_ips。 | <code>        sockaddr = info[4]</code> |
| L1267 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_host_ips。 | <code>        if not sockaddr:</code> |
| L1268 | 控制当前循环或占位分支的执行流程，当前位于函数 resolve_host_ips。 | <code>            continue</code> |
| L1269 | 计算并保存 &#96;ip_text&#96;（iptext），供后续逻辑使用，当前位于函数 resolve_host_ips。 | <code>        ip_text = normalize_ip_literal(sockaddr[0])</code> |
| L1270 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_host_ips。 | <code>        if ip_text and ip_text not in out:</code> |
| L1271 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 resolve_host_ips。 | <code>            out.append(ip_text)</code> |
| L1272 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_host_ips。 | <code>    return out</code> |
| L1273 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1274 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1275 | 定义collect事件封禁ips函数 &#96;collect_event_block_ips&#96;，封装可复用业务逻辑。 | <code>def collect_event_block_ips(</code> |
| L1276 | 计算并保存 &#96;cur&#96;（cur），供后续逻辑使用，当前位于函数 collect_event_block_ips。 | <code>    cur: Any, event_id: str, source_ip: str, request_log: str, block_mode: str = "source"</code> |
| L1277 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 collect_event_block_ips。 | <code>) -&gt; Tuple[List[str], Dict[str, Any]]:</code> |
| L1278 | 计算并保存 &#96;mode&#96;（mode），供后续逻辑使用，当前位于函数 collect_event_block_ips。 | <code>    mode = str(block_mode or "source").strip().lower()</code> |
| L1279 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 collect_event_block_ips。 | <code>    if mode not in {"source", "target", "both"}:</code> |
| L1280 | 计算并保存 &#96;mode&#96;（mode），供后续逻辑使用，当前位于函数 collect_event_block_ips。 | <code>        mode = "source"</code> |
| L1281 | 计算并保存 &#96;ips&#96;（ips），供后续逻辑使用，当前位于函数 collect_event_block_ips。 | <code>    ips: List[str] = []</code> |
| L1282 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1283 | 计算并保存 &#96;source_candidates&#96;（来源candidates），供后续逻辑使用，当前位于函数 collect_event_block_ips。 | <code>    source_candidates: List[str] = []</code> |
| L1284 | 计算并保存 &#96;first_source&#96;（first来源），供后续逻辑使用，当前位于函数 collect_event_block_ips。 | <code>    first_source = normalize_ip_literal(source_ip)</code> |
| L1285 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 collect_event_block_ips。 | <code>    if first_source:</code> |
| L1286 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 collect_event_block_ips。 | <code>        source_candidates.append(first_source)</code> |
| L1287 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1288 | 遍历集合中的数据项并逐项处理，当前位于函数 collect_event_block_ips。 | <code>    for pat in [r"(?mi)^src_ip=([^\r\n]+)", r"(?mi)\bsrc(?:_&#124; )?ip[:=]\s*([0-9a-fA-F:.]+)"]:</code> |
| L1289 | 遍历集合中的数据项并逐项处理，当前位于函数 collect_event_block_ips。 | <code>        for m in re.finditer(pat, str(request_log or "")):</code> |
| L1290 | 计算并保存 &#96;src&#96;（src），供后续逻辑使用，当前位于函数 collect_event_block_ips。 | <code>            src = normalize_ip_literal(m.group(1))</code> |
| L1291 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 collect_event_block_ips。 | <code>            if src and src not in source_candidates:</code> |
| L1292 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 collect_event_block_ips。 | <code>                source_candidates.append(src)</code> |
| L1293 | 遍历集合中的数据项并逐项处理，当前位于函数 collect_event_block_ips。 | <code>    for m in re.finditer(r"((?:\d{1,3}\.){3}\d{1,3})\s*-&gt;", str(request_log or "")):</code> |
| L1294 | 计算并保存 &#96;src&#96;（src），供后续逻辑使用，当前位于函数 collect_event_block_ips。 | <code>        src = normalize_ip_literal(m.group(1))</code> |
| L1295 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 collect_event_block_ips。 | <code>        if src and src not in source_candidates:</code> |
| L1296 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 collect_event_block_ips。 | <code>            source_candidates.append(src)</code> |
| L1297 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1298 | 计算并保存 &#96;destination_ip_norm&#96;（destinationipnorm），供后续逻辑使用，当前位于函数 collect_event_block_ips。 | <code>    destination_ip_norm = ""</code> |
| L1299 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 collect_event_block_ips。 | <code>    cur.execute("SELECT source_ip, attack_ip, destination_ip FROM analyses WHERE case_id=%s LIMIT 1", (event_id,))</code> |
| L1300 | 计算并保存 &#96;ana&#96;（ana），供后续逻辑使用，当前位于函数 collect_event_block_ips。 | <code>    ana = cur.fetchone() or {}</code> |
| L1301 | 遍历集合中的数据项并逐项处理，当前位于函数 collect_event_block_ips。 | <code>    for v in [ana.get("source_ip"), ana.get("attack_ip")]:</code> |
| L1302 | 计算并保存 &#96;src&#96;（src），供后续逻辑使用，当前位于函数 collect_event_block_ips。 | <code>        src = normalize_ip_literal(v)</code> |
| L1303 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 collect_event_block_ips。 | <code>        if src and src not in source_candidates:</code> |
| L1304 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 collect_event_block_ips。 | <code>            source_candidates.append(src)</code> |
| L1305 | 计算并保存 &#96;destination_ip_norm&#96;（destinationipnorm），供后续逻辑使用，当前位于函数 collect_event_block_ips。 | <code>    destination_ip_norm = normalize_ip_literal(ana.get("destination_ip"))</code> |
| L1306 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 collect_event_block_ips。 | <code>    if mode in {"source", "both"}:</code> |
| L1307 | 遍历集合中的数据项并逐项处理，当前位于函数 collect_event_block_ips。 | <code>        for src in source_candidates:</code> |
| L1308 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 collect_event_block_ips。 | <code>            if src not in ips:</code> |
| L1309 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 collect_event_block_ips。 | <code>                ips.append(src)</code> |
| L1310 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 collect_event_block_ips。 | <code>    if destination_ip_norm and mode in {"target", "both"} and destination_ip_norm not in ips:</code> |
| L1311 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 collect_event_block_ips。 | <code>        ips.append(destination_ip_norm)</code> |
| L1312 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1313 | 计算并保存 &#96;host_candidates&#96;（hostcandidates），供后续逻辑使用，当前位于函数 collect_event_block_ips。 | <code>    host_candidates = extract_host_candidates(request_log)</code> |
| L1314 | 计算并保存 &#96;host_resolved&#96;（hostresolved），供后续逻辑使用，当前位于函数 collect_event_block_ips。 | <code>    host_resolved: Dict[str, List[str]] = {}</code> |
| L1315 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 collect_event_block_ips。 | <code>    if mode in {"target", "both"}:</code> |
| L1316 | 遍历集合中的数据项并逐项处理，当前位于函数 collect_event_block_ips。 | <code>        for host in host_candidates:</code> |
| L1317 | 计算并保存 &#96;rs&#96;（rs），供后续逻辑使用，当前位于函数 collect_event_block_ips。 | <code>            rs = resolve_host_ips(host)</code> |
| L1318 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 collect_event_block_ips。 | <code>            if rs:</code> |
| L1319 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_event_block_ips。 | <code>                host_resolved[host] = rs</code> |
| L1320 | 遍历集合中的数据项并逐项处理，当前位于函数 collect_event_block_ips。 | <code>            for ip_text in rs:</code> |
| L1321 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 collect_event_block_ips。 | <code>                if ip_text not in ips:</code> |
| L1322 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 collect_event_block_ips。 | <code>                    ips.append(ip_text)</code> |
| L1323 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1324 | 计算并保存 &#96;meta&#96;（meta），供后续逻辑使用，当前位于函数 collect_event_block_ips。 | <code>    meta = {</code> |
| L1325 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_event_block_ips。 | <code>        "mode": mode,</code> |
| L1326 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_event_block_ips。 | <code>        "source_ip": source_candidates[0] if source_candidates else "",</code> |
| L1327 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_event_block_ips。 | <code>        "source_candidates": source_candidates,</code> |
| L1328 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_event_block_ips。 | <code>        "destination_ip": destination_ip_norm,</code> |
| L1329 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_event_block_ips。 | <code>        "hosts": host_candidates,</code> |
| L1330 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_event_block_ips。 | <code>        "host_resolved": host_resolved,</code> |
| L1331 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 collect_event_block_ips。 | <code>    }</code> |
| L1332 | 结束当前函数并把结果返回给调用方，当前位于函数 collect_event_block_ips。 | <code>    return ips, meta</code> |
| L1333 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1334 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1335 | 定义读取ragconn函数 &#96;get_rag_conn&#96;，封装可复用业务逻辑。 | <code>def get_rag_conn(rag_db_path: str):</code> |
| L1336 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 get_rag_conn。 | <code>    conn = sqlite3.connect(rag_db_path)</code> |
| L1337 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_rag_conn。 | <code>    conn.row_factory = sqlite3.Row</code> |
| L1338 | 结束当前函数并把结果返回给调用方，当前位于函数 get_rag_conn。 | <code>    return conn</code> |
| L1339 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1340 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1341 | 定义ensureragschema函数 &#96;ensure_rag_schema&#96;，封装可复用业务逻辑。 | <code>def ensure_rag_schema(rag_db_path: str) -&gt; None:</code> |
| L1342 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 ensure_rag_schema。 | <code>    with closing(get_rag_conn(rag_db_path)) as conn:</code> |
| L1343 | 计算并保存 &#96;cur&#96;（cur），供后续逻辑使用，当前位于函数 ensure_rag_schema。 | <code>        cur = conn.cursor()</code> |
| L1344 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_rag_schema。 | <code>        cur.execute(</code> |
| L1345 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_rag_schema。 | <code>            """</code> |
| L1346 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_rag_schema。 | <code>            CREATE VIRTUAL TABLE IF NOT EXISTS rag_docs USING fts5(</code> |
| L1347 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_rag_schema。 | <code>              doc_id UNINDEXED,</code> |
| L1348 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_rag_schema。 | <code>              title,</code> |
| L1349 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_rag_schema。 | <code>              tags,</code> |
| L1350 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_rag_schema。 | <code>              attack_type,</code> |
| L1351 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_rag_schema。 | <code>              content,</code> |
| L1352 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_rag_schema。 | <code>              evidence,</code> |
| L1353 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_rag_schema。 | <code>              mitigation,</code> |
| L1354 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_rag_schema。 | <code>              severity UNINDEXED,</code> |
| L1355 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_rag_schema。 | <code>              source UNINDEXED,</code> |
| L1356 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_rag_schema。 | <code>              tokenize='unicode61'</code> |
| L1357 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_rag_schema。 | <code>            )</code> |
| L1358 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_rag_schema。 | <code>            """</code> |
| L1359 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ensure_rag_schema。 | <code>        )</code> |
| L1360 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_rag_schema。 | <code>        conn.commit()</code> |
| L1361 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1362 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1363 | 定义读取ragseed函数 &#96;read_rag_seed&#96;，封装可复用业务逻辑。 | <code>def read_rag_seed(seed_path: str) -&gt; List[Dict[str, Any]]:</code> |
| L1364 | 计算并保存 &#96;p&#96;（p），供后续逻辑使用，当前位于函数 read_rag_seed。 | <code>    p = Path(seed_path)</code> |
| L1365 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_rag_seed。 | <code>    if not p.exists():</code> |
| L1366 | 结束当前函数并把结果返回给调用方，当前位于函数 read_rag_seed。 | <code>        return []</code> |
| L1367 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 read_rag_seed。 | <code>    try:</code> |
| L1368 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 read_rag_seed。 | <code>        data = json.loads(p.read_text(encoding="utf-8"))</code> |
| L1369 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 read_rag_seed。 | <code>    except Exception:</code> |
| L1370 | 结束当前函数并把结果返回给调用方，当前位于函数 read_rag_seed。 | <code>        return []</code> |
| L1371 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_rag_seed。 | <code>    if not isinstance(data, list):</code> |
| L1372 | 结束当前函数并把结果返回给调用方，当前位于函数 read_rag_seed。 | <code>        return []</code> |
| L1373 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 read_rag_seed。 | <code>    rows: List[Dict[str, Any]] = []</code> |
| L1374 | 遍历集合中的数据项并逐项处理，当前位于函数 read_rag_seed。 | <code>    for idx, row in enumerate(data, start=1):</code> |
| L1375 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_rag_seed。 | <code>        if not isinstance(row, dict):</code> |
| L1376 | 控制当前循环或占位分支的执行流程，当前位于函数 read_rag_seed。 | <code>            continue</code> |
| L1377 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 read_rag_seed。 | <code>        rows.append(</code> |
| L1378 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_rag_seed。 | <code>            {</code> |
| L1379 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_rag_seed。 | <code>                "doc_id": str(row.get("doc_id") or f"RAG-{idx:04d}"),</code> |
| L1380 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_rag_seed。 | <code>                "title": str(row.get("title") or ""),</code> |
| L1381 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_rag_seed。 | <code>                "tags": str(row.get("tags") or ""),</code> |
| L1382 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_rag_seed。 | <code>                "attack_type": str(row.get("attack_type") or ""),</code> |
| L1383 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_rag_seed。 | <code>                "content": str(row.get("content") or ""),</code> |
| L1384 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_rag_seed。 | <code>                "evidence": str(row.get("evidence") or ""),</code> |
| L1385 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_rag_seed。 | <code>                "mitigation": str(row.get("mitigation") or ""),</code> |
| L1386 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_rag_seed。 | <code>                "severity": str(row.get("severity") or "medium").lower(),</code> |
| L1387 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_rag_seed。 | <code>                "source": str(row.get("source") or "local_seed"),</code> |
| L1388 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 read_rag_seed。 | <code>            }</code> |
| L1389 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 read_rag_seed。 | <code>        )</code> |
| L1390 | 结束当前函数并把结果返回给调用方，当前位于函数 read_rag_seed。 | <code>    return rows</code> |
| L1391 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1392 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1393 | 定义ragupsertdoc函数 &#96;rag_upsert_doc&#96;，封装可复用业务逻辑。 | <code>def rag_upsert_doc(rag_db_path: str, row: Dict[str, Any]) -&gt; None:</code> |
| L1394 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag_upsert_doc。 | <code>    with closing(get_rag_conn(rag_db_path)) as conn:</code> |
| L1395 | 计算并保存 &#96;cur&#96;（cur），供后续逻辑使用，当前位于函数 rag_upsert_doc。 | <code>        cur = conn.cursor()</code> |
| L1396 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 rag_upsert_doc。 | <code>        cur.execute("DELETE FROM rag_docs WHERE doc_id=?", (row["doc_id"],))</code> |
| L1397 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 rag_upsert_doc。 | <code>        cur.execute(</code> |
| L1398 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 rag_upsert_doc。 | <code>            """</code> |
| L1399 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 rag_upsert_doc。 | <code>            INSERT INTO rag_docs(doc_id, title, tags, attack_type, content, evidence, mitigation, severity, source)</code> |
| L1400 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 rag_upsert_doc。 | <code>            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)</code> |
| L1401 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 rag_upsert_doc。 | <code>            """,</code> |
| L1402 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_upsert_doc。 | <code>            (</code> |
| L1403 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_upsert_doc。 | <code>                row["doc_id"],</code> |
| L1404 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_upsert_doc。 | <code>                row["title"],</code> |
| L1405 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_upsert_doc。 | <code>                row["tags"],</code> |
| L1406 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_upsert_doc。 | <code>                row["attack_type"],</code> |
| L1407 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_upsert_doc。 | <code>                row["content"],</code> |
| L1408 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_upsert_doc。 | <code>                row["evidence"],</code> |
| L1409 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_upsert_doc。 | <code>                row["mitigation"],</code> |
| L1410 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_upsert_doc。 | <code>                row["severity"],</code> |
| L1411 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_upsert_doc。 | <code>                row["source"],</code> |
| L1412 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 rag_upsert_doc。 | <code>            ),</code> |
| L1413 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 rag_upsert_doc。 | <code>        )</code> |
| L1414 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_upsert_doc。 | <code>        conn.commit()</code> |
| L1415 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1416 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1417 | 定义ragrebuildfromseed函数 &#96;rag_rebuild_from_seed&#96;，封装可复用业务逻辑。 | <code>def rag_rebuild_from_seed(rag_db_path: str, seed_path: str) -&gt; int:</code> |
| L1418 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 rag_rebuild_from_seed。 | <code>    rows = read_rag_seed(seed_path)</code> |
| L1419 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag_rebuild_from_seed。 | <code>    with closing(get_rag_conn(rag_db_path)) as conn:</code> |
| L1420 | 计算并保存 &#96;cur&#96;（cur），供后续逻辑使用，当前位于函数 rag_rebuild_from_seed。 | <code>        cur = conn.cursor()</code> |
| L1421 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 rag_rebuild_from_seed。 | <code>        cur.execute("DROP TABLE IF EXISTS rag_docs")</code> |
| L1422 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_rebuild_from_seed。 | <code>        conn.commit()</code> |
| L1423 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_rebuild_from_seed。 | <code>    ensure_rag_schema(rag_db_path)</code> |
| L1424 | 遍历集合中的数据项并逐项处理，当前位于函数 rag_rebuild_from_seed。 | <code>    for row in rows:</code> |
| L1425 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_rebuild_from_seed。 | <code>        rag_upsert_doc(rag_db_path, row)</code> |
| L1426 | 结束当前函数并把结果返回给调用方，当前位于函数 rag_rebuild_from_seed。 | <code>    return len(rows)</code> |
| L1427 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1428 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1429 | 定义rag构建matchquery函数 &#96;rag_build_match_query&#96;，封装可复用业务逻辑。 | <code>def rag_build_match_query(text: str, max_terms: int = 12) -&gt; str:</code> |
| L1430 | 计算并保存 &#96;terms&#96;（terms），供后续逻辑使用，当前位于函数 rag_build_match_query。 | <code>    terms = re.findall(r"[a-zA-Z0-9_./:-]{2,}", (text or "").lower())</code> |
| L1431 | 计算并保存 &#96;uniq&#96;（uniq），供后续逻辑使用，当前位于函数 rag_build_match_query。 | <code>    uniq: List[str] = []</code> |
| L1432 | 计算并保存 &#96;seen&#96;（seen），供后续逻辑使用，当前位于函数 rag_build_match_query。 | <code>    seen = set()</code> |
| L1433 | 遍历集合中的数据项并逐项处理，当前位于函数 rag_build_match_query。 | <code>    for t in terms:</code> |
| L1434 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag_build_match_query。 | <code>        if t in seen:</code> |
| L1435 | 控制当前循环或占位分支的执行流程，当前位于函数 rag_build_match_query。 | <code>            continue</code> |
| L1436 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 rag_build_match_query。 | <code>        seen.add(t)</code> |
| L1437 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 rag_build_match_query。 | <code>        uniq.append(t)</code> |
| L1438 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag_build_match_query。 | <code>        if len(uniq) &gt;= max_terms:</code> |
| L1439 | 控制当前循环或占位分支的执行流程，当前位于函数 rag_build_match_query。 | <code>            break</code> |
| L1440 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag_build_match_query。 | <code>    if not uniq:</code> |
| L1441 | 结束当前函数并把结果返回给调用方，当前位于函数 rag_build_match_query。 | <code>        return ""</code> |
| L1442 | 计算并保存 &#96;escaped&#96;（escaped），供后续逻辑使用，当前位于函数 rag_build_match_query。 | <code>    escaped = [f"\"{x.replace('\"', '')}\"" for x in uniq if x.strip()]</code> |
| L1443 | 结束当前函数并把结果返回给调用方，当前位于函数 rag_build_match_query。 | <code>    return " OR ".join(escaped)</code> |
| L1444 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1445 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1446 | 定义rag列出docs函数 &#96;rag_list_docs&#96;，封装可复用业务逻辑。 | <code>def rag_list_docs(rag_db_path: str, q: str, attack_type: str, page: int, page_size: int) -&gt; Dict[str, Any]:</code> |
| L1447 | 计算并保存 &#96;where_sql&#96;（wheresql），供后续逻辑使用，当前位于函数 rag_list_docs。 | <code>    where_sql = ""</code> |
| L1448 | 计算并保存 &#96;params&#96;（params），供后续逻辑使用，当前位于函数 rag_list_docs。 | <code>    params: List[Any] = []</code> |
| L1449 | 计算并保存 &#96;q&#96;（q），供后续逻辑使用，当前位于函数 rag_list_docs。 | <code>    q = q.strip()</code> |
| L1450 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 rag_list_docs。 | <code>    attack_type = attack_type.strip()</code> |
| L1451 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1452 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag_list_docs。 | <code>    with closing(get_rag_conn(rag_db_path)) as conn:</code> |
| L1453 | 计算并保存 &#96;cur&#96;（cur），供后续逻辑使用，当前位于函数 rag_list_docs。 | <code>        cur = conn.cursor()</code> |
| L1454 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag_list_docs。 | <code>        if q:</code> |
| L1455 | 计算并保存 &#96;match_q&#96;（matchq），供后续逻辑使用，当前位于函数 rag_list_docs。 | <code>            match_q = rag_build_match_query(q, max_terms=14)</code> |
| L1456 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag_list_docs。 | <code>            if match_q:</code> |
| L1457 | 计算并保存 &#96;where_sql&#96;（wheresql），供后续逻辑使用，当前位于函数 rag_list_docs。 | <code>                where_sql = "WHERE rag_docs MATCH ?"</code> |
| L1458 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 rag_list_docs。 | <code>                params.append(match_q)</code> |
| L1459 | 处理前述条件均未命中的情况，当前位于函数 rag_list_docs。 | <code>            else:</code> |
| L1460 | 计算并保存 &#96;where_sql&#96;（wheresql），供后续逻辑使用，当前位于函数 rag_list_docs。 | <code>                where_sql = "WHERE title LIKE ? OR tags LIKE ? OR content LIKE ?"</code> |
| L1461 | 计算并保存 &#96;like&#96;（like），供后续逻辑使用，当前位于函数 rag_list_docs。 | <code>                like = f"%{q}%"</code> |
| L1462 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 rag_list_docs。 | <code>                params.extend([like, like, like])</code> |
| L1463 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag_list_docs。 | <code>        if attack_type:</code> |
| L1464 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag_list_docs。 | <code>            if where_sql:</code> |
| L1465 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_list_docs。 | <code>                where_sql += " AND attack_type=?"</code> |
| L1466 | 处理前述条件均未命中的情况，当前位于函数 rag_list_docs。 | <code>            else:</code> |
| L1467 | 计算并保存 &#96;where_sql&#96;（wheresql），供后续逻辑使用，当前位于函数 rag_list_docs。 | <code>                where_sql = "WHERE attack_type=?"</code> |
| L1468 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 rag_list_docs。 | <code>            params.append(attack_type)</code> |
| L1469 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1470 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 rag_list_docs。 | <code>        cur.execute(f"SELECT COUNT(*) AS c FROM rag_docs {where_sql}", tuple(params))</code> |
| L1471 | 计算并保存 &#96;total&#96;（total），供后续逻辑使用，当前位于函数 rag_list_docs。 | <code>        total = int((cur.fetchone() or {"c": 0})["c"])</code> |
| L1472 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1473 | 计算并保存 &#96;offset&#96;（offset），供后续逻辑使用，当前位于函数 rag_list_docs。 | <code>        offset = (page - 1) * page_size</code> |
| L1474 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 rag_list_docs。 | <code>        cur.execute(</code> |
| L1475 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_list_docs。 | <code>            f"""</code> |
| L1476 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 rag_list_docs。 | <code>            SELECT rowid, doc_id, title, tags, attack_type, content, evidence, mitigation, severity, source</code> |
| L1477 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_list_docs。 | <code>            FROM rag_docs</code> |
| L1478 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_list_docs。 | <code>            {where_sql}</code> |
| L1479 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_list_docs。 | <code>            ORDER BY rowid DESC</code> |
| L1480 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_list_docs。 | <code>            LIMIT ? OFFSET ?</code> |
| L1481 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_list_docs。 | <code>            """,</code> |
| L1482 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_list_docs。 | <code>            tuple(params + [page_size, offset]),</code> |
| L1483 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 rag_list_docs。 | <code>        )</code> |
| L1484 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 rag_list_docs。 | <code>        items = [dict(x) for x in cur.fetchall()]</code> |
| L1485 | 结束当前函数并把结果返回给调用方，当前位于函数 rag_list_docs。 | <code>    return {"items": items, "total": total, "page": page, "page_size": page_size}</code> |
| L1486 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1487 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1488 | 定义rag读取doc函数 &#96;rag_get_doc&#96;，封装可复用业务逻辑。 | <code>def rag_get_doc(rag_db_path: str, doc_id: str) -&gt; Optional[Dict[str, Any]]:</code> |
| L1489 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag_get_doc。 | <code>    with closing(get_rag_conn(rag_db_path)) as conn:</code> |
| L1490 | 计算并保存 &#96;cur&#96;（cur），供后续逻辑使用，当前位于函数 rag_get_doc。 | <code>        cur = conn.cursor()</code> |
| L1491 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 rag_get_doc。 | <code>        cur.execute(</code> |
| L1492 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 rag_get_doc。 | <code>            """</code> |
| L1493 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 rag_get_doc。 | <code>            SELECT rowid, doc_id, title, tags, attack_type, content, evidence, mitigation, severity, source</code> |
| L1494 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 rag_get_doc。 | <code>            FROM rag_docs</code> |
| L1495 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 rag_get_doc。 | <code>            WHERE doc_id=?</code> |
| L1496 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 rag_get_doc。 | <code>            LIMIT 1</code> |
| L1497 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 rag_get_doc。 | <code>            """,</code> |
| L1498 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_get_doc。 | <code>            (doc_id,),</code> |
| L1499 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 rag_get_doc。 | <code>        )</code> |
| L1500 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 rag_get_doc。 | <code>        row = cur.fetchone()</code> |
| L1501 | 结束当前函数并把结果返回给调用方，当前位于函数 rag_get_doc。 | <code>        return dict(row) if row else None</code> |
| L1502 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1503 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1504 | 定义rag删除doc函数 &#96;rag_delete_doc&#96;，封装可复用业务逻辑。 | <code>def rag_delete_doc(rag_db_path: str, doc_id: str) -&gt; int:</code> |
| L1505 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag_delete_doc。 | <code>    with closing(get_rag_conn(rag_db_path)) as conn:</code> |
| L1506 | 计算并保存 &#96;cur&#96;（cur），供后续逻辑使用，当前位于函数 rag_delete_doc。 | <code>        cur = conn.cursor()</code> |
| L1507 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 rag_delete_doc。 | <code>        cur.execute("DELETE FROM rag_docs WHERE doc_id=?", (doc_id,))</code> |
| L1508 | 计算并保存 &#96;changed&#96;（changed），供后续逻辑使用，当前位于函数 rag_delete_doc。 | <code>        changed = int(cur.rowcount)</code> |
| L1509 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_delete_doc。 | <code>        conn.commit()</code> |
| L1510 | 结束当前函数并把结果返回给调用方，当前位于函数 rag_delete_doc。 | <code>    return changed</code> |
| L1511 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1512 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1513 | 定义读取conn函数 &#96;get_conn&#96;，封装可复用业务逻辑。 | <code>def get_conn(mysql_conf: Dict[str, Any], autocommit: bool = False):</code> |
| L1514 | 结束当前函数并把结果返回给调用方，当前位于函数 get_conn。 | <code>    return pymysql.connect(</code> |
| L1515 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 get_conn。 | <code>        host=mysql_conf["host"],</code> |
| L1516 | 计算并保存 &#96;port&#96;（port），供后续逻辑使用，当前位于函数 get_conn。 | <code>        port=mysql_conf["port"],</code> |
| L1517 | 计算并保存 &#96;user&#96;（user），供后续逻辑使用，当前位于函数 get_conn。 | <code>        user=mysql_conf["user"],</code> |
| L1518 | 控制当前循环或占位分支的执行流程，当前位于函数 get_conn。 | <code>        password=mysql_conf["password"],</code> |
| L1519 | 计算并保存 &#96;database&#96;（数据库），供后续逻辑使用，当前位于函数 get_conn。 | <code>        database=mysql_conf["database"],</code> |
| L1520 | 计算并保存 &#96;charset&#96;（charset），供后续逻辑使用，当前位于函数 get_conn。 | <code>        charset="utf8mb4",</code> |
| L1521 | 计算并保存 &#96;cursorclass&#96;（cursorclass），供后续逻辑使用，当前位于函数 get_conn。 | <code>        cursorclass=DictCursor,</code> |
| L1522 | 计算并保存 &#96;autocommit&#96;（autocommit），供后续逻辑使用，当前位于函数 get_conn。 | <code>        autocommit=autocommit,</code> |
| L1523 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 get_conn。 | <code>    )</code> |
| L1524 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1525 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1526 | 定义加载system配置map函数 &#96;load_system_config_map&#96;，封装可复用业务逻辑。 | <code>def load_system_config_map(conn: Any) -&gt; Dict[str, str]:</code> |
| L1527 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 load_system_config_map。 | <code>    with conn.cursor() as cur:</code> |
| L1528 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 load_system_config_map。 | <code>        cur.execute("SELECT config_key, config_value FROM demo_system_config")</code> |
| L1529 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 load_system_config_map。 | <code>        rows = cur.fetchall()</code> |
| L1530 | 结束当前函数并把结果返回给调用方，当前位于函数 load_system_config_map。 | <code>    return {str(x.get("config_key", "")).strip(): str(x.get("config_value", "")).strip() for x in rows}</code> |
| L1531 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1532 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1533 | 定义标准化homepagebackgroundurl函数 &#96;normalize_homepage_background_url&#96;，封装可复用业务逻辑。 | <code>def normalize_homepage_background_url(value: str) -&gt; str:</code> |
| L1534 | 计算并保存 &#96;url&#96;（url），供后续逻辑使用，当前位于函数 normalize_homepage_background_url。 | <code>    url = str(value or "").strip()</code> |
| L1535 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_homepage_background_url。 | <code>    if url == "/assets/bg-main.jpg":</code> |
| L1536 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_homepage_background_url。 | <code>        return DEFAULT_HOMEPAGE_BACKGROUND</code> |
| L1537 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_homepage_background_url。 | <code>    if not url or not url.startswith("/") or url.startswith("//") or "\\" in url or '"' in url:</code> |
| L1538 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_homepage_background_url。 | <code>        return DEFAULT_HOMEPAGE_BACKGROUND</code> |
| L1539 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_homepage_background_url。 | <code>    if url.startswith("/uploads/homepage_background_"):</code> |
| L1540 | 计算并保存 &#96;upload_path&#96;（uploadpath），供后续逻辑使用，当前位于函数 normalize_homepage_background_url。 | <code>        upload_path = DASHBOARD_PUBLIC_DIR / url.lstrip("/")</code> |
| L1541 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_homepage_background_url。 | <code>        if not upload_path.is_file():</code> |
| L1542 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_homepage_background_url。 | <code>            return DEFAULT_HOMEPAGE_BACKGROUND</code> |
| L1543 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_homepage_background_url。 | <code>    return url[:240]</code> |
| L1544 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1545 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1546 | 定义检测backgroundextension函数 &#96;detect_background_extension&#96;，封装可复用业务逻辑。 | <code>def detect_background_extension(filename: str, content_type: str, data: bytes) -&gt; str:</code> |
| L1547 | 计算并保存 &#96;suffix&#96;（suffix），供后续逻辑使用，当前位于函数 detect_background_extension。 | <code>    suffix = Path(filename or "").suffix.lower().lstrip(".")</code> |
| L1548 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 detect_background_extension。 | <code>    if suffix == "jpeg":</code> |
| L1549 | 计算并保存 &#96;suffix&#96;（suffix），供后续逻辑使用，当前位于函数 detect_background_extension。 | <code>        suffix = "jpg"</code> |
| L1550 | 计算并保存 &#96;content_type&#96;（contenttype），供后续逻辑使用，当前位于函数 detect_background_extension。 | <code>    content_type = str(content_type or "").lower()</code> |
| L1551 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 detect_background_extension。 | <code>    if suffix not in ALLOWED_BACKGROUND_EXTENSIONS:</code> |
| L1552 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 detect_background_extension。 | <code>        if "png" in content_type:</code> |
| L1553 | 计算并保存 &#96;suffix&#96;（suffix），供后续逻辑使用，当前位于函数 detect_background_extension。 | <code>            suffix = "png"</code> |
| L1554 | 当前一条件未命中时继续判断另一条件，当前位于函数 detect_background_extension。 | <code>        elif "webp" in content_type:</code> |
| L1555 | 计算并保存 &#96;suffix&#96;（suffix），供后续逻辑使用，当前位于函数 detect_background_extension。 | <code>            suffix = "webp"</code> |
| L1556 | 当前一条件未命中时继续判断另一条件，当前位于函数 detect_background_extension。 | <code>        elif "jpeg" in content_type or "jpg" in content_type:</code> |
| L1557 | 计算并保存 &#96;suffix&#96;（suffix），供后续逻辑使用，当前位于函数 detect_background_extension。 | <code>            suffix = "jpg"</code> |
| L1558 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 detect_background_extension。 | <code>    if suffix not in ALLOWED_BACKGROUND_EXTENSIONS:</code> |
| L1559 | 结束当前函数并把结果返回给调用方，当前位于函数 detect_background_extension。 | <code>        return ""</code> |
| L1560 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 detect_background_extension。 | <code>    if suffix == "png" and data.startswith(b"\x89PNG\r\n\x1a\n"):</code> |
| L1561 | 结束当前函数并把结果返回给调用方，当前位于函数 detect_background_extension。 | <code>        return "png"</code> |
| L1562 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 detect_background_extension。 | <code>    if suffix == "jpg" and data.startswith(b"\xff\xd8\xff"):</code> |
| L1563 | 结束当前函数并把结果返回给调用方，当前位于函数 detect_background_extension。 | <code>        return "jpg"</code> |
| L1564 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 detect_background_extension。 | <code>    if suffix == "webp" and data.startswith(b"RIFF") and data[8:12] == b"WEBP":</code> |
| L1565 | 结束当前函数并把结果返回给调用方，当前位于函数 detect_background_extension。 | <code>        return "webp"</code> |
| L1566 | 结束当前函数并把结果返回给调用方，当前位于函数 detect_background_extension。 | <code>    return ""</code> |
| L1567 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1568 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1569 | 定义标准化ollamaurl函数 &#96;normalize_ollama_url&#96;，封装可复用业务逻辑。 | <code>def normalize_ollama_url(raw_url: str) -&gt; str:</code> |
| L1570 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 normalize_ollama_url。 | <code>    text = str(raw_url or "").strip()</code> |
| L1571 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_ollama_url。 | <code>    if not text:</code> |
| L1572 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_ollama_url。 | <code>        return "http://127.0.0.1:11434"</code> |
| L1573 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_ollama_url。 | <code>    return text.rstrip("/")</code> |
| L1574 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1575 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1576 | 定义列出ollamamodels函数 &#96;list_ollama_models&#96;，封装可复用业务逻辑。 | <code>def list_ollama_models(ollama_url: str, timeout: int = 5) -&gt; Dict[str, Any]:</code> |
| L1577 | 计算并保存 &#96;base&#96;（base），供后续逻辑使用，当前位于函数 list_ollama_models。 | <code>    base = normalize_ollama_url(ollama_url)</code> |
| L1578 | 计算并保存 &#96;endpoint&#96;（endpoint），供后续逻辑使用，当前位于函数 list_ollama_models。 | <code>    endpoint = f"{base}/api/tags"</code> |
| L1579 | 计算并保存 &#96;req&#96;（req），供后续逻辑使用，当前位于函数 list_ollama_models。 | <code>    req = urllib.request.Request(endpoint, method="GET")</code> |
| L1580 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 list_ollama_models。 | <code>    try:</code> |
| L1581 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 list_ollama_models。 | <code>        with urllib.request.urlopen(req, timeout=timeout) as resp:</code> |
| L1582 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 list_ollama_models。 | <code>            body = resp.read().decode("utf-8", errors="replace")</code> |
| L1583 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 list_ollama_models。 | <code>            data = json.loads(body or "{}")</code> |
| L1584 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 list_ollama_models。 | <code>    except Exception as exc:  # noqa: BLE001</code> |
| L1585 | 结束当前函数并把结果返回给调用方，当前位于函数 list_ollama_models。 | <code>        return {"ok": False, "models": [], "error": str(exc), "ollama_url": base}</code> |
| L1586 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1587 | 计算并保存 &#96;raw_models&#96;（rawmodels），供后续逻辑使用，当前位于函数 list_ollama_models。 | <code>    raw_models = data.get("models", [])</code> |
| L1588 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 list_ollama_models。 | <code>    items: List[Dict[str, Any]] = []</code> |
| L1589 | 计算并保存 &#96;seen&#96;（seen），供后续逻辑使用，当前位于函数 list_ollama_models。 | <code>    seen = set()</code> |
| L1590 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_ollama_models。 | <code>    if isinstance(raw_models, list):</code> |
| L1591 | 遍历集合中的数据项并逐项处理，当前位于函数 list_ollama_models。 | <code>        for row in raw_models:</code> |
| L1592 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_ollama_models。 | <code>            if not isinstance(row, dict):</code> |
| L1593 | 控制当前循环或占位分支的执行流程，当前位于函数 list_ollama_models。 | <code>                continue</code> |
| L1594 | 计算并保存 &#96;name&#96;（name），供后续逻辑使用，当前位于函数 list_ollama_models。 | <code>            name = str(row.get("name", "")).strip()</code> |
| L1595 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_ollama_models。 | <code>            if not name or name in seen:</code> |
| L1596 | 控制当前循环或占位分支的执行流程，当前位于函数 list_ollama_models。 | <code>                continue</code> |
| L1597 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 list_ollama_models。 | <code>            seen.add(name)</code> |
| L1598 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 list_ollama_models。 | <code>            items.append(</code> |
| L1599 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_ollama_models。 | <code>                {</code> |
| L1600 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_ollama_models。 | <code>                    "name": name,</code> |
| L1601 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_ollama_models。 | <code>                    "size": int(row.get("size") or 0),</code> |
| L1602 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_ollama_models。 | <code>                    "modified_at": str(row.get("modified_at") or ""),</code> |
| L1603 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 list_ollama_models。 | <code>                }</code> |
| L1604 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 list_ollama_models。 | <code>            )</code> |
| L1605 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_ollama_models。 | <code>    items.sort(key=lambda x: x["name"])</code> |
| L1606 | 结束当前函数并把结果返回给调用方，当前位于函数 list_ollama_models。 | <code>    return {"ok": True, "models": items, "error": "", "ollama_url": base}</code> |
| L1607 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1608 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1609 | 定义解析并确定legacy模型artifacts函数 &#96;resolve_legacy_model_artifacts&#96;，封装可复用业务逻辑。 | <code>def resolve_legacy_model_artifacts() -&gt; Tuple[Path, Path]:</code> |
| L1610 | 计算并保存 &#96;script_dir&#96;（scriptdir），供后续逻辑使用，当前位于函数 resolve_legacy_model_artifacts。 | <code>    script_dir = Path(__file__).resolve().parent</code> |
| L1611 | 计算并保存 &#96;project_root&#96;（projectroot），供后续逻辑使用，当前位于函数 resolve_legacy_model_artifacts。 | <code>    project_root = script_dir.parent</code> |
| L1612 | 计算并保存 &#96;local_models&#96;（localmodels），供后续逻辑使用，当前位于函数 resolve_legacy_model_artifacts。 | <code>    local_models = project_root / "models"</code> |
| L1613 | 计算并保存 &#96;local_pre&#96;（localpre），供后续逻辑使用，当前位于函数 resolve_legacy_model_artifacts。 | <code>    local_pre = local_models / "preprocessor.joblib"</code> |
| L1614 | 计算并保存 &#96;local_mdl&#96;（localmdl），供后续逻辑使用，当前位于函数 resolve_legacy_model_artifacts。 | <code>    local_mdl = local_models / "best_mlp.pth"</code> |
| L1615 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_legacy_model_artifacts。 | <code>    if local_pre.exists() and local_mdl.exists():</code> |
| L1616 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_legacy_model_artifacts。 | <code>        return local_pre, local_mdl</code> |
| L1617 | 计算并保存 &#96;fallback_models&#96;（fallbackmodels），供后续逻辑使用，当前位于函数 resolve_legacy_model_artifacts。 | <code>    fallback_models = project_root.parent / "traffic_mlp" / "models"</code> |
| L1618 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_legacy_model_artifacts。 | <code>    return fallback_models / "preprocessor.joblib", fallback_models / "best_mlp.pth"</code> |
| L1619 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1620 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1621 | 定义列出tsharkinterfaces函数 &#96;list_tshark_interfaces&#96;，封装可复用业务逻辑。 | <code>def list_tshark_interfaces(timeout: int = 12) -&gt; Dict[str, Any]:</code> |
| L1622 | 计算并保存 &#96;tshark_path&#96;（tsharkpath），供后续逻辑使用，当前位于函数 list_tshark_interfaces。 | <code>    tshark_path = shutil.which("tshark")</code> |
| L1623 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_tshark_interfaces。 | <code>    if not tshark_path:</code> |
| L1624 | 结束当前函数并把结果返回给调用方，当前位于函数 list_tshark_interfaces。 | <code>        return {"ok": False, "path": "", "items": [], "error": "tshark_not_found"}</code> |
| L1625 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 list_tshark_interfaces。 | <code>    try:</code> |
| L1626 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 list_tshark_interfaces。 | <code>        result = subprocess.run(</code> |
| L1627 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_tshark_interfaces。 | <code>            [tshark_path, "-D"],</code> |
| L1628 | 计算并保存 &#96;capture_output&#96;（captureoutput），供后续逻辑使用，当前位于函数 list_tshark_interfaces。 | <code>            capture_output=True,</code> |
| L1629 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 list_tshark_interfaces。 | <code>            text=True,</code> |
| L1630 | 计算并保存 &#96;encoding&#96;（encoding），供后续逻辑使用，当前位于函数 list_tshark_interfaces。 | <code>            encoding="utf-8",</code> |
| L1631 | 计算并保存 &#96;errors&#96;（errors），供后续逻辑使用，当前位于函数 list_tshark_interfaces。 | <code>            errors="replace",</code> |
| L1632 | 计算并保存 &#96;timeout&#96;（timeout），供后续逻辑使用，当前位于函数 list_tshark_interfaces。 | <code>            timeout=timeout,</code> |
| L1633 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 list_tshark_interfaces。 | <code>        )</code> |
| L1634 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 list_tshark_interfaces。 | <code>    except Exception as exc:  # noqa: BLE001</code> |
| L1635 | 结束当前函数并把结果返回给调用方，当前位于函数 list_tshark_interfaces。 | <code>        return {"ok": False, "path": tshark_path, "items": [], "error": str(exc)}</code> |
| L1636 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_tshark_interfaces。 | <code>    if result.returncode != 0:</code> |
| L1637 | 计算并保存 &#96;detail&#96;（detail），供后续逻辑使用，当前位于函数 list_tshark_interfaces。 | <code>        detail = (result.stderr or result.stdout or "").strip()</code> |
| L1638 | 结束当前函数并把结果返回给调用方，当前位于函数 list_tshark_interfaces。 | <code>        return {"ok": False, "path": tshark_path, "items": [], "error": detail or f"returncode={result.returncode}"}</code> |
| L1639 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1640 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 list_tshark_interfaces。 | <code>    items: List[Dict[str, str]] = []</code> |
| L1641 | 遍历集合中的数据项并逐项处理，当前位于函数 list_tshark_interfaces。 | <code>    for raw_line in (result.stdout or "").splitlines():</code> |
| L1642 | 计算并保存 &#96;line&#96;（line），供后续逻辑使用，当前位于函数 list_tshark_interfaces。 | <code>        line = str(raw_line or "").strip()</code> |
| L1643 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_tshark_interfaces。 | <code>        if not line:</code> |
| L1644 | 控制当前循环或占位分支的执行流程，当前位于函数 list_tshark_interfaces。 | <code>            continue</code> |
| L1645 | 计算并保存 &#96;m&#96;（m），供后续逻辑使用，当前位于函数 list_tshark_interfaces。 | <code>        m = re.match(r"^(\d+)\.\s+(.+)$", line)</code> |
| L1646 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_tshark_interfaces。 | <code>        if not m:</code> |
| L1647 | 控制当前循环或占位分支的执行流程，当前位于函数 list_tshark_interfaces。 | <code>            continue</code> |
| L1648 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 list_tshark_interfaces。 | <code>        items.append({"index": m.group(1), "name": m.group(2), "raw": line})</code> |
| L1649 | 结束当前函数并把结果返回给调用方，当前位于函数 list_tshark_interfaces。 | <code>    return {"ok": True, "path": tshark_path, "items": items, "error": ""}</code> |
| L1650 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1651 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1652 | 定义解析并确定captureinterface函数 &#96;resolve_capture_interface&#96;，封装可复用业务逻辑。 | <code>def resolve_capture_interface(</code> |
| L1653 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 resolve_capture_interface。 | <code>    configured_interface: str,</code> |
| L1654 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 resolve_capture_interface。 | <code>    interface_items: List[Dict[str, str]],</code> |
| L1655 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 resolve_capture_interface。 | <code>) -&gt; Tuple[str, str]:</code> |
| L1656 | 计算并保存 &#96;cfg&#96;（cfg），供后续逻辑使用，当前位于函数 resolve_capture_interface。 | <code>    cfg = str(configured_interface or "").strip()</code> |
| L1657 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_capture_interface。 | <code>    if not interface_items:</code> |
| L1658 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_capture_interface。 | <code>        return "", ""</code> |
| L1659 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_capture_interface。 | <code>    if not cfg or cfg.lower() in {"auto", "default", "自动"}:</code> |
| L1660 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_capture_interface。 | <code>        return str(interface_items[0].get("index", "")).strip(), str(interface_items[0].get("name", "")).strip()</code> |
| L1661 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1662 | 遍历集合中的数据项并逐项处理，当前位于函数 resolve_capture_interface。 | <code>    for row in interface_items:</code> |
| L1663 | 计算并保存 &#96;idx&#96;（idx），供后续逻辑使用，当前位于函数 resolve_capture_interface。 | <code>        idx = str(row.get("index", "")).strip()</code> |
| L1664 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_capture_interface。 | <code>        if cfg == idx:</code> |
| L1665 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_capture_interface。 | <code>            return idx, str(row.get("name", "")).strip()</code> |
| L1666 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1667 | 计算并保存 &#96;cfg_lower&#96;（cfglower），供后续逻辑使用，当前位于函数 resolve_capture_interface。 | <code>    cfg_lower = cfg.lower()</code> |
| L1668 | 遍历集合中的数据项并逐项处理，当前位于函数 resolve_capture_interface。 | <code>    for row in interface_items:</code> |
| L1669 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 resolve_capture_interface。 | <code>        raw = str(row.get("raw", "")).lower()</code> |
| L1670 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_capture_interface。 | <code>        if cfg_lower and cfg_lower in raw:</code> |
| L1671 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_capture_interface。 | <code>            return str(row.get("index", "")).strip(), str(row.get("name", "")).strip()</code> |
| L1672 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1673 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_capture_interface。 | <code>    return "", ""</code> |
| L1674 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1675 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1676 | 定义probecaptureoninterface函数 &#96;probe_capture_on_interface&#96;，封装可复用业务逻辑。 | <code>def probe_capture_on_interface(interface_index: str, monitor_ports: str, timeout: int = 10) -&gt; Dict[str, Any]:</code> |
| L1677 | 计算并保存 &#96;tshark_path&#96;（tsharkpath），供后续逻辑使用，当前位于函数 probe_capture_on_interface。 | <code>    tshark_path = shutil.which("tshark")</code> |
| L1678 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 probe_capture_on_interface。 | <code>    if not tshark_path:</code> |
| L1679 | 结束当前函数并把结果返回给调用方，当前位于函数 probe_capture_on_interface。 | <code>        return {"ok": False, "error": "tshark_not_found", "detail": ""}</code> |
| L1680 | 计算并保存 &#96;iface&#96;（iface），供后续逻辑使用，当前位于函数 probe_capture_on_interface。 | <code>    iface = str(interface_index or "").strip()</code> |
| L1681 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 probe_capture_on_interface。 | <code>    if not iface:</code> |
| L1682 | 结束当前函数并把结果返回给调用方，当前位于函数 probe_capture_on_interface。 | <code>        return {"ok": False, "error": "empty_interface", "detail": ""}</code> |
| L1683 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1684 | 计算并保存 &#96;cmd&#96;（cmd），供后续逻辑使用，当前位于函数 probe_capture_on_interface。 | <code>    cmd = [tshark_path, "-i", iface, "-a", "duration:1", "-Q", "-c", "1"]</code> |
| L1685 | 计算并保存 &#96;raw_parts&#96;（rawparts），供后续逻辑使用，当前位于函数 probe_capture_on_interface。 | <code>    raw_parts = [x for x in re.split(r"[\s,]+", str(monitor_ports or "").strip()) if x]</code> |
| L1686 | 计算并保存 &#96;ports&#96;（ports），供后续逻辑使用，当前位于函数 probe_capture_on_interface。 | <code>    ports: List[str] = [x for x in raw_parts if x.isdigit() and 1 &lt;= int(x) &lt;= 65535][:6]</code> |
| L1687 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 probe_capture_on_interface。 | <code>    if ports:</code> |
| L1688 | 计算并保存 &#96;expr&#96;（expr），供后续逻辑使用，当前位于函数 probe_capture_on_interface。 | <code>        expr = " or ".join(f"tcp port {p}" for p in ports)</code> |
| L1689 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 probe_capture_on_interface。 | <code>        cmd.extend(["-f", expr])</code> |
| L1690 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1691 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 probe_capture_on_interface。 | <code>    try:</code> |
| L1692 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 probe_capture_on_interface。 | <code>        result = subprocess.run(</code> |
| L1693 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 probe_capture_on_interface。 | <code>            cmd,</code> |
| L1694 | 计算并保存 &#96;capture_output&#96;（captureoutput），供后续逻辑使用，当前位于函数 probe_capture_on_interface。 | <code>            capture_output=True,</code> |
| L1695 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 probe_capture_on_interface。 | <code>            text=True,</code> |
| L1696 | 计算并保存 &#96;encoding&#96;（encoding），供后续逻辑使用，当前位于函数 probe_capture_on_interface。 | <code>            encoding="utf-8",</code> |
| L1697 | 计算并保存 &#96;errors&#96;（errors），供后续逻辑使用，当前位于函数 probe_capture_on_interface。 | <code>            errors="replace",</code> |
| L1698 | 计算并保存 &#96;timeout&#96;（timeout），供后续逻辑使用，当前位于函数 probe_capture_on_interface。 | <code>            timeout=timeout,</code> |
| L1699 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 probe_capture_on_interface。 | <code>        )</code> |
| L1700 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 probe_capture_on_interface。 | <code>    except Exception as exc:  # noqa: BLE001</code> |
| L1701 | 结束当前函数并把结果返回给调用方，当前位于函数 probe_capture_on_interface。 | <code>        return {"ok": False, "error": "probe_exception", "detail": str(exc), "cmd": cmd}</code> |
| L1702 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1703 | 计算并保存 &#96;mix&#96;（mix），供后续逻辑使用，当前位于函数 probe_capture_on_interface。 | <code>    mix = f"{result.stdout or ''}\n{result.stderr or ''}".lower()</code> |
| L1704 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 probe_capture_on_interface。 | <code>    if result.returncode == 0:</code> |
| L1705 | 结束当前函数并把结果返回给调用方，当前位于函数 probe_capture_on_interface。 | <code>        return {"ok": True, "error": "", "detail": "短时抓包探测成功", "cmd": cmd}</code> |
| L1706 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 probe_capture_on_interface。 | <code>    if any(</code> |
| L1707 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 probe_capture_on_interface。 | <code>        token in mix</code> |
| L1708 | 遍历集合中的数据项并逐项处理，当前位于函数 probe_capture_on_interface。 | <code>        for token in [</code> |
| L1709 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 probe_capture_on_interface。 | <code>            "permission",</code> |
| L1710 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 probe_capture_on_interface。 | <code>            "you don't have permission",</code> |
| L1711 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 probe_capture_on_interface。 | <code>            "access is denied",</code> |
| L1712 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 probe_capture_on_interface。 | <code>            "could not be initiated",</code> |
| L1713 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 probe_capture_on_interface。 | <code>            "cannot open adapter",</code> |
| L1714 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 probe_capture_on_interface。 | <code>        ]</code> |
| L1715 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 probe_capture_on_interface。 | <code>    ):</code> |
| L1716 | 结束当前函数并把结果返回给调用方，当前位于函数 probe_capture_on_interface。 | <code>        return {</code> |
| L1717 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 probe_capture_on_interface。 | <code>            "ok": False,</code> |
| L1718 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 probe_capture_on_interface。 | <code>            "error": "permission_denied",</code> |
| L1719 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 probe_capture_on_interface。 | <code>            "detail": "抓包权限不足，请使用管理员权限运行 app.py 或检查 Npcap AdminOnly",</code> |
| L1720 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 probe_capture_on_interface。 | <code>            "cmd": cmd,</code> |
| L1721 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 probe_capture_on_interface。 | <code>        }</code> |
| L1722 | 计算并保存 &#96;detail&#96;（detail），供后续逻辑使用，当前位于函数 probe_capture_on_interface。 | <code>    detail = (result.stderr or result.stdout or "").strip()</code> |
| L1723 | 结束当前函数并把结果返回给调用方，当前位于函数 probe_capture_on_interface。 | <code>    return {"ok": False, "error": f"probe_failed_rc_{result.returncode}", "detail": detail, "cmd": cmd}</code> |
| L1724 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1725 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1726 | 定义ensureschema函数 &#96;ensure_schema&#96;，封装可复用业务逻辑。 | <code>def ensure_schema(conn: Any) -&gt; None:</code> |
| L1727 | 计算并保存 &#96;ddl_list&#96;（ddl列出），供后续逻辑使用，当前位于函数 ensure_schema。 | <code>    ddl_list = [</code> |
| L1728 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """</code> |
| L1729 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>        CREATE TABLE IF NOT EXISTS demo_users (</code> |
| L1730 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          id INT AUTO_INCREMENT PRIMARY KEY,</code> |
| L1731 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          username VARCHAR(64) NOT NULL UNIQUE,</code> |
| L1732 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          password VARCHAR(128) NOT NULL,</code> |
| L1733 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          role VARCHAR(16) NOT NULL,</code> |
| L1734 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          display_name VARCHAR(64) NOT NULL,</code> |
| L1735 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          nickname VARCHAR(64) NOT NULL DEFAULT '',</code> |
| L1736 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          avatar_url VARCHAR(512) NOT NULL DEFAULT '',</code> |
| L1737 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L1738 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP</code> |
| L1739 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L1740 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """,</code> |
| L1741 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """</code> |
| L1742 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>        CREATE TABLE IF NOT EXISTS demo_machines (</code> |
| L1743 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          id INT AUTO_INCREMENT PRIMARY KEY,</code> |
| L1744 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          machine_name VARCHAR(64) NOT NULL UNIQUE,</code> |
| L1745 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          ip_address VARCHAR(64) NOT NULL,</code> |
| L1746 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          deploy_location VARCHAR(128) NOT NULL,</code> |
| L1747 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          online_status VARCHAR(16) NOT NULL DEFAULT 'online',</code> |
| L1748 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          today_attack_count INT NOT NULL DEFAULT 0,</code> |
| L1749 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          current_alert_count INT NOT NULL DEFAULT 0,</code> |
| L1750 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          last_heartbeat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L1751 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          cpu_usage DOUBLE NOT NULL DEFAULT 0,</code> |
| L1752 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          memory_usage DOUBLE NOT NULL DEFAULT 0,</code> |
| L1753 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          gpu_usage DOUBLE NOT NULL DEFAULT 0,</code> |
| L1754 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          model_status VARCHAR(32) NOT NULL DEFAULT 'running',</code> |
| L1755 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L1756 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP</code> |
| L1757 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L1758 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """,</code> |
| L1759 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """</code> |
| L1760 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>        CREATE TABLE IF NOT EXISTS demo_attack_events (</code> |
| L1761 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          event_id VARCHAR(40) PRIMARY KEY,</code> |
| L1762 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          occurred_at DATETIME(3) NOT NULL,</code> |
| L1763 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          risk_level VARCHAR(16) NOT NULL,</code> |
| L1764 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          attack_type VARCHAR(64) NOT NULL,</code> |
| L1765 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          source_ip VARCHAR(64) NOT NULL,</code> |
| L1766 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          source_region VARCHAR(64) NOT NULL,</code> |
| L1767 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          target_node VARCHAR(64) NOT NULL,</code> |
| L1768 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          target_port INT NULL,</code> |
| L1769 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          target_interface VARCHAR(255) NOT NULL,</code> |
| L1770 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          attack_result VARCHAR(16) NOT NULL,</code> |
| L1771 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          process_status VARCHAR(16) NOT NULL,</code> |
| L1772 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          acked TINYINT(1) NOT NULL DEFAULT 0,</code> |
| L1773 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          attack_payload LONGTEXT,</code> |
| L1774 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          request_log LONGTEXT,</code> |
| L1775 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          protection_action TEXT,</code> |
| L1776 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          handling_suggestion TEXT,</code> |
| L1777 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          note TEXT,</code> |
| L1778 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          response_ms INT NOT NULL DEFAULT 0,</code> |
| L1779 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          anomaly_detected TINYINT(1) NOT NULL DEFAULT 0,</code> |
| L1780 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          machine_id INT NULL,</code> |
| L1781 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L1782 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,</code> |
| L1783 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          KEY idx_event_time (occurred_at),</code> |
| L1784 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          KEY idx_event_risk (risk_level),</code> |
| L1785 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          KEY idx_event_type (attack_type),</code> |
| L1786 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          KEY idx_event_node (target_node)</code> |
| L1787 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L1788 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """,</code> |
| L1789 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """</code> |
| L1790 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>        CREATE TABLE IF NOT EXISTS ip_geo_cache (</code> |
| L1791 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          ip VARCHAR(64) PRIMARY KEY,</code> |
| L1792 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          region VARCHAR(128) NOT NULL,</code> |
| L1793 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          source VARCHAR(32) NOT NULL DEFAULT 'fallback',</code> |
| L1794 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP</code> |
| L1795 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L1796 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """,</code> |
| L1797 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """</code> |
| L1798 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>        CREATE TABLE IF NOT EXISTS demo_model_metrics (</code> |
| L1799 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          id INT AUTO_INCREMENT PRIMARY KEY,</code> |
| L1800 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          metric_time DATETIME NOT NULL,</code> |
| L1801 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          node_name VARCHAR(64) NOT NULL,</code> |
| L1802 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          drift_score DOUBLE NOT NULL,</code> |
| L1803 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          accuracy DOUBLE NOT NULL,</code> |
| L1804 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          recall_rate DOUBLE NOT NULL,</code> |
| L1805 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          inference_ms DOUBLE NOT NULL,</code> |
| L1806 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L1807 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          KEY idx_metric_time (metric_time)</code> |
| L1808 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L1809 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """,</code> |
| L1810 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """</code> |
| L1811 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>        CREATE TABLE IF NOT EXISTS demo_blocked_ips (</code> |
| L1812 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          id BIGINT AUTO_INCREMENT PRIMARY KEY,</code> |
| L1813 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          ip_address VARCHAR(64) NOT NULL UNIQUE,</code> |
| L1814 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          source_event_id VARCHAR(40) NOT NULL DEFAULT '',</code> |
| L1815 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          reason VARCHAR(255) NOT NULL DEFAULT '',</code> |
| L1816 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          blocked_by VARCHAR(64) NOT NULL DEFAULT '',</code> |
| L1817 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          blocked_role VARCHAR(16) NOT NULL DEFAULT '',</code> |
| L1818 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          defense_latency_ms DOUBLE NULL,</code> |
| L1819 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L1820 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,</code> |
| L1821 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          KEY idx_blocked_at (blocked_at)</code> |
| L1822 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L1823 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """,</code> |
| L1824 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """</code> |
| L1825 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>        CREATE TABLE IF NOT EXISTS demo_auto_defense_releases (</code> |
| L1826 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          ip_address VARCHAR(64) PRIMARY KEY,</code> |
| L1827 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          released_action_at DATETIME(3) NULL,</code> |
| L1828 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          released_by VARCHAR(64) NOT NULL DEFAULT '',</code> |
| L1829 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          released_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L1830 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP</code> |
| L1831 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L1832 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """,</code> |
| L1833 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """</code> |
| L1834 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>        CREATE TABLE IF NOT EXISTS demo_fast_defense_audit (</code> |
| L1835 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          id BIGINT AUTO_INCREMENT PRIMARY KEY,</code> |
| L1836 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          request_fingerprint CHAR(64) NOT NULL,</code> |
| L1837 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          source_ip VARCHAR(64) NOT NULL,</code> |
| L1838 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          destination_ip VARCHAR(64) NOT NULL DEFAULT '',</code> |
| L1839 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          method VARCHAR(16) NOT NULL DEFAULT '',</code> |
| L1840 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          uri TEXT NOT NULL,</code> |
| L1841 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          category VARCHAR(64) NOT NULL,</code> |
| L1842 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          score INT NOT NULL,</code> |
| L1843 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          rule_ids_json TEXT NOT NULL,</code> |
| L1844 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          decision VARCHAR(32) NOT NULL,</code> |
| L1845 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          firewall_success TINYINT(1) NOT NULL DEFAULT 0,</code> |
| L1846 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          firewall_detail TEXT NOT NULL,</code> |
| L1847 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          defense_latency_ms DOUBLE NULL,</code> |
| L1848 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          request_time DATETIME(3) NULL,</code> |
| L1849 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L1850 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          KEY idx_fast_ip_time (source_ip, created_at),</code> |
| L1851 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          KEY idx_fast_category_time (category, created_at)</code> |
| L1852 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L1853 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """,</code> |
| L1854 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """</code> |
| L1855 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>        CREATE TABLE IF NOT EXISTS demo_user_action_logs (</code> |
| L1856 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          id BIGINT AUTO_INCREMENT PRIMARY KEY,</code> |
| L1857 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          username VARCHAR(64) NOT NULL,</code> |
| L1858 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          role VARCHAR(16) NOT NULL,</code> |
| L1859 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          action VARCHAR(64) NOT NULL,</code> |
| L1860 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          target VARCHAR(128) NOT NULL,</code> |
| L1861 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          detail TEXT NOT NULL,</code> |
| L1862 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L1863 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          KEY idx_log_time (created_at),</code> |
| L1864 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          KEY idx_log_user (username)</code> |
| L1865 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L1866 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """,</code> |
| L1867 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """</code> |
| L1868 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>        CREATE TABLE IF NOT EXISTS demo_system_config (</code> |
| L1869 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          config_key VARCHAR(64) PRIMARY KEY,</code> |
| L1870 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          config_value VARCHAR(256) NOT NULL,</code> |
| L1871 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP</code> |
| L1872 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L1873 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """,</code> |
| L1874 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ensure_schema。 | <code>    ]</code> |
| L1875 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 ensure_schema。 | <code>    with conn.cursor() as cur:</code> |
| L1876 | 遍历集合中的数据项并逐项处理，当前位于函数 ensure_schema。 | <code>        for ddl in ddl_list:</code> |
| L1877 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>            cur.execute(ddl)</code> |
| L1878 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema。 | <code>        if not db_column_exists(cur, "demo_users", "nickname"):</code> |
| L1879 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>            cur.execute("ALTER TABLE demo_users ADD COLUMN nickname VARCHAR(64) NOT NULL DEFAULT '' AFTER display_name")</code> |
| L1880 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema。 | <code>        if not db_column_exists(cur, "demo_users", "avatar_url"):</code> |
| L1881 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>            cur.execute("ALTER TABLE demo_users ADD COLUMN avatar_url VARCHAR(512) NOT NULL DEFAULT '' AFTER nickname")</code> |
| L1882 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema。 | <code>        if not db_column_exists(cur, "demo_blocked_ips", "defense_latency_ms"):</code> |
| L1883 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>            cur.execute("ALTER TABLE demo_blocked_ips ADD COLUMN defense_latency_ms DOUBLE NULL AFTER blocked_role")</code> |
| L1884 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema。 | <code>        if not db_column_exists(cur, "demo_fast_defense_audit", "defense_latency_ms"):</code> |
| L1885 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>            cur.execute(</code> |
| L1886 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema。 | <code>                "ALTER TABLE demo_fast_defense_audit ADD COLUMN defense_latency_ms DOUBLE NULL AFTER firewall_detail"</code> |
| L1887 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ensure_schema。 | <code>            )</code> |
| L1888 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema。 | <code>        if not db_column_exists(cur, "demo_attack_events", "target_port"):</code> |
| L1889 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>            cur.execute("ALTER TABLE demo_attack_events ADD COLUMN target_port INT NULL AFTER target_node")</code> |
| L1890 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>        cur.execute(</code> |
| L1891 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>            """</code> |
| L1892 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>            UPDATE demo_users</code> |
| L1893 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>            SET nickname=display_name</code> |
| L1894 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>            WHERE (nickname IS NULL OR nickname='')</code> |
| L1895 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>            """</code> |
| L1896 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ensure_schema。 | <code>        )</code> |
| L1897 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1898 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1899 | 定义logaction函数 &#96;log_action&#96;，封装可复用业务逻辑。 | <code>def log_action(conn: Any, username: str, role: str, action: str, target: str, detail: str) -&gt; None:</code> |
| L1900 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 log_action。 | <code>    with conn.cursor() as cur:</code> |
| L1901 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 log_action。 | <code>        cur.execute(</code> |
| L1902 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 log_action。 | <code>            """</code> |
| L1903 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 log_action。 | <code>            INSERT INTO demo_user_action_logs(username, role, action, target, detail)</code> |
| L1904 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 log_action。 | <code>            VALUES (%s, %s, %s, %s, %s)</code> |
| L1905 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 log_action。 | <code>            """,</code> |
| L1906 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 log_action。 | <code>            (username, role, action, target, detail),</code> |
| L1907 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 log_action。 | <code>        )</code> |
| L1908 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1909 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1910 | 定义recordautodefenserelease函数 &#96;record_auto_defense_release&#96;，封装可复用业务逻辑。 | <code>def record_auto_defense_release(cur: Any, ip_address: str, username: str) -&gt; None:</code> |
| L1911 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 record_auto_defense_release。 | <code>    """Prevent old situation evidence from immediately undoing a manual release."""</code> |
| L1912 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 record_auto_defense_release。 | <code>    cur.execute(</code> |
| L1913 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 record_auto_defense_release。 | <code>        """</code> |
| L1914 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 record_auto_defense_release。 | <code>        INSERT INTO demo_auto_defense_releases(ip_address, released_action_at, released_by)</code> |
| L1915 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 record_auto_defense_release。 | <code>        SELECT %s, MAX(last_action_at), %s</code> |
| L1916 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 record_auto_defense_release。 | <code>        FROM attack_situations</code> |
| L1917 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 record_auto_defense_release。 | <code>        WHERE source_ip=%s</code> |
| L1918 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 record_auto_defense_release。 | <code>        ON DUPLICATE KEY UPDATE</code> |
| L1919 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 record_auto_defense_release。 | <code>          released_action_at=VALUES(released_action_at),</code> |
| L1920 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 record_auto_defense_release。 | <code>          released_by=VALUES(released_by),</code> |
| L1921 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 record_auto_defense_release。 | <code>          released_at=CURRENT_TIMESTAMP</code> |
| L1922 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 record_auto_defense_release。 | <code>        """,</code> |
| L1923 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 record_auto_defense_release。 | <code>        (ip_address, username, ip_address),</code> |
| L1924 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 record_auto_defense_release。 | <code>    )</code> |
| L1925 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1926 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1927 | 定义seeddemodata函数 &#96;seed_demo_data&#96;，封装可复用业务逻辑。 | <code>def seed_demo_data(conn: Any, force_seed: bool = False) -&gt; None:</code> |
| L1928 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 seed_demo_data。 | <code>    with conn.cursor() as cur:</code> |
| L1929 | 遍历集合中的数据项并逐项处理，当前位于函数 seed_demo_data。 | <code>        for row in DEMO_SEED_USERS:</code> |
| L1930 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 seed_demo_data。 | <code>            if force_seed:</code> |
| L1931 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 seed_demo_data。 | <code>                cur.execute(</code> |
| L1932 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                    """</code> |
| L1933 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 seed_demo_data。 | <code>                    INSERT INTO demo_users(username, password, role, display_name, nickname)</code> |
| L1934 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                    VALUES (%s, %s, %s, %s, %s)</code> |
| L1935 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                    ON DUPLICATE KEY UPDATE</code> |
| L1936 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                      password=VALUES(password),</code> |
| L1937 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                      role=VALUES(role),</code> |
| L1938 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                      display_name=VALUES(display_name),</code> |
| L1939 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                      nickname=CASE WHEN nickname='' THEN VALUES(nickname) ELSE nickname END</code> |
| L1940 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                    """,</code> |
| L1941 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                    (row["username"], row["password"], row["role"], row["display_name"], row["display_name"]),</code> |
| L1942 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo_data。 | <code>                )</code> |
| L1943 | 处理前述条件均未命中的情况，当前位于函数 seed_demo_data。 | <code>            else:</code> |
| L1944 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 seed_demo_data。 | <code>                cur.execute(</code> |
| L1945 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                    """</code> |
| L1946 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 seed_demo_data。 | <code>                    INSERT INTO demo_users(username, password, role, display_name, nickname)</code> |
| L1947 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                    VALUES (%s, %s, %s, %s, %s)</code> |
| L1948 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                    ON DUPLICATE KEY UPDATE</code> |
| L1949 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                      role=VALUES(role),</code> |
| L1950 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                      display_name=VALUES(display_name),</code> |
| L1951 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                      nickname=CASE WHEN nickname='' THEN VALUES(nickname) ELSE nickname END</code> |
| L1952 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                    """,</code> |
| L1953 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                    (row["username"], row["password"], row["role"], row["display_name"], row["display_name"]),</code> |
| L1954 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo_data。 | <code>                )</code> |
| L1955 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 seed_demo_data。 | <code>        cur.execute(</code> |
| L1956 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>            """</code> |
| L1957 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 seed_demo_data。 | <code>            UPDATE demo_users</code> |
| L1958 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>            SET role=%s</code> |
| L1959 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>            WHERE role NOT IN (%s, %s)</code> |
| L1960 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>            """,</code> |
| L1961 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            (ROLE_NORMAL, ROLE_NORMAL, ROLE_ADMIN),</code> |
| L1962 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo_data。 | <code>        )</code> |
| L1963 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1964 | 计算并保存 &#96;defaults&#96;（defaults），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>        defaults = {</code> |
| L1965 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            "alert_threshold_high": "10",</code> |
| L1966 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            "auto_refresh_seconds": "5",</code> |
| L1967 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            "sound_alert_enabled": "1",</code> |
| L1968 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            "capture_batch_size": "4",</code> |
| L1969 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            "monitor_ports": "80,443,8080",</code> |
| L1970 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            "capture_interface": "auto",</code> |
| L1971 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            "llm_model": "qwen3:8b",</code> |
| L1972 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            "rag_enabled": "1",</code> |
| L1973 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            "llm_realtime_enabled": "1",</code> |
| L1974 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            "situation_minimum_actions": "3",</code> |
| L1975 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            "situation_window_minutes": "30",</code> |
| L1976 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            "situation_inactivity_minutes": "15",</code> |
| L1977 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            "scan_port_threshold": "10",</code> |
| L1978 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            "scan_window_seconds": "60",</code> |
| L1979 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            "proxy_cluster_window_minutes": "60",</code> |
| L1980 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            "auto_defense_enabled": "0",</code> |
| L1981 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            "auto_defense_min_risk": "critical",</code> |
| L1982 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            "auto_defense_allow_private": "0",</code> |
| L1983 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            "homepage_background_url": DEFAULT_HOMEPAGE_BACKGROUND,</code> |
| L1984 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo_data。 | <code>        }</code> |
| L1985 | 遍历集合中的数据项并逐项处理，当前位于函数 seed_demo_data。 | <code>        for k, v in defaults.items():</code> |
| L1986 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 seed_demo_data。 | <code>            cur.execute(</code> |
| L1987 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                """</code> |
| L1988 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 seed_demo_data。 | <code>                INSERT INTO demo_system_config(config_key, config_value)</code> |
| L1989 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                VALUES (%s, %s)</code> |
| L1990 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 seed_demo_data。 | <code>                ON DUPLICATE KEY UPDATE config_value=config_value</code> |
| L1991 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                """,</code> |
| L1992 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                (k, v),</code> |
| L1993 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo_data。 | <code>            )</code> |
| L1994 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1995 | 计算并保存 &#96;system&#96;（system），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>        system = collect_local_system_status()</code> |
| L1996 | 计算并保存 &#96;machine_name&#96;（machinename），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>        machine_name = str(system.get("hostname") or socket.gethostname() or "local-server")[:64]</code> |
| L1997 | 计算并保存 &#96;ip_addr&#96;（ipaddr），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>        ip_addr = str(system.get("local_ip") or "127.0.0.1")[:64]</code> |
| L1998 | 计算并保存 &#96;cpu_usage&#96;（cpuusage），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>        cpu_usage = float(system.get("cpu_percent") or 0)</code> |
| L1999 | 计算并保存 &#96;memory_usage&#96;（memoryusage），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>        memory_usage = float((system.get("memory") or {}).get("used_percent") or 0)</code> |
| L2000 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 seed_demo_data。 | <code>        cur.execute(</code> |
| L2001 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>            """</code> |
| L2002 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 seed_demo_data。 | <code>            INSERT INTO demo_machines(machine_name, ip_address, deploy_location, online_status, cpu_usage, memory_usage, gpu_usage, model_status)</code> |
| L2003 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>            VALUES (%s, %s, '本机服务器', 'online', %s, %s, 0, 'running')</code> |
| L2004 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>            ON DUPLICATE KEY UPDATE</code> |
| L2005 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>              ip_address=VALUES(ip_address), deploy_location=VALUES(deploy_location),</code> |
| L2006 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>              online_status='online', cpu_usage=VALUES(cpu_usage), memory_usage=VALUES(memory_usage), gpu_usage=0</code> |
| L2007 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>            """,</code> |
| L2008 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            (machine_name, ip_addr, cpu_usage, memory_usage),</code> |
| L2009 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo_data。 | <code>        )</code> |
| L2010 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 seed_demo_data。 | <code>        cur.execute("SELECT id FROM demo_machines WHERE machine_name=%s LIMIT 1", (machine_name,))</code> |
| L2011 | 计算并保存 &#96;local_machine_id&#96;（localmachineid），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>        local_machine_id = int((cur.fetchone() or {}).get("id") or 0)</code> |
| L2012 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 seed_demo_data。 | <code>        if local_machine_id:</code> |
| L2013 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 seed_demo_data。 | <code>            cur.execute(</code> |
| L2014 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                "UPDATE demo_attack_events SET machine_id=%s, target_node=%s",</code> |
| L2015 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                (local_machine_id, machine_name),</code> |
| L2016 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo_data。 | <code>            )</code> |
| L2017 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 seed_demo_data。 | <code>            cur.execute("DELETE FROM demo_machines WHERE id&lt;&gt;%s", (local_machine_id,))</code> |
| L2018 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2019 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 seed_demo_data。 | <code>        if force_seed:</code> |
| L2020 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 seed_demo_data。 | <code>            cur.execute("DELETE FROM demo_attack_events")</code> |
| L2021 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 seed_demo_data。 | <code>            cur.execute("DELETE FROM demo_model_metrics")</code> |
| L2022 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2023 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 seed_demo_data。 | <code>        cur.execute("SELECT COUNT(*) AS c FROM demo_attack_events")</code> |
| L2024 | 计算并保存 &#96;event_count&#96;（事件count），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>        event_count = int(cur.fetchone()["c"])</code> |
| L2025 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 seed_demo_data。 | <code>        if event_count == 0:</code> |
| L2026 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 seed_demo_data。 | <code>            cur.execute("SELECT id, machine_name FROM demo_machines")</code> |
| L2027 | 计算并保存 &#96;machine_rows&#96;（machine数据库记录），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>            machine_rows = cur.fetchall()</code> |
| L2028 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>            rows: List[Tuple[Any, ...]] = []</code> |
| L2029 | 计算并保存 &#96;begin&#96;（begin），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>            begin = now_dt() - timedelta(days=30)</code> |
| L2030 | 遍历集合中的数据项并逐项处理，当前位于函数 seed_demo_data。 | <code>            for idx in range(1500):</code> |
| L2031 | 计算并保存 &#96;occurred&#96;（occurred），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                occurred = begin + timedelta(seconds=random.randint(0, 30 * 24 * 3600))</code> |
| L2032 | 计算并保存 &#96;risk_level&#96;（risklevel），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                risk_level = random.choices(["high", "medium", "low"], weights=[0.2, 0.35, 0.45], k=1)[0]</code> |
| L2033 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                attack_type = random.choice(ATTACK_TYPES)</code> |
| L2034 | 计算并保存 &#96;source_region&#96;（来源region），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                source_region = random.choice(SOURCE_REGIONS)</code> |
| L2035 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                source_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"</code> |
| L2036 | 计算并保存 &#96;machine&#96;（machine），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                machine = random.choice(machine_rows)</code> |
| L2037 | 计算并保存 &#96;target_node&#96;（targetnode），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                target_node = machine["machine_name"]</code> |
| L2038 | 计算并保存 &#96;target_interface&#96;（targetinterface），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                target_interface = random.choice(TARGET_INTERFACES)</code> |
| L2039 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                block_prob = 0.72 if risk_level == "high" else (0.84 if risk_level == "medium" else 0.93)</code> |
| L2040 | 计算并保存 &#96;attack_result&#96;（攻击结果），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                attack_result = "blocked" if random.random() &lt; block_prob else "success"</code> |
| L2041 | 计算并保存 &#96;process_status&#96;（process状态），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                process_status = random.choices(</code> |
| L2042 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                    ["unprocessed", "processing", "done", "ignored"],</code> |
| L2043 | 计算并保存 &#96;weights&#96;（weights），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                    weights=[0.15, 0.15, 0.55, 0.15],</code> |
| L2044 | 计算并保存 &#96;k&#96;（k），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                    k=1,</code> |
| L2045 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo_data。 | <code>                )[0]</code> |
| L2046 | 计算并保存 &#96;acked&#96;（acked），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                acked = 1 if process_status in {"done", "ignored"} else 0</code> |
| L2047 | 计算并保存 &#96;response_ms&#96;（responsems），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                response_ms = random.randint(30, 2800)</code> |
| L2048 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                anomaly = 1 if (risk_level == "high" and random.random() &lt; 0.85) else (1 if random.random() &lt; 0.18 else 0)</code> |
| L2049 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                payload = demo_payload_by_type(attack_type)</code> |
| L2050 | 计算并保存 &#96;request_log&#96;（requestlog），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                request_log = f"{dt_to_str(occurred)} {source_ip} -&gt; {target_interface} {payload}"</code> |
| L2051 | 计算并保存 &#96;protection_action&#96;（protectionaction），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                protection_action = f"Applied strategy for {attack_type}, result={attack_result}"</code> |
| L2052 | 计算并保存 &#96;suggestion&#96;（suggestion），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                suggestion = f"Review rule set and strengthen policy for {attack_type}"</code> |
| L2053 | 计算并保存 &#96;event_id&#96;（事件id），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                event_id = f"EVT{occurred.strftime('%Y%m%d')}{idx:06d}"</code> |
| L2054 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 seed_demo_data。 | <code>                rows.append(</code> |
| L2055 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                    (</code> |
| L2056 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        event_id,</code> |
| L2057 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        occurred,</code> |
| L2058 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        risk_level,</code> |
| L2059 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        attack_type,</code> |
| L2060 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        source_ip,</code> |
| L2061 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        source_region,</code> |
| L2062 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        target_node,</code> |
| L2063 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        target_interface,</code> |
| L2064 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        attack_result,</code> |
| L2065 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        process_status,</code> |
| L2066 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        acked,</code> |
| L2067 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        payload,</code> |
| L2068 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        request_log,</code> |
| L2069 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        protection_action,</code> |
| L2070 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        suggestion,</code> |
| L2071 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        "",</code> |
| L2072 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        response_ms,</code> |
| L2073 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        anomaly,</code> |
| L2074 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        machine["id"],</code> |
| L2075 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo_data。 | <code>                    )</code> |
| L2076 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo_data。 | <code>                )</code> |
| L2077 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            cur.executemany(</code> |
| L2078 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                """</code> |
| L2079 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 seed_demo_data。 | <code>                INSERT INTO demo_attack_events(</code> |
| L2080 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                  event_id, occurred_at, risk_level, attack_type, source_ip, source_region, target_node, target_interface,</code> |
| L2081 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                  attack_result, process_status, acked, attack_payload, request_log, protection_action, handling_suggestion,</code> |
| L2082 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                  note, response_ms, anomaly_detected, machine_id</code> |
| L2083 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                ) VALUES(</code> |
| L2084 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                  %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s</code> |
| L2085 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                )</code> |
| L2086 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                """,</code> |
| L2087 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                rows,</code> |
| L2088 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo_data。 | <code>            )</code> |
| L2089 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2090 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 seed_demo_data。 | <code>        cur.execute("SELECT COUNT(*) AS c FROM demo_model_metrics")</code> |
| L2091 | 计算并保存 &#96;metric_count&#96;（metriccount），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>        metric_count = int(cur.fetchone()["c"])</code> |
| L2092 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 seed_demo_data。 | <code>        if metric_count == 0:</code> |
| L2093 | 计算并保存 &#96;metric_rows&#96;（metric数据库记录），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>            metric_rows: List[Tuple[Any, ...]] = []</code> |
| L2094 | 遍历集合中的数据项并逐项处理，当前位于函数 seed_demo_data。 | <code>            for day_idx in range(30):</code> |
| L2095 | 计算并保存 &#96;metric_time&#96;（metrictime），供后续逻辑使用，当前位于函数 seed_demo_data。 | <code>                metric_time = (now_dt() - timedelta(days=29 - day_idx)).replace(hour=1, minute=0, second=0, microsecond=0)</code> |
| L2096 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 seed_demo_data。 | <code>                metric_rows.append(</code> |
| L2097 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                    (</code> |
| L2098 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        metric_time,</code> |
| L2099 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        "global",</code> |
| L2100 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        round(random.uniform(0.02, 0.21), 4),</code> |
| L2101 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        round(random.uniform(0.90, 0.98), 4),</code> |
| L2102 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        round(random.uniform(0.86, 0.97), 4),</code> |
| L2103 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                        round(random.uniform(55, 250), 2),</code> |
| L2104 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo_data。 | <code>                    )</code> |
| L2105 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo_data。 | <code>                )</code> |
| L2106 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>            cur.executemany(</code> |
| L2107 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                """</code> |
| L2108 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 seed_demo_data。 | <code>                INSERT INTO demo_model_metrics(metric_time, node_name, drift_score, accuracy, recall_rate, inference_ms)</code> |
| L2109 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                VALUES (%s, %s, %s, %s, %s, %s)</code> |
| L2110 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_demo_data。 | <code>                """,</code> |
| L2111 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>                metric_rows,</code> |
| L2112 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo_data。 | <code>            )</code> |
| L2113 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo_data。 | <code>    refresh_machine_stats(conn)</code> |
| L2114 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2115 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2116 | 定义ensurebuiltinadmin函数 &#96;ensure_builtin_admin&#96;，封装可复用业务逻辑。 | <code>def ensure_builtin_admin(conn: Any) -&gt; None:</code> |
| L2117 | 源码原注释：Keep a deterministic bootstrap admin account for first login/recovery. | <code>    # Keep a deterministic bootstrap admin account for first login/recovery.</code> |
| L2118 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 ensure_builtin_admin。 | <code>    with conn.cursor() as cur:</code> |
| L2119 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_builtin_admin。 | <code>        cur.execute(</code> |
| L2120 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_builtin_admin。 | <code>            """</code> |
| L2121 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_builtin_admin。 | <code>            INSERT INTO demo_users(username, password, role, display_name, nickname)</code> |
| L2122 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_builtin_admin。 | <code>            VALUES (%s, %s, %s, %s, %s)</code> |
| L2123 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_builtin_admin。 | <code>            ON DUPLICATE KEY UPDATE</code> |
| L2124 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_builtin_admin。 | <code>              password=VALUES(password),</code> |
| L2125 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_builtin_admin。 | <code>              role=VALUES(role),</code> |
| L2126 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_builtin_admin。 | <code>              display_name=VALUES(display_name),</code> |
| L2127 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_builtin_admin。 | <code>              nickname=CASE WHEN nickname='' THEN VALUES(nickname) ELSE nickname END</code> |
| L2128 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_builtin_admin。 | <code>            """,</code> |
| L2129 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_builtin_admin。 | <code>            ("admin", "admin", ROLE_ADMIN, "管理员", "管理员"),</code> |
| L2130 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ensure_builtin_admin。 | <code>        )</code> |
| L2131 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2132 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2133 | 定义demopayloadbytype函数 &#96;demo_payload_by_type&#96;，封装可复用业务逻辑。 | <code>def demo_payload_by_type(attack_type: str) -&gt; str:</code> |
| L2134 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 demo_payload_by_type。 | <code>    attack_type = normalize_attack_type_label(attack_type)</code> |
| L2135 | 计算并保存 &#96;mapping&#96;（mapping），供后续逻辑使用，当前位于函数 demo_payload_by_type。 | <code>    mapping = {</code> |
| L2136 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 demo_payload_by_type。 | <code>        "SQL注入": "username=admin' OR 1=1 --",</code> |
| L2137 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 demo_payload_by_type。 | <code>        "XSS": "&lt;script&gt;alert('xss')&lt;/script&gt;",</code> |
| L2138 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 demo_payload_by_type。 | <code>        "暴力破解": "POST /login retry=120 user=admin",</code> |
| L2139 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 demo_payload_by_type。 | <code>        "DDoS": "High frequency requests burst detected",</code> |
| L2140 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 demo_payload_by_type。 | <code>        "端口扫描": "SYN scan to 22,80,443,3306",</code> |
| L2141 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 demo_payload_by_type。 | <code>        "命令注入": "cmd=ping 127.0.0.1 &amp;&amp; whoami",</code> |
| L2142 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 demo_payload_by_type。 | <code>        "路径遍历": "../../etc/passwd",</code> |
| L2143 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 demo_payload_by_type。 | <code>        "文件上传": "multipart payload with executable signature",</code> |
| L2144 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 demo_payload_by_type。 | <code>        "SSRF": "url=http://169.254.169.254/latest/meta-data",</code> |
| L2145 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 demo_payload_by_type。 | <code>        "RCE": "template={{7*7}} runtime command chain",</code> |
| L2146 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 demo_payload_by_type。 | <code>    }</code> |
| L2147 | 结束当前函数并把结果返回给调用方，当前位于函数 demo_payload_by_type。 | <code>    return mapping.get(attack_type, "suspicious payload")</code> |
| L2148 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2149 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2150 | 定义refreshmachinestats函数 &#96;refresh_machine_stats&#96;，封装可复用业务逻辑。 | <code>def refresh_machine_stats(conn: Any) -&gt; None:</code> |
| L2151 | 计算并保存 &#96;visible_sql&#96;（visiblesql），供后续逻辑使用，当前位于函数 refresh_machine_stats。 | <code>    visible_sql = visible_attack_event_clause()</code> |
| L2152 | 计算并保存 &#96;system&#96;（system），供后续逻辑使用，当前位于函数 refresh_machine_stats。 | <code>    system = collect_local_system_status()</code> |
| L2153 | 计算并保存 &#96;machine_name&#96;（machinename），供后续逻辑使用，当前位于函数 refresh_machine_stats。 | <code>    machine_name = str(system.get("hostname") or socket.gethostname() or "local-server")[:64]</code> |
| L2154 | 计算并保存 &#96;ip_addr&#96;（ipaddr），供后续逻辑使用，当前位于函数 refresh_machine_stats。 | <code>    ip_addr = str(system.get("local_ip") or "127.0.0.1")[:64]</code> |
| L2155 | 计算并保存 &#96;cpu_usage&#96;（cpuusage），供后续逻辑使用，当前位于函数 refresh_machine_stats。 | <code>    cpu_usage = float(system.get("cpu_percent") or 0)</code> |
| L2156 | 计算并保存 &#96;memory_usage&#96;（memoryusage），供后续逻辑使用，当前位于函数 refresh_machine_stats。 | <code>    memory_usage = float((system.get("memory") or {}).get("used_percent") or 0)</code> |
| L2157 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 refresh_machine_stats。 | <code>    with conn.cursor() as cur:</code> |
| L2158 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 refresh_machine_stats。 | <code>        cur.execute(</code> |
| L2159 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 refresh_machine_stats。 | <code>            f"""</code> |
| L2160 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 refresh_machine_stats。 | <code>            UPDATE demo_machines</code> |
| L2161 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 refresh_machine_stats。 | <code>            SET machine_name=%s, ip_address=%s, deploy_location='本机服务器', online_status='online',</code> |
| L2162 | 计算并保存 &#96;today_attack_count&#96;（today攻击count），供后续逻辑使用，当前位于函数 refresh_machine_stats。 | <code>                today_attack_count=(SELECT COUNT(*) FROM demo_attack_events WHERE DATE(occurred_at)=CURDATE() AND {visible_sql}),</code> |
| L2163 | 计算并保存 &#96;current_alert_count&#96;（currentalertcount），供后续逻辑使用，当前位于函数 refresh_machine_stats。 | <code>                current_alert_count=(SELECT COUNT(*) FROM demo_attack_events WHERE DATE(occurred_at)=CURDATE() AND risk_level IN ('critical','high') AND process_status IN ('unprocessed','processing') AND {visible_sql}),</code> |
| L2164 | 计算并保存 &#96;last_heartbeat&#96;（lastheartbeat），供后续逻辑使用，当前位于函数 refresh_machine_stats。 | <code>                last_heartbeat=NOW(), cpu_usage=%s, memory_usage=%s, gpu_usage=0</code> |
| L2165 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 refresh_machine_stats。 | <code>            """</code> |
| L2166 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 refresh_machine_stats。 | <code>            , (machine_name, ip_addr, cpu_usage, memory_usage)</code> |
| L2167 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 refresh_machine_stats。 | <code>        )</code> |
| L2168 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2169 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2170 | 定义b64urlencode函数 &#96;_b64url_encode&#96;，封装可复用业务逻辑。 | <code>def _b64url_encode(raw: bytes) -&gt; str:</code> |
| L2171 | 结束当前函数并把结果返回给调用方，当前位于函数 _b64url_encode。 | <code>    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")</code> |
| L2172 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2173 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2174 | 定义b64urldecode函数 &#96;_b64url_decode&#96;，封装可复用业务逻辑。 | <code>def _b64url_decode(raw: str) -&gt; bytes:</code> |
| L2175 | 计算并保存 &#96;padding&#96;（padding），供后续逻辑使用，当前位于函数 _b64url_decode。 | <code>    padding = "=" * ((4 - len(raw) % 4) % 4)</code> |
| L2176 | 结束当前函数并把结果返回给调用方，当前位于函数 _b64url_decode。 | <code>    return base64.urlsafe_b64decode((raw + padding).encode("ascii"))</code> |
| L2177 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2178 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2179 | 定义jwtsigninginput函数 &#96;_jwt_signing_input&#96;，封装可复用业务逻辑。 | <code>def _jwt_signing_input(header: Dict[str, Any], payload: Dict[str, Any]) -&gt; str:</code> |
| L2180 | 计算并保存 &#96;header_seg&#96;（headerseg），供后续逻辑使用，当前位于函数 _jwt_signing_input。 | <code>    header_seg = _b64url_encode(json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))</code> |
| L2181 | 计算并保存 &#96;payload_seg&#96;（payloadseg），供后续逻辑使用，当前位于函数 _jwt_signing_input。 | <code>    payload_seg = _b64url_encode(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))</code> |
| L2182 | 结束当前函数并把结果返回给调用方，当前位于函数 _jwt_signing_input。 | <code>    return f"{header_seg}.{payload_seg}"</code> |
| L2183 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2184 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2185 | 定义jwtsign函数 &#96;_jwt_sign&#96;，封装可复用业务逻辑。 | <code>def _jwt_sign(signing_input: str, secret: str) -&gt; str:</code> |
| L2186 | 计算并保存 &#96;digest&#96;（digest），供后续逻辑使用，当前位于函数 _jwt_sign。 | <code>    digest = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()</code> |
| L2187 | 结束当前函数并把结果返回给调用方，当前位于函数 _jwt_sign。 | <code>    return _b64url_encode(digest)</code> |
| L2188 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2189 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2190 | 定义创建jwttoken函数 &#96;create_jwt_token&#96;，封装可复用业务逻辑。 | <code>def create_jwt_token(user_row: Dict[str, Any], secret: str, ttl_seconds: int = TOKEN_TTL_SECONDS) -&gt; str:</code> |
| L2191 | 计算并保存 &#96;now_ts&#96;（nowts），供后续逻辑使用，当前位于函数 create_jwt_token。 | <code>    now_ts = int(now_dt().timestamp())</code> |
| L2192 | 计算并保存 &#96;exp_ts&#96;（expts），供后续逻辑使用，当前位于函数 create_jwt_token。 | <code>    exp_ts = now_ts + max(60, int(ttl_seconds))</code> |
| L2193 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 create_jwt_token。 | <code>    payload = {</code> |
| L2194 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_jwt_token。 | <code>        "sub": str(user_row.get("username") or ""),</code> |
| L2195 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_jwt_token。 | <code>        "role": str(user_row.get("role") or ""),</code> |
| L2196 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_jwt_token。 | <code>        "display_name": str(user_row.get("display_name") or ""),</code> |
| L2197 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_jwt_token。 | <code>        "nickname": str(user_row.get("nickname") or user_row.get("display_name") or ""),</code> |
| L2198 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_jwt_token。 | <code>        "avatar_url": str(user_row.get("avatar_url") or ""),</code> |
| L2199 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_jwt_token。 | <code>        "iat": now_ts,</code> |
| L2200 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_jwt_token。 | <code>        "exp": exp_ts,</code> |
| L2201 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_jwt_token。 | <code>        "jti": uuid.uuid4().hex,</code> |
| L2202 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 create_jwt_token。 | <code>    }</code> |
| L2203 | 计算并保存 &#96;signing_input&#96;（signinginput），供后续逻辑使用，当前位于函数 create_jwt_token。 | <code>    signing_input = _jwt_signing_input(JWT_HEADER, payload)</code> |
| L2204 | 结束当前函数并把结果返回给调用方，当前位于函数 create_jwt_token。 | <code>    return f"{signing_input}.{_jwt_sign(signing_input, secret)}"</code> |
| L2205 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2206 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2207 | 定义decodejwttoken函数 &#96;decode_jwt_token&#96;，封装可复用业务逻辑。 | <code>def decode_jwt_token(token: str, secret: str) -&gt; Tuple[Optional[Dict[str, Any]], str]:</code> |
| L2208 | 计算并保存 &#96;parts&#96;（parts），供后续逻辑使用，当前位于函数 decode_jwt_token。 | <code>    parts = token.split(".")</code> |
| L2209 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_jwt_token。 | <code>    if len(parts) != 3:</code> |
| L2210 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_jwt_token。 | <code>        return None, "token_malformed"</code> |
| L2211 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decode_jwt_token。 | <code>    header_seg, payload_seg, sign_seg = parts</code> |
| L2212 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 decode_jwt_token。 | <code>    try:</code> |
| L2213 | 计算并保存 &#96;header&#96;（header），供后续逻辑使用，当前位于函数 decode_jwt_token。 | <code>        header = json.loads(_b64url_decode(header_seg).decode("utf-8"))</code> |
| L2214 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 decode_jwt_token。 | <code>        payload = json.loads(_b64url_decode(payload_seg).decode("utf-8"))</code> |
| L2215 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 decode_jwt_token。 | <code>    except Exception:</code> |
| L2216 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_jwt_token。 | <code>        return None, "token_malformed"</code> |
| L2217 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_jwt_token。 | <code>    if not isinstance(header, dict) or not isinstance(payload, dict):</code> |
| L2218 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_jwt_token。 | <code>        return None, "token_malformed"</code> |
| L2219 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_jwt_token。 | <code>    if str(header.get("alg") or "") != JWT_ALGORITHM:</code> |
| L2220 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_jwt_token。 | <code>        return None, "unsupported_alg"</code> |
| L2221 | 计算并保存 &#96;expected_sign&#96;（expectedsign），供后续逻辑使用，当前位于函数 decode_jwt_token。 | <code>    expected_sign = _jwt_sign(f"{header_seg}.{payload_seg}", secret)</code> |
| L2222 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_jwt_token。 | <code>    if not hmac.compare_digest(expected_sign, sign_seg):</code> |
| L2223 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_jwt_token。 | <code>        return None, "bad_signature"</code> |
| L2224 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 decode_jwt_token。 | <code>    try:</code> |
| L2225 | 计算并保存 &#96;exp_ts&#96;（expts），供后续逻辑使用，当前位于函数 decode_jwt_token。 | <code>        exp_ts = int(payload.get("exp") or 0)</code> |
| L2226 | 计算并保存 &#96;iat_ts&#96;（iatts），供后续逻辑使用，当前位于函数 decode_jwt_token。 | <code>        iat_ts = int(payload.get("iat") or 0)</code> |
| L2227 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 decode_jwt_token。 | <code>    except Exception:</code> |
| L2228 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_jwt_token。 | <code>        return None, "invalid_claims"</code> |
| L2229 | 计算并保存 &#96;now_ts&#96;（nowts），供后续逻辑使用，当前位于函数 decode_jwt_token。 | <code>    now_ts = int(now_dt().timestamp())</code> |
| L2230 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_jwt_token。 | <code>    if exp_ts &lt;= now_ts:</code> |
| L2231 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_jwt_token。 | <code>        return None, "token_expired"</code> |
| L2232 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_jwt_token。 | <code>    if iat_ts &gt; now_ts + 300:</code> |
| L2233 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_jwt_token。 | <code>        return None, "token_not_yet_valid"</code> |
| L2234 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_jwt_token。 | <code>    if not str(payload.get("sub") or "") or not str(payload.get("role") or ""):</code> |
| L2235 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_jwt_token。 | <code>        return None, "invalid_claims"</code> |
| L2236 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_jwt_token。 | <code>    return payload, ""</code> |
| L2237 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2238 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2239 | 定义读取jwtexpunverified函数 &#96;read_jwt_exp_unverified&#96;，封装可复用业务逻辑。 | <code>def read_jwt_exp_unverified(token: str) -&gt; Optional[int]:</code> |
| L2240 | 计算并保存 &#96;parts&#96;（parts），供后续逻辑使用，当前位于函数 read_jwt_exp_unverified。 | <code>    parts = str(token or "").split(".")</code> |
| L2241 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_jwt_exp_unverified。 | <code>    if len(parts) != 3:</code> |
| L2242 | 结束当前函数并把结果返回给调用方，当前位于函数 read_jwt_exp_unverified。 | <code>        return None</code> |
| L2243 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 read_jwt_exp_unverified。 | <code>    try:</code> |
| L2244 | 计算并保存 &#96;payload_raw&#96;（payloadraw），供后续逻辑使用，当前位于函数 read_jwt_exp_unverified。 | <code>        payload_raw = _b64url_decode(parts[1]).decode("utf-8")</code> |
| L2245 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 read_jwt_exp_unverified。 | <code>        payload = json.loads(payload_raw)</code> |
| L2246 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_jwt_exp_unverified。 | <code>        if not isinstance(payload, dict):</code> |
| L2247 | 结束当前函数并把结果返回给调用方，当前位于函数 read_jwt_exp_unverified。 | <code>            return None</code> |
| L2248 | 计算并保存 &#96;exp_ts&#96;（expts），供后续逻辑使用，当前位于函数 read_jwt_exp_unverified。 | <code>        exp_ts = payload.get("exp")</code> |
| L2249 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_jwt_exp_unverified。 | <code>        if exp_ts is None:</code> |
| L2250 | 结束当前函数并把结果返回给调用方，当前位于函数 read_jwt_exp_unverified。 | <code>            return None</code> |
| L2251 | 结束当前函数并把结果返回给调用方，当前位于函数 read_jwt_exp_unverified。 | <code>        return int(exp_ts)</code> |
| L2252 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 read_jwt_exp_unverified。 | <code>    except Exception:</code> |
| L2253 | 结束当前函数并把结果返回给调用方，当前位于函数 read_jwt_exp_unverified。 | <code>        return None</code> |
| L2254 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2255 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2256 | 定义prunerevokedjtis函数 &#96;prune_revoked_jtis&#96;，封装可复用业务逻辑。 | <code>def prune_revoked_jtis() -&gt; None:</code> |
| L2257 | 计算并保存 &#96;now_ts&#96;（nowts），供后续逻辑使用，当前位于函数 prune_revoked_jtis。 | <code>    now_ts = int(now_dt().timestamp())</code> |
| L2258 | 计算并保存 &#96;expired&#96;（expired），供后续逻辑使用，当前位于函数 prune_revoked_jtis。 | <code>    expired = [k for k, exp in JWT_REVOKED_JTIS.items() if exp &lt;= now_ts]</code> |
| L2259 | 遍历集合中的数据项并逐项处理，当前位于函数 prune_revoked_jtis。 | <code>    for key in expired:</code> |
| L2260 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 prune_revoked_jtis。 | <code>        JWT_REVOKED_JTIS.pop(key, None)</code> |
| L2261 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2262 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2263 | 定义revokejwt函数 &#96;revoke_jwt&#96;，封装可复用业务逻辑。 | <code>def revoke_jwt(payload: Dict[str, Any]) -&gt; None:</code> |
| L2264 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 revoke_jwt。 | <code>    try:</code> |
| L2265 | 计算并保存 &#96;exp_ts&#96;（expts），供后续逻辑使用，当前位于函数 revoke_jwt。 | <code>        exp_ts = int(payload.get("exp") or 0)</code> |
| L2266 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 revoke_jwt。 | <code>    except Exception:</code> |
| L2267 | 计算并保存 &#96;exp_ts&#96;（expts），供后续逻辑使用，当前位于函数 revoke_jwt。 | <code>        exp_ts = 0</code> |
| L2268 | 计算并保存 &#96;jti&#96;（jti），供后续逻辑使用，当前位于函数 revoke_jwt。 | <code>    jti = str(payload.get("jti") or "").strip()</code> |
| L2269 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 revoke_jwt。 | <code>    if jti and exp_ts &gt; 0:</code> |
| L2270 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 revoke_jwt。 | <code>        JWT_REVOKED_JTIS[jti] = exp_ts</code> |
| L2271 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2272 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2273 | 定义isjwtrevoked函数 &#96;is_jwt_revoked&#96;，封装可复用业务逻辑。 | <code>def is_jwt_revoked(payload: Dict[str, Any]) -&gt; bool:</code> |
| L2274 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 is_jwt_revoked。 | <code>    prune_revoked_jtis()</code> |
| L2275 | 计算并保存 &#96;jti&#96;（jti），供后续逻辑使用，当前位于函数 is_jwt_revoked。 | <code>    jti = str(payload.get("jti") or "").strip()</code> |
| L2276 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_jwt_revoked。 | <code>    if not jti:</code> |
| L2277 | 结束当前函数并把结果返回给调用方，当前位于函数 is_jwt_revoked。 | <code>        return False</code> |
| L2278 | 结束当前函数并把结果返回给调用方，当前位于函数 is_jwt_revoked。 | <code>    return jti in JWT_REVOKED_JTIS</code> |
| L2279 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2280 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2281 | 定义构建sessionfromclaims函数 &#96;build_session_from_claims&#96;，封装可复用业务逻辑。 | <code>def build_session_from_claims(payload: Dict[str, Any]) -&gt; Dict[str, Any]:</code> |
| L2282 | 计算并保存 &#96;exp_ts&#96;（expts），供后续逻辑使用，当前位于函数 build_session_from_claims。 | <code>    exp_ts = int(payload.get("exp") or 0)</code> |
| L2283 | 计算并保存 &#96;expires_at&#96;（expiresat），供后续逻辑使用，当前位于函数 build_session_from_claims。 | <code>    expires_at = datetime.fromtimestamp(exp_ts) if exp_ts &gt; 0 else now_dt()</code> |
| L2284 | 结束当前函数并把结果返回给调用方，当前位于函数 build_session_from_claims。 | <code>    return {</code> |
| L2285 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_session_from_claims。 | <code>        "username": str(payload.get("sub") or ""),</code> |
| L2286 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_session_from_claims。 | <code>        "role": str(payload.get("role") or ""),</code> |
| L2287 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_session_from_claims。 | <code>        "display_name": str(payload.get("display_name") or ""),</code> |
| L2288 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_session_from_claims。 | <code>        "nickname": str(payload.get("nickname") or payload.get("display_name") or ""),</code> |
| L2289 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_session_from_claims。 | <code>        "avatar_url": normalize_avatar_url(payload.get("avatar_url") or ""),</code> |
| L2290 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_session_from_claims。 | <code>        "expires_at": expires_at,</code> |
| L2291 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_session_from_claims。 | <code>    }</code> |
| L2292 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2293 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2294 | 定义isvalidusername函数 &#96;is_valid_username&#96;，封装可复用业务逻辑。 | <code>def is_valid_username(username: str) -&gt; bool:</code> |
| L2295 | 结束当前函数并把结果返回给调用方，当前位于函数 is_valid_username。 | <code>    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,32}", username))</code> |
| L2296 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2297 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2298 | 定义标准化profiletext函数 &#96;normalize_profile_text&#96;，封装可复用业务逻辑。 | <code>def normalize_profile_text(value: Any, fallback: str = "", max_len: int = 64) -&gt; str:</code> |
| L2299 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 normalize_profile_text。 | <code>    text = re.sub(r"\s+", " ", str(value or "").strip())</code> |
| L2300 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_profile_text。 | <code>    if not text:</code> |
| L2301 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 normalize_profile_text。 | <code>        text = fallback</code> |
| L2302 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_profile_text。 | <code>    return text[:max_len]</code> |
| L2303 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2304 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2305 | 定义标准化avatarurl函数 &#96;normalize_avatar_url&#96;，封装可复用业务逻辑。 | <code>def normalize_avatar_url(value: Any) -&gt; str:</code> |
| L2306 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 normalize_avatar_url。 | <code>    text = str(value or "").strip()</code> |
| L2307 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_avatar_url。 | <code>    if not text:</code> |
| L2308 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_avatar_url。 | <code>        return ""</code> |
| L2309 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_avatar_url。 | <code>    if len(text) &gt; 512 or any(x in text for x in ['"', "'", "\\", "\r", "\n"]):</code> |
| L2310 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_avatar_url。 | <code>        return ""</code> |
| L2311 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_avatar_url。 | <code>    if text.startswith("/uploads/avatars/"):</code> |
| L2312 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_avatar_url。 | <code>        return text</code> |
| L2313 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_avatar_url。 | <code>    if text.startswith("https://") or text.startswith("http://"):</code> |
| L2314 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_avatar_url。 | <code>        return text</code> |
| L2315 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_avatar_url。 | <code>    return ""</code> |
| L2316 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2317 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2318 | 定义profilepublicfields函数 &#96;profile_public_fields&#96;，封装可复用业务逻辑。 | <code>def profile_public_fields(row: Dict[str, Any]) -&gt; Dict[str, Any]:</code> |
| L2319 | 计算并保存 &#96;display_name&#96;（displayname），供后续逻辑使用，当前位于函数 profile_public_fields。 | <code>    display_name = str(row.get("display_name") or row.get("username") or "")</code> |
| L2320 | 计算并保存 &#96;nickname&#96;（nickname），供后续逻辑使用，当前位于函数 profile_public_fields。 | <code>    nickname = str(row.get("nickname") or display_name)</code> |
| L2321 | 计算并保存 &#96;avatar_url&#96;（avatarurl），供后续逻辑使用，当前位于函数 profile_public_fields。 | <code>    avatar_url = normalize_avatar_url(row.get("avatar_url") or "")</code> |
| L2322 | 结束当前函数并把结果返回给调用方，当前位于函数 profile_public_fields。 | <code>    return {</code> |
| L2323 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 profile_public_fields。 | <code>        "id": row.get("id"),</code> |
| L2324 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 profile_public_fields。 | <code>        "username": str(row.get("username") or ""),</code> |
| L2325 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 profile_public_fields。 | <code>        "role": str(row.get("role") or ""),</code> |
| L2326 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 profile_public_fields。 | <code>        "display_name": display_name,</code> |
| L2327 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 profile_public_fields。 | <code>        "nickname": nickname,</code> |
| L2328 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 profile_public_fields。 | <code>        "avatar_url": avatar_url,</code> |
| L2329 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 profile_public_fields。 | <code>    }</code> |
| L2330 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2331 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2332 | 定义读取authtokenfromrequest函数 &#96;get_auth_token_from_request&#96;，封装可复用业务逻辑。 | <code>def get_auth_token_from_request() -&gt; str:</code> |
| L2333 | 计算并保存 &#96;auth_header&#96;（authheader），供后续逻辑使用，当前位于函数 get_auth_token_from_request。 | <code>    auth_header = request.headers.get("Authorization", "").strip()</code> |
| L2334 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 get_auth_token_from_request。 | <code>    if auth_header.startswith("Bearer "):</code> |
| L2335 | 计算并保存 &#96;token&#96;（token），供后续逻辑使用，当前位于函数 get_auth_token_from_request。 | <code>        token = auth_header.split(" ", 1)[1].strip()</code> |
| L2336 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 get_auth_token_from_request。 | <code>        if token:</code> |
| L2337 | 结束当前函数并把结果返回给调用方，当前位于函数 get_auth_token_from_request。 | <code>            return token</code> |
| L2338 | 计算并保存 &#96;cookie_name&#96;（cookiename），供后续逻辑使用，当前位于函数 get_auth_token_from_request。 | <code>    cookie_name = str(current_app.config.get("AUTH_COOKIE_NAME") or AUTH_COOKIE_NAME).strip() or AUTH_COOKIE_NAME</code> |
| L2339 | 计算并保存 &#96;cookie_token&#96;（cookietoken），供后续逻辑使用，当前位于函数 get_auth_token_from_request。 | <code>    cookie_token = str(request.cookies.get(cookie_name, "")).strip()</code> |
| L2340 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 get_auth_token_from_request。 | <code>    if cookie_token:</code> |
| L2341 | 结束当前函数并把结果返回给调用方，当前位于函数 get_auth_token_from_request。 | <code>        return cookie_token</code> |
| L2342 | 结束当前函数并把结果返回给调用方，当前位于函数 get_auth_token_from_request。 | <code>    return ""</code> |
| L2343 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2344 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2345 | 定义setauthcookie函数 &#96;set_auth_cookie&#96;，封装可复用业务逻辑。 | <code>def set_auth_cookie(resp: Response, token: str) -&gt; Response:</code> |
| L2346 | 计算并保存 &#96;cookie_name&#96;（cookiename），供后续逻辑使用，当前位于函数 set_auth_cookie。 | <code>    cookie_name = str(current_app.config.get("AUTH_COOKIE_NAME") or AUTH_COOKIE_NAME).strip() or AUTH_COOKIE_NAME</code> |
| L2347 | 计算并保存 &#96;cookie_secure&#96;（cookiesecure），供后续逻辑使用，当前位于函数 set_auth_cookie。 | <code>    cookie_secure = bool(current_app.config.get("AUTH_COOKIE_SECURE", False))</code> |
| L2348 | 计算并保存 &#96;cookie_domain&#96;（cookiedomain），供后续逻辑使用，当前位于函数 set_auth_cookie。 | <code>    cookie_domain = str(current_app.config.get("AUTH_COOKIE_DOMAIN") or "").strip() or None</code> |
| L2349 | 计算并保存 &#96;max_age&#96;（maxage），供后续逻辑使用，当前位于函数 set_auth_cookie。 | <code>    max_age = int(current_app.config.get("JWT_TTL_SECONDS") or TOKEN_TTL_SECONDS)</code> |
| L2350 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 set_auth_cookie。 | <code>    resp.set_cookie(</code> |
| L2351 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 set_auth_cookie。 | <code>        cookie_name,</code> |
| L2352 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 set_auth_cookie。 | <code>        token,</code> |
| L2353 | 计算并保存 &#96;max_age&#96;（maxage），供后续逻辑使用，当前位于函数 set_auth_cookie。 | <code>        max_age=max_age,</code> |
| L2354 | 计算并保存 &#96;httponly&#96;（httponly），供后续逻辑使用，当前位于函数 set_auth_cookie。 | <code>        httponly=True,</code> |
| L2355 | 计算并保存 &#96;secure&#96;（secure），供后续逻辑使用，当前位于函数 set_auth_cookie。 | <code>        secure=cookie_secure,</code> |
| L2356 | 计算并保存 &#96;samesite&#96;（samesite），供后续逻辑使用，当前位于函数 set_auth_cookie。 | <code>        samesite="Lax",</code> |
| L2357 | 计算并保存 &#96;path&#96;（path），供后续逻辑使用，当前位于函数 set_auth_cookie。 | <code>        path="/",</code> |
| L2358 | 计算并保存 &#96;domain&#96;（domain），供后续逻辑使用，当前位于函数 set_auth_cookie。 | <code>        domain=cookie_domain,</code> |
| L2359 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 set_auth_cookie。 | <code>    )</code> |
| L2360 | 结束当前函数并把结果返回给调用方，当前位于函数 set_auth_cookie。 | <code>    return resp</code> |
| L2361 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2362 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2363 | 定义clearauthcookie函数 &#96;clear_auth_cookie&#96;，封装可复用业务逻辑。 | <code>def clear_auth_cookie(resp: Response) -&gt; Response:</code> |
| L2364 | 计算并保存 &#96;cookie_name&#96;（cookiename），供后续逻辑使用，当前位于函数 clear_auth_cookie。 | <code>    cookie_name = str(current_app.config.get("AUTH_COOKIE_NAME") or AUTH_COOKIE_NAME).strip() or AUTH_COOKIE_NAME</code> |
| L2365 | 计算并保存 &#96;cookie_secure&#96;（cookiesecure），供后续逻辑使用，当前位于函数 clear_auth_cookie。 | <code>    cookie_secure = bool(current_app.config.get("AUTH_COOKIE_SECURE", False))</code> |
| L2366 | 计算并保存 &#96;cookie_domain&#96;（cookiedomain），供后续逻辑使用，当前位于函数 clear_auth_cookie。 | <code>    cookie_domain = str(current_app.config.get("AUTH_COOKIE_DOMAIN") or "").strip() or None</code> |
| L2367 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 clear_auth_cookie。 | <code>    resp.set_cookie(</code> |
| L2368 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 clear_auth_cookie。 | <code>        cookie_name,</code> |
| L2369 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 clear_auth_cookie。 | <code>        "",</code> |
| L2370 | 计算并保存 &#96;max_age&#96;（maxage），供后续逻辑使用，当前位于函数 clear_auth_cookie。 | <code>        max_age=0,</code> |
| L2371 | 计算并保存 &#96;expires&#96;（expires），供后续逻辑使用，当前位于函数 clear_auth_cookie。 | <code>        expires=0,</code> |
| L2372 | 计算并保存 &#96;httponly&#96;（httponly），供后续逻辑使用，当前位于函数 clear_auth_cookie。 | <code>        httponly=True,</code> |
| L2373 | 计算并保存 &#96;secure&#96;（secure），供后续逻辑使用，当前位于函数 clear_auth_cookie。 | <code>        secure=cookie_secure,</code> |
| L2374 | 计算并保存 &#96;samesite&#96;（samesite），供后续逻辑使用，当前位于函数 clear_auth_cookie。 | <code>        samesite="Lax",</code> |
| L2375 | 计算并保存 &#96;path&#96;（path），供后续逻辑使用，当前位于函数 clear_auth_cookie。 | <code>        path="/",</code> |
| L2376 | 计算并保存 &#96;domain&#96;（domain），供后续逻辑使用，当前位于函数 clear_auth_cookie。 | <code>        domain=cookie_domain,</code> |
| L2377 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 clear_auth_cookie。 | <code>    )</code> |
| L2378 | 结束当前函数并把结果返回给调用方，当前位于函数 clear_auth_cookie。 | <code>    return resp</code> |
| L2379 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2380 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2381 | 定义requireroles函数 &#96;require_roles&#96;，封装可复用业务逻辑。 | <code>def require_roles(*roles: str):</code> |
| L2382 | 定义decorator函数 &#96;decorator&#96;，封装可复用业务逻辑。 | <code>    def decorator(func):</code> |
| L2383 | 应用装饰器 &#96;@wraps(func)&#96;，为下一定义附加权限、缓存或注册行为。 | <code>        @wraps(func)</code> |
| L2384 | 定义wrapper函数 &#96;wrapper&#96;，封装可复用业务逻辑。 | <code>        def wrapper(*args, **kwargs):</code> |
| L2385 | 计算并保存 &#96;token&#96;（token），供后续逻辑使用，当前位于函数 wrapper。 | <code>            token = get_auth_token_from_request()</code> |
| L2386 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 wrapper。 | <code>            if not token:</code> |
| L2387 | 结束当前函数并把结果返回给调用方，当前位于函数 wrapper。 | <code>                return jsonify({"error": "unauthorized", "message": "Missing auth token"}), 401</code> |
| L2388 | 计算并保存 &#96;jwt_secret&#96;（jwtsecret），供后续逻辑使用，当前位于函数 wrapper。 | <code>            jwt_secret = str(current_app.config.get("JWT_SECRET") or "").strip()</code> |
| L2389 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 wrapper。 | <code>            if not jwt_secret:</code> |
| L2390 | 结束当前函数并把结果返回给调用方，当前位于函数 wrapper。 | <code>                return jsonify({"error": "server_error", "message": "JWT secret not configured"}), 500</code> |
| L2391 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 wrapper。 | <code>            claims, err = decode_jwt_token(token, jwt_secret)</code> |
| L2392 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 wrapper。 | <code>            if not claims:</code> |
| L2393 | 结束当前函数并把结果返回给调用方，当前位于函数 wrapper。 | <code>                return jsonify({"error": "unauthorized", "message": err or "Invalid token"}), 401</code> |
| L2394 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 wrapper。 | <code>            if is_jwt_revoked(claims):</code> |
| L2395 | 结束当前函数并把结果返回给调用方，当前位于函数 wrapper。 | <code>                return jsonify({"error": "unauthorized", "message": "Token revoked"}), 401</code> |
| L2396 | 计算并保存 &#96;session&#96;（session），供后续逻辑使用，当前位于函数 wrapper。 | <code>            session = build_session_from_claims(claims)</code> |
| L2397 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 wrapper。 | <code>            if roles and session["role"] not in set(roles):</code> |
| L2398 | 结束当前函数并把结果返回给调用方，当前位于函数 wrapper。 | <code>                return jsonify({"error": "forbidden", "message": "Role not allowed"}), 403</code> |
| L2399 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 wrapper。 | <code>            g.session = session</code> |
| L2400 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 wrapper。 | <code>            g.token_claims = claims</code> |
| L2401 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 wrapper。 | <code>            g.token = token</code> |
| L2402 | 结束当前函数并把结果返回给调用方，当前位于函数 wrapper。 | <code>            return func(*args, **kwargs)</code> |
| L2403 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2404 | 结束当前函数并把结果返回给调用方，当前位于函数 decorator。 | <code>        return wrapper</code> |
| L2405 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2406 | 结束当前函数并把结果返回给调用方，当前位于函数 require_roles。 | <code>    return decorator</code> |
| L2407 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2408 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2409 | 定义构建timerange函数 &#96;build_time_range&#96;，封装可复用业务逻辑。 | <code>def build_time_range() -&gt; Tuple[datetime, datetime]:</code> |
| L2410 | 计算并保存 &#96;now&#96;（now），供后续逻辑使用，当前位于函数 build_time_range。 | <code>    now = now_dt()</code> |
| L2411 | 计算并保存 &#96;time_range&#96;（timerange），供后续逻辑使用，当前位于函数 build_time_range。 | <code>    time_range = request.args.get("time_range", "24h").strip().lower()</code> |
| L2412 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_time_range。 | <code>    if time_range == "1h":</code> |
| L2413 | 结束当前函数并把结果返回给调用方，当前位于函数 build_time_range。 | <code>        return now - timedelta(hours=1), now</code> |
| L2414 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_time_range。 | <code>    if time_range == "6h":</code> |
| L2415 | 结束当前函数并把结果返回给调用方，当前位于函数 build_time_range。 | <code>        return now - timedelta(hours=6), now</code> |
| L2416 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_time_range。 | <code>    if time_range == "24h":</code> |
| L2417 | 结束当前函数并把结果返回给调用方，当前位于函数 build_time_range。 | <code>        return now - timedelta(hours=24), now</code> |
| L2418 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_time_range。 | <code>    if time_range == "7d":</code> |
| L2419 | 结束当前函数并把结果返回给调用方，当前位于函数 build_time_range。 | <code>        return now - timedelta(days=7), now</code> |
| L2420 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_time_range。 | <code>    if time_range == "30d":</code> |
| L2421 | 结束当前函数并把结果返回给调用方，当前位于函数 build_time_range。 | <code>        return now - timedelta(days=30), now</code> |
| L2422 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_time_range。 | <code>    if time_range == "custom":</code> |
| L2423 | 计算并保存 &#96;start_text&#96;（启动text），供后续逻辑使用，当前位于函数 build_time_range。 | <code>        start_text = request.args.get("start_time", "").strip()</code> |
| L2424 | 计算并保存 &#96;end_text&#96;（endtext），供后续逻辑使用，当前位于函数 build_time_range。 | <code>        end_text = request.args.get("end_time", "").strip()</code> |
| L2425 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_time_range。 | <code>        if not start_text or not end_text:</code> |
| L2426 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 build_time_range。 | <code>            raise ValueError("custom range requires start_time and end_time")</code> |
| L2427 | 计算并保存 &#96;start_dt&#96;（启动dt），供后续逻辑使用，当前位于函数 build_time_range。 | <code>        start_dt = datetime.fromisoformat(start_text.replace("Z", "+00:00")).replace(tzinfo=None)</code> |
| L2428 | 计算并保存 &#96;end_dt&#96;（enddt），供后续逻辑使用，当前位于函数 build_time_range。 | <code>        end_dt = datetime.fromisoformat(end_text.replace("Z", "+00:00")).replace(tzinfo=None)</code> |
| L2429 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_time_range。 | <code>        if start_dt &gt;= end_dt:</code> |
| L2430 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 build_time_range。 | <code>            raise ValueError("start_time must be earlier than end_time")</code> |
| L2431 | 结束当前函数并把结果返回给调用方，当前位于函数 build_time_range。 | <code>        return start_dt, end_dt</code> |
| L2432 | 结束当前函数并把结果返回给调用方，当前位于函数 build_time_range。 | <code>    return now - timedelta(hours=24), now</code> |
| L2433 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2434 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2435 | 定义创建app函数 &#96;create_app&#96;，封装可复用业务逻辑。 | <code>def create_app(</code> |
| L2436 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    mysql_conf: Dict[str, Any],</code> |
| L2437 | 计算并保存 &#96;seed_demo&#96;（seeddemo），供后续逻辑使用，当前位于函数 create_app。 | <code>    seed_demo: bool = True,</code> |
| L2438 | 计算并保存 &#96;force_seed&#96;（forceseed），供后续逻辑使用，当前位于函数 create_app。 | <code>    force_seed: bool = False,</code> |
| L2439 | 计算并保存 &#96;rag_db_path&#96;（rag数据库path），供后续逻辑使用，当前位于函数 create_app。 | <code>    rag_db_path: str = "llm/rag/rag_knowledge.db",</code> |
| L2440 | 计算并保存 &#96;rag_seed_path&#96;（ragseedpath），供后续逻辑使用，当前位于函数 create_app。 | <code>    rag_seed_path: str = "llm/rag/rag_seed.json",</code> |
| L2441 | 计算并保存 &#96;rag_force_seed&#96;（ragforceseed），供后续逻辑使用，当前位于函数 create_app。 | <code>    rag_force_seed: bool = False,</code> |
| L2442 | 计算并保存 &#96;jwt_secret&#96;（jwtsecret），供后续逻辑使用，当前位于函数 create_app。 | <code>    jwt_secret: str = "",</code> |
| L2443 | 计算并保存 &#96;jwt_ttl_seconds&#96;（jwtttlseconds），供后续逻辑使用，当前位于函数 create_app。 | <code>    jwt_ttl_seconds: int = TOKEN_TTL_SECONDS,</code> |
| L2444 | 计算并保存 &#96;ollama_url&#96;（ollamaurl），供后续逻辑使用，当前位于函数 create_app。 | <code>    ollama_url: str = "http://127.0.0.1:11434",</code> |
| L2445 | 计算并保存 &#96;llm_prompt_path&#96;（llmpromptpath），供后续逻辑使用，当前位于函数 create_app。 | <code>    llm_prompt_path: str = "llm/prompts/system_prompt.txt",</code> |
| L2446 | 计算并保存 &#96;professional_report_prompt_path&#96;（professional报告promptpath），供后续逻辑使用，当前位于函数 create_app。 | <code>    professional_report_prompt_path: str = "llm/prompts/professional_situation_report_prompt.txt",</code> |
| L2447 | 计算并保存 &#96;rag_data_dir&#96;（ragdatadir），供后续逻辑使用，当前位于函数 create_app。 | <code>    rag_data_dir: str = "",</code> |
| L2448 | 计算并保存 &#96;rag_api_config&#96;（rag接口配置），供后续逻辑使用，当前位于函数 create_app。 | <code>    rag_api_config: str = "config/ai_api.local.json",</code> |
| L2449 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 create_app。 | <code>) -&gt; Flask:</code> |
| L2450 | 计算并保存 &#96;app&#96;（app），供后续逻辑使用，当前位于函数 create_app。 | <code>    app = Flask(__name__)</code> |
| L2451 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    app.url_map.strict_slashes = False</code> |
| L2452 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    app.config["MYSQL_CONF"] = mysql_conf</code> |
| L2453 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    app.config["RAG_DB_PATH"] = str(Path(rag_db_path).resolve())</code> |
| L2454 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    app.config["RAG_SEED_PATH"] = str(Path(rag_seed_path).resolve())</code> |
| L2455 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    app.config["OLLAMA_URL"] = normalize_ollama_url(ollama_url)</code> |
| L2456 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    app.config["LLM_PROMPT_PATH"] = str(resolve_project_path(llm_prompt_path, DEFAULT_LLM_PROMPT_PATH))</code> |
| L2457 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    app.config["PROFESSIONAL_REPORT_PROMPT_PATH"] = str(resolve_project_path(professional_report_prompt_path, DEFAULT_PROFESSIONAL_REPORT_PROMPT_PATH))</code> |
| L2458 | 计算并保存 &#96;default_rag_data&#96;（defaultragdata），供后续逻辑使用，当前位于函数 create_app。 | <code>    default_rag_data = Path(os.environ.get("RAG_DATA_DIR") or rag_data_dir or (PROJECT_ROOT / "llm" / "rag" / "runtime"))</code> |
| L2459 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    app.config["RAG_DATA_DIR"] = str(default_rag_data.resolve())</code> |
| L2460 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    app.config["RAG_API_CONFIG_PATH"] = str(resolve_project_path(rag_api_config, PROJECT_ROOT / "config" / "ai_api.local.json"))</code> |
| L2461 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    app.config["AUTH_COOKIE_NAME"] = os.environ.get("TP_AUTH_COOKIE_NAME", AUTH_COOKIE_NAME)</code> |
| L2462 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    app.config["AUTH_COOKIE_SECURE"] = str(os.environ.get("TP_AUTH_COOKIE_SECURE", "0")).strip().lower() in {</code> |
| L2463 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>        "1",</code> |
| L2464 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>        "true",</code> |
| L2465 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>        "yes",</code> |
| L2466 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>        "on",</code> |
| L2467 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 create_app。 | <code>    }</code> |
| L2468 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    app.config["AUTH_COOKIE_DOMAIN"] = os.environ.get("TP_AUTH_COOKIE_DOMAIN", "")</code> |
| L2469 | 计算并保存 &#96;final_jwt_secret&#96;（finaljwtsecret），供后续逻辑使用，当前位于函数 create_app。 | <code>    final_jwt_secret = (jwt_secret or os.environ.get("TP_JWT_SECRET", "")).strip()</code> |
| L2470 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 create_app。 | <code>    if not final_jwt_secret:</code> |
| L2471 | 计算并保存 &#96;final_jwt_secret&#96;（finaljwtsecret），供后续逻辑使用，当前位于函数 create_app。 | <code>        final_jwt_secret = load_or_create_jwt_secret()</code> |
| L2472 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 create_app。 | <code>        print(f"[info] JWT secret loaded from {display_project_path(DEFAULT_JWT_SECRET_PATH)}")</code> |
| L2473 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    app.config["JWT_SECRET"] = final_jwt_secret</code> |
| L2474 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    app.config["JWT_TTL_SECONDS"] = max(300, int(jwt_ttl_seconds))</code> |
| L2475 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2476 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 create_app。 | <code>    with closing(get_conn(mysql_conf, autocommit=False)) as conn:</code> |
| L2477 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>        ensure_schema(conn)</code> |
| L2478 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>        ensure_review_schema(conn)</code> |
| L2479 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>        rag2_ensure_schema(conn)</code> |
| L2480 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>        rag2_ensure_default_kb(conn)</code> |
| L2481 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>        MySQLSituationStore(MySQLSettings(**mysql_conf), connection=conn).ensure_schema()</code> |
| L2482 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>        ensure_professional_report_schema(conn)</code> |
| L2483 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>        ensure_builtin_admin(conn)</code> |
| L2484 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 create_app。 | <code>        if seed_demo:</code> |
| L2485 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>            seed_demo_data(conn, force_seed=force_seed)</code> |
| L2486 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>        conn.commit()</code> |
| L2487 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2488 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    Path(app.config["RAG_DATA_DIR"]).mkdir(parents=True, exist_ok=True)</code> |
| L2489 | 计算并保存 &#96;preferred_report_root&#96;（preferred报告root），供后续逻辑使用，当前位于函数 create_app。 | <code>    preferred_report_root = Path(os.environ.get("SITUATION_REPORT_DIR") or "D:/JingyuanTrafficPipelineData/reports")</code> |
| L2490 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 create_app。 | <code>    if not preferred_report_root.drive or not Path(f"{preferred_report_root.drive}/").exists():</code> |
| L2491 | 计算并保存 &#96;preferred_report_root&#96;（preferred报告root），供后续逻辑使用，当前位于函数 create_app。 | <code>        preferred_report_root = PROJECT_ROOT / "output" / "professional_reports"</code> |
| L2492 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    preferred_report_root.mkdir(parents=True, exist_ok=True)</code> |
| L2493 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    app.config["PROFESSIONAL_REPORT_DIR"] = str(preferred_report_root.resolve())</code> |
| L2494 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    app.config["PROFESSIONAL_REPORT_MANAGER"] = ProfessionalReportManager(</code> |
| L2495 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>        mysql_conf,</code> |
| L2496 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>        preferred_report_root.resolve(),</code> |
| L2497 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>        Path(app.config["PROFESSIONAL_REPORT_PROMPT_PATH"]),</code> |
| L2498 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>        Path(app.config["RAG_DATA_DIR"]),</code> |
| L2499 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>        Path(app.config["RAG_API_CONFIG_PATH"]),</code> |
| L2500 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 create_app。 | <code>    )</code> |
| L2501 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 create_app。 | <code>    with closing(get_conn(mysql_conf, autocommit=False)) as conn:</code> |
| L2502 | 计算并保存 &#96;migration&#96;（migration），供后续逻辑使用，当前位于函数 create_app。 | <code>        migration = rag2_migrate_legacy_sqlite(conn, Path(app.config["RAG_DB_PATH"]))</code> |
| L2503 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 create_app。 | <code>        if migration.get("document_id"):</code> |
| L2504 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 create_app。 | <code>            print(f"[info] legacy RAG metadata migrated: {migration}")</code> |
| L2505 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2506 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>    ensure_rag_schema(app.config["RAG_DB_PATH"])</code> |
| L2507 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 create_app。 | <code>    if rag_force_seed:</code> |
| L2508 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>        rag_rebuild_from_seed(app.config["RAG_DB_PATH"], app.config["RAG_SEED_PATH"])</code> |
| L2509 | 当前一条件未命中时继续判断另一条件，当前位于函数 create_app。 | <code>    elif seed_demo:</code> |
| L2510 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 create_app。 | <code>        with closing(get_rag_conn(app.config["RAG_DB_PATH"])) as rag_conn:</code> |
| L2511 | 计算并保存 &#96;cur&#96;（cur），供后续逻辑使用，当前位于函数 create_app。 | <code>            cur = rag_conn.cursor()</code> |
| L2512 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 create_app。 | <code>            cur.execute("SELECT COUNT(*) AS c FROM rag_docs")</code> |
| L2513 | 计算并保存 &#96;count&#96;（count），供后续逻辑使用，当前位于函数 create_app。 | <code>            count = int((cur.fetchone() or {"c": 0})["c"])</code> |
| L2514 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 create_app。 | <code>        if count == 0:</code> |
| L2515 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_app。 | <code>            rag_rebuild_from_seed(app.config["RAG_DB_PATH"], app.config["RAG_SEED_PATH"])</code> |
| L2516 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2517 | 应用装饰器 &#96;@app.after_request&#96;，为下一定义附加权限、缓存或注册行为。 | <code>    @app.after_request</code> |
| L2518 | 定义addcorsheaders函数 &#96;add_cors_headers&#96;，封装可复用业务逻辑。 | <code>    def add_cors_headers(resp):</code> |
| L2519 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 add_cors_headers。 | <code>        resp.headers["Access-Control-Allow-Origin"] = "*"</code> |
| L2520 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 add_cors_headers。 | <code>        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"</code> |
| L2521 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 add_cors_headers。 | <code>        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, OPTIONS"</code> |
| L2522 | 结束当前函数并把结果返回给调用方，当前位于函数 add_cors_headers。 | <code>        return resp</code> |
| L2523 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2524 | 注册 Flask HTTP 接口 "/api/v1/screen/ping", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v1/screen/ping", methods=["GET"])</code> |
| L2525 | 定义ping函数 &#96;ping&#96;，封装可复用业务逻辑。 | <code>    def ping():</code> |
| L2526 | 结束当前函数并把结果返回给调用方，当前位于函数 ping。 | <code>        return jsonify({"ok": True})</code> |
| L2527 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2528 | 注册 Flask HTTP 接口 "/api/v2/auth/demo-accounts", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/auth/demo-accounts", methods=["GET"])</code> |
| L2529 | 定义demoaccounts函数 &#96;demo_accounts&#96;，封装可复用业务逻辑。 | <code>    def demo_accounts():</code> |
| L2530 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 demo_accounts。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L2531 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 demo_accounts。 | <code>            rows = list_demo_accounts(conn)</code> |
| L2532 | 结束当前函数并把结果返回给调用方，当前位于函数 demo_accounts。 | <code>        return jsonify({"accounts": rows})</code> |
| L2533 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2534 | 注册 Flask HTTP 接口 "/api/v2/auth/register", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/auth/register", methods=["POST"])</code> |
| L2535 | 定义注册函数 &#96;register&#96;，封装可复用业务逻辑。 | <code>    def register():</code> |
| L2536 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 register。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L2537 | 计算并保存 &#96;username&#96;（username），供后续逻辑使用，当前位于函数 register。 | <code>        username = str(body.get("username", "")).strip()</code> |
| L2538 | 控制当前循环或占位分支的执行流程，当前位于函数 register。 | <code>        password = str(body.get("password", "")).strip()</code> |
| L2539 | 计算并保存 &#96;display_name&#96;（displayname），供后续逻辑使用，当前位于函数 register。 | <code>        display_name = str(body.get("display_name", "")).strip()</code> |
| L2540 | 计算并保存 &#96;role_hint&#96;（rolehint），供后续逻辑使用，当前位于函数 register。 | <code>        role_hint = str(body.get("role", "")).strip().lower()</code> |
| L2541 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 register。 | <code>        if role_hint and role_hint != ROLE_NORMAL:</code> |
| L2542 | 结束当前函数并把结果返回给调用方，当前位于函数 register。 | <code>            return jsonify({"error": "only_normal_role_can_register"}), 400</code> |
| L2543 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 register。 | <code>        if not is_valid_username(username):</code> |
| L2544 | 结束当前函数并把结果返回给调用方，当前位于函数 register。 | <code>            return jsonify({"error": "invalid_username", "message": "username must be 3-32 chars: letters/numbers/_"}), 400</code> |
| L2545 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 register。 | <code>        if len(password) &lt; 6:</code> |
| L2546 | 结束当前函数并把结果返回给调用方，当前位于函数 register。 | <code>            return jsonify({"error": "password_too_short", "message": "password length must be &gt;= 6"}), 400</code> |
| L2547 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 register。 | <code>        if len(password) &gt; 128:</code> |
| L2548 | 结束当前函数并把结果返回给调用方，当前位于函数 register。 | <code>            return jsonify({"error": "password_too_long"}), 400</code> |
| L2549 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 register。 | <code>        if not display_name:</code> |
| L2550 | 计算并保存 &#96;display_name&#96;（displayname），供后续逻辑使用，当前位于函数 register。 | <code>            display_name = username</code> |
| L2551 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 register。 | <code>        if len(display_name) &gt; 64:</code> |
| L2552 | 结束当前函数并把结果返回给调用方，当前位于函数 register。 | <code>            return jsonify({"error": "display_name_too_long"}), 400</code> |
| L2553 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2554 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 register。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L2555 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 register。 | <code>            with conn.cursor() as cur:</code> |
| L2556 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 register。 | <code>                cur.execute("SELECT id FROM demo_users WHERE username=%s LIMIT 1", (username,))</code> |
| L2557 | 计算并保存 &#96;exists&#96;（exists），供后续逻辑使用，当前位于函数 register。 | <code>                exists = cur.fetchone()</code> |
| L2558 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 register。 | <code>                if exists:</code> |
| L2559 | 结束当前函数并把结果返回给调用方，当前位于函数 register。 | <code>                    return jsonify({"error": "username_already_exists"}), 409</code> |
| L2560 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 register。 | <code>                cur.execute(</code> |
| L2561 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 register。 | <code>                    """</code> |
| L2562 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 register。 | <code>                    INSERT INTO demo_users(username, password, role, display_name, nickname)</code> |
| L2563 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 register。 | <code>                    VALUES (%s, %s, %s, %s, %s)</code> |
| L2564 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 register。 | <code>                    """,</code> |
| L2565 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 register。 | <code>                    (username, password, ROLE_NORMAL, display_name, display_name),</code> |
| L2566 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 register。 | <code>                )</code> |
| L2567 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 register。 | <code>                cur.execute(</code> |
| L2568 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 register。 | <code>                    """</code> |
| L2569 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 register。 | <code>                    SELECT id, username, role, display_name, nickname, avatar_url</code> |
| L2570 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 register。 | <code>                    FROM demo_users</code> |
| L2571 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 register。 | <code>                    WHERE username=%s</code> |
| L2572 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 register。 | <code>                    LIMIT 1</code> |
| L2573 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 register。 | <code>                    """,</code> |
| L2574 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 register。 | <code>                    (username,),</code> |
| L2575 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 register。 | <code>                )</code> |
| L2576 | 计算并保存 &#96;account&#96;（account），供后续逻辑使用，当前位于函数 register。 | <code>                account = cur.fetchone()</code> |
| L2577 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 register。 | <code>                if not account:</code> |
| L2578 | 结束当前函数并把结果返回给调用方，当前位于函数 register。 | <code>                    return jsonify({"error": "register_failed"}), 500</code> |
| L2579 | 计算并保存 &#96;token&#96;（token），供后续逻辑使用，当前位于函数 register。 | <code>                token = create_jwt_token(account, app.config["JWT_SECRET"], app.config["JWT_TTL_SECONDS"])</code> |
| L2580 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 register。 | <code>                log_action(conn, account["username"], account["role"], "register", "auth", "register_success")</code> |
| L2581 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 register。 | <code>            conn.commit()</code> |
| L2582 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2583 | 计算并保存 &#96;resp&#96;（resp），供后续逻辑使用，当前位于函数 register。 | <code>        resp = jsonify(</code> |
| L2584 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 register。 | <code>            {</code> |
| L2585 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 register。 | <code>                "token": token,</code> |
| L2586 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 register。 | <code>                "expires_in": int(app.config["JWT_TTL_SECONDS"]),</code> |
| L2587 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 register。 | <code>                "role": account["role"],</code> |
| L2588 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 register。 | <code>                "display_name": account["display_name"],</code> |
| L2589 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 register。 | <code>                "nickname": account.get("nickname") or account["display_name"],</code> |
| L2590 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 register。 | <code>                "avatar_url": normalize_avatar_url(account.get("avatar_url") or ""),</code> |
| L2591 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 register。 | <code>                "username": account["username"],</code> |
| L2592 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 register。 | <code>            }</code> |
| L2593 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 register。 | <code>        )</code> |
| L2594 | 结束当前函数并把结果返回给调用方，当前位于函数 register。 | <code>        return set_auth_cookie(resp, token)</code> |
| L2595 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2596 | 注册 Flask HTTP 接口 "/api/v2/auth/login", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/auth/login", methods=["POST"])</code> |
| L2597 | 定义登录函数 &#96;login&#96;，封装可复用业务逻辑。 | <code>    def login():</code> |
| L2598 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 login。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L2599 | 计算并保存 &#96;username&#96;（username），供后续逻辑使用，当前位于函数 login。 | <code>        username = str(body.get("username", "")).strip()</code> |
| L2600 | 控制当前循环或占位分支的执行流程，当前位于函数 login。 | <code>        password = str(body.get("password", "")).strip()</code> |
| L2601 | 计算并保存 &#96;role_hint&#96;（rolehint），供后续逻辑使用，当前位于函数 login。 | <code>        role_hint = str(body.get("role", "")).strip().lower()</code> |
| L2602 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 login。 | <code>        if role_hint and role_hint not in {ROLE_NORMAL, ROLE_ADMIN}:</code> |
| L2603 | 结束当前函数并把结果返回给调用方，当前位于函数 login。 | <code>            return jsonify({"error": "invalid_role"}), 400</code> |
| L2604 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 login。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L2605 | 计算并保存 &#96;account&#96;（account），供后续逻辑使用，当前位于函数 login。 | <code>            account = find_demo_account(conn, username, password, role_hint)</code> |
| L2606 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 login。 | <code>            if not account:</code> |
| L2607 | 结束当前函数并把结果返回给调用方，当前位于函数 login。 | <code>                return jsonify({"error": "invalid_credentials"}), 401</code> |
| L2608 | 计算并保存 &#96;token&#96;（token），供后续逻辑使用，当前位于函数 login。 | <code>            token = create_jwt_token(account, app.config["JWT_SECRET"], app.config["JWT_TTL_SECONDS"])</code> |
| L2609 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 login。 | <code>            log_action(conn, account["username"], account["role"], "login", "auth", "login_success")</code> |
| L2610 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 login。 | <code>            conn.commit()</code> |
| L2611 | 计算并保存 &#96;resp&#96;（resp），供后续逻辑使用，当前位于函数 login。 | <code>        resp = jsonify(</code> |
| L2612 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 login。 | <code>            {</code> |
| L2613 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 login。 | <code>                "token": token,</code> |
| L2614 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 login。 | <code>                "expires_in": int(app.config["JWT_TTL_SECONDS"]),</code> |
| L2615 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 login。 | <code>                "role": account["role"],</code> |
| L2616 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 login。 | <code>                "display_name": account["display_name"],</code> |
| L2617 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 login。 | <code>                "nickname": account.get("nickname") or account["display_name"],</code> |
| L2618 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 login。 | <code>                "avatar_url": normalize_avatar_url(account.get("avatar_url") or ""),</code> |
| L2619 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 login。 | <code>                "username": account["username"],</code> |
| L2620 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 login。 | <code>            }</code> |
| L2621 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 login。 | <code>        )</code> |
| L2622 | 结束当前函数并把结果返回给调用方，当前位于函数 login。 | <code>        return set_auth_cookie(resp, token)</code> |
| L2623 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2624 | 注册 Flask HTTP 接口 "/api/v2/auth/logout", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/auth/logout", methods=["POST"])</code> |
| L2625 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L2626 | 定义logout函数 &#96;logout&#96;，封装可复用业务逻辑。 | <code>    def logout():</code> |
| L2627 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 logout。 | <code>        revoke_jwt(g.token_claims)</code> |
| L2628 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 logout。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L2629 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 logout。 | <code>            log_action(conn, g.session["username"], g.session["role"], "logout", "auth", "logout_success")</code> |
| L2630 | 结束当前函数并把结果返回给调用方，当前位于函数 logout。 | <code>        return clear_auth_cookie(jsonify({"ok": True}))</code> |
| L2631 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2632 | 注册 Flask HTTP 接口 "/api/v2/auth/profile", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/auth/profile", methods=["GET"])</code> |
| L2633 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L2634 | 定义profile函数 &#96;profile&#96;，封装可复用业务逻辑。 | <code>    def profile():</code> |
| L2635 | 计算并保存 &#96;session&#96;（session），供后续逻辑使用，当前位于函数 profile。 | <code>        session = dict(g.session)</code> |
| L2636 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 profile。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L2637 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 profile。 | <code>            with conn.cursor() as cur:</code> |
| L2638 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 profile。 | <code>                cur.execute(</code> |
| L2639 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 profile。 | <code>                    """</code> |
| L2640 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 profile。 | <code>                    SELECT id, username, role, display_name, nickname, avatar_url</code> |
| L2641 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 profile。 | <code>                    FROM demo_users</code> |
| L2642 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 profile。 | <code>                    WHERE username=%s</code> |
| L2643 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 profile。 | <code>                    LIMIT 1</code> |
| L2644 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 profile。 | <code>                    """,</code> |
| L2645 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 profile。 | <code>                    (g.session["username"],),</code> |
| L2646 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 profile。 | <code>                )</code> |
| L2647 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 profile。 | <code>                row = cur.fetchone()</code> |
| L2648 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 profile。 | <code>        if row:</code> |
| L2649 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 profile。 | <code>            session.update(profile_public_fields(row))</code> |
| L2650 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 profile。 | <code>        session["expires_at"] = dt_to_str(session["expires_at"])</code> |
| L2651 | 结束当前函数并把结果返回给调用方，当前位于函数 profile。 | <code>        return jsonify(session)</code> |
| L2652 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2653 | 注册 Flask HTTP 接口 "/api/v2/auth/profile", methods=["PUT"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/auth/profile", methods=["PUT"])</code> |
| L2654 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L2655 | 定义更新profile函数 &#96;update_profile&#96;，封装可复用业务逻辑。 | <code>    def update_profile():</code> |
| L2656 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 update_profile。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L2657 | 计算并保存 &#96;display_name&#96;（displayname），供后续逻辑使用，当前位于函数 update_profile。 | <code>        display_name = normalize_profile_text(body.get("display_name"), g.session["display_name"], 64)</code> |
| L2658 | 计算并保存 &#96;nickname&#96;（nickname），供后续逻辑使用，当前位于函数 update_profile。 | <code>        nickname = normalize_profile_text(body.get("nickname"), display_name, 64)</code> |
| L2659 | 计算并保存 &#96;avatar_url&#96;（avatarurl），供后续逻辑使用，当前位于函数 update_profile。 | <code>        avatar_url = normalize_avatar_url(body.get("avatar_url") or "")</code> |
| L2660 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 update_profile。 | <code>        if not display_name:</code> |
| L2661 | 计算并保存 &#96;display_name&#96;（displayname），供后续逻辑使用，当前位于函数 update_profile。 | <code>            display_name = g.session["username"]</code> |
| L2662 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 update_profile。 | <code>        if not nickname:</code> |
| L2663 | 计算并保存 &#96;nickname&#96;（nickname），供后续逻辑使用，当前位于函数 update_profile。 | <code>            nickname = display_name</code> |
| L2664 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 update_profile。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L2665 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 update_profile。 | <code>            with conn.cursor() as cur:</code> |
| L2666 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 update_profile。 | <code>                cur.execute(</code> |
| L2667 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 update_profile。 | <code>                    """</code> |
| L2668 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 update_profile。 | <code>                    UPDATE demo_users</code> |
| L2669 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 update_profile。 | <code>                    SET display_name=%s, nickname=%s, avatar_url=%s</code> |
| L2670 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 update_profile。 | <code>                    WHERE username=%s</code> |
| L2671 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 update_profile。 | <code>                    """,</code> |
| L2672 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_profile。 | <code>                    (display_name, nickname, avatar_url, g.session["username"]),</code> |
| L2673 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 update_profile。 | <code>                )</code> |
| L2674 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 update_profile。 | <code>                cur.execute(</code> |
| L2675 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 update_profile。 | <code>                    """</code> |
| L2676 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 update_profile。 | <code>                    SELECT id, username, role, display_name, nickname, avatar_url</code> |
| L2677 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 update_profile。 | <code>                    FROM demo_users</code> |
| L2678 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 update_profile。 | <code>                    WHERE username=%s</code> |
| L2679 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 update_profile。 | <code>                    LIMIT 1</code> |
| L2680 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 update_profile。 | <code>                    """,</code> |
| L2681 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_profile。 | <code>                    (g.session["username"],),</code> |
| L2682 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 update_profile。 | <code>                )</code> |
| L2683 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 update_profile。 | <code>                row = cur.fetchone()</code> |
| L2684 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_profile。 | <code>                log_action(conn, g.session["username"], g.session["role"], "update_profile", "self", "profile_updated")</code> |
| L2685 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_profile。 | <code>            conn.commit()</code> |
| L2686 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 update_profile。 | <code>        if not row:</code> |
| L2687 | 结束当前函数并把结果返回给调用方，当前位于函数 update_profile。 | <code>            return jsonify({"error": "user_not_found"}), 404</code> |
| L2688 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 update_profile。 | <code>        payload = profile_public_fields(row)</code> |
| L2689 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_profile。 | <code>        payload["ok"] = True</code> |
| L2690 | 结束当前函数并把结果返回给调用方，当前位于函数 update_profile。 | <code>        return jsonify(payload)</code> |
| L2691 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2692 | 注册 Flask HTTP 接口 "/api/v2/auth/avatar", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/auth/avatar", methods=["POST"])</code> |
| L2693 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L2694 | 定义uploadavatar函数 &#96;upload_avatar&#96;，封装可复用业务逻辑。 | <code>    def upload_avatar():</code> |
| L2695 | 计算并保存 &#96;file_obj&#96;（fileobj），供后续逻辑使用，当前位于函数 upload_avatar。 | <code>        file_obj = request.files.get("avatar")</code> |
| L2696 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 upload_avatar。 | <code>        if not file_obj or not file_obj.filename:</code> |
| L2697 | 结束当前函数并把结果返回给调用方，当前位于函数 upload_avatar。 | <code>            return jsonify({"error": "avatar_required", "message": "请选择头像图片"}), 400</code> |
| L2698 | 计算并保存 &#96;ext&#96;（ext），供后续逻辑使用，当前位于函数 upload_avatar。 | <code>        ext = file_obj.filename.rsplit(".", 1)[-1].lower() if "." in file_obj.filename else ""</code> |
| L2699 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 upload_avatar。 | <code>        if ext not in ALLOWED_AVATAR_EXTENSIONS:</code> |
| L2700 | 结束当前函数并把结果返回给调用方，当前位于函数 upload_avatar。 | <code>            return jsonify({"error": "invalid_avatar_type", "message": "头像仅支持 jpg、png、webp"}), 400</code> |
| L2701 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 upload_avatar。 | <code>        raw = file_obj.read(MAX_AVATAR_BYTES + 1)</code> |
| L2702 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 upload_avatar。 | <code>        if len(raw) &gt; MAX_AVATAR_BYTES:</code> |
| L2703 | 结束当前函数并把结果返回给调用方，当前位于函数 upload_avatar。 | <code>            return jsonify({"error": "avatar_too_large", "message": "头像图片不能超过 2MB"}), 400</code> |
| L2704 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upload_avatar。 | <code>        AVATAR_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)</code> |
| L2705 | 计算并保存 &#96;safe_name&#96;（safename），供后续逻辑使用，当前位于函数 upload_avatar。 | <code>        safe_name = f"{g.session['username']}_{uuid.uuid4().hex[:12]}.{ext}"</code> |
| L2706 | 计算并保存 &#96;target&#96;（target），供后续逻辑使用，当前位于函数 upload_avatar。 | <code>        target = AVATAR_UPLOAD_DIR / safe_name</code> |
| L2707 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upload_avatar。 | <code>        target.write_bytes(raw)</code> |
| L2708 | 计算并保存 &#96;url&#96;（url），供后续逻辑使用，当前位于函数 upload_avatar。 | <code>        url = f"/uploads/avatars/{safe_name}"</code> |
| L2709 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 upload_avatar。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L2710 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 upload_avatar。 | <code>            with conn.cursor() as cur:</code> |
| L2711 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 upload_avatar。 | <code>                cur.execute("UPDATE demo_users SET avatar_url=%s WHERE username=%s", (url, g.session["username"]))</code> |
| L2712 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upload_avatar。 | <code>                log_action(conn, g.session["username"], g.session["role"], "upload_avatar", "self", url)</code> |
| L2713 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upload_avatar。 | <code>            conn.commit()</code> |
| L2714 | 结束当前函数并把结果返回给调用方，当前位于函数 upload_avatar。 | <code>        return jsonify({"ok": True, "avatar_url": url})</code> |
| L2715 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2716 | 注册 Flask HTTP 接口 "/api/v2/auth/change-password", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/auth/change-password", methods=["POST"])</code> |
| L2717 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L2718 | 定义authchangepassword函数 &#96;auth_change_password&#96;，封装可复用业务逻辑。 | <code>    def auth_change_password():</code> |
| L2719 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 auth_change_password。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L2720 | 计算并保存 &#96;old_password&#96;（oldpassword），供后续逻辑使用，当前位于函数 auth_change_password。 | <code>        old_password = str(body.get("old_password", "")).strip()</code> |
| L2721 | 计算并保存 &#96;new_password&#96;（newpassword），供后续逻辑使用，当前位于函数 auth_change_password。 | <code>        new_password = str(body.get("new_password", "")).strip()</code> |
| L2722 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 auth_change_password。 | <code>        if not old_password or not new_password:</code> |
| L2723 | 结束当前函数并把结果返回给调用方，当前位于函数 auth_change_password。 | <code>            return jsonify({"error": "old_password_and_new_password_required"}), 400</code> |
| L2724 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 auth_change_password。 | <code>        if len(new_password) &lt; 4:</code> |
| L2725 | 结束当前函数并把结果返回给调用方，当前位于函数 auth_change_password。 | <code>            return jsonify({"error": "new_password_too_short"}), 400</code> |
| L2726 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 auth_change_password。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L2727 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 auth_change_password。 | <code>            with conn.cursor() as cur:</code> |
| L2728 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 auth_change_password。 | <code>                cur.execute("SELECT password FROM demo_users WHERE username=%s LIMIT 1", (g.session["username"],))</code> |
| L2729 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 auth_change_password。 | <code>                row = cur.fetchone()</code> |
| L2730 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 auth_change_password。 | <code>                if not row:</code> |
| L2731 | 结束当前函数并把结果返回给调用方，当前位于函数 auth_change_password。 | <code>                    return jsonify({"error": "user_not_found"}), 404</code> |
| L2732 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 auth_change_password。 | <code>                if str(row.get("password", "")) != old_password:</code> |
| L2733 | 结束当前函数并把结果返回给调用方，当前位于函数 auth_change_password。 | <code>                    return jsonify({"error": "old_password_incorrect"}), 400</code> |
| L2734 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 auth_change_password。 | <code>                cur.execute("UPDATE demo_users SET password=%s WHERE username=%s", (new_password, g.session["username"]))</code> |
| L2735 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 auth_change_password。 | <code>                log_action(conn, g.session["username"], g.session["role"], "change_password", "self", "self_password_updated")</code> |
| L2736 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 auth_change_password。 | <code>            conn.commit()</code> |
| L2737 | 结束当前函数并把结果返回给调用方，当前位于函数 auth_change_password。 | <code>        return jsonify({"ok": True})</code> |
| L2738 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2739 | 注册 Flask HTTP 接口 "/api/v2/common/system-status", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/common/system-status", methods=["GET"])</code> |
| L2740 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L2741 | 定义system状态函数 &#96;system_status&#96;，封装可复用业务逻辑。 | <code>    def system_status():</code> |
| L2742 | 计算并保存 &#96;visible_sql&#96;（visiblesql），供后续逻辑使用，当前位于函数 system_status。 | <code>        visible_sql = visible_attack_event_clause()</code> |
| L2743 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 system_status。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L2744 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 system_status。 | <code>            refresh_machine_stats(conn)</code> |
| L2745 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 system_status。 | <code>            with conn.cursor() as cur:</code> |
| L2746 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 system_status。 | <code>                cur.execute(</code> |
| L2747 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 system_status。 | <code>                    f"""</code> |
| L2748 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 system_status。 | <code>                    SELECT</code> |
| L2749 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 system_status。 | <code>                      MAX(occurred_at) AS latest_event_time,</code> |
| L2750 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 system_status。 | <code>                      SUM(CASE WHEN risk_level IN ('critical','high') AND occurred_at &gt;= DATE_SUB(NOW(), INTERVAL 10 MINUTE) THEN 1 ELSE 0 END) AS high_10m</code> |
| L2751 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 system_status。 | <code>                    FROM demo_attack_events</code> |
| L2752 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 system_status。 | <code>                    WHERE {visible_sql}</code> |
| L2753 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 system_status。 | <code>                    """</code> |
| L2754 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 system_status。 | <code>                )</code> |
| L2755 | 计算并保存 &#96;base&#96;（base），供后续逻辑使用，当前位于函数 system_status。 | <code>                base = cur.fetchone() or {}</code> |
| L2756 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 system_status。 | <code>                cur.execute("SELECT COUNT(*) AS offline_count FROM demo_machines WHERE online_status &lt;&gt; 'online'")</code> |
| L2757 | 计算并保存 &#96;offline_count&#96;（offlinecount），供后续逻辑使用，当前位于函数 system_status。 | <code>                offline_count = int((cur.fetchone() or {}).get("offline_count", 0))</code> |
| L2758 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 system_status。 | <code>                cur.execute(</code> |
| L2759 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 system_status。 | <code>                    "SELECT config_value FROM demo_system_config WHERE config_key='auto_refresh_seconds' LIMIT 1"</code> |
| L2760 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 system_status。 | <code>                )</code> |
| L2761 | 计算并保存 &#96;cfg&#96;（cfg），供后续逻辑使用，当前位于函数 system_status。 | <code>                cfg = cur.fetchone() or {}</code> |
| L2762 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 system_status。 | <code>            conn.commit()</code> |
| L2763 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2764 | 计算并保存 &#96;high_10m&#96;（high10m），供后续逻辑使用，当前位于函数 system_status。 | <code>        high_10m = int(base.get("high_10m") or 0)</code> |
| L2765 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 system_status。 | <code>        if offline_count &gt; 0:</code> |
| L2766 | 计算并保存 &#96;state&#96;（state），供后续逻辑使用，当前位于函数 system_status。 | <code>            state = {"level": "error", "color": "red"}</code> |
| L2767 | 当前一条件未命中时继续判断另一条件，当前位于函数 system_status。 | <code>        elif high_10m &gt;= 8:</code> |
| L2768 | 计算并保存 &#96;state&#96;（state），供后续逻辑使用，当前位于函数 system_status。 | <code>            state = {"level": "warning", "color": "yellow"}</code> |
| L2769 | 处理前述条件均未命中的情况，当前位于函数 system_status。 | <code>        else:</code> |
| L2770 | 计算并保存 &#96;state&#96;（state），供后续逻辑使用，当前位于函数 system_status。 | <code>            state = {"level": "normal", "color": "green"}</code> |
| L2771 | 结束当前函数并把结果返回给调用方，当前位于函数 system_status。 | <code>        return jsonify(</code> |
| L2772 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 system_status。 | <code>            {</code> |
| L2773 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 system_status。 | <code>                "server_time": dt_to_str(now_dt()),</code> |
| L2774 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 system_status。 | <code>                "latest_data_time": dt_to_str(base.get("latest_event_time")),</code> |
| L2775 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 system_status。 | <code>                "state": state,</code> |
| L2776 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 system_status。 | <code>                "refresh_interval_seconds": int(cfg.get("config_value") or 5),</code> |
| L2777 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 system_status。 | <code>                "high_risk_last_10m": high_10m,</code> |
| L2778 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 system_status。 | <code>                "offline_machine_count": offline_count,</code> |
| L2779 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 system_status。 | <code>            }</code> |
| L2780 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 system_status。 | <code>        )</code> |
| L2781 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2782 | 注册 Flask HTTP 接口 "/api/v2/common/alerts/ticker", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/common/alerts/ticker", methods=["GET"])</code> |
| L2783 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L2784 | 定义alertsticker函数 &#96;alerts_ticker&#96;，封装可复用业务逻辑。 | <code>    def alerts_ticker():</code> |
| L2785 | 计算并保存 &#96;limit&#96;（limit），供后续逻辑使用，当前位于函数 alerts_ticker。 | <code>        limit = max(1, min(int(request.args.get("limit", "3")), 10))</code> |
| L2786 | 计算并保存 &#96;visible_sql&#96;（visiblesql），供后续逻辑使用，当前位于函数 alerts_ticker。 | <code>        visible_sql = visible_attack_event_clause()</code> |
| L2787 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 alerts_ticker。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L2788 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 alerts_ticker。 | <code>            with conn.cursor() as cur:</code> |
| L2789 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 alerts_ticker。 | <code>                cur.execute(</code> |
| L2790 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 alerts_ticker。 | <code>                    f"""</code> |
| L2791 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 alerts_ticker。 | <code>                    SELECT event_id, occurred_at, risk_level, attack_type, source_ip, target_node, target_interface</code> |
| L2792 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 alerts_ticker。 | <code>                    FROM demo_attack_events</code> |
| L2793 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 alerts_ticker。 | <code>                    WHERE risk_level IN ('critical','high') AND {visible_sql}</code> |
| L2794 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 alerts_ticker。 | <code>                    ORDER BY occurred_at DESC</code> |
| L2795 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 alerts_ticker。 | <code>                    LIMIT %s</code> |
| L2796 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 alerts_ticker。 | <code>                    """,</code> |
| L2797 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 alerts_ticker。 | <code>                    (limit,),</code> |
| L2798 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 alerts_ticker。 | <code>                )</code> |
| L2799 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 alerts_ticker。 | <code>                rows = cur.fetchall()</code> |
| L2800 | 结束当前函数并把结果返回给调用方，当前位于函数 alerts_ticker。 | <code>        return jsonify({"items": normalize_rows(rows)})</code> |
| L2801 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2802 | 注册 Flask HTTP 接口 "/api/v2/common/alerts/popup", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/common/alerts/popup", methods=["GET"])</code> |
| L2803 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L2804 | 定义alertspopup函数 &#96;alerts_popup&#96;，封装可复用业务逻辑。 | <code>    def alerts_popup():</code> |
| L2805 | 计算并保存 &#96;limit&#96;（limit），供后续逻辑使用，当前位于函数 alerts_popup。 | <code>        limit = max(1, min(int(request.args.get("limit", "5")), 20))</code> |
| L2806 | 计算并保存 &#96;visible_sql&#96;（visiblesql），供后续逻辑使用，当前位于函数 alerts_popup。 | <code>        visible_sql = visible_attack_event_clause()</code> |
| L2807 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 alerts_popup。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L2808 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 alerts_popup。 | <code>            with conn.cursor() as cur:</code> |
| L2809 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 alerts_popup。 | <code>                cur.execute(</code> |
| L2810 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 alerts_popup。 | <code>                    f"""</code> |
| L2811 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 alerts_popup。 | <code>                    SELECT event_id, occurred_at, attack_type, source_ip, target_node, target_interface</code> |
| L2812 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 alerts_popup。 | <code>                    FROM demo_attack_events</code> |
| L2813 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 alerts_popup。 | <code>                    WHERE risk_level IN ('critical','high') AND acked=0 AND {visible_sql}</code> |
| L2814 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 alerts_popup。 | <code>                    ORDER BY occurred_at DESC</code> |
| L2815 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 alerts_popup。 | <code>                    LIMIT %s</code> |
| L2816 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 alerts_popup。 | <code>                    """,</code> |
| L2817 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 alerts_popup。 | <code>                    (limit,),</code> |
| L2818 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 alerts_popup。 | <code>                )</code> |
| L2819 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 alerts_popup。 | <code>                rows = cur.fetchall()</code> |
| L2820 | 结束当前函数并把结果返回给调用方，当前位于函数 alerts_popup。 | <code>        return jsonify({"items": normalize_rows(rows)})</code> |
| L2821 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2822 | 注册 Flask HTTP 接口 "/api/v2/common/alerts/&lt;event_id&gt;/ack", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/common/alerts/&lt;event_id&gt;/ack", methods=["POST"])</code> |
| L2823 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L2824 | 定义alertack函数 &#96;alert_ack&#96;，封装可复用业务逻辑。 | <code>    def alert_ack(event_id: str):</code> |
| L2825 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 alert_ack。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L2826 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 alert_ack。 | <code>            with conn.cursor() as cur:</code> |
| L2827 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 alert_ack。 | <code>                cur.execute(</code> |
| L2828 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 alert_ack。 | <code>                    """</code> |
| L2829 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 alert_ack。 | <code>                    UPDATE demo_attack_events</code> |
| L2830 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 alert_ack。 | <code>                    SET acked=1,</code> |
| L2831 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 alert_ack。 | <code>                        process_status=CASE WHEN process_status='unprocessed' THEN 'processing' ELSE process_status END</code> |
| L2832 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 alert_ack。 | <code>                    WHERE event_id=%s</code> |
| L2833 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 alert_ack。 | <code>                    """,</code> |
| L2834 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 alert_ack。 | <code>                    (event_id,),</code> |
| L2835 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 alert_ack。 | <code>                )</code> |
| L2836 | 计算并保存 &#96;changed&#96;（changed），供后续逻辑使用，当前位于函数 alert_ack。 | <code>                changed = cur.rowcount</code> |
| L2837 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 alert_ack。 | <code>                refresh_machine_stats(conn)</code> |
| L2838 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 alert_ack。 | <code>                log_action(conn, g.session["username"], g.session["role"], "ack_alert", event_id, "acked")</code> |
| L2839 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 alert_ack。 | <code>            conn.commit()</code> |
| L2840 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 alert_ack。 | <code>        if changed == 0:</code> |
| L2841 | 结束当前函数并把结果返回给调用方，当前位于函数 alert_ack。 | <code>            return jsonify({"error": "event_not_found"}), 404</code> |
| L2842 | 结束当前函数并把结果返回给调用方，当前位于函数 alert_ack。 | <code>        return jsonify({"ok": True, "event_id": event_id})</code> |
| L2843 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2844 | 注册 Flask HTTP 接口 "/api/v2/llm/prompt", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/llm/prompt", methods=["GET"])</code> |
| L2845 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L2846 | 定义llmprompt读取函数 &#96;llm_prompt_get&#96;，封装可复用业务逻辑。 | <code>    def llm_prompt_get():</code> |
| L2847 | 计算并保存 &#96;prompt_path&#96;（promptpath），供后续逻辑使用，当前位于函数 llm_prompt_get。 | <code>        prompt_path = Path(app.config["LLM_PROMPT_PATH"])</code> |
| L2848 | 结束当前函数并把结果返回给调用方，当前位于函数 llm_prompt_get。 | <code>        return jsonify(build_llm_prompt_payload(prompt_path))</code> |
| L2849 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2850 | 注册 Flask HTTP 接口 "/api/v2/llm/prompt", methods=["PUT"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/llm/prompt", methods=["PUT"])</code> |
| L2851 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L2852 | 定义llmprompt更新函数 &#96;llm_prompt_update&#96;，封装可复用业务逻辑。 | <code>    def llm_prompt_update():</code> |
| L2853 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 llm_prompt_update。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L2854 | 计算并保存 &#96;prompt&#96;（prompt），供后续逻辑使用，当前位于函数 llm_prompt_update。 | <code>        prompt = str(body.get("prompt", ""))</code> |
| L2855 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 llm_prompt_update。 | <code>        if not prompt.strip():</code> |
| L2856 | 结束当前函数并把结果返回给调用方，当前位于函数 llm_prompt_update。 | <code>            return jsonify({"error": "prompt_required", "message": "提示词不能为空"}), 400</code> |
| L2857 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 llm_prompt_update。 | <code>        if len(prompt) &gt; MAX_LLM_PROMPT_CHARS:</code> |
| L2858 | 结束当前函数并把结果返回给调用方，当前位于函数 llm_prompt_update。 | <code>            return (</code> |
| L2859 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 llm_prompt_update。 | <code>                jsonify(</code> |
| L2860 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 llm_prompt_update。 | <code>                    {</code> |
| L2861 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 llm_prompt_update。 | <code>                        "error": "prompt_too_long",</code> |
| L2862 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 llm_prompt_update。 | <code>                        "message": f"提示词不能超过 {MAX_LLM_PROMPT_CHARS} 个字符",</code> |
| L2863 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 llm_prompt_update。 | <code>                        "max_chars": MAX_LLM_PROMPT_CHARS,</code> |
| L2864 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 llm_prompt_update。 | <code>                    }</code> |
| L2865 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 llm_prompt_update。 | <code>                ),</code> |
| L2866 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 llm_prompt_update。 | <code>                400,</code> |
| L2867 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 llm_prompt_update。 | <code>            )</code> |
| L2868 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2869 | 计算并保存 &#96;prompt_path&#96;（promptpath），供后续逻辑使用，当前位于函数 llm_prompt_update。 | <code>        prompt_path = Path(app.config["LLM_PROMPT_PATH"])</code> |
| L2870 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 llm_prompt_update。 | <code>        write_llm_prompt_file(prompt_path, prompt)</code> |
| L2871 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 llm_prompt_update。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L2872 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 llm_prompt_update。 | <code>            log_action(</code> |
| L2873 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 llm_prompt_update。 | <code>                conn,</code> |
| L2874 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 llm_prompt_update。 | <code>                g.session["username"],</code> |
| L2875 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 llm_prompt_update。 | <code>                g.session["role"],</code> |
| L2876 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 llm_prompt_update。 | <code>                "llm_prompt_update",</code> |
| L2877 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 llm_prompt_update。 | <code>                display_project_path(prompt_path),</code> |
| L2878 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 llm_prompt_update。 | <code>                f"chars={len(prompt)}",</code> |
| L2879 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 llm_prompt_update。 | <code>            )</code> |
| L2880 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 llm_prompt_update。 | <code>        payload = build_llm_prompt_payload(prompt_path)</code> |
| L2881 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 llm_prompt_update。 | <code>        payload["ok"] = True</code> |
| L2882 | 结束当前函数并把结果返回给调用方，当前位于函数 llm_prompt_update。 | <code>        return jsonify(payload)</code> |
| L2883 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2884 | 注册 Flask HTTP 接口 "/api/v2/llm/professional-report-prompt", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/llm/professional-report-prompt", methods=["GET"])</code> |
| L2885 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L2886 | 定义professional报告prompt读取函数 &#96;professional_report_prompt_get&#96;，封装可复用业务逻辑。 | <code>    def professional_report_prompt_get():</code> |
| L2887 | 计算并保存 &#96;prompt_path&#96;（promptpath），供后续逻辑使用，当前位于函数 professional_report_prompt_get。 | <code>        prompt_path = Path(app.config["PROFESSIONAL_REPORT_PROMPT_PATH"])</code> |
| L2888 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 professional_report_prompt_get。 | <code>        payload = build_llm_prompt_payload(prompt_path)</code> |
| L2889 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 professional_report_prompt_get。 | <code>        payload["max_chars"] = MAX_PROFESSIONAL_REPORT_PROMPT_CHARS</code> |
| L2890 | 结束当前函数并把结果返回给调用方，当前位于函数 professional_report_prompt_get。 | <code>        return jsonify(payload)</code> |
| L2891 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2892 | 注册 Flask HTTP 接口 "/api/v2/llm/professional-report-prompt", methods=["PUT"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/llm/professional-report-prompt", methods=["PUT"])</code> |
| L2893 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L2894 | 定义professional报告prompt更新函数 &#96;professional_report_prompt_update&#96;，封装可复用业务逻辑。 | <code>    def professional_report_prompt_update():</code> |
| L2895 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 professional_report_prompt_update。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L2896 | 计算并保存 &#96;prompt&#96;（prompt），供后续逻辑使用，当前位于函数 professional_report_prompt_update。 | <code>        prompt = str(body.get("prompt", ""))</code> |
| L2897 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 professional_report_prompt_update。 | <code>        if not prompt.strip():</code> |
| L2898 | 结束当前函数并把结果返回给调用方，当前位于函数 professional_report_prompt_update。 | <code>            return jsonify({"error": "prompt_required", "message": "专业报告提示词不能为空"}), 400</code> |
| L2899 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 professional_report_prompt_update。 | <code>        if len(prompt) &gt; MAX_PROFESSIONAL_REPORT_PROMPT_CHARS:</code> |
| L2900 | 结束当前函数并把结果返回给调用方，当前位于函数 professional_report_prompt_update。 | <code>            return jsonify({"error": "prompt_too_long", "message": f"专业报告提示词不能超过 {MAX_PROFESSIONAL_REPORT_PROMPT_CHARS} 个字符"}), 400</code> |
| L2901 | 计算并保存 &#96;prompt_path&#96;（promptpath），供后续逻辑使用，当前位于函数 professional_report_prompt_update。 | <code>        prompt_path = Path(app.config["PROFESSIONAL_REPORT_PROMPT_PATH"])</code> |
| L2902 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 professional_report_prompt_update。 | <code>        write_llm_prompt_file(prompt_path, prompt)</code> |
| L2903 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 professional_report_prompt_update。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L2904 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 professional_report_prompt_update。 | <code>            log_action(conn, g.session["username"], g.session["role"], "professional_report_prompt_update", display_project_path(prompt_path), f"chars={len(prompt)}")</code> |
| L2905 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 professional_report_prompt_update。 | <code>        payload = build_llm_prompt_payload(prompt_path)</code> |
| L2906 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 professional_report_prompt_update。 | <code>        payload.update({"ok": True, "max_chars": MAX_PROFESSIONAL_REPORT_PROMPT_CHARS})</code> |
| L2907 | 结束当前函数并把结果返回给调用方，当前位于函数 professional_report_prompt_update。 | <code>        return jsonify(payload)</code> |
| L2908 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2909 | 定义rag2runtime函数 &#96;rag2_runtime&#96;，封装可复用业务逻辑。 | <code>    def rag2_runtime() -&gt; Tuple[Path, Dict[str, Any]]:</code> |
| L2910 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_runtime。 | <code>        return Path(app.config["RAG_DATA_DIR"]), rag2_load_api_config(Path(app.config["RAG_API_CONFIG_PATH"]))</code> |
| L2911 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2912 | 定义rag2isenabled函数 &#96;rag2_is_enabled&#96;，封装可复用业务逻辑。 | <code>    def rag2_is_enabled() -&gt; bool:</code> |
| L2913 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_is_enabled。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L2914 | 计算并保存 &#96;config_map&#96;（配置map），供后续逻辑使用，当前位于函数 rag2_is_enabled。 | <code>            config_map = load_system_config_map(conn)</code> |
| L2915 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_is_enabled。 | <code>        return str(config_map.get("rag_enabled", "1")).strip().lower() in {"1", "true", "yes", "on"}</code> |
| L2916 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2917 | 注册 Flask HTTP 接口 "/api/v3/rag/status", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/status", methods=["GET"])</code> |
| L2918 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L2919 | 定义rag2状态函数 &#96;rag2_status&#96;，封装可复用业务逻辑。 | <code>    def rag2_status():</code> |
| L2920 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_status。 | <code>        data_dir, api_config = rag2_runtime()</code> |
| L2921 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_status。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L2922 | 计算并保存 &#96;kbs&#96;（kbs），供后续逻辑使用，当前位于函数 rag2_status。 | <code>            kbs = rag2_list_kbs(conn)</code> |
| L2923 | 计算并保存 &#96;config_map&#96;（配置map），供后续逻辑使用，当前位于函数 rag2_status。 | <code>            config_map = load_system_config_map(conn)</code> |
| L2924 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_status。 | <code>        return jsonify(</code> |
| L2925 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_status。 | <code>            {</code> |
| L2926 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_status。 | <code>                "ok": True,</code> |
| L2927 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_status。 | <code>                "enabled": str(config_map.get("rag_enabled", "1")).strip().lower() in {"1", "true", "yes", "on"},</code> |
| L2928 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_status。 | <code>                "cloud_configured": bool(api_config.get("api_key")),</code> |
| L2929 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 rag2_status。 | <code>                "embedding_model": api_config["embedding_model"],</code> |
| L2930 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 rag2_status。 | <code>                "rerank_model": api_config["rerank_model"],</code> |
| L2931 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 rag2_status。 | <code>                "embedding_dimensions": api_config["embedding_dimensions"],</code> |
| L2932 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_status。 | <code>                "data_dir": display_project_path(data_dir),</code> |
| L2933 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_status。 | <code>                "knowledge_base_count": len(kbs),</code> |
| L2934 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_status。 | <code>                "document_count": sum(int(row.get("document_count") or 0) for row in kbs),</code> |
| L2935 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_status。 | <code>                "chunk_count": sum(int(row.get("chunk_count") or 0) for row in kbs),</code> |
| L2936 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_status。 | <code>                "supported_extensions": sorted(RAG_SUPPORTED_EXTENSIONS),</code> |
| L2937 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_status。 | <code>                "max_upload_mb": RAG_MAX_UPLOAD_BYTES // 1024 // 1024,</code> |
| L2938 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 rag2_status。 | <code>            }</code> |
| L2939 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 rag2_status。 | <code>        )</code> |
| L2940 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2941 | 注册 Flask HTTP 接口 "/api/v3/rag/knowledge-bases", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/knowledge-bases", methods=["GET"])</code> |
| L2942 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L2943 | 定义rag2kb列出函数 &#96;rag2_kb_list&#96;，封装可复用业务逻辑。 | <code>    def rag2_kb_list():</code> |
| L2944 | 计算并保存 &#96;q&#96;（q），供后续逻辑使用，当前位于函数 rag2_kb_list。 | <code>        q = str(request.args.get("q") or "").strip()</code> |
| L2945 | 计算并保存 &#96;include_disabled&#96;（includedisabled），供后续逻辑使用，当前位于函数 rag2_kb_list。 | <code>        include_disabled = str(request.args.get("include_disabled", "1")).lower() not in {"0", "false", "no"}</code> |
| L2946 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_kb_list。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L2947 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 rag2_kb_list。 | <code>            rows = rag2_list_kbs(conn, q=q, include_disabled=include_disabled)</code> |
| L2948 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_kb_list。 | <code>        return jsonify({"items": rows, "total": len(rows)})</code> |
| L2949 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2950 | 注册 Flask HTTP 接口 "/api/v3/rag/knowledge-bases", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/knowledge-bases", methods=["POST"])</code> |
| L2951 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L2952 | 定义rag2kb创建函数 &#96;rag2_kb_create&#96;，封装可复用业务逻辑。 | <code>    def rag2_kb_create():</code> |
| L2953 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 rag2_kb_create。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L2954 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 rag2_kb_create。 | <code>        try:</code> |
| L2955 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_kb_create。 | <code>            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L2956 | 计算并保存 &#96;kb_id&#96;（kbid），供后续逻辑使用，当前位于函数 rag2_kb_create。 | <code>                kb_id = rag2_save_kb(conn, body, g.session["username"])</code> |
| L2957 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 rag2_kb_create。 | <code>                item = rag2_get_kb(conn, kb_id)</code> |
| L2958 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_kb_create。 | <code>                log_action(conn, g.session["username"], g.session["role"], "rag_kb_create", str(kb_id), str(body.get("name") or ""))</code> |
| L2959 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 rag2_kb_create。 | <code>        except (ValueError, pymysql.IntegrityError) as exc:</code> |
| L2960 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_kb_create。 | <code>            return jsonify({"error": "invalid_knowledge_base", "message": str(exc)}), 400</code> |
| L2961 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_kb_create。 | <code>        return jsonify({"ok": True, "item": item}), 201</code> |
| L2962 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2963 | 注册 Flask HTTP 接口 "/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;", methods=["GET"])</code> |
| L2964 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L2965 | 定义rag2kbdetail函数 &#96;rag2_kb_detail&#96;，封装可复用业务逻辑。 | <code>    def rag2_kb_detail(kb_id: int):</code> |
| L2966 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_kb_detail。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L2967 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 rag2_kb_detail。 | <code>            item = rag2_get_kb(conn, kb_id)</code> |
| L2968 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_kb_detail。 | <code>        if not item:</code> |
| L2969 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_kb_detail。 | <code>            return jsonify({"error": "knowledge_base_not_found"}), 404</code> |
| L2970 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_kb_detail。 | <code>        return jsonify({"item": item})</code> |
| L2971 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2972 | 注册 Flask HTTP 接口 "/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;", methods=["PUT"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;", methods=["PUT"])</code> |
| L2973 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L2974 | 定义rag2kb更新函数 &#96;rag2_kb_update&#96;，封装可复用业务逻辑。 | <code>    def rag2_kb_update(kb_id: int):</code> |
| L2975 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 rag2_kb_update。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L2976 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 rag2_kb_update。 | <code>        try:</code> |
| L2977 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_kb_update。 | <code>            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L2978 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_kb_update。 | <code>                rag2_save_kb(conn, body, g.session["username"], kb_id=kb_id)</code> |
| L2979 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 rag2_kb_update。 | <code>                item = rag2_get_kb(conn, kb_id)</code> |
| L2980 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_kb_update。 | <code>                log_action(conn, g.session["username"], g.session["role"], "rag_kb_update", str(kb_id), str(body.get("name") or ""))</code> |
| L2981 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 rag2_kb_update。 | <code>        except KeyError:</code> |
| L2982 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_kb_update。 | <code>            return jsonify({"error": "knowledge_base_not_found"}), 404</code> |
| L2983 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 rag2_kb_update。 | <code>        except (ValueError, pymysql.IntegrityError) as exc:</code> |
| L2984 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_kb_update。 | <code>            return jsonify({"error": "invalid_knowledge_base", "message": str(exc)}), 400</code> |
| L2985 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_kb_update。 | <code>        return jsonify({"ok": True, "item": item})</code> |
| L2986 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L2987 | 注册 Flask HTTP 接口 "/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/toggle", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/toggle", methods=["POST"])</code> |
| L2988 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L2989 | 定义rag2kbtoggle函数 &#96;rag2_kb_toggle&#96;，封装可复用业务逻辑。 | <code>    def rag2_kb_toggle(kb_id: int):</code> |
| L2990 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 rag2_kb_toggle。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L2991 | 计算并保存 &#96;enabled&#96;（enabled），供后续逻辑使用，当前位于函数 rag2_kb_toggle。 | <code>        enabled = bool(body.get("enabled", True))</code> |
| L2992 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_kb_toggle。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L2993 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 rag2_kb_toggle。 | <code>            item = rag2_get_kb(conn, kb_id)</code> |
| L2994 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_kb_toggle。 | <code>            if not item:</code> |
| L2995 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_kb_toggle。 | <code>                return jsonify({"error": "knowledge_base_not_found"}), 404</code> |
| L2996 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_kb_toggle。 | <code>            item["enabled"] = enabled</code> |
| L2997 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_kb_toggle。 | <code>            rag2_save_kb(conn, item, g.session["username"], kb_id=kb_id)</code> |
| L2998 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_kb_toggle。 | <code>        return jsonify({"ok": True, "enabled": enabled})</code> |
| L2999 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3000 | 注册 Flask HTTP 接口 "/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/delete", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/delete", methods=["POST"])</code> |
| L3001 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3002 | 定义rag2kb删除函数 &#96;rag2_kb_delete&#96;，封装可复用业务逻辑。 | <code>    def rag2_kb_delete(kb_id: int):</code> |
| L3003 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_kb_delete。 | <code>        data_dir, _ = rag2_runtime()</code> |
| L3004 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_kb_delete。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L3005 | 计算并保存 &#96;changed&#96;（changed），供后续逻辑使用，当前位于函数 rag2_kb_delete。 | <code>            changed = rag2_delete_kb(conn, data_dir, kb_id)</code> |
| L3006 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_kb_delete。 | <code>            if changed:</code> |
| L3007 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_kb_delete。 | <code>                log_action(conn, g.session["username"], g.session["role"], "rag_kb_delete", str(kb_id), "deleted")</code> |
| L3008 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_kb_delete。 | <code>        if not changed:</code> |
| L3009 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_kb_delete。 | <code>            return jsonify({"error": "knowledge_base_not_found"}), 404</code> |
| L3010 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_kb_delete。 | <code>        return jsonify({"ok": True})</code> |
| L3011 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3012 | 注册 Flask HTTP 接口 "/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/documents", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/documents", methods=["GET"])</code> |
| L3013 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3014 | 定义rag2documents函数 &#96;rag2_documents&#96;，封装可复用业务逻辑。 | <code>    def rag2_documents(kb_id: int):</code> |
| L3015 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_documents。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L3016 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_documents。 | <code>            if not rag2_get_kb(conn, kb_id):</code> |
| L3017 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_documents。 | <code>                return jsonify({"error": "knowledge_base_not_found"}), 404</code> |
| L3018 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 rag2_documents。 | <code>            rows = rag2_list_documents(conn, kb_id)</code> |
| L3019 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_documents。 | <code>        return jsonify({"items": rows, "total": len(rows)})</code> |
| L3020 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3021 | 注册 Flask HTTP 接口 "/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/documents/upload", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/documents/upload", methods=["POST"])</code> |
| L3022 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3023 | 定义rag2upload函数 &#96;rag2_upload&#96;，封装可复用业务逻辑。 | <code>    def rag2_upload(kb_id: int):</code> |
| L3024 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_upload。 | <code>        if not rag2_is_enabled():</code> |
| L3025 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_upload。 | <code>            return jsonify({"error": "rag_disabled", "message": "RAG 已关闭，未调用云端向量 API"}), 409</code> |
| L3026 | 计算并保存 &#96;upload&#96;（upload），供后续逻辑使用，当前位于函数 rag2_upload。 | <code>        upload = request.files.get("file")</code> |
| L3027 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_upload。 | <code>        if not upload or not upload.filename:</code> |
| L3028 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_upload。 | <code>            return jsonify({"error": "file_required", "message": "请选择要上传的文件"}), 400</code> |
| L3029 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_upload。 | <code>        data_dir, api_config = rag2_runtime()</code> |
| L3030 | 计算并保存 &#96;temp_dir&#96;（tempdir），供后续逻辑使用，当前位于函数 rag2_upload。 | <code>        temp_dir = data_dir / "temp"</code> |
| L3031 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_upload。 | <code>        temp_dir.mkdir(parents=True, exist_ok=True)</code> |
| L3032 | 计算并保存 &#96;temp_path&#96;（temppath），供后续逻辑使用，当前位于函数 rag2_upload。 | <code>        temp_path = temp_dir / f"{uuid.uuid4().hex}_{Path(upload.filename).name}"</code> |
| L3033 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_upload。 | <code>        upload.save(temp_path)</code> |
| L3034 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 rag2_upload。 | <code>        try:</code> |
| L3035 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_upload。 | <code>            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L3036 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 rag2_upload。 | <code>                item = rag2_ingest_file(conn, data_dir, api_config, kb_id, temp_path, upload.filename, g.session["username"])</code> |
| L3037 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_upload。 | <code>                log_action(conn, g.session["username"], g.session["role"], "rag_document_upload", str(item["id"]), upload.filename)</code> |
| L3038 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_upload。 | <code>            return jsonify({"ok": True, "item": item}), 201</code> |
| L3039 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 rag2_upload。 | <code>        except (ValueError, KeyError, RuntimeError) as exc:</code> |
| L3040 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_upload。 | <code>            return jsonify({"error": "document_ingest_failed", "message": str(exc)}), 400</code> |
| L3041 | 无论成功或异常都执行资源清理，当前位于函数 rag2_upload。 | <code>        finally:</code> |
| L3042 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_upload。 | <code>            temp_path.unlink(missing_ok=True)</code> |
| L3043 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3044 | 注册 Flask HTTP 接口 "/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/documents/text", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/documents/text", methods=["POST"])</code> |
| L3045 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3046 | 定义rag2addtext函数 &#96;rag2_add_text&#96;，封装可复用业务逻辑。 | <code>    def rag2_add_text(kb_id: int):</code> |
| L3047 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_add_text。 | <code>        if not rag2_is_enabled():</code> |
| L3048 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_add_text。 | <code>            return jsonify({"error": "rag_disabled", "message": "RAG 已关闭，未调用云端向量 API"}), 409</code> |
| L3049 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 rag2_add_text。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L3050 | 计算并保存 &#96;title&#96;（title），供后续逻辑使用，当前位于函数 rag2_add_text。 | <code>        title = str(body.get("title") or "在线知识.txt").strip()</code> |
| L3051 | 计算并保存 &#96;content&#96;（content），供后续逻辑使用，当前位于函数 rag2_add_text。 | <code>        content = str(body.get("content") or "").strip()</code> |
| L3052 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_add_text。 | <code>        if not content:</code> |
| L3053 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_add_text。 | <code>            return jsonify({"error": "content_required", "message": "知识正文不能为空"}), 400</code> |
| L3054 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_add_text。 | <code>        data_dir, api_config = rag2_runtime()</code> |
| L3055 | 计算并保存 &#96;temp_dir&#96;（tempdir），供后续逻辑使用，当前位于函数 rag2_add_text。 | <code>        temp_dir = data_dir / "temp"</code> |
| L3056 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_add_text。 | <code>        temp_dir.mkdir(parents=True, exist_ok=True)</code> |
| L3057 | 计算并保存 &#96;name&#96;（name），供后续逻辑使用，当前位于函数 rag2_add_text。 | <code>        name = title if Path(title).suffix else f"{title}.txt"</code> |
| L3058 | 计算并保存 &#96;temp_path&#96;（temppath），供后续逻辑使用，当前位于函数 rag2_add_text。 | <code>        temp_path = temp_dir / f"{uuid.uuid4().hex}_{Path(name).name}"</code> |
| L3059 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_add_text。 | <code>        temp_path.write_text(content, encoding="utf-8")</code> |
| L3060 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 rag2_add_text。 | <code>        try:</code> |
| L3061 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_add_text。 | <code>            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L3062 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 rag2_add_text。 | <code>                item = rag2_ingest_file(conn, data_dir, api_config, kb_id, temp_path, name, g.session["username"], source_type="text")</code> |
| L3063 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_add_text。 | <code>            return jsonify({"ok": True, "item": item}), 201</code> |
| L3064 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 rag2_add_text。 | <code>        except (ValueError, KeyError, RuntimeError) as exc:</code> |
| L3065 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_add_text。 | <code>            return jsonify({"error": "document_ingest_failed", "message": str(exc)}), 400</code> |
| L3066 | 无论成功或异常都执行资源清理，当前位于函数 rag2_add_text。 | <code>        finally:</code> |
| L3067 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_add_text。 | <code>            temp_path.unlink(missing_ok=True)</code> |
| L3068 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3069 | 注册 Flask HTTP 接口 "/api/v3/rag/documents/&lt;int:document_id&gt;/delete", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/documents/&lt;int:document_id&gt;/delete", methods=["POST"])</code> |
| L3070 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3071 | 定义rag2document删除函数 &#96;rag2_document_delete&#96;，封装可复用业务逻辑。 | <code>    def rag2_document_delete(document_id: int):</code> |
| L3072 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_document_delete。 | <code>        data_dir, _ = rag2_runtime()</code> |
| L3073 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_document_delete。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L3074 | 计算并保存 &#96;changed&#96;（changed），供后续逻辑使用，当前位于函数 rag2_document_delete。 | <code>            changed = rag2_delete_document(conn, data_dir, document_id)</code> |
| L3075 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_document_delete。 | <code>        if not changed:</code> |
| L3076 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_document_delete。 | <code>            return jsonify({"error": "document_not_found"}), 404</code> |
| L3077 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_document_delete。 | <code>        return jsonify({"ok": True})</code> |
| L3078 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3079 | 注册 Flask HTTP 接口 "/api/v3/rag/documents/&lt;int:document_id&gt;/index", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/documents/&lt;int:document_id&gt;/index", methods=["POST"])</code> |
| L3080 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3081 | 定义rag2documentindex函数 &#96;rag2_document_index&#96;，封装可复用业务逻辑。 | <code>    def rag2_document_index(document_id: int):</code> |
| L3082 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_document_index。 | <code>        if not rag2_is_enabled():</code> |
| L3083 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_document_index。 | <code>            return jsonify({"error": "rag_disabled", "message": "RAG 已关闭，未调用云端向量 API"}), 409</code> |
| L3084 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_document_index。 | <code>        data_dir, api_config = rag2_runtime()</code> |
| L3085 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 rag2_document_index。 | <code>        try:</code> |
| L3086 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_document_index。 | <code>            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L3087 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 rag2_document_index。 | <code>                item = rag2_index_pending_document(conn, data_dir, api_config, document_id)</code> |
| L3088 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_document_index。 | <code>            return jsonify({"ok": True, "item": item})</code> |
| L3089 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 rag2_document_index。 | <code>        except (KeyError, RuntimeError) as exc:</code> |
| L3090 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_document_index。 | <code>            return jsonify({"error": "document_index_failed", "message": str(exc)}), 400</code> |
| L3091 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3092 | 注册 Flask HTTP 接口 "/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/chunks", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/chunks", methods=["GET"])</code> |
| L3093 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3094 | 定义rag2chunks函数 &#96;rag2_chunks&#96;，封装可复用业务逻辑。 | <code>    def rag2_chunks(kb_id: int):</code> |
| L3095 | 计算并保存 &#96;document_id&#96;（documentid），供后续逻辑使用，当前位于函数 rag2_chunks。 | <code>        document_id = int(request.args.get("document_id") or 0) or None</code> |
| L3096 | 计算并保存 &#96;summary&#96;（summary），供后续逻辑使用，当前位于函数 rag2_chunks。 | <code>        summary = str(request.args.get("summary") or "").strip().lower() in {"1", "true", "yes", "on"}</code> |
| L3097 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_chunks。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L3098 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 rag2_chunks。 | <code>            rows = rag2_list_chunks(conn, kb_id, document_id=document_id, include_content=not summary)</code> |
| L3099 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_chunks。 | <code>        return jsonify({"items": rows, "total": len(rows)})</code> |
| L3100 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3101 | 注册 Flask HTTP 接口 "/api/v3/rag/chunks/&lt;int:chunk_id&gt;", methods=["GET", "PUT"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/chunks/&lt;int:chunk_id&gt;", methods=["GET", "PUT"])</code> |
| L3102 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3103 | 定义rag2chunk更新函数 &#96;rag2_chunk_update&#96;，封装可复用业务逻辑。 | <code>    def rag2_chunk_update(chunk_id: int):</code> |
| L3104 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_chunk_update。 | <code>        if request.method == "GET":</code> |
| L3105 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_chunk_update。 | <code>            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L3106 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 rag2_chunk_update。 | <code>                item = rag2_get_chunk(conn, chunk_id)</code> |
| L3107 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_chunk_update。 | <code>            if not item:</code> |
| L3108 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_chunk_update。 | <code>                return jsonify({"error": "chunk_not_found", "message": "切片不存在"}), 404</code> |
| L3109 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_chunk_update。 | <code>            return jsonify({"item": item})</code> |
| L3110 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_chunk_update。 | <code>        if not rag2_is_enabled():</code> |
| L3111 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_chunk_update。 | <code>            return jsonify({"error": "rag_disabled", "message": "RAG 已关闭，未调用云端向量 API"}), 409</code> |
| L3112 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 rag2_chunk_update。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L3113 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_chunk_update。 | <code>        data_dir, api_config = rag2_runtime()</code> |
| L3114 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 rag2_chunk_update。 | <code>        try:</code> |
| L3115 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_chunk_update。 | <code>            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L3116 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_chunk_update。 | <code>                rag2_update_chunk(conn, data_dir, api_config, chunk_id, str(body.get("content") or ""), bool(body.get("enabled", True)))</code> |
| L3117 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 rag2_chunk_update。 | <code>        except (ValueError, KeyError, RuntimeError) as exc:</code> |
| L3118 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_chunk_update。 | <code>            return jsonify({"error": "chunk_update_failed", "message": str(exc)}), 400</code> |
| L3119 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_chunk_update。 | <code>        return jsonify({"ok": True})</code> |
| L3120 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3121 | 注册 Flask HTTP 接口 "/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/recall", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/recall", methods=["POST"])</code> |
| L3122 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3123 | 定义rag2recall函数 &#96;rag2_recall&#96;，封装可复用业务逻辑。 | <code>    def rag2_recall(kb_id: int):</code> |
| L3124 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_recall。 | <code>        if not rag2_is_enabled():</code> |
| L3125 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_recall。 | <code>            return jsonify({"error": "rag_disabled", "message": "RAG 已关闭，未调用云端召回 API"}), 409</code> |
| L3126 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 rag2_recall。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L3127 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_recall。 | <code>        data_dir, api_config = rag2_runtime()</code> |
| L3128 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 rag2_recall。 | <code>        try:</code> |
| L3129 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_recall。 | <code>            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L3130 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 rag2_recall。 | <code>                result = rag2_hybrid_search(conn, data_dir, api_config, kb_id, str(body.get("query") or ""), g.session["username"], save_test=True)</code> |
| L3131 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 rag2_recall。 | <code>        except (ValueError, KeyError, RuntimeError) as exc:</code> |
| L3132 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_recall。 | <code>            return jsonify({"error": "recall_failed", "message": str(exc)}), 400</code> |
| L3133 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_recall。 | <code>        return jsonify(result)</code> |
| L3134 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3135 | 注册 Flask HTTP 接口 "/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/recall-history", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/recall-history", methods=["GET"])</code> |
| L3136 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3137 | 定义rag2recallhistory函数 &#96;rag2_recall_history&#96;，封装可复用业务逻辑。 | <code>    def rag2_recall_history(kb_id: int):</code> |
| L3138 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_recall_history。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L3139 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 rag2_recall_history。 | <code>            rows = rag2_list_test_history(conn, kb_id)</code> |
| L3140 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_recall_history。 | <code>        return jsonify({"items": rows, "total": len(rows)})</code> |
| L3141 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3142 | 注册 Flask HTTP 接口 "/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/eval-cases", methods=["GET", "POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/eval-cases", methods=["GET", "POST"])</code> |
| L3143 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3144 | 定义rag2evalcases函数 &#96;rag2_eval_cases&#96;，封装可复用业务逻辑。 | <code>    def rag2_eval_cases(kb_id: int):</code> |
| L3145 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_eval_cases。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=request.method == "GET")) as conn:</code> |
| L3146 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_eval_cases。 | <code>            if request.method == "GET":</code> |
| L3147 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 rag2_eval_cases。 | <code>                rows = rag2_list_eval_cases(conn, kb_id)</code> |
| L3148 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_eval_cases。 | <code>                return jsonify({"items": rows, "total": len(rows)})</code> |
| L3149 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 rag2_eval_cases。 | <code>            try:</code> |
| L3150 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 rag2_eval_cases。 | <code>                item = rag2_save_eval_case(conn, kb_id, request.get_json(silent=True) or {})</code> |
| L3151 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 rag2_eval_cases。 | <code>            except (ValueError, KeyError) as exc:</code> |
| L3152 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_eval_cases。 | <code>                return jsonify({"error": "eval_case_save_failed", "message": str(exc)}), 400</code> |
| L3153 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_eval_cases。 | <code>        return jsonify({"ok": True, "item": item}), 201</code> |
| L3154 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3155 | 注册 Flask HTTP 接口 "/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/eval-cases/&lt;int:case_id&gt;", methods=["PUT", "POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/eval-cases/&lt;int:case_id&gt;", methods=["PUT", "POST"])</code> |
| L3156 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3157 | 定义rag2evalcase更新函数 &#96;rag2_eval_case_update&#96;，封装可复用业务逻辑。 | <code>    def rag2_eval_case_update(kb_id: int, case_id: int):</code> |
| L3158 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 rag2_eval_case_update。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L3159 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_eval_case_update。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L3160 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 rag2_eval_case_update。 | <code>            try:</code> |
| L3161 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_eval_case_update。 | <code>                if request.method == "POST" and body.get("action") == "delete":</code> |
| L3162 | 计算并保存 &#96;changed&#96;（changed），供后续逻辑使用，当前位于函数 rag2_eval_case_update。 | <code>                    changed = rag2_delete_eval_case(conn, kb_id, case_id)</code> |
| L3163 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_eval_case_update。 | <code>                    if not changed:</code> |
| L3164 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_eval_case_update。 | <code>                        return jsonify({"error": "eval_case_not_found"}), 404</code> |
| L3165 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_eval_case_update。 | <code>                    return jsonify({"ok": True})</code> |
| L3166 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 rag2_eval_case_update。 | <code>                item = rag2_save_eval_case(conn, kb_id, body, case_id=case_id)</code> |
| L3167 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 rag2_eval_case_update。 | <code>            except (ValueError, KeyError) as exc:</code> |
| L3168 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_eval_case_update。 | <code>                return jsonify({"error": "eval_case_save_failed", "message": str(exc)}), 400</code> |
| L3169 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_eval_case_update。 | <code>        return jsonify({"ok": True, "item": item})</code> |
| L3170 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3171 | 注册 Flask HTTP 接口 "/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/eval-runs", methods=["GET", "POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/knowledge-bases/&lt;int:kb_id&gt;/eval-runs", methods=["GET", "POST"])</code> |
| L3172 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3173 | 定义rag2evalruns函数 &#96;rag2_eval_runs&#96;，封装可复用业务逻辑。 | <code>    def rag2_eval_runs(kb_id: int):</code> |
| L3174 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_eval_runs。 | <code>        if request.method == "POST" and not rag2_is_enabled():</code> |
| L3175 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_eval_runs。 | <code>            return jsonify({"error": "rag_disabled", "message": "RAG 已关闭，未调用云端评估 API"}), 409</code> |
| L3176 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_eval_runs。 | <code>        data_dir, api_config = rag2_runtime()</code> |
| L3177 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_eval_runs。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=request.method == "GET")) as conn:</code> |
| L3178 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag2_eval_runs。 | <code>            if request.method == "GET":</code> |
| L3179 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 rag2_eval_runs。 | <code>                rows = rag2_list_eval_runs(conn, kb_id)</code> |
| L3180 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_eval_runs。 | <code>                return jsonify({"items": rows, "total": len(rows)})</code> |
| L3181 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 rag2_eval_runs。 | <code>            try:</code> |
| L3182 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 rag2_eval_runs。 | <code>                result = rag2_run_eval_suite(conn, data_dir, api_config, kb_id, g.session["username"])</code> |
| L3183 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 rag2_eval_runs。 | <code>            except (ValueError, KeyError, RuntimeError) as exc:</code> |
| L3184 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_eval_runs。 | <code>                return jsonify({"error": "eval_run_failed", "message": str(exc)}), 400</code> |
| L3185 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_eval_runs。 | <code>        return jsonify({"ok": True, **result})</code> |
| L3186 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3187 | 注册 Flask HTTP 接口 "/api/v2/rag/docs", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/rag/docs", methods=["GET"])</code> |
| L3188 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3189 | 定义ragdocs列出函数 &#96;rag_docs_list&#96;，封装可复用业务逻辑。 | <code>    def rag_docs_list():</code> |
| L3190 | 计算并保存 &#96;page&#96;（page），供后续逻辑使用，当前位于函数 rag_docs_list。 | <code>        page = max(1, int(request.args.get("page", "1")))</code> |
| L3191 | 计算并保存 &#96;page_size&#96;（pagesize），供后续逻辑使用，当前位于函数 rag_docs_list。 | <code>        page_size = max(1, min(int(request.args.get("page_size", "20")), 200))</code> |
| L3192 | 计算并保存 &#96;q&#96;（q），供后续逻辑使用，当前位于函数 rag_docs_list。 | <code>        q = request.args.get("q", "").strip()</code> |
| L3193 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 rag_docs_list。 | <code>        attack_type = request.args.get("attack_type", "").strip()</code> |
| L3194 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 rag_docs_list。 | <code>        payload = rag_list_docs(</code> |
| L3195 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_list。 | <code>            app.config["RAG_DB_PATH"],</code> |
| L3196 | 计算并保存 &#96;q&#96;（q），供后续逻辑使用，当前位于函数 rag_docs_list。 | <code>            q=q,</code> |
| L3197 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 rag_docs_list。 | <code>            attack_type=attack_type,</code> |
| L3198 | 计算并保存 &#96;page&#96;（page），供后续逻辑使用，当前位于函数 rag_docs_list。 | <code>            page=page,</code> |
| L3199 | 计算并保存 &#96;page_size&#96;（pagesize），供后续逻辑使用，当前位于函数 rag_docs_list。 | <code>            page_size=page_size,</code> |
| L3200 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 rag_docs_list。 | <code>        )</code> |
| L3201 | 结束当前函数并把结果返回给调用方，当前位于函数 rag_docs_list。 | <code>        return jsonify(payload)</code> |
| L3202 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3203 | 注册 Flask HTTP 接口 "/api/v2/rag/docs", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/rag/docs", methods=["POST"])</code> |
| L3204 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3205 | 定义ragdocsadd函数 &#96;rag_docs_add&#96;，封装可复用业务逻辑。 | <code>    def rag_docs_add():</code> |
| L3206 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 rag_docs_add。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L3207 | 计算并保存 &#96;title&#96;（title），供后续逻辑使用，当前位于函数 rag_docs_add。 | <code>        title = str(body.get("title", "")).strip()</code> |
| L3208 | 计算并保存 &#96;tags&#96;（tags），供后续逻辑使用，当前位于函数 rag_docs_add。 | <code>        tags = str(body.get("tags", "")).strip()</code> |
| L3209 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 rag_docs_add。 | <code>        attack_type = str(body.get("attack_type", "")).strip()</code> |
| L3210 | 计算并保存 &#96;content&#96;（content），供后续逻辑使用，当前位于函数 rag_docs_add。 | <code>        content = str(body.get("content", "")).strip()</code> |
| L3211 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 rag_docs_add。 | <code>        evidence = str(body.get("evidence", "")).strip()</code> |
| L3212 | 计算并保存 &#96;mitigation&#96;（mitigation），供后续逻辑使用，当前位于函数 rag_docs_add。 | <code>        mitigation = str(body.get("mitigation", "")).strip()</code> |
| L3213 | 计算并保存 &#96;severity&#96;（severity），供后续逻辑使用，当前位于函数 rag_docs_add。 | <code>        severity = str(body.get("severity", "medium")).strip().lower() or "medium"</code> |
| L3214 | 计算并保存 &#96;source&#96;（来源），供后续逻辑使用，当前位于函数 rag_docs_add。 | <code>        source = str(body.get("source", "")).strip() or f"user:{g.session['username']}"</code> |
| L3215 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3216 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag_docs_add。 | <code>        if not title or not content:</code> |
| L3217 | 结束当前函数并把结果返回给调用方，当前位于函数 rag_docs_add。 | <code>            return jsonify({"error": "title_and_content_required"}), 400</code> |
| L3218 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag_docs_add。 | <code>        if severity not in RAG_SEVERITY_SET:</code> |
| L3219 | 结束当前函数并把结果返回给调用方，当前位于函数 rag_docs_add。 | <code>            return jsonify({"error": "invalid_severity"}), 400</code> |
| L3220 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3221 | 计算并保存 &#96;doc_id&#96;（docid），供后续逻辑使用，当前位于函数 rag_docs_add。 | <code>        doc_id = str(body.get("doc_id", "")).strip() or f"USR-{uuid.uuid4().hex[:10].upper()}"</code> |
| L3222 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 rag_docs_add。 | <code>        row = {</code> |
| L3223 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_add。 | <code>            "doc_id": doc_id,</code> |
| L3224 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_add。 | <code>            "title": title,</code> |
| L3225 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_add。 | <code>            "tags": tags,</code> |
| L3226 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_add。 | <code>            "attack_type": attack_type,</code> |
| L3227 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_add。 | <code>            "content": content,</code> |
| L3228 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_add。 | <code>            "evidence": evidence,</code> |
| L3229 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_add。 | <code>            "mitigation": mitigation,</code> |
| L3230 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_add。 | <code>            "severity": severity,</code> |
| L3231 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_add。 | <code>            "source": source,</code> |
| L3232 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 rag_docs_add。 | <code>        }</code> |
| L3233 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_add。 | <code>        rag_upsert_doc(app.config["RAG_DB_PATH"], row)</code> |
| L3234 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag_docs_add。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L3235 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_add。 | <code>            log_action(</code> |
| L3236 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_add。 | <code>                conn,</code> |
| L3237 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_add。 | <code>                g.session["username"],</code> |
| L3238 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_add。 | <code>                g.session["role"],</code> |
| L3239 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_add。 | <code>                "rag_add_doc",</code> |
| L3240 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_add。 | <code>                doc_id,</code> |
| L3241 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_add。 | <code>                f"title={title[:60]}",</code> |
| L3242 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 rag_docs_add。 | <code>            )</code> |
| L3243 | 结束当前函数并把结果返回给调用方，当前位于函数 rag_docs_add。 | <code>        return jsonify({"ok": True, "doc_id": doc_id})</code> |
| L3244 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3245 | 注册 Flask HTTP 接口 "/api/v2/rag/docs/&lt;doc_id&gt;", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/rag/docs/&lt;doc_id&gt;", methods=["GET"])</code> |
| L3246 | 注册 Flask HTTP 接口 "/api/v2/rag/docs/&lt;doc_id&gt;/", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/rag/docs/&lt;doc_id&gt;/", methods=["GET"])</code> |
| L3247 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3248 | 定义ragdocsdetail函数 &#96;rag_docs_detail&#96;，封装可复用业务逻辑。 | <code>    def rag_docs_detail(doc_id: str):</code> |
| L3249 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 rag_docs_detail。 | <code>        row = rag_get_doc(app.config["RAG_DB_PATH"], doc_id=doc_id)</code> |
| L3250 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag_docs_detail。 | <code>        if not row:</code> |
| L3251 | 结束当前函数并把结果返回给调用方，当前位于函数 rag_docs_detail。 | <code>            return jsonify({"error": "doc_not_found"}), 404</code> |
| L3252 | 结束当前函数并把结果返回给调用方，当前位于函数 rag_docs_detail。 | <code>        return jsonify({"item": row})</code> |
| L3253 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3254 | 注册 Flask HTTP 接口 "/api/v2/rag/docs/&lt;doc_id&gt;", methods=["PUT"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/rag/docs/&lt;doc_id&gt;", methods=["PUT"])</code> |
| L3255 | 注册 Flask HTTP 接口 "/api/v2/rag/docs/&lt;doc_id&gt;/update", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/rag/docs/&lt;doc_id&gt;/update", methods=["POST"])</code> |
| L3256 | 注册 Flask HTTP 接口 "/api/v2/rag/docs/&lt;doc_id&gt;/update/", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/rag/docs/&lt;doc_id&gt;/update/", methods=["POST"])</code> |
| L3257 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3258 | 定义ragdocs更新函数 &#96;rag_docs_update&#96;，封装可复用业务逻辑。 | <code>    def rag_docs_update(doc_id: str):</code> |
| L3259 | 计算并保存 &#96;old&#96;（old），供后续逻辑使用，当前位于函数 rag_docs_update。 | <code>        old = rag_get_doc(app.config["RAG_DB_PATH"], doc_id=doc_id)</code> |
| L3260 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag_docs_update。 | <code>        if not old:</code> |
| L3261 | 结束当前函数并把结果返回给调用方，当前位于函数 rag_docs_update。 | <code>            return jsonify({"error": "doc_not_found"}), 404</code> |
| L3262 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3263 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 rag_docs_update。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L3264 | 计算并保存 &#96;title&#96;（title），供后续逻辑使用，当前位于函数 rag_docs_update。 | <code>        title = str(body.get("title", old.get("title", ""))).strip()</code> |
| L3265 | 计算并保存 &#96;tags&#96;（tags），供后续逻辑使用，当前位于函数 rag_docs_update。 | <code>        tags = str(body.get("tags", old.get("tags", ""))).strip()</code> |
| L3266 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 rag_docs_update。 | <code>        attack_type = str(body.get("attack_type", old.get("attack_type", ""))).strip()</code> |
| L3267 | 计算并保存 &#96;content&#96;（content），供后续逻辑使用，当前位于函数 rag_docs_update。 | <code>        content = str(body.get("content", old.get("content", ""))).strip()</code> |
| L3268 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 rag_docs_update。 | <code>        evidence = str(body.get("evidence", old.get("evidence", ""))).strip()</code> |
| L3269 | 计算并保存 &#96;mitigation&#96;（mitigation），供后续逻辑使用，当前位于函数 rag_docs_update。 | <code>        mitigation = str(body.get("mitigation", old.get("mitigation", ""))).strip()</code> |
| L3270 | 计算并保存 &#96;severity&#96;（severity），供后续逻辑使用，当前位于函数 rag_docs_update。 | <code>        severity = str(body.get("severity", old.get("severity", "medium"))).strip().lower() or "medium"</code> |
| L3271 | 计算并保存 &#96;source&#96;（来源），供后续逻辑使用，当前位于函数 rag_docs_update。 | <code>        source = str(body.get("source", old.get("source", ""))).strip() or old.get("source", "")</code> |
| L3272 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3273 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag_docs_update。 | <code>        if not title or not content:</code> |
| L3274 | 结束当前函数并把结果返回给调用方，当前位于函数 rag_docs_update。 | <code>            return jsonify({"error": "title_and_content_required"}), 400</code> |
| L3275 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag_docs_update。 | <code>        if severity not in RAG_SEVERITY_SET:</code> |
| L3276 | 结束当前函数并把结果返回给调用方，当前位于函数 rag_docs_update。 | <code>            return jsonify({"error": "invalid_severity"}), 400</code> |
| L3277 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3278 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 rag_docs_update。 | <code>        row = {</code> |
| L3279 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_update。 | <code>            "doc_id": doc_id,</code> |
| L3280 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_update。 | <code>            "title": title,</code> |
| L3281 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_update。 | <code>            "tags": tags,</code> |
| L3282 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_update。 | <code>            "attack_type": attack_type,</code> |
| L3283 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_update。 | <code>            "content": content,</code> |
| L3284 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_update。 | <code>            "evidence": evidence,</code> |
| L3285 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_update。 | <code>            "mitigation": mitigation,</code> |
| L3286 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_update。 | <code>            "severity": severity,</code> |
| L3287 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_update。 | <code>            "source": source,</code> |
| L3288 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 rag_docs_update。 | <code>        }</code> |
| L3289 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_update。 | <code>        rag_upsert_doc(app.config["RAG_DB_PATH"], row)</code> |
| L3290 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag_docs_update。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L3291 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_update。 | <code>            log_action(</code> |
| L3292 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_update。 | <code>                conn,</code> |
| L3293 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_update。 | <code>                g.session["username"],</code> |
| L3294 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_update。 | <code>                g.session["role"],</code> |
| L3295 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_update。 | <code>                "rag_update_doc",</code> |
| L3296 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_update。 | <code>                doc_id,</code> |
| L3297 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_update。 | <code>                f"title={title[:60]}",</code> |
| L3298 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 rag_docs_update。 | <code>            )</code> |
| L3299 | 结束当前函数并把结果返回给调用方，当前位于函数 rag_docs_update。 | <code>        return jsonify({"ok": True, "doc_id": doc_id, "item": row})</code> |
| L3300 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3301 | 注册 Flask HTTP 接口 "/api/v2/rag/docs/&lt;doc_id&gt;/delete", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/rag/docs/&lt;doc_id&gt;/delete", methods=["POST"])</code> |
| L3302 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3303 | 定义ragdocs删除函数 &#96;rag_docs_delete&#96;，封装可复用业务逻辑。 | <code>    def rag_docs_delete(doc_id: str):</code> |
| L3304 | 计算并保存 &#96;changed&#96;（changed），供后续逻辑使用，当前位于函数 rag_docs_delete。 | <code>        changed = rag_delete_doc(app.config["RAG_DB_PATH"], doc_id=doc_id)</code> |
| L3305 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rag_docs_delete。 | <code>        if changed == 0:</code> |
| L3306 | 结束当前函数并把结果返回给调用方，当前位于函数 rag_docs_delete。 | <code>            return jsonify({"error": "doc_not_found"}), 404</code> |
| L3307 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag_docs_delete。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L3308 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_docs_delete。 | <code>            log_action(conn, g.session["username"], g.session["role"], "rag_delete_doc", doc_id, "deleted")</code> |
| L3309 | 结束当前函数并把结果返回给调用方，当前位于函数 rag_docs_delete。 | <code>        return jsonify({"ok": True, "doc_id": doc_id})</code> |
| L3310 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3311 | 注册 Flask HTTP 接口 "/api/v2/rag/rebuild", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/rag/rebuild", methods=["POST"])</code> |
| L3312 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3313 | 定义ragrebuild接口函数 &#96;rag_rebuild_api&#96;，封装可复用业务逻辑。 | <code>    def rag_rebuild_api():</code> |
| L3314 | 计算并保存 &#96;count&#96;（count），供后续逻辑使用，当前位于函数 rag_rebuild_api。 | <code>        count = rag_rebuild_from_seed(app.config["RAG_DB_PATH"], app.config["RAG_SEED_PATH"])</code> |
| L3315 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag_rebuild_api。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L3316 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag_rebuild_api。 | <code>            log_action(conn, g.session["username"], g.session["role"], "rag_rebuild", "seed", f"count={count}")</code> |
| L3317 | 结束当前函数并把结果返回给调用方，当前位于函数 rag_rebuild_api。 | <code>        return jsonify({"ok": True, "rows": count})</code> |
| L3318 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3319 | 注册 Flask HTTP 接口 "/api/v2/plugins/phishing/check", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/plugins/phishing/check", methods=["POST"])</code> |
| L3320 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3321 | 定义pluginphishing检查函数 &#96;plugin_phishing_check&#96;，封装可复用业务逻辑。 | <code>    def plugin_phishing_check():</code> |
| L3322 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 plugin_phishing_check。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L3323 | 计算并保存 &#96;url_text&#96;（urltext），供后续逻辑使用，当前位于函数 plugin_phishing_check。 | <code>        url_text = str(body.get("url", "")).strip()</code> |
| L3324 | 计算并保存 &#96;token&#96;（token），供后续逻辑使用，当前位于函数 plugin_phishing_check。 | <code>        token = str(body.get("token", "")).strip()</code> |
| L3325 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 plugin_phishing_check。 | <code>        if not url_text or not token:</code> |
| L3326 | 结束当前函数并把结果返回给调用方，当前位于函数 plugin_phishing_check。 | <code>            return jsonify({"error": "url_and_token_required"}), 400</code> |
| L3327 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 plugin_phishing_check。 | <code>        if not re.match(r"^https?://", url_text, flags=re.IGNORECASE):</code> |
| L3328 | 结束当前函数并把结果返回给调用方，当前位于函数 plugin_phishing_check。 | <code>            return jsonify({"error": "invalid_url", "message": "url must start with http:// or https://"}), 400</code> |
| L3329 | 计算并保存 &#96;exp_ts&#96;（expts），供后续逻辑使用，当前位于函数 plugin_phishing_check。 | <code>        exp_ts = read_jwt_exp_unverified(token)</code> |
| L3330 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 plugin_phishing_check。 | <code>        if exp_ts is not None and exp_ts &lt;= int(now_dt().timestamp()):</code> |
| L3331 | 结束当前函数并把结果返回给调用方，当前位于函数 plugin_phishing_check。 | <code>            return (</code> |
| L3332 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>                jsonify(</code> |
| L3333 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>                    {</code> |
| L3334 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>                        "error": "token_expired",</code> |
| L3335 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>                        "message": "token已过期，请更换新的token",</code> |
| L3336 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>                        "expired_at": dt_to_str(datetime.fromtimestamp(exp_ts), ms=False),</code> |
| L3337 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 plugin_phishing_check。 | <code>                    }</code> |
| L3338 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 plugin_phishing_check。 | <code>                ),</code> |
| L3339 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>                400,</code> |
| L3340 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 plugin_phishing_check。 | <code>            )</code> |
| L3341 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3342 | 计算并保存 &#96;upstream&#96;（upstream），供后续逻辑使用，当前位于函数 plugin_phishing_check。 | <code>        upstream = "http://ctf.ski:9898/?" + urllib.parse.urlencode({"url": url_text, "token": token})</code> |
| L3343 | 计算并保存 &#96;req&#96;（req），供后续逻辑使用，当前位于函数 plugin_phishing_check。 | <code>        req = urllib.request.Request(upstream, method="GET")</code> |
| L3344 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 plugin_phishing_check。 | <code>        try:</code> |
| L3345 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 plugin_phishing_check。 | <code>            with urllib.request.urlopen(req, timeout=20) as resp:</code> |
| L3346 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 plugin_phishing_check。 | <code>                payload = resp.read().decode("utf-8", errors="replace")</code> |
| L3347 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 plugin_phishing_check。 | <code>                data = json.loads(payload)</code> |
| L3348 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 plugin_phishing_check。 | <code>        except urllib.error.HTTPError as exc:</code> |
| L3349 | 计算并保存 &#96;detail&#96;（detail），供后续逻辑使用，当前位于函数 plugin_phishing_check。 | <code>            detail = ""</code> |
| L3350 | 计算并保存 &#96;message&#96;（message），供后续逻辑使用，当前位于函数 plugin_phishing_check。 | <code>            message = ""</code> |
| L3351 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 plugin_phishing_check。 | <code>            try:</code> |
| L3352 | 计算并保存 &#96;detail&#96;（detail），供后续逻辑使用，当前位于函数 plugin_phishing_check。 | <code>                detail = exc.read().decode("utf-8", errors="replace").strip()</code> |
| L3353 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 plugin_phishing_check。 | <code>                if detail:</code> |
| L3354 | 计算并保存 &#96;body_obj&#96;（bodyobj），供后续逻辑使用，当前位于函数 plugin_phishing_check。 | <code>                    body_obj = json.loads(detail)</code> |
| L3355 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 plugin_phishing_check。 | <code>                    if isinstance(body_obj, dict):</code> |
| L3356 | 计算并保存 &#96;message&#96;（message），供后续逻辑使用，当前位于函数 plugin_phishing_check。 | <code>                        message = str(body_obj.get("msg") or body_obj.get("message") or body_obj.get("error") or "").strip()</code> |
| L3357 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 plugin_phishing_check。 | <code>            except Exception:</code> |
| L3358 | 计算并保存 &#96;detail&#96;（detail），供后续逻辑使用，当前位于函数 plugin_phishing_check。 | <code>                detail = ""</code> |
| L3359 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 plugin_phishing_check。 | <code>            if not message and int(exc.code) == 401:</code> |
| L3360 | 计算并保存 &#96;message&#96;（message），供后续逻辑使用，当前位于函数 plugin_phishing_check。 | <code>                message = "上游鉴权失败，token可能无效或已过期"</code> |
| L3361 | 计算并保存 &#96;resp_obj&#96;（respobj），供后续逻辑使用，当前位于函数 plugin_phishing_check。 | <code>            resp_obj: Dict[str, Any] = {"error": "upstream_http_error", "status": int(exc.code)}</code> |
| L3362 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 plugin_phishing_check。 | <code>            if message:</code> |
| L3363 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>                resp_obj["message"] = message</code> |
| L3364 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 plugin_phishing_check。 | <code>            if detail:</code> |
| L3365 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>                resp_obj["detail"] = detail[:400]</code> |
| L3366 | 结束当前函数并把结果返回给调用方，当前位于函数 plugin_phishing_check。 | <code>            return jsonify(resp_obj), 502</code> |
| L3367 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 plugin_phishing_check。 | <code>        except urllib.error.URLError as exc:</code> |
| L3368 | 结束当前函数并把结果返回给调用方，当前位于函数 plugin_phishing_check。 | <code>            return jsonify({"error": "upstream_unreachable", "detail": str(exc.reason)}), 502</code> |
| L3369 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 plugin_phishing_check。 | <code>        except Exception as exc:</code> |
| L3370 | 结束当前函数并把结果返回给调用方，当前位于函数 plugin_phishing_check。 | <code>            return jsonify({"error": "upstream_parse_error", "detail": str(exc)}), 502</code> |
| L3371 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3372 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 plugin_phishing_check。 | <code>        result = {</code> |
| L3373 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>            "action": data.get("action"),</code> |
| L3374 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>            "verdict": data.get("verdict"),</code> |
| L3375 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>            "confidence": data.get("confidence"),</code> |
| L3376 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>            "reason": data.get("reason"),</code> |
| L3377 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>            "evidence": data.get("evidence") if isinstance(data.get("evidence"), list) else [],</code> |
| L3378 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 plugin_phishing_check。 | <code>        }</code> |
| L3379 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 plugin_phishing_check。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L3380 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>            log_action(</code> |
| L3381 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>                conn,</code> |
| L3382 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>                g.session["username"],</code> |
| L3383 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>                g.session["role"],</code> |
| L3384 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>                "plugin_phishing_check",</code> |
| L3385 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>                url_text[:120],</code> |
| L3386 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_phishing_check。 | <code>                f"verdict={result.get('verdict')},confidence={result.get('confidence')}",</code> |
| L3387 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 plugin_phishing_check。 | <code>            )</code> |
| L3388 | 结束当前函数并把结果返回给调用方，当前位于函数 plugin_phishing_check。 | <code>        return jsonify(result)</code> |
| L3389 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3390 | 注册 Flask HTTP 接口 "/api/v2/plugins/ip-analyze", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/plugins/ip-analyze", methods=["POST"])</code> |
| L3391 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3392 | 定义pluginipanalyze函数 &#96;plugin_ip_analyze&#96;，封装可复用业务逻辑。 | <code>    def plugin_ip_analyze():</code> |
| L3393 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 plugin_ip_analyze。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L3394 | 计算并保存 &#96;ip_raw&#96;（ipraw），供后续逻辑使用，当前位于函数 plugin_ip_analyze。 | <code>        ip_raw = str(body.get("ip", "")).strip()</code> |
| L3395 | 计算并保存 &#96;ip_norm&#96;（ipnorm），供后续逻辑使用，当前位于函数 plugin_ip_analyze。 | <code>        ip_norm = normalize_ip_literal(ip_raw)</code> |
| L3396 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 plugin_ip_analyze。 | <code>        if not ip_norm:</code> |
| L3397 | 结束当前函数并把结果返回给调用方，当前位于函数 plugin_ip_analyze。 | <code>            return jsonify({"error": "invalid_ip", "message": "请输入合法的 IPv4/IPv6 地址"}), 400</code> |
| L3398 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3399 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 plugin_ip_analyze。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L3400 | 计算并保存 &#96;region&#96;（region），供后续逻辑使用，当前位于函数 plugin_ip_analyze。 | <code>            region = resolve_region_for_event(conn, ip_norm, "")</code> |
| L3401 | 计算并保存 &#96;cache_source&#96;（cache来源），供后续逻辑使用，当前位于函数 plugin_ip_analyze。 | <code>            cache_source = ""</code> |
| L3402 | 计算并保存 &#96;updated_at&#96;（updatedat），供后续逻辑使用，当前位于函数 plugin_ip_analyze。 | <code>            updated_at = None</code> |
| L3403 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 plugin_ip_analyze。 | <code>            with conn.cursor() as cur:</code> |
| L3404 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 plugin_ip_analyze。 | <code>                cur.execute("SELECT source, updated_at FROM ip_geo_cache WHERE ip=%s LIMIT 1", (ip_norm,))</code> |
| L3405 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 plugin_ip_analyze。 | <code>                row = cur.fetchone() or {}</code> |
| L3406 | 计算并保存 &#96;cache_source&#96;（cache来源），供后续逻辑使用，当前位于函数 plugin_ip_analyze。 | <code>                cache_source = str(row.get("source") or "")</code> |
| L3407 | 计算并保存 &#96;updated_at&#96;（updatedat），供后续逻辑使用，当前位于函数 plugin_ip_analyze。 | <code>                updated_at = row.get("updated_at")</code> |
| L3408 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_ip_analyze。 | <code>            log_action(</code> |
| L3409 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_ip_analyze。 | <code>                conn,</code> |
| L3410 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_ip_analyze。 | <code>                g.session["username"],</code> |
| L3411 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_ip_analyze。 | <code>                g.session["role"],</code> |
| L3412 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_ip_analyze。 | <code>                "plugin_ip_analyze",</code> |
| L3413 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_ip_analyze。 | <code>                ip_norm,</code> |
| L3414 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_ip_analyze。 | <code>                f"region={region}",</code> |
| L3415 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 plugin_ip_analyze。 | <code>            )</code> |
| L3416 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_ip_analyze。 | <code>            conn.commit()</code> |
| L3417 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3418 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 plugin_ip_analyze。 | <code>        if not cache_source:</code> |
| L3419 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_ip_analyze。 | <code>            cache_source = "private" if region == "内网" else ("fallback" if region == "未知" else "remote")</code> |
| L3420 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3421 | 结束当前函数并把结果返回给调用方，当前位于函数 plugin_ip_analyze。 | <code>        return jsonify(</code> |
| L3422 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_ip_analyze。 | <code>            {</code> |
| L3423 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_ip_analyze。 | <code>                "ip": ip_norm,</code> |
| L3424 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_ip_analyze。 | <code>                "region": region,</code> |
| L3425 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_ip_analyze。 | <code>                "is_public": bool(is_public_ip(ip_norm)),</code> |
| L3426 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_ip_analyze。 | <code>                "source": cache_source,</code> |
| L3427 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_ip_analyze。 | <code>                "updated_at": dt_to_str(updated_at, ms=True) if isinstance(updated_at, datetime) else normalize_value(updated_at),</code> |
| L3428 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 plugin_ip_analyze。 | <code>            }</code> |
| L3429 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 plugin_ip_analyze。 | <code>        )</code> |
| L3430 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3431 | 注册 Flask HTTP 接口 "/api/v2/plugins/local-status", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/plugins/local-status", methods=["GET"])</code> |
| L3432 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3433 | 定义pluginlocal状态函数 &#96;plugin_local_status&#96;，封装可复用业务逻辑。 | <code>    def plugin_local_status():</code> |
| L3434 | 计算并保存 &#96;snapshot&#96;（snapshot），供后续逻辑使用，当前位于函数 plugin_local_status。 | <code>        snapshot = collect_local_system_status()</code> |
| L3435 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 plugin_local_status。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L3436 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_local_status。 | <code>            log_action(</code> |
| L3437 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_local_status。 | <code>                conn,</code> |
| L3438 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_local_status。 | <code>                g.session["username"],</code> |
| L3439 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_local_status。 | <code>                g.session["role"],</code> |
| L3440 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_local_status。 | <code>                "plugin_local_status",</code> |
| L3441 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_local_status。 | <code>                snapshot.get("hostname") or "",</code> |
| L3442 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 plugin_local_status。 | <code>                f"cpu={snapshot.get('cpu_percent')}",</code> |
| L3443 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 plugin_local_status。 | <code>            )</code> |
| L3444 | 结束当前函数并把结果返回给调用方，当前位于函数 plugin_local_status。 | <code>        return jsonify(snapshot)</code> |
| L3445 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3446 | 注册 Flask HTTP 接口 "/api/v2/user/dashboard/kpis", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/user/dashboard/kpis", methods=["GET"])</code> |
| L3447 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3448 | 定义userkpis函数 &#96;user_kpis&#96;，封装可复用业务逻辑。 | <code>    def user_kpis():</code> |
| L3449 | 计算并保存 &#96;visible_sql&#96;（visiblesql），供后续逻辑使用，当前位于函数 user_kpis。 | <code>        visible_sql = visible_attack_event_clause()</code> |
| L3450 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 user_kpis。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L3451 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>            refresh_machine_stats(conn)</code> |
| L3452 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 user_kpis。 | <code>            with conn.cursor() as cur:</code> |
| L3453 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 user_kpis。 | <code>                cur.execute(f"SELECT COUNT(*) AS c FROM demo_attack_events WHERE DATE(occurred_at)=CURDATE() AND {visible_sql}")</code> |
| L3454 | 计算并保存 &#96;today_total&#96;（todaytotal），供后续逻辑使用，当前位于函数 user_kpis。 | <code>                today_total = int((cur.fetchone() or {}).get("c", 0))</code> |
| L3455 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 user_kpis。 | <code>                cur.execute(</code> |
| L3456 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                    f"""</code> |
| L3457 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 user_kpis。 | <code>                    SELECT COUNT(*) AS c</code> |
| L3458 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                    FROM demo_attack_events</code> |
| L3459 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                    WHERE DATE(occurred_at)=DATE_SUB(CURDATE(), INTERVAL 1 DAY) AND {visible_sql}</code> |
| L3460 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                    """</code> |
| L3461 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 user_kpis。 | <code>                )</code> |
| L3462 | 计算并保存 &#96;yesterday_total&#96;（yesterdaytotal），供后续逻辑使用，当前位于函数 user_kpis。 | <code>                yesterday_total = int((cur.fetchone() or {}).get("c", 0))</code> |
| L3463 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 user_kpis。 | <code>                cur.execute(</code> |
| L3464 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                    f"""</code> |
| L3465 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 user_kpis。 | <code>                    SELECT COUNT(*) AS c</code> |
| L3466 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                    FROM demo_attack_events</code> |
| L3467 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                    WHERE risk_level IN ('critical','high') AND process_status IN ('unprocessed','processing') AND {visible_sql}</code> |
| L3468 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                    """</code> |
| L3469 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 user_kpis。 | <code>                )</code> |
| L3470 | 计算并保存 &#96;high_active&#96;（highactive），供后续逻辑使用，当前位于函数 user_kpis。 | <code>                high_active = int((cur.fetchone() or {}).get("c", 0))</code> |
| L3471 | 计算并保存 &#96;today_situations&#96;（todaysituations），供后续逻辑使用，当前位于函数 user_kpis。 | <code>                today_situations = 0</code> |
| L3472 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 user_kpis。 | <code>                if db_table_exists(cur, "attack_situations"):</code> |
| L3473 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 user_kpis。 | <code>                    cur.execute("SELECT COUNT(*) AS c FROM attack_situations WHERE DATE(created_at)=CURDATE()")</code> |
| L3474 | 计算并保存 &#96;today_situations&#96;（todaysituations），供后续逻辑使用，当前位于函数 user_kpis。 | <code>                    today_situations = int((cur.fetchone() or {}).get("c") or 0)</code> |
| L3475 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 user_kpis。 | <code>                cur.execute(</code> |
| L3476 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 user_kpis。 | <code>                    """</code> |
| L3477 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 user_kpis。 | <code>                    SELECT AVG(defense_latency_ms) / 1000.0 AS avg_seconds, COUNT(*) AS sample_count</code> |
| L3478 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 user_kpis。 | <code>                    FROM demo_fast_defense_audit</code> |
| L3479 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 user_kpis。 | <code>                    WHERE DATE(created_at)=CURDATE()</code> |
| L3480 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 user_kpis。 | <code>                      AND decision='silent_block'</code> |
| L3481 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 user_kpis。 | <code>                      AND firewall_success=1</code> |
| L3482 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 user_kpis。 | <code>                      AND defense_latency_ms IS NOT NULL</code> |
| L3483 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 user_kpis。 | <code>                      AND defense_latency_ms &gt;= 0</code> |
| L3484 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 user_kpis。 | <code>                    """</code> |
| L3485 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 user_kpis。 | <code>                )</code> |
| L3486 | 计算并保存 &#96;defense_obj&#96;（defenseobj），供后续逻辑使用，当前位于函数 user_kpis。 | <code>                defense_obj = cur.fetchone() or {}</code> |
| L3487 | 计算并保存 &#96;avg_defense_seconds&#96;（avgdefenseseconds），供后续逻辑使用，当前位于函数 user_kpis。 | <code>                avg_defense_seconds = float(defense_obj.get("avg_seconds") or 0)</code> |
| L3488 | 计算并保存 &#96;defense_samples&#96;（defensesamples），供后续逻辑使用，当前位于函数 user_kpis。 | <code>                defense_samples = int(defense_obj.get("sample_count") or 0)</code> |
| L3489 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 user_kpis。 | <code>                cur.execute(</code> |
| L3490 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                    f"""</code> |
| L3491 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 user_kpis。 | <code>                    SELECT COUNT(*) AS c</code> |
| L3492 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                    FROM demo_attack_events</code> |
| L3493 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                    WHERE DATE(occurred_at)=CURDATE() AND anomaly_detected=1 AND {visible_sql}</code> |
| L3494 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                    """</code> |
| L3495 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 user_kpis。 | <code>                )</code> |
| L3496 | 计算并保存 &#96;anomaly_cnt&#96;（anomalycnt），供后续逻辑使用，当前位于函数 user_kpis。 | <code>                anomaly_cnt = int((cur.fetchone() or {}).get("c", 0))</code> |
| L3497 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 user_kpis。 | <code>                cur.execute("SELECT COUNT(*) AS c FROM demo_machines WHERE online_status='online'")</code> |
| L3498 | 计算并保存 &#96;online_nodes&#96;（onlinenodes），供后续逻辑使用，当前位于函数 user_kpis。 | <code>                online_nodes = int((cur.fetchone() or {}).get("c", 0))</code> |
| L3499 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>            conn.commit()</code> |
| L3500 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3501 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>        yoy = 0.0 if yesterday_total == 0 else ((today_total - yesterday_total) / yesterday_total) * 100.0</code> |
| L3502 | 结束当前函数并把结果返回给调用方，当前位于函数 user_kpis。 | <code>        return jsonify(</code> |
| L3503 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>            {</code> |
| L3504 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                "today_attack_total": today_total,</code> |
| L3505 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                "yoy_percent": round(yoy, 2),</code> |
| L3506 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                "active_high_alerts": high_active,</code> |
| L3507 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                "today_situation_total": today_situations,</code> |
| L3508 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                "avg_auto_defense_block_seconds": round(avg_defense_seconds, 2),</code> |
| L3509 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                "auto_defense_block_samples": defense_samples,</code> |
| L3510 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                "today_anomaly_detected": anomaly_cnt,</code> |
| L3511 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 user_kpis。 | <code>                "online_protection_nodes": online_nodes,</code> |
| L3512 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 user_kpis。 | <code>            }</code> |
| L3513 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 user_kpis。 | <code>        )</code> |
| L3514 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3515 | 注册 Flask HTTP 接口 "/api/v2/user/dashboard/trend7d", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/user/dashboard/trend7d", methods=["GET"])</code> |
| L3516 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3517 | 定义trend7d函数 &#96;trend7d&#96;，封装可复用业务逻辑。 | <code>    def trend7d():</code> |
| L3518 | 计算并保存 &#96;visible_sql&#96;（visiblesql），供后续逻辑使用，当前位于函数 trend7d。 | <code>        visible_sql = visible_attack_event_clause()</code> |
| L3519 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 trend7d。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L3520 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 trend7d。 | <code>            with conn.cursor() as cur:</code> |
| L3521 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 trend7d。 | <code>                cur.execute(</code> |
| L3522 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 trend7d。 | <code>                    f"""</code> |
| L3523 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 trend7d。 | <code>                    SELECT</code> |
| L3524 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 trend7d。 | <code>                      DATE(occurred_at) AS d,</code> |
| L3525 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 trend7d。 | <code>                      COUNT(*) AS total,</code> |
| L3526 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 trend7d。 | <code>                      SUM(CASE WHEN attack_result='blocked' THEN 1 ELSE 0 END) AS blocked</code> |
| L3527 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 trend7d。 | <code>                    FROM demo_attack_events</code> |
| L3528 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 trend7d。 | <code>                    WHERE occurred_at &gt;= DATE_SUB(CURDATE(), INTERVAL 6 DAY) AND {visible_sql}</code> |
| L3529 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 trend7d。 | <code>                    GROUP BY DATE(occurred_at)</code> |
| L3530 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 trend7d。 | <code>                    ORDER BY d</code> |
| L3531 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 trend7d。 | <code>                    """</code> |
| L3532 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 trend7d。 | <code>                )</code> |
| L3533 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 trend7d。 | <code>                rows = cur.fetchall()</code> |
| L3534 | 计算并保存 &#96;by_day&#96;（byday），供后续逻辑使用，当前位于函数 trend7d。 | <code>        by_day = {row["d"]: row for row in rows}</code> |
| L3535 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 trend7d。 | <code>        items = []</code> |
| L3536 | 计算并保存 &#96;max_total&#96;（maxtotal），供后续逻辑使用，当前位于函数 trend7d。 | <code>        max_total = 0</code> |
| L3537 | 遍历集合中的数据项并逐项处理，当前位于函数 trend7d。 | <code>        for i in range(6, -1, -1):</code> |
| L3538 | 计算并保存 &#96;day&#96;（day），供后续逻辑使用，当前位于函数 trend7d。 | <code>            day = (now_dt() - timedelta(days=i)).date()</code> |
| L3539 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 trend7d。 | <code>            row = by_day.get(day)</code> |
| L3540 | 计算并保存 &#96;total&#96;（total），供后续逻辑使用，当前位于函数 trend7d。 | <code>            total = int((row or {}).get("total") or 0)</code> |
| L3541 | 计算并保存 &#96;blocked&#96;（blocked），供后续逻辑使用，当前位于函数 trend7d。 | <code>            blocked = int((row or {}).get("blocked") or 0)</code> |
| L3542 | 计算并保存 &#96;max_total&#96;（maxtotal），供后续逻辑使用，当前位于函数 trend7d。 | <code>            max_total = max(max_total, total)</code> |
| L3543 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 trend7d。 | <code>            items.append({"date": str(day), "total_attack": total, "blocked_attack": blocked, "is_peak": False})</code> |
| L3544 | 遍历集合中的数据项并逐项处理，当前位于函数 trend7d。 | <code>        for row in items:</code> |
| L3545 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 trend7d。 | <code>            if row["total_attack"] == max_total and max_total &gt; 0:</code> |
| L3546 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 trend7d。 | <code>                row["is_peak"] = True</code> |
| L3547 | 结束当前函数并把结果返回给调用方，当前位于函数 trend7d。 | <code>        return jsonify({"items": items})</code> |
| L3548 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3549 | 注册 Flask HTTP 接口 "/api/v2/user/dashboard/top-attack-types", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/user/dashboard/top-attack-types", methods=["GET"])</code> |
| L3550 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3551 | 定义top攻击types函数 &#96;top_attack_types&#96;，封装可复用业务逻辑。 | <code>    def top_attack_types():</code> |
| L3552 | 计算并保存 &#96;visible_sql&#96;（visiblesql），供后续逻辑使用，当前位于函数 top_attack_types。 | <code>        visible_sql = visible_attack_event_clause()</code> |
| L3553 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 top_attack_types。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L3554 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 top_attack_types。 | <code>            with conn.cursor() as cur:</code> |
| L3555 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 top_attack_types。 | <code>                cur.execute(</code> |
| L3556 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 top_attack_types。 | <code>                    f"""</code> |
| L3557 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 top_attack_types。 | <code>                    SELECT attack_type, COUNT(*) AS total</code> |
| L3558 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 top_attack_types。 | <code>                    FROM demo_attack_events</code> |
| L3559 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 top_attack_types。 | <code>                    WHERE occurred_at &gt;= DATE_SUB(NOW(), INTERVAL 7 DAY) AND {visible_sql}</code> |
| L3560 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 top_attack_types。 | <code>                    GROUP BY attack_type</code> |
| L3561 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 top_attack_types。 | <code>                    ORDER BY total DESC</code> |
| L3562 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 top_attack_types。 | <code>                    """</code> |
| L3563 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 top_attack_types。 | <code>                )</code> |
| L3564 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 top_attack_types。 | <code>                rows = cur.fetchall()</code> |
| L3565 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 top_attack_types。 | <code>        items = aggregate_counts_by_label(rows, "attack_type")[:10]</code> |
| L3566 | 结束当前函数并把结果返回给调用方，当前位于函数 top_attack_types。 | <code>        return jsonify({"items": normalize_rows(items)})</code> |
| L3567 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3568 | 注册 Flask HTTP 接口 "/api/v2/user/dashboard/source-distribution", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/user/dashboard/source-distribution", methods=["GET"])</code> |
| L3569 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3570 | 定义来源distribution函数 &#96;source_distribution&#96;，封装可复用业务逻辑。 | <code>    def source_distribution():</code> |
| L3571 | 计算并保存 &#96;visible_sql&#96;（visiblesql），供后续逻辑使用，当前位于函数 source_distribution。 | <code>        visible_sql = visible_attack_event_clause()</code> |
| L3572 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 source_distribution。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L3573 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 source_distribution。 | <code>            with conn.cursor() as cur:</code> |
| L3574 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 source_distribution。 | <code>                cur.execute(</code> |
| L3575 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_distribution。 | <code>                    f"""</code> |
| L3576 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 source_distribution。 | <code>                    SELECT source_ip, source_region, COUNT(*) AS total</code> |
| L3577 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_distribution。 | <code>                    FROM demo_attack_events</code> |
| L3578 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_distribution。 | <code>                    WHERE occurred_at &gt;= DATE_SUB(NOW(), INTERVAL 7 DAY) AND {visible_sql}</code> |
| L3579 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_distribution。 | <code>                    GROUP BY source_ip, source_region</code> |
| L3580 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_distribution。 | <code>                    """</code> |
| L3581 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 source_distribution。 | <code>                )</code> |
| L3582 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 source_distribution。 | <code>                rows = cur.fetchall()</code> |
| L3583 | 计算并保存 &#96;region_bucket&#96;（regionbucket），供后续逻辑使用，当前位于函数 source_distribution。 | <code>            region_bucket: Dict[str, int] = {}</code> |
| L3584 | 遍历集合中的数据项并逐项处理，当前位于函数 source_distribution。 | <code>            for row in rows:</code> |
| L3585 | 计算并保存 &#96;count&#96;（count），供后续逻辑使用，当前位于函数 source_distribution。 | <code>                count = int(row.get("total") or 0)</code> |
| L3586 | 计算并保存 &#96;region&#96;（region），供后续逻辑使用，当前位于函数 source_distribution。 | <code>                region = resolve_region_for_event(</code> |
| L3587 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_distribution。 | <code>                    conn,</code> |
| L3588 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_distribution。 | <code>                    str(row.get("source_ip") or ""),</code> |
| L3589 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_distribution。 | <code>                    str(row.get("source_region") or ""),</code> |
| L3590 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 source_distribution。 | <code>                )</code> |
| L3591 | 计算并保存 &#96;region&#96;（region），供后续逻辑使用，当前位于函数 source_distribution。 | <code>                region = simplify_source_region_for_dashboard(region)</code> |
| L3592 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_distribution。 | <code>                region_bucket[region] = region_bucket.get(region, 0) + count</code> |
| L3593 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 source_distribution。 | <code>        items = [{"source_region": k, "total": v} for k, v in region_bucket.items()]</code> |
| L3594 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_distribution。 | <code>        items.sort(key=lambda x: int(x.get("total") or 0), reverse=True)</code> |
| L3595 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 source_distribution。 | <code>        items = items[:7]</code> |
| L3596 | 结束当前函数并把结果返回给调用方，当前位于函数 source_distribution。 | <code>        return jsonify({"items": normalize_rows(items)})</code> |
| L3597 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3598 | 注册 Flask HTTP 接口 "/api/v2/user/dashboard/source-map", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/user/dashboard/source-map", methods=["GET"])</code> |
| L3599 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3600 | 定义来源map函数 &#96;source_map&#96;，封装可复用业务逻辑。 | <code>    def source_map():</code> |
| L3601 | 计算并保存 &#96;visible_sql&#96;（visiblesql），供后续逻辑使用，当前位于函数 source_map。 | <code>        visible_sql = visible_attack_event_clause()</code> |
| L3602 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 source_map。 | <code>        try:</code> |
| L3603 | 计算并保存 &#96;days&#96;（days），供后续逻辑使用，当前位于函数 source_map。 | <code>            days = max(1, min(90, int(request.args.get("days", 30))))</code> |
| L3604 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 source_map。 | <code>        except ValueError:</code> |
| L3605 | 计算并保存 &#96;days&#96;（days），供后续逻辑使用，当前位于函数 source_map。 | <code>            days = 30</code> |
| L3606 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 source_map。 | <code>        try:</code> |
| L3607 | 计算并保存 &#96;limit&#96;（limit），供后续逻辑使用，当前位于函数 source_map。 | <code>            limit = max(1, min(50, int(request.args.get("limit", 10))))</code> |
| L3608 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 source_map。 | <code>        except ValueError:</code> |
| L3609 | 计算并保存 &#96;limit&#96;（limit），供后续逻辑使用，当前位于函数 source_map。 | <code>            limit = 10</code> |
| L3610 | 计算并保存 &#96;candidate_limit&#96;（candidatelimit），供后续逻辑使用，当前位于函数 source_map。 | <code>        candidate_limit = max(100, limit * 4)</code> |
| L3611 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3612 | 定义collect数据库记录函数 &#96;collect_rows&#96;，封装可复用业务逻辑。 | <code>        def collect_rows(time_filter_sql: str) -&gt; List[Dict[str, Any]]:</code> |
| L3613 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 collect_rows。 | <code>            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L3614 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 collect_rows。 | <code>                with conn.cursor() as cur:</code> |
| L3615 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 collect_rows。 | <code>                    cur.execute(</code> |
| L3616 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_rows。 | <code>                        f"""</code> |
| L3617 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 collect_rows。 | <code>                        SELECT source_ip, source_region, COUNT(*) AS total, MAX(occurred_at) AS latest_at</code> |
| L3618 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_rows。 | <code>                        FROM demo_attack_events</code> |
| L3619 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_rows。 | <code>                        WHERE {time_filter_sql} AND {visible_sql}</code> |
| L3620 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_rows。 | <code>                        GROUP BY source_ip, source_region</code> |
| L3621 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_rows。 | <code>                        ORDER BY latest_at DESC</code> |
| L3622 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_rows。 | <code>                        LIMIT {candidate_limit}</code> |
| L3623 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_rows。 | <code>                        """</code> |
| L3624 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 collect_rows。 | <code>                    )</code> |
| L3625 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 collect_rows。 | <code>                    rows = cur.fetchall()</code> |
| L3626 | 结束当前函数并把结果返回给调用方，当前位于函数 collect_rows。 | <code>                return build_source_map_items(conn, rows)</code> |
| L3627 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3628 | 计算并保存 &#96;recent_items&#96;（recent数据项），供后续逻辑使用，当前位于函数 source_map。 | <code>        recent_items = collect_rows(f"occurred_at &gt;= DATE_SUB(NOW(), INTERVAL {days} DAY)")</code> |
| L3629 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 source_map。 | <code>        items = [{**item, "historical_supplement": False} for item in recent_items[:limit]]</code> |
| L3630 | 计算并保存 &#96;historical_supplement_count&#96;（historicalsupplementcount），供后续逻辑使用，当前位于函数 source_map。 | <code>        historical_supplement_count = 0</code> |
| L3631 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 source_map。 | <code>        if len(items) &lt; limit:</code> |
| L3632 | 计算并保存 &#96;seen_cities&#96;（seencities），供后续逻辑使用，当前位于函数 source_map。 | <code>            seen_cities = {str(item.get("source_city") or item.get("source_region") or "").casefold() for item in items}</code> |
| L3633 | 遍历集合中的数据项并逐项处理，当前位于函数 source_map。 | <code>            for item in collect_rows("1=1"):</code> |
| L3634 | 计算并保存 &#96;city&#96;（city），供后续逻辑使用，当前位于函数 source_map。 | <code>                city = str(item.get("source_city") or item.get("source_region") or "").strip()</code> |
| L3635 | 计算并保存 &#96;city_key&#96;（citykey），供后续逻辑使用，当前位于函数 source_map。 | <code>                city_key = city.casefold()</code> |
| L3636 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 source_map。 | <code>                if not city or city_key in seen_cities:</code> |
| L3637 | 控制当前循环或占位分支的执行流程，当前位于函数 source_map。 | <code>                    continue</code> |
| L3638 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 source_map。 | <code>                items.append({**item, "historical_supplement": True})</code> |
| L3639 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 source_map。 | <code>                seen_cities.add(city_key)</code> |
| L3640 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_map。 | <code>                historical_supplement_count += 1</code> |
| L3641 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 source_map。 | <code>                if len(items) &gt;= limit:</code> |
| L3642 | 控制当前循环或占位分支的执行流程，当前位于函数 source_map。 | <code>                    break</code> |
| L3643 | 计算并保存 &#96;fallback_all_time&#96;（fallbackalltime），供后续逻辑使用，当前位于函数 source_map。 | <code>        fallback_all_time = not recent_items and bool(items)</code> |
| L3644 | 计算并保存 &#96;data_updated_at&#96;（dataupdatedat），供后续逻辑使用，当前位于函数 source_map。 | <code>        data_updated_at = max((str(item.get("latest_at") or "") for item in items), default="") or None</code> |
| L3645 | 结束当前函数并把结果返回给调用方，当前位于函数 source_map。 | <code>        return jsonify(</code> |
| L3646 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_map。 | <code>            {</code> |
| L3647 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_map。 | <code>                "items": normalize_rows(items),</code> |
| L3648 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_map。 | <code>                "period_days": days,</code> |
| L3649 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_map。 | <code>                "limit": limit,</code> |
| L3650 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_map。 | <code>                "fallback_all_time": fallback_all_time,</code> |
| L3651 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_map。 | <code>                "historical_supplement_count": historical_supplement_count,</code> |
| L3652 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_map。 | <code>                "recent_item_count": min(len(recent_items), limit),</code> |
| L3653 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_map。 | <code>                "data_updated_at": data_updated_at,</code> |
| L3654 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_map。 | <code>                "server_region": "北京",</code> |
| L3655 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 source_map。 | <code>                "server_coord": [116.4074, 39.9042],</code> |
| L3656 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 source_map。 | <code>            }</code> |
| L3657 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 source_map。 | <code>        )</code> |
| L3658 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3659 | 注册 Flask HTTP 接口 "/api/v2/user/dashboard/heatmap", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/user/dashboard/heatmap", methods=["GET"])</code> |
| L3660 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3661 | 定义heatmap函数 &#96;heatmap&#96;，封装可复用业务逻辑。 | <code>    def heatmap():</code> |
| L3662 | 计算并保存 &#96;visible_sql&#96;（visiblesql），供后续逻辑使用，当前位于函数 heatmap。 | <code>        visible_sql = visible_attack_event_clause()</code> |
| L3663 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 heatmap。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L3664 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 heatmap。 | <code>            with conn.cursor() as cur:</code> |
| L3665 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 heatmap。 | <code>                cur.execute(</code> |
| L3666 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 heatmap。 | <code>                    f"""</code> |
| L3667 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 heatmap。 | <code>                    SELECT</code> |
| L3668 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 heatmap。 | <code>                      WEEKDAY(occurred_at) AS weekday_idx,</code> |
| L3669 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 heatmap。 | <code>                      HOUR(occurred_at) AS hour_idx,</code> |
| L3670 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 heatmap。 | <code>                      COUNT(*) AS total</code> |
| L3671 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 heatmap。 | <code>                    FROM demo_attack_events</code> |
| L3672 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 heatmap。 | <code>                    WHERE occurred_at &gt;= DATE_SUB(NOW(), INTERVAL 30 DAY) AND {visible_sql}</code> |
| L3673 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 heatmap。 | <code>                    GROUP BY WEEKDAY(occurred_at), HOUR(occurred_at)</code> |
| L3674 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 heatmap。 | <code>                    ORDER BY weekday_idx, hour_idx</code> |
| L3675 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 heatmap。 | <code>                    """</code> |
| L3676 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 heatmap。 | <code>                )</code> |
| L3677 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 heatmap。 | <code>                rows = cur.fetchall()</code> |
| L3678 | 结束当前函数并把结果返回给调用方，当前位于函数 heatmap。 | <code>        return jsonify({"items": normalize_rows(rows)})</code> |
| L3679 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3680 | 注册 Flask HTTP 接口 "/api/v2/user/dashboard/method-share", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/user/dashboard/method-share", methods=["GET"])</code> |
| L3681 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3682 | 定义methodshare函数 &#96;method_share&#96;，封装可复用业务逻辑。 | <code>    def method_share():</code> |
| L3683 | 计算并保存 &#96;visible_sql&#96;（visiblesql），供后续逻辑使用，当前位于函数 method_share。 | <code>        visible_sql = visible_attack_event_clause()</code> |
| L3684 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 method_share。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L3685 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 method_share。 | <code>            with conn.cursor() as cur:</code> |
| L3686 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 method_share。 | <code>                cur.execute(</code> |
| L3687 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 method_share。 | <code>                    f"""</code> |
| L3688 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 method_share。 | <code>                    SELECT attack_type, COUNT(*) AS total</code> |
| L3689 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 method_share。 | <code>                    FROM demo_attack_events</code> |
| L3690 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 method_share。 | <code>                    WHERE occurred_at &gt;= DATE_SUB(NOW(), INTERVAL 7 DAY) AND {visible_sql}</code> |
| L3691 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 method_share。 | <code>                    GROUP BY attack_type</code> |
| L3692 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 method_share。 | <code>                    ORDER BY total DESC</code> |
| L3693 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 method_share。 | <code>                    """</code> |
| L3694 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 method_share。 | <code>                )</code> |
| L3695 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 method_share。 | <code>                rows = cur.fetchall()</code> |
| L3696 | 计算并保存 &#96;merged&#96;（merged），供后续逻辑使用，当前位于函数 method_share。 | <code>        merged = aggregate_counts_by_label(rows, "attack_type")</code> |
| L3697 | 计算并保存 &#96;total&#96;（total），供后续逻辑使用，当前位于函数 method_share。 | <code>        total = sum(int(r.get("total") or 0) for r in merged)</code> |
| L3698 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 method_share。 | <code>        items = []</code> |
| L3699 | 遍历集合中的数据项并逐项处理，当前位于函数 method_share。 | <code>        for r in merged:</code> |
| L3700 | 计算并保存 &#96;count&#96;（count），供后续逻辑使用，当前位于函数 method_share。 | <code>            count = int(r.get("total") or 0)</code> |
| L3701 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 method_share。 | <code>            ratio = 0.0 if total == 0 else (count / total) * 100.0</code> |
| L3702 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 method_share。 | <code>            items.append({"attack_type": r["attack_type"], "total": count, "ratio_percent": round(ratio, 2)})</code> |
| L3703 | 结束当前函数并把结果返回给调用方，当前位于函数 method_share。 | <code>        return jsonify({"items": items})</code> |
| L3704 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3705 | 定义open态势store函数 &#96;open_situation_store&#96;，封装可复用业务逻辑。 | <code>    def open_situation_store() -&gt; MySQLSituationStore:</code> |
| L3706 | 结束当前函数并把结果返回给调用方，当前位于函数 open_situation_store。 | <code>        return MySQLSituationStore(MySQLSettings(**app.config["MYSQL_CONF"]))</code> |
| L3707 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3708 | 定义加载proxycluster数据库记录函数 &#96;load_proxy_cluster_rows&#96;，封装可复用业务逻辑。 | <code>    def load_proxy_cluster_rows(window_minutes: int, lookback_hours: int, status: str = "") -&gt; List[Dict[str, Any]]:</code> |
| L3709 | 计算并保存 &#96;store&#96;（store），供后续逻辑使用，当前位于函数 load_proxy_cluster_rows。 | <code>        store = open_situation_store()</code> |
| L3710 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 load_proxy_cluster_rows。 | <code>        try:</code> |
| L3711 | 计算并保存 &#96;full_rows&#96;（full数据库记录），供后续逻辑使用，当前位于函数 load_proxy_cluster_rows。 | <code>            full_rows = store.list_situation_details(</code> |
| L3712 | 计算并保存 &#96;limit&#96;（limit），供后续逻辑使用，当前位于函数 load_proxy_cluster_rows。 | <code>                limit=5000,</code> |
| L3713 | 计算并保存 &#96;status&#96;（状态），供后续逻辑使用，当前位于函数 load_proxy_cluster_rows。 | <code>                status=status,</code> |
| L3714 | 计算并保存 &#96;lookback_hours&#96;（lookbackhours），供后续逻辑使用，当前位于函数 load_proxy_cluster_rows。 | <code>                lookback_hours=lookback_hours,</code> |
| L3715 | 计算并保存 &#96;include_observing&#96;（includeobserving），供后续逻辑使用，当前位于函数 load_proxy_cluster_rows。 | <code>                include_observing=True,</code> |
| L3716 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_proxy_cluster_rows。 | <code>            )</code> |
| L3717 | 结束当前函数并把结果返回给调用方，当前位于函数 load_proxy_cluster_rows。 | <code>            return build_proxy_clusters(full_rows, window_minutes=window_minutes, lookback_hours=lookback_hours)</code> |
| L3718 | 无论成功或异常都执行资源清理，当前位于函数 load_proxy_cluster_rows。 | <code>        finally:</code> |
| L3719 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_proxy_cluster_rows。 | <code>            store.close()</code> |
| L3720 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3721 | 注册 Flask HTTP 接口 "/api/v2/situation-clusters", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/situation-clusters", methods=["GET"])</code> |
| L3722 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3723 | 定义态势clusters函数 &#96;situation_clusters&#96;，封装可复用业务逻辑。 | <code>    def situation_clusters():</code> |
| L3724 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 situation_clusters。 | <code>        try:</code> |
| L3725 | 计算并保存 &#96;window_minutes&#96;（windowminutes），供后续逻辑使用，当前位于函数 situation_clusters。 | <code>            window_minutes = max(5, min(1440, int(request.args.get("window_minutes", "60"))))</code> |
| L3726 | 计算并保存 &#96;lookback_hours&#96;（lookbackhours），供后续逻辑使用，当前位于函数 situation_clusters。 | <code>            lookback_hours = max(1, min(720, int(request.args.get("lookback_hours", "24"))))</code> |
| L3727 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 situation_clusters。 | <code>        except ValueError:</code> |
| L3728 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_clusters。 | <code>            return jsonify({"error": "invalid_time_range"}), 400</code> |
| L3729 | 计算并保存 &#96;status&#96;（状态），供后续逻辑使用，当前位于函数 situation_clusters。 | <code>        status = request.args.get("status", "").strip()</code> |
| L3730 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 situation_clusters。 | <code>        if status and status not in {"open", "closed", "handled", "ignored", "observing"}:</code> |
| L3731 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_clusters。 | <code>            return jsonify({"error": "invalid_status"}), 400</code> |
| L3732 | 计算并保存 &#96;clusters&#96;（clusters），供后续逻辑使用，当前位于函数 situation_clusters。 | <code>        clusters = load_proxy_cluster_rows(window_minutes, lookback_hours, status=status)</code> |
| L3733 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 situation_clusters。 | <code>        items = []</code> |
| L3734 | 遍历集合中的数据项并逐项处理，当前位于函数 situation_clusters。 | <code>        for cluster in clusters:</code> |
| L3735 | 计算并保存 &#96;summary&#96;（summary），供后续逻辑使用，当前位于函数 situation_clusters。 | <code>            summary = {key: value for key, value in cluster.items() if key not in {"actions", "graph", "ai_report"}}</code> |
| L3736 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_clusters。 | <code>            summary["ai_status"] = cluster.get("ai_status")</code> |
| L3737 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 situation_clusters。 | <code>            items.append(summary)</code> |
| L3738 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_clusters。 | <code>        return jsonify(</code> |
| L3739 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_clusters。 | <code>            {</code> |
| L3740 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_clusters。 | <code>                "items": normalize_rows(items),</code> |
| L3741 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_clusters。 | <code>                "total": len(items),</code> |
| L3742 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_clusters。 | <code>                "window_minutes": window_minutes,</code> |
| L3743 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_clusters。 | <code>                "lookback_hours": lookback_hours,</code> |
| L3744 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_clusters。 | <code>                "correlation_rule": "same_target + time_window + multiple_ips + at_least_3_action_types",</code> |
| L3745 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 situation_clusters。 | <code>            }</code> |
| L3746 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 situation_clusters。 | <code>        )</code> |
| L3747 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3748 | 注册 Flask HTTP 接口 "/api/v3/rag/enabled", methods=["PUT"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v3/rag/enabled", methods=["PUT"])</code> |
| L3749 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3750 | 定义rag2enabled更新函数 &#96;rag2_enabled_update&#96;，封装可复用业务逻辑。 | <code>    def rag2_enabled_update():</code> |
| L3751 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 rag2_enabled_update。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L3752 | 计算并保存 &#96;enabled&#96;（enabled），供后续逻辑使用，当前位于函数 rag2_enabled_update。 | <code>        enabled = bool(body.get("enabled", False))</code> |
| L3753 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_enabled_update。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L3754 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 rag2_enabled_update。 | <code>            with conn.cursor() as cur:</code> |
| L3755 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 rag2_enabled_update。 | <code>                cur.execute(</code> |
| L3756 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 rag2_enabled_update。 | <code>                    """</code> |
| L3757 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 rag2_enabled_update。 | <code>                    INSERT INTO demo_system_config(config_key, config_value)</code> |
| L3758 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 rag2_enabled_update。 | <code>                    VALUES ('rag_enabled', %s)</code> |
| L3759 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 rag2_enabled_update。 | <code>                    ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)</code> |
| L3760 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 rag2_enabled_update。 | <code>                    """,</code> |
| L3761 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_enabled_update。 | <code>                    ("1" if enabled else "0",),</code> |
| L3762 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 rag2_enabled_update。 | <code>                )</code> |
| L3763 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_enabled_update。 | <code>                log_action(conn, g.session["username"], g.session["role"], "rag_toggle", "rag", "enabled" if enabled else "disabled")</code> |
| L3764 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rag2_enabled_update。 | <code>            conn.commit()</code> |
| L3765 | 结束当前函数并把结果返回给调用方，当前位于函数 rag2_enabled_update。 | <code>        return jsonify({"ok": True, "enabled": enabled})</code> |
| L3766 | 注册 Flask HTTP 接口 "/api/v2/situation-clusters/&lt;cluster_id&gt;", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/situation-clusters/&lt;cluster_id&gt;", methods=["GET"])</code> |
| L3767 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3768 | 定义态势clusterdetail函数 &#96;situation_cluster_detail&#96;，封装可复用业务逻辑。 | <code>    def situation_cluster_detail(cluster_id: str):</code> |
| L3769 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 situation_cluster_detail。 | <code>        try:</code> |
| L3770 | 计算并保存 &#96;window_minutes&#96;（windowminutes），供后续逻辑使用，当前位于函数 situation_cluster_detail。 | <code>            window_minutes = max(5, min(1440, int(request.args.get("window_minutes", "60"))))</code> |
| L3771 | 计算并保存 &#96;lookback_hours&#96;（lookbackhours），供后续逻辑使用，当前位于函数 situation_cluster_detail。 | <code>            lookback_hours = max(1, min(720, int(request.args.get("lookback_hours", "24"))))</code> |
| L3772 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 situation_cluster_detail。 | <code>        except ValueError:</code> |
| L3773 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_cluster_detail。 | <code>            return jsonify({"error": "invalid_time_range"}), 400</code> |
| L3774 | 计算并保存 &#96;cluster&#96;（cluster），供后续逻辑使用，当前位于函数 situation_cluster_detail。 | <code>        cluster = next(</code> |
| L3775 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_cluster_detail。 | <code>            (row for row in load_proxy_cluster_rows(window_minutes, lookback_hours) if row.get("cluster_id") == cluster_id),</code> |
| L3776 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_cluster_detail。 | <code>            None,</code> |
| L3777 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 situation_cluster_detail。 | <code>        )</code> |
| L3778 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 situation_cluster_detail。 | <code>        if not cluster:</code> |
| L3779 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_cluster_detail。 | <code>            return jsonify({"error": "cluster_not_found"}), 404</code> |
| L3780 | 计算并保存 &#96;graph&#96;（graph），供后续逻辑使用，当前位于函数 situation_cluster_detail。 | <code>        graph = cluster.pop("graph", {"nodes": [], "edges": []})</code> |
| L3781 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_cluster_detail。 | <code>        return jsonify({"item": normalize_rows([cluster])[0], "graph": normalize_rows([graph])[0]})</code> |
| L3782 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3783 | 注册 Flask HTTP 接口 "/api/v2/situation-clusters/&lt;cluster_id&gt;/reanalyze", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/situation-clusters/&lt;cluster_id&gt;/reanalyze", methods=["POST"])</code> |
| L3784 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L3785 | 定义态势clusterreanalyze函数 &#96;situation_cluster_reanalyze&#96;，封装可复用业务逻辑。 | <code>    def situation_cluster_reanalyze(cluster_id: str):</code> |
| L3786 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 situation_cluster_reanalyze。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L3787 | 计算并保存 &#96;window_minutes&#96;（windowminutes），供后续逻辑使用，当前位于函数 situation_cluster_reanalyze。 | <code>        window_minutes = max(5, min(1440, int(body.get("window_minutes", 60))))</code> |
| L3788 | 计算并保存 &#96;lookback_hours&#96;（lookbackhours），供后续逻辑使用，当前位于函数 situation_cluster_reanalyze。 | <code>        lookback_hours = max(1, min(720, int(body.get("lookback_hours", 24))))</code> |
| L3789 | 计算并保存 &#96;cluster&#96;（cluster），供后续逻辑使用，当前位于函数 situation_cluster_reanalyze。 | <code>        cluster = next(</code> |
| L3790 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_cluster_reanalyze。 | <code>            (row for row in load_proxy_cluster_rows(window_minutes, lookback_hours) if row.get("cluster_id") == cluster_id),</code> |
| L3791 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_cluster_reanalyze。 | <code>            None,</code> |
| L3792 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 situation_cluster_reanalyze。 | <code>        )</code> |
| L3793 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 situation_cluster_reanalyze。 | <code>        if not cluster:</code> |
| L3794 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_cluster_reanalyze。 | <code>            return jsonify({"error": "cluster_not_found"}), 404</code> |
| L3795 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 situation_cluster_reanalyze。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L3796 | 计算并保存 &#96;config_map&#96;（配置map），供后续逻辑使用，当前位于函数 situation_cluster_reanalyze。 | <code>            config_map = load_system_config_map(conn)</code> |
| L3797 | 计算并保存 &#96;ai_input&#96;（aiinput），供后续逻辑使用，当前位于函数 situation_cluster_reanalyze。 | <code>        ai_input = dict(cluster)</code> |
| L3798 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_cluster_reanalyze。 | <code>        ai_input["source_ip"] = f"多个代理来源：{', '.join(cluster.get('source_ips') or [])}"</code> |
| L3799 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_cluster_reanalyze。 | <code>        report, ai_status = analyze_situation(</code> |
| L3800 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_cluster_reanalyze。 | <code>            ai_input,</code> |
| L3801 | 计算并保存 &#96;ollama_url&#96;（ollamaurl），供后续逻辑使用，当前位于函数 situation_cluster_reanalyze。 | <code>            ollama_url=app.config["OLLAMA_URL"],</code> |
| L3802 | 计算并保存 &#96;model&#96;（模型），供后续逻辑使用，当前位于函数 situation_cluster_reanalyze。 | <code>            model=config_map.get("llm_model", "qwen3:8b"),</code> |
| L3803 | 计算并保存 &#96;rag_db_path&#96;（rag数据库path），供后续逻辑使用，当前位于函数 situation_cluster_reanalyze。 | <code>            rag_db_path=Path(app.config["RAG_DB_PATH"]),</code> |
| L3804 | 计算并保存 &#96;rag_mysql_conf&#96;（ragmysqlconf），供后续逻辑使用，当前位于函数 situation_cluster_reanalyze。 | <code>            rag_mysql_conf=app.config["MYSQL_CONF"],</code> |
| L3805 | 计算并保存 &#96;rag_data_dir&#96;（ragdatadir），供后续逻辑使用，当前位于函数 situation_cluster_reanalyze。 | <code>            rag_data_dir=Path(app.config["RAG_DATA_DIR"]),</code> |
| L3806 | 计算并保存 &#96;rag_api_config&#96;（rag接口配置），供后续逻辑使用，当前位于函数 situation_cluster_reanalyze。 | <code>            rag_api_config=Path(app.config["RAG_API_CONFIG_PATH"]),</code> |
| L3807 | 计算并保存 &#96;rag_enabled&#96;（ragenabled），供后续逻辑使用，当前位于函数 situation_cluster_reanalyze。 | <code>            rag_enabled=str(config_map.get("rag_enabled", "1")).strip().lower() in {"1", "true", "yes", "on"},</code> |
| L3808 | 计算并保存 &#96;rag_top_k&#96;（ragtopk），供后续逻辑使用，当前位于函数 situation_cluster_reanalyze。 | <code>            rag_top_k=4,</code> |
| L3809 | 计算并保存 &#96;timeout_sec&#96;（timeoutsec），供后续逻辑使用，当前位于函数 situation_cluster_reanalyze。 | <code>            timeout_sec=120,</code> |
| L3810 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 situation_cluster_reanalyze。 | <code>        )</code> |
| L3811 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_cluster_reanalyze。 | <code>        return jsonify({"ok": True, "cluster_id": cluster_id, "ai_status": ai_status, "report": report})</code> |
| L3812 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3813 | 注册 Flask HTTP 接口 "/api/v2/situations", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/situations", methods=["GET"])</code> |
| L3814 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3815 | 定义态势列出函数 &#96;situation_list&#96;，封装可复用业务逻辑。 | <code>    def situation_list():</code> |
| L3816 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 situation_list。 | <code>        source_ip = request.args.get("source_ip", "").strip()</code> |
| L3817 | 计算并保存 &#96;status&#96;（状态），供后续逻辑使用，当前位于函数 situation_list。 | <code>        status = request.args.get("status", "").strip().lower()</code> |
| L3818 | 计算并保存 &#96;limit&#96;（limit），供后续逻辑使用，当前位于函数 situation_list。 | <code>        limit = max(1, min(200, int(request.args.get("limit", "50"))))</code> |
| L3819 | 计算并保存 &#96;offset&#96;（offset），供后续逻辑使用，当前位于函数 situation_list。 | <code>        offset = max(0, int(request.args.get("offset", "0")))</code> |
| L3820 | 计算并保存 &#96;minimum_risk&#96;（minimumrisk），供后续逻辑使用，当前位于函数 situation_list。 | <code>        minimum_risk = max(0.0, min(1.0, float(request.args.get("minimum_risk", "0"))))</code> |
| L3821 | 计算并保存 &#96;store&#96;（store），供后续逻辑使用，当前位于函数 situation_list。 | <code>        store = open_situation_store()</code> |
| L3822 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 situation_list。 | <code>        try:</code> |
| L3823 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 situation_list。 | <code>            items = store.list_situations(</code> |
| L3824 | 计算并保存 &#96;limit&#96;（limit），供后续逻辑使用，当前位于函数 situation_list。 | <code>                limit=limit,</code> |
| L3825 | 计算并保存 &#96;offset&#96;（offset），供后续逻辑使用，当前位于函数 situation_list。 | <code>                offset=offset,</code> |
| L3826 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 situation_list。 | <code>                source_ip=source_ip,</code> |
| L3827 | 计算并保存 &#96;status&#96;（状态），供后续逻辑使用，当前位于函数 situation_list。 | <code>                status=status,</code> |
| L3828 | 计算并保存 &#96;minimum_risk&#96;（minimumrisk），供后续逻辑使用，当前位于函数 situation_list。 | <code>                minimum_risk=minimum_risk,</code> |
| L3829 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 situation_list。 | <code>            )</code> |
| L3830 | 无论成功或异常都执行资源清理，当前位于函数 situation_list。 | <code>        finally:</code> |
| L3831 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_list。 | <code>            store.close()</code> |
| L3832 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_list。 | <code>        return jsonify({"items": normalize_situation_value(items), "limit": limit, "offset": offset})</code> |
| L3833 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3834 | 注册 Flask HTTP 接口 "/api/v2/situations/by-ip/&lt;source_ip&gt;", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/situations/by-ip/&lt;source_ip&gt;", methods=["GET"])</code> |
| L3835 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3836 | 定义situationsbyip函数 &#96;situations_by_ip&#96;，封装可复用业务逻辑。 | <code>    def situations_by_ip(source_ip: str):</code> |
| L3837 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 situations_by_ip。 | <code>        try:</code> |
| L3838 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situations_by_ip。 | <code>            ipaddress.ip_address(source_ip)</code> |
| L3839 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 situations_by_ip。 | <code>        except ValueError:</code> |
| L3840 | 结束当前函数并把结果返回给调用方，当前位于函数 situations_by_ip。 | <code>            return jsonify({"error": "invalid_source_ip", "message": "来源 IP 格式不正确"}), 400</code> |
| L3841 | 计算并保存 &#96;store&#96;（store），供后续逻辑使用，当前位于函数 situations_by_ip。 | <code>        store = open_situation_store()</code> |
| L3842 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 situations_by_ip。 | <code>        try:</code> |
| L3843 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 situations_by_ip。 | <code>            items = store.list_situations(limit=200, source_ip=source_ip)</code> |
| L3844 | 无论成功或异常都执行资源清理，当前位于函数 situations_by_ip。 | <code>        finally:</code> |
| L3845 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situations_by_ip。 | <code>            store.close()</code> |
| L3846 | 结束当前函数并把结果返回给调用方，当前位于函数 situations_by_ip。 | <code>        return jsonify({"source_ip": source_ip, "items": normalize_situation_value(items)})</code> |
| L3847 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3848 | 注册 Flask HTTP 接口 "/api/v2/situations/&lt;situation_id&gt;", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/situations/&lt;situation_id&gt;", methods=["GET"])</code> |
| L3849 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3850 | 定义态势detail函数 &#96;situation_detail&#96;，封装可复用业务逻辑。 | <code>    def situation_detail(situation_id: str):</code> |
| L3851 | 计算并保存 &#96;store&#96;（store），供后续逻辑使用，当前位于函数 situation_detail。 | <code>        store = open_situation_store()</code> |
| L3852 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 situation_detail。 | <code>        try:</code> |
| L3853 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 situation_detail。 | <code>            item = store.get_situation(situation_id)</code> |
| L3854 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 situation_detail。 | <code>            if item:</code> |
| L3855 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_detail。 | <code>                item["ai_queue"] = store.get_ai_queue_status(situation_id)</code> |
| L3856 | 无论成功或异常都执行资源清理，当前位于函数 situation_detail。 | <code>        finally:</code> |
| L3857 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_detail。 | <code>            store.close()</code> |
| L3858 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 situation_detail。 | <code>        if not item:</code> |
| L3859 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_detail。 | <code>            return jsonify({"error": "situation_not_found"}), 404</code> |
| L3860 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_detail。 | <code>        return jsonify({"item": normalize_situation_value(item)})</code> |
| L3861 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3862 | 注册 Flask HTTP 接口 "/api/v2/situations/&lt;situation_id&gt;/prioritize-report", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/situations/&lt;situation_id&gt;/prioritize-report", methods=["POST"])</code> |
| L3863 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3864 | 定义态势prioritize报告函数 &#96;situation_prioritize_report&#96;，封装可复用业务逻辑。 | <code>    def situation_prioritize_report(situation_id: str):</code> |
| L3865 | 计算并保存 &#96;store&#96;（store），供后续逻辑使用，当前位于函数 situation_prioritize_report。 | <code>        store = open_situation_store()</code> |
| L3866 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 situation_prioritize_report。 | <code>        try:</code> |
| L3867 | 计算并保存 &#96;queue&#96;（queue），供后续逻辑使用，当前位于函数 situation_prioritize_report。 | <code>            queue = store.prioritize_ai(situation_id)</code> |
| L3868 | 无论成功或异常都执行资源清理，当前位于函数 situation_prioritize_report。 | <code>        finally:</code> |
| L3869 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_prioritize_report。 | <code>            store.close()</code> |
| L3870 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 situation_prioritize_report。 | <code>        if not queue:</code> |
| L3871 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_prioritize_report。 | <code>            return jsonify({"error": "situation_not_found"}), 404</code> |
| L3872 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_prioritize_report。 | <code>        return jsonify({"ok": True, "queue": normalize_situation_value(queue)})</code> |
| L3873 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3874 | 定义加载professional报告态势函数 &#96;load_professional_report_situation&#96;，封装可复用业务逻辑。 | <code>    def load_professional_report_situation(situation_id: str) -&gt; Optional[Dict[str, Any]]:</code> |
| L3875 | 计算并保存 &#96;store&#96;（store），供后续逻辑使用，当前位于函数 load_professional_report_situation。 | <code>        store = open_situation_store()</code> |
| L3876 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 load_professional_report_situation。 | <code>        try:</code> |
| L3877 | 结束当前函数并把结果返回给调用方，当前位于函数 load_professional_report_situation。 | <code>            return store.get_situation(situation_id)</code> |
| L3878 | 无论成功或异常都执行资源清理，当前位于函数 load_professional_report_situation。 | <code>        finally:</code> |
| L3879 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_professional_report_situation。 | <code>            store.close()</code> |
| L3880 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3881 | 注册 Flask HTTP 接口 "/api/v2/situations/&lt;situation_id&gt;/professional-report", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/situations/&lt;situation_id&gt;/professional-report", methods=["POST"])</code> |
| L3882 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3883 | 定义professional报告创建函数 &#96;professional_report_create&#96;，封装可复用业务逻辑。 | <code>    def professional_report_create(situation_id: str):</code> |
| L3884 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 professional_report_create。 | <code>        item = load_professional_report_situation(situation_id)</code> |
| L3885 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 professional_report_create。 | <code>        if not item:</code> |
| L3886 | 结束当前函数并把结果返回给调用方，当前位于函数 professional_report_create。 | <code>            return jsonify({"error": "situation_not_found"}), 404</code> |
| L3887 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 professional_report_create。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L3888 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 professional_report_create。 | <code>            expire_professional_report_jobs(conn)</code> |
| L3889 | 计算并保存 &#96;job&#96;（job），供后续逻辑使用，当前位于函数 professional_report_create。 | <code>            job = create_professional_report_job(conn, item, str(g.session.get("username") or "unknown"))</code> |
| L3890 | 计算并保存 &#96;manager&#96;（manager），供后续逻辑使用，当前位于函数 professional_report_create。 | <code>        manager: ProfessionalReportManager = app.config["PROFESSIONAL_REPORT_MANAGER"]</code> |
| L3891 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 professional_report_create。 | <code>        if job.get("status") in {"queued", "running"}:</code> |
| L3892 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 professional_report_create。 | <code>            manager.start(str(job["job_id"]))</code> |
| L3893 | 结束当前函数并把结果返回给调用方，当前位于函数 professional_report_create。 | <code>        return jsonify({"job": normalize_situation_value(public_professional_report_job(job))}), 202</code> |
| L3894 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3895 | 注册 Flask HTTP 接口 "/api/v2/situations/&lt;situation_id&gt;/professional-report", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/situations/&lt;situation_id&gt;/professional-report", methods=["GET"])</code> |
| L3896 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3897 | 定义professional报告状态函数 &#96;professional_report_status&#96;，封装可复用业务逻辑。 | <code>    def professional_report_status(situation_id: str):</code> |
| L3898 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 professional_report_status。 | <code>        item = load_professional_report_situation(situation_id)</code> |
| L3899 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 professional_report_status。 | <code>        if not item:</code> |
| L3900 | 结束当前函数并把结果返回给调用方，当前位于函数 professional_report_status。 | <code>            return jsonify({"error": "situation_not_found"}), 404</code> |
| L3901 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 professional_report_status。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L3902 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 professional_report_status。 | <code>            expire_professional_report_jobs(conn)</code> |
| L3903 | 计算并保存 &#96;job&#96;（job），供后续逻辑使用，当前位于函数 professional_report_status。 | <code>            job = find_professional_report_job(conn, situation_id, str(item.get("sequence_hash") or ""))</code> |
| L3904 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 professional_report_status。 | <code>            if not job:</code> |
| L3905 | 计算并保存 &#96;job&#96;（job），供后续逻辑使用，当前位于函数 professional_report_status。 | <code>                job = find_latest_completed_professional_report_job(conn, situation_id)</code> |
| L3906 | 结束当前函数并把结果返回给调用方，当前位于函数 professional_report_status。 | <code>        return jsonify({"job": normalize_situation_value(public_professional_report_job(job))})</code> |
| L3907 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3908 | 注册 Flask HTTP 接口 "/api/v2/situations/&lt;situation_id&gt;/professional-report/download", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/situations/&lt;situation_id&gt;/professional-report/download", methods=["GET"])</code> |
| L3909 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3910 | 定义professional报告download函数 &#96;professional_report_download&#96;，封装可复用业务逻辑。 | <code>    def professional_report_download(situation_id: str):</code> |
| L3911 | 计算并保存 &#96;job_id&#96;（jobid），供后续逻辑使用，当前位于函数 professional_report_download。 | <code>        job_id = request.args.get("job_id", "").strip()</code> |
| L3912 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 professional_report_download。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L3913 | 计算并保存 &#96;job&#96;（job），供后续逻辑使用，当前位于函数 professional_report_download。 | <code>            job = get_professional_report_job(conn, job_id) if job_id else find_professional_report_job(conn, situation_id)</code> |
| L3914 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 professional_report_download。 | <code>        if not job or str(job.get("situation_id")) != situation_id:</code> |
| L3915 | 结束当前函数并把结果返回给调用方，当前位于函数 professional_report_download。 | <code>            return jsonify({"error": "report_not_found", "message": "尚未生成专业态势报告"}), 404</code> |
| L3916 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 professional_report_download。 | <code>        if job.get("status") != "completed" or not job.get("pdf_path"):</code> |
| L3917 | 结束当前函数并把结果返回给调用方，当前位于函数 professional_report_download。 | <code>            return jsonify({"error": "report_not_ready", "message": "专业态势报告仍在生成中"}), 409</code> |
| L3918 | 计算并保存 &#96;path&#96;（path），供后续逻辑使用，当前位于函数 professional_report_download。 | <code>        path = Path(str(job["pdf_path"])).resolve()</code> |
| L3919 | 计算并保存 &#96;report_root&#96;（报告root），供后续逻辑使用，当前位于函数 professional_report_download。 | <code>        report_root = Path(app.config["PROFESSIONAL_REPORT_DIR"]).resolve()</code> |
| L3920 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 professional_report_download。 | <code>        if report_root not in path.parents or not path.is_file():</code> |
| L3921 | 结束当前函数并把结果返回给调用方，当前位于函数 professional_report_download。 | <code>            return jsonify({"error": "report_file_missing", "message": "报告文件不存在"}), 404</code> |
| L3922 | 结束当前函数并把结果返回给调用方，当前位于函数 professional_report_download。 | <code>        return send_file(path, mimetype="application/pdf", as_attachment=True, download_name=f"{situation_id}_专业态势感知报告.pdf")</code> |
| L3923 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3924 | 注册 Flask HTTP 接口 "/api/v2/situations/&lt;situation_id&gt;/graph", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/situations/&lt;situation_id&gt;/graph", methods=["GET"])</code> |
| L3925 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3926 | 定义态势graph函数 &#96;situation_graph&#96;，封装可复用业务逻辑。 | <code>    def situation_graph(situation_id: str):</code> |
| L3927 | 计算并保存 &#96;store&#96;（store），供后续逻辑使用，当前位于函数 situation_graph。 | <code>        store = open_situation_store()</code> |
| L3928 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 situation_graph。 | <code>        try:</code> |
| L3929 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 situation_graph。 | <code>            item = store.get_situation(situation_id)</code> |
| L3930 | 无论成功或异常都执行资源清理，当前位于函数 situation_graph。 | <code>        finally:</code> |
| L3931 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>            store.close()</code> |
| L3932 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 situation_graph。 | <code>        if not item:</code> |
| L3933 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_graph。 | <code>            return jsonify({"error": "situation_not_found"}), 404</code> |
| L3934 | 计算并保存 &#96;nodes&#96;（nodes），供后续逻辑使用，当前位于函数 situation_graph。 | <code>        nodes = []</code> |
| L3935 | 计算并保存 &#96;edges&#96;（edges），供后续逻辑使用，当前位于函数 situation_graph。 | <code>        edges = []</code> |
| L3936 | 遍历集合中的数据项并逐项处理，当前位于函数 situation_graph。 | <code>        for index, action in enumerate(item.get("actions") or []):</code> |
| L3937 | 计算并保存 &#96;action_type&#96;（actiontype），供后续逻辑使用，当前位于函数 situation_graph。 | <code>            action_type = str(action.get("action_type") or "UNKNOWN")</code> |
| L3938 | 计算并保存 &#96;catalog&#96;（catalog），供后续逻辑使用，当前位于函数 situation_graph。 | <code>            catalog = ACTION_CATALOG.get(action_type, ACTION_CATALOG["UNKNOWN"])</code> |
| L3939 | 计算并保存 &#96;node_id&#96;（nodeid），供后续逻辑使用，当前位于函数 situation_graph。 | <code>            node_id = str(action.get("action_id") or f"node-{index + 1}")</code> |
| L3940 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 situation_graph。 | <code>            nodes.append(</code> |
| L3941 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                {</code> |
| L3942 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    "id": node_id,</code> |
| L3943 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    "sequence": int(action.get("sequence_no") or index + 1),</code> |
| L3944 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    "name": catalog["label"],</code> |
| L3945 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    "action_type": action_type,</code> |
| L3946 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    "stage": action.get("stage") or catalog["stage"],</code> |
| L3947 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    "stage_label": STAGE_LABELS.get(str(action.get("stage") or catalog["stage"]), "其他行为"),</code> |
| L3948 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    "occurred_at": action.get("occurred_at"),</code> |
| L3949 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    "last_seen_at": action.get("last_seen_at"),</code> |
| L3950 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    "count": int(action.get("action_count") or 1),</code> |
| L3951 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    "confidence": float(action.get("confidence") or 0),</code> |
| L3952 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    "gap_seconds": int(action.get("gap_seconds") or 0),</code> |
| L3953 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    "target_interface": action.get("target_interface") or "",</code> |
| L3954 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 situation_graph。 | <code>                }</code> |
| L3955 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 situation_graph。 | <code>            )</code> |
| L3956 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 situation_graph。 | <code>            if index:</code> |
| L3957 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 situation_graph。 | <code>                edges.append(</code> |
| L3958 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    {</code> |
| L3959 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                        "source": nodes[index - 1]["id"],</code> |
| L3960 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                        "target": node_id,</code> |
| L3961 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                        "gap_seconds": nodes[index]["gap_seconds"],</code> |
| L3962 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 situation_graph。 | <code>                    }</code> |
| L3963 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 situation_graph。 | <code>                )</code> |
| L3964 | 计算并保存 &#96;stages&#96;（stages），供后续逻辑使用，当前位于函数 situation_graph。 | <code>        stages = [</code> |
| L3965 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>            {"id": key, "name": STAGE_LABELS[key], "order": STAGE_ORDER[key]}</code> |
| L3966 | 遍历集合中的数据项并逐项处理，当前位于函数 situation_graph。 | <code>            for key in sorted(STAGE_LABELS, key=lambda value: STAGE_ORDER.get(value, 0))</code> |
| L3967 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 situation_graph。 | <code>        ]</code> |
| L3968 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_graph。 | <code>        return jsonify(</code> |
| L3969 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>            normalize_situation_value(</code> |
| L3970 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                {</code> |
| L3971 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    "situation_id": situation_id,</code> |
| L3972 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    "source_ip": item.get("source_ip"),</code> |
| L3973 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    "risk_score": item.get("risk_score"),</code> |
| L3974 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    "risk_level": item.get("risk_level"),</code> |
| L3975 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    "nodes": nodes,</code> |
| L3976 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    "edges": edges,</code> |
| L3977 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_graph。 | <code>                    "stages": stages,</code> |
| L3978 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 situation_graph。 | <code>                }</code> |
| L3979 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 situation_graph。 | <code>            )</code> |
| L3980 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 situation_graph。 | <code>        )</code> |
| L3981 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L3982 | 注册 Flask HTTP 接口 "/api/v2/situations/&lt;situation_id&gt;/evidence", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/situations/&lt;situation_id&gt;/evidence", methods=["GET"])</code> |
| L3983 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L3984 | 定义态势evidence函数 &#96;situation_evidence&#96;，封装可复用业务逻辑。 | <code>    def situation_evidence(situation_id: str):</code> |
| L3985 | 计算并保存 &#96;store&#96;（store），供后续逻辑使用，当前位于函数 situation_evidence。 | <code>        store = open_situation_store()</code> |
| L3986 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 situation_evidence。 | <code>        try:</code> |
| L3987 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 situation_evidence。 | <code>            item = store.get_situation(situation_id)</code> |
| L3988 | 无论成功或异常都执行资源清理，当前位于函数 situation_evidence。 | <code>        finally:</code> |
| L3989 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_evidence。 | <code>            store.close()</code> |
| L3990 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 situation_evidence。 | <code>        if not item:</code> |
| L3991 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_evidence。 | <code>            return jsonify({"error": "situation_not_found"}), 404</code> |
| L3992 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 situation_evidence。 | <code>        evidence = [</code> |
| L3993 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_evidence。 | <code>            {</code> |
| L3994 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_evidence。 | <code>                "sequence": action.get("sequence_no"),</code> |
| L3995 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_evidence。 | <code>                "action_id": action.get("action_id"),</code> |
| L3996 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_evidence。 | <code>                "action_type": action.get("action_type"),</code> |
| L3997 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_evidence。 | <code>                "sensor": action.get("sensor"),</code> |
| L3998 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_evidence。 | <code>                "evidence_refs": action.get("evidence_refs") or [],</code> |
| L3999 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_evidence。 | <code>                "metadata": action.get("metadata") or {},</code> |
| L4000 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 situation_evidence。 | <code>            }</code> |
| L4001 | 遍历集合中的数据项并逐项处理，当前位于函数 situation_evidence。 | <code>            for action in item.get("actions") or []</code> |
| L4002 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 situation_evidence。 | <code>        ]</code> |
| L4003 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_evidence。 | <code>        return jsonify(normalize_situation_value({"situation_id": situation_id, "items": evidence}))</code> |
| L4004 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4005 | 注册 Flask HTTP 接口 "/api/v2/situations/&lt;situation_id&gt;/reanalyze", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/situations/&lt;situation_id&gt;/reanalyze", methods=["POST"])</code> |
| L4006 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L4007 | 定义态势reanalyze函数 &#96;situation_reanalyze&#96;，封装可复用业务逻辑。 | <code>    def situation_reanalyze(situation_id: str):</code> |
| L4008 | 计算并保存 &#96;store&#96;（store），供后续逻辑使用，当前位于函数 situation_reanalyze。 | <code>        store = open_situation_store()</code> |
| L4009 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 situation_reanalyze。 | <code>        try:</code> |
| L4010 | 计算并保存 &#96;queue&#96;（queue），供后续逻辑使用，当前位于函数 situation_reanalyze。 | <code>            queue = store.requeue_ai(situation_id)</code> |
| L4011 | 无论成功或异常都执行资源清理，当前位于函数 situation_reanalyze。 | <code>        finally:</code> |
| L4012 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_reanalyze。 | <code>            store.close()</code> |
| L4013 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 situation_reanalyze。 | <code>        if not queue:</code> |
| L4014 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_reanalyze。 | <code>            return jsonify({"error": "situation_not_found"}), 404</code> |
| L4015 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_reanalyze。 | <code>        return jsonify({"ok": True, "ai_status": queue["status"], "queue": normalize_situation_value(queue)}), 202</code> |
| L4016 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4017 | 注册 Flask HTTP 接口 "/api/v2/situations/&lt;situation_id&gt;/status", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/situations/&lt;situation_id&gt;/status", methods=["POST"])</code> |
| L4018 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L4019 | 定义态势更新状态函数 &#96;situation_update_status&#96;，封装可复用业务逻辑。 | <code>    def situation_update_status(situation_id: str):</code> |
| L4020 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 situation_update_status。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L4021 | 计算并保存 &#96;status&#96;（状态），供后续逻辑使用，当前位于函数 situation_update_status。 | <code>        status = str(body.get("status") or "").strip().lower()</code> |
| L4022 | 计算并保存 &#96;store&#96;（store），供后续逻辑使用，当前位于函数 situation_update_status。 | <code>        store = open_situation_store()</code> |
| L4023 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 situation_update_status。 | <code>        try:</code> |
| L4024 | 计算并保存 &#96;changed&#96;（changed），供后续逻辑使用，当前位于函数 situation_update_status。 | <code>            changed = store.update_status(situation_id, status)</code> |
| L4025 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 situation_update_status。 | <code>        except ValueError as exc:</code> |
| L4026 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_update_status。 | <code>            return jsonify({"error": "invalid_status", "message": str(exc)}), 400</code> |
| L4027 | 无论成功或异常都执行资源清理，当前位于函数 situation_update_status。 | <code>        finally:</code> |
| L4028 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_update_status。 | <code>            store.close()</code> |
| L4029 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 situation_update_status。 | <code>        if not changed:</code> |
| L4030 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_update_status。 | <code>            return jsonify({"error": "situation_not_found"}), 404</code> |
| L4031 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_update_status。 | <code>        return jsonify({"ok": True, "situation_id": situation_id, "status": status})</code> |
| L4032 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4033 | 注册 Flask HTTP 接口 "/api/v2/situations/stream", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/situations/stream", methods=["GET"])</code> |
| L4034 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L4035 | 定义态势stream函数 &#96;situation_stream&#96;，封装可复用业务逻辑。 | <code>    def situation_stream():</code> |
| L4036 | 计算并保存 &#96;store&#96;（store），供后续逻辑使用，当前位于函数 situation_stream。 | <code>        store = open_situation_store()</code> |
| L4037 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 situation_stream。 | <code>        try:</code> |
| L4038 | 计算并保存 &#96;latest&#96;（latest），供后续逻辑使用，当前位于函数 situation_stream。 | <code>            latest = store.list_situations(limit=1)</code> |
| L4039 | 无论成功或异常都执行资源清理，当前位于函数 situation_stream。 | <code>        finally:</code> |
| L4040 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_stream。 | <code>            store.close()</code> |
| L4041 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 situation_stream。 | <code>        payload = json.dumps(normalize_situation_value({"items": latest}), ensure_ascii=False)</code> |
| L4042 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_stream。 | <code>        return Response(f"retry: 5000\nevent: situations\ndata: {payload}\n\n", mimetype="text/event-stream")</code> |
| L4043 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4044 | 注册 Flask HTTP 接口 "/api/v2/pro/events", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/pro/events", methods=["GET"])</code> |
| L4045 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L4046 | 定义pro事件函数 &#96;pro_events&#96;，封装可复用业务逻辑。 | <code>    def pro_events():</code> |
| L4047 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 pro_events。 | <code>        try:</code> |
| L4048 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>            start_dt, end_dt = build_time_range()</code> |
| L4049 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 pro_events。 | <code>        except ValueError as exc:</code> |
| L4050 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_events。 | <code>            return jsonify({"error": "invalid_time_range", "message": str(exc)}), 400</code> |
| L4051 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4052 | 计算并保存 &#96;risk_level&#96;（risklevel），供后续逻辑使用，当前位于函数 pro_events。 | <code>        risk_level = request.args.get("risk_level", "all").strip().lower()</code> |
| L4053 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 pro_events。 | <code>        attack_type = request.args.get("attack_type", "all").strip()</code> |
| L4054 | 计算并保存 &#96;target_port&#96;（targetport），供后续逻辑使用，当前位于函数 pro_events。 | <code>        target_port = request.args.get("target_port", "all").strip()</code> |
| L4055 | 计算并保存 &#96;process_status&#96;（process状态），供后续逻辑使用，当前位于函数 pro_events。 | <code>        process_status = request.args.get("process_status", "all").strip().lower()</code> |
| L4056 | 计算并保存 &#96;keyword&#96;（keyword），供后续逻辑使用，当前位于函数 pro_events。 | <code>        keyword = request.args.get("keyword", "").strip()</code> |
| L4057 | 计算并保存 &#96;page&#96;（page），供后续逻辑使用，当前位于函数 pro_events。 | <code>        page = max(1, int(request.args.get("page", "1")))</code> |
| L4058 | 计算并保存 &#96;page_size&#96;（pagesize），供后续逻辑使用，当前位于函数 pro_events。 | <code>        page_size = max(1, min(int(request.args.get("page_size", "20")), 200))</code> |
| L4059 | 计算并保存 &#96;offset&#96;（offset），供后续逻辑使用，当前位于函数 pro_events。 | <code>        offset = (page - 1) * page_size</code> |
| L4060 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4061 | 计算并保存 &#96;where&#96;（where），供后续逻辑使用，当前位于函数 pro_events。 | <code>        where = ["e.occurred_at BETWEEN %s AND %s", visible_attack_event_clause("e")]</code> |
| L4062 | 计算并保存 &#96;params&#96;（params），供后续逻辑使用，当前位于函数 pro_events。 | <code>        params: List[Any] = [start_dt, end_dt]</code> |
| L4063 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_events。 | <code>        if risk_level != "all":</code> |
| L4064 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 pro_events。 | <code>            where.append("e.risk_level=%s")</code> |
| L4065 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 pro_events。 | <code>            params.append(risk_level)</code> |
| L4066 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_events。 | <code>        if attack_type != "all":</code> |
| L4067 | 计算并保存 &#96;aliases&#96;（aliases），供后续逻辑使用，当前位于函数 pro_events。 | <code>            aliases = attack_type_aliases(attack_type)</code> |
| L4068 | 计算并保存 &#96;placeholders&#96;（placeholders），供后续逻辑使用，当前位于函数 pro_events。 | <code>            placeholders = ", ".join(["%s"] * len(aliases))</code> |
| L4069 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 pro_events。 | <code>            where.append(f"e.attack_type IN ({placeholders})")</code> |
| L4070 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 pro_events。 | <code>            params.extend(aliases)</code> |
| L4071 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_events。 | <code>        if target_port != "all":</code> |
| L4072 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_events。 | <code>            if not target_port.isdigit() or not 1 &lt;= int(target_port) &lt;= 65535:</code> |
| L4073 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_events。 | <code>                return jsonify({"error": "invalid_target_port"}), 400</code> |
| L4074 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 pro_events。 | <code>            where.append("e.target_port=%s")</code> |
| L4075 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 pro_events。 | <code>            params.append(int(target_port))</code> |
| L4076 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_events。 | <code>        if process_status != "all":</code> |
| L4077 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 pro_events。 | <code>            where.append("e.process_status=%s")</code> |
| L4078 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 pro_events。 | <code>            params.append(process_status)</code> |
| L4079 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_events。 | <code>        if keyword:</code> |
| L4080 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 pro_events。 | <code>            where.append("(e.event_id LIKE %s OR e.source_ip LIKE %s OR e.target_interface LIKE %s)")</code> |
| L4081 | 计算并保存 &#96;like&#96;（like），供后续逻辑使用，当前位于函数 pro_events。 | <code>            like = f"%{keyword}%"</code> |
| L4082 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 pro_events。 | <code>            params.extend([like, like, like])</code> |
| L4083 | 计算并保存 &#96;where_sql&#96;（wheresql），供后续逻辑使用，当前位于函数 pro_events。 | <code>        where_sql = " AND ".join(where)</code> |
| L4084 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4085 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_events。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L4086 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_events。 | <code>            with conn.cursor() as cur:</code> |
| L4087 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_events。 | <code>                cur.execute(f"SELECT COUNT(*) AS c FROM demo_attack_events e WHERE {where_sql}", tuple(params))</code> |
| L4088 | 计算并保存 &#96;total&#96;（total），供后续逻辑使用，当前位于函数 pro_events。 | <code>                total = int((cur.fetchone() or {}).get("c", 0))</code> |
| L4089 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_events。 | <code>                cur.execute(</code> |
| L4090 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                    f"""</code> |
| L4091 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                    SELECT</code> |
| L4092 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                      e.event_id,</code> |
| L4093 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                      e.occurred_at,</code> |
| L4094 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                      e.risk_level,</code> |
| L4095 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                      e.attack_type,</code> |
| L4096 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                      e.source_ip,</code> |
| L4097 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                      e.source_region,</code> |
| L4098 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                      e.target_port,</code> |
| L4099 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                      e.target_interface,</code> |
| L4100 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                      e.process_status,</code> |
| L4101 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                      e.response_ms,</code> |
| L4102 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                      CASE WHEN b.ip_address IS NULL THEN 0 ELSE 1 END AS ip_blocked</code> |
| L4103 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                    FROM demo_attack_events e</code> |
| L4104 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                    LEFT JOIN (</code> |
| L4105 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_events。 | <code>                      SELECT ip_address, MAX(blocked_at) AS blocked_at</code> |
| L4106 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                      FROM demo_blocked_ips</code> |
| L4107 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                      GROUP BY ip_address</code> |
| L4108 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_events。 | <code>                    ) b ON b.ip_address = e.source_ip</code> |
| L4109 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                    WHERE {where_sql}</code> |
| L4110 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                    ORDER BY e.occurred_at DESC</code> |
| L4111 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                    LIMIT %s OFFSET %s</code> |
| L4112 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                    """,</code> |
| L4113 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>                    tuple(params + [page_size, offset]),</code> |
| L4114 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_events。 | <code>                )</code> |
| L4115 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 pro_events。 | <code>                rows = cur.fetchall()</code> |
| L4116 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 pro_events。 | <code>        items = []</code> |
| L4117 | 遍历集合中的数据项并逐项处理，当前位于函数 pro_events。 | <code>        for row in normalize_rows(rows):</code> |
| L4118 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>            row["attack_type"] = normalize_attack_type_label(row.get("attack_type"))</code> |
| L4119 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>            row["source_region"] = normalize_source_region_label(row.get("source_region"))</code> |
| L4120 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_events。 | <code>            row["ip_blocked"] = 1 if row.get("ip_blocked") else 0</code> |
| L4121 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 pro_events。 | <code>            items.append(row)</code> |
| L4122 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_events。 | <code>        return jsonify({"items": items, "page": page, "page_size": page_size, "total": total})</code> |
| L4123 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4124 | 注册 Flask HTTP 接口 "/api/v2/pro/candidates", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/pro/candidates", methods=["GET"])</code> |
| L4125 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L4126 | 定义procandidates函数 &#96;pro_candidates&#96;，封装可复用业务逻辑。 | <code>    def pro_candidates():</code> |
| L4127 | 计算并保存 &#96;page&#96;（page），供后续逻辑使用，当前位于函数 pro_candidates。 | <code>        page = max(1, int(request.args.get("page", "1")))</code> |
| L4128 | 计算并保存 &#96;page_size&#96;（pagesize），供后续逻辑使用，当前位于函数 pro_candidates。 | <code>        page_size = max(1, min(int(request.args.get("page_size", "10")), 100))</code> |
| L4129 | 计算并保存 &#96;q&#96;（q），供后续逻辑使用，当前位于函数 pro_candidates。 | <code>        q = request.args.get("q", "").strip()</code> |
| L4130 | 计算并保存 &#96;offset&#96;（offset），供后续逻辑使用，当前位于函数 pro_candidates。 | <code>        offset = (page - 1) * page_size</code> |
| L4131 | 计算并保存 &#96;where&#96;（where），供后续逻辑使用，当前位于函数 pro_candidates。 | <code>        where = ["c.decision='candidate'"]</code> |
| L4132 | 计算并保存 &#96;params&#96;（params），供后续逻辑使用，当前位于函数 pro_candidates。 | <code>        params: List[Any] = []</code> |
| L4133 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_candidates。 | <code>        if q:</code> |
| L4134 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 pro_candidates。 | <code>            where.append("(c.event_id LIKE %s OR c.case_id LIKE %s OR c.source_ip LIKE %s OR c.target_interface LIKE %s)")</code> |
| L4135 | 计算并保存 &#96;like&#96;（like），供后续逻辑使用，当前位于函数 pro_candidates。 | <code>            like = f"%{q}%"</code> |
| L4136 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 pro_candidates。 | <code>            params.extend([like, like, like, like])</code> |
| L4137 | 计算并保存 &#96;where_sql&#96;（wheresql），供后续逻辑使用，当前位于函数 pro_candidates。 | <code>        where_sql = " AND ".join(where)</code> |
| L4138 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4139 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_candidates。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L4140 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_candidates。 | <code>            with conn.cursor() as cur:</code> |
| L4141 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_candidates。 | <code>                if not db_table_exists(cur, "detection_candidates"):</code> |
| L4142 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_candidates。 | <code>                    return jsonify({"items": [], "page": page, "page_size": page_size, "total": 0})</code> |
| L4143 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_candidates。 | <code>                cur.execute(f"SELECT COUNT(*) AS c FROM detection_candidates c WHERE {where_sql}", tuple(params))</code> |
| L4144 | 计算并保存 &#96;total&#96;（total），供后续逻辑使用，当前位于函数 pro_candidates。 | <code>                total = int((cur.fetchone() or {}).get("c", 0))</code> |
| L4145 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_candidates。 | <code>                cur.execute(</code> |
| L4146 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidates。 | <code>                    f"""</code> |
| L4147 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidates。 | <code>                    SELECT</code> |
| L4148 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidates。 | <code>                      c.event_id, c.case_id, c.file_id, c.seq_id, c.decision, c.final_score,</code> |
| L4149 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidates。 | <code>                      c.risk_level, c.attack_type, c.source_ip, c.target_interface, c.created_at,</code> |
| L4150 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidates。 | <code>                      r.method, r.host, r.status_code</code> |
| L4151 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidates。 | <code>                    FROM detection_candidates c</code> |
| L4152 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidates。 | <code>                    LEFT JOIN raw_http_logs r ON r.case_id = c.case_id</code> |
| L4153 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidates。 | <code>                    WHERE {where_sql}</code> |
| L4154 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidates。 | <code>                    ORDER BY c.final_score DESC, c.created_at DESC</code> |
| L4155 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidates。 | <code>                    LIMIT %s OFFSET %s</code> |
| L4156 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidates。 | <code>                    """,</code> |
| L4157 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidates。 | <code>                    tuple(params + [page_size, offset]),</code> |
| L4158 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_candidates。 | <code>                )</code> |
| L4159 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 pro_candidates。 | <code>                rows = cur.fetchall()</code> |
| L4160 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 pro_candidates。 | <code>        items = []</code> |
| L4161 | 遍历集合中的数据项并逐项处理，当前位于函数 pro_candidates。 | <code>        for row in normalize_rows(rows):</code> |
| L4162 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidates。 | <code>            row["attack_type"] = normalize_attack_type_label(row.get("attack_type"))</code> |
| L4163 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 pro_candidates。 | <code>            items.append(row)</code> |
| L4164 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_candidates。 | <code>        return jsonify({"items": items, "page": page, "page_size": page_size, "total": total})</code> |
| L4165 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4166 | 注册 Flask HTTP 接口 "/api/v2/pro/candidates/&lt;event_id&gt;", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/pro/candidates/&lt;event_id&gt;", methods=["GET"])</code> |
| L4167 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L4168 | 定义procandidatedetail函数 &#96;pro_candidate_detail&#96;，封装可复用业务逻辑。 | <code>    def pro_candidate_detail(event_id: str):</code> |
| L4169 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_candidate_detail。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L4170 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_candidate_detail。 | <code>            with conn.cursor() as cur:</code> |
| L4171 | 计算并保存 &#96;detail&#96;（detail），供后续逻辑使用，当前位于函数 pro_candidate_detail。 | <code>                detail = load_v2_detection_detail(cur, event_id)</code> |
| L4172 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_candidate_detail。 | <code>            if not detail:</code> |
| L4173 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_candidate_detail。 | <code>                return jsonify({"error": "candidate_not_found"}), 404</code> |
| L4174 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 pro_candidate_detail。 | <code>            raw = detail.get("raw_http") or {}</code> |
| L4175 | 计算并保存 &#96;source_region&#96;（来源region），供后续逻辑使用，当前位于函数 pro_candidate_detail。 | <code>            source_region = resolve_region_for_event(conn, str(detail.get("source_ip") or ""), "")</code> |
| L4176 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 pro_candidate_detail。 | <code>        item = {</code> |
| L4177 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_detail。 | <code>            "event_id": detail.get("event_id") or event_id,</code> |
| L4178 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_detail。 | <code>            "occurred_at": raw.get("event_time") or raw.get("created_at") or "-",</code> |
| L4179 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_detail。 | <code>            "risk_level": detail.get("risk_level") or "medium",</code> |
| L4180 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_detail。 | <code>            "attack_type": normalize_attack_type_label(detail.get("attack_type")),</code> |
| L4181 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_detail。 | <code>            "source_ip": detail.get("source_ip") or raw.get("source_ip") or "-",</code> |
| L4182 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_detail。 | <code>            "source_region": source_region,</code> |
| L4183 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_detail。 | <code>            "target_node": "candidate-review",</code> |
| L4184 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_detail。 | <code>            "target_interface": detail.get("target_interface") or raw.get("uri") or "-",</code> |
| L4185 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_detail。 | <code>            "attack_result": "pending",</code> |
| L4186 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_detail。 | <code>            "process_status": "unprocessed",</code> |
| L4187 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_detail。 | <code>            "attack_payload": raw.get("request_text") or "",</code> |
| L4188 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_detail。 | <code>            "request_log": raw.get("request_text") or "",</code> |
| L4189 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_detail。 | <code>            "protection_action": "候选事件暂未进入大屏告警，等待人工复核。",</code> |
| L4190 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_detail。 | <code>            "handling_suggestion": "查看 Payload/POC/行为证据，确认后可提升为攻击事件，误报则忽略候选。",</code> |
| L4191 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_detail。 | <code>            "note": "",</code> |
| L4192 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_detail。 | <code>            "response_ms": 0,</code> |
| L4193 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_detail。 | <code>            "ip_blocked": 0,</code> |
| L4194 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_detail。 | <code>            "v2_detection": detail,</code> |
| L4195 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_candidate_detail。 | <code>        }</code> |
| L4196 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_candidate_detail。 | <code>        return jsonify(item)</code> |
| L4197 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4198 | 注册 Flask HTTP 接口 "/api/v2/pro/candidates/&lt;event_id&gt;/ignore", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/pro/candidates/&lt;event_id&gt;/ignore", methods=["POST"])</code> |
| L4199 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L4200 | 定义procandidateignore函数 &#96;pro_candidate_ignore&#96;，封装可复用业务逻辑。 | <code>    def pro_candidate_ignore(event_id: str):</code> |
| L4201 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_candidate_ignore。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L4202 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_candidate_ignore。 | <code>            with conn.cursor() as cur:</code> |
| L4203 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_candidate_ignore。 | <code>                if not db_table_exists(cur, "detection_candidates"):</code> |
| L4204 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_candidate_ignore。 | <code>                    return jsonify({"error": "candidate_not_found"}), 404</code> |
| L4205 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_candidate_ignore。 | <code>                cur.execute("SELECT event_id, case_id FROM detection_candidates WHERE event_id=%s LIMIT 1", (event_id,))</code> |
| L4206 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 pro_candidate_ignore。 | <code>                row = cur.fetchone()</code> |
| L4207 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_candidate_ignore。 | <code>                if not row:</code> |
| L4208 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_candidate_ignore。 | <code>                    return jsonify({"error": "candidate_not_found"}), 404</code> |
| L4209 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_candidate_ignore。 | <code>                cur.execute(</code> |
| L4210 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_ignore。 | <code>                    "UPDATE detection_candidates SET decision='raw_only', risk_level='info' WHERE event_id=%s",</code> |
| L4211 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_ignore。 | <code>                    (event_id,),</code> |
| L4212 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_candidate_ignore。 | <code>                )</code> |
| L4213 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_candidate_ignore。 | <code>                cur.execute("DELETE FROM attack_events WHERE event_id=%s", (event_id,))</code> |
| L4214 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_ignore。 | <code>                log_action(conn, g.session["username"], g.session["role"], "candidate_ignore", event_id, str(row.get("case_id") or ""))</code> |
| L4215 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_ignore。 | <code>            conn.commit()</code> |
| L4216 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_candidate_ignore。 | <code>        return jsonify({"ok": True, "event_id": event_id})</code> |
| L4217 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4218 | 注册 Flask HTTP 接口 "/api/v2/pro/candidates/&lt;event_id&gt;/promote", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/pro/candidates/&lt;event_id&gt;/promote", methods=["POST"])</code> |
| L4219 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L4220 | 定义procandidatepromote函数 &#96;pro_candidate_promote&#96;，封装可复用业务逻辑。 | <code>    def pro_candidate_promote(event_id: str):</code> |
| L4221 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_candidate_promote。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L4222 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_candidate_promote。 | <code>            with conn.cursor() as cur:</code> |
| L4223 | 计算并保存 &#96;detail&#96;（detail），供后续逻辑使用，当前位于函数 pro_candidate_promote。 | <code>                detail = load_v2_detection_detail(cur, event_id)</code> |
| L4224 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_candidate_promote。 | <code>                if not detail:</code> |
| L4225 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_candidate_promote。 | <code>                    return jsonify({"error": "candidate_not_found"}), 404</code> |
| L4226 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 pro_candidate_promote。 | <code>                raw = detail.get("raw_http") or {}</code> |
| L4227 | 计算并保存 &#96;event_key&#96;（事件key），供后续逻辑使用，当前位于函数 pro_candidate_promote。 | <code>                event_key = str(detail.get("event_id") or event_id)[:40]</code> |
| L4228 | 计算并保存 &#96;risk_level&#96;（risklevel），供后续逻辑使用，当前位于函数 pro_candidate_promote。 | <code>                risk_level = str(detail.get("risk_level") or "medium")[:16]</code> |
| L4229 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 pro_candidate_promote。 | <code>                attack_type = normalize_attack_type_label(detail.get("attack_type"))[:64]</code> |
| L4230 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 pro_candidate_promote。 | <code>                source_ip = str(detail.get("source_ip") or raw.get("source_ip") or "unknown")[:64]</code> |
| L4231 | 计算并保存 &#96;source_region&#96;（来源region），供后续逻辑使用，当前位于函数 pro_candidate_promote。 | <code>                source_region = resolve_region_for_event(conn, source_ip, "")</code> |
| L4232 | 计算并保存 &#96;target_interface&#96;（targetinterface），供后续逻辑使用，当前位于函数 pro_candidate_promote。 | <code>                target_interface = str(detail.get("target_interface") or raw.get("uri") or "-")[:255]</code> |
| L4233 | 计算并保存 &#96;occurred_at&#96;（occurredat），供后续逻辑使用，当前位于函数 pro_candidate_promote。 | <code>                occurred_at = raw.get("event_time") or raw.get("created_at") or dt_to_str(now_dt())</code> |
| L4234 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_candidate_promote。 | <code>                cur.execute(</code> |
| L4235 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                    """</code> |
| L4236 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 pro_candidate_promote。 | <code>                    INSERT INTO attack_events(event_id, case_id, occurred_at, source_ip, target_interface, attack_type,</code> |
| L4237 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                                              risk_level, confidence, status, evidence_json)</code> |
| L4238 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)</code> |
| L4239 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                    ON DUPLICATE KEY UPDATE</code> |
| L4240 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                      attack_type=VALUES(attack_type),</code> |
| L4241 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                      risk_level=VALUES(risk_level),</code> |
| L4242 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                      confidence=VALUES(confidence),</code> |
| L4243 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                      evidence_json=VALUES(evidence_json)</code> |
| L4244 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                    """,</code> |
| L4245 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                    (</code> |
| L4246 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        event_key,</code> |
| L4247 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        detail.get("case_id"),</code> |
| L4248 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        occurred_at,</code> |
| L4249 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        source_ip,</code> |
| L4250 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        target_interface,</code> |
| L4251 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        attack_type,</code> |
| L4252 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        risk_level,</code> |
| L4253 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        detail.get("final_score"),</code> |
| L4254 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        "unprocessed",</code> |
| L4255 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        json.dumps(detail.get("evidence") or [], ensure_ascii=False),</code> |
| L4256 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_candidate_promote。 | <code>                    ),</code> |
| L4257 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_candidate_promote。 | <code>                )</code> |
| L4258 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_candidate_promote。 | <code>                cur.execute(</code> |
| L4259 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                    "UPDATE detection_candidates SET decision='attack_event' WHERE event_id=%s",</code> |
| L4260 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                    (event_key,),</code> |
| L4261 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_candidate_promote。 | <code>                )</code> |
| L4262 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_candidate_promote。 | <code>                cur.execute(</code> |
| L4263 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                    """</code> |
| L4264 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 pro_candidate_promote。 | <code>                    INSERT INTO demo_attack_events(</code> |
| L4265 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                      event_id, occurred_at, risk_level, attack_type, source_ip, source_region, target_node, target_interface,</code> |
| L4266 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                      attack_result, process_status, acked, attack_payload, request_log, protection_action, handling_suggestion,</code> |
| L4267 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                      note, response_ms, anomaly_detected, machine_id</code> |
| L4268 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                    )</code> |
| L4269 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                    VALUES(</code> |
| L4270 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                      %s, COALESCE(STR_TO_DATE(%s, '%%Y-%%m-%%dT%%H:%%i:%%s'), NOW(3)), %s, %s, %s, %s, %s, %s,</code> |
| L4271 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                      %s, %s, 0, %s, %s, %s, %s, '', 0, 1, NULL</code> |
| L4272 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                    )</code> |
| L4273 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                    ON DUPLICATE KEY UPDATE</code> |
| L4274 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                      risk_level=VALUES(risk_level),</code> |
| L4275 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                      attack_type=VALUES(attack_type),</code> |
| L4276 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                      source_ip=VALUES(source_ip),</code> |
| L4277 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                      source_region=VALUES(source_region),</code> |
| L4278 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                      target_interface=VALUES(target_interface),</code> |
| L4279 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                      attack_payload=VALUES(attack_payload),</code> |
| L4280 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                      request_log=VALUES(request_log),</code> |
| L4281 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                      protection_action=VALUES(protection_action),</code> |
| L4282 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                      handling_suggestion=VALUES(handling_suggestion),</code> |
| L4283 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                      anomaly_detected=1</code> |
| L4284 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_candidate_promote。 | <code>                    """,</code> |
| L4285 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                    (</code> |
| L4286 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        event_key,</code> |
| L4287 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        str(occurred_at or ""),</code> |
| L4288 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        risk_level,</code> |
| L4289 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        attack_type,</code> |
| L4290 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        source_ip,</code> |
| L4291 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        source_region,</code> |
| L4292 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        "candidate-review",</code> |
| L4293 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        target_interface,</code> |
| L4294 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        "blocked",</code> |
| L4295 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        "unprocessed",</code> |
| L4296 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        str(raw.get("request_text") or "")[:20000],</code> |
| L4297 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        str(raw.get("request_text") or "")[:20000],</code> |
| L4298 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        "候选事件已由管理员提升为攻击事件。",</code> |
| L4299 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                        "建议进一步核查来源 IP、请求载荷和业务接口日志。",</code> |
| L4300 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_candidate_promote。 | <code>                    ),</code> |
| L4301 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_candidate_promote。 | <code>                )</code> |
| L4302 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>                log_action(conn, g.session["username"], g.session["role"], "candidate_promote", event_key, str(detail.get("case_id") or ""))</code> |
| L4303 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_candidate_promote。 | <code>            conn.commit()</code> |
| L4304 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_candidate_promote。 | <code>        return jsonify({"ok": True, "event_id": event_id})</code> |
| L4305 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4306 | 注册 Flask HTTP 接口 "/api/v2/pro/events/&lt;event_id&gt;", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/pro/events/&lt;event_id&gt;", methods=["GET"])</code> |
| L4307 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L4308 | 定义pro事件detail函数 &#96;pro_event_detail&#96;，封装可复用业务逻辑。 | <code>    def pro_event_detail(event_id: str):</code> |
| L4309 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_event_detail。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L4310 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_event_detail。 | <code>            with conn.cursor() as cur:</code> |
| L4311 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_event_detail。 | <code>                cur.execute(</code> |
| L4312 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_event_detail。 | <code>                    """</code> |
| L4313 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_event_detail。 | <code>                    SELECT</code> |
| L4314 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_event_detail。 | <code>                      e.event_id, e.occurred_at, e.risk_level, e.attack_type, e.source_ip, e.source_region,</code> |
| L4315 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_event_detail。 | <code>                      e.target_port, e.target_interface, e.process_status, e.attack_payload,</code> |
| L4316 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_event_detail。 | <code>                      e.request_log, e.protection_action, e.handling_suggestion, e.note, e.response_ms, e.anomaly_detected,</code> |
| L4317 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_event_detail。 | <code>                      CASE WHEN b.ip_address IS NULL THEN 0 ELSE 1 END AS ip_blocked,</code> |
| L4318 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_event_detail。 | <code>                      b.blocked_at AS ip_blocked_at</code> |
| L4319 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_event_detail。 | <code>                    FROM demo_attack_events e</code> |
| L4320 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_event_detail。 | <code>                    LEFT JOIN (</code> |
| L4321 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 pro_event_detail。 | <code>                      SELECT ip_address, MAX(blocked_at) AS blocked_at</code> |
| L4322 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_event_detail。 | <code>                      FROM demo_blocked_ips</code> |
| L4323 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_event_detail。 | <code>                      GROUP BY ip_address</code> |
| L4324 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_event_detail。 | <code>                    ) b ON b.ip_address = e.source_ip</code> |
| L4325 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_event_detail。 | <code>                    WHERE e.event_id=%s</code> |
| L4326 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_event_detail。 | <code>                    LIMIT 1</code> |
| L4327 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_event_detail。 | <code>                    """,</code> |
| L4328 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_event_detail。 | <code>                    (event_id,),</code> |
| L4329 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_event_detail。 | <code>                )</code> |
| L4330 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 pro_event_detail。 | <code>                row = cur.fetchone()</code> |
| L4331 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_event_detail。 | <code>        if not row:</code> |
| L4332 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_event_detail。 | <code>            return jsonify({"error": "event_not_found"}), 404</code> |
| L4333 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 pro_event_detail。 | <code>        item = normalize_row(row)</code> |
| L4334 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_event_detail。 | <code>        item["attack_type"] = normalize_attack_type_label(item.get("attack_type"))</code> |
| L4335 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_event_detail。 | <code>        item["ip_blocked"] = 1 if item.get("ip_blocked") else 0</code> |
| L4336 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_event_detail。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L4337 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_event_detail。 | <code>            item["source_region"] = resolve_region_for_event(</code> |
| L4338 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_event_detail。 | <code>                conn,</code> |
| L4339 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_event_detail。 | <code>                str(item.get("source_ip") or ""),</code> |
| L4340 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_event_detail。 | <code>                str(item.get("source_region") or ""),</code> |
| L4341 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_event_detail。 | <code>            )</code> |
| L4342 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_event_detail。 | <code>            with conn.cursor() as cur:</code> |
| L4343 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_event_detail。 | <code>                item["v2_detection"] = load_v2_detection_detail(cur, event_id)</code> |
| L4344 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_event_detail。 | <code>        return jsonify(item)</code> |
| L4345 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4346 | 注册 Flask HTTP 接口 "/api/v2/pro/events/&lt;event_id&gt;/block-ip", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/pro/events/&lt;event_id&gt;/block-ip", methods=["POST"])</code> |
| L4347 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L4348 | 定义pro封禁ip函数 &#96;pro_block_ip&#96;，封装可复用业务逻辑。 | <code>    def pro_block_ip(event_id: str):</code> |
| L4349 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 pro_block_ip。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L4350 | 计算并保存 &#96;reason&#96;（reason），供后续逻辑使用，当前位于函数 pro_block_ip。 | <code>        reason = str(body.get("reason", "")).strip()</code> |
| L4351 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_block_ip。 | <code>        if not reason:</code> |
| L4352 | 计算并保存 &#96;reason&#96;（reason），供后续逻辑使用，当前位于函数 pro_block_ip。 | <code>            reason = "manual_block_from_ui"</code> |
| L4353 | 计算并保存 &#96;block_mode&#96;（封禁mode），供后续逻辑使用，当前位于函数 pro_block_ip。 | <code>        block_mode = str(body.get("block_mode", "source") or "source").strip().lower()</code> |
| L4354 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_block_ip。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L4355 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_block_ip。 | <code>            with conn.cursor() as cur:</code> |
| L4356 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_block_ip。 | <code>                cur.execute("SELECT source_ip, request_log FROM demo_attack_events WHERE event_id=%s LIMIT 1", (event_id,))</code> |
| L4357 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 pro_block_ip。 | <code>                row = cur.fetchone()</code> |
| L4358 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_block_ip。 | <code>                if not row:</code> |
| L4359 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_block_ip。 | <code>                    return jsonify({"error": "event_not_found"}), 404</code> |
| L4360 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 pro_block_ip。 | <code>                source_ip = str(row.get("source_ip") or "").strip()</code> |
| L4361 | 计算并保存 &#96;request_log&#96;（requestlog），供后续逻辑使用，当前位于函数 pro_block_ip。 | <code>                request_log = str(row.get("request_log") or "")</code> |
| L4362 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                block_ips, block_meta = collect_event_block_ips(cur, event_id, source_ip, request_log, block_mode)</code> |
| L4363 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_block_ip。 | <code>                if not block_ips:</code> |
| L4364 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_block_ip。 | <code>                    return jsonify({"error": "source_ip_not_found", "message": "未识别到可封禁的来源IP"}), 400</code> |
| L4365 | 计算并保存 &#96;applied&#96;（applied），供后续逻辑使用，当前位于函数 pro_block_ip。 | <code>                applied: List[str] = []</code> |
| L4366 | 计算并保存 &#96;existed_count&#96;（existedcount），供后续逻辑使用，当前位于函数 pro_block_ip。 | <code>                existed_count = 0</code> |
| L4367 | 遍历集合中的数据项并逐项处理，当前位于函数 pro_block_ip。 | <code>                for ip_text in block_ips:</code> |
| L4368 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                    fw_ok, fw_detail = firewall_block_ip(ip_text)</code> |
| L4369 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_block_ip。 | <code>                    if not fw_ok:</code> |
| L4370 | 遍历集合中的数据项并逐项处理，当前位于函数 pro_block_ip。 | <code>                        for rollback_ip in applied:</code> |
| L4371 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                            firewall_unblock_ip(rollback_ip)</code> |
| L4372 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_block_ip。 | <code>                        return jsonify(</code> |
| L4373 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                            {</code> |
| L4374 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                                "error": "firewall_block_failed",</code> |
| L4375 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                                "message": "系统防火墙封禁失败，请使用管理员权限启动服务后重试",</code> |
| L4376 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                                "detail": fw_detail,</code> |
| L4377 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                                "failed_ip": ip_text,</code> |
| L4378 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                                "source_ip": block_meta.get("source_ip") or source_ip,</code> |
| L4379 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                                "blocked_ips": block_ips,</code> |
| L4380 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                                "block_mode": block_meta.get("mode"),</code> |
| L4381 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_block_ip。 | <code>                            }</code> |
| L4382 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_block_ip。 | <code>                        ), 500</code> |
| L4383 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 pro_block_ip。 | <code>                    applied.append(ip_text)</code> |
| L4384 | 遍历集合中的数据项并逐项处理，当前位于函数 pro_block_ip。 | <code>                for ip_text in block_ips:</code> |
| L4385 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_block_ip。 | <code>                    cur.execute("SELECT id FROM demo_blocked_ips WHERE ip_address=%s LIMIT 1", (ip_text,))</code> |
| L4386 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_block_ip。 | <code>                    if cur.fetchone():</code> |
| L4387 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                        existed_count += 1</code> |
| L4388 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_block_ip。 | <code>                    cur.execute(</code> |
| L4389 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_block_ip。 | <code>                        """</code> |
| L4390 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 pro_block_ip。 | <code>                        INSERT INTO demo_blocked_ips(ip_address, source_event_id, reason, blocked_by, blocked_role)</code> |
| L4391 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_block_ip。 | <code>                        VALUES (%s, %s, %s, %s, %s)</code> |
| L4392 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_block_ip。 | <code>                        ON DUPLICATE KEY UPDATE</code> |
| L4393 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_block_ip。 | <code>                          source_event_id=VALUES(source_event_id),</code> |
| L4394 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_block_ip。 | <code>                          reason=VALUES(reason),</code> |
| L4395 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_block_ip。 | <code>                          blocked_by=VALUES(blocked_by),</code> |
| L4396 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_block_ip。 | <code>                          blocked_role=VALUES(blocked_role),</code> |
| L4397 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_block_ip。 | <code>                          blocked_at=CURRENT_TIMESTAMP</code> |
| L4398 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_block_ip。 | <code>                        """,</code> |
| L4399 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                        (ip_text, event_id, reason[:255], g.session["username"], g.session["role"]),</code> |
| L4400 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_block_ip。 | <code>                    )</code> |
| L4401 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                log_action(</code> |
| L4402 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                    conn,</code> |
| L4403 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                    g.session["username"],</code> |
| L4404 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                    g.session["role"],</code> |
| L4405 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                    "block_ip",</code> |
| L4406 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                    ",".join(block_ips),</code> |
| L4407 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                    f"event_id={event_id},mode={block_meta.get('mode')},reason={reason[:120]}",</code> |
| L4408 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_block_ip。 | <code>                )</code> |
| L4409 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>            conn.commit()</code> |
| L4410 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_block_ip。 | <code>        return jsonify(</code> |
| L4411 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>            {</code> |
| L4412 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                "ok": True,</code> |
| L4413 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                "event_id": event_id,</code> |
| L4414 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                "source_ip": block_meta.get("source_ip") or source_ip,</code> |
| L4415 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                "blocked_ips": block_ips,</code> |
| L4416 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                "blocked_count": len(block_ips),</code> |
| L4417 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                "block_mode": block_meta.get("mode"),</code> |
| L4418 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_block_ip。 | <code>                "already_blocked_count": existed_count,</code> |
| L4419 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_block_ip。 | <code>            }</code> |
| L4420 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_block_ip。 | <code>        )</code> |
| L4421 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4422 | 注册 Flask HTTP 接口 "/api/v2/pro/events/&lt;event_id&gt;/unblock-ip", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/pro/events/&lt;event_id&gt;/unblock-ip", methods=["POST"])</code> |
| L4423 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L4424 | 定义pro解封ip函数 &#96;pro_unblock_ip&#96;，封装可复用业务逻辑。 | <code>    def pro_unblock_ip(event_id: str):</code> |
| L4425 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 pro_unblock_ip。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L4426 | 计算并保存 &#96;reason&#96;（reason），供后续逻辑使用，当前位于函数 pro_unblock_ip。 | <code>        reason = str(body.get("reason", "")).strip()</code> |
| L4427 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_unblock_ip。 | <code>        if not reason:</code> |
| L4428 | 计算并保存 &#96;reason&#96;（reason），供后续逻辑使用，当前位于函数 pro_unblock_ip。 | <code>            reason = "manual_unblock_from_ui"</code> |
| L4429 | 计算并保存 &#96;block_mode&#96;（封禁mode），供后续逻辑使用，当前位于函数 pro_unblock_ip。 | <code>        block_mode = str(body.get("block_mode", "source") or "source").strip().lower()</code> |
| L4430 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_unblock_ip。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L4431 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_unblock_ip。 | <code>            with conn.cursor() as cur:</code> |
| L4432 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_unblock_ip。 | <code>                cur.execute("SELECT source_ip, request_log FROM demo_attack_events WHERE event_id=%s LIMIT 1", (event_id,))</code> |
| L4433 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 pro_unblock_ip。 | <code>                row = cur.fetchone()</code> |
| L4434 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_unblock_ip。 | <code>                if not row:</code> |
| L4435 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_unblock_ip。 | <code>                    return jsonify({"error": "event_not_found"}), 404</code> |
| L4436 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 pro_unblock_ip。 | <code>                source_ip = str(row.get("source_ip") or "").strip()</code> |
| L4437 | 计算并保存 &#96;request_log&#96;（requestlog），供后续逻辑使用，当前位于函数 pro_unblock_ip。 | <code>                request_log = str(row.get("request_log") or "")</code> |
| L4438 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                event_ips, block_meta = collect_event_block_ips(cur, event_id, source_ip, request_log, block_mode)</code> |
| L4439 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_unblock_ip。 | <code>                cur.execute("SELECT ip_address FROM demo_blocked_ips WHERE source_event_id=%s", (event_id,))</code> |
| L4440 | 计算并保存 &#96;db_rows&#96;（数据库数据库记录），供后续逻辑使用，当前位于函数 pro_unblock_ip。 | <code>                db_rows = cur.fetchall() or []</code> |
| L4441 | 计算并保存 &#96;unblock_ips&#96;（解封ips），供后续逻辑使用，当前位于函数 pro_unblock_ip。 | <code>                unblock_ips: List[str] = []</code> |
| L4442 | 遍历集合中的数据项并逐项处理，当前位于函数 pro_unblock_ip。 | <code>                for ip_text in [*(r.get("ip_address") for r in db_rows), *event_ips]:</code> |
| L4443 | 计算并保存 &#96;ip_norm&#96;（ipnorm），供后续逻辑使用，当前位于函数 pro_unblock_ip。 | <code>                    ip_norm = normalize_ip_literal(ip_text)</code> |
| L4444 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_unblock_ip。 | <code>                    if ip_norm and ip_norm not in unblock_ips:</code> |
| L4445 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 pro_unblock_ip。 | <code>                        unblock_ips.append(ip_norm)</code> |
| L4446 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_unblock_ip。 | <code>                if not unblock_ips:</code> |
| L4447 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_unblock_ip。 | <code>                    return jsonify(</code> |
| L4448 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                        {</code> |
| L4449 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                            "ok": True,</code> |
| L4450 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                            "event_id": event_id,</code> |
| L4451 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                            "source_ip": block_meta.get("source_ip") or source_ip,</code> |
| L4452 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                            "unblocked_ips": [],</code> |
| L4453 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                            "deleted_rows": 0,</code> |
| L4454 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                            "block_mode": block_meta.get("mode"),</code> |
| L4455 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_unblock_ip。 | <code>                        }</code> |
| L4456 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_unblock_ip。 | <code>                    )</code> |
| L4457 | 计算并保存 &#96;failed&#96;（failed），供后续逻辑使用，当前位于函数 pro_unblock_ip。 | <code>                failed: List[Dict[str, str]] = []</code> |
| L4458 | 遍历集合中的数据项并逐项处理，当前位于函数 pro_unblock_ip。 | <code>                for ip_text in unblock_ips:</code> |
| L4459 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                    fw_ok, fw_detail = firewall_unblock_ip(ip_text)</code> |
| L4460 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_unblock_ip。 | <code>                    if not fw_ok:</code> |
| L4461 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 pro_unblock_ip。 | <code>                        failed.append({"ip": ip_text, "detail": fw_detail})</code> |
| L4462 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_unblock_ip。 | <code>                if failed:</code> |
| L4463 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_unblock_ip。 | <code>                    return jsonify(</code> |
| L4464 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                        {</code> |
| L4465 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                            "error": "firewall_unblock_failed",</code> |
| L4466 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                            "message": "系统防火墙解封失败，请使用管理员权限启动服务后重试",</code> |
| L4467 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                            "failed": failed,</code> |
| L4468 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                            "source_ip": block_meta.get("source_ip") or source_ip,</code> |
| L4469 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                            "unblocked_ips": unblock_ips,</code> |
| L4470 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                            "block_mode": block_meta.get("mode"),</code> |
| L4471 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_unblock_ip。 | <code>                        }</code> |
| L4472 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_unblock_ip。 | <code>                    ), 500</code> |
| L4473 | 计算并保存 &#96;placeholders&#96;（placeholders），供后续逻辑使用，当前位于函数 pro_unblock_ip。 | <code>                placeholders = ",".join(["%s"] * len(unblock_ips))</code> |
| L4474 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_unblock_ip。 | <code>                cur.execute(f"DELETE FROM demo_blocked_ips WHERE ip_address IN ({placeholders})", tuple(unblock_ips))</code> |
| L4475 | 计算并保存 &#96;changed&#96;（changed），供后续逻辑使用，当前位于函数 pro_unblock_ip。 | <code>                changed = int(cur.rowcount or 0)</code> |
| L4476 | 遍历集合中的数据项并逐项处理，当前位于函数 pro_unblock_ip。 | <code>                for ip_text in unblock_ips:</code> |
| L4477 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                    record_auto_defense_release(cur, ip_text, g.session["username"])</code> |
| L4478 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                log_action(</code> |
| L4479 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                    conn,</code> |
| L4480 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                    g.session["username"],</code> |
| L4481 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                    g.session["role"],</code> |
| L4482 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                    "unblock_ip",</code> |
| L4483 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                    ",".join(unblock_ips),</code> |
| L4484 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                    f"event_id={event_id},mode={block_meta.get('mode')},reason={reason[:120]}",</code> |
| L4485 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_unblock_ip。 | <code>                )</code> |
| L4486 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>            conn.commit()</code> |
| L4487 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_unblock_ip。 | <code>        return jsonify(</code> |
| L4488 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>            {</code> |
| L4489 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                "ok": True,</code> |
| L4490 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                "event_id": event_id,</code> |
| L4491 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                "source_ip": block_meta.get("source_ip") or source_ip,</code> |
| L4492 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                "unblocked_ips": unblock_ips,</code> |
| L4493 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                "unblocked_count": len(unblock_ips),</code> |
| L4494 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                "deleted_rows": changed,</code> |
| L4495 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_unblock_ip。 | <code>                "block_mode": block_meta.get("mode"),</code> |
| L4496 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_unblock_ip。 | <code>            }</code> |
| L4497 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_unblock_ip。 | <code>        )</code> |
| L4498 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4499 | 注册 Flask HTTP 接口 "/api/v2/defense/status", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/defense/status", methods=["GET"])</code> |
| L4500 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L4501 | 定义defense状态函数 &#96;defense_status&#96;，封装可复用业务逻辑。 | <code>    def defense_status():</code> |
| L4502 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 defense_status。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L4503 | 计算并保存 &#96;config&#96;（配置），供后续逻辑使用，当前位于函数 defense_status。 | <code>            config = load_system_config_map(conn)</code> |
| L4504 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 defense_status。 | <code>            with conn.cursor() as cur:</code> |
| L4505 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 defense_status。 | <code>                cur.execute("SELECT COUNT(*) AS c FROM demo_blocked_ips")</code> |
| L4506 | 计算并保存 &#96;blocked_count&#96;（blockedcount），供后续逻辑使用，当前位于函数 defense_status。 | <code>                blocked_count = int((cur.fetchone() or {}).get("c", 0))</code> |
| L4507 | 结束当前函数并把结果返回给调用方，当前位于函数 defense_status。 | <code>        return jsonify(</code> |
| L4508 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_status。 | <code>            {</code> |
| L4509 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_status。 | <code>                "enabled": config.get("auto_defense_enabled", "0") == "1",</code> |
| L4510 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_status。 | <code>                "minimum_risk": config.get("auto_defense_min_risk", "critical"),</code> |
| L4511 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_status。 | <code>                "allow_private": config.get("auto_defense_allow_private", "0") == "1",</code> |
| L4512 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_status。 | <code>                "blocked_count": blocked_count,</code> |
| L4513 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_status。 | <code>                "enforcement": "windows_firewall_bidirectional",</code> |
| L4514 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_status。 | <code>                "platform_supported": os.name == "nt",</code> |
| L4515 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_status。 | <code>                "poll_seconds": 5,</code> |
| L4516 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 defense_status。 | <code>            }</code> |
| L4517 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 defense_status。 | <code>        )</code> |
| L4518 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4519 | 注册 Flask HTTP 接口 "/api/v2/defense/config", methods=["PUT"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/defense/config", methods=["PUT"])</code> |
| L4520 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L4521 | 定义defense配置更新函数 &#96;defense_config_update&#96;，封装可复用业务逻辑。 | <code>    def defense_config_update():</code> |
| L4522 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 defense_config_update。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L4523 | 计算并保存 &#96;enabled&#96;（enabled），供后续逻辑使用，当前位于函数 defense_config_update。 | <code>        enabled = bool(body.get("enabled"))</code> |
| L4524 | 计算并保存 &#96;minimum_risk&#96;（minimumrisk），供后续逻辑使用，当前位于函数 defense_config_update。 | <code>        minimum_risk = str(body.get("minimum_risk", "critical")).strip().lower()</code> |
| L4525 | 计算并保存 &#96;allow_private&#96;（allowprivate），供后续逻辑使用，当前位于函数 defense_config_update。 | <code>        allow_private = bool(body.get("allow_private", False))</code> |
| L4526 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 defense_config_update。 | <code>        if minimum_risk not in {"high", "critical"}:</code> |
| L4527 | 结束当前函数并把结果返回给调用方，当前位于函数 defense_config_update。 | <code>            return jsonify({"error": "invalid_minimum_risk"}), 400</code> |
| L4528 | 计算并保存 &#96;values&#96;（values），供后续逻辑使用，当前位于函数 defense_config_update。 | <code>        values = {</code> |
| L4529 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_config_update。 | <code>            "auto_defense_enabled": "1" if enabled else "0",</code> |
| L4530 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_config_update。 | <code>            "auto_defense_min_risk": minimum_risk,</code> |
| L4531 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_config_update。 | <code>            "auto_defense_allow_private": "1" if allow_private else "0",</code> |
| L4532 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 defense_config_update。 | <code>        }</code> |
| L4533 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 defense_config_update。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L4534 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 defense_config_update。 | <code>            with conn.cursor() as cur:</code> |
| L4535 | 遍历集合中的数据项并逐项处理，当前位于函数 defense_config_update。 | <code>                for key, value in values.items():</code> |
| L4536 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 defense_config_update。 | <code>                    cur.execute(</code> |
| L4537 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 defense_config_update。 | <code>                        """INSERT INTO demo_system_config(config_key,config_value)</code> |
| L4538 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 defense_config_update。 | <code>                           VALUES(%s,%s) ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)""",</code> |
| L4539 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_config_update。 | <code>                        (key, value),</code> |
| L4540 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 defense_config_update。 | <code>                    )</code> |
| L4541 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_config_update。 | <code>                log_action(</code> |
| L4542 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_config_update。 | <code>                    conn,</code> |
| L4543 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_config_update。 | <code>                    g.session["username"],</code> |
| L4544 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_config_update。 | <code>                    g.session["role"],</code> |
| L4545 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_config_update。 | <code>                    "update_auto_defense",</code> |
| L4546 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_config_update。 | <code>                    "windows_firewall",</code> |
| L4547 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_config_update。 | <code>                    json.dumps(values, ensure_ascii=False),</code> |
| L4548 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 defense_config_update。 | <code>                )</code> |
| L4549 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defense_config_update。 | <code>            conn.commit()</code> |
| L4550 | 结束当前函数并把结果返回给调用方，当前位于函数 defense_config_update。 | <code>        return jsonify({"ok": True, "enabled": enabled, "minimum_risk": minimum_risk, "allow_private": allow_private})</code> |
| L4551 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4552 | 注册 Flask HTTP 接口 "/api/v2/pro/blocked-ips", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/pro/blocked-ips", methods=["GET"])</code> |
| L4553 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L4554 | 定义problockedips函数 &#96;pro_blocked_ips&#96;，封装可复用业务逻辑。 | <code>    def pro_blocked_ips():</code> |
| L4555 | 计算并保存 &#96;q&#96;（q），供后续逻辑使用，当前位于函数 pro_blocked_ips。 | <code>        q = request.args.get("q", "").strip()</code> |
| L4556 | 计算并保存 &#96;page&#96;（page），供后续逻辑使用，当前位于函数 pro_blocked_ips。 | <code>        page = max(1, int(request.args.get("page", "1")))</code> |
| L4557 | 计算并保存 &#96;page_size&#96;（pagesize），供后续逻辑使用，当前位于函数 pro_blocked_ips。 | <code>        page_size = max(1, min(int(request.args.get("page_size", "20")), 200))</code> |
| L4558 | 计算并保存 &#96;offset&#96;（offset），供后续逻辑使用，当前位于函数 pro_blocked_ips。 | <code>        offset = (page - 1) * page_size</code> |
| L4559 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4560 | 计算并保存 &#96;where&#96;（where），供后续逻辑使用，当前位于函数 pro_blocked_ips。 | <code>        where: List[str] = []</code> |
| L4561 | 计算并保存 &#96;params&#96;（params），供后续逻辑使用，当前位于函数 pro_blocked_ips。 | <code>        params: List[Any] = []</code> |
| L4562 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_blocked_ips。 | <code>        if q:</code> |
| L4563 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 pro_blocked_ips。 | <code>            where.append("(b.ip_address LIKE %s OR b.source_event_id LIKE %s OR b.reason LIKE %s OR b.blocked_by LIKE %s)")</code> |
| L4564 | 计算并保存 &#96;like&#96;（like），供后续逻辑使用，当前位于函数 pro_blocked_ips。 | <code>            like = f"%{q}%"</code> |
| L4565 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 pro_blocked_ips。 | <code>            params.extend([like, like, like, like])</code> |
| L4566 | 计算并保存 &#96;where_sql&#96;（wheresql），供后续逻辑使用，当前位于函数 pro_blocked_ips。 | <code>        where_sql = ("WHERE " + " AND ".join(where)) if where else ""</code> |
| L4567 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4568 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_blocked_ips。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L4569 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_blocked_ips。 | <code>            with conn.cursor() as cur:</code> |
| L4570 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_blocked_ips。 | <code>                cur.execute(f"SELECT COUNT(*) AS c FROM demo_blocked_ips b {where_sql}", tuple(params))</code> |
| L4571 | 计算并保存 &#96;total&#96;（total），供后续逻辑使用，当前位于函数 pro_blocked_ips。 | <code>                total = int((cur.fetchone() or {}).get("c", 0))</code> |
| L4572 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_blocked_ips。 | <code>                cur.execute(</code> |
| L4573 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips。 | <code>                    f"""</code> |
| L4574 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips。 | <code>                    SELECT</code> |
| L4575 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips。 | <code>                      b.id,</code> |
| L4576 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips。 | <code>                      b.ip_address,</code> |
| L4577 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips。 | <code>                      b.source_event_id,</code> |
| L4578 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips。 | <code>                      b.reason,</code> |
| L4579 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips。 | <code>                      b.blocked_by,</code> |
| L4580 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips。 | <code>                      b.blocked_role,</code> |
| L4581 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips。 | <code>                      b.blocked_at</code> |
| L4582 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips。 | <code>                    FROM demo_blocked_ips b</code> |
| L4583 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips。 | <code>                    {where_sql}</code> |
| L4584 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips。 | <code>                    ORDER BY b.blocked_at DESC, b.id DESC</code> |
| L4585 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips。 | <code>                    LIMIT %s OFFSET %s</code> |
| L4586 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips。 | <code>                    """,</code> |
| L4587 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips。 | <code>                    tuple(params + [page_size, offset]),</code> |
| L4588 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_blocked_ips。 | <code>                )</code> |
| L4589 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 pro_blocked_ips。 | <code>                rows = list(cur.fetchall())</code> |
| L4590 | 计算并保存 &#96;firewall_states&#96;（firewallstates），供后续逻辑使用，当前位于函数 pro_blocked_ips。 | <code>        firewall_states = verified_firewall_status_many([str(row.get("ip_address") or "") for row in rows])</code> |
| L4591 | 遍历集合中的数据项并逐项处理，当前位于函数 pro_blocked_ips。 | <code>        for row in rows:</code> |
| L4592 | 计算并保存 &#96;status&#96;（状态），供后续逻辑使用，当前位于函数 pro_blocked_ips。 | <code>            status = firewall_states.get(str(row.get("ip_address") or ""), {})</code> |
| L4593 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips。 | <code>            row["firewall_active"] = bool(status.get("active"))</code> |
| L4594 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips。 | <code>            row["inbound_active"] = bool(status.get("inbound"))</code> |
| L4595 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips。 | <code>            row["outbound_active"] = bool(status.get("outbound"))</code> |
| L4596 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_blocked_ips。 | <code>        return jsonify({"items": normalize_rows(rows), "page": page, "page_size": page_size, "total": total})</code> |
| L4597 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4598 | 注册 Flask HTTP 接口 "/api/v2/pro/blocked-ips/unblock", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/pro/blocked-ips/unblock", methods=["POST"])</code> |
| L4599 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L4600 | 定义problockedips解封函数 &#96;pro_blocked_ips_unblock&#96;，封装可复用业务逻辑。 | <code>    def pro_blocked_ips_unblock():</code> |
| L4601 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 pro_blocked_ips_unblock。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L4602 | 计算并保存 &#96;ip_text&#96;（iptext），供后续逻辑使用，当前位于函数 pro_blocked_ips_unblock。 | <code>        ip_text = normalize_ip_literal(body.get("ip_address"))</code> |
| L4603 | 计算并保存 &#96;reason&#96;（reason），供后续逻辑使用，当前位于函数 pro_blocked_ips_unblock。 | <code>        reason = str(body.get("reason", "")).strip() or "manual_unblock_from_blocked_list"</code> |
| L4604 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_blocked_ips_unblock。 | <code>        if not ip_text:</code> |
| L4605 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_blocked_ips_unblock。 | <code>            return jsonify({"error": "invalid_ip_address"}), 400</code> |
| L4606 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips_unblock。 | <code>        fw_ok, fw_detail = firewall_unblock_ip(ip_text)</code> |
| L4607 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_blocked_ips_unblock。 | <code>        if not fw_ok:</code> |
| L4608 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_blocked_ips_unblock。 | <code>            return jsonify(</code> |
| L4609 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips_unblock。 | <code>                {</code> |
| L4610 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips_unblock。 | <code>                    "error": "firewall_unblock_failed",</code> |
| L4611 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips_unblock。 | <code>                    "message": "系统防火墙解封失败，请使用管理员权限启动服务后重试",</code> |
| L4612 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips_unblock。 | <code>                    "detail": fw_detail,</code> |
| L4613 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips_unblock。 | <code>                    "ip_address": ip_text,</code> |
| L4614 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_blocked_ips_unblock。 | <code>                }</code> |
| L4615 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_blocked_ips_unblock。 | <code>            ), 500</code> |
| L4616 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_blocked_ips_unblock。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L4617 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_blocked_ips_unblock。 | <code>            with conn.cursor() as cur:</code> |
| L4618 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_blocked_ips_unblock。 | <code>                cur.execute("DELETE FROM demo_blocked_ips WHERE ip_address=%s", (ip_text,))</code> |
| L4619 | 计算并保存 &#96;changed&#96;（changed），供后续逻辑使用，当前位于函数 pro_blocked_ips_unblock。 | <code>                changed = int(cur.rowcount or 0)</code> |
| L4620 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips_unblock。 | <code>                record_auto_defense_release(cur, ip_text, g.session["username"])</code> |
| L4621 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips_unblock。 | <code>                log_action(</code> |
| L4622 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips_unblock。 | <code>                    conn,</code> |
| L4623 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips_unblock。 | <code>                    g.session["username"],</code> |
| L4624 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips_unblock。 | <code>                    g.session["role"],</code> |
| L4625 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips_unblock。 | <code>                    "unblock_ip_direct",</code> |
| L4626 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips_unblock。 | <code>                    ip_text,</code> |
| L4627 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips_unblock。 | <code>                    f"reason={reason[:120]}",</code> |
| L4628 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_blocked_ips_unblock。 | <code>                )</code> |
| L4629 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_blocked_ips_unblock。 | <code>            conn.commit()</code> |
| L4630 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_blocked_ips_unblock。 | <code>        return jsonify({"ok": True, "ip_address": ip_text, "deleted_rows": changed})</code> |
| L4631 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4632 | 注册 Flask HTTP 接口 "/api/v2/pro/events/batch-status", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/pro/events/batch-status", methods=["POST"])</code> |
| L4633 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L4634 | 定义probatch状态函数 &#96;pro_batch_status&#96;，封装可复用业务逻辑。 | <code>    def pro_batch_status():</code> |
| L4635 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 pro_batch_status。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L4636 | 计算并保存 &#96;event_ids&#96;（事件ids），供后续逻辑使用，当前位于函数 pro_batch_status。 | <code>        event_ids = body.get("event_ids", [])</code> |
| L4637 | 计算并保存 &#96;new_status&#96;（new状态），供后续逻辑使用，当前位于函数 pro_batch_status。 | <code>        new_status = str(body.get("process_status", "")).strip().lower()</code> |
| L4638 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_batch_status。 | <code>        if not isinstance(event_ids, list) or not event_ids:</code> |
| L4639 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_batch_status。 | <code>            return jsonify({"error": "event_ids_required"}), 400</code> |
| L4640 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_batch_status。 | <code>        if new_status not in PROCESS_STATUS_SET:</code> |
| L4641 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_batch_status。 | <code>            return jsonify({"error": "invalid_process_status"}), 400</code> |
| L4642 | 计算并保存 &#96;placeholders&#96;（placeholders），供后续逻辑使用，当前位于函数 pro_batch_status。 | <code>        placeholders = ",".join(["%s"] * len(event_ids))</code> |
| L4643 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_batch_status。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L4644 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_batch_status。 | <code>            with conn.cursor() as cur:</code> |
| L4645 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_batch_status。 | <code>                cur.execute(</code> |
| L4646 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_batch_status。 | <code>                    f"UPDATE demo_attack_events SET process_status=%s, acked=CASE WHEN %s IN ('done','ignored') THEN 1 ELSE acked END WHERE event_id IN ({placeholders})",</code> |
| L4647 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_batch_status。 | <code>                    tuple([new_status, new_status] + event_ids),</code> |
| L4648 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_batch_status。 | <code>                )</code> |
| L4649 | 计算并保存 &#96;affected&#96;（affected），供后续逻辑使用，当前位于函数 pro_batch_status。 | <code>                affected = cur.rowcount</code> |
| L4650 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_batch_status。 | <code>                refresh_machine_stats(conn)</code> |
| L4651 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_batch_status。 | <code>                log_action(</code> |
| L4652 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_batch_status。 | <code>                    conn,</code> |
| L4653 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_batch_status。 | <code>                    g.session["username"],</code> |
| L4654 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_batch_status。 | <code>                    g.session["role"],</code> |
| L4655 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_batch_status。 | <code>                    "batch_status_update",</code> |
| L4656 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_batch_status。 | <code>                    "events",</code> |
| L4657 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_batch_status。 | <code>                    f"count={len(event_ids)},status={new_status}",</code> |
| L4658 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_batch_status。 | <code>                )</code> |
| L4659 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_batch_status。 | <code>            conn.commit()</code> |
| L4660 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_batch_status。 | <code>        return jsonify({"ok": True, "affected": affected})</code> |
| L4661 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4662 | 注册 Flask HTTP 接口 "/api/v2/pro/events/&lt;event_id&gt;/note", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/pro/events/&lt;event_id&gt;/note", methods=["POST"])</code> |
| L4663 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L4664 | 定义pro事件note函数 &#96;pro_event_note&#96;，封装可复用业务逻辑。 | <code>    def pro_event_note(event_id: str):</code> |
| L4665 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 pro_event_note。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L4666 | 计算并保存 &#96;note&#96;（note），供后续逻辑使用，当前位于函数 pro_event_note。 | <code>        note = str(body.get("note", "")).strip()</code> |
| L4667 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_event_note。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L4668 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_event_note。 | <code>            with conn.cursor() as cur:</code> |
| L4669 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_event_note。 | <code>                cur.execute("UPDATE demo_attack_events SET note=%s WHERE event_id=%s", (note, event_id))</code> |
| L4670 | 计算并保存 &#96;changed&#96;（changed），供后续逻辑使用，当前位于函数 pro_event_note。 | <code>                changed = cur.rowcount</code> |
| L4671 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_event_note。 | <code>                log_action(conn, g.session["username"], g.session["role"], "event_note", event_id, note[:120])</code> |
| L4672 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_event_note。 | <code>            conn.commit()</code> |
| L4673 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_event_note。 | <code>        if changed == 0:</code> |
| L4674 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_event_note。 | <code>            return jsonify({"error": "event_not_found"}), 404</code> |
| L4675 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_event_note。 | <code>        return jsonify({"ok": True, "event_id": event_id})</code> |
| L4676 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4677 | 注册 Flask HTTP 接口 "/api/v2/pro/model/performance", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/pro/model/performance", methods=["GET"])</code> |
| L4678 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L4679 | 定义pro模型performance函数 &#96;pro_model_performance&#96;，封装可复用业务逻辑。 | <code>    def pro_model_performance():</code> |
| L4680 | 计算并保存 &#96;visible_sql&#96;（visiblesql），供后续逻辑使用，当前位于函数 pro_model_performance。 | <code>        visible_sql = visible_attack_event_clause()</code> |
| L4681 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_model_performance。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L4682 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_model_performance。 | <code>            with conn.cursor() as cur:</code> |
| L4683 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_model_performance。 | <code>                cur.execute(</code> |
| L4684 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_model_performance。 | <code>                    """</code> |
| L4685 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_model_performance。 | <code>                    SELECT</code> |
| L4686 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_model_performance。 | <code>                      DATE(metric_time) AS d,</code> |
| L4687 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_model_performance。 | <code>                      AVG(drift_score) AS drift_score,</code> |
| L4688 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_model_performance。 | <code>                      AVG(accuracy) AS accuracy,</code> |
| L4689 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_model_performance。 | <code>                      AVG(recall_rate) AS recall_rate,</code> |
| L4690 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_model_performance。 | <code>                      AVG(inference_ms) AS inference_ms</code> |
| L4691 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_model_performance。 | <code>                    FROM demo_model_metrics</code> |
| L4692 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_model_performance。 | <code>                    WHERE metric_time &gt;= DATE_SUB(CURDATE(), INTERVAL 30 DAY)</code> |
| L4693 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_model_performance。 | <code>                    GROUP BY DATE(metric_time)</code> |
| L4694 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_model_performance。 | <code>                    ORDER BY d</code> |
| L4695 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 pro_model_performance。 | <code>                    """</code> |
| L4696 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_model_performance。 | <code>                )</code> |
| L4697 | 计算并保存 &#96;trend&#96;（trend），供后续逻辑使用，当前位于函数 pro_model_performance。 | <code>                trend = cur.fetchall()</code> |
| L4698 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_model_performance。 | <code>                cur.execute(</code> |
| L4699 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_model_performance。 | <code>                    f"""</code> |
| L4700 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_model_performance。 | <code>                    SELECT</code> |
| L4701 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_model_performance。 | <code>                      SUM(CASE WHEN response_ms &lt; 100 THEN 1 ELSE 0 END) AS lt_100,</code> |
| L4702 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_model_performance。 | <code>                      SUM(CASE WHEN response_ms &gt;= 100 AND response_ms &lt; 300 THEN 1 ELSE 0 END) AS b100_300,</code> |
| L4703 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_model_performance。 | <code>                      SUM(CASE WHEN response_ms &gt;= 300 AND response_ms &lt; 800 THEN 1 ELSE 0 END) AS b300_800,</code> |
| L4704 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_model_performance。 | <code>                      SUM(CASE WHEN response_ms &gt;= 800 THEN 1 ELSE 0 END) AS ge_800</code> |
| L4705 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_model_performance。 | <code>                    FROM demo_attack_events</code> |
| L4706 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_model_performance。 | <code>                    WHERE occurred_at &gt;= DATE_SUB(NOW(), INTERVAL 30 DAY) AND {visible_sql}</code> |
| L4707 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_model_performance。 | <code>                    """</code> |
| L4708 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_model_performance。 | <code>                )</code> |
| L4709 | 计算并保存 &#96;dist&#96;（dist），供后续逻辑使用，当前位于函数 pro_model_performance。 | <code>                dist = cur.fetchone() or {}</code> |
| L4710 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_model_performance。 | <code>        return jsonify(</code> |
| L4711 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_model_performance。 | <code>            {</code> |
| L4712 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_model_performance。 | <code>                "trend": normalize_rows(trend),</code> |
| L4713 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_model_performance。 | <code>                "inference_distribution": [</code> |
| L4714 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_model_performance。 | <code>                    {"bucket": "&lt;100ms", "count": int(dist.get("lt_100") or 0)},</code> |
| L4715 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_model_performance。 | <code>                    {"bucket": "100-300ms", "count": int(dist.get("b100_300") or 0)},</code> |
| L4716 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_model_performance。 | <code>                    {"bucket": "300-800ms", "count": int(dist.get("b300_800") or 0)},</code> |
| L4717 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_model_performance。 | <code>                    {"bucket": "&gt;=800ms", "count": int(dist.get("ge_800") or 0)},</code> |
| L4718 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_model_performance。 | <code>                ],</code> |
| L4719 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_model_performance。 | <code>            }</code> |
| L4720 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_model_performance。 | <code>        )</code> |
| L4721 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4722 | 注册 Flask HTTP 接口 "/api/v2/pro/nodes/&lt;node_name&gt;/detail", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/pro/nodes/&lt;node_name&gt;/detail", methods=["GET"])</code> |
| L4723 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_NORMAL, ROLE_ADMIN)</code> |
| L4724 | 定义pronodedetail函数 &#96;pro_node_detail&#96;，封装可复用业务逻辑。 | <code>    def pro_node_detail(node_name: str):</code> |
| L4725 | 计算并保存 &#96;visible_sql&#96;（visiblesql），供后续逻辑使用，当前位于函数 pro_node_detail。 | <code>        visible_sql = visible_attack_event_clause()</code> |
| L4726 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_node_detail。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L4727 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 pro_node_detail。 | <code>            with conn.cursor() as cur:</code> |
| L4728 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_node_detail。 | <code>                cur.execute("SELECT * FROM demo_machines WHERE machine_name=%s LIMIT 1", (node_name,))</code> |
| L4729 | 计算并保存 &#96;machine&#96;（machine），供后续逻辑使用，当前位于函数 pro_node_detail。 | <code>                machine = cur.fetchone()</code> |
| L4730 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 pro_node_detail。 | <code>                if not machine:</code> |
| L4731 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_node_detail。 | <code>                    return jsonify({"error": "node_not_found"}), 404</code> |
| L4732 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_node_detail。 | <code>                cur.execute(</code> |
| L4733 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_node_detail。 | <code>                    f"""</code> |
| L4734 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_node_detail。 | <code>                    SELECT COUNT(*) AS total_7d,</code> |
| L4735 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_node_detail。 | <code>                           SUM(CASE WHEN attack_result='blocked' THEN 1 ELSE 0 END) AS blocked_7d,</code> |
| L4736 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_node_detail。 | <code>                           SUM(CASE WHEN risk_level IN ('critical','high') THEN 1 ELSE 0 END) AS high_7d</code> |
| L4737 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_node_detail。 | <code>                    FROM demo_attack_events</code> |
| L4738 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_node_detail。 | <code>                    WHERE target_node=%s AND occurred_at &gt;= DATE_SUB(NOW(), INTERVAL 7 DAY) AND {visible_sql}</code> |
| L4739 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_node_detail。 | <code>                    """,</code> |
| L4740 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_node_detail。 | <code>                    (node_name,),</code> |
| L4741 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_node_detail。 | <code>                )</code> |
| L4742 | 计算并保存 &#96;stats&#96;（stats），供后续逻辑使用，当前位于函数 pro_node_detail。 | <code>                stats = cur.fetchone() or {}</code> |
| L4743 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_node_detail。 | <code>                cur.execute(</code> |
| L4744 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_node_detail。 | <code>                    f"""</code> |
| L4745 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 pro_node_detail。 | <code>                    SELECT event_id, occurred_at, risk_level, attack_type, source_ip, attack_result, process_status</code> |
| L4746 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_node_detail。 | <code>                    FROM demo_attack_events</code> |
| L4747 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_node_detail。 | <code>                    WHERE target_node=%s AND {visible_sql}</code> |
| L4748 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_node_detail。 | <code>                    ORDER BY occurred_at DESC</code> |
| L4749 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_node_detail。 | <code>                    LIMIT 50</code> |
| L4750 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_node_detail。 | <code>                    """,</code> |
| L4751 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 pro_node_detail。 | <code>                    (node_name,),</code> |
| L4752 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 pro_node_detail。 | <code>                )</code> |
| L4753 | 计算并保存 &#96;events&#96;（事件），供后续逻辑使用，当前位于函数 pro_node_detail。 | <code>                events = cur.fetchall()</code> |
| L4754 | 结束当前函数并把结果返回给调用方，当前位于函数 pro_node_detail。 | <code>        return jsonify({"machine": normalize_row(machine), "stats": normalize_row(stats), "recent_events": normalize_rows(events)})</code> |
| L4755 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4756 | 注册 Flask HTTP 接口 "/api/v2/admin/users", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/admin/users", methods=["GET"])</code> |
| L4757 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L4758 | 定义adminusers列出函数 &#96;admin_users_list&#96;，封装可复用业务逻辑。 | <code>    def admin_users_list():</code> |
| L4759 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_users_list。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L4760 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_users_list。 | <code>            with conn.cursor() as cur:</code> |
| L4761 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_users_list。 | <code>                cur.execute(</code> |
| L4762 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_users_list。 | <code>                    """</code> |
| L4763 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 admin_users_list。 | <code>                    SELECT id, username, role, display_name, nickname, avatar_url, created_at, updated_at</code> |
| L4764 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_users_list。 | <code>                    FROM demo_users</code> |
| L4765 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_users_list。 | <code>                    WHERE role IN (%s, %s)</code> |
| L4766 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_users_list。 | <code>                    ORDER BY CASE role</code> |
| L4767 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_users_list。 | <code>                        WHEN %s THEN 1</code> |
| L4768 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_users_list。 | <code>                        WHEN %s THEN 2</code> |
| L4769 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_users_list。 | <code>                        ELSE 3</code> |
| L4770 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_users_list。 | <code>                    END, username</code> |
| L4771 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_users_list。 | <code>                    """,</code> |
| L4772 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_users_list。 | <code>                    (ROLE_NORMAL, ROLE_ADMIN, ROLE_ADMIN, ROLE_NORMAL),</code> |
| L4773 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_users_list。 | <code>                )</code> |
| L4774 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 admin_users_list。 | <code>                rows = cur.fetchall()</code> |
| L4775 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_users_list。 | <code>        return jsonify({"items": normalize_rows(rows)})</code> |
| L4776 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4777 | 注册 Flask HTTP 接口 "/api/v2/admin/users/&lt;username&gt;/profile", methods=["PUT"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/admin/users/&lt;username&gt;/profile", methods=["PUT"])</code> |
| L4778 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L4779 | 定义adminuser更新profile函数 &#96;admin_user_update_profile&#96;，封装可复用业务逻辑。 | <code>    def admin_user_update_profile(username: str):</code> |
| L4780 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 admin_user_update_profile。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L4781 | 计算并保存 &#96;display_name&#96;（displayname），供后续逻辑使用，当前位于函数 admin_user_update_profile。 | <code>        display_name = normalize_profile_text(body.get("display_name"), username, 64)</code> |
| L4782 | 计算并保存 &#96;nickname&#96;（nickname），供后续逻辑使用，当前位于函数 admin_user_update_profile。 | <code>        nickname = normalize_profile_text(body.get("nickname"), display_name, 64)</code> |
| L4783 | 计算并保存 &#96;avatar_url&#96;（avatarurl），供后续逻辑使用，当前位于函数 admin_user_update_profile。 | <code>        avatar_url = normalize_avatar_url(body.get("avatar_url") or "")</code> |
| L4784 | 计算并保存 &#96;role&#96;（role），供后续逻辑使用，当前位于函数 admin_user_update_profile。 | <code>        role = str(body.get("role", "")).strip().lower()</code> |
| L4785 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_user_update_profile。 | <code>        if role and role not in {ROLE_NORMAL, ROLE_ADMIN}:</code> |
| L4786 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_user_update_profile。 | <code>            return jsonify({"error": "invalid_role", "message": "角色只能设置为普通用户或管理员"}), 400</code> |
| L4787 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_user_update_profile。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L4788 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_user_update_profile。 | <code>            with conn.cursor() as cur:</code> |
| L4789 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_user_update_profile。 | <code>                cur.execute(</code> |
| L4790 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_update_profile。 | <code>                    "SELECT id, role FROM demo_users WHERE username=%s AND role IN (%s, %s) LIMIT 1",</code> |
| L4791 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_update_profile。 | <code>                    (username, ROLE_NORMAL, ROLE_ADMIN),</code> |
| L4792 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_user_update_profile。 | <code>                )</code> |
| L4793 | 计算并保存 &#96;exists&#96;（exists），供后续逻辑使用，当前位于函数 admin_user_update_profile。 | <code>                exists = cur.fetchone()</code> |
| L4794 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_user_update_profile。 | <code>                if not exists:</code> |
| L4795 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_user_update_profile。 | <code>                    return jsonify({"error": "user_not_found"}), 404</code> |
| L4796 | 计算并保存 &#96;next_role&#96;（nextrole），供后续逻辑使用，当前位于函数 admin_user_update_profile。 | <code>                next_role = role or str(exists.get("role") or ROLE_NORMAL)</code> |
| L4797 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_user_update_profile。 | <code>                if username == g.session["username"] and next_role != g.session["role"]:</code> |
| L4798 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_user_update_profile。 | <code>                    return jsonify({"error": "self_role_change_not_allowed", "message": "不能修改当前登录账号自己的角色"}), 400</code> |
| L4799 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_user_update_profile。 | <code>                cur.execute(</code> |
| L4800 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_user_update_profile。 | <code>                    """</code> |
| L4801 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 admin_user_update_profile。 | <code>                    UPDATE demo_users</code> |
| L4802 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_user_update_profile。 | <code>                    SET display_name=%s, nickname=%s, avatar_url=%s, role=%s</code> |
| L4803 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_user_update_profile。 | <code>                    WHERE username=%s AND role IN (%s, %s)</code> |
| L4804 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_user_update_profile。 | <code>                    """,</code> |
| L4805 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_update_profile。 | <code>                    (display_name, nickname, avatar_url, next_role, username, ROLE_NORMAL, ROLE_ADMIN),</code> |
| L4806 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_user_update_profile。 | <code>                )</code> |
| L4807 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_update_profile。 | <code>                log_action(</code> |
| L4808 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_update_profile。 | <code>                    conn,</code> |
| L4809 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_update_profile。 | <code>                    g.session["username"],</code> |
| L4810 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_update_profile。 | <code>                    g.session["role"],</code> |
| L4811 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_update_profile。 | <code>                    "admin_update_user_profile",</code> |
| L4812 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_update_profile。 | <code>                    username,</code> |
| L4813 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_update_profile。 | <code>                    f"profile_updated role={next_role}",</code> |
| L4814 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_user_update_profile。 | <code>                )</code> |
| L4815 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_update_profile。 | <code>            conn.commit()</code> |
| L4816 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_user_update_profile。 | <code>        return jsonify({"ok": True, "username": username})</code> |
| L4817 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4818 | 注册 Flask HTTP 接口 "/api/v2/admin/users/&lt;username&gt;/password", methods=["PUT"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/admin/users/&lt;username&gt;/password", methods=["PUT"])</code> |
| L4819 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L4820 | 定义adminuserchangepassword函数 &#96;admin_user_change_password&#96;，封装可复用业务逻辑。 | <code>    def admin_user_change_password(username: str):</code> |
| L4821 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 admin_user_change_password。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L4822 | 计算并保存 &#96;new_password&#96;（newpassword），供后续逻辑使用，当前位于函数 admin_user_change_password。 | <code>        new_password = str(body.get("new_password", "")).strip()</code> |
| L4823 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_user_change_password。 | <code>        if not new_password:</code> |
| L4824 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_user_change_password。 | <code>            return jsonify({"error": "new_password_required"}), 400</code> |
| L4825 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_user_change_password。 | <code>        if len(new_password) &lt; 4:</code> |
| L4826 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_user_change_password。 | <code>            return jsonify({"error": "new_password_too_short"}), 400</code> |
| L4827 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_user_change_password。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L4828 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_user_change_password。 | <code>            with conn.cursor() as cur:</code> |
| L4829 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_user_change_password。 | <code>                cur.execute(</code> |
| L4830 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_change_password。 | <code>                    "SELECT id FROM demo_users WHERE username=%s AND role IN (%s, %s) LIMIT 1",</code> |
| L4831 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_change_password。 | <code>                    (username, ROLE_NORMAL, ROLE_ADMIN),</code> |
| L4832 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_user_change_password。 | <code>                )</code> |
| L4833 | 计算并保存 &#96;exists&#96;（exists），供后续逻辑使用，当前位于函数 admin_user_change_password。 | <code>                exists = cur.fetchone()</code> |
| L4834 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_user_change_password。 | <code>                if not exists:</code> |
| L4835 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_user_change_password。 | <code>                    return jsonify({"error": "user_not_found"}), 404</code> |
| L4836 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_user_change_password。 | <code>                cur.execute("UPDATE demo_users SET password=%s WHERE username=%s", (new_password, username))</code> |
| L4837 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_change_password。 | <code>                log_action(</code> |
| L4838 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_change_password。 | <code>                    conn,</code> |
| L4839 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_change_password。 | <code>                    g.session["username"],</code> |
| L4840 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_change_password。 | <code>                    g.session["role"],</code> |
| L4841 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_change_password。 | <code>                    "admin_change_user_password",</code> |
| L4842 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_change_password。 | <code>                    username,</code> |
| L4843 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_change_password。 | <code>                    "updated",</code> |
| L4844 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_user_change_password。 | <code>                )</code> |
| L4845 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_change_password。 | <code>            conn.commit()</code> |
| L4846 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_user_change_password。 | <code>        return jsonify({"ok": True, "username": username})</code> |
| L4847 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4848 | 注册 Flask HTTP 接口 "/api/v2/admin/summary", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/admin/summary", methods=["GET"])</code> |
| L4849 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L4850 | 定义adminsummary函数 &#96;admin_summary&#96;，封装可复用业务逻辑。 | <code>    def admin_summary():</code> |
| L4851 | 计算并保存 &#96;visible_sql&#96;（visiblesql），供后续逻辑使用，当前位于函数 admin_summary。 | <code>        visible_sql = visible_attack_event_clause()</code> |
| L4852 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_summary。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L4853 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_summary。 | <code>            refresh_machine_stats(conn)</code> |
| L4854 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_summary。 | <code>            with conn.cursor() as cur:</code> |
| L4855 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_summary。 | <code>                cur.execute("SELECT COUNT(*) AS c FROM demo_machines WHERE online_status='online'")</code> |
| L4856 | 计算并保存 &#96;online_count&#96;（onlinecount），供后续逻辑使用，当前位于函数 admin_summary。 | <code>                online_count = int((cur.fetchone() or {}).get("c", 0))</code> |
| L4857 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_summary。 | <code>                cur.execute(f"SELECT COUNT(*) AS c FROM demo_attack_events WHERE DATE(occurred_at)=CURDATE() AND {visible_sql}")</code> |
| L4858 | 计算并保存 &#96;today_attacks&#96;（todayattacks），供后续逻辑使用，当前位于函数 admin_summary。 | <code>                today_attacks = int((cur.fetchone() or {}).get("c", 0))</code> |
| L4859 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_summary。 | <code>                cur.execute("SELECT COUNT(*) AS c FROM demo_machines WHERE current_alert_count &gt; 0")</code> |
| L4860 | 计算并保存 &#96;alert_machine_count&#96;（alertmachinecount），供后续逻辑使用，当前位于函数 admin_summary。 | <code>                alert_machine_count = int((cur.fetchone() or {}).get("c", 0))</code> |
| L4861 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_summary。 | <code>                cur.execute("SELECT COUNT(*) AS c FROM demo_machines WHERE online_status &lt;&gt; 'online'")</code> |
| L4862 | 计算并保存 &#96;offline_count&#96;（offlinecount），供后续逻辑使用，当前位于函数 admin_summary。 | <code>                offline_count = int((cur.fetchone() or {}).get("c", 0))</code> |
| L4863 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_summary。 | <code>            conn.commit()</code> |
| L4864 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_summary。 | <code>        return jsonify(</code> |
| L4865 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_summary。 | <code>            {</code> |
| L4866 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_summary。 | <code>                "online_machine_total": online_count,</code> |
| L4867 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_summary。 | <code>                "today_attack_total": today_attacks,</code> |
| L4868 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_summary。 | <code>                "alert_machine_count": alert_machine_count,</code> |
| L4869 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_summary。 | <code>                "offline_machine_count": offline_count,</code> |
| L4870 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_summary。 | <code>            }</code> |
| L4871 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_summary。 | <code>        )</code> |
| L4872 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4873 | 注册 Flask HTTP 接口 "/api/v2/admin/machines/ranking", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/admin/machines/ranking", methods=["GET"])</code> |
| L4874 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L4875 | 定义adminmachineranking函数 &#96;admin_machine_ranking&#96;，封装可复用业务逻辑。 | <code>    def admin_machine_ranking():</code> |
| L4876 | 计算并保存 &#96;visible_sql&#96;（visiblesql），供后续逻辑使用，当前位于函数 admin_machine_ranking。 | <code>        visible_sql = visible_attack_event_clause()</code> |
| L4877 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_machine_ranking。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L4878 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_machine_ranking。 | <code>            with conn.cursor() as cur:</code> |
| L4879 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_machine_ranking。 | <code>                cur.execute(</code> |
| L4880 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_machine_ranking。 | <code>                    f"""</code> |
| L4881 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_machine_ranking。 | <code>                    SELECT target_node AS machine_name, COUNT(*) AS attack_total</code> |
| L4882 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_machine_ranking。 | <code>                    FROM demo_attack_events</code> |
| L4883 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_machine_ranking。 | <code>                    WHERE DATE(occurred_at)=CURDATE() AND {visible_sql}</code> |
| L4884 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_machine_ranking。 | <code>                    GROUP BY target_node</code> |
| L4885 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_machine_ranking。 | <code>                    ORDER BY attack_total DESC</code> |
| L4886 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_machine_ranking。 | <code>                    """</code> |
| L4887 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_machine_ranking。 | <code>                )</code> |
| L4888 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 admin_machine_ranking。 | <code>                rows = cur.fetchall()</code> |
| L4889 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_machine_ranking。 | <code>        return jsonify({"items": normalize_rows(rows)})</code> |
| L4890 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4891 | 注册 Flask HTTP 接口 "/api/v2/admin/trend7d", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/admin/trend7d", methods=["GET"])</code> |
| L4892 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L4893 | 定义admintrend7d函数 &#96;admin_trend7d&#96;，封装可复用业务逻辑。 | <code>    def admin_trend7d():</code> |
| L4894 | 计算并保存 &#96;visible_sql&#96;（visiblesql），供后续逻辑使用，当前位于函数 admin_trend7d。 | <code>        visible_sql = visible_attack_event_clause()</code> |
| L4895 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_trend7d。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L4896 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_trend7d。 | <code>            with conn.cursor() as cur:</code> |
| L4897 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_trend7d。 | <code>                cur.execute(</code> |
| L4898 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_trend7d。 | <code>                    f"""</code> |
| L4899 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_trend7d。 | <code>                    SELECT DATE(occurred_at) AS d, COUNT(*) AS total</code> |
| L4900 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_trend7d。 | <code>                    FROM demo_attack_events</code> |
| L4901 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_trend7d。 | <code>                    WHERE occurred_at &gt;= DATE_SUB(CURDATE(), INTERVAL 6 DAY) AND {visible_sql}</code> |
| L4902 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_trend7d。 | <code>                    GROUP BY DATE(occurred_at)</code> |
| L4903 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_trend7d。 | <code>                    ORDER BY d</code> |
| L4904 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_trend7d。 | <code>                    """</code> |
| L4905 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_trend7d。 | <code>                )</code> |
| L4906 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 admin_trend7d。 | <code>                rows = cur.fetchall()</code> |
| L4907 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_trend7d。 | <code>        return jsonify({"items": normalize_rows(rows)})</code> |
| L4908 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4909 | 注册 Flask HTTP 接口 "/api/v2/admin/machines", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/admin/machines", methods=["GET"])</code> |
| L4910 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L4911 | 定义adminmachines函数 &#96;admin_machines&#96;，封装可复用业务逻辑。 | <code>    def admin_machines():</code> |
| L4912 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_machines。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L4913 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_machines。 | <code>            refresh_machine_stats(conn)</code> |
| L4914 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_machines。 | <code>            with conn.cursor() as cur:</code> |
| L4915 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_machines。 | <code>                cur.execute(</code> |
| L4916 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_machines。 | <code>                    """</code> |
| L4917 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 admin_machines。 | <code>                    SELECT id, machine_name, ip_address, deploy_location, online_status,</code> |
| L4918 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_machines。 | <code>                           today_attack_count, current_alert_count, last_heartbeat,</code> |
| L4919 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_machines。 | <code>                           cpu_usage, memory_usage, gpu_usage, model_status</code> |
| L4920 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_machines。 | <code>                    FROM demo_machines</code> |
| L4921 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_machines。 | <code>                    ORDER BY machine_name</code> |
| L4922 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_machines。 | <code>                    """</code> |
| L4923 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_machines。 | <code>                )</code> |
| L4924 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 admin_machines。 | <code>                rows = cur.fetchall()</code> |
| L4925 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_machines。 | <code>            conn.commit()</code> |
| L4926 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_machines。 | <code>        return jsonify({"items": normalize_rows(rows)})</code> |
| L4927 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4928 | 注册 Flask HTTP 接口 "/api/v2/admin/machines/&lt;int:machine_id&gt;", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/admin/machines/&lt;int:machine_id&gt;", methods=["GET"])</code> |
| L4929 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L4930 | 定义adminmachinedetail函数 &#96;admin_machine_detail&#96;，封装可复用业务逻辑。 | <code>    def admin_machine_detail(machine_id: int):</code> |
| L4931 | 计算并保存 &#96;visible_sql&#96;（visiblesql），供后续逻辑使用，当前位于函数 admin_machine_detail。 | <code>        visible_sql = visible_attack_event_clause()</code> |
| L4932 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_machine_detail。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L4933 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_machine_detail。 | <code>            with conn.cursor() as cur:</code> |
| L4934 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_machine_detail。 | <code>                cur.execute("SELECT * FROM demo_machines WHERE id=%s LIMIT 1", (machine_id,))</code> |
| L4935 | 计算并保存 &#96;machine&#96;（machine），供后续逻辑使用，当前位于函数 admin_machine_detail。 | <code>                machine = cur.fetchone()</code> |
| L4936 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_machine_detail。 | <code>                if not machine:</code> |
| L4937 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_machine_detail。 | <code>                    return jsonify({"error": "machine_not_found"}), 404</code> |
| L4938 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_machine_detail。 | <code>                cur.execute(</code> |
| L4939 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_machine_detail。 | <code>                    f"""</code> |
| L4940 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_machine_detail。 | <code>                    SELECT event_id, occurred_at, risk_level, attack_type, source_ip, target_interface, attack_result, process_status</code> |
| L4941 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_machine_detail。 | <code>                    FROM demo_attack_events</code> |
| L4942 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_machine_detail。 | <code>                    WHERE machine_id=%s AND {visible_sql}</code> |
| L4943 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_machine_detail。 | <code>                    ORDER BY occurred_at DESC</code> |
| L4944 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_machine_detail。 | <code>                    LIMIT 100</code> |
| L4945 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_machine_detail。 | <code>                    """,</code> |
| L4946 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_machine_detail。 | <code>                    (machine_id,),</code> |
| L4947 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_machine_detail。 | <code>                )</code> |
| L4948 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 admin_machine_detail。 | <code>                rows = cur.fetchall()</code> |
| L4949 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_machine_detail。 | <code>        return jsonify({"machine": normalize_row(machine), "events": normalize_rows(rows)})</code> |
| L4950 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4951 | 注册 Flask HTTP 接口 "/api/v2/admin/machines/&lt;int:machine_id&gt;/restart-service", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/admin/machines/&lt;int:machine_id&gt;/restart-service", methods=["POST"])</code> |
| L4952 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L4953 | 定义adminrestartservice函数 &#96;admin_restart_service&#96;，封装可复用业务逻辑。 | <code>    def admin_restart_service(machine_id: int):</code> |
| L4954 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_restart_service。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L4955 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_restart_service。 | <code>            with conn.cursor() as cur:</code> |
| L4956 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_restart_service。 | <code>                cur.execute(</code> |
| L4957 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_restart_service。 | <code>                    """</code> |
| L4958 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 admin_restart_service。 | <code>                    UPDATE demo_machines</code> |
| L4959 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_restart_service。 | <code>                    SET model_status='running', last_heartbeat=NOW(), online_status='online'</code> |
| L4960 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_restart_service。 | <code>                    WHERE id=%s</code> |
| L4961 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_restart_service。 | <code>                    """,</code> |
| L4962 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_restart_service。 | <code>                    (machine_id,),</code> |
| L4963 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_restart_service。 | <code>                )</code> |
| L4964 | 计算并保存 &#96;changed&#96;（changed），供后续逻辑使用，当前位于函数 admin_restart_service。 | <code>                changed = cur.rowcount</code> |
| L4965 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_restart_service。 | <code>                log_action(conn, g.session["username"], g.session["role"], "restart_service", f"machine:{machine_id}", "demo_restart")</code> |
| L4966 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_restart_service。 | <code>            conn.commit()</code> |
| L4967 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_restart_service。 | <code>        if changed == 0:</code> |
| L4968 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_restart_service。 | <code>            return jsonify({"error": "machine_not_found"}), 404</code> |
| L4969 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_restart_service。 | <code>        return jsonify({"ok": True, "machine_id": machine_id, "message": "service restarted (demo)"})</code> |
| L4970 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4971 | 注册 Flask HTTP 接口 "/api/v2/admin/user-op-logs", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/admin/user-op-logs", methods=["GET"])</code> |
| L4972 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L4973 | 定义adminuseroplogs函数 &#96;admin_user_op_logs&#96;，封装可复用业务逻辑。 | <code>    def admin_user_op_logs():</code> |
| L4974 | 计算并保存 &#96;page&#96;（page），供后续逻辑使用，当前位于函数 admin_user_op_logs。 | <code>        page = max(1, int(request.args.get("page", "1")))</code> |
| L4975 | 计算并保存 &#96;page_size&#96;（pagesize），供后续逻辑使用，当前位于函数 admin_user_op_logs。 | <code>        page_size = max(1, min(int(request.args.get("page_size", "30")), 200))</code> |
| L4976 | 计算并保存 &#96;username&#96;（username），供后续逻辑使用，当前位于函数 admin_user_op_logs。 | <code>        username = request.args.get("username", "").strip()</code> |
| L4977 | 计算并保存 &#96;offset&#96;（offset），供后续逻辑使用，当前位于函数 admin_user_op_logs。 | <code>        offset = (page - 1) * page_size</code> |
| L4978 | 计算并保存 &#96;where_sql&#96;（wheresql），供后续逻辑使用，当前位于函数 admin_user_op_logs。 | <code>        where_sql = "WHERE username=%s" if username else ""</code> |
| L4979 | 计算并保存 &#96;params&#96;（params），供后续逻辑使用，当前位于函数 admin_user_op_logs。 | <code>        params: List[Any] = [username] if username else []</code> |
| L4980 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4981 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_user_op_logs。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L4982 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_user_op_logs。 | <code>            with conn.cursor() as cur:</code> |
| L4983 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_user_op_logs。 | <code>                cur.execute(f"SELECT COUNT(*) AS c FROM demo_user_action_logs {where_sql}", tuple(params))</code> |
| L4984 | 计算并保存 &#96;total&#96;（total），供后续逻辑使用，当前位于函数 admin_user_op_logs。 | <code>                total = int((cur.fetchone() or {}).get("c", 0))</code> |
| L4985 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_user_op_logs。 | <code>                cur.execute(</code> |
| L4986 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_op_logs。 | <code>                    f"""</code> |
| L4987 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_user_op_logs。 | <code>                    SELECT id, username, role, action, target, detail, created_at</code> |
| L4988 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_op_logs。 | <code>                    FROM demo_user_action_logs</code> |
| L4989 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_op_logs。 | <code>                    {where_sql}</code> |
| L4990 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_op_logs。 | <code>                    ORDER BY created_at DESC</code> |
| L4991 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_op_logs。 | <code>                    LIMIT %s OFFSET %s</code> |
| L4992 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_op_logs。 | <code>                    """,</code> |
| L4993 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_user_op_logs。 | <code>                    tuple(params + [page_size, offset]),</code> |
| L4994 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_user_op_logs。 | <code>                )</code> |
| L4995 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 admin_user_op_logs。 | <code>                rows = cur.fetchall()</code> |
| L4996 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_user_op_logs。 | <code>        return jsonify({"items": normalize_rows(rows), "page": page, "page_size": page_size, "total": total})</code> |
| L4997 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L4998 | 注册 Flask HTTP 接口 "/api/v2/admin/config", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/admin/config", methods=["GET"])</code> |
| L4999 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L5000 | 定义admin配置读取函数 &#96;admin_config_get&#96;，封装可复用业务逻辑。 | <code>    def admin_config_get():</code> |
| L5001 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_config_get。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L5002 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_config_get。 | <code>            with conn.cursor() as cur:</code> |
| L5003 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_config_get。 | <code>                cur.execute("SELECT config_key, config_value, updated_at FROM demo_system_config ORDER BY config_key")</code> |
| L5004 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 admin_config_get。 | <code>                rows = cur.fetchall()</code> |
| L5005 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_get。 | <code>        return jsonify({"items": normalize_rows(rows)})</code> |
| L5006 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5007 | 注册 Flask HTTP 接口 "/api/v2/admin/tasks/emergency-reset", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/admin/tasks/emergency-reset", methods=["POST"])</code> |
| L5008 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L5009 | 定义admintasksemergencyreset函数 &#96;admin_tasks_emergency_reset&#96;，封装可复用业务逻辑。 | <code>    def admin_tasks_emergency_reset():</code> |
| L5010 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>        """Cancel unfinished pipeline work while preserving completed evidence."""</code> |
| L5011 | 计算并保存 &#96;cleared&#96;（cleared），供后续逻辑使用，当前位于函数 admin_tasks_emergency_reset。 | <code>        cleared: Dict[str, int] = {}</code> |
| L5012 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_tasks_emergency_reset。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L5013 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_tasks_emergency_reset。 | <code>            with conn.cursor() as cur:</code> |
| L5014 | 计算并保存 &#96;operations&#96;（operations），供后续逻辑使用，当前位于函数 admin_tasks_emergency_reset。 | <code>                operations = (</code> |
| L5015 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>                    ("llm_reviews", "DELETE FROM llm_review_jobs WHERE status IN ('pending','processing','failed')"),</code> |
| L5016 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>                    ("situation_ai", "UPDATE attack_situations SET ai_status='cancelled' WHERE ai_status IN ('pending','retry','processing')"),</code> |
| L5017 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>                    ("professional_reports", "UPDATE situation_professional_reports SET status='failed',progress=100,stage='管理员已紧急取消',error_message='emergency_reset',completed_at=NOW(3) WHERE status IN ('queued','running')"),</code> |
| L5018 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>                    ("rag_documents", "UPDATE rag_documents SET status='failed',progress=0,error_message='管理员已紧急取消任务' WHERE status IN ('pending','processing')"),</code> |
| L5019 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>                    ("graph_outbox", "UPDATE situation_outbox SET status='cancelled',last_error='emergency_reset',processed_at=NOW(3) WHERE status IN ('pending','retry','processing')"),</code> |
| L5020 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_tasks_emergency_reset。 | <code>                )</code> |
| L5021 | 遍历集合中的数据项并逐项处理，当前位于函数 admin_tasks_emergency_reset。 | <code>                for name, sql in operations:</code> |
| L5022 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 admin_tasks_emergency_reset。 | <code>                    try:</code> |
| L5023 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_tasks_emergency_reset。 | <code>                        cleared[name] = int(cur.execute(sql) or 0)</code> |
| L5024 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 admin_tasks_emergency_reset。 | <code>                    except Exception as exc:  # Optional modules may not be initialized yet.</code> |
| L5025 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_tasks_emergency_reset。 | <code>                        if getattr(exc, "args", [None])[0] != 1146:</code> |
| L5026 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>                            raise</code> |
| L5027 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>                        cleared[name] = 0</code> |
| L5028 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>                log_action(</code> |
| L5029 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>                    conn,</code> |
| L5030 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>                    g.session["username"],</code> |
| L5031 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>                    g.session["role"],</code> |
| L5032 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>                    "emergency_task_reset",</code> |
| L5033 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>                    "pipeline_queues",</code> |
| L5034 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>                    json.dumps(cleared, ensure_ascii=False),</code> |
| L5035 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_tasks_emergency_reset。 | <code>                )</code> |
| L5036 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>            conn.commit()</code> |
| L5037 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5038 | 计算并保存 &#96;queue_path&#96;（queuepath），供后续逻辑使用，当前位于函数 admin_tasks_emergency_reset。 | <code>        queue_path = PROJECT_ROOT / "output" / "input_ready.jsonl"</code> |
| L5039 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 admin_tasks_emergency_reset。 | <code>        try:</code> |
| L5040 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>            queue_path.parent.mkdir(parents=True, exist_ok=True)</code> |
| L5041 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>            queue_path.write_text("", encoding="ascii")</code> |
| L5042 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>            (queue_path.parent / "pipeline_reset.request").write_text(</code> |
| L5043 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>                datetime.now().isoformat(timespec="milliseconds"), encoding="ascii"</code> |
| L5044 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_tasks_emergency_reset。 | <code>            )</code> |
| L5045 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 admin_tasks_emergency_reset。 | <code>        except OSError:</code> |
| L5046 | 控制当前循环或占位分支的执行流程，当前位于函数 admin_tasks_emergency_reset。 | <code>            pass</code> |
| L5047 | 源码原注释：Wake workers immediately so they observe the empty queues instead of | <code>        # Wake workers immediately so they observe the empty queues instead of</code> |
| L5048 | 源码原注释：sleeping until their fallback poll. | <code>        # sleeping until their fallback poll.</code> |
| L5049 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 admin_tasks_emergency_reset。 | <code>        try:</code> |
| L5050 | 导入后续逻辑所需的模块、类或函数：&#96;from pipeline_events import DB_READY_EVENT, LLM_READY_EVENT, notify_event&#96;。 | <code>            from pipeline_events import DB_READY_EVENT, LLM_READY_EVENT, notify_event</code> |
| L5051 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5052 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>            notify_event(DB_READY_EVENT)</code> |
| L5053 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_tasks_emergency_reset。 | <code>            notify_event(LLM_READY_EVENT)</code> |
| L5054 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 admin_tasks_emergency_reset。 | <code>        except Exception:</code> |
| L5055 | 控制当前循环或占位分支的执行流程，当前位于函数 admin_tasks_emergency_reset。 | <code>            pass</code> |
| L5056 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_tasks_emergency_reset。 | <code>        return jsonify({"ok": True, "cleared": cleared, "message": "未完成任务已清空，历史数据保持不变"})</code> |
| L5057 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5058 | 注册 Flask HTTP 接口 "/api/v2/common/home-background", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/common/home-background", methods=["GET"])</code> |
| L5059 | 定义commonhomebackground函数 &#96;common_home_background&#96;，封装可复用业务逻辑。 | <code>    def common_home_background():</code> |
| L5060 | 计算并保存 &#96;url&#96;（url），供后续逻辑使用，当前位于函数 common_home_background。 | <code>        url = DEFAULT_HOMEPAGE_BACKGROUND</code> |
| L5061 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 common_home_background。 | <code>        try:</code> |
| L5062 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 common_home_background。 | <code>            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L5063 | 计算并保存 &#96;cfg&#96;（cfg），供后续逻辑使用，当前位于函数 common_home_background。 | <code>                cfg = load_system_config_map(conn)</code> |
| L5064 | 计算并保存 &#96;url&#96;（url），供后续逻辑使用，当前位于函数 common_home_background。 | <code>                url = normalize_homepage_background_url(cfg.get("homepage_background_url", DEFAULT_HOMEPAGE_BACKGROUND))</code> |
| L5065 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 common_home_background。 | <code>        except Exception:</code> |
| L5066 | 计算并保存 &#96;url&#96;（url），供后续逻辑使用，当前位于函数 common_home_background。 | <code>            url = DEFAULT_HOMEPAGE_BACKGROUND</code> |
| L5067 | 结束当前函数并把结果返回给调用方，当前位于函数 common_home_background。 | <code>        return jsonify({"url": url})</code> |
| L5068 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5069 | 注册 Flask HTTP 接口 "/api/v2/admin/home-background", methods=["POST"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/admin/home-background", methods=["POST"])</code> |
| L5070 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L5071 | 定义adminhomebackgroundupload函数 &#96;admin_home_background_upload&#96;，封装可复用业务逻辑。 | <code>    def admin_home_background_upload():</code> |
| L5072 | 计算并保存 &#96;upload&#96;（upload），供后续逻辑使用，当前位于函数 admin_home_background_upload。 | <code>        upload = request.files.get("file")</code> |
| L5073 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_home_background_upload。 | <code>        if upload is None:</code> |
| L5074 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_home_background_upload。 | <code>            return jsonify({"error": "missing_file", "message": "请选择要上传的背景图片"}), 400</code> |
| L5075 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 admin_home_background_upload。 | <code>        data = upload.read()</code> |
| L5076 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_home_background_upload。 | <code>        if not data:</code> |
| L5077 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_home_background_upload。 | <code>            return jsonify({"error": "empty_file", "message": "图片文件为空"}), 400</code> |
| L5078 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_home_background_upload。 | <code>        if len(data) &gt; MAX_BACKGROUND_BYTES:</code> |
| L5079 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_home_background_upload。 | <code>            return jsonify({"error": "file_too_large", "message": "图片不能超过 10MB"}), 413</code> |
| L5080 | 计算并保存 &#96;ext&#96;（ext），供后续逻辑使用，当前位于函数 admin_home_background_upload。 | <code>        ext = detect_background_extension(upload.filename or "", upload.content_type or "", data[:64])</code> |
| L5081 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_home_background_upload。 | <code>        if not ext:</code> |
| L5082 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_home_background_upload。 | <code>            return jsonify({"error": "invalid_image", "message": "仅支持 JPG、PNG、WebP 图片"}), 400</code> |
| L5083 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5084 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_home_background_upload。 | <code>        DASHBOARD_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)</code> |
| L5085 | 计算并保存 &#96;filename&#96;（filename），供后续逻辑使用，当前位于函数 admin_home_background_upload。 | <code>        filename = f"homepage_background_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}.{ext}"</code> |
| L5086 | 计算并保存 &#96;target&#96;（target），供后续逻辑使用，当前位于函数 admin_home_background_upload。 | <code>        target = DASHBOARD_UPLOAD_DIR / filename</code> |
| L5087 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_home_background_upload。 | <code>        target.write_bytes(data)</code> |
| L5088 | 计算并保存 &#96;url&#96;（url），供后续逻辑使用，当前位于函数 admin_home_background_upload。 | <code>        url = f"/uploads/{filename}"</code> |
| L5089 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5090 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_home_background_upload。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L5091 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_home_background_upload。 | <code>            with conn.cursor() as cur:</code> |
| L5092 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_home_background_upload。 | <code>                cur.execute(</code> |
| L5093 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_home_background_upload。 | <code>                    """</code> |
| L5094 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 admin_home_background_upload。 | <code>                    INSERT INTO demo_system_config(config_key, config_value)</code> |
| L5095 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_home_background_upload。 | <code>                    VALUES ('homepage_background_url', %s)</code> |
| L5096 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 admin_home_background_upload。 | <code>                    ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)</code> |
| L5097 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_home_background_upload。 | <code>                    """,</code> |
| L5098 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_home_background_upload。 | <code>                    (url,),</code> |
| L5099 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_home_background_upload。 | <code>                )</code> |
| L5100 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_home_background_upload。 | <code>                log_action(conn, g.session["username"], g.session["role"], "update_background", "homepage", url)</code> |
| L5101 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_home_background_upload。 | <code>            conn.commit()</code> |
| L5102 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_home_background_upload。 | <code>        return jsonify({"ok": True, "url": url})</code> |
| L5103 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5104 | 注册 Flask HTTP 接口 "/api/v2/admin/ollama/models", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/admin/ollama/models", methods=["GET"])</code> |
| L5105 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L5106 | 定义adminollamamodels函数 &#96;admin_ollama_models&#96;，封装可复用业务逻辑。 | <code>    def admin_ollama_models():</code> |
| L5107 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_ollama_models。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L5108 | 计算并保存 &#96;cfg&#96;（cfg），供后续逻辑使用，当前位于函数 admin_ollama_models。 | <code>            cfg = load_system_config_map(conn)</code> |
| L5109 | 计算并保存 &#96;current_model&#96;（current模型），供后续逻辑使用，当前位于函数 admin_ollama_models。 | <code>        current_model = str(cfg.get("llm_model", "qwen3:8b")).strip() or "qwen3:8b"</code> |
| L5110 | 计算并保存 &#96;model_info&#96;（模型info），供后续逻辑使用，当前位于函数 admin_ollama_models。 | <code>        model_info = list_ollama_models(app.config.get("OLLAMA_URL", "http://127.0.0.1:11434"))</code> |
| L5111 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_ollama_models。 | <code>        return jsonify(</code> |
| L5112 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_ollama_models。 | <code>            {</code> |
| L5113 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_ollama_models。 | <code>                "ok": bool(model_info.get("ok")),</code> |
| L5114 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_ollama_models。 | <code>                "items": model_info.get("models", []),</code> |
| L5115 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_ollama_models。 | <code>                "current_model": current_model,</code> |
| L5116 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_ollama_models。 | <code>                "ollama_url": model_info.get("ollama_url"),</code> |
| L5117 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_ollama_models。 | <code>                "error": model_info.get("error", ""),</code> |
| L5118 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_ollama_models。 | <code>            }</code> |
| L5119 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_ollama_models。 | <code>        )</code> |
| L5120 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5121 | 注册 Flask HTTP 接口 "/api/v2/admin/capture-interfaces", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/admin/capture-interfaces", methods=["GET"])</code> |
| L5122 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L5123 | 定义admincaptureinterfaces函数 &#96;admin_capture_interfaces&#96;，封装可复用业务逻辑。 | <code>    def admin_capture_interfaces():</code> |
| L5124 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_capture_interfaces。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L5125 | 计算并保存 &#96;cfg&#96;（cfg），供后续逻辑使用，当前位于函数 admin_capture_interfaces。 | <code>            cfg = load_system_config_map(conn)</code> |
| L5126 | 计算并保存 &#96;configured&#96;（configured），供后续逻辑使用，当前位于函数 admin_capture_interfaces。 | <code>        configured = str(cfg.get("capture_interface", "auto")).strip() or "auto"</code> |
| L5127 | 计算并保存 &#96;info&#96;（info），供后续逻辑使用，当前位于函数 admin_capture_interfaces。 | <code>        info = list_tshark_interfaces()</code> |
| L5128 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 admin_capture_interfaces。 | <code>        items = info.get("items", [])</code> |
| L5129 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_capture_interfaces。 | <code>        resolved_index, resolved_name = resolve_capture_interface(configured, items)</code> |
| L5130 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_capture_interfaces。 | <code>        return jsonify(</code> |
| L5131 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_capture_interfaces。 | <code>            {</code> |
| L5132 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_capture_interfaces。 | <code>                "ok": bool(info.get("ok")),</code> |
| L5133 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_capture_interfaces。 | <code>                "items": items,</code> |
| L5134 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_capture_interfaces。 | <code>                "configured_interface": configured,</code> |
| L5135 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_capture_interfaces。 | <code>                "resolved_interface_index": resolved_index,</code> |
| L5136 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_capture_interfaces。 | <code>                "resolved_interface_name": resolved_name,</code> |
| L5137 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_capture_interfaces。 | <code>                "tshark_path": info.get("path", ""),</code> |
| L5138 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_capture_interfaces。 | <code>                "error": info.get("error", ""),</code> |
| L5139 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_capture_interfaces。 | <code>            }</code> |
| L5140 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_capture_interfaces。 | <code>        )</code> |
| L5141 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5142 | 注册 Flask HTTP 接口 "/api/v2/admin/runtime-check", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/admin/runtime-check", methods=["GET"])</code> |
| L5143 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L5144 | 定义adminruntime检查函数 &#96;admin_runtime_check&#96;，封装可复用业务逻辑。 | <code>    def admin_runtime_check():</code> |
| L5145 | 计算并保存 &#96;checks&#96;（checks），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>        checks: List[Dict[str, Any]] = []</code> |
| L5146 | 计算并保存 &#96;errors&#96;（errors），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>        errors = 0</code> |
| L5147 | 计算并保存 &#96;warnings&#96;（warnings），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>        warnings = 0</code> |
| L5148 | 计算并保存 &#96;config_map&#96;（配置map），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>        config_map: Dict[str, str] = {}</code> |
| L5149 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5150 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 admin_runtime_check。 | <code>        try:</code> |
| L5151 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_runtime_check。 | <code>            with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L5152 | 计算并保存 &#96;config_map&#96;（配置map），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>                config_map = load_system_config_map(conn)</code> |
| L5153 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_runtime_check。 | <code>                with conn.cursor() as cur:</code> |
| L5154 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_runtime_check。 | <code>                    cur.execute("SELECT 1 AS ok")</code> |
| L5155 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    cur.fetchone()</code> |
| L5156 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_runtime_check。 | <code>                    cur.execute("SHOW TABLES")</code> |
| L5157 | 计算并保存 &#96;table_rows&#96;（table数据库记录），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>                    table_rows = cur.fetchall()</code> |
| L5158 | 计算并保存 &#96;table_count&#96;（tablecount），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>            table_count = len(table_rows)</code> |
| L5159 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_runtime_check。 | <code>            checks.append({"name": "MySQL连接", "status": "ok", "message": "连接成功", "detail": f"已检测到 {table_count} 张表"})</code> |
| L5160 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 admin_runtime_check。 | <code>        except Exception as exc:  # noqa: BLE001</code> |
| L5161 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>            errors += 1</code> |
| L5162 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_runtime_check。 | <code>            checks.append({"name": "MySQL连接", "status": "error", "message": "连接失败", "detail": str(exc)})</code> |
| L5163 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5164 | 计算并保存 &#96;tshark_info&#96;（tsharkinfo），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>        tshark_info = list_tshark_interfaces()</code> |
| L5165 | 计算并保存 &#96;tshark_path&#96;（tsharkpath），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>        tshark_path = str(tshark_info.get("path") or "")</code> |
| L5166 | 计算并保存 &#96;interface_items&#96;（interface数据项），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>        interface_items = tshark_info.get("items") if isinstance(tshark_info.get("items"), list) else []</code> |
| L5167 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_runtime_check。 | <code>        if not tshark_info.get("ok"):</code> |
| L5168 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>            errors += 1</code> |
| L5169 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_runtime_check。 | <code>            checks.append(</code> |
| L5170 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                {</code> |
| L5171 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "name": "抓包依赖",</code> |
| L5172 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "status": "error",</code> |
| L5173 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "message": "tshark 不可用",</code> |
| L5174 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "detail": str(tshark_info.get("error") or "请安装 Wireshark + Npcap，并确保 tshark 在 PATH 中"),</code> |
| L5175 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>                }</code> |
| L5176 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>            )</code> |
| L5177 | 处理前述条件均未命中的情况，当前位于函数 admin_runtime_check。 | <code>        else:</code> |
| L5178 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_runtime_check。 | <code>            checks.append({"name": "抓包依赖", "status": "ok", "message": "tshark可用", "detail": tshark_path})</code> |
| L5179 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_runtime_check。 | <code>            checks.append(</code> |
| L5180 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                {</code> |
| L5181 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "name": "抓包网卡",</code> |
| L5182 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "status": "ok" if interface_items else "warn",</code> |
| L5183 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "message": f"检测到 {len(interface_items)} 个网卡",</code> |
| L5184 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "detail": "；".join([f"{x.get('index')}. {x.get('name')}" for x in interface_items[:8]]) or "未检测到网卡",</code> |
| L5185 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>                }</code> |
| L5186 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>            )</code> |
| L5187 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5188 | 计算并保存 &#96;ollama_exe&#96;（ollamaexe），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>        ollama_exe = shutil.which("ollama")</code> |
| L5189 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_runtime_check。 | <code>        if not ollama_exe:</code> |
| L5190 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>            errors += 1</code> |
| L5191 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_runtime_check。 | <code>            checks.append(</code> |
| L5192 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                {</code> |
| L5193 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "name": "Ollama客户端",</code> |
| L5194 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "status": "error",</code> |
| L5195 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "message": "未找到 ollama 命令",</code> |
| L5196 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "detail": "请先安装 Ollama 客户端",</code> |
| L5197 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>                }</code> |
| L5198 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>            )</code> |
| L5199 | 处理前述条件均未命中的情况，当前位于函数 admin_runtime_check。 | <code>        else:</code> |
| L5200 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_runtime_check。 | <code>            checks.append({"name": "Ollama客户端", "status": "ok", "message": "ollama可用", "detail": ollama_exe})</code> |
| L5201 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5202 | 计算并保存 &#96;selected_model&#96;（selected模型），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>        selected_model = str(config_map.get("llm_model", "qwen3:8b")).strip() or "qwen3:8b"</code> |
| L5203 | 计算并保存 &#96;model_info&#96;（模型info），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>        model_info = list_ollama_models(app.config.get("OLLAMA_URL", "http://127.0.0.1:11434"))</code> |
| L5204 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_runtime_check。 | <code>        if not model_info.get("ok"):</code> |
| L5205 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>            errors += 1</code> |
| L5206 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_runtime_check。 | <code>            checks.append(</code> |
| L5207 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                {</code> |
| L5208 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "name": "Ollama服务",</code> |
| L5209 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "status": "error",</code> |
| L5210 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "message": "服务不可达",</code> |
| L5211 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "detail": str(model_info.get("error") or "unknown error"),</code> |
| L5212 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>                }</code> |
| L5213 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>            )</code> |
| L5214 | 处理前述条件均未命中的情况，当前位于函数 admin_runtime_check。 | <code>        else:</code> |
| L5215 | 计算并保存 &#96;names&#96;（names），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>            names = {str(x.get("name", "")).strip() for x in model_info.get("models", [])}</code> |
| L5216 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_runtime_check。 | <code>            if selected_model in names:</code> |
| L5217 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_runtime_check。 | <code>                checks.append(</code> |
| L5218 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    {</code> |
| L5219 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                        "name": "LLM模型",</code> |
| L5220 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                        "status": "ok",</code> |
| L5221 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                        "message": "模型已安装",</code> |
| L5222 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                        "detail": f"当前模型：{selected_model}",</code> |
| L5223 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>                    }</code> |
| L5224 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>                )</code> |
| L5225 | 处理前述条件均未命中的情况，当前位于函数 admin_runtime_check。 | <code>            else:</code> |
| L5226 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                warnings += 1</code> |
| L5227 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_runtime_check。 | <code>                checks.append(</code> |
| L5228 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    {</code> |
| L5229 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                        "name": "LLM模型",</code> |
| L5230 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                        "status": "warn",</code> |
| L5231 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                        "message": "当前模型未安装",</code> |
| L5232 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                        "detail": f"配置模型：{selected_model}，请执行：ollama pull {selected_model}",</code> |
| L5233 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>                    }</code> |
| L5234 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>                )</code> |
| L5235 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_runtime_check。 | <code>            checks.append(</code> |
| L5236 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                {</code> |
| L5237 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "name": "Ollama服务",</code> |
| L5238 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "status": "ok",</code> |
| L5239 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "message": "服务正常",</code> |
| L5240 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "detail": f"地址：{model_info.get('ollama_url')}，已发现 {len(model_info.get('models', []))} 个模型",</code> |
| L5241 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>                }</code> |
| L5242 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>            )</code> |
| L5243 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5244 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>        pre_path, mdl_path = resolve_legacy_model_artifacts()</code> |
| L5245 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_runtime_check。 | <code>        if pre_path.exists() and mdl_path.exists():</code> |
| L5246 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_runtime_check。 | <code>            checks.append(</code> |
| L5247 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                {</code> |
| L5248 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "name": "检测模型文件",</code> |
| L5249 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "status": "ok",</code> |
| L5250 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "message": "兼容模型文件可用",</code> |
| L5251 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "detail": f"pre={pre_path} ; model={mdl_path}",</code> |
| L5252 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>                }</code> |
| L5253 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>            )</code> |
| L5254 | 处理前述条件均未命中的情况，当前位于函数 admin_runtime_check。 | <code>        else:</code> |
| L5255 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>            errors += 1</code> |
| L5256 | 计算并保存 &#96;missing&#96;（missing），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>            missing = []</code> |
| L5257 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_runtime_check。 | <code>            if not pre_path.exists():</code> |
| L5258 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_runtime_check。 | <code>                missing.append(str(pre_path))</code> |
| L5259 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_runtime_check。 | <code>            if not mdl_path.exists():</code> |
| L5260 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_runtime_check。 | <code>                missing.append(str(mdl_path))</code> |
| L5261 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_runtime_check。 | <code>            checks.append(</code> |
| L5262 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                {</code> |
| L5263 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "name": "检测模型文件",</code> |
| L5264 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "status": "error",</code> |
| L5265 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "message": "缺少兼容模型文件",</code> |
| L5266 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    "detail": " ; ".join(missing),</code> |
| L5267 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>                }</code> |
| L5268 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>            )</code> |
| L5269 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5270 | 计算并保存 &#96;monitor_ports&#96;（monitorports），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>        monitor_ports = str(config_map.get("monitor_ports", "80,443,8080")).strip()</code> |
| L5271 | 计算并保存 &#96;batch_size&#96;（batchsize），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>        batch_size = str(config_map.get("capture_batch_size", "4")).strip()</code> |
| L5272 | 计算并保存 &#96;configured_interface&#96;（configuredinterface），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>        configured_interface = str(config_map.get("capture_interface", "auto")).strip() or "auto"</code> |
| L5273 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>        resolved_idx, resolved_name = resolve_capture_interface(configured_interface, interface_items)</code> |
| L5274 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_runtime_check。 | <code>        if tshark_info.get("ok"):</code> |
| L5275 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_runtime_check。 | <code>            if configured_interface not in {"", "auto", "default", "自动"} and not resolved_idx:</code> |
| L5276 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                warnings += 1</code> |
| L5277 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_runtime_check。 | <code>                checks.append(</code> |
| L5278 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    {</code> |
| L5279 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                        "name": "抓包配置",</code> |
| L5280 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                        "status": "warn",</code> |
| L5281 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                        "message": "当前网卡配置未匹配到可用网卡",</code> |
| L5282 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                        "detail": f"capture_interface={configured_interface}",</code> |
| L5283 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>                    }</code> |
| L5284 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>                )</code> |
| L5285 | 当前一条件未命中时继续判断另一条件，当前位于函数 admin_runtime_check。 | <code>            elif resolved_idx:</code> |
| L5286 | 计算并保存 &#96;probe&#96;（probe），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>                probe = probe_capture_on_interface(resolved_idx, monitor_ports)</code> |
| L5287 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_runtime_check。 | <code>                if probe.get("ok"):</code> |
| L5288 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_runtime_check。 | <code>                    checks.append(</code> |
| L5289 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                        {</code> |
| L5290 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                            "name": "抓包检测",</code> |
| L5291 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                            "status": "ok",</code> |
| L5292 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                            "message": "短时抓包探测成功",</code> |
| L5293 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                            "detail": f"网卡={resolved_idx}. {resolved_name}，端口={monitor_ports}",</code> |
| L5294 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>                        }</code> |
| L5295 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>                    )</code> |
| L5296 | 处理前述条件均未命中的情况，当前位于函数 admin_runtime_check。 | <code>                else:</code> |
| L5297 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    errors += 1</code> |
| L5298 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_runtime_check。 | <code>                    checks.append(</code> |
| L5299 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                        {</code> |
| L5300 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                            "name": "抓包检测",</code> |
| L5301 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                            "status": "error",</code> |
| L5302 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                            "message": "短时抓包探测失败",</code> |
| L5303 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                            "detail": str(probe.get("detail") or probe.get("error") or "unknown"),</code> |
| L5304 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>                        }</code> |
| L5305 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>                    )</code> |
| L5306 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_runtime_check。 | <code>        checks.append(</code> |
| L5307 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>            {</code> |
| L5308 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                "name": "系统配置",</code> |
| L5309 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                "status": "ok",</code> |
| L5310 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                "message": "读取成功",</code> |
| L5311 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                "detail": (</code> |
| L5312 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    f"监测端口={monitor_ports}，分组数量={batch_size}，网卡={configured_interface}，模型={selected_model}；"</code> |
| L5313 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    f"态势动作阈值={config_map.get('situation_minimum_actions', '3')}，"</code> |
| L5314 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    f"关联窗口={config_map.get('situation_window_minutes', '30')}分钟，"</code> |
| L5315 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                    f"扫描端口阈值={config_map.get('scan_port_threshold', '10')}"</code> |
| L5316 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>                ),</code> |
| L5317 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>            }</code> |
| L5318 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>        )</code> |
| L5319 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5320 | 计算并保存 &#96;overall&#96;（overall），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>        overall = "ok"</code> |
| L5321 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_runtime_check。 | <code>        if errors &gt; 0:</code> |
| L5322 | 计算并保存 &#96;overall&#96;（overall），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>            overall = "error"</code> |
| L5323 | 当前一条件未命中时继续判断另一条件，当前位于函数 admin_runtime_check。 | <code>        elif warnings &gt; 0:</code> |
| L5324 | 计算并保存 &#96;overall&#96;（overall），供后续逻辑使用，当前位于函数 admin_runtime_check。 | <code>            overall = "warn"</code> |
| L5325 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_runtime_check。 | <code>        return jsonify(</code> |
| L5326 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>            {</code> |
| L5327 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                "overall": overall,</code> |
| L5328 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                "errors": errors,</code> |
| L5329 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                "warnings": warnings,</code> |
| L5330 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                "checks": checks,</code> |
| L5331 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                "selected_model": selected_model,</code> |
| L5332 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_runtime_check。 | <code>                "ollama_url": model_info.get("ollama_url", app.config.get("OLLAMA_URL")),</code> |
| L5333 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>            }</code> |
| L5334 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_runtime_check。 | <code>        )</code> |
| L5335 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5336 | 注册 Flask HTTP 接口 "/api/v2/admin/config", methods=["PUT"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/admin/config", methods=["PUT"])</code> |
| L5337 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L5338 | 定义admin配置put函数 &#96;admin_config_put&#96;，封装可复用业务逻辑。 | <code>    def admin_config_put():</code> |
| L5339 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>        body = request.get_json(silent=True) or {}</code> |
| L5340 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>        if not isinstance(body, dict) or not body:</code> |
| L5341 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>            return jsonify({"error": "invalid_payload"}), 400</code> |
| L5342 | 计算并保存 &#96;normalized&#96;（normalized），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>        normalized: Dict[str, str] = {}</code> |
| L5343 | 遍历集合中的数据项并逐项处理，当前位于函数 admin_config_put。 | <code>        for key, value in body.items():</code> |
| L5344 | 计算并保存 &#96;cfg_key&#96;（cfgkey），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>            cfg_key = str(key).strip()</code> |
| L5345 | 计算并保存 &#96;cfg_val&#96;（cfgval），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>            cfg_val = str(value).strip()</code> |
| L5346 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>            if not cfg_key:</code> |
| L5347 | 控制当前循环或占位分支的执行流程，当前位于函数 admin_config_put。 | <code>                continue</code> |
| L5348 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>            if cfg_key == "capture_batch_size":</code> |
| L5349 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 admin_config_put。 | <code>                try:</code> |
| L5350 | 计算并保存 &#96;v&#96;（v），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                    v = int(cfg_val)</code> |
| L5351 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 admin_config_put。 | <code>                except ValueError:</code> |
| L5352 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": "invalid_capture_batch_size"}), 400</code> |
| L5353 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                if v &lt; 1 or v &gt; 128:</code> |
| L5354 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": "invalid_capture_batch_size"}), 400</code> |
| L5355 | 计算并保存 &#96;cfg_val&#96;（cfgval），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                cfg_val = str(v)</code> |
| L5356 | 当前一条件未命中时继续判断另一条件，当前位于函数 admin_config_put。 | <code>            elif cfg_key == "monitor_ports":</code> |
| L5357 | 计算并保存 &#96;raw_parts&#96;（rawparts），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                raw_parts = [x for x in re.split(r"[\s,]+", cfg_val) if x]</code> |
| L5358 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                if not raw_parts:</code> |
| L5359 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": "invalid_monitor_ports"}), 400</code> |
| L5360 | 计算并保存 &#96;seen&#96;（seen），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                seen = set()</code> |
| L5361 | 计算并保存 &#96;ports&#96;（ports），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                ports: List[int] = []</code> |
| L5362 | 遍历集合中的数据项并逐项处理，当前位于函数 admin_config_put。 | <code>                for item in raw_parts:</code> |
| L5363 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                    if not item.isdigit():</code> |
| L5364 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                        return jsonify({"error": "invalid_monitor_ports"}), 400</code> |
| L5365 | 计算并保存 &#96;port&#96;（port），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                    port = int(item)</code> |
| L5366 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                    if port &lt; 1 or port &gt; 65535:</code> |
| L5367 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                        return jsonify({"error": "invalid_monitor_ports"}), 400</code> |
| L5368 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                    if port not in seen:</code> |
| L5369 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_config_put。 | <code>                        seen.add(port)</code> |
| L5370 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 admin_config_put。 | <code>                        ports.append(port)</code> |
| L5371 | 计算并保存 &#96;cfg_val&#96;（cfgval），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                cfg_val = ",".join(str(p) for p in ports)</code> |
| L5372 | 当前一条件未命中时继续判断另一条件，当前位于函数 admin_config_put。 | <code>            elif cfg_key == "auto_refresh_seconds":</code> |
| L5373 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 admin_config_put。 | <code>                try:</code> |
| L5374 | 计算并保存 &#96;v&#96;（v），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                    v = int(cfg_val)</code> |
| L5375 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 admin_config_put。 | <code>                except ValueError:</code> |
| L5376 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": "invalid_auto_refresh_seconds"}), 400</code> |
| L5377 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                if v &lt; 1 or v &gt; 3600:</code> |
| L5378 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": "invalid_auto_refresh_seconds"}), 400</code> |
| L5379 | 计算并保存 &#96;cfg_val&#96;（cfgval），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                cfg_val = str(v)</code> |
| L5380 | 当前一条件未命中时继续判断另一条件，当前位于函数 admin_config_put。 | <code>            elif cfg_key == "alert_threshold_high":</code> |
| L5381 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 admin_config_put。 | <code>                try:</code> |
| L5382 | 计算并保存 &#96;v&#96;（v），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                    v = int(cfg_val)</code> |
| L5383 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 admin_config_put。 | <code>                except ValueError:</code> |
| L5384 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": "invalid_alert_threshold_high"}), 400</code> |
| L5385 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                if v &lt; 1 or v &gt; 100000:</code> |
| L5386 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": "invalid_alert_threshold_high"}), 400</code> |
| L5387 | 计算并保存 &#96;cfg_val&#96;（cfgval），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                cfg_val = str(v)</code> |
| L5388 | 当前一条件未命中时继续判断另一条件，当前位于函数 admin_config_put。 | <code>            elif cfg_key in {"sound_alert_enabled", "llm_realtime_enabled"}:</code> |
| L5389 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                if cfg_val not in {"0", "1"}:</code> |
| L5390 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": f"invalid_{cfg_key}"}), 400</code> |
| L5391 | 当前一条件未命中时继续判断另一条件，当前位于函数 admin_config_put。 | <code>            elif cfg_key == "llm_model":</code> |
| L5392 | 计算并保存 &#96;cfg_val&#96;（cfgval），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                cfg_val = cfg_val.strip()</code> |
| L5393 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                if not cfg_val or len(cfg_val) &gt; 128:</code> |
| L5394 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": "invalid_llm_model"}), 400</code> |
| L5395 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                if not re.match(r"^[A-Za-z0-9._:-]+$", cfg_val):</code> |
| L5396 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": "invalid_llm_model"}), 400</code> |
| L5397 | 当前一条件未命中时继续判断另一条件，当前位于函数 admin_config_put。 | <code>            elif cfg_key == "capture_interface":</code> |
| L5398 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                if not cfg_val:</code> |
| L5399 | 计算并保存 &#96;cfg_val&#96;（cfgval），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                    cfg_val = "auto"</code> |
| L5400 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                if cfg_val.lower() in {"default", "自动"}:</code> |
| L5401 | 计算并保存 &#96;cfg_val&#96;（cfgval），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                    cfg_val = "auto"</code> |
| L5402 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                if len(cfg_val) &gt; 128:</code> |
| L5403 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": "invalid_capture_interface"}), 400</code> |
| L5404 | 计算并保存 &#96;interface_info&#96;（interfaceinfo），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                interface_info = list_tshark_interfaces()</code> |
| L5405 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_config_put。 | <code>                resolved_index, resolved_name = resolve_capture_interface(</code> |
| L5406 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_config_put。 | <code>                    cfg_val, interface_info.get("items", [])</code> |
| L5407 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_config_put。 | <code>                )</code> |
| L5408 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                if cfg_val.lower() != "auto" and not resolved_index:</code> |
| L5409 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": "capture_interface_not_found"}), 400</code> |
| L5410 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                if resolved_name:</code> |
| L5411 | 源码原注释：Store the stable NPF device token, not the localized | <code>                    # Store the stable NPF device token, not the localized</code> |
| L5412 | 源码原注释：adapter description or mutable tshark numeric index. | <code>                    # adapter description or mutable tshark numeric index.</code> |
| L5413 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_config_put。 | <code>                    normalized["capture_interface_identity"] = resolved_name.split(" (", 1)[0].strip()</code> |
| L5414 | 当前一条件未命中时继续判断另一条件，当前位于函数 admin_config_put。 | <code>            elif cfg_key == "situation_minimum_actions":</code> |
| L5415 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 admin_config_put。 | <code>                try:</code> |
| L5416 | 计算并保存 &#96;v&#96;（v），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                    v = int(cfg_val)</code> |
| L5417 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 admin_config_put。 | <code>                except ValueError:</code> |
| L5418 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": "invalid_situation_minimum_actions"}), 400</code> |
| L5419 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                if v &lt; 3 or v &gt; 12:</code> |
| L5420 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": "invalid_situation_minimum_actions"}), 400</code> |
| L5421 | 计算并保存 &#96;cfg_val&#96;（cfgval），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                cfg_val = str(v)</code> |
| L5422 | 当前一条件未命中时继续判断另一条件，当前位于函数 admin_config_put。 | <code>            elif cfg_key in {"situation_window_minutes", "situation_inactivity_minutes"}:</code> |
| L5423 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 admin_config_put。 | <code>                try:</code> |
| L5424 | 计算并保存 &#96;v&#96;（v），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                    v = int(cfg_val)</code> |
| L5425 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 admin_config_put。 | <code>                except ValueError:</code> |
| L5426 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": f"invalid_{cfg_key}"}), 400</code> |
| L5427 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                if v &lt; 1 or v &gt; 1440:</code> |
| L5428 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": f"invalid_{cfg_key}"}), 400</code> |
| L5429 | 计算并保存 &#96;cfg_val&#96;（cfgval），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                cfg_val = str(v)</code> |
| L5430 | 当前一条件未命中时继续判断另一条件，当前位于函数 admin_config_put。 | <code>            elif cfg_key == "scan_port_threshold":</code> |
| L5431 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 admin_config_put。 | <code>                try:</code> |
| L5432 | 计算并保存 &#96;v&#96;（v），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                    v = int(cfg_val)</code> |
| L5433 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 admin_config_put。 | <code>                except ValueError:</code> |
| L5434 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": "invalid_scan_port_threshold"}), 400</code> |
| L5435 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                if v &lt; 3 or v &gt; 65535:</code> |
| L5436 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": "invalid_scan_port_threshold"}), 400</code> |
| L5437 | 计算并保存 &#96;cfg_val&#96;（cfgval），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                cfg_val = str(v)</code> |
| L5438 | 当前一条件未命中时继续判断另一条件，当前位于函数 admin_config_put。 | <code>            elif cfg_key == "scan_window_seconds":</code> |
| L5439 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 admin_config_put。 | <code>                try:</code> |
| L5440 | 计算并保存 &#96;v&#96;（v），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                    v = int(cfg_val)</code> |
| L5441 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 admin_config_put。 | <code>                except ValueError:</code> |
| L5442 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": "invalid_scan_window_seconds"}), 400</code> |
| L5443 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                if v &lt; 10 or v &gt; 3600:</code> |
| L5444 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": "invalid_scan_window_seconds"}), 400</code> |
| L5445 | 计算并保存 &#96;cfg_val&#96;（cfgval），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                cfg_val = str(v)</code> |
| L5446 | 当前一条件未命中时继续判断另一条件，当前位于函数 admin_config_put。 | <code>            elif cfg_key == "homepage_background_url":</code> |
| L5447 | 计算并保存 &#96;cfg_val&#96;（cfgval），供后续逻辑使用，当前位于函数 admin_config_put。 | <code>                cfg_val = normalize_homepage_background_url(cfg_val)</code> |
| L5448 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>                if not (cfg_val == DEFAULT_HOMEPAGE_BACKGROUND or cfg_val.startswith("/uploads/homepage_background_")):</code> |
| L5449 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>                    return jsonify({"error": "invalid_homepage_background_url"}), 400</code> |
| L5450 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_config_put。 | <code>            normalized[cfg_key] = cfg_val</code> |
| L5451 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 admin_config_put。 | <code>        if not normalized:</code> |
| L5452 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>            return jsonify({"error": "invalid_payload"}), 400</code> |
| L5453 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_config_put。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L5454 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_config_put。 | <code>            with conn.cursor() as cur:</code> |
| L5455 | 遍历集合中的数据项并逐项处理，当前位于函数 admin_config_put。 | <code>                for key, value in normalized.items():</code> |
| L5456 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_config_put。 | <code>                    cur.execute(</code> |
| L5457 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_config_put。 | <code>                        """</code> |
| L5458 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 admin_config_put。 | <code>                        INSERT INTO demo_system_config(config_key, config_value)</code> |
| L5459 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_config_put。 | <code>                        VALUES (%s, %s)</code> |
| L5460 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 admin_config_put。 | <code>                        ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)</code> |
| L5461 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_config_put。 | <code>                        """,</code> |
| L5462 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_config_put。 | <code>                        (str(key), str(value)),</code> |
| L5463 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_config_put。 | <code>                    )</code> |
| L5464 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_config_put。 | <code>                log_action(conn, g.session["username"], g.session["role"], "update_config", "system_config", str(normalized))</code> |
| L5465 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_config_put。 | <code>            conn.commit()</code> |
| L5466 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_config_put。 | <code>        return jsonify({"ok": True})</code> |
| L5467 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5468 | 注册 Flask HTTP 接口 "/api/v2/admin/reports/export", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/admin/reports/export", methods=["GET"])</code> |
| L5469 | 限制接口访问角色，JWT 用户必须具备指定权限。 | <code>    @require_roles(ROLE_ADMIN)</code> |
| L5470 | 定义admin报告export函数 &#96;admin_report_export&#96;，封装可复用业务逻辑。 | <code>    def admin_report_export():</code> |
| L5471 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_report_export。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=False)) as conn:</code> |
| L5472 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 admin_report_export。 | <code>            with conn.cursor() as cur:</code> |
| L5473 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 admin_report_export。 | <code>                cur.execute(</code> |
| L5474 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_report_export。 | <code>                    """</code> |
| L5475 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 admin_report_export。 | <code>                    SELECT DATE(occurred_at) AS day,</code> |
| L5476 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_report_export。 | <code>                           COUNT(*) AS attack_total,</code> |
| L5477 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_report_export。 | <code>                           SUM(CASE WHEN attack_result='blocked' THEN 1 ELSE 0 END) AS blocked_total,</code> |
| L5478 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_report_export。 | <code>                           SUM(CASE WHEN risk_level IN ('critical','high') THEN 1 ELSE 0 END) AS high_total</code> |
| L5479 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_report_export。 | <code>                    FROM demo_attack_events</code> |
| L5480 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_report_export。 | <code>                    WHERE occurred_at &gt;= DATE_SUB(CURDATE(), INTERVAL 30 DAY)</code> |
| L5481 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_report_export。 | <code>                    GROUP BY DATE(occurred_at)</code> |
| L5482 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_report_export。 | <code>                    ORDER BY day</code> |
| L5483 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 admin_report_export。 | <code>                    """</code> |
| L5484 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_report_export。 | <code>                )</code> |
| L5485 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 admin_report_export。 | <code>                rows = cur.fetchall()</code> |
| L5486 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_report_export。 | <code>                log_action(conn, g.session["username"], g.session["role"], "export_report", "platform_30d", "csv_export")</code> |
| L5487 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_report_export。 | <code>            conn.commit()</code> |
| L5488 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5489 | 计算并保存 &#96;output&#96;（output），供后续逻辑使用，当前位于函数 admin_report_export。 | <code>        output = io.StringIO()</code> |
| L5490 | 计算并保存 &#96;writer&#96;（writer），供后续逻辑使用，当前位于函数 admin_report_export。 | <code>        writer = csv.writer(output)</code> |
| L5491 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_report_export。 | <code>        writer.writerow(["day", "attack_total", "blocked_total", "high_total"])</code> |
| L5492 | 遍历集合中的数据项并逐项处理，当前位于函数 admin_report_export。 | <code>        for row in rows:</code> |
| L5493 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_report_export。 | <code>            writer.writerow([row["day"], row["attack_total"], row["blocked_total"], row["high_total"]])</code> |
| L5494 | 计算并保存 &#96;csv_text&#96;（csvtext），供后续逻辑使用，当前位于函数 admin_report_export。 | <code>        csv_text = output.getvalue()</code> |
| L5495 | 结束当前函数并把结果返回给调用方，当前位于函数 admin_report_export。 | <code>        return Response(</code> |
| L5496 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 admin_report_export。 | <code>            csv_text,</code> |
| L5497 | 计算并保存 &#96;mimetype&#96;（mimetype），供后续逻辑使用，当前位于函数 admin_report_export。 | <code>            mimetype="text/csv; charset=utf-8",</code> |
| L5498 | 计算并保存 &#96;headers&#96;（headers），供后续逻辑使用，当前位于函数 admin_report_export。 | <code>            headers={"Content-Disposition": "attachment; filename=platform_report_30d.csv"},</code> |
| L5499 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 admin_report_export。 | <code>        )</code> |
| L5500 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5501 | 源码原注释：compatibility endpoints for previous dashboard | <code>    # compatibility endpoints for previous dashboard</code> |
| L5502 | 注册 Flask HTTP 接口 "/api/v1/screen/attacks", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v1/screen/attacks", methods=["GET"])</code> |
| L5503 | 定义列出attacksv1函数 &#96;list_attacks_v1&#96;，封装可复用业务逻辑。 | <code>    def list_attacks_v1():</code> |
| L5504 | 计算并保存 &#96;limit&#96;（limit），供后续逻辑使用，当前位于函数 list_attacks_v1。 | <code>        limit = max(1, min(int(request.args.get("limit", "100")), 500))</code> |
| L5505 | 计算并保存 &#96;offset&#96;（offset），供后续逻辑使用，当前位于函数 list_attacks_v1。 | <code>        offset = max(0, int(request.args.get("offset", "0")))</code> |
| L5506 | 计算并保存 &#96;llm_status&#96;（llm状态），供后续逻辑使用，当前位于函数 list_attacks_v1。 | <code>        llm_status = request.args.get("llm_status", "").strip()</code> |
| L5507 | 计算并保存 &#96;where_clause&#96;（whereclause），供后续逻辑使用，当前位于函数 list_attacks_v1。 | <code>        where_clause = ""</code> |
| L5508 | 计算并保存 &#96;params&#96;（params），供后续逻辑使用，当前位于函数 list_attacks_v1。 | <code>        params: List[Any] = []</code> |
| L5509 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_attacks_v1。 | <code>        if llm_status:</code> |
| L5510 | 计算并保存 &#96;where_clause&#96;（whereclause），供后续逻辑使用，当前位于函数 list_attacks_v1。 | <code>            where_clause = "WHERE llm_status = %s"</code> |
| L5511 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 list_attacks_v1。 | <code>            params.append(llm_status)</code> |
| L5512 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 list_attacks_v1。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L5513 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 list_attacks_v1。 | <code>            with conn.cursor() as cur:</code> |
| L5514 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 list_attacks_v1。 | <code>                cur.execute(</code> |
| L5515 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                    f"""</code> |
| L5516 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                    SELECT</code> |
| L5517 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                      case_id,</code> |
| L5518 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                      file_id,</code> |
| L5519 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                      seq_id,</code> |
| L5520 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                      attack_event_time AS event_time,</code> |
| L5521 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                      attack_ip,</code> |
| L5522 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                      target_interface,</code> |
| L5523 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                      attack_type,</code> |
| L5524 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                      attack_confidence AS confidence,</code> |
| L5525 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                      llm_status</code> |
| L5526 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                    FROM analyses</code> |
| L5527 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                    {where_clause}</code> |
| L5528 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                    ORDER BY</code> |
| L5529 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                      CASE WHEN attack_event_time IS NULL OR attack_event_time = '' THEN 1 ELSE 0 END,</code> |
| L5530 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                      attack_event_time DESC,</code> |
| L5531 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                      updated_at DESC</code> |
| L5532 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                    LIMIT %s OFFSET %s</code> |
| L5533 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                    """,</code> |
| L5534 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_attacks_v1。 | <code>                    tuple(params + [limit, offset]),</code> |
| L5535 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 list_attacks_v1。 | <code>                )</code> |
| L5536 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 list_attacks_v1。 | <code>                rows = cur.fetchall()</code> |
| L5537 | 结束当前函数并把结果返回给调用方，当前位于函数 list_attacks_v1。 | <code>        return jsonify({"items": normalize_rows(rows), "limit": limit, "offset": offset})</code> |
| L5538 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5539 | 注册 Flask HTTP 接口 "/api/v1/screen/request-body", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v1/screen/request-body", methods=["GET"])</code> |
| L5540 | 定义requestbodyv1函数 &#96;request_body_v1&#96;，封装可复用业务逻辑。 | <code>    def request_body_v1():</code> |
| L5541 | 计算并保存 &#96;filters&#96;（filters），供后续逻辑使用，当前位于函数 request_body_v1。 | <code>        filters = build_case_filters()</code> |
| L5542 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 request_body_v1。 | <code>        if filters["error"]:</code> |
| L5543 | 结束当前函数并把结果返回给调用方，当前位于函数 request_body_v1。 | <code>            return jsonify({"error": filters["error"]}), 400</code> |
| L5544 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 request_body_v1。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L5545 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 request_body_v1。 | <code>            with conn.cursor() as cur:</code> |
| L5546 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 request_body_v1。 | <code>                cur.execute(</code> |
| L5547 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_body_v1。 | <code>                    f"""</code> |
| L5548 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 request_body_v1。 | <code>                    SELECT case_id, file_id, seq_id, request_content</code> |
| L5549 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_body_v1。 | <code>                    FROM requests</code> |
| L5550 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_body_v1。 | <code>                    {filters['where']}</code> |
| L5551 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_body_v1。 | <code>                    LIMIT 1</code> |
| L5552 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_body_v1。 | <code>                    """,</code> |
| L5553 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_body_v1。 | <code>                    filters["params"],</code> |
| L5554 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 request_body_v1。 | <code>                )</code> |
| L5555 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 request_body_v1。 | <code>                row = cur.fetchone()</code> |
| L5556 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 request_body_v1。 | <code>        if not row:</code> |
| L5557 | 结束当前函数并把结果返回给调用方，当前位于函数 request_body_v1。 | <code>            return jsonify({"error": "record_not_found"}), 404</code> |
| L5558 | 结束当前函数并把结果返回给调用方，当前位于函数 request_body_v1。 | <code>        return jsonify(normalize_row(row))</code> |
| L5559 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5560 | 注册 Flask HTTP 接口 "/api/v1/screen/response-body", methods=["GET"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v1/screen/response-body", methods=["GET"])</code> |
| L5561 | 定义responsebodyv1函数 &#96;response_body_v1&#96;，封装可复用业务逻辑。 | <code>    def response_body_v1():</code> |
| L5562 | 计算并保存 &#96;filters&#96;（filters），供后续逻辑使用，当前位于函数 response_body_v1。 | <code>        filters = build_case_filters()</code> |
| L5563 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 response_body_v1。 | <code>        if filters["error"]:</code> |
| L5564 | 结束当前函数并把结果返回给调用方，当前位于函数 response_body_v1。 | <code>            return jsonify({"error": filters["error"]}), 400</code> |
| L5565 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 response_body_v1。 | <code>        with closing(get_conn(app.config["MYSQL_CONF"], autocommit=True)) as conn:</code> |
| L5566 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 response_body_v1。 | <code>            with conn.cursor() as cur:</code> |
| L5567 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 response_body_v1。 | <code>                cur.execute(</code> |
| L5568 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 response_body_v1。 | <code>                    f"""</code> |
| L5569 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 response_body_v1。 | <code>                    SELECT case_id, file_id, seq_id, response_content</code> |
| L5570 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 response_body_v1。 | <code>                    FROM responses</code> |
| L5571 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 response_body_v1。 | <code>                    {filters['where']}</code> |
| L5572 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 response_body_v1。 | <code>                    LIMIT 1</code> |
| L5573 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 response_body_v1。 | <code>                    """,</code> |
| L5574 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 response_body_v1。 | <code>                    filters["params"],</code> |
| L5575 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 response_body_v1。 | <code>                )</code> |
| L5576 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 response_body_v1。 | <code>                row = cur.fetchone()</code> |
| L5577 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 response_body_v1。 | <code>        if not row:</code> |
| L5578 | 结束当前函数并把结果返回给调用方，当前位于函数 response_body_v1。 | <code>            return jsonify({"error": "record_not_found"}), 404</code> |
| L5579 | 结束当前函数并把结果返回给调用方，当前位于函数 response_body_v1。 | <code>        return jsonify(normalize_row(row))</code> |
| L5580 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5581 | 注册 Flask HTTP 接口 "/api/v1/screen/ping", methods=["OPTIONS"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v1/screen/ping", methods=["OPTIONS"])</code> |
| L5582 | 注册 Flask HTTP 接口 "/api/v2/&lt;path:_subpath&gt;", methods=["OPTIONS"]，下一函数负责处理该请求。 | <code>    @app.route("/api/v2/&lt;path:_subpath&gt;", methods=["OPTIONS"])</code> |
| L5583 | 定义optionshandler函数 &#96;options_handler&#96;，封装可复用业务逻辑。 | <code>    def options_handler(_subpath: str = ""):</code> |
| L5584 | 结束当前函数并把结果返回给调用方，当前位于函数 options_handler。 | <code>        return ("", 204)</code> |
| L5585 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5586 | 结束当前函数并把结果返回给调用方，当前位于函数 create_app。 | <code>    return app</code> |
| L5587 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5588 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5589 | 定义构建casefilters函数 &#96;build_case_filters&#96;，封装可复用业务逻辑。 | <code>def build_case_filters() -&gt; Dict[str, Any]:</code> |
| L5590 | 计算并保存 &#96;case_id&#96;（caseid），供后续逻辑使用，当前位于函数 build_case_filters。 | <code>    case_id = request.args.get("case_id", "").strip()</code> |
| L5591 | 计算并保存 &#96;file_id&#96;（fileid），供后续逻辑使用，当前位于函数 build_case_filters。 | <code>    file_id = request.args.get("file_id", "").strip()</code> |
| L5592 | 计算并保存 &#96;seq_id_raw&#96;（seqidraw），供后续逻辑使用，当前位于函数 build_case_filters。 | <code>    seq_id_raw = request.args.get("seq_id", "").strip()</code> |
| L5593 | 计算并保存 &#96;seq_id&#96;（seqid），供后续逻辑使用，当前位于函数 build_case_filters。 | <code>    seq_id: Optional[int] = None</code> |
| L5594 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_case_filters。 | <code>    if seq_id_raw:</code> |
| L5595 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 build_case_filters。 | <code>        try:</code> |
| L5596 | 计算并保存 &#96;seq_id&#96;（seqid），供后续逻辑使用，当前位于函数 build_case_filters。 | <code>            seq_id = int(seq_id_raw)</code> |
| L5597 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 build_case_filters。 | <code>        except ValueError:</code> |
| L5598 | 结束当前函数并把结果返回给调用方，当前位于函数 build_case_filters。 | <code>            return {"where": "", "params": (), "error": "seq_id must be integer"}</code> |
| L5599 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_case_filters。 | <code>    if case_id:</code> |
| L5600 | 结束当前函数并把结果返回给调用方，当前位于函数 build_case_filters。 | <code>        return {"where": "WHERE case_id=%s", "params": (case_id,), "error": ""}</code> |
| L5601 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_case_filters。 | <code>    if file_id and seq_id is not None:</code> |
| L5602 | 结束当前函数并把结果返回给调用方，当前位于函数 build_case_filters。 | <code>        return {"where": "WHERE file_id=%s AND seq_id=%s", "params": (file_id, seq_id), "error": ""}</code> |
| L5603 | 结束当前函数并把结果返回给调用方，当前位于函数 build_case_filters。 | <code>    return {"where": "", "params": (), "error": "provide case_id OR (file_id and seq_id)"}</code> |
| L5604 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5605 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5606 | 定义解析args函数 &#96;parse_args&#96;，封装可复用业务逻辑。 | <code>def parse_args() -&gt; argparse.Namespace:</code> |
| L5607 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 parse_args。 | <code>    parser = argparse.ArgumentParser(description="AI attack situation awareness API server")</code> |
| L5608 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--host", default="0.0.0.0", help="Flask bind host")</code> |
| L5609 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--port", type=int, default=3049, help="Flask bind port")</code> |
| L5610 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-host", default="127.0.0.1", help="MySQL host")</code> |
| L5611 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-port", type=int, default=3306, help="MySQL port")</code> |
| L5612 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-user", default="root", help="MySQL user")</code> |
| L5613 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-password", default="123456", help="MySQL password")</code> |
| L5614 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-database", default="traffic_pipeline", help="MySQL database")</code> |
| L5615 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-db-path", default="llm/rag/rag_knowledge.db", help="RAG sqlite db path")</code> |
| L5616 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-seed-file", default="llm/rag/rag_seed.json", help="RAG seed json path")</code> |
| L5617 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-force-seed", action="store_true", help="Force rebuild RAG db from seed on startup")</code> |
| L5618 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-data-dir", default="", help="Advanced RAG runtime data directory; RAG_DATA_DIR env has priority")</code> |
| L5619 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-api-config", default="config/ai_api.local.json", help="DashScope local config JSON")</code> |
| L5620 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--llm-prompt", default="llm/prompts/system_prompt.txt", help="LLM system prompt file path")</code> |
| L5621 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--professional-report-prompt", default="llm/prompts/professional_situation_report_prompt.txt", help="Professional situation report prompt file path")</code> |
| L5622 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--jwt-secret", default="", help="JWT secret, fallback to env TP_JWT_SECRET")</code> |
| L5623 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--jwt-ttl-seconds", type=int, default=TOKEN_TTL_SECONDS, help="JWT token TTL seconds")</code> |
| L5624 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434", help="Ollama base URL")</code> |
| L5625 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--seed-demo", action="store_true", help="Seed demo data if tables are empty")</code> |
| L5626 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--force-seed", action="store_true", help="Force regenerate demo data")</code> |
| L5627 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_args。 | <code>    return parser.parse_args()</code> |
| L5628 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5629 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5630 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; None:</code> |
| L5631 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parse_args()</code> |
| L5632 | 计算并保存 &#96;mysql_conf&#96;（mysqlconf），供后续逻辑使用，当前位于函数 main。 | <code>    mysql_conf = {</code> |
| L5633 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "host": args.mysql_host,</code> |
| L5634 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "port": args.mysql_port,</code> |
| L5635 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "user": args.mysql_user,</code> |
| L5636 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "password": args.mysql_password,</code> |
| L5637 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "database": args.mysql_database,</code> |
| L5638 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    }</code> |
| L5639 | 计算并保存 &#96;app&#96;（app），供后续逻辑使用，当前位于函数 main。 | <code>    app = create_app(</code> |
| L5640 | 计算并保存 &#96;mysql_conf&#96;（mysqlconf），供后续逻辑使用，当前位于函数 main。 | <code>        mysql_conf=mysql_conf,</code> |
| L5641 | 计算并保存 &#96;seed_demo&#96;（seeddemo），供后续逻辑使用，当前位于函数 main。 | <code>        seed_demo=args.seed_demo or args.force_seed,</code> |
| L5642 | 计算并保存 &#96;force_seed&#96;（forceseed），供后续逻辑使用，当前位于函数 main。 | <code>        force_seed=args.force_seed,</code> |
| L5643 | 计算并保存 &#96;rag_db_path&#96;（rag数据库path），供后续逻辑使用，当前位于函数 main。 | <code>        rag_db_path=args.rag_db_path,</code> |
| L5644 | 计算并保存 &#96;rag_seed_path&#96;（ragseedpath），供后续逻辑使用，当前位于函数 main。 | <code>        rag_seed_path=args.rag_seed_file,</code> |
| L5645 | 计算并保存 &#96;rag_force_seed&#96;（ragforceseed），供后续逻辑使用，当前位于函数 main。 | <code>        rag_force_seed=args.rag_force_seed,</code> |
| L5646 | 计算并保存 &#96;jwt_secret&#96;（jwtsecret），供后续逻辑使用，当前位于函数 main。 | <code>        jwt_secret=args.jwt_secret,</code> |
| L5647 | 计算并保存 &#96;jwt_ttl_seconds&#96;（jwtttlseconds），供后续逻辑使用，当前位于函数 main。 | <code>        jwt_ttl_seconds=args.jwt_ttl_seconds,</code> |
| L5648 | 计算并保存 &#96;ollama_url&#96;（ollamaurl），供后续逻辑使用，当前位于函数 main。 | <code>        ollama_url=args.ollama_url,</code> |
| L5649 | 计算并保存 &#96;llm_prompt_path&#96;（llmpromptpath），供后续逻辑使用，当前位于函数 main。 | <code>        llm_prompt_path=args.llm_prompt,</code> |
| L5650 | 计算并保存 &#96;professional_report_prompt_path&#96;（professional报告promptpath），供后续逻辑使用，当前位于函数 main。 | <code>        professional_report_prompt_path=args.professional_report_prompt,</code> |
| L5651 | 计算并保存 &#96;rag_data_dir&#96;（ragdatadir），供后续逻辑使用，当前位于函数 main。 | <code>        rag_data_dir=args.rag_data_dir,</code> |
| L5652 | 计算并保存 &#96;rag_api_config&#96;（rag接口配置），供后续逻辑使用，当前位于函数 main。 | <code>        rag_api_config=args.rag_api_config,</code> |
| L5653 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L5654 | 源码原注释：Dashboard polling is expected traffic, not an error. Keeping Werkzeug's | <code>    # Dashboard polling is expected traffic, not an error. Keeping Werkzeug's</code> |
| L5655 | 源码原注释：per-request access logger enabled can grow stderr by tens of MB per day. | <code>    # per-request access logger enabled can grow stderr by tens of MB per day.</code> |
| L5656 | 导入后续逻辑所需的模块、类或函数：&#96;import logging&#96;。 | <code>    import logging</code> |
| L5657 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5658 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.getLogger("werkzeug").setLevel(logging.ERROR)</code> |
| L5659 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    app.run(host=args.host, port=args.port, debug=False)</code> |
| L5660 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5661 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5662 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L5663 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
| L5664 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5665 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5666 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5667 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5668 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L5669 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
