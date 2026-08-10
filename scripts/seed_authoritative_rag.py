"""Download authoritative security sources and ingest them into advanced RAG.

Sources are intentionally limited to official OWASP, MITRE and CISA datasets.
Run this script again to create a newly versioned source snapshot.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from rag_service import (  # noqa: E402
    ensure_default_kb,
    ensure_schema,
    get_kb,
    ingest_file,
    list_eval_cases,
    load_api_config,
    mysql_connect,
    save_eval_case,
)


OWASP_FILES = [
    "SQL_Injection_Prevention_Cheat_Sheet.md",
    "Cross_Site_Scripting_Prevention_Cheat_Sheet.md",
    "Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md",
    "File_Upload_Cheat_Sheet.md",
    "Authentication_Cheat_Sheet.md",
    "Deserialization_Cheat_Sheet.md",
    "Logging_Cheat_Sheet.md",
    "REST_Security_Cheat_Sheet.md",
]


def fetch(url: str, timeout: int = 120, attempts: int = 4) -> bytes:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Jingyuan-RAG-Seed/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except Exception as exc:
            last_error = exc
            if attempt < attempts:
                time.sleep(min(12, attempt * 3))
    raise RuntimeError(f"下载官方知识失败（已重试 {attempts} 次）：{url}: {last_error}")


def build_owasp() -> str:
    sections = [
        "# OWASP Web 安全防护知识快照",
        "",
        "来源：https://github.com/OWASP/CheatSheetSeries",
        "用途：Web 攻击判定、证据解释与安全修复建议。",
    ]
    base = "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/"
    for name in OWASP_FILES:
        text = fetch(base + name).decode("utf-8", errors="replace")
        sections.extend(["", f"# 来源文档：{name}", f"原始地址：{base + name}", "", text])
    return "\n".join(sections)


def build_mitre() -> str:
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    payload = json.loads(fetch(url).decode("utf-8"))
    keywords = {
        "scan", "scanning", "reconnaissance", "public-facing", "brute force", "credential",
        "phishing", "web", "exploit", "remote service", "network service", "valid accounts",
    }
    rows: List[str] = [
        "# MITRE ATT&CK Enterprise 攻击技术精选",
        "",
        f"STIX 2.1 数据来源：{url}",
        "筛选范围：与外部侦察、公开服务利用、凭据攻击、钓鱼和远程服务相关的攻击技术。",
    ]
    selected = []
    for obj in payload.get("objects") or []:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        haystack = f"{obj.get('name','')} {obj.get('description','')}".lower()
        if not any(keyword in haystack for keyword in keywords):
            continue
        refs = obj.get("external_references") or []
        attack_ref = next((ref for ref in refs if ref.get("source_name") == "mitre-attack"), {})
        selected.append(
            (
                str(attack_ref.get("external_id") or "ATT&CK"),
                str(obj.get("name") or "Unnamed technique"),
                str(obj.get("description") or "").replace("\r", "").strip(),
                str(attack_ref.get("url") or url),
            )
        )
    for external_id, name, description, source in sorted(selected)[:180]:
        rows.extend(["", f"## {external_id} {name}", f"来源：{source}", "", description])
    return "\n".join(rows)


def build_cisa() -> str:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    payload = json.loads(fetch(url).decode("utf-8"))
    vulnerabilities = sorted(payload.get("vulnerabilities") or [], key=lambda row: row.get("dateAdded", ""), reverse=True)[:300]
    rows = [
        "# CISA Known Exploited Vulnerabilities 精选",
        "",
        f"来源：{url}",
        f"目录版本：{payload.get('catalogVersion', '-')}",
        "说明：仅收录已知在野利用漏洞，用于 CVE 风险优先级和 N-day 攻击证据增强。",
    ]
    for item in vulnerabilities:
        rows.extend(
            [
                "",
                f"## {item.get('cveID', 'CVE')} {item.get('vulnerabilityName', '')}",
                f"厂商与产品：{item.get('vendorProject', '-')} / {item.get('product', '-')}",
                f"加入日期：{item.get('dateAdded', '-')}；要求处置日期：{item.get('dueDate', '-')}",
                f"漏洞说明：{item.get('shortDescription', '')}",
                f"处置要求：{item.get('requiredAction', '')}",
                f"勒索软件关联：{item.get('knownRansomwareCampaignUse', 'Unknown')}",
                f"参考：{item.get('notes', '')}",
            ]
        )
    return "\n".join(rows)


def read_db_config(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    mysql = data.get("mysql") if isinstance(data.get("mysql"), dict) else data
    return {
        "host": str(mysql.get("host") or "127.0.0.1"),
        "port": int(mysql.get("port") or 3306),
        "user": str(mysql.get("user") or "root"),
        "password": str(mysql.get("password") or "123456"),
        "database": str(mysql.get("database") or "traffic_pipeline"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed authoritative RAG documents")
    parser.add_argument("--db-config", default="config/db_config.json")
    parser.add_argument("--api-config", default="config/ai_api.local.json")
    parser.add_argument("--data-dir", default="D:/JingyuanTrafficPipelineData/rag")
    parser.add_argument("--kb-id", type=int, default=0)
    parser.add_argument("--source-dir", default="", help="已下载的三份官方 Markdown 快照目录")
    args = parser.parse_args()

    conf = read_db_config((PROJECT_ROOT / args.db_config).resolve())
    api_config = load_api_config((PROJECT_ROOT / args.api_config).resolve())
    data_dir = Path(args.data_dir).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    with mysql_connect(conf, autocommit=False) as conn:
        ensure_schema(conn)
        kb_id = args.kb_id or ensure_default_kb(conn)
        if not get_kb(conn, kb_id):
            raise SystemExit(f"Knowledge base {kb_id} does not exist")
        builders = [
            ("OWASP_Cheat_Sheet_Security_Knowledge.md", build_owasp),
            ("MITRE_ATTACK_Enterprise_Selected_Techniques.md", build_mitre),
            ("CISA_KEV_Selected.md", build_cisa),
        ]
        with tempfile.TemporaryDirectory(prefix="jingyuan-rag-") as temp_dir:
            for filename, builder in builders:
                print(f"[download] {filename}")
                path = Path(temp_dir) / filename
                cached = Path(args.source_dir).resolve() / filename if args.source_dir else None
                if cached and cached.exists():
                    path.write_bytes(cached.read_bytes())
                    print(f"[cache] {cached}")
                else:
                    path.write_text(builder(), encoding="utf-8")
                result = ingest_file(conn, data_dir, api_config, kb_id, path, filename, "official-seed", source_type="official")
                print(f"[ready] {result}")
        if not list_eval_cases(conn, kb_id):
            cases = [
                {
                    "question": "登录接口的 password 参数出现单引号、OR 1=1 与注释符，应如何识别和修复？",
                    "expected_keywords": "SQL Injection, SQL 注入, parameterized",
                    "expected_document": "OWASP",
                },
                {
                    "question": "响应页面把用户输入直接插入 HTML，出现 script 标签和 onerror 事件时，应如何防护？",
                    "expected_keywords": "XSS, output encoding, CSP",
                    "expected_document": "OWASP",
                },
                {
                    "question": "Nmap 在短时间内向服务器多个端口发送 SYN 探测包，这属于什么行为，应如何发现和处置？",
                    "expected_keywords": "PortScan, port scan, 端口扫描",
                    "expected_document": "",
                },
            ]
            for case in cases:
                save_eval_case(conn, kb_id, case)
            print(f"[ready] created {len(cases)} regression cases")


if __name__ == "__main__":
    main()
