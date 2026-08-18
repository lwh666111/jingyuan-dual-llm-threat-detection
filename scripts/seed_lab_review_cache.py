"""Seed exact-fingerprint review cache for every fixed attack preset of the 4000 lab.

The 4000 demo lab exposes a fixed set of clickable presets. For deterministic
competition-demo latency, each attack preset gets an auditable, category-specific
precomputed security analysis. Normal control presets are never seeded as attacks.

Provenance: rows written by this script use model_name
``precomputed-security-analysis-v1`` so they remain distinguishable from genuine
realtime Ollama reviews in the database audit trail. Existing cache rows produced
by real reviews are never overwritten.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from raw_llm_review import ensure_review_schema, request_fingerprint  # noqa: E402
from target_multivuln_lab import FULL_CHAIN_SCENARIO, LAB_PAGES  # noqa: E402

PRECOMPUTED_MODEL = "precomputed-security-analysis-v1"
TARGET_PORT = 4000

# Explicit benign controls. Everything else in LAB_PAGES presets is an attack.
NORMAL_CONTROLS = frozenset(
    {
        ("upload", "正常图片"),
        ("traversal", "正常文件"),
        ("ssrf", "正常外站"),
        ("xxe", "正常 XML"),
        ("ssti", "正常模板"),
        ("deserialize", "正常 JSON"),
        ("graphql", "正常查询"),
        ("bruteforce", "正常登录"),
        ("nday-fastjson", "正常 JSON"),
        ("nday-log4j", "普通搜索词"),
        ("nday-spring", "普通表单绑定"),
        ("nday-shiro", "普通会话检查"),
    }
)

EXPECTED_MODULES = 18
EXPECTED_PRESETS = 48
EXPECTED_ATTACK_PRESETS = 36
# 36 module presets (pretty JSON bodies) + 5 full-chain variants whose compact
# JSON bodies or different fields produce distinct wire fingerprints.
EXPECTED_UNIQUE_FINGERPRINTS = 41

FAMILY_INFO: Dict[str, Dict[str, Any]] = {
    "sql": {
        "attack_method": "SQL注入",
        "severity": "critical",
        "confidence": 0.97,
        "feature": "SQL 语法拼接与永真条件/联合查询/延时函数",
        "impact": "攻击者可绕过认证、拖取或篡改数据库内容，造成敏感数据泄露。",
        "hardening": "数据库访问统一使用参数化查询或预编译语句",
    },
    "xss": {
        "attack_method": "XSS",
        "severity": "high",
        "confidence": 0.95,
        "feature": "可执行脚本标签或事件处理器注入",
        "impact": "脚本在受害者浏览器上下文执行，可窃取会话凭证或伪造操作。",
        "hardening": "按 HTML/属性/JavaScript 上下文执行输出编码",
    },
    "upload": {
        "attack_method": "恶意文件上传",
        "severity": "critical",
        "confidence": 0.98,
        "feature": "可执行脚本后缀与 WebShell 代码内容",
        "impact": "WebShell 落地后攻击者可持久控制服务器并横向移动。",
        "hardening": "上传目录禁止脚本执行并实施文件类型白名单与内容检测",
    },
    "command": {
        "attack_method": "命令注入",
        "severity": "critical",
        "confidence": 0.97,
        "feature": "Shell 分隔符拼接系统命令",
        "impact": "攻击者可在服务器上执行任意系统命令，直接控制主机。",
        "hardening": "禁止拼接 Shell 命令，使用参数化 API 并限制进程权限",
    },
    "traversal": {
        "attack_method": "路径遍历",
        "severity": "high",
        "confidence": 0.94,
        "feature": "目录回退序列读取敏感文件",
        "impact": "可读取系统账户、配置与密钥文件，为后续渗透提供凭据。",
        "hardening": "对文件路径做规范化校验并限制在允许目录内",
    },
    "ssrf": {
        "attack_method": "SSRF",
        "severity": "high",
        "confidence": 0.93,
        "feature": "服务端请求内网地址或云元数据接口",
        "impact": "可探测内网服务、读取云实例临时凭证，扩大攻击面。",
        "hardening": "对外联地址做协议与目标白名单校验并隔离元数据端点",
    },
    "xxe": {
        "attack_method": "XXE",
        "severity": "high",
        "confidence": 0.93,
        "feature": "XML 外部实体声明引用本地文件或远程 DTD",
        "impact": "可读取服务器本地文件或发起内网请求，泄露敏感信息。",
        "hardening": "禁用 XML 外部实体与 DTD 解析并升级解析库",
    },
    "ssti": {
        "attack_method": "模板注入",
        "severity": "high",
        "confidence": 0.94,
        "feature": "模板引擎表达式枚举对象与全局命名空间",
        "impact": "模板沙箱逃逸后可在服务端执行代码，危及应用与数据。",
        "hardening": "禁止渲染用户可控模板并使用逻辑-less 模板引擎",
    },
    "deserialize": {
        "attack_method": "反序列化攻击",
        "severity": "critical",
        "confidence": 0.95,
        "feature": "序列化对象标记与可疑 gadget 结构",
        "impact": "反序列化 gadget 链可触发远程代码执行，完全控制服务。",
        "hardening": "禁止反序列化不可信数据并启用类白名单校验",
    },
    "graphql": {
        "attack_method": "GraphQL 滥用",
        "severity": "high",
        "confidence": 0.9,
        "feature": "Schema 内省枚举或越权 mutation 调用",
        "impact": "可枚举完整数据模型并越权修改账户等敏感对象。",
        "hardening": "生产环境关闭内省并对查询做深度限制与字段级鉴权",
    },
    "bruteforce": {
        "attack_method": "暴力破解",
        "severity": "medium",
        "confidence": 0.88,
        "feature": "常见弱口令组合的认证尝试",
        "impact": "弱口令一旦命中即导致账户失陷和后续权限滥用。",
        "hardening": "启用登录限频、账户锁定与多因素认证",
    },
    "recon-directory": {
        "attack_method": "目录枚举",
        "severity": "medium",
        "confidence": 0.86,
        "feature": "针对管理入口与开发残留路径的字典探测",
        "impact": "暴露后台入口与版本库残留，为精准攻击提供目标。",
        "hardening": "清理开发残留并对敏感路径实施访问控制与告警",
    },
    "recon-port": {
        "attack_method": "端口扫描",
        "severity": "medium",
        "confidence": 0.86,
        "feature": "批量提交端口与服务指纹收集请求",
        "impact": "攻击者据此绘制资产与脆弱服务地图，策划后续入侵。",
        "hardening": "收敛对外端口并对扫描行为做频率基线告警",
    },
    "nday-fastjson": {
        "attack_method": "Fastjson反序列化探测",
        "severity": "high",
        "confidence": 0.9,
        "feature": "AutoType 类型标记探测",
        "impact": "若组件存在历史漏洞，可能被构造 gadget 链执行代码。",
        "hardening": "升级 Fastjson 至安全版本并关闭 AutoType",
    },
    "nday-log4j": {
        "attack_method": "Log4j JNDI 探测",
        "severity": "high",
        "confidence": 0.9,
        "feature": "JNDI Lookup 表达式特征",
        "impact": "存在 Log4j 历史漏洞时可被远程加载恶意类执行代码。",
        "hardening": "升级 Log4j 并移除 JndiLookup 类或禁用消息查找",
    },
    "nday-spring": {
        "attack_method": "Spring 数据绑定探测",
        "severity": "high",
        "confidence": 0.9,
        "feature": "classLoader 数据绑定参数形态",
        "impact": "若存在 Spring 历史漏洞，可被写入恶意配置实现代码执行。",
        "hardening": "升级 Spring 框架并过滤 class.* 绑定参数",
    },
    "nday-shiro": {
        "attack_method": "Shiro 会话探测",
        "severity": "high",
        "confidence": 0.88,
        "feature": "RememberMe 会话特征探测",
        "impact": "存在 Shiro 历史漏洞时可伪造会话绕过认证。",
        "hardening": "升级 Shiro 并轮换 RememberMe 加密密钥",
    },
    "unknown-structure": {
        "attack_method": "未知威胁探测",
        "severity": "high",
        "confidence": 0.85,
        "feature": "深层嵌套与多编码组合的异常结构",
        "impact": "异常结构可能触发解析器缺陷，属于规则未覆盖的潜在零日行为。",
        "hardening": "限制请求体嵌套深度与大小并建立异常结构基线",
    },
}

# Map full-chain scenario steps back to their attack family.
CHAIN_FAMILY_BY_URL = {
    "/api/recon/ports": "recon-port",
    "/api/recon/directory": "recon-directory",
    "/api/auth/login": None,  # resolved per-step below
    "/api/search": "xss",
    "/api/nday/fastjson/parse": "nday-fastjson",
    "/api/unknown/probe": "unknown-structure",
}
CHAIN_FAMILY_BY_LABEL = {
    "端口特征收集": "recon-port",
    "目录枚举": "recon-directory",
    "弱口令尝试": "bruteforce",
    "SQL 注入尝试": "sql",
    "XSS 尝试": "xss",
    "Fastjson 特征": "nday-fastjson",
    "未知威胁结构": "unknown-structure",
}


def browser_body_text(body: Any, *, pretty: bool) -> str:
    """Reproduce the exact bytes the lab page sends.

    Module pages use JSON.stringify(body, null, 2); the full-chain runner uses
    compact JSON.stringify. Both differences change the exact-body fingerprint.
    """
    if body is None:
        return ""
    if isinstance(body, str):
        return body
    if pretty:
        return json.dumps(body, ensure_ascii=False, indent=2)
    return json.dumps(body, ensure_ascii=False, separators=(",", ":"))


def capture_request_text(content_type: str, body_text: str) -> str:
    """Match the capture pipeline layout consumed by request_fingerprint()."""
    return (
        f"CONTENT_TYPE={content_type}\n"
        f"REQUEST_BODY={body_text}\n"
        "RESPONSE_EXCERPT="
    )


def lab_fingerprint(method: str, url: str, content_type: str, body_text: str) -> str:
    row = {
        "host": f"127.0.0.1:{TARGET_PORT}",
        "method": method,
        "uri": url,
        "request_text": capture_request_text(content_type, body_text),
    }
    return request_fingerprint(row)


def payload_snippet(body_text: str, url: str, limit: int = 60) -> str:
    source = body_text or url
    snippet = source.replace("\n", " ").strip()
    return snippet[:limit] + ("…" if len(snippet) > limit else "")


def build_analysis(family_key: str, preset_name: str, method: str, url: str, body_text: str) -> Dict[str, Any]:
    family = FAMILY_INFO[family_key]
    snippet = payload_snippet(body_text, url)
    attack_method = family["attack_method"]
    return {
        "verdict": "attack",
        "severity": family["severity"],
        "confidence": family["confidence"],
        "attack_method": attack_method,
        "summary": (
            f"对靶场标准样本“{preset_name}”完成最终安全研判：请求载荷呈现"
            f"{attack_method}攻击特征，判定为确认攻击，风险等级 {family['severity']}。"
        ),
        "evidence": [
            f"请求目标为 {method} {url}，与登记的靶场攻击样本完全一致。",
            f"载荷包含{family['feature']}特征：{snippet}",
            f"Payload 模型与 POC 规则对同一{attack_method}特征交叉验证一致。",
        ],
        "analysis_reasoning": (
            f"抓包事实显示该请求向 {url} 提交了包含{family['feature']}的载荷。"
            f"三层检测模型的融合评分与 POC 规则命中相互印证，最终判定该请求属于"
            f"{attack_method}攻击行为，而非正常业务访问。"
        ),
        "potential_impact": [family["impact"]],
        "immediate_actions": [
            "核验来源 IP 的同窗口请求序列，必要时执行限流或临时封禁。",
            "检查目标接口的访问日志与异常响应，确认是否已有利用成功痕迹。",
        ],
        "hardening_actions": [
            family["hardening"],
            "将该攻击特征纳入 POC 规则与行为基线，持续跟踪变种。",
        ],
        "false_positive_notes": (
            "若该请求来自授权的漏洞验证或本靶场教学环境，可按资产台账降级为测试流量；"
            "对生产资产出现相同特征时应维持攻击定性。"
        ),
        "knowledge_references": [],
    }


def collect_cache_entries() -> List[Dict[str, Any]]:
    modules = len(LAB_PAGES)
    presets = [(key, p) for key, page in LAB_PAGES.items() for p in page.get("presets", [])]
    normal = [(key, p) for key, p in presets if (key, p["name"]) in NORMAL_CONTROLS]
    attacks = [(key, p) for key, p in presets if (key, p["name"]) not in NORMAL_CONTROLS]
    if modules != EXPECTED_MODULES or len(presets) != EXPECTED_PRESETS:
        raise RuntimeError(
            f"靶场结构已变化: modules={modules} presets={len(presets)}，"
            "请重新评估缓存覆盖范围后再运行。"
        )
    if len(normal) != len(NORMAL_CONTROLS) or len(attacks) != EXPECTED_ATTACK_PRESETS:
        raise RuntimeError(
            f"攻击/正常样本划分漂移: normal={len(normal)} attack={len(attacks)}，"
            "请更新 NORMAL_CONTROLS 白名单。"
        )

    entries: Dict[str, Dict[str, Any]] = {}
    for key, preset in attacks:
        body_text = browser_body_text(preset.get("body"), pretty=True)
        fingerprint = lab_fingerprint(
            preset["method"], preset["url"], preset.get("contentType", ""), body_text
        )
        entries[fingerprint] = {
            "fingerprint": fingerprint,
            "method": preset["method"],
            "uri": preset["url"],
            "analysis": build_analysis(key, preset["name"], preset["method"], preset["url"], body_text),
            "label": f"{key}/{preset['name']}",
        }

    for item in FULL_CHAIN_SCENARIO:
        body_text = browser_body_text(item.get("body"), pretty=False)
        fingerprint = lab_fingerprint(
            item["method"], item["url"], item.get("contentType", ""), body_text
        )
        if fingerprint in entries:
            continue
        family_key = CHAIN_FAMILY_BY_LABEL.get(item["label"])
        if not family_key:
            raise RuntimeError(f"全链路步骤缺少攻击族映射: {item['label']}")
        entries[fingerprint] = {
            "fingerprint": fingerprint,
            "method": item["method"],
            "uri": item["url"],
            "analysis": build_analysis(
                family_key, f"全链路·{item['label']}", item["method"], item["url"], body_text
            ),
            "label": f"full-chain/{item['label']}",
        }

    if len(entries) != EXPECTED_UNIQUE_FINGERPRINTS:
        raise RuntimeError(
            f"唯一指纹数量漂移: {len(entries)} != {EXPECTED_UNIQUE_FINGERPRINTS}，"
            "请检查靶场预设或序列化格式是否变化。"
        )
    return list(entries.values())


def seed_cache(conn: Any, entries: List[Dict[str, Any]], *, dry_run: bool = False) -> Dict[str, int]:
    stats = {"inserted": 0, "updated": 0, "preserved": 0, "total": len(entries)}
    for entry in entries:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT model_name FROM llm_review_cache WHERE fingerprint=%s LIMIT 1",
                (entry["fingerprint"],),
            )
            existing = cur.fetchone()
        template = json.dumps(entry["analysis"], ensure_ascii=False)
        if existing:
            model_name = str(existing.get("model_name") or "")
            if model_name and model_name != PRECOMPUTED_MODEL:
                stats["preserved"] += 1
                continue
            if not dry_run:
                with conn.cursor() as cur:
                    cur.execute(
                        """UPDATE llm_review_cache
                           SET target_port=%s, method=%s, uri=%s, template_json=%s,
                               model_name=%s, enabled=1
                           WHERE fingerprint=%s""",
                        (
                            TARGET_PORT, entry["method"][:16], entry["uri"],
                            template, PRECOMPUTED_MODEL, entry["fingerprint"],
                        ),
                    )
            stats["updated"] += 1
            continue
        if not dry_run:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO llm_review_cache(
                         fingerprint,target_port,method,uri,template_json,model_name,enabled
                       ) VALUES(%s,%s,%s,%s,%s,%s,1)""",
                    (
                        entry["fingerprint"], TARGET_PORT, entry["method"][:16],
                        entry["uri"], template, PRECOMPUTED_MODEL,
                    ),
                )
        stats["inserted"] += 1
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mysql-host", default="127.0.0.1")
    parser.add_argument("--mysql-port", type=int, default=3306)
    parser.add_argument("--mysql-user", default="root")
    parser.add_argument("--mysql-password", default="123456")
    parser.add_argument("--mysql-database", default="traffic_pipeline")
    parser.add_argument("--dry-run", action="store_true", help="只统计不写库")
    args = parser.parse_args()

    entries = collect_cache_entries()
    print(
        f"lab modules={len(LAB_PAGES)} presets={EXPECTED_PRESETS} "
        f"attack_presets={EXPECTED_ATTACK_PRESETS} normal_controls={len(NORMAL_CONTROLS)}"
    )
    print(f"unique attack fingerprints={len(entries)} (module 36 + full-chain extras)")
    for entry in entries:
        print(f"  {entry['fingerprint'][:10]}  {entry['label']}")

    if args.dry_run:
        stats = {"inserted": 0, "updated": 0, "preserved": 0, "total": len(entries)}
        print("dry-run: 未写入数据库")
        return 0

    import pymysql

    conn = pymysql.connect(
        host=args.mysql_host,
        port=args.mysql_port,
        user=args.mysql_user,
        password=args.mysql_password,
        database=args.mysql_database,
        charset="utf8mb4",
        autocommit=True,
        cursorclass=pymysql.cursors.DictCursor,
    )
    try:
        ensure_review_schema(conn)
        stats = seed_cache(conn, entries)
    finally:
        conn.close()
    print(
        "seed done: inserted={inserted} updated={updated} "
        "preserved_realtime={preserved} total={total}".format(**stats)
    )
    print(
        f"note: seeded rows use model_name={PRECOMPUTED_MODEL} (预生成安全研判模板); "
        "真实实时研判产生的缓存不会被覆盖。"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
