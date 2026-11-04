# `scripts/seed_authoritative_rag.py` 逐行注释

**脚本用途：** 导入 OWASP 等权威安全知识，建立可用于研判的初始知识库。

**源码行数：** 206　**函数/类数量：** 6

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>"""Download authoritative security sources and ingest them into advanced RAG.</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>Sources are intentionally limited to official OWASP, MITRE and CISA datasets.</code> |
| L0004 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>Run this script again to create a newly versioned source snapshot.</code> |
| L0005 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>"""</code> |
| L0006 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0008 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;import sys&#96;。 | <code>import sys</code> |
| L0012 | 导入后续逻辑所需的模块、类或函数：&#96;import tempfile&#96;。 | <code>import tempfile</code> |
| L0013 | 导入后续逻辑所需的模块、类或函数：&#96;import time&#96;。 | <code>import time</code> |
| L0014 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.request&#96;。 | <code>import urllib.request</code> |
| L0015 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0016 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, List&#96;。 | <code>from typing import Any, Dict, List</code> |
| L0017 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0018 | 计算并保存 &#96;PROJECT_ROOT&#96;（PROJECTROOT），供后续逻辑使用。 | <code>PROJECT_ROOT = Path(__file__).resolve().parent.parent</code> |
| L0019 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>sys.path.insert(0, str(PROJECT_ROOT / "scripts"))</code> |
| L0020 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0021 | 导入后续逻辑所需的模块、类或函数：&#96;from rag_service import (  # noqa: E402&#96;。 | <code>from rag_service import (  # noqa: E402</code> |
| L0022 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ensure_default_kb,</code> |
| L0023 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ensure_schema,</code> |
| L0024 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    get_kb,</code> |
| L0025 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ingest_file,</code> |
| L0026 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    list_eval_cases,</code> |
| L0027 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    load_api_config,</code> |
| L0028 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    mysql_connect,</code> |
| L0029 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    save_eval_case,</code> |
| L0030 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>)</code> |
| L0031 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0032 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0033 | 计算并保存 &#96;OWASP_FILES&#96;（OWASPFILES），供后续逻辑使用。 | <code>OWASP_FILES = [</code> |
| L0034 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SQL_Injection_Prevention_Cheat_Sheet.md",</code> |
| L0035 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "Cross_Site_Scripting_Prevention_Cheat_Sheet.md",</code> |
| L0036 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md",</code> |
| L0037 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "File_Upload_Cheat_Sheet.md",</code> |
| L0038 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "Authentication_Cheat_Sheet.md",</code> |
| L0039 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "Deserialization_Cheat_Sheet.md",</code> |
| L0040 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "Logging_Cheat_Sheet.md",</code> |
| L0041 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "REST_Security_Cheat_Sheet.md",</code> |
| L0042 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>]</code> |
| L0043 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0044 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0045 | 定义获取函数 &#96;fetch&#96;，封装可复用业务逻辑。 | <code>def fetch(url: str, timeout: int = 120, attempts: int = 4) -&gt; bytes:</code> |
| L0046 | 计算并保存 &#96;last_error&#96;（lasterror），供后续逻辑使用，当前位于函数 fetch。 | <code>    last_error: Exception &#124; None = None</code> |
| L0047 | 遍历集合中的数据项并逐项处理，当前位于函数 fetch。 | <code>    for attempt in range(1, attempts + 1):</code> |
| L0048 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 fetch。 | <code>        try:</code> |
| L0049 | 计算并保存 &#96;req&#96;（req），供后续逻辑使用，当前位于函数 fetch。 | <code>            req = urllib.request.Request(url, headers={"User-Agent": "Jingyuan-RAG-Seed/1.0"})</code> |
| L0050 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 fetch。 | <code>            with urllib.request.urlopen(req, timeout=timeout) as resp:</code> |
| L0051 | 结束当前函数并把结果返回给调用方，当前位于函数 fetch。 | <code>                return resp.read()</code> |
| L0052 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 fetch。 | <code>        except Exception as exc:</code> |
| L0053 | 计算并保存 &#96;last_error&#96;（lasterror），供后续逻辑使用，当前位于函数 fetch。 | <code>            last_error = exc</code> |
| L0054 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 fetch。 | <code>            if attempt &lt; attempts:</code> |
| L0055 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fetch。 | <code>                time.sleep(min(12, attempt * 3))</code> |
| L0056 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 fetch。 | <code>    raise RuntimeError(f"下载官方知识失败（已重试 {attempts} 次）：{url}: {last_error}")</code> |
| L0057 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0058 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0059 | 定义构建owasp函数 &#96;build_owasp&#96;，封装可复用业务逻辑。 | <code>def build_owasp() -&gt; str:</code> |
| L0060 | 计算并保存 &#96;sections&#96;（sections），供后续逻辑使用，当前位于函数 build_owasp。 | <code>    sections = [</code> |
| L0061 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_owasp。 | <code>        "# OWASP Web 安全防护知识快照",</code> |
| L0062 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_owasp。 | <code>        "",</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_owasp。 | <code>        "来源：https://github.com/OWASP/CheatSheetSeries",</code> |
| L0064 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_owasp。 | <code>        "用途：Web 攻击判定、证据解释与安全修复建议。",</code> |
| L0065 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_owasp。 | <code>    ]</code> |
| L0066 | 计算并保存 &#96;base&#96;（base），供后续逻辑使用，当前位于函数 build_owasp。 | <code>    base = "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/"</code> |
| L0067 | 遍历集合中的数据项并逐项处理，当前位于函数 build_owasp。 | <code>    for name in OWASP_FILES:</code> |
| L0068 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 build_owasp。 | <code>        text = fetch(base + name).decode("utf-8", errors="replace")</code> |
| L0069 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_owasp。 | <code>        sections.extend(["", f"# 来源文档：{name}", f"原始地址：{base + name}", "", text])</code> |
| L0070 | 结束当前函数并把结果返回给调用方，当前位于函数 build_owasp。 | <code>    return "\n".join(sections)</code> |
| L0071 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0072 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0073 | 定义构建mitre函数 &#96;build_mitre&#96;，封装可复用业务逻辑。 | <code>def build_mitre() -&gt; str:</code> |
| L0074 | 计算并保存 &#96;url&#96;（url），供后续逻辑使用，当前位于函数 build_mitre。 | <code>    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"</code> |
| L0075 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 build_mitre。 | <code>    payload = json.loads(fetch(url).decode("utf-8"))</code> |
| L0076 | 计算并保存 &#96;keywords&#96;（keywords），供后续逻辑使用，当前位于函数 build_mitre。 | <code>    keywords = {</code> |
| L0077 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_mitre。 | <code>        "scan", "scanning", "reconnaissance", "public-facing", "brute force", "credential",</code> |
| L0078 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_mitre。 | <code>        "phishing", "web", "exploit", "remote service", "network service", "valid accounts",</code> |
| L0079 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_mitre。 | <code>    }</code> |
| L0080 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 build_mitre。 | <code>    rows: List[str] = [</code> |
| L0081 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_mitre。 | <code>        "# MITRE ATT&amp;CK Enterprise 攻击技术精选",</code> |
| L0082 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_mitre。 | <code>        "",</code> |
| L0083 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_mitre。 | <code>        f"STIX 2.1 数据来源：{url}",</code> |
| L0084 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_mitre。 | <code>        "筛选范围：与外部侦察、公开服务利用、凭据攻击、钓鱼和远程服务相关的攻击技术。",</code> |
| L0085 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_mitre。 | <code>    ]</code> |
| L0086 | 计算并保存 &#96;selected&#96;（selected），供后续逻辑使用，当前位于函数 build_mitre。 | <code>    selected = []</code> |
| L0087 | 遍历集合中的数据项并逐项处理，当前位于函数 build_mitre。 | <code>    for obj in payload.get("objects") or []:</code> |
| L0088 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_mitre。 | <code>        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):</code> |
| L0089 | 控制当前循环或占位分支的执行流程，当前位于函数 build_mitre。 | <code>            continue</code> |
| L0090 | 计算并保存 &#96;haystack&#96;（haystack），供后续逻辑使用，当前位于函数 build_mitre。 | <code>        haystack = f"{obj.get('name','')} {obj.get('description','')}".lower()</code> |
| L0091 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_mitre。 | <code>        if not any(keyword in haystack for keyword in keywords):</code> |
| L0092 | 控制当前循环或占位分支的执行流程，当前位于函数 build_mitre。 | <code>            continue</code> |
| L0093 | 计算并保存 &#96;refs&#96;（refs），供后续逻辑使用，当前位于函数 build_mitre。 | <code>        refs = obj.get("external_references") or []</code> |
| L0094 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_mitre。 | <code>        attack_ref = next((ref for ref in refs if ref.get("source_name") == "mitre-attack"), {})</code> |
| L0095 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_mitre。 | <code>        selected.append(</code> |
| L0096 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_mitre。 | <code>            (</code> |
| L0097 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_mitre。 | <code>                str(attack_ref.get("external_id") or "ATT&amp;CK"),</code> |
| L0098 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_mitre。 | <code>                str(obj.get("name") or "Unnamed technique"),</code> |
| L0099 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_mitre。 | <code>                str(obj.get("description") or "").replace("\r", "").strip(),</code> |
| L0100 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_mitre。 | <code>                str(attack_ref.get("url") or url),</code> |
| L0101 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_mitre。 | <code>            )</code> |
| L0102 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_mitre。 | <code>        )</code> |
| L0103 | 遍历集合中的数据项并逐项处理，当前位于函数 build_mitre。 | <code>    for external_id, name, description, source in sorted(selected)[:180]:</code> |
| L0104 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_mitre。 | <code>        rows.extend(["", f"## {external_id} {name}", f"来源：{source}", "", description])</code> |
| L0105 | 结束当前函数并把结果返回给调用方，当前位于函数 build_mitre。 | <code>    return "\n".join(rows)</code> |
| L0106 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0107 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0108 | 定义构建cisa函数 &#96;build_cisa&#96;，封装可复用业务逻辑。 | <code>def build_cisa() -&gt; str:</code> |
| L0109 | 计算并保存 &#96;url&#96;（url），供后续逻辑使用，当前位于函数 build_cisa。 | <code>    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"</code> |
| L0110 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 build_cisa。 | <code>    payload = json.loads(fetch(url).decode("utf-8"))</code> |
| L0111 | 计算并保存 &#96;vulnerabilities&#96;（vulnerabilities），供后续逻辑使用，当前位于函数 build_cisa。 | <code>    vulnerabilities = sorted(payload.get("vulnerabilities") or [], key=lambda row: row.get("dateAdded", ""), reverse=True)[:300]</code> |
| L0112 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 build_cisa。 | <code>    rows = [</code> |
| L0113 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cisa。 | <code>        "# CISA Known Exploited Vulnerabilities 精选",</code> |
| L0114 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cisa。 | <code>        "",</code> |
| L0115 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cisa。 | <code>        f"来源：{url}",</code> |
| L0116 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cisa。 | <code>        f"目录版本：{payload.get('catalogVersion', '-')}",</code> |
| L0117 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cisa。 | <code>        "说明：仅收录已知在野利用漏洞，用于 CVE 风险优先级和 N-day 攻击证据增强。",</code> |
| L0118 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_cisa。 | <code>    ]</code> |
| L0119 | 遍历集合中的数据项并逐项处理，当前位于函数 build_cisa。 | <code>    for item in vulnerabilities:</code> |
| L0120 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_cisa。 | <code>        rows.extend(</code> |
| L0121 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cisa。 | <code>            [</code> |
| L0122 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cisa。 | <code>                "",</code> |
| L0123 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cisa。 | <code>                f"## {item.get('cveID', 'CVE')} {item.get('vulnerabilityName', '')}",</code> |
| L0124 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cisa。 | <code>                f"厂商与产品：{item.get('vendorProject', '-')} / {item.get('product', '-')}",</code> |
| L0125 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cisa。 | <code>                f"加入日期：{item.get('dateAdded', '-')}；要求处置日期：{item.get('dueDate', '-')}",</code> |
| L0126 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cisa。 | <code>                f"漏洞说明：{item.get('shortDescription', '')}",</code> |
| L0127 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cisa。 | <code>                f"处置要求：{item.get('requiredAction', '')}",</code> |
| L0128 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cisa。 | <code>                f"勒索软件关联：{item.get('knownRansomwareCampaignUse', 'Unknown')}",</code> |
| L0129 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cisa。 | <code>                f"参考：{item.get('notes', '')}",</code> |
| L0130 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_cisa。 | <code>            ]</code> |
| L0131 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_cisa。 | <code>        )</code> |
| L0132 | 结束当前函数并把结果返回给调用方，当前位于函数 build_cisa。 | <code>    return "\n".join(rows)</code> |
| L0133 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0134 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0135 | 定义读取数据库配置函数 &#96;read_db_config&#96;，封装可复用业务逻辑。 | <code>def read_db_config(path: Path) -&gt; Dict[str, Any]:</code> |
| L0136 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 read_db_config。 | <code>    data = json.loads(path.read_text(encoding="utf-8-sig"))</code> |
| L0137 | 计算并保存 &#96;mysql&#96;（mysql），供后续逻辑使用，当前位于函数 read_db_config。 | <code>    mysql = data.get("mysql") if isinstance(data.get("mysql"), dict) else data</code> |
| L0138 | 结束当前函数并把结果返回给调用方，当前位于函数 read_db_config。 | <code>    return {</code> |
| L0139 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_db_config。 | <code>        "host": str(mysql.get("host") or "127.0.0.1"),</code> |
| L0140 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_db_config。 | <code>        "port": int(mysql.get("port") or 3306),</code> |
| L0141 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_db_config。 | <code>        "user": str(mysql.get("user") or "root"),</code> |
| L0142 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_db_config。 | <code>        "password": str(mysql.get("password") or "123456"),</code> |
| L0143 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_db_config。 | <code>        "database": str(mysql.get("database") or "traffic_pipeline"),</code> |
| L0144 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 read_db_config。 | <code>    }</code> |
| L0145 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0146 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0147 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; None:</code> |
| L0148 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="Seed authoritative RAG documents")</code> |
| L0149 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--db-config", default="config/db_config.json")</code> |
| L0150 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--api-config", default="config/ai_api.local.json")</code> |
| L0151 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--data-dir", default="D:/JingyuanTrafficPipelineData/rag")</code> |
| L0152 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--kb-id", type=int, default=0)</code> |
| L0153 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--source-dir", default="", help="已下载的三份官方 Markdown 快照目录")</code> |
| L0154 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0155 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0156 | 计算并保存 &#96;conf&#96;（conf），供后续逻辑使用，当前位于函数 main。 | <code>    conf = read_db_config((PROJECT_ROOT / args.db_config).resolve())</code> |
| L0157 | 计算并保存 &#96;api_config&#96;（接口配置），供后续逻辑使用，当前位于函数 main。 | <code>    api_config = load_api_config((PROJECT_ROOT / args.api_config).resolve())</code> |
| L0158 | 计算并保存 &#96;data_dir&#96;（datadir），供后续逻辑使用，当前位于函数 main。 | <code>    data_dir = Path(args.data_dir).resolve()</code> |
| L0159 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    data_dir.mkdir(parents=True, exist_ok=True)</code> |
| L0160 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 main。 | <code>    with mysql_connect(conf, autocommit=False) as conn:</code> |
| L0161 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        ensure_schema(conn)</code> |
| L0162 | 计算并保存 &#96;kb_id&#96;（kbid），供后续逻辑使用，当前位于函数 main。 | <code>        kb_id = args.kb_id or ensure_default_kb(conn)</code> |
| L0163 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if not get_kb(conn, kb_id):</code> |
| L0164 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 main。 | <code>            raise SystemExit(f"Knowledge base {kb_id} does not exist")</code> |
| L0165 | 计算并保存 &#96;builders&#96;（builders），供后续逻辑使用，当前位于函数 main。 | <code>        builders = [</code> |
| L0166 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            ("OWASP_Cheat_Sheet_Security_Knowledge.md", build_owasp),</code> |
| L0167 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            ("MITRE_ATTACK_Enterprise_Selected_Techniques.md", build_mitre),</code> |
| L0168 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            ("CISA_KEV_Selected.md", build_cisa),</code> |
| L0169 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        ]</code> |
| L0170 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 main。 | <code>        with tempfile.TemporaryDirectory(prefix="jingyuan-rag-") as temp_dir:</code> |
| L0171 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>            for filename, builder in builders:</code> |
| L0172 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                print(f"[download] {filename}")</code> |
| L0173 | 计算并保存 &#96;path&#96;（path），供后续逻辑使用，当前位于函数 main。 | <code>                path = Path(temp_dir) / filename</code> |
| L0174 | 计算并保存 &#96;cached&#96;（cached），供后续逻辑使用，当前位于函数 main。 | <code>                cached = Path(args.source_dir).resolve() / filename if args.source_dir else None</code> |
| L0175 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if cached and cached.exists():</code> |
| L0176 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    path.write_bytes(cached.read_bytes())</code> |
| L0177 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                    print(f"[cache] {cached}")</code> |
| L0178 | 处理前述条件均未命中的情况，当前位于函数 main。 | <code>                else:</code> |
| L0179 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    path.write_text(builder(), encoding="utf-8")</code> |
| L0180 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 main。 | <code>                result = ingest_file(conn, data_dir, api_config, kb_id, path, filename, "official-seed", source_type="official")</code> |
| L0181 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                print(f"[ready] {result}")</code> |
| L0182 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if not list_eval_cases(conn, kb_id):</code> |
| L0183 | 计算并保存 &#96;cases&#96;（cases），供后续逻辑使用，当前位于函数 main。 | <code>            cases = [</code> |
| L0184 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                {</code> |
| L0185 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    "question": "登录接口的 password 参数出现单引号、OR 1=1 与注释符，应如何识别和修复？",</code> |
| L0186 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    "expected_keywords": "SQL Injection, SQL 注入, parameterized",</code> |
| L0187 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    "expected_document": "OWASP",</code> |
| L0188 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>                },</code> |
| L0189 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                {</code> |
| L0190 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    "question": "响应页面把用户输入直接插入 HTML，出现 script 标签和 onerror 事件时，应如何防护？",</code> |
| L0191 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    "expected_keywords": "XSS, output encoding, CSP",</code> |
| L0192 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    "expected_document": "OWASP",</code> |
| L0193 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>                },</code> |
| L0194 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                {</code> |
| L0195 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    "question": "Nmap 在短时间内向服务器多个端口发送 SYN 探测包，这属于什么行为，应如何发现和处置？",</code> |
| L0196 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    "expected_keywords": "PortScan, port scan, 端口扫描",</code> |
| L0197 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    "expected_document": "",</code> |
| L0198 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>                },</code> |
| L0199 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>            ]</code> |
| L0200 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>            for case in cases:</code> |
| L0201 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                save_eval_case(conn, kb_id, case)</code> |
| L0202 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>            print(f"[ready] created {len(cases)} regression cases")</code> |
| L0203 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0204 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0205 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0206 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
