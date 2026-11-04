# `scripts/security_detection_v2.py` 逐行注释

**脚本用途：** 新架构融合检测核心：Payload 模型、POC 规则、行为窗口和上下文证据融合。

**源码行数：** 650　**函数/类数量：** 32

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import html&#96;。 | <code>import html</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import re&#96;。 | <code>import re</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;from collections import defaultdict, deque&#96;。 | <code>from collections import defaultdict, deque</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;from dataclasses import dataclass, field&#96;。 | <code>from dataclasses import dataclass, field</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime, timedelta&#96;。 | <code>from datetime import datetime, timedelta</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, Iterable, List, Optional, Tuple&#96;。 | <code>from typing import Any, Dict, Iterable, List, Optional, Tuple</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;from urllib.parse import unquote_plus, urlsplit&#96;。 | <code>from urllib.parse import unquote_plus, urlsplit</code> |
| L0012 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0013 | 导入后续逻辑所需的模块、类或函数：&#96;import joblib&#96;。 | <code>import joblib</code> |
| L0014 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0015 | 计算并保存 &#96;PROJECT_ROOT&#96;（PROJECTROOT），供后续逻辑使用。 | <code>PROJECT_ROOT = Path(__file__).resolve().parent.parent</code> |
| L0016 | 计算并保存 &#96;DEFAULT_RULES_PATH&#96;（DEFAULTRULESPATH），供后续逻辑使用。 | <code>DEFAULT_RULES_PATH = PROJECT_ROOT / "rules" / "poc_rules.json"</code> |
| L0017 | 计算并保存 &#96;DEFAULT_MODEL_PATH&#96;（DEFAULT模型PATH），供后续逻辑使用。 | <code>DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "payload_model_v2.joblib"</code> |
| L0018 | 计算并保存 &#96;DEFAULT_BEHAVIOR_MODEL_PATH&#96;（DEFAULTBEHAVIOR模型PATH），供后续逻辑使用。 | <code>DEFAULT_BEHAVIOR_MODEL_PATH = PROJECT_ROOT / "models" / "behavior_model_v2.joblib"</code> |
| L0019 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0020 | 计算并保存 &#96;ATTACK_TYPE_PRIORITY&#96;（攻击TYPEPRIORITY），供后续逻辑使用。 | <code>ATTACK_TYPE_PRIORITY = {</code> |
| L0021 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "XXE": 100,</code> |
| L0022 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "命令注入": 95,</code> |
| L0023 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "Fastjson反序列化探测": 94,</code> |
| L0024 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SQL注入": 90,</code> |
| L0025 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "XSS": 88,</code> |
| L0026 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "路径遍历": 85,</code> |
| L0027 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SSRF": 84,</code> |
| L0028 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SSTI": 83,</code> |
| L0029 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "危险文件上传": 82,</code> |
| L0030 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "反序列化": 80,</code> |
| L0031 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "GraphQL探测": 60,</code> |
| L0032 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>}</code> |
| L0033 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0034 | 计算并保存 &#96;SEVERITY_SCORE&#96;（SEVERITYSCORE），供后续逻辑使用。 | <code>SEVERITY_SCORE = {</code> |
| L0035 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "info": 0.05,</code> |
| L0036 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "low": 0.35,</code> |
| L0037 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "medium": 0.65,</code> |
| L0038 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "high": 0.9,</code> |
| L0039 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "critical": 0.98,</code> |
| L0040 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>}</code> |
| L0041 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0042 | 计算并保存 &#96;SAFE_PAGE_PATHS&#96;（SAFEPAGEPATHS），供后续逻辑使用。 | <code>SAFE_PAGE_PATHS = {</code> |
| L0043 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/",</code> |
| L0044 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/login",</code> |
| L0045 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/sql",</code> |
| L0046 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/xss",</code> |
| L0047 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/upload",</code> |
| L0048 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/command",</code> |
| L0049 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/traversal",</code> |
| L0050 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/ssrf",</code> |
| L0051 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/xxe",</code> |
| L0052 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/deserialize",</code> |
| L0053 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/graphql",</code> |
| L0054 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/ssti",</code> |
| L0055 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/bruteforce",</code> |
| L0056 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>}</code> |
| L0057 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0058 | 计算并保存 &#96;SENSITIVE_CONTEXT_PATTERNS&#96;（SENSITIVECONTEXTPATTERNS），供后续逻辑使用。 | <code>SENSITIVE_CONTEXT_PATTERNS = [</code> |
| L0059 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    (re.compile(r"(?i)(/login&#124;/auth&#124;/signin&#124;/session&#124;/api/auth)"), 0.85, "认证接口"),</code> |
| L0060 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    (re.compile(r"(?i)(/upload&#124;/file&#124;/import)"), 0.75, "文件/导入接口"),</code> |
| L0061 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    (re.compile(r"(?i)(/admin&#124;/manage&#124;/config)"), 0.8, "管理接口"),</code> |
| L0062 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    (re.compile(r"(?i)(/search&#124;/comment&#124;/profile&#124;/message)"), 0.6, "可回显接口"),</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    (re.compile(r"(?i)(/ping&#124;/system&#124;/exec&#124;/cmd)"), 0.9, "系统命令相关接口"),</code> |
| L0064 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>]</code> |
| L0065 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0066 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0067 | 定义标准化text函数 &#96;normalize_text&#96;，封装可复用业务逻辑。 | <code>def normalize_text(text: Any, rounds: int = 4) -&gt; str:</code> |
| L0068 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 normalize_text。 | <code>    current = str(text or "")</code> |
| L0069 | 计算并保存 &#96;variants&#96;（variants），供后续逻辑使用，当前位于函数 normalize_text。 | <code>    variants = []</code> |
| L0070 | 遍历集合中的数据项并逐项处理，当前位于函数 normalize_text。 | <code>    for _ in range(rounds):</code> |
| L0071 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_text。 | <code>        if current not in variants:</code> |
| L0072 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 normalize_text。 | <code>            variants.append(current)</code> |
| L0073 | 计算并保存 &#96;decoded&#96;（decoded），供后续逻辑使用，当前位于函数 normalize_text。 | <code>        decoded = html.unescape(unquote_plus(current))</code> |
| L0074 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_text。 | <code>        if decoded == current:</code> |
| L0075 | 控制当前循环或占位分支的执行流程，当前位于函数 normalize_text。 | <code>            break</code> |
| L0076 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 normalize_text。 | <code>        current = decoded</code> |
| L0077 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_text。 | <code>    return "\n".join(variants)</code> |
| L0078 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0079 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0080 | 定义lowernorm函数 &#96;lower_norm&#96;，封装可复用业务逻辑。 | <code>def lower_norm(text: Any) -&gt; str:</code> |
| L0081 | 结束当前函数并把结果返回给调用方，当前位于函数 lower_norm。 | <code>    return normalize_text(text).lower()</code> |
| L0082 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0083 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0084 | 定义splitrequestresponsesummary函数 &#96;split_request_response_summary&#96;，封装可复用业务逻辑。 | <code>def split_request_response_summary(text: str) -&gt; Tuple[str, str]:</code> |
| L0085 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 split_request_response_summary。 | <code>    text = str(text or "")</code> |
| L0086 | 计算并保存 &#96;marker&#96;（marker），供后续逻辑使用，当前位于函数 split_request_response_summary。 | <code>    marker = "RESPONSE_EXCERPT="</code> |
| L0087 | 计算并保存 &#96;idx&#96;（idx），供后续逻辑使用，当前位于函数 split_request_response_summary。 | <code>    idx = text.upper().find(marker)</code> |
| L0088 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 split_request_response_summary。 | <code>    if idx &gt;= 0:</code> |
| L0089 | 结束当前函数并把结果返回给调用方，当前位于函数 split_request_response_summary。 | <code>        return text[:idx], text[idx + len(marker):]</code> |
| L0090 | 结束当前函数并把结果返回给调用方，当前位于函数 split_request_response_summary。 | <code>    return text, ""</code> |
| L0091 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0092 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0093 | 定义extractbodyfromrawrequest函数 &#96;extract_body_from_raw_request&#96;，封装可复用业务逻辑。 | <code>def extract_body_from_raw_request(raw: str) -&gt; str:</code> |
| L0094 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 extract_body_from_raw_request。 | <code>    raw = str(raw or "")</code> |
| L0095 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 extract_body_from_raw_request。 | <code>    if "\r\n\r\n" in raw:</code> |
| L0096 | 结束当前函数并把结果返回给调用方，当前位于函数 extract_body_from_raw_request。 | <code>        return raw.split("\r\n\r\n", 1)[1].strip()</code> |
| L0097 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 extract_body_from_raw_request。 | <code>    if "\n\n" in raw:</code> |
| L0098 | 结束当前函数并把结果返回给调用方，当前位于函数 extract_body_from_raw_request。 | <code>        return raw.split("\n\n", 1)[1].strip()</code> |
| L0099 | 计算并保存 &#96;m&#96;（m），供后续逻辑使用，当前位于函数 extract_body_from_raw_request。 | <code>    m = re.search(r"(?is)\bBody:\s*(.*)$", raw)</code> |
| L0100 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 extract_body_from_raw_request。 | <code>    if m:</code> |
| L0101 | 结束当前函数并把结果返回给调用方，当前位于函数 extract_body_from_raw_request。 | <code>        return m.group(1).strip()</code> |
| L0102 | 计算并保存 &#96;m&#96;（m），供后续逻辑使用，当前位于函数 extract_body_from_raw_request。 | <code>    m = re.search(r"(?is)REQUEST_BODY=(.*?)(?:\n[A-Z_]+=&#124;$)", raw)</code> |
| L0103 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 extract_body_from_raw_request。 | <code>    if m:</code> |
| L0104 | 结束当前函数并把结果返回给调用方，当前位于函数 extract_body_from_raw_request。 | <code>        return m.group(1).strip()</code> |
| L0105 | 结束当前函数并把结果返回给调用方，当前位于函数 extract_body_from_raw_request。 | <code>    return ""</code> |
| L0106 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0107 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0108 | 定义extractrequestfromrecord函数 &#96;extract_request_from_record&#96;，封装可复用业务逻辑。 | <code>def extract_request_from_record(record: Dict[str, Any]) -&gt; Dict[str, Any]:</code> |
| L0109 | 计算并保存 &#96;request_text&#96;（requesttext），供后续逻辑使用，当前位于函数 extract_request_from_record。 | <code>    request_text = str(record.get("request_text") or record.get("request_text_summary") or "")</code> |
| L0110 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>    request_side, response_side = split_request_response_summary(request_text)</code> |
| L0111 | 计算并保存 &#96;raw_request&#96;（rawrequest），供后续逻辑使用，当前位于函数 extract_request_from_record。 | <code>    raw_request = str(record.get("raw_request_block") or record.get("request_content") or "")</code> |
| L0112 | 计算并保存 &#96;raw_response&#96;（rawresponse），供后续逻辑使用，当前位于函数 extract_request_from_record。 | <code>    raw_response = str(record.get("raw_response_block") or record.get("response_content") or response_side or "")</code> |
| L0113 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0114 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 extract_request_from_record。 | <code>    method = str(record.get("method") or "").upper()</code> |
| L0115 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 extract_request_from_record。 | <code>    uri = str(record.get("uri") or "")</code> |
| L0116 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 extract_request_from_record。 | <code>    host = str(record.get("host") or "")</code> |
| L0117 | 计算并保存 &#96;status_code&#96;（状态code），供后续逻辑使用，当前位于函数 extract_request_from_record。 | <code>    status_code = record.get("status_code")</code> |
| L0118 | 计算并保存 &#96;content_type&#96;（contenttype），供后续逻辑使用，当前位于函数 extract_request_from_record。 | <code>    content_type = str(record.get("content_type") or "")</code> |
| L0119 | 计算并保存 &#96;user_agent&#96;（useragent），供后续逻辑使用，当前位于函数 extract_request_from_record。 | <code>    user_agent = str(record.get("user_agent") or "")</code> |
| L0120 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 extract_request_from_record。 | <code>    body = str(record.get("request_body") or "") or extract_body_from_raw_request(raw_request or request_side)</code> |
| L0121 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0122 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 extract_request_from_record。 | <code>    if not method:</code> |
| L0123 | 计算并保存 &#96;m&#96;（m），供后续逻辑使用，当前位于函数 extract_request_from_record。 | <code>        m = re.search(r"(?im)^\s*(GET&#124;POST&#124;PUT&#124;DELETE&#124;PATCH&#124;HEAD&#124;OPTIONS)\s+(\S+)", raw_request or request_side)</code> |
| L0124 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 extract_request_from_record。 | <code>        if m:</code> |
| L0125 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 extract_request_from_record。 | <code>            method = m.group(1).upper()</code> |
| L0126 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 extract_request_from_record。 | <code>            uri = uri or m.group(2)</code> |
| L0127 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 extract_request_from_record。 | <code>    if not host:</code> |
| L0128 | 计算并保存 &#96;m&#96;（m），供后续逻辑使用，当前位于函数 extract_request_from_record。 | <code>        m = re.search(r"(?im)^\s*Host:\s*(.+?)\s*$", raw_request or request_side)</code> |
| L0129 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 extract_request_from_record。 | <code>        if m:</code> |
| L0130 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 extract_request_from_record。 | <code>            host = m.group(1).strip()</code> |
| L0131 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 extract_request_from_record。 | <code>    if not content_type:</code> |
| L0132 | 计算并保存 &#96;m&#96;（m），供后续逻辑使用，当前位于函数 extract_request_from_record。 | <code>        m = re.search(r"(?im)^\s*Content-Type:\s*(.+?)\s*$", raw_request or request_side)</code> |
| L0133 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 extract_request_from_record。 | <code>        if m:</code> |
| L0134 | 计算并保存 &#96;content_type&#96;（contenttype），供后续逻辑使用，当前位于函数 extract_request_from_record。 | <code>            content_type = m.group(1).strip()</code> |
| L0135 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 extract_request_from_record。 | <code>    if not user_agent:</code> |
| L0136 | 计算并保存 &#96;m&#96;（m），供后续逻辑使用，当前位于函数 extract_request_from_record。 | <code>        m = re.search(r"(?im)^\s*User-Agent:\s*(.+?)\s*$", raw_request or request_side)</code> |
| L0137 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 extract_request_from_record。 | <code>        if m:</code> |
| L0138 | 计算并保存 &#96;user_agent&#96;（useragent），供后续逻辑使用，当前位于函数 extract_request_from_record。 | <code>            user_agent = m.group(1).strip()</code> |
| L0139 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0140 | 结束当前函数并把结果返回给调用方，当前位于函数 extract_request_from_record。 | <code>    return {</code> |
| L0141 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>        "case_id": record.get("case_id"),</code> |
| L0142 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>        "file_id": record.get("file_id"),</code> |
| L0143 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>        "seq_id": record.get("seq_id"),</code> |
| L0144 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>        "timestamp": record.get("attack_event_time") or record.get("created_at") or record.get("time"),</code> |
| L0145 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>        "source_ip": record.get("source_ip") or record.get("attack_ip") or record.get("src_ip"),</code> |
| L0146 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>        "destination_ip": record.get("destination_ip") or record.get("dst_ip"),</code> |
| L0147 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>        "source_port": record.get("source_port") or record.get("src_port"),</code> |
| L0148 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>        "destination_port": record.get("destination_port") or record.get("dst_port"),</code> |
| L0149 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>        "method": method,</code> |
| L0150 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>        "uri": uri,</code> |
| L0151 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>        "host": host,</code> |
| L0152 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>        "status_code": status_code,</code> |
| L0153 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>        "content_type": content_type,</code> |
| L0154 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>        "user_agent": user_agent,</code> |
| L0155 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>        "body": body,</code> |
| L0156 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>        "request_side": request_side,</code> |
| L0157 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>        "response_side": response_side or raw_response,</code> |
| L0158 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>        "raw_request": raw_request or request_side,</code> |
| L0159 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 extract_request_from_record。 | <code>        "raw_response": raw_response,</code> |
| L0160 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 extract_request_from_record。 | <code>    }</code> |
| L0161 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0162 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0163 | 定义requestdetectiontext函数 &#96;request_detection_text&#96;，封装可复用业务逻辑。 | <code>def request_detection_text(event: Dict[str, Any]) -&gt; str:</code> |
| L0164 | 结束当前函数并把结果返回给调用方，当前位于函数 request_detection_text。 | <code>    return "\n".join(</code> |
| L0165 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_detection_text。 | <code>        str(x or "")</code> |
| L0166 | 遍历集合中的数据项并逐项处理，当前位于函数 request_detection_text。 | <code>        for x in [</code> |
| L0167 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_detection_text。 | <code>            event.get("method"),</code> |
| L0168 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_detection_text。 | <code>            event.get("uri"),</code> |
| L0169 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_detection_text。 | <code>            event.get("host"),</code> |
| L0170 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_detection_text。 | <code>            event.get("content_type"),</code> |
| L0171 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_detection_text。 | <code>            event.get("user_agent"),</code> |
| L0172 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_detection_text。 | <code>            event.get("body"),</code> |
| L0173 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_detection_text。 | <code>            event.get("request_side"),</code> |
| L0174 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_detection_text。 | <code>            event.get("raw_request"),</code> |
| L0175 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 request_detection_text。 | <code>        ]</code> |
| L0176 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 request_detection_text。 | <code>    )</code> |
| L0177 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0178 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0179 | 定义payload模型text函数 &#96;payload_model_text&#96;，封装可复用业务逻辑。 | <code>def payload_model_text(event: Dict[str, Any]) -&gt; str:</code> |
| L0180 | 结束当前函数并把结果返回给调用方，当前位于函数 payload_model_text。 | <code>    return normalize_text(</code> |
| L0181 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 payload_model_text。 | <code>        "\n".join(</code> |
| L0182 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 payload_model_text。 | <code>            [</code> |
| L0183 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 payload_model_text。 | <code>                f"METHOD={event.get('method') or ''}",</code> |
| L0184 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 payload_model_text。 | <code>                f"URI={event.get('uri') or ''}",</code> |
| L0185 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 payload_model_text。 | <code>                f"HOST={event.get('host') or ''}",</code> |
| L0186 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 payload_model_text。 | <code>                f"CONTENT_TYPE={event.get('content_type') or ''}",</code> |
| L0187 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 payload_model_text。 | <code>                f"USER_AGENT={event.get('user_agent') or ''}",</code> |
| L0188 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 payload_model_text。 | <code>                f"BODY={event.get('body') or ''}",</code> |
| L0189 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 payload_model_text。 | <code>            ]</code> |
| L0190 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 payload_model_text。 | <code>        )</code> |
| L0191 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 payload_model_text。 | <code>    )</code> |
| L0192 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0193 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0194 | 定义解析事件time函数 &#96;parse_event_time&#96;，封装可复用业务逻辑。 | <code>def parse_event_time(value: Any) -&gt; Optional[datetime]:</code> |
| L0195 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_event_time。 | <code>    if not value:</code> |
| L0196 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_event_time。 | <code>        return None</code> |
| L0197 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_event_time。 | <code>    if isinstance(value, datetime):</code> |
| L0198 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_event_time。 | <code>        return value</code> |
| L0199 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 parse_event_time。 | <code>    text = str(value).strip()</code> |
| L0200 | 遍历集合中的数据项并逐项处理，当前位于函数 parse_event_time。 | <code>    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):</code> |
| L0201 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 parse_event_time。 | <code>        try:</code> |
| L0202 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_event_time。 | <code>            if fmt is None:</code> |
| L0203 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_event_time。 | <code>                return datetime.fromisoformat(text.replace("Z", "+00:00").replace(" ", "T"))</code> |
| L0204 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_event_time。 | <code>            return datetime.strptime(text, fmt)</code> |
| L0205 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 parse_event_time。 | <code>        except Exception:</code> |
| L0206 | 控制当前循环或占位分支的执行流程，当前位于函数 parse_event_time。 | <code>            continue</code> |
| L0207 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_event_time。 | <code>    return None</code> |
| L0208 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0209 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0210 | 定义issimplepageview函数 &#96;is_simple_page_view&#96;，封装可复用业务逻辑。 | <code>def is_simple_page_view(event: Dict[str, Any]) -&gt; bool:</code> |
| L0211 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 is_simple_page_view。 | <code>    method = str(event.get("method") or "").upper()</code> |
| L0212 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 is_simple_page_view。 | <code>    uri = str(event.get("uri") or "")</code> |
| L0213 | 计算并保存 &#96;path&#96;（path），供后续逻辑使用，当前位于函数 is_simple_page_view。 | <code>    path = urlsplit(uri).path or uri</code> |
| L0214 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 is_simple_page_view。 | <code>    body = str(event.get("body") or "").strip()</code> |
| L0215 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_simple_page_view。 | <code>    if method != "GET":</code> |
| L0216 | 结束当前函数并把结果返回给调用方，当前位于函数 is_simple_page_view。 | <code>        return False</code> |
| L0217 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_simple_page_view。 | <code>    if "?" in uri or body:</code> |
| L0218 | 结束当前函数并把结果返回给调用方，当前位于函数 is_simple_page_view。 | <code>        return False</code> |
| L0219 | 结束当前函数并把结果返回给调用方，当前位于函数 is_simple_page_view。 | <code>    return path in SAFE_PAGE_PATHS</code> |
| L0220 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0221 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0222 | 定义contextscore函数 &#96;context_score&#96;，封装可复用业务逻辑。 | <code>def context_score(event: Dict[str, Any]) -&gt; Tuple[float, str]:</code> |
| L0223 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 context_score。 | <code>    uri = str(event.get("uri") or "")</code> |
| L0224 | 遍历集合中的数据项并逐项处理，当前位于函数 context_score。 | <code>    for pattern, score, reason in SENSITIVE_CONTEXT_PATTERNS:</code> |
| L0225 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 context_score。 | <code>        if pattern.search(uri):</code> |
| L0226 | 结束当前函数并把结果返回给调用方，当前位于函数 context_score。 | <code>            return score, reason</code> |
| L0227 | 结束当前函数并把结果返回给调用方，当前位于函数 context_score。 | <code>    return 0.15, "普通接口"</code> |
| L0228 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0229 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0230 | 定义issuccessfulauthentication函数 &#96;is_successful_authentication&#96;，封装可复用业务逻辑。 | <code>def is_successful_authentication(event: Dict[str, Any]) -&gt; bool:</code> |
| L0231 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 is_successful_authentication。 | <code>    """Use a successful ordinary login as strong negative evidence."""</code> |
| L0232 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 is_successful_authentication。 | <code>    uri = str(event.get("uri") or "")</code> |
| L0233 | 计算并保存 &#96;path&#96;（path），供后续逻辑使用，当前位于函数 is_successful_authentication。 | <code>    path = urlsplit(uri).path or uri</code> |
| L0234 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_successful_authentication。 | <code>    if not re.search(r"(?i)(/login&#124;/auth/login&#124;/signin&#124;/session)$", path):</code> |
| L0235 | 结束当前函数并把结果返回给调用方，当前位于函数 is_successful_authentication。 | <code>        return False</code> |
| L0236 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 is_successful_authentication。 | <code>    try:</code> |
| L0237 | 计算并保存 &#96;status_code&#96;（状态code），供后续逻辑使用，当前位于函数 is_successful_authentication。 | <code>        status_code = int(event.get("status_code") or 0)</code> |
| L0238 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 is_successful_authentication。 | <code>    except (TypeError, ValueError):</code> |
| L0239 | 计算并保存 &#96;status_code&#96;（状态code），供后续逻辑使用，当前位于函数 is_successful_authentication。 | <code>        status_code = 0</code> |
| L0240 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_successful_authentication。 | <code>    if not 200 &lt;= status_code &lt; 300:</code> |
| L0241 | 结束当前函数并把结果返回给调用方，当前位于函数 is_successful_authentication。 | <code>        return False</code> |
| L0242 | 计算并保存 &#96;response&#96;（response），供后续逻辑使用，当前位于函数 is_successful_authentication。 | <code>    response = lower_norm(event.get("response_side") or event.get("raw_response") or "")</code> |
| L0243 | 结束当前函数并把结果返回给调用方，当前位于函数 is_successful_authentication。 | <code>    return bool(re.search(r'(?i)(access[_-]?token&#124;"token"\s*:&#124;"user"\s*:&#124;login[_ -]?success)', response))</code> |
| L0244 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0245 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0246 | 应用装饰器 &#96;@dataclass&#96;，为下一定义附加权限、缓存或注册行为。 | <code>@dataclass</code> |
| L0247 | 定义类 &#96;POCMatch&#96;，集中保存相关状态与操作。 | <code>class POCMatch:</code> |
| L0248 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 POCMatch。 | <code>    rule_id: str</code> |
| L0249 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 POCMatch。 | <code>    name: str</code> |
| L0250 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 POCMatch。 | <code>    attack_type: str</code> |
| L0251 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 POCMatch。 | <code>    severity: str</code> |
| L0252 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 POCMatch。 | <code>    score: float</code> |
| L0253 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于类 POCMatch。 | <code>    evidence: List[str] = field(default_factory=list)</code> |
| L0254 | 计算并保存 &#96;tags&#96;（tags），供后续逻辑使用，当前位于类 POCMatch。 | <code>    tags: List[str] = field(default_factory=list)</code> |
| L0255 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0256 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0257 | 定义类 &#96;POCRuleEngine&#96;，集中保存相关状态与操作。 | <code>class POCRuleEngine:</code> |
| L0258 | 定义init函数 &#96;__init__&#96;，封装可复用业务逻辑。 | <code>    def __init__(self, rules_path: Path &#124; str = DEFAULT_RULES_PATH):</code> |
| L0259 | 计算并保存 &#96;rules_path&#96;（rulespath），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.rules_path = Path(rules_path)</code> |
| L0260 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 __init__。 | <code>        if not self.rules_path.is_file():</code> |
| L0261 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 __init__。 | <code>            raise FileNotFoundError(f"POC rule file is missing: {self.rules_path}")</code> |
| L0262 | 计算并保存 &#96;rules&#96;（rules），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.rules = json.loads(self.rules_path.read_text(encoding="utf-8-sig"))</code> |
| L0263 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 __init__。 | <code>        if not isinstance(self.rules, list) or not self.rules:</code> |
| L0264 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 __init__。 | <code>            raise ValueError(f"POC rule file contains no rules: {self.rules_path}")</code> |
| L0265 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0266 | 定义match函数 &#96;match&#96;，封装可复用业务逻辑。 | <code>    def match(self, event: Dict[str, Any]) -&gt; List[POCMatch]:</code> |
| L0267 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 match。 | <code>        text = normalize_text(request_detection_text(event))</code> |
| L0268 | 计算并保存 &#96;path&#96;（path），供后续逻辑使用，当前位于函数 match。 | <code>        path = str(urlsplit(str(event.get("uri") or "")).path or event.get("uri") or "")</code> |
| L0269 | 计算并保存 &#96;matches&#96;（matches），供后续逻辑使用，当前位于函数 match。 | <code>        matches: List[POCMatch] = []</code> |
| L0270 | 遍历集合中的数据项并逐项处理，当前位于函数 match。 | <code>        for rule in self.rules:</code> |
| L0271 | 计算并保存 &#96;req&#96;（req），供后续逻辑使用，当前位于函数 match。 | <code>            req = rule.get("request") or {}</code> |
| L0272 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 match。 | <code>            evidence: List[str] = []</code> |
| L0273 | 计算并保存 &#96;path_patterns&#96;（pathpatterns），供后续逻辑使用，当前位于函数 match。 | <code>            path_patterns = req.get("path_regex") or []</code> |
| L0274 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 match。 | <code>            if path_patterns and not any(re.search(p, path, flags=re.I &#124; re.S) for p in path_patterns):</code> |
| L0275 | 控制当前循环或占位分支的执行流程，当前位于函数 match。 | <code>                continue</code> |
| L0276 | 计算并保存 &#96;ok&#96;（ok），供后续逻辑使用，当前位于函数 match。 | <code>            ok = False</code> |
| L0277 | 遍历集合中的数据项并逐项处理，当前位于函数 match。 | <code>            for pattern in req.get("text_regex") or []:</code> |
| L0278 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 match。 | <code>                if re.search(pattern, text, flags=re.I &#124; re.S):</code> |
| L0279 | 计算并保存 &#96;ok&#96;（ok），供后续逻辑使用，当前位于函数 match。 | <code>                    ok = True</code> |
| L0280 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 match。 | <code>                    evidence.append(pattern)</code> |
| L0281 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 match。 | <code>            if ok or (path_patterns and not (req.get("text_regex") or [])):</code> |
| L0282 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 match。 | <code>                matches.append(</code> |
| L0283 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 match。 | <code>                    POCMatch(</code> |
| L0284 | 计算并保存 &#96;rule_id&#96;（ruleid），供后续逻辑使用，当前位于函数 match。 | <code>                        rule_id=str(rule.get("id") or ""),</code> |
| L0285 | 计算并保存 &#96;name&#96;（name），供后续逻辑使用，当前位于函数 match。 | <code>                        name=str(rule.get("name") or ""),</code> |
| L0286 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 match。 | <code>                        attack_type=str(rule.get("attack_type") or "可疑流量"),</code> |
| L0287 | 计算并保存 &#96;severity&#96;（severity），供后续逻辑使用，当前位于函数 match。 | <code>                        severity=str(rule.get("severity") or "medium"),</code> |
| L0288 | 计算并保存 &#96;score&#96;（score），供后续逻辑使用，当前位于函数 match。 | <code>                        score=float(rule.get("score") or SEVERITY_SCORE.get(str(rule.get("severity") or "medium"), 0.65)),</code> |
| L0289 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 match。 | <code>                        evidence=evidence,</code> |
| L0290 | 计算并保存 &#96;tags&#96;（tags），供后续逻辑使用，当前位于函数 match。 | <code>                        tags=list(rule.get("tags") or []),</code> |
| L0291 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 match。 | <code>                    )</code> |
| L0292 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 match。 | <code>                )</code> |
| L0293 | 结束当前函数并把结果返回给调用方，当前位于函数 match。 | <code>        return matches</code> |
| L0294 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0295 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0296 | 定义类 &#96;PayloadModel&#96;，集中保存相关状态与操作。 | <code>class PayloadModel:</code> |
| L0297 | 定义init函数 &#96;__init__&#96;，封装可复用业务逻辑。 | <code>    def __init__(self, model_path: Path &#124; str = DEFAULT_MODEL_PATH):</code> |
| L0298 | 计算并保存 &#96;model_path&#96;（模型path），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.model_path = Path(model_path)</code> |
| L0299 | 计算并保存 &#96;bundle&#96;（bundle），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.bundle = joblib.load(self.model_path) if self.model_path.exists() else None</code> |
| L0300 | 计算并保存 &#96;model&#96;（模型），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.model = self.bundle.get("model") if isinstance(self.bundle, dict) else self.bundle</code> |
| L0301 | 计算并保存 &#96;labels&#96;（labels），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.labels = list(self.bundle.get("labels", [])) if isinstance(self.bundle, dict) else []</code> |
| L0302 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0303 | 应用装饰器 &#96;@property&#96;，为下一定义附加权限、缓存或注册行为。 | <code>    @property</code> |
| L0304 | 定义available函数 &#96;available&#96;，封装可复用业务逻辑。 | <code>    def available(self) -&gt; bool:</code> |
| L0305 | 结束当前函数并把结果返回给调用方，当前位于函数 available。 | <code>        return self.model is not None</code> |
| L0306 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0307 | 定义预测函数 &#96;predict&#96;，封装可复用业务逻辑。 | <code>    def predict(self, event: Dict[str, Any]) -&gt; Dict[str, Any]:</code> |
| L0308 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 predict。 | <code>        if not self.available:</code> |
| L0309 | 结束当前函数并把结果返回给调用方，当前位于函数 predict。 | <code>            return {"label": "unknown", "score": 0.0, "proba": {}}</code> |
| L0310 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 predict。 | <code>        text = payload_model_text(event)</code> |
| L0311 | 执行小模型推理并取得预测分数，当前位于函数 predict。 | <code>        label = str(self.model.predict([text])[0])</code> |
| L0312 | 计算并保存 &#96;proba&#96;（proba），供后续逻辑使用，当前位于函数 predict。 | <code>        proba: Dict[str, float] = {}</code> |
| L0313 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 predict。 | <code>        if hasattr(self.model, "predict_proba"):</code> |
| L0314 | 执行小模型推理并取得预测分数，当前位于函数 predict。 | <code>            values = self.model.predict_proba([text])[0]</code> |
| L0315 | 计算并保存 &#96;labels&#96;（labels），供后续逻辑使用，当前位于函数 predict。 | <code>            labels = list(getattr(self.model, "classes_", self.labels))</code> |
| L0316 | 计算并保存 &#96;proba&#96;（proba），供后续逻辑使用，当前位于函数 predict。 | <code>            proba = {str(k): float(v) for k, v in zip(labels, values)}</code> |
| L0317 | 计算并保存 &#96;score&#96;（score），供后续逻辑使用，当前位于函数 predict。 | <code>            score = float(max(proba.values())) if proba else 0.0</code> |
| L0318 | 处理前述条件均未命中的情况，当前位于函数 predict。 | <code>        else:</code> |
| L0319 | 计算并保存 &#96;score&#96;（score），供后续逻辑使用，当前位于函数 predict。 | <code>            score = 0.8 if label != "normal" else 0.1</code> |
| L0320 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 predict。 | <code>        attack_score = 0.0 if label == "normal" else score</code> |
| L0321 | 结束当前函数并把结果返回给调用方，当前位于函数 predict。 | <code>        return {"label": label, "score": attack_score, "confidence": score, "proba": proba}</code> |
| L0322 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0323 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0324 | 定义类 &#96;BehaviorWindowAnalyzer&#96;，集中保存相关状态与操作。 | <code>class BehaviorWindowAnalyzer:</code> |
| L0325 | 定义init函数 &#96;__init__&#96;，封装可复用业务逻辑。 | <code>    def __init__(self, window_minutes: int = 5, model_path: Path &#124; str = DEFAULT_BEHAVIOR_MODEL_PATH):</code> |
| L0326 | 计算并保存 &#96;window&#96;（window），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.window = timedelta(minutes=window_minutes)</code> |
| L0327 | 计算并保存 &#96;events_by_ip&#96;（事件byip），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.events_by_ip: Dict[str, deque] = defaultdict(deque)</code> |
| L0328 | 计算并保存 &#96;model_path&#96;（模型path），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.model_path = Path(model_path)</code> |
| L0329 | 计算并保存 &#96;model_bundle&#96;（模型bundle），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.model_bundle = None</code> |
| L0330 | 计算并保存 &#96;model&#96;（模型），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.model = None</code> |
| L0331 | 计算并保存 &#96;model_features&#96;（模型features），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.model_features = []</code> |
| L0332 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 __init__。 | <code>        if self.model_path.exists():</code> |
| L0333 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 __init__。 | <code>            try:</code> |
| L0334 | 计算并保存 &#96;model_bundle&#96;（模型bundle），供后续逻辑使用，当前位于函数 __init__。 | <code>                self.model_bundle = joblib.load(self.model_path)</code> |
| L0335 | 计算并保存 &#96;model&#96;（模型），供后续逻辑使用，当前位于函数 __init__。 | <code>                self.model = self.model_bundle.get("model") if isinstance(self.model_bundle, dict) else self.model_bundle</code> |
| L0336 | 计算并保存 &#96;model_features&#96;（模型features），供后续逻辑使用，当前位于函数 __init__。 | <code>                self.model_features = list(self.model_bundle.get("features", [])) if isinstance(self.model_bundle, dict) else []</code> |
| L0337 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 __init__。 | <code>            except Exception:</code> |
| L0338 | 计算并保存 &#96;model_bundle&#96;（模型bundle），供后续逻辑使用，当前位于函数 __init__。 | <code>                self.model_bundle = None</code> |
| L0339 | 计算并保存 &#96;model&#96;（模型），供后续逻辑使用，当前位于函数 __init__。 | <code>                self.model = None</code> |
| L0340 | 计算并保存 &#96;model_features&#96;（模型features），供后续逻辑使用，当前位于函数 __init__。 | <code>                self.model_features = []</code> |
| L0341 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0342 | 定义observe函数 &#96;observe&#96;，封装可复用业务逻辑。 | <code>    def observe(self, event: Dict[str, Any], payload_or_rule_hit: bool = False) -&gt; Dict[str, Any]:</code> |
| L0343 | 计算并保存 &#96;ip&#96;（ip），供后续逻辑使用，当前位于函数 observe。 | <code>        ip = str(event.get("source_ip") or "")</code> |
| L0344 | 计算并保存 &#96;t&#96;（t），供后续逻辑使用，当前位于函数 observe。 | <code>        t = parse_event_time(event.get("timestamp")) or datetime.now()</code> |
| L0345 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 observe。 | <code>        if not ip:</code> |
| L0346 | 结束当前函数并把结果返回给调用方，当前位于函数 observe。 | <code>            return {"score": 0.0, "type": "normal", "evidence": [], "features": {}}</code> |
| L0347 | 计算并保存 &#96;dq&#96;（dq），供后续逻辑使用，当前位于函数 observe。 | <code>        dq = self.events_by_ip[ip]</code> |
| L0348 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 observe。 | <code>        item = {</code> |
| L0349 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 observe。 | <code>            "time": t,</code> |
| L0350 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 observe。 | <code>            "uri": str(event.get("uri") or ""),</code> |
| L0351 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 observe。 | <code>            "path": urlsplit(str(event.get("uri") or "")).path,</code> |
| L0352 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 observe。 | <code>            "method": str(event.get("method") or "").upper(),</code> |
| L0353 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 observe。 | <code>            "status_code": int(event.get("status_code") or 0) if str(event.get("status_code") or "").isdigit() else 0,</code> |
| L0354 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 observe。 | <code>            "ua": str(event.get("user_agent") or ""),</code> |
| L0355 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 observe。 | <code>            "payload_or_rule_hit": bool(payload_or_rule_hit),</code> |
| L0356 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 observe。 | <code>            "body": str(event.get("body") or ""),</code> |
| L0357 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 observe。 | <code>        }</code> |
| L0358 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 observe。 | <code>        dq.append(item)</code> |
| L0359 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 observe。 | <code>        while dq and t - dq[0]["time"] &gt; self.window:</code> |
| L0360 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 observe。 | <code>            dq.popleft()</code> |
| L0361 | 结束当前函数并把结果返回给调用方，当前位于函数 observe。 | <code>        return self.score_window(ip)</code> |
| L0362 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0363 | 定义scorewindow函数 &#96;score_window&#96;，封装可复用业务逻辑。 | <code>    def score_window(self, ip: str) -&gt; Dict[str, Any]:</code> |
| L0364 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 score_window。 | <code>        items = list(self.events_by_ip.get(ip) or [])</code> |
| L0365 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 score_window。 | <code>        if not items:</code> |
| L0366 | 结束当前函数并把结果返回给调用方，当前位于函数 score_window。 | <code>            return {"score": 0.0, "type": "normal", "evidence": [], "features": {}}</code> |
| L0367 | 计算并保存 &#96;req_count&#96;（reqcount），供后续逻辑使用，当前位于函数 score_window。 | <code>        req_count = len(items)</code> |
| L0368 | 计算并保存 &#96;paths&#96;（paths），供后续逻辑使用，当前位于函数 score_window。 | <code>        paths = {x["path"] for x in items if x["path"]}</code> |
| L0369 | 计算并保存 &#96;statuses&#96;（statuses），供后续逻辑使用，当前位于函数 score_window。 | <code>        statuses = [x["status_code"] for x in items]</code> |
| L0370 | 计算并保存 &#96;login_items&#96;（登录数据项），供后续逻辑使用，当前位于函数 score_window。 | <code>        login_items = [x for x in items if re.search(r"(?i)(/login&#124;/auth&#124;/signin&#124;/session)", x["uri"])]</code> |
| L0371 | 计算并保存 &#96;login_fail&#96;（登录fail），供后续逻辑使用，当前位于函数 score_window。 | <code>        login_fail = sum(1 for x in login_items if x["status_code"] in {0, 401, 403, 429} or re.search(r"(?i)(wrong&#124;fail&#124;invalid&#124;error&#124;denied)", x["body"]))</code> |
| L0372 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>        not_found = sum(1 for x in items if x["status_code"] == 404)</code> |
| L0373 | 计算并保存 &#96;ua_count&#96;（uacount），供后续逻辑使用，当前位于函数 score_window。 | <code>        ua_count = len({x["ua"] for x in items if x["ua"]})</code> |
| L0374 | 计算并保存 &#96;payload_hits&#96;（payloadhits），供后续逻辑使用，当前位于函数 score_window。 | <code>        payload_hits = sum(1 for x in items if x["payload_or_rule_hit"])</code> |
| L0375 | 计算并保存 &#96;status_5xx&#96;（状态5xx），供后续逻辑使用，当前位于函数 score_window。 | <code>        status_5xx = sum(1 for x in items if 500 &lt;= int(x["status_code"] or 0) &lt;= 599)</code> |
| L0376 | 计算并保存 &#96;path_ratio&#96;（pathratio），供后续逻辑使用，当前位于函数 score_window。 | <code>        path_ratio = len(paths) / max(1, req_count)</code> |
| L0377 | 计算并保存 &#96;features&#96;（features），供后续逻辑使用，当前位于函数 score_window。 | <code>        features = {</code> |
| L0378 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>            "request_count": req_count,</code> |
| L0379 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>            "distinct_path_count": len(paths),</code> |
| L0380 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>            "login_request_count": len(login_items),</code> |
| L0381 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>            "login_fail_count": login_fail,</code> |
| L0382 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>            "not_found_count": not_found,</code> |
| L0383 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>            "user_agent_count": ua_count,</code> |
| L0384 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>            "payload_hit_count": payload_hits,</code> |
| L0385 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>            "status_5xx_count": status_5xx,</code> |
| L0386 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 score_window。 | <code>        }</code> |
| L0387 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 score_window。 | <code>        evidence: List[str] = []</code> |
| L0388 | 计算并保存 &#96;score&#96;（score），供后续逻辑使用，当前位于函数 score_window。 | <code>        score = 0.0</code> |
| L0389 | 计算并保存 &#96;typ&#96;（typ），供后续逻辑使用，当前位于函数 score_window。 | <code>        typ = "normal"</code> |
| L0390 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 score_window。 | <code>        if login_fail &gt;= 20:</code> |
| L0391 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>            score, typ = 0.95, "暴力破解"</code> |
| L0392 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 score_window。 | <code>            evidence.append(f"{self.window} 内登录失败 {login_fail} 次")</code> |
| L0393 | 当前一条件未命中时继续判断另一条件，当前位于函数 score_window。 | <code>        elif login_fail &gt;= 8:</code> |
| L0394 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>            score, typ = 0.82, "疑似暴力破解"</code> |
| L0395 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 score_window。 | <code>            evidence.append(f"{self.window} 内登录失败 {login_fail} 次")</code> |
| L0396 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 score_window。 | <code>        if len(paths) &gt;= 25 and req_count &gt;= 30 and (not_found &gt;= 5 or path_ratio &gt;= 0.60):</code> |
| L0397 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 score_window。 | <code>            if score &lt; 0.88:</code> |
| L0398 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>                score, typ = 0.88, "扫描探测"</code> |
| L0399 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 score_window。 | <code>            evidence.append(f"{self.window} 内访问 {len(paths)} 个不同路径/{req_count} 次请求")</code> |
| L0400 | 当前一条件未命中时继续判断另一条件，当前位于函数 score_window。 | <code>        elif len(paths) &gt;= 10 and req_count &gt;= 15 and (not_found &gt;= 4 or path_ratio &gt;= 0.70):</code> |
| L0401 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 score_window。 | <code>            if score &lt; 0.72:</code> |
| L0402 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>                score, typ = 0.72, "疑似扫描探测"</code> |
| L0403 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 score_window。 | <code>            evidence.append(f"{self.window} 内访问 {len(paths)} 个不同路径/{req_count} 次请求")</code> |
| L0404 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 score_window。 | <code>        if not_found &gt;= 10 and req_count &gt;= 15:</code> |
| L0405 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 score_window。 | <code>            if score &lt; 0.78:</code> |
| L0406 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>                score, typ = 0.78, "目录探测"</code> |
| L0407 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 score_window。 | <code>            evidence.append(f"{self.window} 内 404 响应 {not_found} 次")</code> |
| L0408 | 计算并保存 &#96;high_frequency_supported&#96;（highfrequencysupported），供后续逻辑使用，当前位于函数 score_window。 | <code>        high_frequency_supported = req_count &gt;= 600 or (</code> |
| L0409 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>            req_count &gt;= 200</code> |
| L0410 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>            and (status_5xx &gt;= 20 or login_fail &gt;= 8 or not_found &gt;= 20 or payload_hits &gt;= 5)</code> |
| L0411 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 score_window。 | <code>        )</code> |
| L0412 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 score_window。 | <code>        if high_frequency_supported:</code> |
| L0413 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>            score, typ = max(score, 0.9), "高频请求"</code> |
| L0414 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 score_window。 | <code>            evidence.append(f"{self.window} 内请求 {req_count} 次")</code> |
| L0415 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0416 | 计算并保存 &#96;model_supported&#96;（模型supported），供后续逻辑使用，当前位于函数 score_window。 | <code>        model_supported = self.behavior_model_supported(features)</code> |
| L0417 | 计算并保存 &#96;model_result&#96;（模型结果），供后续逻辑使用，当前位于函数 score_window。 | <code>        model_result = self.score_with_model(features) if model_supported else {"score": 0.0, "label": "not_enough_context", "type": "normal"}</code> |
| L0418 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 score_window。 | <code>        if model_supported and not self.behavior_prediction_supported(str(model_result.get("label") or ""), features):</code> |
| L0419 | 源码原注释：The statistical model was trained on attack-shaped windows. A | <code>            # The statistical model was trained on attack-shaped windows. A</code> |
| L0420 | 源码原注释：successful portal session can also touch many API/static paths, | <code>            # successful portal session can also touch many API/static paths,</code> |
| L0421 | 源码原注释：so require observable protocol evidence before accepting labels. | <code>            # so require observable protocol evidence before accepting labels.</code> |
| L0422 | 计算并保存 &#96;model_result&#96;（模型结果），供后续逻辑使用，当前位于函数 score_window。 | <code>            model_result = {"score": 0.0, "label": "normal", "type": "normal"}</code> |
| L0423 | 计算并保存 &#96;model_supported&#96;（模型supported），供后续逻辑使用，当前位于函数 score_window。 | <code>            model_supported = False</code> |
| L0424 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 score_window。 | <code>        if float(model_result.get("score") or 0.0) &gt; score:</code> |
| L0425 | 计算并保存 &#96;score&#96;（score），供后续逻辑使用，当前位于函数 score_window。 | <code>            score = float(model_result.get("score") or 0.0)</code> |
| L0426 | 计算并保存 &#96;typ&#96;（typ），供后续逻辑使用，当前位于函数 score_window。 | <code>            typ = str(model_result.get("type") or typ)</code> |
| L0427 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 score_window。 | <code>            evidence.append(f"行为模型判定 {typ}, score={score:.3f}")</code> |
| L0428 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>        features["behavior_model_label"] = model_result.get("label") or ""</code> |
| L0429 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>        features["behavior_model_score"] = model_result.get("score") or 0.0</code> |
| L0430 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_window。 | <code>        features["behavior_model_supported"] = model_supported</code> |
| L0431 | 结束当前函数并把结果返回给调用方，当前位于函数 score_window。 | <code>        return {"score": score, "type": typ, "evidence": evidence, "features": features}</code> |
| L0432 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0433 | 应用装饰器 &#96;@staticmethod&#96;，为下一定义附加权限、缓存或注册行为。 | <code>    @staticmethod</code> |
| L0434 | 定义behaviorpredictionsupported函数 &#96;behavior_prediction_supported&#96;，封装可复用业务逻辑。 | <code>    def behavior_prediction_supported(label: str, features: Dict[str, Any]) -&gt; bool:</code> |
| L0435 | 计算并保存 &#96;req_count&#96;（reqcount），供后续逻辑使用，当前位于函数 behavior_prediction_supported。 | <code>        req_count = int(features.get("request_count") or 0)</code> |
| L0436 | 计算并保存 &#96;distinct&#96;（distinct），供后续逻辑使用，当前位于函数 behavior_prediction_supported。 | <code>        distinct = int(features.get("distinct_path_count") or 0)</code> |
| L0437 | 计算并保存 &#96;login_fail&#96;（登录fail），供后续逻辑使用，当前位于函数 behavior_prediction_supported。 | <code>        login_fail = int(features.get("login_fail_count") or 0)</code> |
| L0438 | 计算并保存 &#96;not_found&#96;（notfound），供后续逻辑使用，当前位于函数 behavior_prediction_supported。 | <code>        not_found = int(features.get("not_found_count") or 0)</code> |
| L0439 | 计算并保存 &#96;payload_hits&#96;（payloadhits），供后续逻辑使用，当前位于函数 behavior_prediction_supported。 | <code>        payload_hits = int(features.get("payload_hit_count") or 0)</code> |
| L0440 | 计算并保存 &#96;status_5xx&#96;（状态5xx），供后续逻辑使用，当前位于函数 behavior_prediction_supported。 | <code>        status_5xx = int(features.get("status_5xx_count") or 0)</code> |
| L0441 | 计算并保存 &#96;path_ratio&#96;（pathratio），供后续逻辑使用，当前位于函数 behavior_prediction_supported。 | <code>        path_ratio = distinct / max(1, req_count)</code> |
| L0442 | 计算并保存 &#96;payload_ratio&#96;（payloadratio），供后续逻辑使用，当前位于函数 behavior_prediction_supported。 | <code>        payload_ratio = payload_hits / max(1, req_count)</code> |
| L0443 | 计算并保存 &#96;normalized&#96;（normalized），供后续逻辑使用，当前位于函数 behavior_prediction_supported。 | <code>        normalized = str(label or "").strip().lower()</code> |
| L0444 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 behavior_prediction_supported。 | <code>        if normalized == "bruteforce":</code> |
| L0445 | 结束当前函数并把结果返回给调用方，当前位于函数 behavior_prediction_supported。 | <code>            return login_fail &gt;= 8</code> |
| L0446 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 behavior_prediction_supported。 | <code>        if normalized == "dir_probe":</code> |
| L0447 | 结束当前函数并把结果返回给调用方，当前位于函数 behavior_prediction_supported。 | <code>            return req_count &gt;= 15 and not_found &gt;= 6</code> |
| L0448 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 behavior_prediction_supported。 | <code>        if normalized == "scan":</code> |
| L0449 | 结束当前函数并把结果返回给调用方，当前位于函数 behavior_prediction_supported。 | <code>            return req_count &gt;= 30 and distinct &gt;= 20 and (not_found &gt;= 5 or path_ratio &gt;= 0.60)</code> |
| L0450 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 behavior_prediction_supported。 | <code>        if normalized == "payload_burst":</code> |
| L0451 | 结束当前函数并把结果返回给调用方，当前位于函数 behavior_prediction_supported。 | <code>            return payload_hits &gt;= 5 and payload_ratio &gt;= 0.20</code> |
| L0452 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 behavior_prediction_supported。 | <code>        if normalized == "high_frequency":</code> |
| L0453 | 结束当前函数并把结果返回给调用方，当前位于函数 behavior_prediction_supported。 | <code>            return req_count &gt;= 600 or (</code> |
| L0454 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 behavior_prediction_supported。 | <code>                req_count &gt;= 200</code> |
| L0455 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 behavior_prediction_supported。 | <code>                and (status_5xx &gt;= 20 or login_fail &gt;= 8 or not_found &gt;= 20 or payload_hits &gt;= 5)</code> |
| L0456 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 behavior_prediction_supported。 | <code>            )</code> |
| L0457 | 结束当前函数并把结果返回给调用方，当前位于函数 behavior_prediction_supported。 | <code>        return normalized in {"", "normal", "not_enough_context", "unavailable"}</code> |
| L0458 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0459 | 定义behavior模型supported函数 &#96;behavior_model_supported&#96;，封装可复用业务逻辑。 | <code>    def behavior_model_supported(self, features: Dict[str, Any]) -&gt; bool:</code> |
| L0460 | 计算并保存 &#96;req_count&#96;（reqcount），供后续逻辑使用，当前位于函数 behavior_model_supported。 | <code>        req_count = int(features.get("request_count") or 0)</code> |
| L0461 | 计算并保存 &#96;distinct_path_count&#96;（distinctpathcount），供后续逻辑使用，当前位于函数 behavior_model_supported。 | <code>        distinct_path_count = int(features.get("distinct_path_count") or 0)</code> |
| L0462 | 计算并保存 &#96;login_fail_count&#96;（登录failcount），供后续逻辑使用，当前位于函数 behavior_model_supported。 | <code>        login_fail_count = int(features.get("login_fail_count") or 0)</code> |
| L0463 | 计算并保存 &#96;not_found_count&#96;（notfoundcount），供后续逻辑使用，当前位于函数 behavior_model_supported。 | <code>        not_found_count = int(features.get("not_found_count") or 0)</code> |
| L0464 | 计算并保存 &#96;payload_hit_count&#96;（payloadhitcount），供后续逻辑使用，当前位于函数 behavior_model_supported。 | <code>        payload_hit_count = int(features.get("payload_hit_count") or 0)</code> |
| L0465 | 计算并保存 &#96;status_5xx_count&#96;（状态5xxcount），供后续逻辑使用，当前位于函数 behavior_model_supported。 | <code>        status_5xx_count = int(features.get("status_5xx_count") or 0)</code> |
| L0466 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 behavior_model_supported。 | <code>        if req_count &lt; 12:</code> |
| L0467 | 结束当前函数并把结果返回给调用方，当前位于函数 behavior_model_supported。 | <code>            return False</code> |
| L0468 | 结束当前函数并把结果返回给调用方，当前位于函数 behavior_model_supported。 | <code>        return (</code> |
| L0469 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 behavior_model_supported。 | <code>            login_fail_count &gt;= 4</code> |
| L0470 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 behavior_model_supported。 | <code>            or distinct_path_count &gt;= 8</code> |
| L0471 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 behavior_model_supported。 | <code>            or not_found_count &gt;= 6</code> |
| L0472 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 behavior_model_supported。 | <code>            or payload_hit_count &gt;= 3</code> |
| L0473 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 behavior_model_supported。 | <code>            or status_5xx_count &gt;= 5</code> |
| L0474 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 behavior_model_supported。 | <code>            or req_count &gt;= 60</code> |
| L0475 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 behavior_model_supported。 | <code>        )</code> |
| L0476 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0477 | 定义scorewith模型函数 &#96;score_with_model&#96;，封装可复用业务逻辑。 | <code>    def score_with_model(self, features: Dict[str, Any]) -&gt; Dict[str, Any]:</code> |
| L0478 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 score_with_model。 | <code>        if self.model is None or not self.model_features:</code> |
| L0479 | 结束当前函数并把结果返回给调用方，当前位于函数 score_with_model。 | <code>            return {"score": 0.0, "label": "unavailable", "type": "normal"}</code> |
| L0480 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 score_with_model。 | <code>        vector = [[float(features.get(k) or 0.0) for k in self.model_features]]</code> |
| L0481 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 score_with_model。 | <code>        try:</code> |
| L0482 | 执行小模型推理并取得预测分数，当前位于函数 score_with_model。 | <code>            label = str(self.model.predict(vector)[0])</code> |
| L0483 | 计算并保存 &#96;proba&#96;（proba），供后续逻辑使用，当前位于函数 score_with_model。 | <code>            proba = {}</code> |
| L0484 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 score_with_model。 | <code>            if hasattr(self.model, "predict_proba"):</code> |
| L0485 | 执行小模型推理并取得预测分数，当前位于函数 score_with_model。 | <code>                values = self.model.predict_proba(vector)[0]</code> |
| L0486 | 计算并保存 &#96;labels&#96;（labels），供后续逻辑使用，当前位于函数 score_with_model。 | <code>                labels = list(getattr(self.model, "classes_", []))</code> |
| L0487 | 计算并保存 &#96;proba&#96;（proba），供后续逻辑使用，当前位于函数 score_with_model。 | <code>                proba = {str(k): float(v) for k, v in zip(labels, values)}</code> |
| L0488 | 计算并保存 &#96;normal_score&#96;（normalscore），供后续逻辑使用，当前位于函数 score_with_model。 | <code>                normal_score = float(proba.get("normal", 0.0))</code> |
| L0489 | 计算并保存 &#96;score&#96;（score），供后续逻辑使用，当前位于函数 score_with_model。 | <code>                score = max(0.0, 1.0 - normal_score)</code> |
| L0490 | 处理前述条件均未命中的情况，当前位于函数 score_with_model。 | <code>            else:</code> |
| L0491 | 计算并保存 &#96;score&#96;（score），供后续逻辑使用，当前位于函数 score_with_model。 | <code>                score = 0.75 if label != "normal" else 0.0</code> |
| L0492 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 score_with_model。 | <code>        except Exception:</code> |
| L0493 | 结束当前函数并把结果返回给调用方，当前位于函数 score_with_model。 | <code>            return {"score": 0.0, "label": "error", "type": "normal"}</code> |
| L0494 | 计算并保存 &#96;type_map&#96;（typemap），供后续逻辑使用，当前位于函数 score_with_model。 | <code>        type_map = {</code> |
| L0495 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_with_model。 | <code>            "bruteforce": "暴力破解",</code> |
| L0496 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_with_model。 | <code>            "scan": "扫描探测",</code> |
| L0497 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_with_model。 | <code>            "high_frequency": "高频请求",</code> |
| L0498 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_with_model。 | <code>            "dir_probe": "目录探测",</code> |
| L0499 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_with_model。 | <code>            "payload_burst": "Payload异常突增",</code> |
| L0500 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 score_with_model。 | <code>            "normal": "normal",</code> |
| L0501 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 score_with_model。 | <code>        }</code> |
| L0502 | 结束当前函数并把结果返回给调用方，当前位于函数 score_with_model。 | <code>        return {"score": score if label != "normal" else 0.0, "label": label, "type": type_map.get(label, label)}</code> |
| L0503 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0504 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0505 | 定义severityfromscore函数 &#96;severity_from_score&#96;，封装可复用业务逻辑。 | <code>def severity_from_score(score: float) -&gt; str:</code> |
| L0506 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 severity_from_score。 | <code>    if score &gt;= 0.9:</code> |
| L0507 | 结束当前函数并把结果返回给调用方，当前位于函数 severity_from_score。 | <code>        return "critical"</code> |
| L0508 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 severity_from_score。 | <code>    if score &gt;= 0.75:</code> |
| L0509 | 结束当前函数并把结果返回给调用方，当前位于函数 severity_from_score。 | <code>        return "high"</code> |
| L0510 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 severity_from_score。 | <code>    if score &gt;= 0.55:</code> |
| L0511 | 结束当前函数并把结果返回给调用方，当前位于函数 severity_from_score。 | <code>        return "medium"</code> |
| L0512 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 severity_from_score。 | <code>    if score &gt;= 0.3:</code> |
| L0513 | 结束当前函数并把结果返回给调用方，当前位于函数 severity_from_score。 | <code>        return "low"</code> |
| L0514 | 结束当前函数并把结果返回给调用方，当前位于函数 severity_from_score。 | <code>    return "info"</code> |
| L0515 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0516 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0517 | 定义fusedetection函数 &#96;fuse_detection&#96;，封装可复用业务逻辑。 | <code>def fuse_detection(</code> |
| L0518 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>    event: Dict[str, Any],</code> |
| L0519 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>    payload_pred: Dict[str, Any],</code> |
| L0520 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>    poc_matches: List[POCMatch],</code> |
| L0521 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>    behavior: Dict[str, Any],</code> |
| L0522 | 计算并保存 &#96;candidate_threshold&#96;（candidatethreshold），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>    candidate_threshold: float = 0.65,</code> |
| L0523 | 计算并保存 &#96;event_threshold&#96;（事件threshold），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>    event_threshold: float = 0.75,</code> |
| L0524 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fuse_detection。 | <code>) -&gt; Dict[str, Any]:</code> |
| L0525 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 fuse_detection。 | <code>    if is_simple_page_view(event) and not poc_matches:</code> |
| L0526 | 结束当前函数并把结果返回给调用方，当前位于函数 fuse_detection。 | <code>        return {</code> |
| L0527 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>            "decision": "raw_only",</code> |
| L0528 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>            "final_score": 0.0,</code> |
| L0529 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>            "attack_type": "正常访问",</code> |
| L0530 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>            "risk_level": "info",</code> |
| L0531 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>            "reason": "普通页面访问，无 query/body/POC 命中",</code> |
| L0532 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>            "candidate": False,</code> |
| L0533 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>            "attack_event": False,</code> |
| L0534 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>            "evidence": [],</code> |
| L0535 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fuse_detection。 | <code>        }</code> |
| L0536 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0537 | 计算并保存 &#96;payload_label&#96;（payloadlabel），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>    payload_label = str(payload_pred.get("label") or "unknown")</code> |
| L0538 | 计算并保存 &#96;payload_score&#96;（payloadscore），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>    payload_score = float(payload_pred.get("score") or 0.0)</code> |
| L0539 | 计算并保存 &#96;poc_score&#96;（pocscore），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>    poc_score = max([m.score for m in poc_matches], default=0.0)</code> |
| L0540 | 计算并保存 &#96;behavior_score&#96;（behaviorscore），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>    behavior_score = float(behavior.get("score") or 0.0)</code> |
| L0541 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>    ctx_score, ctx_reason = context_score(event)</code> |
| L0542 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0543 | 计算并保存 &#96;successful_auth&#96;（successfulauth），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>    successful_auth = is_successful_authentication(event)</code> |
| L0544 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 fuse_detection。 | <code>    if successful_auth and not poc_matches and payload_score &lt; 0.90:</code> |
| L0545 | 计算并保存 &#96;payload_label&#96;（payloadlabel），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>        payload_label = "normal"</code> |
| L0546 | 计算并保存 &#96;payload_score&#96;（payloadscore），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>        payload_score = 0.0</code> |
| L0547 | 计算并保存 &#96;behavior_score&#96;（behaviorscore），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>        behavior_score = 0.0</code> |
| L0548 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0549 | 计算并保存 &#96;final_score&#96;（finalscore），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>    final_score = payload_score * 0.45 + behavior_score * 0.30 + poc_score * 0.20 + ctx_score * 0.05</code> |
| L0550 | 计算并保存 &#96;strong_poc&#96;（strongpoc），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>    strong_poc = any(m.severity in {"high", "critical"} for m in poc_matches)</code> |
| L0551 | 源码原注释：The bundled lab emits safe reconnaissance simulations instead of running a | <code>    # The bundled lab emits safe reconnaissance simulations instead of running a</code> |
| L0552 | 源码原注释：real scanner. Promote only these explicitly tagged rules so their recon | <code>    # real scanner. Promote only these explicitly tagged rules so their recon</code> |
| L0553 | 源码原注释：stages reach the situation chain without weakening ordinary medium rules. | <code>    # stages reach the situation chain without weakening ordinary medium rules.</code> |
| L0554 | 计算并保存 &#96;simulation_recon_poc&#96;（simulationreconpoc），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>    simulation_recon_poc = any(</code> |
| L0555 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        m.attack_type in {"端口扫描", "目录扫描"}</code> |
| L0556 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        and m.score &gt;= 0.75</code> |
| L0557 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        and "simulation" in {str(tag).strip().lower() for tag in m.tags}</code> |
| L0558 | 遍历集合中的数据项并逐项处理，当前位于函数 fuse_detection。 | <code>        for m in poc_matches</code> |
| L0559 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fuse_detection。 | <code>    )</code> |
| L0560 | 计算并保存 &#96;behavior_features&#96;（behaviorfeatures），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>    behavior_features = behavior.get("features") or {}</code> |
| L0561 | 计算并保存 &#96;behavior_supported&#96;（behaviorsupported），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>    behavior_supported = bool(behavior_features.get("behavior_model_supported", True))</code> |
| L0562 | 计算并保存 &#96;strong_behavior&#96;（strongbehavior），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>    strong_behavior = behavior_score &gt;= 0.82 and behavior_supported</code> |
| L0563 | 计算并保存 &#96;high_payload&#96;（highpayload），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>    high_payload = payload_score &gt;= 0.90 and payload_label != "normal"</code> |
| L0564 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0565 | 计算并保存 &#96;candidate&#96;（candidate），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>    candidate = final_score &gt;= candidate_threshold or strong_poc or simulation_recon_poc or strong_behavior or high_payload</code> |
| L0566 | 计算并保存 &#96;attack_event&#96;（攻击事件），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>    attack_event = (</code> |
| L0567 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        final_score &gt;= event_threshold</code> |
| L0568 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        or strong_poc</code> |
| L0569 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        or simulation_recon_poc</code> |
| L0570 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        or strong_behavior</code> |
| L0571 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        or payload_score &gt;= 0.94</code> |
| L0572 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        or (payload_score &gt;= 0.80 and poc_score &gt;= 0.65)</code> |
| L0573 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fuse_detection。 | <code>    )</code> |
| L0574 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0575 | 计算并保存 &#96;strong_poc_matches&#96;（strongpocmatches），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>    strong_poc_matches = [m for m in poc_matches if m.severity in {"high", "critical"}]</code> |
| L0576 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 fuse_detection。 | <code>    if strong_poc_matches:</code> |
| L0577 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>        attack_type = sorted(</code> |
| L0578 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>            strong_poc_matches,</code> |
| L0579 | 计算并保存 &#96;key&#96;（key），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>            key=lambda m: (SEVERITY_SCORE.get(m.severity, 0), ATTACK_TYPE_PRIORITY.get(m.attack_type, 0), m.score),</code> |
| L0580 | 计算并保存 &#96;reverse&#96;（reverse），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>            reverse=True,</code> |
| L0581 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fuse_detection。 | <code>        )[0].attack_type</code> |
| L0582 | 当前一条件未命中时继续判断另一条件，当前位于函数 fuse_detection。 | <code>    elif payload_label and payload_label not in {"normal", "unknown"}:</code> |
| L0583 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>        attack_type = payload_label</code> |
| L0584 | 当前一条件未命中时继续判断另一条件，当前位于函数 fuse_detection。 | <code>    elif behavior_score &gt;= 0.82:</code> |
| L0585 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>        attack_type = str(behavior.get("type") or "行为异常")</code> |
| L0586 | 当前一条件未命中时继续判断另一条件，当前位于函数 fuse_detection。 | <code>    elif poc_matches:</code> |
| L0587 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>        attack_type = sorted(poc_matches, key=lambda m: (ATTACK_TYPE_PRIORITY.get(m.attack_type, 0), m.score), reverse=True)[0].attack_type</code> |
| L0588 | 处理前述条件均未命中的情况，当前位于函数 fuse_detection。 | <code>    else:</code> |
| L0589 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>        attack_type = "可疑流量"</code> |
| L0590 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0591 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>    evidence = []</code> |
| L0592 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 fuse_detection。 | <code>    evidence.extend([f"POC {m.rule_id}: {m.name}" for m in poc_matches[:5]])</code> |
| L0593 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 fuse_detection。 | <code>    evidence.extend(list(behavior.get("evidence") or []))</code> |
| L0594 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 fuse_detection。 | <code>    if payload_label not in {"normal", "unknown"}:</code> |
| L0595 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 fuse_detection。 | <code>        evidence.append(f"Payload模型判定 {payload_label}, score={payload_score:.3f}")</code> |
| L0596 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 fuse_detection。 | <code>    if ctx_score &gt;= 0.75:</code> |
| L0597 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 fuse_detection。 | <code>        evidence.append(f"上下文：{ctx_reason}")</code> |
| L0598 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0599 | 计算并保存 &#96;decision&#96;（decision），供后续逻辑使用，当前位于函数 fuse_detection。 | <code>    decision = "attack_event" if attack_event else ("candidate" if candidate else "raw_only")</code> |
| L0600 | 结束当前函数并把结果返回给调用方，当前位于函数 fuse_detection。 | <code>    return {</code> |
| L0601 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        "decision": decision,</code> |
| L0602 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        "final_score": round(float(final_score), 6),</code> |
| L0603 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        "attack_type": attack_type,</code> |
| L0604 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        "risk_level": severity_from_score(max(final_score, poc_score, behavior_score, payload_score if payload_label != "normal" else 0.0)),</code> |
| L0605 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        "reason": "融合评分/规则/行为检测结果",</code> |
| L0606 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        "candidate": candidate,</code> |
| L0607 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        "attack_event": attack_event,</code> |
| L0608 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        "payload_score": round(payload_score, 6),</code> |
| L0609 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        "payload_label": payload_label,</code> |
| L0610 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        "behavior_score": round(behavior_score, 6),</code> |
| L0611 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        "behavior_type": behavior.get("type"),</code> |
| L0612 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        "poc_score": round(poc_score, 6),</code> |
| L0613 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        "context_score": round(ctx_score, 6),</code> |
| L0614 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        "context_reason": ctx_reason,</code> |
| L0615 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        "successful_authentication": successful_auth,</code> |
| L0616 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        "simulation_recon_poc": simulation_recon_poc,</code> |
| L0617 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        "poc_matches": [m.__dict__ for m in poc_matches],</code> |
| L0618 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        "behavior_features": behavior.get("features") or {},</code> |
| L0619 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fuse_detection。 | <code>        "evidence": evidence,</code> |
| L0620 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fuse_detection。 | <code>    }</code> |
| L0621 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0622 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0623 | 定义类 &#96;DetectionEngineV2&#96;，集中保存相关状态与操作。 | <code>class DetectionEngineV2:</code> |
| L0624 | 定义init函数 &#96;__init__&#96;，封装可复用业务逻辑。 | <code>    def __init__(</code> |
| L0625 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>        self,</code> |
| L0626 | 计算并保存 &#96;model_path&#96;（模型path），供后续逻辑使用，当前位于函数 __init__。 | <code>        model_path: Path &#124; str = DEFAULT_MODEL_PATH,</code> |
| L0627 | 计算并保存 &#96;rules_path&#96;（rulespath），供后续逻辑使用，当前位于函数 __init__。 | <code>        rules_path: Path &#124; str = DEFAULT_RULES_PATH,</code> |
| L0628 | 计算并保存 &#96;behavior_model_path&#96;（behavior模型path），供后续逻辑使用，当前位于函数 __init__。 | <code>        behavior_model_path: Path &#124; str = DEFAULT_BEHAVIOR_MODEL_PATH,</code> |
| L0629 | 计算并保存 &#96;behavior_window_minutes&#96;（behaviorwindowminutes），供后续逻辑使用，当前位于函数 __init__。 | <code>        behavior_window_minutes: int = 5,</code> |
| L0630 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 __init__。 | <code>    ):</code> |
| L0631 | 计算并保存 &#96;payload_model&#96;（payload模型），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.payload_model = PayloadModel(model_path)</code> |
| L0632 | 计算并保存 &#96;poc_engine&#96;（pocengine），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.poc_engine = POCRuleEngine(rules_path)</code> |
| L0633 | 计算并保存 &#96;behavior&#96;（behavior），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.behavior = BehaviorWindowAnalyzer(behavior_window_minutes, behavior_model_path)</code> |
| L0634 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0635 | 定义检测函数 &#96;detect&#96;，封装可复用业务逻辑。 | <code>    def detect(self, record: Dict[str, Any]) -&gt; Dict[str, Any]:</code> |
| L0636 | 计算并保存 &#96;event&#96;（事件），供后续逻辑使用，当前位于函数 detect。 | <code>        event = extract_request_from_record(record)</code> |
| L0637 | 计算并保存 &#96;poc_matches&#96;（pocmatches），供后续逻辑使用，当前位于函数 detect。 | <code>        poc_matches = self.poc_engine.match(event)</code> |
| L0638 | 执行小模型推理并取得预测分数，当前位于函数 detect。 | <code>        payload_pred = self.payload_model.predict(event)</code> |
| L0639 | 计算并保存 &#96;behavior&#96;（behavior），供后续逻辑使用，当前位于函数 detect。 | <code>        behavior = self.behavior.observe(event, payload_or_rule_hit=bool(poc_matches) or payload_pred.get("label") not in {"normal", "unknown"})</code> |
| L0640 | 计算并保存 &#96;fused&#96;（fused），供后续逻辑使用，当前位于函数 detect。 | <code>        fused = fuse_detection(event, payload_pred, poc_matches, behavior)</code> |
| L0641 | 结束当前函数并把结果返回给调用方，当前位于函数 detect。 | <code>        return {"event": event, "payload": payload_pred, "poc_matches": [m.__dict__ for m in poc_matches], "behavior": behavior, "fusion": fused}</code> |
| L0642 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0643 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0644 | 定义iterjsonl函数 &#96;iter_jsonl&#96;，封装可复用业务逻辑。 | <code>def iter_jsonl(path: Path) -&gt; Iterable[Dict[str, Any]]:</code> |
| L0645 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 iter_jsonl。 | <code>    with path.open("r", encoding="utf-8-sig") as f:</code> |
| L0646 | 遍历集合中的数据项并逐项处理，当前位于函数 iter_jsonl。 | <code>        for line in f:</code> |
| L0647 | 计算并保存 &#96;line&#96;（line），供后续逻辑使用，当前位于函数 iter_jsonl。 | <code>            line = line.strip()</code> |
| L0648 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 iter_jsonl。 | <code>            if line:</code> |
| L0649 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 iter_jsonl。 | <code>                yield json.loads(line)</code> |
| L0650 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
