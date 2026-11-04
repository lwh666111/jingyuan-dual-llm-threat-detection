# `scripts/seed_lab_review_cache.py` 逐行注释

**脚本用途：** 辅助脚本：根据文件名 `seed_lab_review_cache.py` 完成对应的数据处理或运维任务。

**源码行数：** 457　**函数/类数量：** 8

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>"""Seed exact-fingerprint review cache for every fixed attack preset of the 4000 lab.</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>The 4000 demo lab exposes a fixed set of clickable presets. For deterministic</code> |
| L0004 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>competition-demo latency, each attack preset gets an auditable, category-specific</code> |
| L0005 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>precomputed security analysis. Normal control presets are never seeded as attacks.</code> |
| L0006 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0007 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>Provenance: rows written by this script use model_name</code> |
| L0008 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>&#96;&#96;precomputed-security-analysis-v1&#96;&#96; so they remain distinguishable from genuine</code> |
| L0009 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>realtime Ollama reviews in the database audit trail. Existing cache rows produced</code> |
| L0010 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>by real reviews are never overwritten.</code> |
| L0011 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>"""</code> |
| L0012 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0013 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0014 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0015 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0016 | 导入后续逻辑所需的模块、类或函数：&#96;import sys&#96;。 | <code>import sys</code> |
| L0017 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0018 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, List&#96;。 | <code>from typing import Any, Dict, List</code> |
| L0019 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0020 | 计算并保存 &#96;SCRIPT_DIR&#96;（SCRIPTDIR），供后续逻辑使用。 | <code>SCRIPT_DIR = Path(__file__).resolve().parent</code> |
| L0021 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if str(SCRIPT_DIR) not in sys.path:</code> |
| L0022 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    sys.path.insert(0, str(SCRIPT_DIR))</code> |
| L0023 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0024 | 导入后续逻辑所需的模块、类或函数：&#96;from raw_llm_review import ensure_review_schema, request_fingerprint  # noqa: E402&#96;。 | <code>from raw_llm_review import ensure_review_schema, request_fingerprint  # noqa: E402</code> |
| L0025 | 导入后续逻辑所需的模块、类或函数：&#96;from target_multivuln_lab import FULL_CHAIN_SCENARIO, LAB_PAGES  # noqa: E402&#96;。 | <code>from target_multivuln_lab import FULL_CHAIN_SCENARIO, LAB_PAGES  # noqa: E402</code> |
| L0026 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0027 | 计算并保存 &#96;PRECOMPUTED_MODEL&#96;（PRECOMPUTED模型），供后续逻辑使用。 | <code>PRECOMPUTED_MODEL = "precomputed-security-analysis-v1"</code> |
| L0028 | 计算并保存 &#96;TARGET_PORT&#96;（TARGETPORT），供后续逻辑使用。 | <code>TARGET_PORT = 4000</code> |
| L0029 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0030 | 源码原注释：Explicit benign controls. Everything else in LAB_PAGES presets is an attack. | <code># Explicit benign controls. Everything else in LAB_PAGES presets is an attack.</code> |
| L0031 | 计算并保存 &#96;NORMAL_CONTROLS&#96;（NORMALCONTROLS），供后续逻辑使用。 | <code>NORMAL_CONTROLS = frozenset(</code> |
| L0032 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    {</code> |
| L0033 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        ("upload", "正常图片"),</code> |
| L0034 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        ("traversal", "正常文件"),</code> |
| L0035 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        ("ssrf", "正常外站"),</code> |
| L0036 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        ("xxe", "正常 XML"),</code> |
| L0037 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        ("ssti", "正常模板"),</code> |
| L0038 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        ("deserialize", "正常 JSON"),</code> |
| L0039 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        ("graphql", "正常查询"),</code> |
| L0040 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        ("bruteforce", "正常登录"),</code> |
| L0041 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        ("nday-fastjson", "正常 JSON"),</code> |
| L0042 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        ("nday-log4j", "普通搜索词"),</code> |
| L0043 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        ("nday-spring", "普通表单绑定"),</code> |
| L0044 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        ("nday-shiro", "普通会话检查"),</code> |
| L0045 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    }</code> |
| L0046 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>)</code> |
| L0047 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0048 | 计算并保存 &#96;EXPECTED_MODULES&#96;（EXPECTEDMODULES），供后续逻辑使用。 | <code>EXPECTED_MODULES = 18</code> |
| L0049 | 计算并保存 &#96;EXPECTED_PRESETS&#96;（EXPECTEDPRESETS），供后续逻辑使用。 | <code>EXPECTED_PRESETS = 48</code> |
| L0050 | 计算并保存 &#96;EXPECTED_ATTACK_PRESETS&#96;（EXPECTED攻击PRESETS），供后续逻辑使用。 | <code>EXPECTED_ATTACK_PRESETS = 36</code> |
| L0051 | 源码原注释：36 module presets (pretty JSON bodies) + 5 full-chain variants whose compact | <code># 36 module presets (pretty JSON bodies) + 5 full-chain variants whose compact</code> |
| L0052 | 源码原注释：JSON bodies or different fields produce distinct wire fingerprints. | <code># JSON bodies or different fields produce distinct wire fingerprints.</code> |
| L0053 | 计算并保存 &#96;EXPECTED_UNIQUE_FINGERPRINTS&#96;（EXPECTEDUNIQUEFINGERPRINTS），供后续逻辑使用。 | <code>EXPECTED_UNIQUE_FINGERPRINTS = 41</code> |
| L0054 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0055 | 计算并保存 &#96;FAMILY_INFO&#96;（FAMILYINFO），供后续逻辑使用。 | <code>FAMILY_INFO: Dict[str, Dict[str, Any]] = {</code> |
| L0056 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "sql": {</code> |
| L0057 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_method": "SQL注入",</code> |
| L0058 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "severity": "critical",</code> |
| L0059 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "confidence": 0.97,</code> |
| L0060 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "feature": "SQL 语法拼接与永真条件/联合查询/延时函数",</code> |
| L0061 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "impact": "攻击者可绕过认证、拖取或篡改数据库内容，造成敏感数据泄露。",</code> |
| L0062 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "hardening": "数据库访问统一使用参数化查询或预编译语句",</code> |
| L0063 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0064 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "xss": {</code> |
| L0065 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_method": "XSS",</code> |
| L0066 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "severity": "high",</code> |
| L0067 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "confidence": 0.95,</code> |
| L0068 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "feature": "可执行脚本标签或事件处理器注入",</code> |
| L0069 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "impact": "脚本在受害者浏览器上下文执行，可窃取会话凭证或伪造操作。",</code> |
| L0070 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "hardening": "按 HTML/属性/JavaScript 上下文执行输出编码",</code> |
| L0071 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0072 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "upload": {</code> |
| L0073 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_method": "恶意文件上传",</code> |
| L0074 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "severity": "critical",</code> |
| L0075 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "confidence": 0.98,</code> |
| L0076 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "feature": "可执行脚本后缀与 WebShell 代码内容",</code> |
| L0077 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "impact": "WebShell 落地后攻击者可持久控制服务器并横向移动。",</code> |
| L0078 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "hardening": "上传目录禁止脚本执行并实施文件类型白名单与内容检测",</code> |
| L0079 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0080 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "command": {</code> |
| L0081 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_method": "命令注入",</code> |
| L0082 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "severity": "critical",</code> |
| L0083 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "confidence": 0.97,</code> |
| L0084 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "feature": "Shell 分隔符拼接系统命令",</code> |
| L0085 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "impact": "攻击者可在服务器上执行任意系统命令，直接控制主机。",</code> |
| L0086 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "hardening": "禁止拼接 Shell 命令，使用参数化 API 并限制进程权限",</code> |
| L0087 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0088 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "traversal": {</code> |
| L0089 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_method": "路径遍历",</code> |
| L0090 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "severity": "high",</code> |
| L0091 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "confidence": 0.94,</code> |
| L0092 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "feature": "目录回退序列读取敏感文件",</code> |
| L0093 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "impact": "可读取系统账户、配置与密钥文件，为后续渗透提供凭据。",</code> |
| L0094 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "hardening": "对文件路径做规范化校验并限制在允许目录内",</code> |
| L0095 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0096 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "ssrf": {</code> |
| L0097 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_method": "SSRF",</code> |
| L0098 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "severity": "high",</code> |
| L0099 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "confidence": 0.93,</code> |
| L0100 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "feature": "服务端请求内网地址或云元数据接口",</code> |
| L0101 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "impact": "可探测内网服务、读取云实例临时凭证，扩大攻击面。",</code> |
| L0102 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "hardening": "对外联地址做协议与目标白名单校验并隔离元数据端点",</code> |
| L0103 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0104 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "xxe": {</code> |
| L0105 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_method": "XXE",</code> |
| L0106 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "severity": "high",</code> |
| L0107 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "confidence": 0.93,</code> |
| L0108 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "feature": "XML 外部实体声明引用本地文件或远程 DTD",</code> |
| L0109 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "impact": "可读取服务器本地文件或发起内网请求，泄露敏感信息。",</code> |
| L0110 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "hardening": "禁用 XML 外部实体与 DTD 解析并升级解析库",</code> |
| L0111 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0112 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "ssti": {</code> |
| L0113 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_method": "模板注入",</code> |
| L0114 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "severity": "high",</code> |
| L0115 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "confidence": 0.94,</code> |
| L0116 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "feature": "模板引擎表达式枚举对象与全局命名空间",</code> |
| L0117 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "impact": "模板沙箱逃逸后可在服务端执行代码，危及应用与数据。",</code> |
| L0118 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "hardening": "禁止渲染用户可控模板并使用逻辑-less 模板引擎",</code> |
| L0119 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0120 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "deserialize": {</code> |
| L0121 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_method": "反序列化攻击",</code> |
| L0122 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "severity": "critical",</code> |
| L0123 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "confidence": 0.95,</code> |
| L0124 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "feature": "序列化对象标记与可疑 gadget 结构",</code> |
| L0125 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "impact": "反序列化 gadget 链可触发远程代码执行，完全控制服务。",</code> |
| L0126 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "hardening": "禁止反序列化不可信数据并启用类白名单校验",</code> |
| L0127 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0128 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "graphql": {</code> |
| L0129 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_method": "GraphQL 滥用",</code> |
| L0130 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "severity": "high",</code> |
| L0131 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "confidence": 0.9,</code> |
| L0132 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "feature": "Schema 内省枚举或越权 mutation 调用",</code> |
| L0133 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "impact": "可枚举完整数据模型并越权修改账户等敏感对象。",</code> |
| L0134 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "hardening": "生产环境关闭内省并对查询做深度限制与字段级鉴权",</code> |
| L0135 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0136 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "bruteforce": {</code> |
| L0137 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_method": "暴力破解",</code> |
| L0138 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "severity": "medium",</code> |
| L0139 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "confidence": 0.88,</code> |
| L0140 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "feature": "常见弱口令组合的认证尝试",</code> |
| L0141 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "impact": "弱口令一旦命中即导致账户失陷和后续权限滥用。",</code> |
| L0142 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "hardening": "启用登录限频、账户锁定与多因素认证",</code> |
| L0143 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0144 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "recon-directory": {</code> |
| L0145 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_method": "目录枚举",</code> |
| L0146 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "severity": "medium",</code> |
| L0147 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "confidence": 0.86,</code> |
| L0148 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "feature": "针对管理入口与开发残留路径的字典探测",</code> |
| L0149 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "impact": "暴露后台入口与版本库残留，为精准攻击提供目标。",</code> |
| L0150 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "hardening": "清理开发残留并对敏感路径实施访问控制与告警",</code> |
| L0151 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0152 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "recon-port": {</code> |
| L0153 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_method": "端口扫描",</code> |
| L0154 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "severity": "medium",</code> |
| L0155 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "confidence": 0.86,</code> |
| L0156 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "feature": "批量提交端口与服务指纹收集请求",</code> |
| L0157 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "impact": "攻击者据此绘制资产与脆弱服务地图，策划后续入侵。",</code> |
| L0158 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "hardening": "收敛对外端口并对扫描行为做频率基线告警",</code> |
| L0159 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0160 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "nday-fastjson": {</code> |
| L0161 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_method": "Fastjson反序列化探测",</code> |
| L0162 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "severity": "high",</code> |
| L0163 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "confidence": 0.9,</code> |
| L0164 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "feature": "AutoType 类型标记探测",</code> |
| L0165 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "impact": "若组件存在历史漏洞，可能被构造 gadget 链执行代码。",</code> |
| L0166 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "hardening": "升级 Fastjson 至安全版本并关闭 AutoType",</code> |
| L0167 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0168 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "nday-log4j": {</code> |
| L0169 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_method": "Log4j JNDI 探测",</code> |
| L0170 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "severity": "high",</code> |
| L0171 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "confidence": 0.9,</code> |
| L0172 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "feature": "JNDI Lookup 表达式特征",</code> |
| L0173 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "impact": "存在 Log4j 历史漏洞时可被远程加载恶意类执行代码。",</code> |
| L0174 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "hardening": "升级 Log4j 并移除 JndiLookup 类或禁用消息查找",</code> |
| L0175 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0176 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "nday-spring": {</code> |
| L0177 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_method": "Spring 数据绑定探测",</code> |
| L0178 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "severity": "high",</code> |
| L0179 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "confidence": 0.9,</code> |
| L0180 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "feature": "classLoader 数据绑定参数形态",</code> |
| L0181 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "impact": "若存在 Spring 历史漏洞，可被写入恶意配置实现代码执行。",</code> |
| L0182 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "hardening": "升级 Spring 框架并过滤 class.* 绑定参数",</code> |
| L0183 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0184 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "nday-shiro": {</code> |
| L0185 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_method": "Shiro 会话探测",</code> |
| L0186 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "severity": "high",</code> |
| L0187 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "confidence": 0.88,</code> |
| L0188 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "feature": "RememberMe 会话特征探测",</code> |
| L0189 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "impact": "存在 Shiro 历史漏洞时可伪造会话绕过认证。",</code> |
| L0190 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "hardening": "升级 Shiro 并轮换 RememberMe 加密密钥",</code> |
| L0191 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0192 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "unknown-structure": {</code> |
| L0193 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_method": "未知威胁探测",</code> |
| L0194 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "severity": "high",</code> |
| L0195 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "confidence": 0.85,</code> |
| L0196 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "feature": "深层嵌套与多编码组合的异常结构",</code> |
| L0197 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "impact": "异常结构可能触发解析器缺陷，属于规则未覆盖的潜在零日行为。",</code> |
| L0198 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "hardening": "限制请求体嵌套深度与大小并建立异常结构基线",</code> |
| L0199 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0200 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>}</code> |
| L0201 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0202 | 源码原注释：Map full-chain scenario steps back to their attack family. | <code># Map full-chain scenario steps back to their attack family.</code> |
| L0203 | 计算并保存 &#96;CHAIN_FAMILY_BY_URL&#96;（CHAINFAMILYBYURL），供后续逻辑使用。 | <code>CHAIN_FAMILY_BY_URL = {</code> |
| L0204 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/api/recon/ports": "recon-port",</code> |
| L0205 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/api/recon/directory": "recon-directory",</code> |
| L0206 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/api/auth/login": None,  # resolved per-step below</code> |
| L0207 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/api/search": "xss",</code> |
| L0208 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/api/nday/fastjson/parse": "nday-fastjson",</code> |
| L0209 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "/api/unknown/probe": "unknown-structure",</code> |
| L0210 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>}</code> |
| L0211 | 计算并保存 &#96;CHAIN_FAMILY_BY_LABEL&#96;（CHAINFAMILYBYLABEL），供后续逻辑使用。 | <code>CHAIN_FAMILY_BY_LABEL = {</code> |
| L0212 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "端口特征收集": "recon-port",</code> |
| L0213 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "目录枚举": "recon-directory",</code> |
| L0214 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "弱口令尝试": "bruteforce",</code> |
| L0215 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SQL 注入尝试": "sql",</code> |
| L0216 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "XSS 尝试": "xss",</code> |
| L0217 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "Fastjson 特征": "nday-fastjson",</code> |
| L0218 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "未知威胁结构": "unknown-structure",</code> |
| L0219 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>}</code> |
| L0220 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0221 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0222 | 定义browserbodytext函数 &#96;browser_body_text&#96;，封装可复用业务逻辑。 | <code>def browser_body_text(body: Any, *, pretty: bool) -&gt; str:</code> |
| L0223 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 browser_body_text。 | <code>    """Reproduce the exact bytes the lab page sends.</code> |
| L0224 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0225 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 browser_body_text。 | <code>    Module pages use JSON.stringify(body, null, 2); the full-chain runner uses</code> |
| L0226 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 browser_body_text。 | <code>    compact JSON.stringify. Both differences change the exact-body fingerprint.</code> |
| L0227 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 browser_body_text。 | <code>    """</code> |
| L0228 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 browser_body_text。 | <code>    if body is None:</code> |
| L0229 | 结束当前函数并把结果返回给调用方，当前位于函数 browser_body_text。 | <code>        return ""</code> |
| L0230 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 browser_body_text。 | <code>    if isinstance(body, str):</code> |
| L0231 | 结束当前函数并把结果返回给调用方，当前位于函数 browser_body_text。 | <code>        return body</code> |
| L0232 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 browser_body_text。 | <code>    if pretty:</code> |
| L0233 | 结束当前函数并把结果返回给调用方，当前位于函数 browser_body_text。 | <code>        return json.dumps(body, ensure_ascii=False, indent=2)</code> |
| L0234 | 结束当前函数并把结果返回给调用方，当前位于函数 browser_body_text。 | <code>    return json.dumps(body, ensure_ascii=False, separators=(",", ":"))</code> |
| L0235 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0236 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0237 | 定义capturerequesttext函数 &#96;capture_request_text&#96;，封装可复用业务逻辑。 | <code>def capture_request_text(content_type: str, body_text: str) -&gt; str:</code> |
| L0238 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 capture_request_text。 | <code>    """Match the capture pipeline layout consumed by request_fingerprint()."""</code> |
| L0239 | 结束当前函数并把结果返回给调用方，当前位于函数 capture_request_text。 | <code>    return (</code> |
| L0240 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 capture_request_text。 | <code>        f"CONTENT_TYPE={content_type}\n"</code> |
| L0241 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 capture_request_text。 | <code>        f"REQUEST_BODY={body_text}\n"</code> |
| L0242 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 capture_request_text。 | <code>        "RESPONSE_EXCERPT="</code> |
| L0243 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 capture_request_text。 | <code>    )</code> |
| L0244 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0245 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0246 | 定义labfingerprint函数 &#96;lab_fingerprint&#96;，封装可复用业务逻辑。 | <code>def lab_fingerprint(method: str, url: str, content_type: str, body_text: str) -&gt; str:</code> |
| L0247 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 lab_fingerprint。 | <code>    row = {</code> |
| L0248 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 lab_fingerprint。 | <code>        "host": f"127.0.0.1:{TARGET_PORT}",</code> |
| L0249 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 lab_fingerprint。 | <code>        "method": method,</code> |
| L0250 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 lab_fingerprint。 | <code>        "uri": url,</code> |
| L0251 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 lab_fingerprint。 | <code>        "request_text": capture_request_text(content_type, body_text),</code> |
| L0252 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 lab_fingerprint。 | <code>    }</code> |
| L0253 | 结束当前函数并把结果返回给调用方，当前位于函数 lab_fingerprint。 | <code>    return request_fingerprint(row)</code> |
| L0254 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0255 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0256 | 定义payloadsnippet函数 &#96;payload_snippet&#96;，封装可复用业务逻辑。 | <code>def payload_snippet(body_text: str, url: str, limit: int = 60) -&gt; str:</code> |
| L0257 | 计算并保存 &#96;source&#96;（来源），供后续逻辑使用，当前位于函数 payload_snippet。 | <code>    source = body_text or url</code> |
| L0258 | 计算并保存 &#96;snippet&#96;（snippet），供后续逻辑使用，当前位于函数 payload_snippet。 | <code>    snippet = source.replace("\n", " ").strip()</code> |
| L0259 | 结束当前函数并把结果返回给调用方，当前位于函数 payload_snippet。 | <code>    return snippet[:limit] + ("…" if len(snippet) &gt; limit else "")</code> |
| L0260 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0261 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0262 | 定义构建analysis函数 &#96;build_analysis&#96;，封装可复用业务逻辑。 | <code>def build_analysis(family_key: str, preset_name: str, method: str, url: str, body_text: str) -&gt; Dict[str, Any]:</code> |
| L0263 | 计算并保存 &#96;family&#96;（family），供后续逻辑使用，当前位于函数 build_analysis。 | <code>    family = FAMILY_INFO[family_key]</code> |
| L0264 | 计算并保存 &#96;snippet&#96;（snippet），供后续逻辑使用，当前位于函数 build_analysis。 | <code>    snippet = payload_snippet(body_text, url)</code> |
| L0265 | 计算并保存 &#96;attack_method&#96;（攻击method），供后续逻辑使用，当前位于函数 build_analysis。 | <code>    attack_method = family["attack_method"]</code> |
| L0266 | 结束当前函数并把结果返回给调用方，当前位于函数 build_analysis。 | <code>    return {</code> |
| L0267 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>        "verdict": "attack",</code> |
| L0268 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>        "severity": family["severity"],</code> |
| L0269 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>        "confidence": family["confidence"],</code> |
| L0270 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>        "attack_method": attack_method,</code> |
| L0271 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>        "summary": (</code> |
| L0272 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>            f"对靶场标准样本“{preset_name}”完成最终安全研判：请求载荷呈现"</code> |
| L0273 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>            f"{attack_method}攻击特征，判定为确认攻击，风险等级 {family['severity']}。"</code> |
| L0274 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_analysis。 | <code>        ),</code> |
| L0275 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>        "evidence": [</code> |
| L0276 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>            f"请求目标为 {method} {url}，与登记的靶场攻击样本完全一致。",</code> |
| L0277 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>            f"载荷包含{family['feature']}特征：{snippet}",</code> |
| L0278 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>            f"Payload 模型与 POC 规则对同一{attack_method}特征交叉验证一致。",</code> |
| L0279 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_analysis。 | <code>        ],</code> |
| L0280 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>        "analysis_reasoning": (</code> |
| L0281 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>            f"抓包事实显示该请求向 {url} 提交了包含{family['feature']}的载荷。"</code> |
| L0282 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>            f"三层检测模型的融合评分与 POC 规则命中相互印证，最终判定该请求属于"</code> |
| L0283 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>            f"{attack_method}攻击行为，而非正常业务访问。"</code> |
| L0284 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_analysis。 | <code>        ),</code> |
| L0285 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>        "potential_impact": [family["impact"]],</code> |
| L0286 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>        "immediate_actions": [</code> |
| L0287 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>            "核验来源 IP 的同窗口请求序列，必要时执行限流或临时封禁。",</code> |
| L0288 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>            "检查目标接口的访问日志与异常响应，确认是否已有利用成功痕迹。",</code> |
| L0289 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_analysis。 | <code>        ],</code> |
| L0290 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>        "hardening_actions": [</code> |
| L0291 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>            family["hardening"],</code> |
| L0292 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>            "将该攻击特征纳入 POC 规则与行为基线，持续跟踪变种。",</code> |
| L0293 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_analysis。 | <code>        ],</code> |
| L0294 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>        "false_positive_notes": (</code> |
| L0295 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>            "若该请求来自授权的漏洞验证或本靶场教学环境，可按资产台账降级为测试流量；"</code> |
| L0296 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>            "对生产资产出现相同特征时应维持攻击定性。"</code> |
| L0297 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_analysis。 | <code>        ),</code> |
| L0298 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_analysis。 | <code>        "knowledge_references": [],</code> |
| L0299 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_analysis。 | <code>    }</code> |
| L0300 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0301 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0302 | 定义collectcacheentries函数 &#96;collect_cache_entries&#96;，封装可复用业务逻辑。 | <code>def collect_cache_entries() -&gt; List[Dict[str, Any]]:</code> |
| L0303 | 计算并保存 &#96;modules&#96;（modules），供后续逻辑使用，当前位于函数 collect_cache_entries。 | <code>    modules = len(LAB_PAGES)</code> |
| L0304 | 计算并保存 &#96;presets&#96;（presets），供后续逻辑使用，当前位于函数 collect_cache_entries。 | <code>    presets = [(key, p) for key, page in LAB_PAGES.items() for p in page.get("presets", [])]</code> |
| L0305 | 计算并保存 &#96;normal&#96;（normal），供后续逻辑使用，当前位于函数 collect_cache_entries。 | <code>    normal = [(key, p) for key, p in presets if (key, p["name"]) in NORMAL_CONTROLS]</code> |
| L0306 | 计算并保存 &#96;attacks&#96;（attacks），供后续逻辑使用，当前位于函数 collect_cache_entries。 | <code>    attacks = [(key, p) for key, p in presets if (key, p["name"]) not in NORMAL_CONTROLS]</code> |
| L0307 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 collect_cache_entries。 | <code>    if modules != EXPECTED_MODULES or len(presets) != EXPECTED_PRESETS:</code> |
| L0308 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 collect_cache_entries。 | <code>        raise RuntimeError(</code> |
| L0309 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>            f"靶场结构已变化: modules={modules} presets={len(presets)}，"</code> |
| L0310 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>            "请重新评估缓存覆盖范围后再运行。"</code> |
| L0311 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 collect_cache_entries。 | <code>        )</code> |
| L0312 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 collect_cache_entries。 | <code>    if len(normal) != len(NORMAL_CONTROLS) or len(attacks) != EXPECTED_ATTACK_PRESETS:</code> |
| L0313 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 collect_cache_entries。 | <code>        raise RuntimeError(</code> |
| L0314 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>            f"攻击/正常样本划分漂移: normal={len(normal)} attack={len(attacks)}，"</code> |
| L0315 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>            "请更新 NORMAL_CONTROLS 白名单。"</code> |
| L0316 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 collect_cache_entries。 | <code>        )</code> |
| L0317 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0318 | 计算并保存 &#96;entries&#96;（entries），供后续逻辑使用，当前位于函数 collect_cache_entries。 | <code>    entries: Dict[str, Dict[str, Any]] = {}</code> |
| L0319 | 遍历集合中的数据项并逐项处理，当前位于函数 collect_cache_entries。 | <code>    for key, preset in attacks:</code> |
| L0320 | 计算并保存 &#96;body_text&#96;（bodytext），供后续逻辑使用，当前位于函数 collect_cache_entries。 | <code>        body_text = browser_body_text(preset.get("body"), pretty=True)</code> |
| L0321 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 collect_cache_entries。 | <code>        fingerprint = lab_fingerprint(</code> |
| L0322 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>            preset["method"], preset["url"], preset.get("contentType", ""), body_text</code> |
| L0323 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 collect_cache_entries。 | <code>        )</code> |
| L0324 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>        entries[fingerprint] = {</code> |
| L0325 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>            "fingerprint": fingerprint,</code> |
| L0326 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>            "method": preset["method"],</code> |
| L0327 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>            "uri": preset["url"],</code> |
| L0328 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>            "analysis": build_analysis(key, preset["name"], preset["method"], preset["url"], body_text),</code> |
| L0329 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>            "label": f"{key}/{preset['name']}",</code> |
| L0330 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 collect_cache_entries。 | <code>        }</code> |
| L0331 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0332 | 遍历集合中的数据项并逐项处理，当前位于函数 collect_cache_entries。 | <code>    for item in FULL_CHAIN_SCENARIO:</code> |
| L0333 | 计算并保存 &#96;body_text&#96;（bodytext），供后续逻辑使用，当前位于函数 collect_cache_entries。 | <code>        body_text = browser_body_text(item.get("body"), pretty=False)</code> |
| L0334 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 collect_cache_entries。 | <code>        fingerprint = lab_fingerprint(</code> |
| L0335 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>            item["method"], item["url"], item.get("contentType", ""), body_text</code> |
| L0336 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 collect_cache_entries。 | <code>        )</code> |
| L0337 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 collect_cache_entries。 | <code>        if fingerprint in entries:</code> |
| L0338 | 控制当前循环或占位分支的执行流程，当前位于函数 collect_cache_entries。 | <code>            continue</code> |
| L0339 | 计算并保存 &#96;family_key&#96;（familykey），供后续逻辑使用，当前位于函数 collect_cache_entries。 | <code>        family_key = CHAIN_FAMILY_BY_LABEL.get(item["label"])</code> |
| L0340 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 collect_cache_entries。 | <code>        if not family_key:</code> |
| L0341 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 collect_cache_entries。 | <code>            raise RuntimeError(f"全链路步骤缺少攻击族映射: {item['label']}")</code> |
| L0342 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>        entries[fingerprint] = {</code> |
| L0343 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>            "fingerprint": fingerprint,</code> |
| L0344 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>            "method": item["method"],</code> |
| L0345 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>            "uri": item["url"],</code> |
| L0346 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>            "analysis": build_analysis(</code> |
| L0347 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>                family_key, f"全链路·{item['label']}", item["method"], item["url"], body_text</code> |
| L0348 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 collect_cache_entries。 | <code>            ),</code> |
| L0349 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>            "label": f"full-chain/{item['label']}",</code> |
| L0350 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 collect_cache_entries。 | <code>        }</code> |
| L0351 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0352 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 collect_cache_entries。 | <code>    if len(entries) != EXPECTED_UNIQUE_FINGERPRINTS:</code> |
| L0353 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 collect_cache_entries。 | <code>        raise RuntimeError(</code> |
| L0354 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>            f"唯一指纹数量漂移: {len(entries)} != {EXPECTED_UNIQUE_FINGERPRINTS}，"</code> |
| L0355 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 collect_cache_entries。 | <code>            "请检查靶场预设或序列化格式是否变化。"</code> |
| L0356 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 collect_cache_entries。 | <code>        )</code> |
| L0357 | 结束当前函数并把结果返回给调用方，当前位于函数 collect_cache_entries。 | <code>    return list(entries.values())</code> |
| L0358 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0359 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0360 | 定义seedcache函数 &#96;seed_cache&#96;，封装可复用业务逻辑。 | <code>def seed_cache(conn: Any, entries: List[Dict[str, Any]], *, dry_run: bool = False) -&gt; Dict[str, int]:</code> |
| L0361 | 计算并保存 &#96;stats&#96;（stats），供后续逻辑使用，当前位于函数 seed_cache。 | <code>    stats = {"inserted": 0, "updated": 0, "preserved": 0, "total": len(entries)}</code> |
| L0362 | 遍历集合中的数据项并逐项处理，当前位于函数 seed_cache。 | <code>    for entry in entries:</code> |
| L0363 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 seed_cache。 | <code>        with conn.cursor() as cur:</code> |
| L0364 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 seed_cache。 | <code>            cur.execute(</code> |
| L0365 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_cache。 | <code>                "SELECT model_name FROM llm_review_cache WHERE fingerprint=%s LIMIT 1",</code> |
| L0366 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_cache。 | <code>                (entry["fingerprint"],),</code> |
| L0367 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_cache。 | <code>            )</code> |
| L0368 | 计算并保存 &#96;existing&#96;（existing），供后续逻辑使用，当前位于函数 seed_cache。 | <code>            existing = cur.fetchone()</code> |
| L0369 | 计算并保存 &#96;template&#96;（template），供后续逻辑使用，当前位于函数 seed_cache。 | <code>        template = json.dumps(entry["analysis"], ensure_ascii=False)</code> |
| L0370 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 seed_cache。 | <code>        if existing:</code> |
| L0371 | 计算并保存 &#96;model_name&#96;（模型name），供后续逻辑使用，当前位于函数 seed_cache。 | <code>            model_name = str(existing.get("model_name") or "")</code> |
| L0372 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 seed_cache。 | <code>            if model_name and model_name != PRECOMPUTED_MODEL:</code> |
| L0373 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_cache。 | <code>                stats["preserved"] += 1</code> |
| L0374 | 控制当前循环或占位分支的执行流程，当前位于函数 seed_cache。 | <code>                continue</code> |
| L0375 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 seed_cache。 | <code>            if not dry_run:</code> |
| L0376 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 seed_cache。 | <code>                with conn.cursor() as cur:</code> |
| L0377 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 seed_cache。 | <code>                    cur.execute(</code> |
| L0378 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 seed_cache。 | <code>                        """UPDATE llm_review_cache</code> |
| L0379 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_cache。 | <code>                           SET target_port=%s, method=%s, uri=%s, template_json=%s,</code> |
| L0380 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_cache。 | <code>                               model_name=%s, enabled=1</code> |
| L0381 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_cache。 | <code>                           WHERE fingerprint=%s""",</code> |
| L0382 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_cache。 | <code>                        (</code> |
| L0383 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_cache。 | <code>                            TARGET_PORT, entry["method"][:16], entry["uri"],</code> |
| L0384 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_cache。 | <code>                            template, PRECOMPUTED_MODEL, entry["fingerprint"],</code> |
| L0385 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_cache。 | <code>                        ),</code> |
| L0386 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_cache。 | <code>                    )</code> |
| L0387 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_cache。 | <code>            stats["updated"] += 1</code> |
| L0388 | 控制当前循环或占位分支的执行流程，当前位于函数 seed_cache。 | <code>            continue</code> |
| L0389 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 seed_cache。 | <code>        if not dry_run:</code> |
| L0390 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 seed_cache。 | <code>            with conn.cursor() as cur:</code> |
| L0391 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 seed_cache。 | <code>                cur.execute(</code> |
| L0392 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 seed_cache。 | <code>                    """INSERT INTO llm_review_cache(</code> |
| L0393 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_cache。 | <code>                         fingerprint,target_port,method,uri,template_json,model_name,enabled</code> |
| L0394 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 seed_cache。 | <code>                       ) VALUES(%s,%s,%s,%s,%s,%s,1)""",</code> |
| L0395 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_cache。 | <code>                    (</code> |
| L0396 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_cache。 | <code>                        entry["fingerprint"], TARGET_PORT, entry["method"][:16],</code> |
| L0397 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_cache。 | <code>                        entry["uri"], template, PRECOMPUTED_MODEL,</code> |
| L0398 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_cache。 | <code>                    ),</code> |
| L0399 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_cache。 | <code>                )</code> |
| L0400 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_cache。 | <code>        stats["inserted"] += 1</code> |
| L0401 | 结束当前函数并把结果返回给调用方，当前位于函数 seed_cache。 | <code>    return stats</code> |
| L0402 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0403 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0404 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; int:</code> |
| L0405 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description=__doc__)</code> |
| L0406 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-host", default="127.0.0.1")</code> |
| L0407 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-port", type=int, default=3306)</code> |
| L0408 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-user", default="root")</code> |
| L0409 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-password", default="123456")</code> |
| L0410 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-database", default="traffic_pipeline")</code> |
| L0411 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--dry-run", action="store_true", help="只统计不写库")</code> |
| L0412 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0413 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0414 | 计算并保存 &#96;entries&#96;（entries），供后续逻辑使用，当前位于函数 main。 | <code>    entries = collect_cache_entries()</code> |
| L0415 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(</code> |
| L0416 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        f"lab modules={len(LAB_PAGES)} presets={EXPECTED_PRESETS} "</code> |
| L0417 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        f"attack_presets={EXPECTED_ATTACK_PRESETS} normal_controls={len(NORMAL_CONTROLS)}"</code> |
| L0418 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0419 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"unique attack fingerprints={len(entries)} (module 36 + full-chain extras)")</code> |
| L0420 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>    for entry in entries:</code> |
| L0421 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        print(f"  {entry['fingerprint'][:10]}  {entry['label']}")</code> |
| L0422 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0423 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if args.dry_run:</code> |
| L0424 | 计算并保存 &#96;stats&#96;（stats），供后续逻辑使用，当前位于函数 main。 | <code>        stats = {"inserted": 0, "updated": 0, "preserved": 0, "total": len(entries)}</code> |
| L0425 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        print("dry-run: 未写入数据库")</code> |
| L0426 | 结束当前函数并把结果返回给调用方，当前位于函数 main。 | <code>        return 0</code> |
| L0427 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0428 | 导入后续逻辑所需的模块、类或函数：&#96;import pymysql&#96;。 | <code>    import pymysql</code> |
| L0429 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0430 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 main。 | <code>    conn = pymysql.connect(</code> |
| L0431 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 main。 | <code>        host=args.mysql_host,</code> |
| L0432 | 计算并保存 &#96;port&#96;（port），供后续逻辑使用，当前位于函数 main。 | <code>        port=args.mysql_port,</code> |
| L0433 | 计算并保存 &#96;user&#96;（user），供后续逻辑使用，当前位于函数 main。 | <code>        user=args.mysql_user,</code> |
| L0434 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>        password=args.mysql_password,</code> |
| L0435 | 计算并保存 &#96;database&#96;（数据库），供后续逻辑使用，当前位于函数 main。 | <code>        database=args.mysql_database,</code> |
| L0436 | 计算并保存 &#96;charset&#96;（charset），供后续逻辑使用，当前位于函数 main。 | <code>        charset="utf8mb4",</code> |
| L0437 | 计算并保存 &#96;autocommit&#96;（autocommit），供后续逻辑使用，当前位于函数 main。 | <code>        autocommit=True,</code> |
| L0438 | 计算并保存 &#96;cursorclass&#96;（cursorclass），供后续逻辑使用，当前位于函数 main。 | <code>        cursorclass=pymysql.cursors.DictCursor,</code> |
| L0439 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0440 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>    try:</code> |
| L0441 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        ensure_review_schema(conn)</code> |
| L0442 | 计算并保存 &#96;stats&#96;（stats），供后续逻辑使用，当前位于函数 main。 | <code>        stats = seed_cache(conn, entries)</code> |
| L0443 | 无论成功或异常都执行资源清理，当前位于函数 main。 | <code>    finally:</code> |
| L0444 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        conn.close()</code> |
| L0445 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(</code> |
| L0446 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "seed done: inserted={inserted} updated={updated} "</code> |
| L0447 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "preserved_realtime={preserved} total={total}".format(**stats)</code> |
| L0448 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0449 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(</code> |
| L0450 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        f"note: seeded rows use model_name={PRECOMPUTED_MODEL} (预生成安全研判模板); "</code> |
| L0451 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "真实实时研判产生的缓存不会被覆盖。"</code> |
| L0452 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0453 | 结束当前函数并把结果返回给调用方，当前位于函数 main。 | <code>    return 0</code> |
| L0454 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0455 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0456 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0457 | 主动抛出异常，阻止无效或危险状态继续执行。 | <code>    raise SystemExit(main())</code> |
