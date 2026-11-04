# `scripts/situation_core.py` 逐行注释

**脚本用途：** 按来源、时间和攻击阶段关联事件，形成单 IP 攻击态势。

**源码行数：** 461　**函数/类数量：** 23

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import hashlib&#96;。 | <code>import hashlib</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import math&#96;。 | <code>import math</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;from copy import deepcopy&#96;。 | <code>from copy import deepcopy</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;from dataclasses import dataclass, field&#96;。 | <code>from dataclasses import dataclass, field</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime, timedelta, timezone&#96;。 | <code>from datetime import datetime, timedelta, timezone</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple&#96;。 | <code>from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;from zoneinfo import ZoneInfo&#96;。 | <code>from zoneinfo import ZoneInfo</code> |
| L0011 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0012 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0013 | 计算并保存 &#96;LOCAL_TIMEZONE&#96;（LOCALTIMEZONE），供后续逻辑使用。 | <code>LOCAL_TIMEZONE = ZoneInfo("Asia/Shanghai")</code> |
| L0014 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0015 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0016 | 计算并保存 &#96;STAGE_LABELS&#96;（STAGELABELS），供后续逻辑使用。 | <code>STAGE_LABELS = {</code> |
| L0017 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "recon": "侦察探测",</code> |
| L0018 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "credential": "凭据攻击",</code> |
| L0019 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "exploit": "漏洞利用",</code> |
| L0020 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "execution": "执行控制",</code> |
| L0021 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "impact": "影响处置",</code> |
| L0022 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "unknown": "其他行为",</code> |
| L0023 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>}</code> |
| L0024 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0025 | 计算并保存 &#96;STAGE_ORDER&#96;（STAGEORDER），供后续逻辑使用。 | <code>STAGE_ORDER = {</code> |
| L0026 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "unknown": 0,</code> |
| L0027 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "recon": 1,</code> |
| L0028 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "credential": 2,</code> |
| L0029 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "exploit": 3,</code> |
| L0030 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "execution": 4,</code> |
| L0031 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "impact": 5,</code> |
| L0032 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>}</code> |
| L0033 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0034 | 计算并保存 &#96;ACTION_CATALOG&#96;（ACTIONCATALOG），供后续逻辑使用。 | <code>ACTION_CATALOG: Dict[str, Dict[str, Any]] = {</code> |
| L0035 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "PORT_SCAN": {"label": "端口扫描", "stage": "recon", "weight": 0.35},</code> |
| L0036 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SERVICE_PROBE": {"label": "服务探测", "stage": "recon", "weight": 0.40},</code> |
| L0037 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "DIRECTORY_SCAN": {"label": "目录扫描", "stage": "recon", "weight": 0.42},</code> |
| L0038 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "GRAPHQL_PROBE": {"label": "GraphQL 探测", "stage": "recon", "weight": 0.45},</code> |
| L0039 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SSH_BRUTEFORCE": {"label": "SSH 爆破", "stage": "credential", "weight": 0.68},</code> |
| L0040 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "HTTP_BRUTEFORCE": {"label": "HTTP 爆破", "stage": "credential", "weight": 0.62},</code> |
| L0041 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "AUTH_ABUSE": {"label": "认证滥用", "stage": "credential", "weight": 0.62},</code> |
| L0042 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SQL_INJECTION": {"label": "SQL 注入", "stage": "exploit", "weight": 0.78},</code> |
| L0043 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "XSS": {"label": "XSS", "stage": "exploit", "weight": 0.65},</code> |
| L0044 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "PATH_TRAVERSAL": {"label": "路径遍历", "stage": "exploit", "weight": 0.72},</code> |
| L0045 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "FILE_UPLOAD": {"label": "危险文件上传", "stage": "exploit", "weight": 0.82},</code> |
| L0046 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SSRF": {"label": "SSRF", "stage": "exploit", "weight": 0.76},</code> |
| L0047 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "XXE": {"label": "XXE", "stage": "exploit", "weight": 0.78},</code> |
| L0048 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SSTI": {"label": "SSTI", "stage": "exploit", "weight": 0.78},</code> |
| L0049 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "DESERIALIZATION": {"label": "反序列化", "stage": "execution", "weight": 0.88},</code> |
| L0050 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "FASTJSON_NDAY": {"label": "Fastjson 反序列化探测", "stage": "execution", "weight": 0.89},</code> |
| L0051 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "LOG4J_NDAY": {"label": "Log4j JNDI 探测", "stage": "execution", "weight": 0.94},</code> |
| L0052 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SPRING_NDAY": {"label": "Spring 数据绑定探测", "stage": "exploit", "weight": 0.86},</code> |
| L0053 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SHIRO_NDAY": {"label": "Shiro 认证探测", "stage": "credential", "weight": 0.80},</code> |
| L0054 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "UNKNOWN_THREAT": {"label": "未知威胁探测", "stage": "exploit", "weight": 0.78},</code> |
| L0055 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "COMMAND_INJECTION": {"label": "命令注入", "stage": "execution", "weight": 0.92},</code> |
| L0056 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "WEB_SHELL": {"label": "WebShell 行为", "stage": "execution", "weight": 0.95},</code> |
| L0057 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "IP_BLOCKED": {"label": "IP 已封禁", "stage": "impact", "weight": 0.20},</code> |
| L0058 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "UNKNOWN": {"label": "其他异常", "stage": "unknown", "weight": 0.30},</code> |
| L0059 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>}</code> |
| L0060 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0061 | 计算并保存 &#96;ATTACK_TYPE_ALIASES&#96;（攻击TYPEALIASES），供后续逻辑使用。 | <code>ATTACK_TYPE_ALIASES = {</code> |
| L0062 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "端口扫描": "PORT_SCAN",</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "网络扫描": "PORT_SCAN",</code> |
| L0064 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "服务探测": "SERVICE_PROBE",</code> |
| L0065 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "扫描探测": "SERVICE_PROBE",</code> |
| L0066 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "目录扫描": "DIRECTORY_SCAN",</code> |
| L0067 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "目录探测": "DIRECTORY_SCAN",</code> |
| L0068 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "路径探测": "DIRECTORY_SCAN",</code> |
| L0069 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "graphql探测": "GRAPHQL_PROBE",</code> |
| L0070 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "graphql introspection探测": "GRAPHQL_PROBE",</code> |
| L0071 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "ssh爆破": "SSH_BRUTEFORCE",</code> |
| L0072 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "ssh暴力破解": "SSH_BRUTEFORCE",</code> |
| L0073 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "http爆破": "HTTP_BRUTEFORCE",</code> |
| L0074 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "暴力破解": "HTTP_BRUTEFORCE",</code> |
| L0075 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "疑似暴力破解": "HTTP_BRUTEFORCE",</code> |
| L0076 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "认证滥用": "AUTH_ABUSE",</code> |
| L0077 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "sql注入": "SQL_INJECTION",</code> |
| L0078 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "sql injection": "SQL_INJECTION",</code> |
| L0079 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "xss": "XSS",</code> |
| L0080 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "跨站脚本": "XSS",</code> |
| L0081 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "路径遍历": "PATH_TRAVERSAL",</code> |
| L0082 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "敏感文件读取": "PATH_TRAVERSAL",</code> |
| L0083 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "危险文件上传": "FILE_UPLOAD",</code> |
| L0084 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "文件上传": "FILE_UPLOAD",</code> |
| L0085 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "ssrf": "SSRF",</code> |
| L0086 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "xxe": "XXE",</code> |
| L0087 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "ssti": "SSTI",</code> |
| L0088 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "反序列化": "DESERIALIZATION",</code> |
| L0089 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "fastjson反序列化探测": "FASTJSON_NDAY",</code> |
| L0090 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "fastjson探测": "FASTJSON_NDAY",</code> |
| L0091 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "log4j jndi探测": "LOG4J_NDAY",</code> |
| L0092 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "log4j探测": "LOG4J_NDAY",</code> |
| L0093 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "spring数据绑定探测": "SPRING_NDAY",</code> |
| L0094 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "spring探测": "SPRING_NDAY",</code> |
| L0095 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "shiro认证探测": "SHIRO_NDAY",</code> |
| L0096 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "shiro探测": "SHIRO_NDAY",</code> |
| L0097 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "未知威胁探测": "UNKNOWN_THREAT",</code> |
| L0098 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "零日特征模拟": "UNKNOWN_THREAT",</code> |
| L0099 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "命令注入": "COMMAND_INJECTION",</code> |
| L0100 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "webshell": "WEB_SHELL",</code> |
| L0101 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "ip已封禁": "IP_BLOCKED",</code> |
| L0102 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>}</code> |
| L0103 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0104 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0105 | 定义解析timestamp函数 &#96;parse_timestamp&#96;，封装可复用业务逻辑。 | <code>def parse_timestamp(value: Any) -&gt; datetime:</code> |
| L0106 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_timestamp。 | <code>    if isinstance(value, datetime):</code> |
| L0107 | 计算并保存 &#96;dt&#96;（dt），供后续逻辑使用，当前位于函数 parse_timestamp。 | <code>        dt = value</code> |
| L0108 | 处理前述条件均未命中的情况，当前位于函数 parse_timestamp。 | <code>    else:</code> |
| L0109 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 parse_timestamp。 | <code>        text = str(value or "").strip()</code> |
| L0110 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_timestamp。 | <code>        if not text:</code> |
| L0111 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_timestamp。 | <code>            return datetime.now(timezone.utc)</code> |
| L0112 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 parse_timestamp。 | <code>        text = text.replace("Z", "+00:00")</code> |
| L0113 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 parse_timestamp。 | <code>        try:</code> |
| L0114 | 计算并保存 &#96;dt&#96;（dt），供后续逻辑使用，当前位于函数 parse_timestamp。 | <code>            dt = datetime.fromisoformat(text)</code> |
| L0115 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 parse_timestamp。 | <code>        except ValueError:</code> |
| L0116 | 计算并保存 &#96;dt&#96;（dt），供后续逻辑使用，当前位于函数 parse_timestamp。 | <code>            dt = datetime.strptime(text.split(".", 1)[0], "%Y-%m-%d %H:%M:%S")</code> |
| L0117 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_timestamp。 | <code>    if dt.tzinfo is None:</code> |
| L0118 | 源码原注释：Existing MySQL event timestamps are server-local values without an offset. | <code>        # Existing MySQL event timestamps are server-local values without an offset.</code> |
| L0119 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_timestamp。 | <code>        return dt.replace(tzinfo=LOCAL_TIMEZONE).astimezone(timezone.utc)</code> |
| L0120 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_timestamp。 | <code>    return dt.astimezone(timezone.utc)</code> |
| L0121 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0122 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0123 | 定义timestamptext函数 &#96;timestamp_text&#96;，封装可复用业务逻辑。 | <code>def timestamp_text(value: datetime) -&gt; str:</code> |
| L0124 | 结束当前函数并把结果返回给调用方，当前位于函数 timestamp_text。 | <code>    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")</code> |
| L0125 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0126 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0127 | 定义标准化actiontype函数 &#96;normalize_action_type&#96;，封装可复用业务逻辑。 | <code>def normalize_action_type(value: Any) -&gt; str:</code> |
| L0128 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 normalize_action_type。 | <code>    text = str(value or "").strip()</code> |
| L0129 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_action_type。 | <code>    if not text:</code> |
| L0130 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_action_type。 | <code>        return "UNKNOWN"</code> |
| L0131 | 计算并保存 &#96;upper&#96;（upper），供后续逻辑使用，当前位于函数 normalize_action_type。 | <code>    upper = text.upper().replace("-", "_").replace(" ", "_")</code> |
| L0132 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_action_type。 | <code>    if upper in ACTION_CATALOG:</code> |
| L0133 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_action_type。 | <code>        return upper</code> |
| L0134 | 计算并保存 &#96;compact&#96;（compact），供后续逻辑使用，当前位于函数 normalize_action_type。 | <code>    compact = text.lower().replace(" ", "")</code> |
| L0135 | 计算并保存 &#96;compact_aliases&#96;（compactaliases），供后续逻辑使用，当前位于函数 normalize_action_type。 | <code>    compact_aliases = [</code> |
| L0136 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_action_type。 | <code>        (alias.lower().replace(" ", ""), action_type)</code> |
| L0137 | 遍历集合中的数据项并逐项处理，当前位于函数 normalize_action_type。 | <code>        for alias, action_type in ATTACK_TYPE_ALIASES.items()</code> |
| L0138 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_action_type。 | <code>    ]</code> |
| L0139 | 遍历集合中的数据项并逐项处理，当前位于函数 normalize_action_type。 | <code>    for alias_compact, action_type in compact_aliases:</code> |
| L0140 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_action_type。 | <code>        if compact == alias_compact:</code> |
| L0141 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_action_type。 | <code>            return action_type</code> |
| L0142 | 源码原注释：Prefer the most specific phrase when a label contains both a product | <code>    # Prefer the most specific phrase when a label contains both a product</code> |
| L0143 | 源码原注释：name and a generic family such as “Fastjson反序列化探测”. | <code>    # name and a generic family such as “Fastjson反序列化探测”.</code> |
| L0144 | 遍历集合中的数据项并逐项处理，当前位于函数 normalize_action_type。 | <code>    for alias_compact, action_type in sorted(compact_aliases, key=lambda item: len(item[0]), reverse=True):</code> |
| L0145 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_action_type。 | <code>        if alias_compact in compact:</code> |
| L0146 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_action_type。 | <code>            return action_type</code> |
| L0147 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_action_type。 | <code>    return "UNKNOWN"</code> |
| L0148 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0149 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0150 | 定义severityvalue函数 &#96;severity_value&#96;，封装可复用业务逻辑。 | <code>def severity_value(severity: str) -&gt; float:</code> |
| L0151 | 结束当前函数并把结果返回给调用方，当前位于函数 severity_value。 | <code>    return {</code> |
| L0152 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 severity_value。 | <code>        "critical": 1.0,</code> |
| L0153 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 severity_value。 | <code>        "high": 0.82,</code> |
| L0154 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 severity_value。 | <code>        "medium": 0.58,</code> |
| L0155 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 severity_value。 | <code>        "low": 0.30,</code> |
| L0156 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 severity_value。 | <code>        "info": 0.10,</code> |
| L0157 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 severity_value。 | <code>    }.get(str(severity or "").lower(), 0.45)</code> |
| L0158 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0159 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0160 | 定义risklevel函数 &#96;risk_level&#96;，封装可复用业务逻辑。 | <code>def risk_level(score: float) -&gt; str:</code> |
| L0161 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 risk_level。 | <code>    if score &gt;= 0.82:</code> |
| L0162 | 结束当前函数并把结果返回给调用方，当前位于函数 risk_level。 | <code>        return "critical"</code> |
| L0163 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 risk_level。 | <code>    if score &gt;= 0.68:</code> |
| L0164 | 结束当前函数并把结果返回给调用方，当前位于函数 risk_level。 | <code>        return "high"</code> |
| L0165 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 risk_level。 | <code>    if score &gt;= 0.48:</code> |
| L0166 | 结束当前函数并把结果返回给调用方，当前位于函数 risk_level。 | <code>        return "medium"</code> |
| L0167 | 结束当前函数并把结果返回给调用方，当前位于函数 risk_level。 | <code>    return "low"</code> |
| L0168 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0169 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0170 | 应用装饰器 &#96;@dataclass&#96;，为下一定义附加权限、缓存或注册行为。 | <code>@dataclass</code> |
| L0171 | 定义类 &#96;SecurityAction&#96;，集中保存相关状态与操作。 | <code>class SecurityAction:</code> |
| L0172 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 SecurityAction。 | <code>    action_id: str</code> |
| L0173 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 SecurityAction。 | <code>    source_ip: str</code> |
| L0174 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 SecurityAction。 | <code>    target_asset: str</code> |
| L0175 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 SecurityAction。 | <code>    action_type: str</code> |
| L0176 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 SecurityAction。 | <code>    occurred_at: datetime</code> |
| L0177 | 计算并保存 &#96;last_seen_at&#96;（lastseenat），供后续逻辑使用，当前位于类 SecurityAction。 | <code>    last_seen_at: Optional[datetime] = None</code> |
| L0178 | 计算并保存 &#96;target_port&#96;（targetport），供后续逻辑使用，当前位于类 SecurityAction。 | <code>    target_port: Optional[int] = None</code> |
| L0179 | 计算并保存 &#96;target_interface&#96;（targetinterface），供后续逻辑使用，当前位于类 SecurityAction。 | <code>    target_interface: str = ""</code> |
| L0180 | 计算并保存 &#96;protocol&#96;（protocol），供后续逻辑使用，当前位于类 SecurityAction。 | <code>    protocol: str = ""</code> |
| L0181 | 计算并保存 &#96;sensor&#96;（sensor），供后续逻辑使用，当前位于类 SecurityAction。 | <code>    sensor: str = ""</code> |
| L0182 | 计算并保存 &#96;count&#96;（count），供后续逻辑使用，当前位于类 SecurityAction。 | <code>    count: int = 1</code> |
| L0183 | 计算并保存 &#96;confidence&#96;（confidence），供后续逻辑使用，当前位于类 SecurityAction。 | <code>    confidence: float = 0.0</code> |
| L0184 | 计算并保存 &#96;severity&#96;（severity），供后续逻辑使用，当前位于类 SecurityAction。 | <code>    severity: str = "medium"</code> |
| L0185 | 计算并保存 &#96;evidence_refs&#96;（evidencerefs），供后续逻辑使用，当前位于类 SecurityAction。 | <code>    evidence_refs: List[str] = field(default_factory=list)</code> |
| L0186 | 计算并保存 &#96;metadata&#96;（metadata），供后续逻辑使用，当前位于类 SecurityAction。 | <code>    metadata: Dict[str, Any] = field(default_factory=dict)</code> |
| L0187 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0188 | 定义postinit函数 &#96;__post_init__&#96;，封装可复用业务逻辑。 | <code>    def __post_init__(self) -&gt; None:</code> |
| L0189 | 计算并保存 &#96;action_type&#96;（actiontype），供后续逻辑使用，当前位于函数 __post_init__。 | <code>        self.action_type = normalize_action_type(self.action_type)</code> |
| L0190 | 计算并保存 &#96;occurred_at&#96;（occurredat），供后续逻辑使用，当前位于函数 __post_init__。 | <code>        self.occurred_at = parse_timestamp(self.occurred_at)</code> |
| L0191 | 计算并保存 &#96;last_seen_at&#96;（lastseenat），供后续逻辑使用，当前位于函数 __post_init__。 | <code>        self.last_seen_at = parse_timestamp(self.last_seen_at or self.occurred_at)</code> |
| L0192 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 __post_init__。 | <code>        self.source_ip = str(self.source_ip or "").strip()</code> |
| L0193 | 计算并保存 &#96;target_asset&#96;（targetasset），供后续逻辑使用，当前位于函数 __post_init__。 | <code>        self.target_asset = str(self.target_asset or "local-server").strip() or "local-server"</code> |
| L0194 | 计算并保存 &#96;target_interface&#96;（targetinterface），供后续逻辑使用，当前位于函数 __post_init__。 | <code>        self.target_interface = str(self.target_interface or "").strip()</code> |
| L0195 | 计算并保存 &#96;protocol&#96;（protocol），供后续逻辑使用，当前位于函数 __post_init__。 | <code>        self.protocol = str(self.protocol or "").upper().strip()</code> |
| L0196 | 计算并保存 &#96;sensor&#96;（sensor），供后续逻辑使用，当前位于函数 __post_init__。 | <code>        self.sensor = str(self.sensor or "unknown").strip()</code> |
| L0197 | 计算并保存 &#96;count&#96;（count），供后续逻辑使用，当前位于函数 __post_init__。 | <code>        self.count = max(1, int(self.count or 1))</code> |
| L0198 | 计算并保存 &#96;confidence&#96;（confidence），供后续逻辑使用，当前位于函数 __post_init__。 | <code>        self.confidence = max(0.0, min(1.0, float(self.confidence or 0.0)))</code> |
| L0199 | 计算并保存 &#96;evidence_refs&#96;（evidencerefs），供后续逻辑使用，当前位于函数 __post_init__。 | <code>        self.evidence_refs = [str(x) for x in self.evidence_refs if str(x).strip()]</code> |
| L0200 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0201 | 应用装饰器 &#96;@property&#96;，为下一定义附加权限、缓存或注册行为。 | <code>    @property</code> |
| L0202 | 定义stage函数 &#96;stage&#96;，封装可复用业务逻辑。 | <code>    def stage(self) -&gt; str:</code> |
| L0203 | 结束当前函数并把结果返回给调用方，当前位于函数 stage。 | <code>        return str(ACTION_CATALOG[self.action_type]["stage"])</code> |
| L0204 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0205 | 应用装饰器 &#96;@property&#96;，为下一定义附加权限、缓存或注册行为。 | <code>    @property</code> |
| L0206 | 定义label函数 &#96;label&#96;，封装可复用业务逻辑。 | <code>    def label(self) -&gt; str:</code> |
| L0207 | 结束当前函数并把结果返回给调用方，当前位于函数 label。 | <code>        return str(ACTION_CATALOG[self.action_type]["label"])</code> |
| L0208 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0209 | 应用装饰器 &#96;@property&#96;，为下一定义附加权限、缓存或注册行为。 | <code>    @property</code> |
| L0210 | 定义weight函数 &#96;weight&#96;，封装可复用业务逻辑。 | <code>    def weight(self) -&gt; float:</code> |
| L0211 | 结束当前函数并把结果返回给调用方，当前位于函数 weight。 | <code>        return float(ACTION_CATALOG[self.action_type]["weight"])</code> |
| L0212 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0213 | 定义asdict函数 &#96;as_dict&#96;，封装可复用业务逻辑。 | <code>    def as_dict(self) -&gt; Dict[str, Any]:</code> |
| L0214 | 结束当前函数并把结果返回给调用方，当前位于函数 as_dict。 | <code>        return {</code> |
| L0215 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "action_id": self.action_id,</code> |
| L0216 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "source_ip": self.source_ip,</code> |
| L0217 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "target_asset": self.target_asset,</code> |
| L0218 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "target_port": self.target_port,</code> |
| L0219 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "target_interface": self.target_interface,</code> |
| L0220 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "protocol": self.protocol,</code> |
| L0221 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "action_type": self.action_type,</code> |
| L0222 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "action_label": self.label,</code> |
| L0223 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "stage": self.stage,</code> |
| L0224 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "stage_label": STAGE_LABELS[self.stage],</code> |
| L0225 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "sensor": self.sensor,</code> |
| L0226 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "occurred_at": timestamp_text(self.occurred_at),</code> |
| L0227 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "last_seen_at": timestamp_text(self.last_seen_at or self.occurred_at),</code> |
| L0228 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "count": self.count,</code> |
| L0229 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "confidence": round(self.confidence, 6),</code> |
| L0230 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "severity": self.severity,</code> |
| L0231 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "evidence_refs": list(self.evidence_refs),</code> |
| L0232 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "metadata": dict(self.metadata),</code> |
| L0233 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 as_dict。 | <code>        }</code> |
| L0234 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0235 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0236 | 应用装饰器 &#96;@dataclass&#96;，为下一定义附加权限、缓存或注册行为。 | <code>@dataclass</code> |
| L0237 | 定义类 &#96;Situation&#96;，集中保存相关状态与操作。 | <code>class Situation:</code> |
| L0238 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 Situation。 | <code>    situation_id: str</code> |
| L0239 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 Situation。 | <code>    source_ip: str</code> |
| L0240 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 Situation。 | <code>    target_asset: str</code> |
| L0241 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 Situation。 | <code>    started_at: datetime</code> |
| L0242 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 Situation。 | <code>    last_action_at: datetime</code> |
| L0243 | 计算并保存 &#96;actions&#96;（actions），供后续逻辑使用，当前位于类 Situation。 | <code>    actions: List[SecurityAction] = field(default_factory=list)</code> |
| L0244 | 计算并保存 &#96;status&#96;（状态），供后续逻辑使用，当前位于类 Situation。 | <code>    status: str = "observing"</code> |
| L0245 | 计算并保存 &#96;risk_score&#96;（riskscore），供后续逻辑使用，当前位于类 Situation。 | <code>    risk_score: float = 0.0</code> |
| L0246 | 计算并保存 &#96;risk_level&#96;（risklevel），供后续逻辑使用，当前位于类 Situation。 | <code>    risk_level: str = "low"</code> |
| L0247 | 计算并保存 &#96;current_stage&#96;（currentstage），供后续逻辑使用，当前位于类 Situation。 | <code>    current_stage: str = "unknown"</code> |
| L0248 | 计算并保存 &#96;sequence_hash&#96;（sequencehash），供后续逻辑使用，当前位于类 Situation。 | <code>    sequence_hash: str = ""</code> |
| L0249 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0250 | 应用装饰器 &#96;@property&#96;，为下一定义附加权限、缓存或注册行为。 | <code>    @property</code> |
| L0251 | 定义distinctactiontypes函数 &#96;distinct_action_types&#96;，封装可复用业务逻辑。 | <code>    def distinct_action_types(self) -&gt; int:</code> |
| L0252 | 结束当前函数并把结果返回给调用方，当前位于函数 distinct_action_types。 | <code>        return len({x.action_type for x in self.actions if x.action_type != "IP_BLOCKED"})</code> |
| L0253 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0254 | 应用装饰器 &#96;@property&#96;，为下一定义附加权限、缓存或注册行为。 | <code>    @property</code> |
| L0255 | 定义totalactioncount函数 &#96;total_action_count&#96;，封装可复用业务逻辑。 | <code>    def total_action_count(self) -&gt; int:</code> |
| L0256 | 结束当前函数并把结果返回给调用方，当前位于函数 total_action_count。 | <code>        return sum(x.count for x in self.actions)</code> |
| L0257 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0258 | 定义refresh函数 &#96;refresh&#96;，封装可复用业务逻辑。 | <code>    def refresh(self, minimum_distinct_actions: int) -&gt; None:</code> |
| L0259 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 refresh。 | <code>        self.actions.sort(key=lambda x: (x.occurred_at, x.action_id))</code> |
| L0260 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 refresh。 | <code>        if self.actions:</code> |
| L0261 | 计算并保存 &#96;started_at&#96;（startedat），供后续逻辑使用，当前位于函数 refresh。 | <code>            self.started_at = self.actions[0].occurred_at</code> |
| L0262 | 计算并保存 &#96;last_action_at&#96;（lastactionat），供后续逻辑使用，当前位于函数 refresh。 | <code>            self.last_action_at = max((x.last_seen_at or x.occurred_at) for x in self.actions)</code> |
| L0263 | 计算并保存 &#96;current_stage&#96;（currentstage），供后续逻辑使用，当前位于函数 refresh。 | <code>        self.current_stage = max(</code> |
| L0264 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 refresh。 | <code>            (x.stage for x in self.actions),</code> |
| L0265 | 计算并保存 &#96;key&#96;（key），供后续逻辑使用，当前位于函数 refresh。 | <code>            key=lambda stage: STAGE_ORDER.get(stage, 0),</code> |
| L0266 | 计算并保存 &#96;default&#96;（default），供后续逻辑使用，当前位于函数 refresh。 | <code>            default="unknown",</code> |
| L0267 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 refresh。 | <code>        )</code> |
| L0268 | 计算并保存 &#96;risk_score&#96;（riskscore），供后续逻辑使用，当前位于函数 refresh。 | <code>        self.risk_score = calculate_situation_risk(self.actions)</code> |
| L0269 | 计算并保存 &#96;risk_level&#96;（risklevel），供后续逻辑使用，当前位于函数 refresh。 | <code>        self.risk_level = risk_level(self.risk_score)</code> |
| L0270 | 计算并保存 &#96;status&#96;（状态），供后续逻辑使用，当前位于函数 refresh。 | <code>        self.status = "open" if self.distinct_action_types &gt;= minimum_distinct_actions else "observing"</code> |
| L0271 | 源码原注释：Repeated hits update graph counters without calling AI for every | <code>        # Repeated hits update graph counters without calling AI for every</code> |
| L0272 | 源码原注释：packet. Refresh when the chain changes, the volume crosses a power-of- | <code>        # packet. Refresh when the chain changes, the volume crosses a power-of-</code> |
| L0273 | 源码原注释：two boundary, or activity advances into another five-minute window. | <code>        # two boundary, or activity advances into another five-minute window.</code> |
| L0274 | 源码原注释：This keeps long-running situations current while bounding AI cost. | <code>        # This keeps long-running situations current while bounding AI cost.</code> |
| L0275 | 计算并保存 &#96;material&#96;（material），供后续逻辑使用，当前位于函数 refresh。 | <code>        material = sorted({f"{x.stage}:{x.action_type}" for x in self.actions})</code> |
| L0276 | 计算并保存 &#96;count_bucket&#96;（countbucket），供后续逻辑使用，当前位于函数 refresh。 | <code>        count_bucket = int(math.log2(max(1, self.total_action_count)))</code> |
| L0277 | 计算并保存 &#96;activity_bucket&#96;（activitybucket），供后续逻辑使用，当前位于函数 refresh。 | <code>        activity_bucket = int(self.last_action_at.timestamp()) // 300</code> |
| L0278 | 计算并保存 &#96;signature&#96;（signature），供后续逻辑使用，当前位于函数 refresh。 | <code>        signature = "&#124;".join(material + [f"count:{count_bucket}", f"time:{activity_bucket}"])</code> |
| L0279 | 计算并保存 &#96;sequence_hash&#96;（sequencehash），供后续逻辑使用，当前位于函数 refresh。 | <code>        self.sequence_hash = hashlib.sha256(signature.encode("utf-8")).hexdigest()[:24]</code> |
| L0280 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0281 | 定义asdict函数 &#96;as_dict&#96;，封装可复用业务逻辑。 | <code>    def as_dict(self) -&gt; Dict[str, Any]:</code> |
| L0282 | 计算并保存 &#96;ordered&#96;（ordered），供后续逻辑使用，当前位于函数 as_dict。 | <code>        ordered = sorted(self.actions, key=lambda x: (x.occurred_at, x.action_id))</code> |
| L0283 | 计算并保存 &#96;action_rows&#96;（action数据库记录），供后续逻辑使用，当前位于函数 as_dict。 | <code>        action_rows: List[Dict[str, Any]] = []</code> |
| L0284 | 计算并保存 &#96;previous&#96;（previous），供后续逻辑使用，当前位于函数 as_dict。 | <code>        previous: Optional[SecurityAction] = None</code> |
| L0285 | 遍历集合中的数据项并逐项处理，当前位于函数 as_dict。 | <code>        for seq, action in enumerate(ordered, start=1):</code> |
| L0286 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 as_dict。 | <code>            row = action.as_dict()</code> |
| L0287 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            row["sequence"] = seq</code> |
| L0288 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            row["gap_seconds"] = (</code> |
| L0289 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>                max(0, int((action.occurred_at - (previous.last_seen_at or previous.occurred_at)).total_seconds()))</code> |
| L0290 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 as_dict。 | <code>                if previous</code> |
| L0291 | 处理前述条件均未命中的情况，当前位于函数 as_dict。 | <code>                else 0</code> |
| L0292 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 as_dict。 | <code>            )</code> |
| L0293 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 as_dict。 | <code>            action_rows.append(row)</code> |
| L0294 | 计算并保存 &#96;previous&#96;（previous），供后续逻辑使用，当前位于函数 as_dict。 | <code>            previous = action</code> |
| L0295 | 结束当前函数并把结果返回给调用方，当前位于函数 as_dict。 | <code>        return {</code> |
| L0296 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "situation_id": self.situation_id,</code> |
| L0297 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "source_ip": self.source_ip,</code> |
| L0298 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "target_asset": self.target_asset,</code> |
| L0299 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "started_at": timestamp_text(self.started_at),</code> |
| L0300 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "last_action_at": timestamp_text(self.last_action_at),</code> |
| L0301 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "duration_seconds": max(0, int((self.last_action_at - self.started_at).total_seconds())),</code> |
| L0302 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "status": self.status,</code> |
| L0303 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "distinct_action_types": self.distinct_action_types,</code> |
| L0304 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "total_action_count": self.total_action_count,</code> |
| L0305 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "current_stage": self.current_stage,</code> |
| L0306 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "current_stage_label": STAGE_LABELS[self.current_stage],</code> |
| L0307 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "risk_score": round(self.risk_score, 6),</code> |
| L0308 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "risk_level": self.risk_level,</code> |
| L0309 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "sequence_hash": self.sequence_hash,</code> |
| L0310 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 as_dict。 | <code>            "actions": action_rows,</code> |
| L0311 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 as_dict。 | <code>        }</code> |
| L0312 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0313 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0314 | 定义calculate态势risk函数 &#96;calculate_situation_risk&#96;，封装可复用业务逻辑。 | <code>def calculate_situation_risk(actions: Sequence[SecurityAction]) -&gt; float:</code> |
| L0315 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 calculate_situation_risk。 | <code>    if not actions:</code> |
| L0316 | 结束当前函数并把结果返回给调用方，当前位于函数 calculate_situation_risk。 | <code>        return 0.0</code> |
| L0317 | 计算并保存 &#96;types&#96;（types），供后续逻辑使用，当前位于函数 calculate_situation_risk。 | <code>    types = {x.action_type for x in actions if x.action_type != "IP_BLOCKED"}</code> |
| L0318 | 计算并保存 &#96;stages&#96;（stages），供后续逻辑使用，当前位于函数 calculate_situation_risk。 | <code>    stages = {x.stage for x in actions if x.stage not in {"unknown", "impact"}}</code> |
| L0319 | 计算并保存 &#96;action_danger&#96;（actiondanger），供后续逻辑使用，当前位于函数 calculate_situation_risk。 | <code>    action_danger = max((x.weight for x in actions), default=0.0)</code> |
| L0320 | 计算并保存 &#96;confidence&#96;（confidence），供后续逻辑使用，当前位于函数 calculate_situation_risk。 | <code>    confidence = max((x.confidence for x in actions), default=0.0)</code> |
| L0321 | 计算并保存 &#96;severity&#96;（severity），供后续逻辑使用，当前位于函数 calculate_situation_risk。 | <code>    severity = max((severity_value(x.severity) for x in actions), default=0.0)</code> |
| L0322 | 计算并保存 &#96;diversity&#96;（diversity），供后续逻辑使用，当前位于函数 calculate_situation_risk。 | <code>    diversity = min(1.0, len(types) / 5.0)</code> |
| L0323 | 计算并保存 &#96;stage_depth&#96;（stagedepth），供后续逻辑使用，当前位于函数 calculate_situation_risk。 | <code>    stage_depth = min(1.0, max((STAGE_ORDER.get(x.stage, 0) for x in actions), default=0) / 4.0)</code> |
| L0324 | 计算并保存 &#96;frequency&#96;（frequency），供后续逻辑使用，当前位于函数 calculate_situation_risk。 | <code>    frequency = min(1.0, sum(x.count for x in actions) / 100.0)</code> |
| L0325 | 计算并保存 &#96;progression&#96;（progression），供后续逻辑使用，当前位于函数 calculate_situation_risk。 | <code>    progression = min(1.0, len(stages) / 3.0)</code> |
| L0326 | 计算并保存 &#96;score&#96;（score），供后续逻辑使用，当前位于函数 calculate_situation_risk。 | <code>    score = (</code> |
| L0327 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calculate_situation_risk。 | <code>        action_danger * 0.25</code> |
| L0328 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calculate_situation_risk。 | <code>        + confidence * 0.20</code> |
| L0329 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calculate_situation_risk。 | <code>        + severity * 0.15</code> |
| L0330 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calculate_situation_risk。 | <code>        + diversity * 0.15</code> |
| L0331 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calculate_situation_risk。 | <code>        + stage_depth * 0.10</code> |
| L0332 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calculate_situation_risk。 | <code>        + frequency * 0.05</code> |
| L0333 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calculate_situation_risk。 | <code>        + progression * 0.10</code> |
| L0334 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 calculate_situation_risk。 | <code>    )</code> |
| L0335 | 结束当前函数并把结果返回给调用方，当前位于函数 calculate_situation_risk。 | <code>    return round(max(0.0, min(1.0, score)), 6)</code> |
| L0336 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0337 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0338 | 定义聚合actions函数 &#96;aggregate_actions&#96;，封装可复用业务逻辑。 | <code>def aggregate_actions(actions: Sequence[SecurityAction]) -&gt; List[SecurityAction]:</code> |
| L0339 | 计算并保存 &#96;grouped&#96;（grouped），供后续逻辑使用，当前位于函数 aggregate_actions。 | <code>    grouped: Dict[Tuple[str, str, str, Optional[int], str], SecurityAction] = {}</code> |
| L0340 | 遍历集合中的数据项并逐项处理，当前位于函数 aggregate_actions。 | <code>    for action in sorted(actions, key=lambda x: (x.occurred_at, x.action_id)):</code> |
| L0341 | 计算并保存 &#96;key&#96;（key），供后续逻辑使用，当前位于函数 aggregate_actions。 | <code>        key = (</code> |
| L0342 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_actions。 | <code>            action.source_ip,</code> |
| L0343 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_actions。 | <code>            action.target_asset,</code> |
| L0344 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_actions。 | <code>            action.action_type,</code> |
| L0345 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_actions。 | <code>            action.target_port,</code> |
| L0346 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_actions。 | <code>            action.target_interface,</code> |
| L0347 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 aggregate_actions。 | <code>        )</code> |
| L0348 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 aggregate_actions。 | <code>        current = grouped.get(key)</code> |
| L0349 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 aggregate_actions。 | <code>        if current is None:</code> |
| L0350 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_actions。 | <code>            grouped[key] = SecurityAction(</code> |
| L0351 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_actions。 | <code>                **{</code> |
| L0352 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_actions。 | <code>                    **action.__dict__,</code> |
| L0353 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_actions。 | <code>                    "evidence_refs": list(action.evidence_refs),</code> |
| L0354 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_actions。 | <code>                    "metadata": deepcopy(action.metadata),</code> |
| L0355 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 aggregate_actions。 | <code>                }</code> |
| L0356 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 aggregate_actions。 | <code>            )</code> |
| L0357 | 控制当前循环或占位分支的执行流程，当前位于函数 aggregate_actions。 | <code>            continue</code> |
| L0358 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_actions。 | <code>        current.occurred_at = min(current.occurred_at, action.occurred_at)</code> |
| L0359 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_actions。 | <code>        current.last_seen_at = max(current.last_seen_at or current.occurred_at, action.last_seen_at or action.occurred_at)</code> |
| L0360 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_actions。 | <code>        current.count += action.count</code> |
| L0361 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_actions。 | <code>        current.confidence = max(current.confidence, action.confidence)</code> |
| L0362 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 aggregate_actions。 | <code>        if severity_value(action.severity) &gt; severity_value(current.severity):</code> |
| L0363 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_actions。 | <code>            current.severity = action.severity</code> |
| L0364 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_actions。 | <code>        current.evidence_refs = list(dict.fromkeys(current.evidence_refs + action.evidence_refs))</code> |
| L0365 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_actions。 | <code>        current.metadata = {**current.metadata, **action.metadata}</code> |
| L0366 | 结束当前函数并把结果返回给调用方，当前位于函数 aggregate_actions。 | <code>    return sorted(grouped.values(), key=lambda x: (x.occurred_at, x.action_id))</code> |
| L0367 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0368 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0369 | 定义类 &#96;SituationCorrelator&#96;，集中保存相关状态与操作。 | <code>class SituationCorrelator:</code> |
| L0370 | 定义init函数 &#96;__init__&#96;，封装可复用业务逻辑。 | <code>    def __init__(</code> |
| L0371 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>        self,</code> |
| L0372 | 计算并保存 &#96;minimum_distinct_actions&#96;（minimumdistinctactions），供后续逻辑使用，当前位于函数 __init__。 | <code>        minimum_distinct_actions: int = 3,</code> |
| L0373 | 计算并保存 &#96;window_minutes&#96;（windowminutes），供后续逻辑使用，当前位于函数 __init__。 | <code>        window_minutes: int = 30,</code> |
| L0374 | 计算并保存 &#96;inactivity_minutes&#96;（inactivityminutes），供后续逻辑使用，当前位于函数 __init__。 | <code>        inactivity_minutes: int = 15,</code> |
| L0375 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 __init__。 | <code>    ) -&gt; None:</code> |
| L0376 | 计算并保存 &#96;minimum_distinct_actions&#96;（minimumdistinctactions），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.minimum_distinct_actions = max(2, int(minimum_distinct_actions))</code> |
| L0377 | 计算并保存 &#96;window&#96;（window），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.window = timedelta(minutes=max(1, int(window_minutes)))</code> |
| L0378 | 计算并保存 &#96;inactivity&#96;（inactivity），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.inactivity = timedelta(minutes=max(1, int(inactivity_minutes)))</code> |
| L0379 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0380 | 定义correlate函数 &#96;correlate&#96;，封装可复用业务逻辑。 | <code>    def correlate(self, actions: Iterable[SecurityAction], include_observing: bool = True) -&gt; List[Situation]:</code> |
| L0381 | 计算并保存 &#96;valid&#96;（valid），供后续逻辑使用，当前位于函数 correlate。 | <code>        valid = [x for x in actions if x.source_ip]</code> |
| L0382 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 correlate。 | <code>        valid.sort(key=lambda x: (x.source_ip, x.target_asset, x.occurred_at, x.action_id))</code> |
| L0383 | 计算并保存 &#96;grouped&#96;（grouped），供后续逻辑使用，当前位于函数 correlate。 | <code>        grouped: Dict[Tuple[str, str], List[SecurityAction]] = {}</code> |
| L0384 | 遍历集合中的数据项并逐项处理，当前位于函数 correlate。 | <code>        for action in valid:</code> |
| L0385 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 correlate。 | <code>            grouped.setdefault((action.source_ip, action.target_asset), []).append(action)</code> |
| L0386 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0387 | 计算并保存 &#96;situations&#96;（situations），供后续逻辑使用，当前位于函数 correlate。 | <code>        situations: List[Situation] = []</code> |
| L0388 | 遍历集合中的数据项并逐项处理，当前位于函数 correlate。 | <code>        for (source_ip, target_asset), rows in grouped.items():</code> |
| L0389 | 计算并保存 &#96;bucket&#96;（bucket），供后续逻辑使用，当前位于函数 correlate。 | <code>            bucket: List[SecurityAction] = []</code> |
| L0390 | 遍历集合中的数据项并逐项处理，当前位于函数 correlate。 | <code>            for action in rows:</code> |
| L0391 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 correlate。 | <code>                if bucket:</code> |
| L0392 | 计算并保存 &#96;first&#96;（first），供后续逻辑使用，当前位于函数 correlate。 | <code>                    first = bucket[0].occurred_at</code> |
| L0393 | 计算并保存 &#96;last&#96;（last），供后续逻辑使用，当前位于函数 correlate。 | <code>                    last = max((x.last_seen_at or x.occurred_at) for x in bucket)</code> |
| L0394 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 correlate。 | <code>                    if action.occurred_at - last &gt; self.inactivity or action.occurred_at - first &gt; self.window:</code> |
| L0395 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 correlate。 | <code>                        situations.append(self._build(source_ip, target_asset, bucket))</code> |
| L0396 | 计算并保存 &#96;bucket&#96;（bucket），供后续逻辑使用，当前位于函数 correlate。 | <code>                        bucket = []</code> |
| L0397 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 correlate。 | <code>                bucket.append(action)</code> |
| L0398 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 correlate。 | <code>            if bucket:</code> |
| L0399 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 correlate。 | <code>                situations.append(self._build(source_ip, target_asset, bucket))</code> |
| L0400 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0401 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 correlate。 | <code>        if not include_observing:</code> |
| L0402 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 correlate。 | <code>            situations = [x for x in situations if x.status == "open"]</code> |
| L0403 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 correlate。 | <code>        situations.sort(key=lambda x: x.last_action_at, reverse=True)</code> |
| L0404 | 结束当前函数并把结果返回给调用方，当前位于函数 correlate。 | <code>        return situations</code> |
| L0405 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0406 | 定义构建函数 &#96;_build&#96;，封装可复用业务逻辑。 | <code>    def _build(self, source_ip: str, target_asset: str, rows: Sequence[SecurityAction]) -&gt; Situation:</code> |
| L0407 | 计算并保存 &#96;aggregated&#96;（aggregated），供后续逻辑使用，当前位于函数 _build。 | <code>        aggregated = aggregate_actions(rows)</code> |
| L0408 | 计算并保存 &#96;first&#96;（first），供后续逻辑使用，当前位于函数 _build。 | <code>        first = min(x.occurred_at for x in aggregated)</code> |
| L0409 | 源码原注释：Captured files from one burst may reach MySQL out of order. Using the | <code>        # Captured files from one burst may reach MySQL out of order. Using the</code> |
| L0410 | 源码原注释：earliest individual packet made the situation ID change whenever an | <code>        # earliest individual packet made the situation ID change whenever an</code> |
| L0411 | 源码原注释：older packet arrived a few seconds later, leaving stale partial chains | <code>        # older packet arrived a few seconds later, leaving stale partial chains</code> |
| L0412 | 源码原注释：beside the completed one. Anchor the identity to the correlation | <code>        # beside the completed one. Anchor the identity to the correlation</code> |
| L0413 | 源码原注释：window instead; the exact start time remains available in started_at. | <code>        # window instead; the exact start time remains available in started_at.</code> |
| L0414 | 源码原注释：The inactivity bucket is also the session boundary. It keeps a | <code>        # The inactivity bucket is also the session boundary. It keeps a</code> |
| L0415 | 源码原注释：partially observed burst stable when its files arrive out of order, | <code>        # partially observed burst stable when its files arrive out of order,</code> |
| L0416 | 源码原注释：while two bursts separated by the configured idle gap cannot collide. | <code>        # while two bursts separated by the configured idle gap cannot collide.</code> |
| L0417 | 计算并保存 &#96;bucket_seconds&#96;（bucketseconds），供后续逻辑使用，当前位于函数 _build。 | <code>        bucket_seconds = max(60, int(self.inactivity.total_seconds()))</code> |
| L0418 | 计算并保存 &#96;first_epoch&#96;（firstepoch），供后续逻辑使用，当前位于函数 _build。 | <code>        first_epoch = int(first.timestamp())</code> |
| L0419 | 计算并保存 &#96;bucket_start&#96;（bucket启动），供后续逻辑使用，当前位于函数 _build。 | <code>        bucket_start = datetime.fromtimestamp(</code> |
| L0420 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build。 | <code>            first_epoch - (first_epoch % bucket_seconds),</code> |
| L0421 | 计算并保存 &#96;tz&#96;（tz），供后续逻辑使用，当前位于函数 _build。 | <code>            tz=timezone.utc,</code> |
| L0422 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _build。 | <code>        )</code> |
| L0423 | 计算并保存 &#96;token&#96;（token），供后续逻辑使用，当前位于函数 _build。 | <code>        token = f"{source_ip}&#124;{target_asset}&#124;{timestamp_text(bucket_start)}"</code> |
| L0424 | 计算并保存 &#96;situation_id&#96;（态势id），供后续逻辑使用，当前位于函数 _build。 | <code>        situation_id = "SIT-" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:20].upper()</code> |
| L0425 | 计算并保存 &#96;situation&#96;（态势），供后续逻辑使用，当前位于函数 _build。 | <code>        situation = Situation(</code> |
| L0426 | 计算并保存 &#96;situation_id&#96;（态势id），供后续逻辑使用，当前位于函数 _build。 | <code>            situation_id=situation_id,</code> |
| L0427 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 _build。 | <code>            source_ip=source_ip,</code> |
| L0428 | 计算并保存 &#96;target_asset&#96;（targetasset），供后续逻辑使用，当前位于函数 _build。 | <code>            target_asset=target_asset,</code> |
| L0429 | 计算并保存 &#96;started_at&#96;（startedat），供后续逻辑使用，当前位于函数 _build。 | <code>            started_at=first,</code> |
| L0430 | 计算并保存 &#96;last_action_at&#96;（lastactionat），供后续逻辑使用，当前位于函数 _build。 | <code>            last_action_at=max((x.last_seen_at or x.occurred_at) for x in aggregated),</code> |
| L0431 | 计算并保存 &#96;actions&#96;（actions），供后续逻辑使用，当前位于函数 _build。 | <code>            actions=aggregated,</code> |
| L0432 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _build。 | <code>        )</code> |
| L0433 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build。 | <code>        situation.refresh(self.minimum_distinct_actions)</code> |
| L0434 | 结束当前函数并把结果返回给调用方，当前位于函数 _build。 | <code>        return situation</code> |
| L0435 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0436 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0437 | 定义actionfrom攻击事件函数 &#96;action_from_attack_event&#96;，封装可复用业务逻辑。 | <code>def action_from_attack_event(row: Dict[str, Any], target_asset: str = "local-server") -&gt; SecurityAction:</code> |
| L0438 | 计算并保存 &#96;event_id&#96;（事件id），供后续逻辑使用，当前位于函数 action_from_attack_event。 | <code>    event_id = str(row.get("event_id") or row.get("case_id") or "")</code> |
| L0439 | 计算并保存 &#96;action_type&#96;（actiontype），供后续逻辑使用，当前位于函数 action_from_attack_event。 | <code>    action_type = normalize_action_type(row.get("attack_type"))</code> |
| L0440 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 action_from_attack_event。 | <code>    evidence = row.get("evidence_json")</code> |
| L0441 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 action_from_attack_event。 | <code>    if isinstance(evidence, str):</code> |
| L0442 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 action_from_attack_event。 | <code>        try:</code> |
| L0443 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 action_from_attack_event。 | <code>            evidence = json.loads(evidence)</code> |
| L0444 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 action_from_attack_event。 | <code>        except Exception:</code> |
| L0445 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 action_from_attack_event。 | <code>            evidence = [evidence] if evidence.strip() else []</code> |
| L0446 | 结束当前函数并把结果返回给调用方，当前位于函数 action_from_attack_event。 | <code>    return SecurityAction(</code> |
| L0447 | 计算并保存 &#96;action_id&#96;（actionid），供后续逻辑使用，当前位于函数 action_from_attack_event。 | <code>        action_id=f"ACT-{event_id or hashlib.sha1(json.dumps(row, sort_keys=True, default=str).encode()).hexdigest()[:16]}",</code> |
| L0448 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 action_from_attack_event。 | <code>        source_ip=str(row.get("source_ip") or ""),</code> |
| L0449 | 计算并保存 &#96;target_asset&#96;（targetasset），供后续逻辑使用，当前位于函数 action_from_attack_event。 | <code>        target_asset=str(row.get("target_asset") or row.get("target_node") or target_asset),</code> |
| L0450 | 计算并保存 &#96;target_port&#96;（targetport），供后续逻辑使用，当前位于函数 action_from_attack_event。 | <code>        target_port=int(row["target_port"]) if str(row.get("target_port") or "").isdigit() else None,</code> |
| L0451 | 计算并保存 &#96;target_interface&#96;（targetinterface），供后续逻辑使用，当前位于函数 action_from_attack_event。 | <code>        target_interface=str(row.get("target_interface") or row.get("uri") or ""),</code> |
| L0452 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 action_from_attack_event。 | <code>        protocol=str(row.get("protocol") or ("SSH" if action_type == "SSH_BRUTEFORCE" else "HTTP")),</code> |
| L0453 | 计算并保存 &#96;action_type&#96;（actiontype），供后续逻辑使用，当前位于函数 action_from_attack_event。 | <code>        action_type=action_type,</code> |
| L0454 | 计算并保存 &#96;occurred_at&#96;（occurredat），供后续逻辑使用，当前位于函数 action_from_attack_event。 | <code>        occurred_at=parse_timestamp(row.get("occurred_at") or row.get("event_time") or row.get("created_at")),</code> |
| L0455 | 计算并保存 &#96;sensor&#96;（sensor），供后续逻辑使用，当前位于函数 action_from_attack_event。 | <code>        sensor=str(row.get("sensor") or "detection_v2"),</code> |
| L0456 | 计算并保存 &#96;count&#96;（count），供后续逻辑使用，当前位于函数 action_from_attack_event。 | <code>        count=int(row.get("request_count") or row.get("count") or 1),</code> |
| L0457 | 计算并保存 &#96;confidence&#96;（confidence），供后续逻辑使用，当前位于函数 action_from_attack_event。 | <code>        confidence=float(row.get("confidence") or row.get("final_score") or 0.0),</code> |
| L0458 | 计算并保存 &#96;severity&#96;（severity），供后续逻辑使用，当前位于函数 action_from_attack_event。 | <code>        severity=str(row.get("risk_level") or row.get("severity") or "medium"),</code> |
| L0459 | 计算并保存 &#96;evidence_refs&#96;（evidencerefs），供后续逻辑使用，当前位于函数 action_from_attack_event。 | <code>        evidence_refs=[event_id] if event_id else [],</code> |
| L0460 | 计算并保存 &#96;metadata&#96;（metadata），供后续逻辑使用，当前位于函数 action_from_attack_event。 | <code>        metadata={"evidence": evidence or []},</code> |
| L0461 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 action_from_attack_event。 | <code>    )</code> |
