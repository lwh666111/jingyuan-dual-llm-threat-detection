# `scripts/extract_old_model_features_from_txt.py` 逐行注释

**脚本用途：** 辅助脚本：根据文件名 `extract_old_model_features_from_txt.py` 完成对应的数据处理或运维任务。

**源码行数：** 897　**函数/类数量：** 34

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0002 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import logging&#96;。 | <code>import logging</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import re&#96;。 | <code>import re</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Dict, List, Optional, Tuple&#96;。 | <code>from typing import Dict, List, Optional, Tuple</code> |
| L0007 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;import joblib&#96;。 | <code>import joblib</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;import pandas as pd&#96;。 | <code>import pandas as pd</code> |
| L0010 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0011 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")</code> |
| L0012 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0013 | 计算并保存 &#96;STATIC_EXTENSIONS&#96;（STATICEXTENSIONS），供后续逻辑使用。 | <code>STATIC_EXTENSIONS = {</code> |
| L0014 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ".js",</code> |
| L0015 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ".css",</code> |
| L0016 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ".png",</code> |
| L0017 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ".jpg",</code> |
| L0018 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ".jpeg",</code> |
| L0019 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ".gif",</code> |
| L0020 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ".svg",</code> |
| L0021 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ".ico",</code> |
| L0022 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ".woff",</code> |
| L0023 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ".woff2",</code> |
| L0024 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ".map",</code> |
| L0025 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>}</code> |
| L0026 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0027 | 计算并保存 &#96;SQL_KEYWORDS&#96;（SQLKEYWORDS），供后续逻辑使用。 | <code>SQL_KEYWORDS = [</code> |
| L0028 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    " or ",</code> |
| L0029 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "or1=1",</code> |
| L0030 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "or 1=1",</code> |
| L0031 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "union",</code> |
| L0032 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "select",</code> |
| L0033 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "sleep(",</code> |
| L0034 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "benchmark(",</code> |
| L0035 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "--",</code> |
| L0036 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "../",</code> |
| L0037 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "%27",</code> |
| L0038 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "%3c",</code> |
| L0039 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "%3e",</code> |
| L0040 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "'",</code> |
| L0041 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>]</code> |
| L0042 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0043 | 计算并保存 &#96;WEB_ATTACK_PATTERNS&#96;（WEB攻击PATTERNS），供后续逻辑使用。 | <code>WEB_ATTACK_PATTERNS = {</code> |
| L0044 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "sql": [</code> |
| L0045 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"\bunion\s+(?:all\s+)?select\b",</code> |
| L0046 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"(?:'&#124;\")?\s*\bor\b\s+(?:'&#124;\")?\d+(?:'&#124;\")?\s*=\s*(?:'&#124;\")?\d+",</code> |
| L0047 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"\binformation_schema\b",</code> |
| L0048 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"\bsleep\s*\(",</code> |
| L0049 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"\bbenchmark\s*\(",</code> |
| L0050 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"(?:--&#124;#&#124;/\*)",</code> |
| L0051 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0052 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "xss": [</code> |
| L0053 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"&lt;\s*/?\s*script\b",</code> |
| L0054 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"\bon(?:error&#124;load&#124;click&#124;mouseover&#124;focus&#124;submit)\s*=",</code> |
| L0055 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"\bjavascript\s*:",</code> |
| L0056 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"\balert\s*\(",</code> |
| L0057 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"\bdocument\s*\.\s*cookie\b",</code> |
| L0058 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0059 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "command": [</code> |
| L0060 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"(?:;&#124;\&#124;\&#124;&#124;&amp;&amp;)\s*(?:cat&#124;whoami&#124;id&#124;uname&#124;curl&#124;wget&#124;powershell&#124;cmd\.exe&#124;nc&#124;bash&#124;sh)\b",</code> |
| L0061 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"\b(?:powershell&#124;cmd\.exe&#124;/bin/sh&#124;/bin/bash)\b",</code> |
| L0062 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "traversal": [</code> |
| L0064 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"(?:\.\./&#124;\.\.\\){2,}",</code> |
| L0065 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"(?:/etc/passwd&#124;/etc/shadow&#124;\\windows\\system32\\config)",</code> |
| L0066 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0067 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "ssrf": [</code> |
| L0068 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"(?:url&#124;target&#124;redirect&#124;callback&#124;next)\s*=\s*(?:https?://)?(?:127\.0\.0\.1&#124;localhost&#124;0\.0\.0\.0&#124;10\.&#124;172\.(?:1[6-9]&#124;2\d&#124;3[01])\.&#124;192\.168\.)",</code> |
| L0069 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"(?:url&#124;target&#124;redirect&#124;callback&#124;next)\s*=\s*file://",</code> |
| L0070 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0071 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "upload": [</code> |
| L0072 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"filename\s*=\s*[\"']?[^\"'\r\n]+\.(?:php&#124;jsp&#124;jspx&#124;asp&#124;aspx&#124;exe&#124;bat&#124;cmd&#124;ps1&#124;sh)\b",</code> |
| L0073 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0074 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "xxe": [</code> |
| L0075 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"&lt;!doctype\s+\w+\s+\[",</code> |
| L0076 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"&lt;!entity\b",</code> |
| L0077 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"system\s+[\"']file://",</code> |
| L0078 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0079 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "ssti": [</code> |
| L0080 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"\{\{\s*[^}]*(?:config&#124;class&#124;mro&#124;subclasses&#124;request&#124;cycler&#124;joiner)[^}]*\}\}",</code> |
| L0081 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"\$\{\s*[^}]*(?:runtime&#124;processbuilder&#124;jndi&#124;script)[^}]*\}",</code> |
| L0082 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0083 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "deserialize": [</code> |
| L0084 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"\brO0AB",</code> |
| L0085 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"\bO:\d+:",</code> |
| L0086 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"ysoserial",</code> |
| L0087 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0088 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "graphql": [</code> |
| L0089 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"__schema",</code> |
| L0090 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"__typename",</code> |
| L0091 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        r"mutation\s*\{",</code> |
| L0092 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0093 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>}</code> |
| L0094 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0095 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0096 | 定义读取textfile函数 &#96;read_text_file&#96;，封装可复用业务逻辑。 | <code>def read_text_file(path: Path) -&gt; str:</code> |
| L0097 | 遍历集合中的数据项并逐项处理，当前位于函数 read_text_file。 | <code>    for encoding in ("utf-8", "utf-8-sig", "gbk", "latin1"):</code> |
| L0098 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 read_text_file。 | <code>        try:</code> |
| L0099 | 结束当前函数并把结果返回给调用方，当前位于函数 read_text_file。 | <code>            return path.read_text(encoding=encoding)</code> |
| L0100 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 read_text_file。 | <code>        except UnicodeDecodeError:</code> |
| L0101 | 控制当前循环或占位分支的执行流程，当前位于函数 read_text_file。 | <code>            continue</code> |
| L0102 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 read_text_file。 | <code>    raise RuntimeError(f"无法解码文件: {path}")</code> |
| L0103 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0104 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0105 | 定义iscanonical格式化函数 &#96;is_canonical_format&#96;，封装可复用业务逻辑。 | <code>def is_canonical_format(text: str) -&gt; bool:</code> |
| L0106 | 结束当前函数并把结果返回给调用方，当前位于函数 is_canonical_format。 | <code>    return "### BATCH_START ###" in text and "### CASE_START ###" in text</code> |
| L0107 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0108 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0109 | 定义splitblocks函数 &#96;split_blocks&#96;，封装可复用业务逻辑。 | <code>def split_blocks(text: str) -&gt; List[str]:</code> |
| L0110 | 计算并保存 &#96;normalized&#96;（normalized），供后续逻辑使用，当前位于函数 split_blocks。 | <code>    normalized = text.replace("\r\n", "\n")</code> |
| L0111 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0112 | 计算并保存 &#96;pattern_header&#96;（patternheader），供后续逻辑使用，当前位于函数 split_blocks。 | <code>    pattern_header = re.compile(</code> |
| L0113 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 split_blocks。 | <code>        r"(?=^No\.\s+Time\s+Source\s+Destination\s+Protocol\s+Length\s+Info)", re.MULTILINE</code> |
| L0114 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 split_blocks。 | <code>    )</code> |
| L0115 | 计算并保存 &#96;parts&#96;（parts），供后续逻辑使用，当前位于函数 split_blocks。 | <code>    parts = [p.strip() for p in pattern_header.split(normalized) if p.strip()]</code> |
| L0116 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 split_blocks。 | <code>    if len(parts) &gt; 1:</code> |
| L0117 | 结束当前函数并把结果返回给调用方，当前位于函数 split_blocks。 | <code>        return parts</code> |
| L0118 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0119 | 计算并保存 &#96;pattern_frame&#96;（patternframe），供后续逻辑使用，当前位于函数 split_blocks。 | <code>    pattern_frame = re.compile(r"(?=^Frame\s+\d+\s*:)", re.MULTILINE)</code> |
| L0120 | 计算并保存 &#96;parts&#96;（parts），供后续逻辑使用，当前位于函数 split_blocks。 | <code>    parts = [p.strip() for p in pattern_frame.split(normalized) if p.strip()]</code> |
| L0121 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 split_blocks。 | <code>    if len(parts) &gt; 1:</code> |
| L0122 | 结束当前函数并把结果返回给调用方，当前位于函数 split_blocks。 | <code>        return parts</code> |
| L0123 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0124 | 计算并保存 &#96;summary_re&#96;（summaryre），供后续逻辑使用，当前位于函数 split_blocks。 | <code>    summary_re = re.compile(r"^\s*\d+\s+[0-9.]+\s+\S+\s+\S+\s+\S+\s+\d+\s+.+$")</code> |
| L0125 | 计算并保存 &#96;lines&#96;（lines），供后续逻辑使用，当前位于函数 split_blocks。 | <code>    lines = normalized.split("\n")</code> |
| L0126 | 计算并保存 &#96;blocks&#96;（blocks），供后续逻辑使用，当前位于函数 split_blocks。 | <code>    blocks: List[str] = []</code> |
| L0127 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 split_blocks。 | <code>    current: List[str] = []</code> |
| L0128 | 遍历集合中的数据项并逐项处理，当前位于函数 split_blocks。 | <code>    for line in lines:</code> |
| L0129 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 split_blocks。 | <code>        if summary_re.match(line) and current:</code> |
| L0130 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 split_blocks。 | <code>            blocks.append("\n".join(current).strip())</code> |
| L0131 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 split_blocks。 | <code>            current = [line]</code> |
| L0132 | 处理前述条件均未命中的情况，当前位于函数 split_blocks。 | <code>        else:</code> |
| L0133 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 split_blocks。 | <code>            current.append(line)</code> |
| L0134 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 split_blocks。 | <code>    if current:</code> |
| L0135 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 split_blocks。 | <code>        blocks.append("\n".join(current).strip())</code> |
| L0136 | 结束当前函数并把结果返回给调用方，当前位于函数 split_blocks。 | <code>    return [b for b in blocks if b]</code> |
| L0137 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0138 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0139 | 定义extractfirst函数 &#96;extract_first&#96;，封装可复用业务逻辑。 | <code>def extract_first(pattern: str, text: str, flags=0) -&gt; Optional[str]:</code> |
| L0140 | 计算并保存 &#96;m&#96;（m），供后续逻辑使用，当前位于函数 extract_first。 | <code>    m = re.search(pattern, text, flags)</code> |
| L0141 | 结束当前函数并把结果返回给调用方，当前位于函数 extract_first。 | <code>    return m.group(1) if m else None</code> |
| L0142 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0143 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0144 | 定义ishttprequest封禁函数 &#96;is_http_request_block&#96;，封装可复用业务逻辑。 | <code>def is_http_request_block(block: str) -&gt; bool:</code> |
| L0145 | 结束当前函数并把结果返回给调用方，当前位于函数 is_http_request_block。 | <code>    return bool(</code> |
| L0146 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 is_http_request_block。 | <code>        re.search(r"^\s*(GET&#124;POST&#124;PUT&#124;DELETE&#124;PATCH&#124;HEAD&#124;OPTIONS)\s+\S+\s+HTTP/1\.[01]", block, re.MULTILINE)</code> |
| L0147 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 is_http_request_block。 | <code>    )</code> |
| L0148 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0149 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0150 | 定义ishttpresponse封禁函数 &#96;is_http_response_block&#96;，封装可复用业务逻辑。 | <code>def is_http_response_block(block: str) -&gt; bool:</code> |
| L0151 | 结束当前函数并把结果返回给调用方，当前位于函数 is_http_response_block。 | <code>    return bool(re.search(r"^\s*HTTP/1\.[01]\s+\d{3}", block, re.MULTILINE))</code> |
| L0152 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0153 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0154 | 定义isstaticresource函数 &#96;is_static_resource&#96;，封装可复用业务逻辑。 | <code>def is_static_resource(uri: Optional[str]) -&gt; bool:</code> |
| L0155 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_static_resource。 | <code>    if not uri:</code> |
| L0156 | 结束当前函数并把结果返回给调用方，当前位于函数 is_static_resource。 | <code>        return False</code> |
| L0157 | 计算并保存 &#96;uri_lower&#96;（urilower），供后续逻辑使用，当前位于函数 is_static_resource。 | <code>    uri_lower = uri.lower().split("?", 1)[0]</code> |
| L0158 | 结束当前函数并把结果返回给调用方，当前位于函数 is_static_resource。 | <code>    return any(uri_lower.endswith(ext) for ext in STATIC_EXTENSIONS)</code> |
| L0159 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0160 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0161 | 定义masksensitivetext函数 &#96;mask_sensitive_text&#96;，封装可复用业务逻辑。 | <code>def mask_sensitive_text(text: str) -&gt; str:</code> |
| L0162 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 mask_sensitive_text。 | <code>    if not text:</code> |
| L0163 | 结束当前函数并把结果返回给调用方，当前位于函数 mask_sensitive_text。 | <code>        return text</code> |
| L0164 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 mask_sensitive_text。 | <code>    text = re.sub(r'("password"\s*:\s*")[^"]+(")', r"\1***\2", text, flags=re.I)</code> |
| L0165 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 mask_sensitive_text。 | <code>    text = re.sub(r"(?i)(Authorization:\s*)(.+)", r"\1***", text)</code> |
| L0166 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 mask_sensitive_text。 | <code>    text = re.sub(r"(?i)(Cookie:\s*)(.+)", r"\1***", text)</code> |
| L0167 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 mask_sensitive_text。 | <code>    text = re.sub(r"(data:image/[^;]+;base64,)[A-Za-z0-9+/=]{100,}", r"\1&lt;BASE64_TRUNCATED&gt;", text)</code> |
| L0168 | 结束当前函数并把结果返回给调用方，当前位于函数 mask_sensitive_text。 | <code>    return text</code> |
| L0169 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0170 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0171 | 定义ismostlyreadable函数 &#96;_is_mostly_readable&#96;，封装可复用业务逻辑。 | <code>def _is_mostly_readable(text: str) -&gt; bool:</code> |
| L0172 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _is_mostly_readable。 | <code>    if not text:</code> |
| L0173 | 结束当前函数并把结果返回给调用方，当前位于函数 _is_mostly_readable。 | <code>        return False</code> |
| L0174 | 计算并保存 &#96;bad&#96;（bad），供后续逻辑使用，当前位于函数 _is_mostly_readable。 | <code>    bad = 0</code> |
| L0175 | 计算并保存 &#96;total&#96;（total），供后续逻辑使用，当前位于函数 _is_mostly_readable。 | <code>    total = 0</code> |
| L0176 | 遍历集合中的数据项并逐项处理，当前位于函数 _is_mostly_readable。 | <code>    for ch in text:</code> |
| L0177 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _is_mostly_readable。 | <code>        total += 1</code> |
| L0178 | 计算并保存 &#96;code&#96;（code），供后续逻辑使用，当前位于函数 _is_mostly_readable。 | <code>        code = ord(ch)</code> |
| L0179 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _is_mostly_readable。 | <code>        if code in (9, 10, 13):</code> |
| L0180 | 控制当前循环或占位分支的执行流程，当前位于函数 _is_mostly_readable。 | <code>            continue</code> |
| L0181 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _is_mostly_readable。 | <code>        if code &lt; 32 or code == 127:</code> |
| L0182 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _is_mostly_readable。 | <code>            bad += 1</code> |
| L0183 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _is_mostly_readable。 | <code>    if total == 0:</code> |
| L0184 | 结束当前函数并把结果返回给调用方，当前位于函数 _is_mostly_readable。 | <code>        return False</code> |
| L0185 | 结束当前函数并把结果返回给调用方，当前位于函数 _is_mostly_readable。 | <code>    return (bad / total) &lt;= 0.1</code> |
| L0186 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0187 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0188 | 定义decodehexpayloadifneeded函数 &#96;decode_hex_payload_if_needed&#96;，封装可复用业务逻辑。 | <code>def decode_hex_payload_if_needed(value: str) -&gt; str:</code> |
| L0189 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 decode_hex_payload_if_needed。 | <code>    raw = str(value or "").strip()</code> |
| L0190 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_hex_payload_if_needed。 | <code>    if not raw:</code> |
| L0191 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_hex_payload_if_needed。 | <code>        return ""</code> |
| L0192 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0193 | 计算并保存 &#96;compact&#96;（compact），供后续逻辑使用，当前位于函数 decode_hex_payload_if_needed。 | <code>    compact = raw</code> |
| L0194 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_hex_payload_if_needed。 | <code>    if re.fullmatch(r"(?:[0-9A-Fa-f]{2}:)+[0-9A-Fa-f]{2}", compact):</code> |
| L0195 | 计算并保存 &#96;compact&#96;（compact），供后续逻辑使用，当前位于函数 decode_hex_payload_if_needed。 | <code>        compact = compact.replace(":", "")</code> |
| L0196 | 当前一条件未命中时继续判断另一条件，当前位于函数 decode_hex_payload_if_needed。 | <code>    elif re.fullmatch(r"(?:[0-9A-Fa-f]{2}\s+)+[0-9A-Fa-f]{2}", compact):</code> |
| L0197 | 计算并保存 &#96;compact&#96;（compact），供后续逻辑使用，当前位于函数 decode_hex_payload_if_needed。 | <code>        compact = re.sub(r"\s+", "", compact)</code> |
| L0198 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0199 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_hex_payload_if_needed。 | <code>    if not re.fullmatch(r"[0-9A-Fa-f]+", compact):</code> |
| L0200 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_hex_payload_if_needed。 | <code>        return raw</code> |
| L0201 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_hex_payload_if_needed。 | <code>    if len(compact) &lt; 8 or len(compact) % 2 != 0:</code> |
| L0202 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_hex_payload_if_needed。 | <code>        return raw</code> |
| L0203 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0204 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 decode_hex_payload_if_needed。 | <code>    try:</code> |
| L0205 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 decode_hex_payload_if_needed。 | <code>        data = bytes.fromhex(compact)</code> |
| L0206 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 decode_hex_payload_if_needed。 | <code>    except Exception:</code> |
| L0207 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_hex_payload_if_needed。 | <code>        return raw</code> |
| L0208 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0209 | 遍历集合中的数据项并逐项处理，当前位于函数 decode_hex_payload_if_needed。 | <code>    for enc in ("utf-8", "gb18030", "latin1"):</code> |
| L0210 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 decode_hex_payload_if_needed。 | <code>        try:</code> |
| L0211 | 计算并保存 &#96;decoded&#96;（decoded），供后续逻辑使用，当前位于函数 decode_hex_payload_if_needed。 | <code>            decoded = data.decode(enc)</code> |
| L0212 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 decode_hex_payload_if_needed。 | <code>        except Exception:</code> |
| L0213 | 控制当前循环或占位分支的执行流程，当前位于函数 decode_hex_payload_if_needed。 | <code>            continue</code> |
| L0214 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_hex_payload_if_needed。 | <code>        if _is_mostly_readable(decoded):</code> |
| L0215 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_hex_payload_if_needed。 | <code>            return decoded</code> |
| L0216 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0217 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_hex_payload_if_needed。 | <code>    return raw</code> |
| L0218 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0219 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0220 | 定义加载preprocessorschema函数 &#96;load_preprocessor_schema&#96;，封装可复用业务逻辑。 | <code>def load_preprocessor_schema(preprocessor):</code> |
| L0221 | 计算并保存 &#96;numeric_cols&#96;（numericcols），供后续逻辑使用，当前位于函数 load_preprocessor_schema。 | <code>    numeric_cols = []</code> |
| L0222 | 计算并保存 &#96;categorical_cols&#96;（categoricalcols），供后续逻辑使用，当前位于函数 load_preprocessor_schema。 | <code>    categorical_cols = []</code> |
| L0223 | 计算并保存 &#96;categorical_choices&#96;（categoricalchoices），供后续逻辑使用，当前位于函数 load_preprocessor_schema。 | <code>    categorical_choices = {}</code> |
| L0224 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0225 | 遍历集合中的数据项并逐项处理，当前位于函数 load_preprocessor_schema。 | <code>    for name, transformer, cols in preprocessor.transformers_:</code> |
| L0226 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_preprocessor_schema。 | <code>        if name == "num":</code> |
| L0227 | 计算并保存 &#96;numeric_cols&#96;（numericcols），供后续逻辑使用，当前位于函数 load_preprocessor_schema。 | <code>            numeric_cols = list(cols)</code> |
| L0228 | 当前一条件未命中时继续判断另一条件，当前位于函数 load_preprocessor_schema。 | <code>        elif name == "cat":</code> |
| L0229 | 计算并保存 &#96;categorical_cols&#96;（categoricalcols），供后续逻辑使用，当前位于函数 load_preprocessor_schema。 | <code>            categorical_cols = list(cols)</code> |
| L0230 | 计算并保存 &#96;onehot&#96;（onehot），供后续逻辑使用，当前位于函数 load_preprocessor_schema。 | <code>            onehot = None</code> |
| L0231 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 load_preprocessor_schema。 | <code>            try:</code> |
| L0232 | 计算并保存 &#96;onehot&#96;（onehot），供后续逻辑使用，当前位于函数 load_preprocessor_schema。 | <code>                onehot = transformer.named_steps.get("onehot")</code> |
| L0233 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 load_preprocessor_schema。 | <code>            except Exception:</code> |
| L0234 | 计算并保存 &#96;onehot&#96;（onehot），供后续逻辑使用，当前位于函数 load_preprocessor_schema。 | <code>                onehot = None</code> |
| L0235 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0236 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_preprocessor_schema。 | <code>            if onehot is not None and hasattr(onehot, "categories_"):</code> |
| L0237 | 遍历集合中的数据项并逐项处理，当前位于函数 load_preprocessor_schema。 | <code>                for col_name, cats in zip(categorical_cols, onehot.categories_):</code> |
| L0238 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_preprocessor_schema。 | <code>                    categorical_choices[col_name] = [str(x) for x in cats]</code> |
| L0239 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0240 | 结束当前函数并把结果返回给调用方，当前位于函数 load_preprocessor_schema。 | <code>    return numeric_cols, categorical_cols, categorical_choices</code> |
| L0241 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0242 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0243 | 源码原注释：---------------------- | <code># ----------------------</code> |
| L0244 | 源码原注释：Canonical format parser | <code># Canonical format parser</code> |
| L0245 | 源码原注释：---------------------- | <code># ----------------------</code> |
| L0246 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0247 | 定义解析kvlines函数 &#96;parse_kv_lines&#96;，封装可复用业务逻辑。 | <code>def parse_kv_lines(lines: List[str]) -&gt; Dict[str, str]:</code> |
| L0248 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 parse_kv_lines。 | <code>    data = {}</code> |
| L0249 | 遍历集合中的数据项并逐项处理，当前位于函数 parse_kv_lines。 | <code>    for line in lines:</code> |
| L0250 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_kv_lines。 | <code>        if "=" in line:</code> |
| L0251 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_kv_lines。 | <code>            k, v = line.split("=", 1)</code> |
| L0252 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_kv_lines。 | <code>            data[k.strip()] = v.strip()</code> |
| L0253 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_kv_lines。 | <code>    return data</code> |
| L0254 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0255 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0256 | 定义extractcaseblocks函数 &#96;_extract_case_blocks&#96;，封装可复用业务逻辑。 | <code>def _extract_case_blocks(case_text: str) -&gt; Tuple[Dict[str, str], str, str]:</code> |
| L0257 | 计算并保存 &#96;lines&#96;（lines），供后续逻辑使用，当前位于函数 _extract_case_blocks。 | <code>    lines = case_text.splitlines()</code> |
| L0258 | 计算并保存 &#96;meta_lines&#96;（metalines），供后续逻辑使用，当前位于函数 _extract_case_blocks。 | <code>    meta_lines: List[str] = []</code> |
| L0259 | 计算并保存 &#96;request_lines&#96;（requestlines），供后续逻辑使用，当前位于函数 _extract_case_blocks。 | <code>    request_lines: List[str] = []</code> |
| L0260 | 计算并保存 &#96;response_lines&#96;（responselines），供后续逻辑使用，当前位于函数 _extract_case_blocks。 | <code>    response_lines: List[str] = []</code> |
| L0261 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0262 | 计算并保存 &#96;state&#96;（state），供后续逻辑使用，当前位于函数 _extract_case_blocks。 | <code>    state = "meta"</code> |
| L0263 | 遍历集合中的数据项并逐项处理，当前位于函数 _extract_case_blocks。 | <code>    for line in lines:</code> |
| L0264 | 计算并保存 &#96;s&#96;（s），供后续逻辑使用，当前位于函数 _extract_case_blocks。 | <code>        s = line.strip()</code> |
| L0265 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _extract_case_blocks。 | <code>        if s == "[REQUEST_BLOCK]":</code> |
| L0266 | 计算并保存 &#96;state&#96;（state），供后续逻辑使用，当前位于函数 _extract_case_blocks。 | <code>            state = "request"</code> |
| L0267 | 控制当前循环或占位分支的执行流程，当前位于函数 _extract_case_blocks。 | <code>            continue</code> |
| L0268 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _extract_case_blocks。 | <code>        if s == "[/REQUEST_BLOCK]":</code> |
| L0269 | 计算并保存 &#96;state&#96;（state），供后续逻辑使用，当前位于函数 _extract_case_blocks。 | <code>            state = "meta"</code> |
| L0270 | 控制当前循环或占位分支的执行流程，当前位于函数 _extract_case_blocks。 | <code>            continue</code> |
| L0271 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _extract_case_blocks。 | <code>        if s == "[RESPONSE_BLOCK]":</code> |
| L0272 | 计算并保存 &#96;state&#96;（state），供后续逻辑使用，当前位于函数 _extract_case_blocks。 | <code>            state = "response"</code> |
| L0273 | 控制当前循环或占位分支的执行流程，当前位于函数 _extract_case_blocks。 | <code>            continue</code> |
| L0274 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _extract_case_blocks。 | <code>        if s == "[/RESPONSE_BLOCK]":</code> |
| L0275 | 计算并保存 &#96;state&#96;（state），供后续逻辑使用，当前位于函数 _extract_case_blocks。 | <code>            state = "meta"</code> |
| L0276 | 控制当前循环或占位分支的执行流程，当前位于函数 _extract_case_blocks。 | <code>            continue</code> |
| L0277 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0278 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _extract_case_blocks。 | <code>        if state == "meta":</code> |
| L0279 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 _extract_case_blocks。 | <code>            meta_lines.append(line)</code> |
| L0280 | 当前一条件未命中时继续判断另一条件，当前位于函数 _extract_case_blocks。 | <code>        elif state == "request":</code> |
| L0281 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 _extract_case_blocks。 | <code>            request_lines.append(line)</code> |
| L0282 | 当前一条件未命中时继续判断另一条件，当前位于函数 _extract_case_blocks。 | <code>        elif state == "response":</code> |
| L0283 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 _extract_case_blocks。 | <code>            response_lines.append(line)</code> |
| L0284 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0285 | 结束当前函数并把结果返回给调用方，当前位于函数 _extract_case_blocks。 | <code>    return parse_kv_lines(meta_lines), "\n".join(request_lines).strip(), "\n".join(response_lines).strip()</code> |
| L0286 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0287 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0288 | 定义读取bodyfromrequesttext函数 &#96;_get_body_from_request_text&#96;，封装可复用业务逻辑。 | <code>def _get_body_from_request_text(req_text: str) -&gt; str:</code> |
| L0289 | 遍历集合中的数据项并逐项处理，当前位于函数 _get_body_from_request_text。 | <code>    for line in req_text.split("\n"):</code> |
| L0290 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _get_body_from_request_text。 | <code>        if line.startswith("REQUEST_BODY="):</code> |
| L0291 | 结束当前函数并把结果返回给调用方，当前位于函数 _get_body_from_request_text。 | <code>            return decode_hex_payload_if_needed(line.split("=", 1)[1])</code> |
| L0292 | 结束当前函数并把结果返回给调用方，当前位于函数 _get_body_from_request_text。 | <code>    return decode_hex_payload_if_needed(req_text)</code> |
| L0293 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0294 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0295 | 定义读取responseexcerpt函数 &#96;_get_response_excerpt&#96;，封装可复用业务逻辑。 | <code>def _get_response_excerpt(req_text: str, resp_text: str) -&gt; str:</code> |
| L0296 | 遍历集合中的数据项并逐项处理，当前位于函数 _get_response_excerpt。 | <code>    for line in req_text.split("\n"):</code> |
| L0297 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _get_response_excerpt。 | <code>        if line.startswith("RESPONSE_EXCERPT="):</code> |
| L0298 | 结束当前函数并把结果返回给调用方，当前位于函数 _get_response_excerpt。 | <code>            return decode_hex_payload_if_needed(line.split("=", 1)[1])</code> |
| L0299 | 遍历集合中的数据项并逐项处理，当前位于函数 _get_response_excerpt。 | <code>    for line in resp_text.split("\n"):</code> |
| L0300 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _get_response_excerpt。 | <code>        if line.startswith("RESPONSE_EXCERPT="):</code> |
| L0301 | 结束当前函数并把结果返回给调用方，当前位于函数 _get_response_excerpt。 | <code>            return decode_hex_payload_if_needed(line.split("=", 1)[1])</code> |
| L0302 | 结束当前函数并把结果返回给调用方，当前位于函数 _get_response_excerpt。 | <code>    return decode_hex_payload_if_needed(resp_text)</code> |
| L0303 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0304 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0305 | 定义标准化requesttext函数 &#96;_normalize_request_text&#96;，封装可复用业务逻辑。 | <code>def _normalize_request_text(req_text: str) -&gt; str:</code> |
| L0306 | 计算并保存 &#96;out&#96;（out），供后续逻辑使用，当前位于函数 _normalize_request_text。 | <code>    out = []</code> |
| L0307 | 遍历集合中的数据项并逐项处理，当前位于函数 _normalize_request_text。 | <code>    for line in req_text.split("\n"):</code> |
| L0308 | 计算并保存 &#96;line&#96;（line），供后续逻辑使用，当前位于函数 _normalize_request_text。 | <code>        line = line.rstrip("\\")</code> |
| L0309 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _normalize_request_text。 | <code>        if line.startswith("REQUEST_BODY="):</code> |
| L0310 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 _normalize_request_text。 | <code>            out.append("REQUEST_BODY=" + decode_hex_payload_if_needed(line.split("=", 1)[1]))</code> |
| L0311 | 当前一条件未命中时继续判断另一条件，当前位于函数 _normalize_request_text。 | <code>        elif line.startswith("RESPONSE_EXCERPT="):</code> |
| L0312 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 _normalize_request_text。 | <code>            out.append("RESPONSE_EXCERPT=" + decode_hex_payload_if_needed(line.split("=", 1)[1]))</code> |
| L0313 | 处理前述条件均未命中的情况，当前位于函数 _normalize_request_text。 | <code>        else:</code> |
| L0314 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 _normalize_request_text。 | <code>            out.append(line)</code> |
| L0315 | 结束当前函数并把结果返回给调用方，当前位于函数 _normalize_request_text。 | <code>    return "\n".join(out)</code> |
| L0316 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0317 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0318 | 定义标准化responsetext函数 &#96;_normalize_response_text&#96;，封装可复用业务逻辑。 | <code>def _normalize_response_text(resp_text: str) -&gt; str:</code> |
| L0319 | 计算并保存 &#96;out&#96;（out），供后续逻辑使用，当前位于函数 _normalize_response_text。 | <code>    out = []</code> |
| L0320 | 遍历集合中的数据项并逐项处理，当前位于函数 _normalize_response_text。 | <code>    for line in resp_text.split("\n"):</code> |
| L0321 | 计算并保存 &#96;line&#96;（line），供后续逻辑使用，当前位于函数 _normalize_response_text。 | <code>        line = line.rstrip("\\")</code> |
| L0322 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _normalize_response_text。 | <code>        if line.startswith("RESPONSE_EXCERPT="):</code> |
| L0323 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 _normalize_response_text。 | <code>            out.append("RESPONSE_EXCERPT=" + decode_hex_payload_if_needed(line.split("=", 1)[1]))</code> |
| L0324 | 处理前述条件均未命中的情况，当前位于函数 _normalize_response_text。 | <code>        else:</code> |
| L0325 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 _normalize_response_text。 | <code>            out.append(line)</code> |
| L0326 | 结束当前函数并把结果返回给调用方，当前位于函数 _normalize_response_text。 | <code>    return "\n".join(out)</code> |
| L0327 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0328 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0329 | 定义标准化http封禁body函数 &#96;_normalize_http_block_body&#96;，封装可复用业务逻辑。 | <code>def _normalize_http_block_body(block_text: str) -&gt; str:</code> |
| L0330 | 计算并保存 &#96;marker&#96;（marker），供后续逻辑使用，当前位于函数 _normalize_http_block_body。 | <code>    marker = "\nBody:\n"</code> |
| L0331 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _normalize_http_block_body。 | <code>    if marker not in block_text:</code> |
| L0332 | 结束当前函数并把结果返回给调用方，当前位于函数 _normalize_http_block_body。 | <code>        return block_text</code> |
| L0333 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _normalize_http_block_body。 | <code>    head, tail = block_text.split(marker, 1)</code> |
| L0334 | 结束当前函数并把结果返回给调用方，当前位于函数 _normalize_http_block_body。 | <code>    return head + marker + decode_hex_payload_if_needed(tail)</code> |
| L0335 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0336 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0337 | 定义解析canonicalrecords函数 &#96;parse_canonical_records&#96;，封装可复用业务逻辑。 | <code>def parse_canonical_records(text: str, file_id_fallback: str) -&gt; Tuple[Dict[int, Dict], Dict[int, Dict]]:</code> |
| L0338 | 计算并保存 &#96;requests&#96;（requests），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>    requests: Dict[int, Dict] = {}</code> |
| L0339 | 计算并保存 &#96;responses&#96;（responses），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>    responses: Dict[int, Dict] = {}</code> |
| L0340 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0341 | 计算并保存 &#96;case_blocks&#96;（caseblocks），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>    case_blocks = re.findall(r"### CASE_START ###(.*?)### CASE_END ###", text, flags=re.DOTALL)</code> |
| L0342 | 遍历集合中的数据项并逐项处理，当前位于函数 parse_canonical_records。 | <code>    for idx, block in enumerate(case_blocks, start=1):</code> |
| L0343 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>        meta, req_block, resp_block = _extract_case_blocks(block)</code> |
| L0344 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0345 | 计算并保存 &#96;file_id&#96;（fileid），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>        file_id = meta.get("file_id", file_id_fallback)</code> |
| L0346 | 计算并保存 &#96;seq_id&#96;（seqid），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>        seq_id = int(meta.get("seq_id", idx)) if str(meta.get("seq_id", "")).isdigit() else idx</code> |
| L0347 | 计算并保存 &#96;frame_req&#96;（framereq），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>        frame_req = int(meta.get("frame_req", seq_id)) if str(meta.get("frame_req", "")).isdigit() else seq_id</code> |
| L0348 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0349 | 计算并保存 &#96;frame_resp&#96;（frameresp），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>        frame_resp = None</code> |
| L0350 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_canonical_records。 | <code>        if str(meta.get("frame_resp", "")).isdigit():</code> |
| L0351 | 计算并保存 &#96;frame_resp&#96;（frameresp），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>            frame_resp = int(meta.get("frame_resp"))</code> |
| L0352 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0353 | 计算并保存 &#96;time_req&#96;（timereq），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>        time_req = None</code> |
| L0354 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 parse_canonical_records。 | <code>        try:</code> |
| L0355 | 计算并保存 &#96;time_req&#96;（timereq），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>            time_req = float(meta.get("time_req", ""))</code> |
| L0356 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 parse_canonical_records。 | <code>        except Exception:</code> |
| L0357 | 计算并保存 &#96;time_req&#96;（timereq），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>            time_req = float(seq_id)</code> |
| L0358 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0359 | 计算并保存 &#96;time_resp&#96;（timeresp），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>        time_resp = None</code> |
| L0360 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 parse_canonical_records。 | <code>        try:</code> |
| L0361 | 计算并保存 &#96;time_resp&#96;（timeresp），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>            time_resp = float(meta.get("time_resp", ""))</code> |
| L0362 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 parse_canonical_records。 | <code>        except Exception:</code> |
| L0363 | 计算并保存 &#96;time_resp&#96;（timeresp），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>            time_resp = (time_req + 0.01) if time_req is not None else None</code> |
| L0364 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0365 | 计算并保存 &#96;req_text_raw&#96;（reqtextraw），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>        req_text_raw = meta.get("request_text", "")</code> |
| L0366 | 计算并保存 &#96;resp_text_raw&#96;（resptextraw），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>        resp_text_raw = meta.get("response_text", "")</code> |
| L0367 | 计算并保存 &#96;request_text_value&#96;（requesttextvalue），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>        request_text_value = _normalize_request_text(req_text_raw.replace("\\\\n", "\n").replace("\\n", "\n"))</code> |
| L0368 | 计算并保存 &#96;response_text_value&#96;（responsetextvalue），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>        response_text_value = _normalize_response_text(resp_text_raw.replace("\\\\n", "\n").replace("\\n", "\n"))</code> |
| L0369 | 计算并保存 &#96;req_block&#96;（req封禁），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>        req_block = _normalize_http_block_body(req_block)</code> |
| L0370 | 计算并保存 &#96;resp_block&#96;（resp封禁），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>        resp_block = _normalize_http_block_body(resp_block)</code> |
| L0371 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0372 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>        method = meta.get("method", "")</code> |
| L0373 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>        uri = meta.get("uri", "")</code> |
| L0374 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>        host = meta.get("host", "")</code> |
| L0375 | 计算并保存 &#96;content_type&#96;（contenttype），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>        content_type = meta.get("content_type", "")</code> |
| L0376 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0377 | 计算并保存 &#96;req&#96;（req），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>        req = {</code> |
| L0378 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            "frame_no": frame_req,</code> |
| L0379 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            "time": time_req,</code> |
| L0380 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            "src_ip": meta.get("src_ip", ""),</code> |
| L0381 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            "dst_ip": meta.get("dst_ip", ""),</code> |
| L0382 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            "src_port": int(meta.get("src_port", 0)) if str(meta.get("src_port", "")).isdigit() else 0,</code> |
| L0383 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            "dst_port": int(meta.get("dst_port", 0)) if str(meta.get("dst_port", "")).isdigit() else 0,</code> |
| L0384 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            "raw_block": req_block,</code> |
| L0385 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            "type": "request",</code> |
| L0386 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            "method": method,</code> |
| L0387 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            "uri": uri,</code> |
| L0388 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            "host": host,</code> |
| L0389 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            "full_uri": "",</code> |
| L0390 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            "user_agent": "",</code> |
| L0391 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            "content_type": content_type,</code> |
| L0392 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            "response_frame": frame_resp,</code> |
| L0393 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            "request_body": _get_body_from_request_text(request_text_value),</code> |
| L0394 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            "_request_text": request_text_value,</code> |
| L0395 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            "_file_id": file_id,</code> |
| L0396 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            "_seq_id": seq_id,</code> |
| L0397 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 parse_canonical_records。 | <code>        }</code> |
| L0398 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>        requests[frame_req] = req</code> |
| L0399 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0400 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_canonical_records。 | <code>        if frame_resp is not None:</code> |
| L0401 | 计算并保存 &#96;status_code&#96;（状态code），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>            status_code = None</code> |
| L0402 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 parse_canonical_records。 | <code>            try:</code> |
| L0403 | 计算并保存 &#96;status_code&#96;（状态code），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>                status_code = int(meta.get("status_code", ""))</code> |
| L0404 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 parse_canonical_records。 | <code>            except Exception:</code> |
| L0405 | 计算并保存 &#96;status_code&#96;（状态code），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>                status_code = None</code> |
| L0406 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0407 | 计算并保存 &#96;resp&#96;（resp），供后续逻辑使用，当前位于函数 parse_canonical_records。 | <code>            resp = {</code> |
| L0408 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>                "frame_no": frame_resp,</code> |
| L0409 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>                "time": time_resp,</code> |
| L0410 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>                "src_ip": meta.get("dst_ip", ""),</code> |
| L0411 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>                "dst_ip": meta.get("src_ip", ""),</code> |
| L0412 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>                "src_port": int(meta.get("dst_port", 0)) if str(meta.get("dst_port", "")).isdigit() else 0,</code> |
| L0413 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>                "dst_port": int(meta.get("src_port", 0)) if str(meta.get("src_port", "")).isdigit() else 0,</code> |
| L0414 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>                "raw_block": resp_block,</code> |
| L0415 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>                "type": "response",</code> |
| L0416 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>                "status_code": status_code,</code> |
| L0417 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>                "request_frame": frame_req,</code> |
| L0418 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>                "response_body_excerpt": _get_response_excerpt(request_text_value, response_text_value),</code> |
| L0419 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>                "_response_text": response_text_value,</code> |
| L0420 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 parse_canonical_records。 | <code>            }</code> |
| L0421 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_canonical_records。 | <code>            responses[frame_resp] = resp</code> |
| L0422 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0423 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_canonical_records。 | <code>    return requests, responses</code> |
| L0424 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0425 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0426 | 源码原注释：---------------------- | <code># ----------------------</code> |
| L0427 | 源码原注释：Verbose format parser | <code># Verbose format parser</code> |
| L0428 | 源码原注释：---------------------- | <code># ----------------------</code> |
| L0429 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0430 | 定义解析封禁meta函数 &#96;parse_block_meta&#96;，封装可复用业务逻辑。 | <code>def parse_block_meta(block: str) -&gt; Dict:</code> |
| L0431 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 parse_block_meta。 | <code>    result = {</code> |
| L0432 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_block_meta。 | <code>        "frame_no": None,</code> |
| L0433 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_block_meta。 | <code>        "time": None,</code> |
| L0434 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_block_meta。 | <code>        "src_ip": None,</code> |
| L0435 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_block_meta。 | <code>        "dst_ip": None,</code> |
| L0436 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_block_meta。 | <code>        "src_port": None,</code> |
| L0437 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_block_meta。 | <code>        "dst_port": None,</code> |
| L0438 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_block_meta。 | <code>        "raw_block": block,</code> |
| L0439 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 parse_block_meta。 | <code>    }</code> |
| L0440 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0441 | 计算并保存 &#96;summary_match&#96;（summarymatch），供后续逻辑使用，当前位于函数 parse_block_meta。 | <code>    summary_match = re.search(</code> |
| L0442 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_block_meta。 | <code>        r"^\s*(\d+)\s+([0-9.]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(.+)$", block, re.MULTILINE</code> |
| L0443 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 parse_block_meta。 | <code>    )</code> |
| L0444 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_block_meta。 | <code>    if summary_match:</code> |
| L0445 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_block_meta。 | <code>        result["frame_no"] = int(summary_match.group(1))</code> |
| L0446 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_block_meta。 | <code>        result["time"] = float(summary_match.group(2))</code> |
| L0447 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_block_meta。 | <code>        result["src_ip"] = summary_match.group(3)</code> |
| L0448 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_block_meta。 | <code>        result["dst_ip"] = summary_match.group(4)</code> |
| L0449 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0450 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_block_meta。 | <code>    if result["frame_no"] is None:</code> |
| L0451 | 计算并保存 &#96;frame_match&#96;（framematch），供后续逻辑使用，当前位于函数 parse_block_meta。 | <code>        frame_match = re.search(r"^Frame\s+(\d+)\s*:", block, re.MULTILINE)</code> |
| L0452 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_block_meta。 | <code>        if frame_match:</code> |
| L0453 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_block_meta。 | <code>            result["frame_no"] = int(frame_match.group(1))</code> |
| L0454 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0455 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_block_meta。 | <code>    if result["time"] is None:</code> |
| L0456 | 计算并保存 &#96;epoch_match&#96;（epochmatch），供后续逻辑使用，当前位于函数 parse_block_meta。 | <code>        epoch_match = re.search(r"Epoch Time:\s*([0-9.]+)", block)</code> |
| L0457 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_block_meta。 | <code>        if epoch_match:</code> |
| L0458 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_block_meta。 | <code>            result["time"] = float(epoch_match.group(1))</code> |
| L0459 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0460 | 计算并保存 &#96;tcp_match&#96;（tcpmatch），供后续逻辑使用，当前位于函数 parse_block_meta。 | <code>    tcp_match = re.search(r"Transmission Control Protocol,\s+Src Port:\s*(\d+),\s+Dst Port:\s*(\d+)", block)</code> |
| L0461 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_block_meta。 | <code>    if not tcp_match:</code> |
| L0462 | 计算并保存 &#96;tcp_match&#96;（tcpmatch），供后续逻辑使用，当前位于函数 parse_block_meta。 | <code>        tcp_match = re.search(r"Source Port:\s*(\d+).*?Destination Port:\s*(\d+)", block, re.DOTALL)</code> |
| L0463 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_block_meta。 | <code>    if tcp_match:</code> |
| L0464 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_block_meta。 | <code>        result["src_port"] = int(tcp_match.group(1))</code> |
| L0465 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_block_meta。 | <code>        result["dst_port"] = int(tcp_match.group(2))</code> |
| L0466 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_block_meta。 | <code>    return result</code> |
| L0467 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0468 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0469 | 定义解析httprequest函数 &#96;parse_http_request&#96;，封装可复用业务逻辑。 | <code>def parse_http_request(block: str) -&gt; Dict:</code> |
| L0470 | 计算并保存 &#96;meta&#96;（meta），供后续逻辑使用，当前位于函数 parse_http_request。 | <code>    meta = parse_block_meta(block)</code> |
| L0471 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0472 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 parse_http_request。 | <code>    method = None</code> |
| L0473 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 parse_http_request。 | <code>    uri = None</code> |
| L0474 | 计算并保存 &#96;m&#96;（m），供后续逻辑使用，当前位于函数 parse_http_request。 | <code>    m = re.search(r"^\s*(GET&#124;POST&#124;PUT&#124;DELETE&#124;PATCH&#124;HEAD&#124;OPTIONS)\s+(\S+)\s+HTTP/1\.[01]", block, re.MULTILINE)</code> |
| L0475 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_http_request。 | <code>    if m:</code> |
| L0476 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 parse_http_request。 | <code>        method = m.group(1)</code> |
| L0477 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 parse_http_request。 | <code>        uri = m.group(2)</code> |
| L0478 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0479 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 parse_http_request。 | <code>    host = extract_first(r"^\s*Host:\s*(.+?)\r?$", block, re.MULTILINE)</code> |
| L0480 | 计算并保存 &#96;full_uri&#96;（fulluri），供后续逻辑使用，当前位于函数 parse_http_request。 | <code>    full_uri = extract_first(r"\[Full request URI:\s*(.+?)\]", block)</code> |
| L0481 | 计算并保存 &#96;user_agent&#96;（useragent），供后续逻辑使用，当前位于函数 parse_http_request。 | <code>    user_agent = extract_first(r"^\s*User-Agent:\s*(.+?)\r?$", block, re.MULTILINE)</code> |
| L0482 | 计算并保存 &#96;content_type&#96;（contenttype），供后续逻辑使用，当前位于函数 parse_http_request。 | <code>    content_type = extract_first(r"^\s*Content-Type:\s*(.+?)\r?$", block, re.MULTILINE)</code> |
| L0483 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0484 | 计算并保存 &#96;response_frame&#96;（responseframe），供后续逻辑使用，当前位于函数 parse_http_request。 | <code>    response_frame = extract_first(r"\[Response in frame:\s*(\d+)\]", block)</code> |
| L0485 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_http_request。 | <code>    if not response_frame:</code> |
| L0486 | 计算并保存 &#96;response_frame&#96;（responseframe），供后续逻辑使用，当前位于函数 parse_http_request。 | <code>        response_frame = extract_first(r"Response in frame:\s*(\d+)", block)</code> |
| L0487 | 计算并保存 &#96;response_frame_int&#96;（responseframeint），供后续逻辑使用，当前位于函数 parse_http_request。 | <code>    response_frame_int = int(response_frame) if response_frame else None</code> |
| L0488 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0489 | 计算并保存 &#96;json_value_lines&#96;（jsonvaluelines），供后续逻辑使用，当前位于函数 parse_http_request。 | <code>    json_value_lines = []</code> |
| L0490 | 遍历集合中的数据项并逐项处理，当前位于函数 parse_http_request。 | <code>    for line in block.splitlines():</code> |
| L0491 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_http_request。 | <code>        if any(k in line for k in ("String value:", "Number value:", "False value", "True value", "Null value")):</code> |
| L0492 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 parse_http_request。 | <code>            json_value_lines.append(line.strip())</code> |
| L0493 | 计算并保存 &#96;request_body&#96;（requestbody），供后续逻辑使用，当前位于函数 parse_http_request。 | <code>    request_body = " &#124; ".join(json_value_lines[:50]) if json_value_lines else ""</code> |
| L0494 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0495 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_http_request。 | <code>    return {</code> |
| L0496 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_http_request。 | <code>        **meta,</code> |
| L0497 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_http_request。 | <code>        "type": "request",</code> |
| L0498 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_http_request。 | <code>        "method": method,</code> |
| L0499 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_http_request。 | <code>        "uri": uri,</code> |
| L0500 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_http_request。 | <code>        "host": host.strip() if host else None,</code> |
| L0501 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_http_request。 | <code>        "full_uri": full_uri,</code> |
| L0502 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_http_request。 | <code>        "user_agent": user_agent.strip() if user_agent else None,</code> |
| L0503 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_http_request。 | <code>        "content_type": content_type.strip() if content_type else None,</code> |
| L0504 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_http_request。 | <code>        "response_frame": response_frame_int,</code> |
| L0505 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_http_request。 | <code>        "request_body": request_body,</code> |
| L0506 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 parse_http_request。 | <code>    }</code> |
| L0507 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0508 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0509 | 定义解析httpresponse函数 &#96;parse_http_response&#96;，封装可复用业务逻辑。 | <code>def parse_http_response(block: str) -&gt; Dict:</code> |
| L0510 | 计算并保存 &#96;meta&#96;（meta），供后续逻辑使用，当前位于函数 parse_http_response。 | <code>    meta = parse_block_meta(block)</code> |
| L0511 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0512 | 计算并保存 &#96;status_code&#96;（状态code），供后续逻辑使用，当前位于函数 parse_http_response。 | <code>    status_code = extract_first(r"^\s*HTTP/1\.[01]\s+(\d{3})", block, re.MULTILINE)</code> |
| L0513 | 计算并保存 &#96;status_code_int&#96;（状态codeint），供后续逻辑使用，当前位于函数 parse_http_response。 | <code>    status_code_int = int(status_code) if status_code else None</code> |
| L0514 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0515 | 计算并保存 &#96;request_frame&#96;（requestframe），供后续逻辑使用，当前位于函数 parse_http_response。 | <code>    request_frame = extract_first(r"\[Request in frame:\s*(\d+)\]", block)</code> |
| L0516 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_http_response。 | <code>    if not request_frame:</code> |
| L0517 | 计算并保存 &#96;request_frame&#96;（requestframe），供后续逻辑使用，当前位于函数 parse_http_response。 | <code>        request_frame = extract_first(r"Request in frame:\s*(\d+)", block)</code> |
| L0518 | 计算并保存 &#96;request_frame_int&#96;（requestframeint），供后续逻辑使用，当前位于函数 parse_http_response。 | <code>    request_frame_int = int(request_frame) if request_frame else None</code> |
| L0519 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0520 | 计算并保存 &#96;json_value_lines&#96;（jsonvaluelines），供后续逻辑使用，当前位于函数 parse_http_response。 | <code>    json_value_lines = []</code> |
| L0521 | 遍历集合中的数据项并逐项处理，当前位于函数 parse_http_response。 | <code>    for line in block.splitlines():</code> |
| L0522 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_http_response。 | <code>        if any(k in line for k in ("String value:", "Number value:", "False value", "True value", "Null value")):</code> |
| L0523 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 parse_http_response。 | <code>            json_value_lines.append(line.strip())</code> |
| L0524 | 计算并保存 &#96;response_body_excerpt&#96;（responsebodyexcerpt），供后续逻辑使用，当前位于函数 parse_http_response。 | <code>    response_body_excerpt = " &#124; ".join(json_value_lines[:50]) if json_value_lines else ""</code> |
| L0525 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0526 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_http_response。 | <code>    return {</code> |
| L0527 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_http_response。 | <code>        **meta,</code> |
| L0528 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_http_response。 | <code>        "type": "response",</code> |
| L0529 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_http_response。 | <code>        "status_code": status_code_int,</code> |
| L0530 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_http_response。 | <code>        "request_frame": request_frame_int,</code> |
| L0531 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_http_response。 | <code>        "response_body_excerpt": response_body_excerpt,</code> |
| L0532 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 parse_http_response。 | <code>    }</code> |
| L0533 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0534 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0535 | 源码原注释：---------------------- | <code># ----------------------</code> |
| L0536 | 源码原注释：Shared feature mapping | <code># Shared feature mapping</code> |
| L0537 | 源码原注释：---------------------- | <code># ----------------------</code> |
| L0538 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0539 | 定义lowertext函数 &#96;lower_text&#96;，封装可复用业务逻辑。 | <code>def lower_text(*parts) -&gt; str:</code> |
| L0540 | 结束当前函数并把结果返回给调用方，当前位于函数 lower_text。 | <code>    return " ".join([str(x or "") for x in parts]).lower()</code> |
| L0541 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0542 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0543 | 定义choosecategory函数 &#96;choose_category&#96;，封装可复用业务逻辑。 | <code>def choose_category(col_name, choices, request_rec, response_rec):</code> |
| L0544 | 计算并保存 &#96;cats&#96;（cats），供后续逻辑使用，当前位于函数 choose_category。 | <code>    cats = choices.get(col_name, [])</code> |
| L0545 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0546 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 choose_category。 | <code>    if col_name == "proto":</code> |
| L0547 | 计算并保存 &#96;preferred&#96;（preferred），供后续逻辑使用，当前位于函数 choose_category。 | <code>        preferred = ["tcp", "udp", "icmp"]</code> |
| L0548 | 当前一条件未命中时继续判断另一条件，当前位于函数 choose_category。 | <code>    elif col_name == "service":</code> |
| L0549 | 计算并保存 &#96;preferred&#96;（preferred），供后续逻辑使用，当前位于函数 choose_category。 | <code>        preferred = ["http", "https", "-", "dns"]</code> |
| L0550 | 当前一条件未命中时继续判断另一条件，当前位于函数 choose_category。 | <code>    elif col_name == "state":</code> |
| L0551 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 choose_category。 | <code>        text = lower_text(</code> |
| L0552 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 choose_category。 | <code>            request_rec.get("request_body"),</code> |
| L0553 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 choose_category。 | <code>            response_rec.get("response_body_excerpt") if response_rec else "",</code> |
| L0554 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 choose_category。 | <code>            request_rec.get("uri"),</code> |
| L0555 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 choose_category。 | <code>        )</code> |
| L0556 | 计算并保存 &#96;http_code&#96;（httpcode），供后续逻辑使用，当前位于函数 choose_category。 | <code>        http_code = int(response_rec.get("status_code") or 0) if response_rec else 0</code> |
| L0557 | 计算并保存 &#96;biz_error&#96;（bizerror），供后续逻辑使用，当前位于函数 choose_category。 | <code>        biz_error = 1 if ("errauth" in text or "errcaptcha" in text or "number value: 406" in text) else 0</code> |
| L0558 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 choose_category。 | <code>        if http_code &gt;= 400 or biz_error:</code> |
| L0559 | 计算并保存 &#96;preferred&#96;（preferred），供后续逻辑使用，当前位于函数 choose_category。 | <code>            preferred = ["INT", "FIN", "CON", "REQ"]</code> |
| L0560 | 处理前述条件均未命中的情况，当前位于函数 choose_category。 | <code>        else:</code> |
| L0561 | 计算并保存 &#96;preferred&#96;（preferred），供后续逻辑使用，当前位于函数 choose_category。 | <code>            preferred = ["FIN", "CON", "REQ", "INT"]</code> |
| L0562 | 处理前述条件均未命中的情况，当前位于函数 choose_category。 | <code>    else:</code> |
| L0563 | 计算并保存 &#96;preferred&#96;（preferred），供后续逻辑使用，当前位于函数 choose_category。 | <code>        preferred = []</code> |
| L0564 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0565 | 遍历集合中的数据项并逐项处理，当前位于函数 choose_category。 | <code>    for item in preferred:</code> |
| L0566 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 choose_category。 | <code>        if item in cats:</code> |
| L0567 | 结束当前函数并把结果返回给调用方，当前位于函数 choose_category。 | <code>            return item</code> |
| L0568 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0569 | 结束当前函数并把结果返回给调用方，当前位于函数 choose_category。 | <code>    return cats[0] if cats else {"proto": "tcp", "service": "http", "state": "FIN"}.get(col_name, "unknown")</code> |
| L0570 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0571 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0572 | 定义countsqlsignals函数 &#96;count_sql_signals&#96;，封装可复用业务逻辑。 | <code>def count_sql_signals(text: str) -&gt; int:</code> |
| L0573 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 count_sql_signals。 | <code>    text = text.lower()</code> |
| L0574 | 计算并保存 &#96;count&#96;（count），供后续逻辑使用，当前位于函数 count_sql_signals。 | <code>    count = 0</code> |
| L0575 | 遍历集合中的数据项并逐项处理，当前位于函数 count_sql_signals。 | <code>    for kw in SQL_KEYWORDS:</code> |
| L0576 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 count_sql_signals。 | <code>        count += text.count(kw.lower())</code> |
| L0577 | 结束当前函数并把结果返回给调用方，当前位于函数 count_sql_signals。 | <code>    return count</code> |
| L0578 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0579 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0580 | 定义countpatternsignals函数 &#96;count_pattern_signals&#96;，封装可复用业务逻辑。 | <code>def count_pattern_signals(text: str, patterns: List[str]) -&gt; int:</code> |
| L0581 | 结束当前函数并把结果返回给调用方，当前位于函数 count_pattern_signals。 | <code>    return sum(1 for pattern in patterns if re.search(pattern, text, flags=re.IGNORECASE &#124; re.DOTALL))</code> |
| L0582 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0583 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0584 | 定义countweb攻击signals函数 &#96;count_web_attack_signals&#96;，封装可复用业务逻辑。 | <code>def count_web_attack_signals(text: str) -&gt; Dict[str, int]:</code> |
| L0585 | 计算并保存 &#96;normalized&#96;（normalized），供后续逻辑使用，当前位于函数 count_web_attack_signals。 | <code>    normalized = text.lower()</code> |
| L0586 | 计算并保存 &#96;signals&#96;（signals），供后续逻辑使用，当前位于函数 count_web_attack_signals。 | <code>    signals = {name: count_pattern_signals(normalized, patterns) for name, patterns in WEB_ATTACK_PATTERNS.items()}</code> |
| L0587 | 源码原注释：Keep compatibility with older SQL feature shaping while adding richer web payload semantics. | <code>    # Keep compatibility with older SQL feature shaping while adding richer web payload semantics.</code> |
| L0588 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 count_web_attack_signals。 | <code>    signals["sql"] = max(signals.get("sql", 0), count_sql_signals(normalized))</code> |
| L0589 | 结束当前函数并把结果返回给调用方，当前位于函数 count_web_attack_signals。 | <code>    return signals</code> |
| L0590 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0591 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0592 | 定义containsany函数 &#96;contains_any&#96;，封装可复用业务逻辑。 | <code>def contains_any(text: str, words: List[str]) -&gt; int:</code> |
| L0593 | 计算并保存 &#96;t&#96;（t），供后续逻辑使用，当前位于函数 contains_any。 | <code>    t = text.lower()</code> |
| L0594 | 结束当前函数并把结果返回给调用方，当前位于函数 contains_any。 | <code>    return 1 if any(w in t for w in words) else 0</code> |
| L0595 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0596 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0597 | 定义构建requesttext函数 &#96;build_request_text&#96;，封装可复用业务逻辑。 | <code>def build_request_text(req: Dict, resp: Optional[Dict]) -&gt; str:</code> |
| L0598 | 结束当前函数并把结果返回给调用方，当前位于函数 build_request_text。 | <code>    return "\n".join(</code> |
| L0599 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_text。 | <code>        [</code> |
| L0600 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_text。 | <code>            f"METHOD={req.get('method') or ''}",</code> |
| L0601 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_text。 | <code>            f"URI={req.get('uri') or ''}",</code> |
| L0602 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_text。 | <code>            f"HOST={req.get('host') or ''}",</code> |
| L0603 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_text。 | <code>            f"CONTENT_TYPE={req.get('content_type') or ''}",</code> |
| L0604 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_text。 | <code>            f"STATUS_CODE={resp.get('status_code') if resp else ''}",</code> |
| L0605 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_text。 | <code>            f"REQUEST_BODY={req.get('request_body') or ''}",</code> |
| L0606 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_text。 | <code>            f"RESPONSE_EXCERPT={resp.get('response_body_excerpt') if resp else ''}",</code> |
| L0607 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_request_text。 | <code>        ]</code> |
| L0608 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_request_text。 | <code>    )</code> |
| L0609 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0610 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0611 | 定义构建numericvalue函数 &#96;build_numeric_value&#96;，封装可复用业务逻辑。 | <code>def build_numeric_value(col, req: Dict, resp: Optional[Dict]):</code> |
| L0612 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    uri = str(req.get("uri") or "")</code> |
| L0613 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    host = str(req.get("host") or "")</code> |
| L0614 | 计算并保存 &#96;user_agent&#96;（useragent），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    user_agent = str(req.get("user_agent") or "")</code> |
| L0615 | 计算并保存 &#96;content_type&#96;（contenttype），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    content_type = str(req.get("content_type") or "")</code> |
| L0616 | 计算并保存 &#96;request_body&#96;（requestbody），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    request_body = str(req.get("request_body") or "")</code> |
| L0617 | 计算并保存 &#96;response_excerpt&#96;（responseexcerpt），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    response_excerpt = str(resp.get("response_body_excerpt") or "") if resp else ""</code> |
| L0618 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0619 | 计算并保存 &#96;req_time&#96;（reqtime），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    req_time = float(req.get("time") or 0.0)</code> |
| L0620 | 计算并保存 &#96;resp_time&#96;（resptime），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    resp_time = float(resp.get("time") or 0.0) if resp else 0.0</code> |
| L0621 | 计算并保存 &#96;time_gap&#96;（timegap），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    time_gap = max(0.001, resp_time - req_time) if resp else 0.05</code> |
| L0622 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0623 | 计算并保存 &#96;merged_text&#96;（mergedtext），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    merged_text = lower_text(uri, host, request_body, response_excerpt, user_agent, content_type)</code> |
| L0624 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0625 | 计算并保存 &#96;attack_signals&#96;（攻击signals），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    attack_signals = count_web_attack_signals(merged_text)</code> |
| L0626 | 计算并保存 &#96;sql_signal&#96;（sqlsignal），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    sql_signal = attack_signals.get("sql", 0)</code> |
| L0627 | 计算并保存 &#96;xss_signal&#96;（xsssignal），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    xss_signal = attack_signals.get("xss", 0)</code> |
| L0628 | 计算并保存 &#96;command_signal&#96;（commandsignal），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    command_signal = attack_signals.get("command", 0)</code> |
| L0629 | 计算并保存 &#96;traversal_signal&#96;（traversalsignal），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    traversal_signal = attack_signals.get("traversal", 0)</code> |
| L0630 | 计算并保存 &#96;ssrf_signal&#96;（ssrfsignal），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    ssrf_signal = attack_signals.get("ssrf", 0)</code> |
| L0631 | 计算并保存 &#96;upload_signal&#96;（uploadsignal），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    upload_signal = attack_signals.get("upload", 0)</code> |
| L0632 | 计算并保存 &#96;xxe_signal&#96;（xxesignal），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    xxe_signal = attack_signals.get("xxe", 0)</code> |
| L0633 | 计算并保存 &#96;ssti_signal&#96;（sstisignal），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    ssti_signal = attack_signals.get("ssti", 0)</code> |
| L0634 | 计算并保存 &#96;deserialize_signal&#96;（deserializesignal），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    deserialize_signal = attack_signals.get("deserialize", 0)</code> |
| L0635 | 计算并保存 &#96;graphql_signal&#96;（graphqlsignal），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    graphql_signal = attack_signals.get("graphql", 0)</code> |
| L0636 | 计算并保存 &#96;web_attack_signal&#96;（web攻击signal），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    web_attack_signal = sum(attack_signals.values())</code> |
| L0637 | 计算并保存 &#96;login_kw&#96;（登录kw），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    login_kw = contains_any(merged_text, ["login", "auth", "signin", "session"])</code> |
| L0638 | 计算并保存 &#96;captcha_kw&#96;（captchakw），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    captcha_kw = contains_any(merged_text, ["captcha", "verify"])</code> |
| L0639 | 控制当前循环或占位分支的执行流程，当前位于函数 build_numeric_value。 | <code>    password_kw = contains_any(merged_text, ["password", "passwd", "pwd"])</code> |
| L0640 | 计算并保存 &#96;admin_kw&#96;（adminkw），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    admin_kw = contains_any(merged_text, ["admin", "root", "manage", "panel"])</code> |
| L0641 | 计算并保存 &#96;token_kw&#96;（tokenkw），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    token_kw = contains_any(merged_text, ["token", "jwt", "bearer", "authorization"])</code> |
| L0642 | 计算并保存 &#96;json_kw&#96;（jsonkw），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    json_kw = 1 if "json" in content_type.lower() else 0</code> |
| L0643 | 计算并保存 &#96;business_error&#96;（businesserror），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    business_error = 1 if ("errauth" in merged_text or "errcaptcha" in merged_text or "number value: 406" in merged_text) else 0</code> |
| L0644 | 计算并保存 &#96;suspicious_bonus&#96;（suspiciousbonus），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    suspicious_bonus = (</code> |
| L0645 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        sql_signal * 3</code> |
| L0646 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        + xss_signal * 4</code> |
| L0647 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        + command_signal * 5</code> |
| L0648 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        + traversal_signal * 4</code> |
| L0649 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        + ssrf_signal * 4</code> |
| L0650 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        + upload_signal * 4</code> |
| L0651 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        + xxe_signal * 5</code> |
| L0652 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        + ssti_signal * 5</code> |
| L0653 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        + deserialize_signal * 5</code> |
| L0654 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        + graphql_signal * 2</code> |
| L0655 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        + password_kw * 2</code> |
| L0656 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        + login_kw</code> |
| L0657 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        + business_error * 3</code> |
| L0658 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        + token_kw</code> |
| L0659 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_numeric_value。 | <code>    )</code> |
| L0660 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0661 | 计算并保存 &#96;uri_len&#96;（urilen），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    uri_len = len(uri)</code> |
| L0662 | 计算并保存 &#96;path_depth&#96;（pathdepth），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    path_depth = len([x for x in uri.split("?", 1)[0].split("/") if x])</code> |
| L0663 | 计算并保存 &#96;body_len&#96;（bodylen），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    body_len = len(request_body)</code> |
| L0664 | 计算并保存 &#96;ua_len&#96;（ualen），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    ua_len = len(user_agent)</code> |
| L0665 | 计算并保存 &#96;text_len&#96;（textlen），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    text_len = len(build_request_text(req, resp))</code> |
| L0666 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0667 | 计算并保存 &#96;dur&#96;（dur），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    dur = min(5.0, 0.03 + time_gap + body_len / 5000.0 + web_attack_signal * 0.02)</code> |
| L0668 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>    spkts = 2.0 + path_depth + (1 if req.get("method") == "POST" else 0) + suspicious_bonus</code> |
| L0669 | 计算并保存 &#96;dpkts&#96;（dpkts），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    dpkts = 2.0 + (1 if resp else 0) + business_error</code> |
| L0670 | 计算并保存 &#96;sbytes&#96;（sbytes），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    sbytes = 100.0 + uri_len + body_len + ua_len + suspicious_bonus * 30</code> |
| L0671 | 计算并保存 &#96;dbytes&#96;（dbytes），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    dbytes = 80.0 + min(text_len, 5000) * 0.2 + business_error * 50</code> |
| L0672 | 计算并保存 &#96;rate&#96;（rate），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    rate = (spkts + dpkts) / max(dur, 0.001)</code> |
| L0673 | 计算并保存 &#96;sload&#96;（sload），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    sload = sbytes / max(dur, 0.001)</code> |
| L0674 | 计算并保存 &#96;dload&#96;（dload），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    dload = dbytes / max(dur, 0.001)</code> |
| L0675 | 计算并保存 &#96;sinpkt&#96;（sinpkt），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    sinpkt = dur / max(spkts, 1.0)</code> |
| L0676 | 计算并保存 &#96;dinpkt&#96;（dinpkt），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    dinpkt = dur / max(dpkts, 1.0)</code> |
| L0677 | 计算并保存 &#96;smean&#96;（smean），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    smean = sbytes / max(spkts, 1.0)</code> |
| L0678 | 计算并保存 &#96;dmean&#96;（dmean），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    dmean = dbytes / max(dpkts, 1.0)</code> |
| L0679 | 计算并保存 &#96;sjit&#96;（sjit），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    sjit = web_attack_signal * 0.5 + suspicious_bonus * 0.2</code> |
| L0680 | 计算并保存 &#96;djit&#96;（djit），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    djit = business_error * 0.8 + (command_signal + traversal_signal + ssrf_signal + xxe_signal) * 0.4 + sql_signal * 0.3</code> |
| L0681 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0682 | 计算并保存 &#96;known&#96;（known），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    known = {</code> |
| L0683 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "dur": dur,</code> |
| L0684 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "spkts": spkts,</code> |
| L0685 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "dpkts": dpkts,</code> |
| L0686 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "sbytes": sbytes,</code> |
| L0687 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "dbytes": dbytes,</code> |
| L0688 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "rate": rate,</code> |
| L0689 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "sttl": 64.0,</code> |
| L0690 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "dttl": 64.0,</code> |
| L0691 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "sload": sload,</code> |
| L0692 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "dload": dload,</code> |
| L0693 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "sloss": 0.0,</code> |
| L0694 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "dloss": 0.0,</code> |
| L0695 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "sinpkt": sinpkt,</code> |
| L0696 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "dinpkt": dinpkt,</code> |
| L0697 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "sjit": sjit,</code> |
| L0698 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "djit": djit,</code> |
| L0699 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "swin": 255.0,</code> |
| L0700 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "stcpb": 1000.0 + (req.get("frame_no") or 0) * 10.0,</code> |
| L0701 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "dtcpb": 2000.0 + ((resp.get("frame_no") if resp else 0) or 0) * 10.0,</code> |
| L0702 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "dwin": 255.0,</code> |
| L0703 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "tcprtt": min(1.0, time_gap + business_error * 0.05),</code> |
| L0704 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "synack": min(1.0, time_gap / 2),</code> |
| L0705 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "ackdat": min(1.0, time_gap / 2),</code> |
| L0706 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "smean": smean,</code> |
| L0707 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "dmean": dmean,</code> |
| L0708 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "trans_depth": 1.0 + json_kw + password_kw + login_kw + suspicious_bonus,</code> |
| L0709 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "response_body_len": min(text_len + business_error * 100, 20000),</code> |
| L0710 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "ct_srv_src": 1.0 + login_kw + captcha_kw + admin_kw,</code> |
| L0711 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "ct_state_ttl": 1.0 + business_error + web_attack_signal,</code> |
| L0712 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "ct_dst_ltm": 1.0 + login_kw + business_error,</code> |
| L0713 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "ct_src_dport_ltm": 1.0 + suspicious_bonus,</code> |
| L0714 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "ct_dst_sport_ltm": 1.0 + suspicious_bonus,</code> |
| L0715 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "ct_dst_src_ltm": 1.0 + suspicious_bonus,</code> |
| L0716 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "is_ftp_login": 0.0,</code> |
| L0717 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "ct_ftp_cmd": 0.0,</code> |
| L0718 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "ct_flw_http_mthd": 2.0 if req.get("method") == "POST" else 1.0,</code> |
| L0719 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "ct_src_ltm": 1.0 + password_kw + token_kw + web_attack_signal,</code> |
| L0720 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "ct_srv_dst": 1.0 + admin_kw + business_error + min(web_attack_signal, 5),</code> |
| L0721 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_numeric_value。 | <code>        "is_sm_ips_ports": 0.0,</code> |
| L0722 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_numeric_value。 | <code>    }</code> |
| L0723 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0724 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_numeric_value。 | <code>    if col in known:</code> |
| L0725 | 结束当前函数并把结果返回给调用方，当前位于函数 build_numeric_value。 | <code>        return known[col]</code> |
| L0726 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0727 | 计算并保存 &#96;c&#96;（c），供后续逻辑使用，当前位于函数 build_numeric_value。 | <code>    c = col.lower()</code> |
| L0728 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_numeric_value。 | <code>    if "byte" in c:</code> |
| L0729 | 结束当前函数并把结果返回给调用方，当前位于函数 build_numeric_value。 | <code>        return sbytes</code> |
| L0730 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_numeric_value。 | <code>    if "pkt" in c:</code> |
| L0731 | 结束当前函数并把结果返回给调用方，当前位于函数 build_numeric_value。 | <code>        return spkts</code> |
| L0732 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_numeric_value。 | <code>    if "load" in c:</code> |
| L0733 | 结束当前函数并把结果返回给调用方，当前位于函数 build_numeric_value。 | <code>        return sload</code> |
| L0734 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_numeric_value。 | <code>    if "ttl" in c:</code> |
| L0735 | 结束当前函数并把结果返回给调用方，当前位于函数 build_numeric_value。 | <code>        return 64.0</code> |
| L0736 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_numeric_value。 | <code>    if "mean" in c:</code> |
| L0737 | 结束当前函数并把结果返回给调用方，当前位于函数 build_numeric_value。 | <code>        return smean</code> |
| L0738 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_numeric_value。 | <code>    if "jit" in c:</code> |
| L0739 | 结束当前函数并把结果返回给调用方，当前位于函数 build_numeric_value。 | <code>        return sjit</code> |
| L0740 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_numeric_value。 | <code>    if c.startswith("ct_"):</code> |
| L0741 | 结束当前函数并把结果返回给调用方，当前位于函数 build_numeric_value。 | <code>        return 1.0 + suspicious_bonus</code> |
| L0742 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_numeric_value。 | <code>    if c.startswith("is_"):</code> |
| L0743 | 结束当前函数并把结果返回给调用方，当前位于函数 build_numeric_value。 | <code>        return 0.0</code> |
| L0744 | 结束当前函数并把结果返回给调用方，当前位于函数 build_numeric_value。 | <code>    return 0.0</code> |
| L0745 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0746 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0747 | 定义写入jsonl函数 &#96;write_jsonl&#96;，封装可复用业务逻辑。 | <code>def write_jsonl(records: List[Dict], path: Path):</code> |
| L0748 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 write_jsonl。 | <code>    with path.open("w", encoding="utf-8") as f:</code> |
| L0749 | 遍历集合中的数据项并逐项处理，当前位于函数 write_jsonl。 | <code>        for record in records:</code> |
| L0750 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_jsonl。 | <code>            f.write(json.dumps(record, ensure_ascii=False) + "\n")</code> |
| L0751 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0752 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0753 | 定义maybemask函数 &#96;maybe_mask&#96;，封装可复用业务逻辑。 | <code>def maybe_mask(text: str, enabled: bool) -&gt; str:</code> |
| L0754 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 maybe_mask。 | <code>    if not enabled:</code> |
| L0755 | 结束当前函数并把结果返回给调用方，当前位于函数 maybe_mask。 | <code>        return text or ""</code> |
| L0756 | 结束当前函数并把结果返回给调用方，当前位于函数 maybe_mask。 | <code>    return mask_sensitive_text(text or "")</code> |
| L0757 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0758 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0759 | 定义解析records函数 &#96;parse_records&#96;，封装可复用业务逻辑。 | <code>def parse_records(text: str, file_id: str) -&gt; Tuple[Dict[int, Dict], Dict[int, Dict], str]:</code> |
| L0760 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_records。 | <code>    if is_canonical_format(text):</code> |
| L0761 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_records。 | <code>        req, resp = parse_canonical_records(text, file_id)</code> |
| L0762 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_records。 | <code>        return req, resp, "canonical"</code> |
| L0763 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0764 | 计算并保存 &#96;blocks&#96;（blocks），供后续逻辑使用，当前位于函数 parse_records。 | <code>    blocks = split_blocks(text)</code> |
| L0765 | 计算并保存 &#96;requests&#96;（requests），供后续逻辑使用，当前位于函数 parse_records。 | <code>    requests = {}</code> |
| L0766 | 计算并保存 &#96;responses&#96;（responses），供后续逻辑使用，当前位于函数 parse_records。 | <code>    responses = {}</code> |
| L0767 | 遍历集合中的数据项并逐项处理，当前位于函数 parse_records。 | <code>    for block in blocks:</code> |
| L0768 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 parse_records。 | <code>        try:</code> |
| L0769 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_records。 | <code>            if is_http_request_block(block):</code> |
| L0770 | 计算并保存 &#96;r&#96;（r），供后续逻辑使用，当前位于函数 parse_records。 | <code>                r = parse_http_request(block)</code> |
| L0771 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_records。 | <code>                if r["frame_no"] is not None:</code> |
| L0772 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_records。 | <code>                    requests[r["frame_no"]] = r</code> |
| L0773 | 当前一条件未命中时继续判断另一条件，当前位于函数 parse_records。 | <code>            elif is_http_response_block(block):</code> |
| L0774 | 计算并保存 &#96;s&#96;（s），供后续逻辑使用，当前位于函数 parse_records。 | <code>                s = parse_http_response(block)</code> |
| L0775 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_records。 | <code>                if s["frame_no"] is not None:</code> |
| L0776 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_records。 | <code>                    responses[s["frame_no"]] = s</code> |
| L0777 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 parse_records。 | <code>        except Exception as exc:  # noqa: BLE001</code> |
| L0778 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_records。 | <code>            logging.warning("解析 block 失败: %s", exc)</code> |
| L0779 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_records。 | <code>    return requests, responses, "verbose"</code> |
| L0780 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0781 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0782 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main():</code> |
| L0783 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="从 txt 提取旧模型兼容输入（支持 canonical + verbose）")</code> |
| L0784 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--input", required=True, help="Wireshark/canonical txt 文件路径")</code> |
| L0785 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--preprocessor", required=True, help="旧 preprocessor.joblib 路径")</code> |
| L0786 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--output-dir", required=True, help="输出目录")</code> |
| L0787 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--keep-static", action="store_true", help="保留静态资源")</code> |
| L0788 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mask-sensitive", action="store_true", help="开启敏感字段脱敏（默认关闭）")</code> |
| L0789 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0790 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0791 | 计算并保存 &#96;input_path&#96;（inputpath），供后续逻辑使用，当前位于函数 main。 | <code>    input_path = Path(args.input)</code> |
| L0792 | 计算并保存 &#96;output_dir&#96;（outputdir），供后续逻辑使用，当前位于函数 main。 | <code>    output_dir = Path(args.output_dir)</code> |
| L0793 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    output_dir.mkdir(parents=True, exist_ok=True)</code> |
| L0794 | 计算并保存 &#96;file_id&#96;（fileid），供后续逻辑使用，当前位于函数 main。 | <code>    file_id = input_path.stem</code> |
| L0795 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0796 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 main。 | <code>    text = read_text_file(input_path)</code> |
| L0797 | 计算并保存 &#96;preprocessor&#96;（preprocessor），供后续逻辑使用，当前位于函数 main。 | <code>    preprocessor = joblib.load(args.preprocessor)</code> |
| L0798 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    numeric_cols, categorical_cols, categorical_choices = load_preprocessor_schema(preprocessor)</code> |
| L0799 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0800 | 计算并保存 &#96;schema_json&#96;（schemajson），供后续逻辑使用，当前位于函数 main。 | <code>    schema_json = output_dir / "old_preprocessor_schema.json"</code> |
| L0801 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    schema_json.write_text(</code> |
| L0802 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        json.dumps(</code> |
| L0803 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            {</code> |
| L0804 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "numeric_cols": numeric_cols,</code> |
| L0805 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "categorical_cols": categorical_cols,</code> |
| L0806 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "categorical_choices": categorical_choices,</code> |
| L0807 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>            },</code> |
| L0808 | 计算并保存 &#96;ensure_ascii&#96;（ensureascii），供后续逻辑使用，当前位于函数 main。 | <code>            ensure_ascii=False,</code> |
| L0809 | 计算并保存 &#96;indent&#96;（indent），供后续逻辑使用，当前位于函数 main。 | <code>            indent=2,</code> |
| L0810 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        ),</code> |
| L0811 | 计算并保存 &#96;encoding&#96;（encoding），供后续逻辑使用，当前位于函数 main。 | <code>        encoding="utf-8",</code> |
| L0812 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0813 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0814 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    requests, responses, mode = parse_records(text, file_id)</code> |
| L0815 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0816 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("解析模式: %s", mode)</code> |
| L0817 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("识别到请求数量: %d", len(requests))</code> |
| L0818 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("识别到响应数量: %d", len(responses))</code> |
| L0819 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("当前为 compatibility mode：输出仅用于流程验证，不代表最终检测效果。")</code> |
| L0820 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0821 | 计算并保存 &#96;response_by_req&#96;（responsebyreq），供后续逻辑使用，当前位于函数 main。 | <code>    response_by_req = {r.get("request_frame"): r for r in responses.values() if r.get("request_frame") is not None}</code> |
| L0822 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0823 | 计算并保存 &#96;feature_rows&#96;（feature数据库记录），供后续逻辑使用，当前位于函数 main。 | <code>    feature_rows = []</code> |
| L0824 | 计算并保存 &#96;raw_rows&#96;（raw数据库记录），供后续逻辑使用，当前位于函数 main。 | <code>    raw_rows = []</code> |
| L0825 | 计算并保存 &#96;seq_id&#96;（seqid），供后续逻辑使用，当前位于函数 main。 | <code>    seq_id = 1</code> |
| L0826 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0827 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>    for frame_req in sorted(requests.keys()):</code> |
| L0828 | 计算并保存 &#96;req&#96;（req），供后续逻辑使用，当前位于函数 main。 | <code>        req = requests[frame_req]</code> |
| L0829 | 计算并保存 &#96;resp&#96;（resp），供后续逻辑使用，当前位于函数 main。 | <code>        resp = None</code> |
| L0830 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0831 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if req.get("response_frame") and req.get("response_frame") in responses:</code> |
| L0832 | 计算并保存 &#96;resp&#96;（resp），供后续逻辑使用，当前位于函数 main。 | <code>            resp = responses[req.get("response_frame")]</code> |
| L0833 | 当前一条件未命中时继续判断另一条件，当前位于函数 main。 | <code>        elif frame_req in response_by_req:</code> |
| L0834 | 计算并保存 &#96;resp&#96;（resp），供后续逻辑使用，当前位于函数 main。 | <code>            resp = response_by_req[frame_req]</code> |
| L0835 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0836 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if not args.keep_static and is_static_resource(req.get("uri")):</code> |
| L0837 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>            continue</code> |
| L0838 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0839 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 main。 | <code>        row = {"file_id": file_id, "seq_id": seq_id}</code> |
| L0840 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0841 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>        for col in categorical_cols:</code> |
| L0842 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            row[col] = choose_category(col, categorical_choices, req, resp)</code> |
| L0843 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0844 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>        for col in numeric_cols:</code> |
| L0845 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            row[col] = build_numeric_value(col, req, resp)</code> |
| L0846 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0847 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>        feature_rows.append(row)</code> |
| L0848 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0849 | 计算并保存 &#96;req_text&#96;（reqtext），供后续逻辑使用，当前位于函数 main。 | <code>        req_text = req.get("_request_text") or build_request_text(req, resp)</code> |
| L0850 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>        raw_rows.append(</code> |
| L0851 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            {</code> |
| L0852 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "file_id": file_id,</code> |
| L0853 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "seq_id": seq_id,</code> |
| L0854 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "frame_req": req.get("frame_no"),</code> |
| L0855 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "frame_resp": resp.get("frame_no") if resp else None,</code> |
| L0856 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "src_ip": req.get("src_ip"),</code> |
| L0857 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "dst_ip": req.get("dst_ip"),</code> |
| L0858 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "src_port": req.get("src_port"),</code> |
| L0859 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "dst_port": req.get("dst_port"),</code> |
| L0860 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "method": req.get("method"),</code> |
| L0861 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "uri": req.get("uri"),</code> |
| L0862 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "host": req.get("host"),</code> |
| L0863 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "status_code": resp.get("status_code") if resp else None,</code> |
| L0864 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "request_text": maybe_mask(req_text, args.mask_sensitive),</code> |
| L0865 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "response_text": maybe_mask(resp.get("_response_text", "") if resp else "", args.mask_sensitive),</code> |
| L0866 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "raw_request_block": maybe_mask(req.get("raw_block", ""), args.mask_sensitive),</code> |
| L0867 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "raw_response_block": maybe_mask(resp.get("raw_block", "") if resp else "", args.mask_sensitive),</code> |
| L0868 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>            }</code> |
| L0869 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        )</code> |
| L0870 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        seq_id += 1</code> |
| L0871 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0872 | 计算并保存 &#96;feature_df&#96;（featuredf），供后续逻辑使用，当前位于函数 main。 | <code>    feature_df = pd.DataFrame(feature_rows)</code> |
| L0873 | 计算并保存 &#96;raw_index_jsonl&#96;（rawindexjsonl），供后续逻辑使用，当前位于函数 main。 | <code>    raw_index_jsonl = output_dir / f"{file_id}.raw_index.jsonl"</code> |
| L0874 | 计算并保存 &#96;old_input_csv&#96;（oldinputcsv），供后续逻辑使用，当前位于函数 main。 | <code>    old_input_csv = output_dir / f"{file_id}.old_model_input.csv"</code> |
| L0875 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0876 | 计算并保存 &#96;ordered_cols&#96;（orderedcols），供后续逻辑使用，当前位于函数 main。 | <code>    ordered_cols = ["file_id", "seq_id"] + categorical_cols + numeric_cols</code> |
| L0877 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if feature_df.empty:</code> |
| L0878 | 计算并保存 &#96;feature_df&#96;（featuredf），供后续逻辑使用，当前位于函数 main。 | <code>        feature_df = pd.DataFrame(columns=ordered_cols)</code> |
| L0879 | 处理前述条件均未命中的情况，当前位于函数 main。 | <code>    else:</code> |
| L0880 | 计算并保存 &#96;feature_df&#96;（featuredf），供后续逻辑使用，当前位于函数 main。 | <code>        feature_df = feature_df[ordered_cols]</code> |
| L0881 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0882 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    feature_df.to_csv(old_input_csv, index=False, encoding="utf-8-sig")</code> |
| L0883 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    write_jsonl(raw_rows, raw_index_jsonl)</code> |
| L0884 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0885 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("最终进入 old_model_input.csv 的记录数: %d", len(feature_df))</code> |
| L0886 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("old_model_input.csv 列数: %d", len(feature_df.columns))</code> |
| L0887 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("old_model_input.csv: %s", old_input_csv)</code> |
| L0888 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    logging.info("raw_index.jsonl: %s", raw_index_jsonl)</code> |
| L0889 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0890 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("=" * 80)</code> |
| L0891 | 计算并保存 &#96;preview_cols&#96;（previewcols），供后续逻辑使用，当前位于函数 main。 | <code>    preview_cols = ["file_id", "seq_id"] + [c for c in ["proto", "service", "state"] if c in feature_df.columns]</code> |
| L0892 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(feature_df[preview_cols].head(5))</code> |
| L0893 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("=" * 80)</code> |
| L0894 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0895 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0896 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0897 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
