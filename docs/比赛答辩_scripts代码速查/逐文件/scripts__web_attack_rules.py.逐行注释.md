# `scripts/web_attack_rules.py` 逐行注释

**脚本用途：** Web 攻击 POC 规则库，识别 SQL 注入、XSS、命令注入、路径遍历、SSRF、XXE 等典型载荷。

**源码行数：** 192　**函数/类数量：** 7

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;import html&#96;。 | <code>import html</code> |
| L0002 | 导入后续逻辑所需的模块、类或函数：&#96;import re&#96;。 | <code>import re</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Dict, Optional&#96;。 | <code>from typing import Dict, Optional</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;from urllib.parse import unquote_plus&#96;。 | <code>from urllib.parse import unquote_plus</code> |
| L0005 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0006 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0007 | 计算并保存 &#96;AttackSignal&#96;（AttackSignal），供后续逻辑使用。 | <code>AttackSignal = Dict[str, object]</code> |
| L0008 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0009 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0010 | 定义requestonlytext函数 &#96;request_only_text&#96;，封装可复用业务逻辑。 | <code>def request_only_text(candidate: dict) -&gt; str:</code> |
| L0011 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_only_text。 | <code>    """Build request-side text only, avoiding false positives from response summaries."""</code> |
| L0012 | 计算并保存 &#96;request_text&#96;（requesttext），供后续逻辑使用，当前位于函数 request_only_text。 | <code>    request_text = str(candidate.get("request_text") or "")</code> |
| L0013 | 计算并保存 &#96;request_lines&#96;（requestlines），供后续逻辑使用，当前位于函数 request_only_text。 | <code>    request_lines = []</code> |
| L0014 | 遍历集合中的数据项并逐项处理，当前位于函数 request_only_text。 | <code>    for line in request_text.splitlines():</code> |
| L0015 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 request_only_text。 | <code>        if line.upper().startswith("RESPONSE_EXCERPT="):</code> |
| L0016 | 控制当前循环或占位分支的执行流程，当前位于函数 request_only_text。 | <code>            continue</code> |
| L0017 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 request_only_text。 | <code>        request_lines.append(line)</code> |
| L0018 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0019 | 结束当前函数并把结果返回给调用方，当前位于函数 request_only_text。 | <code>    return "\n".join(</code> |
| L0020 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_only_text。 | <code>        [</code> |
| L0021 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_only_text。 | <code>            str(candidate.get("method") or ""),</code> |
| L0022 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_only_text。 | <code>            str(candidate.get("uri") or ""),</code> |
| L0023 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_only_text。 | <code>            "\n".join(request_lines),</code> |
| L0024 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_only_text。 | <code>            str(candidate.get("raw_request_block") or ""),</code> |
| L0025 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 request_only_text。 | <code>        ]</code> |
| L0026 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 request_only_text。 | <code>    )</code> |
| L0027 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0028 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0029 | 定义candidatefulltext函数 &#96;candidate_full_text&#96;，封装可复用业务逻辑。 | <code>def candidate_full_text(candidate: dict) -&gt; str:</code> |
| L0030 | 结束当前函数并把结果返回给调用方，当前位于函数 candidate_full_text。 | <code>    return "\n".join(</code> |
| L0031 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 candidate_full_text。 | <code>        [</code> |
| L0032 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 candidate_full_text。 | <code>            str(candidate.get("method") or ""),</code> |
| L0033 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 candidate_full_text。 | <code>            str(candidate.get("uri") or ""),</code> |
| L0034 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 candidate_full_text。 | <code>            str(candidate.get("request_text") or ""),</code> |
| L0035 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 candidate_full_text。 | <code>            str(candidate.get("raw_request_block") or ""),</code> |
| L0036 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 candidate_full_text。 | <code>            str(candidate.get("raw_response_block") or ""),</code> |
| L0037 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 candidate_full_text。 | <code>        ]</code> |
| L0038 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 candidate_full_text。 | <code>    )</code> |
| L0039 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0040 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0041 | 定义标准化攻击text函数 &#96;normalize_attack_text&#96;，封装可复用业务逻辑。 | <code>def normalize_attack_text(text: str) -&gt; str:</code> |
| L0042 | 计算并保存 &#96;variants&#96;（variants），供后续逻辑使用，当前位于函数 normalize_attack_text。 | <code>    variants = []</code> |
| L0043 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 normalize_attack_text。 | <code>    current = str(text or "")</code> |
| L0044 | 遍历集合中的数据项并逐项处理，当前位于函数 normalize_attack_text。 | <code>    for _ in range(4):</code> |
| L0045 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_text。 | <code>        if current not in variants:</code> |
| L0046 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 normalize_attack_text。 | <code>            variants.append(current)</code> |
| L0047 | 计算并保存 &#96;decoded&#96;（decoded），供后续逻辑使用，当前位于函数 normalize_attack_text。 | <code>        decoded = html.unescape(unquote_plus(current))</code> |
| L0048 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_text。 | <code>        if decoded == current:</code> |
| L0049 | 控制当前循环或占位分支的执行流程，当前位于函数 normalize_attack_text。 | <code>            break</code> |
| L0050 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 normalize_attack_text。 | <code>        current = decoded</code> |
| L0051 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_text。 | <code>    return "\n".join(variants).lower()</code> |
| L0052 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0053 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0054 | 计算并保存 &#96;ATTACK_RULES&#96;（攻击RULES），供后续逻辑使用。 | <code>ATTACK_RULES = [</code> |
| L0055 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    {</code> |
| L0056 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_type": "XSS",</code> |
| L0057 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "rule_score": 0.94,</code> |
| L0058 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "reason": "Request contains script tag, event handler, JavaScript protocol, or sensitive script call.",</code> |
| L0059 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "patterns": [</code> |
| L0060 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"&lt;\s*/?\s*script\b",</code> |
| L0061 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"&lt;\s*(?:img&#124;svg&#124;iframe&#124;body&#124;input&#124;details&#124;marquee)\b[^&gt;]*(?:onerror&#124;onload&#124;onclick&#124;onmouseover)\s*=",</code> |
| L0062 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"\bon(?:error&#124;load&#124;click&#124;mouseover&#124;focus&#124;submit)\s*=",</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"\bjavascript\s*:",</code> |
| L0064 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"\balert\s*\(",</code> |
| L0065 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"\bdocument\s*\.\s*cookie\b",</code> |
| L0066 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"\beval\s*\(",</code> |
| L0067 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>        ],</code> |
| L0068 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0069 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    {</code> |
| L0070 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_type": "\u0053\u0051\u004c\u6ce8\u5165",</code> |
| L0071 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "rule_score": 0.93,</code> |
| L0072 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "reason": "Request contains UNION SELECT, OR 1=1, SQL comments, or time-delay SQL function.",</code> |
| L0073 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "patterns": [</code> |
| L0074 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"\bunion\s+(?:all\s+)?select\b",</code> |
| L0075 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"(?:'&#124;%27&#124;\"&#124;%22)?\s*\bor\b\s+(?:'&#124;\")?\d+(?:'&#124;\")?\s*=\s*(?:'&#124;\")?\d+",</code> |
| L0076 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"(?:'&#124;%27&#124;\"&#124;%22)?\s*\band\b\s+(?:'&#124;\")?\d+(?:'&#124;\")?\s*=\s*(?:'&#124;\")?\d+",</code> |
| L0077 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"\binformation_schema\b",</code> |
| L0078 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"\bsleep\s*\(",</code> |
| L0079 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"\bbenchmark\s*\(",</code> |
| L0080 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"(?:--&#124;#&#124;/\*)\s*(?:$&#124;[+\s])",</code> |
| L0081 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>        ],</code> |
| L0082 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0083 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    {</code> |
| L0084 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_type": "\u547d\u4ee4\u6ce8\u5165",</code> |
| L0085 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "rule_score": 0.94,</code> |
| L0086 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "reason": "Request contains shell separators and system command execution features.",</code> |
| L0087 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "patterns": [</code> |
| L0088 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"(?:;&#124;\&#124;\&#124;&#124;&amp;&amp;)\s*(?:cat&#124;whoami&#124;id&#124;uname&#124;curl&#124;wget&#124;powershell&#124;cmd\.exe&#124;nc&#124;bash&#124;sh)\b",</code> |
| L0089 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"\b(?:powershell&#124;cmd\.exe&#124;/bin/sh&#124;/bin/bash)\b",</code> |
| L0090 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>        ],</code> |
| L0091 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0092 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    {</code> |
| L0093 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_type": "\u8def\u5f84\u904d\u5386",</code> |
| L0094 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "rule_score": 0.90,</code> |
| L0095 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "reason": "Request path or parameter contains directory traversal and sensitive file access features.",</code> |
| L0096 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "patterns": [</code> |
| L0097 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"(?:\.\./&#124;\.\.\\){2,}",</code> |
| L0098 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"(?:/etc/passwd&#124;/etc/shadow&#124;\\windows\\system32\\config)",</code> |
| L0099 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>        ],</code> |
| L0100 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0101 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    {</code> |
| L0102 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_type": "SSRF",</code> |
| L0103 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "rule_score": 0.88,</code> |
| L0104 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "reason": "Request contains URL parameters pointing to localhost, internal networks, or file protocol.",</code> |
| L0105 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "patterns": [</code> |
| L0106 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"(?:url&#124;target&#124;redirect&#124;callback&#124;next)\s*=\s*(?:https?://)?(?:127\.0\.0\.1&#124;localhost&#124;0\.0\.0\.0&#124;10\.&#124;172\.(?:1[6-9]&#124;2\d&#124;3[01])\.&#124;192\.168\.)",</code> |
| L0107 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"(?:url&#124;target&#124;redirect&#124;callback&#124;next)\s*=\s*file://",</code> |
| L0108 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>        ],</code> |
| L0109 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0110 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    {</code> |
| L0111 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "attack_type": "\u5371\u9669\u6587\u4ef6\u4e0a\u4f20",</code> |
| L0112 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "rule_score": 0.89,</code> |
| L0113 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "reason": "Uploaded filename uses executable script or system executable extension.",</code> |
| L0114 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "patterns": [</code> |
| L0115 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"filename\s*=\s*[\"']?[^\"'\r\n]+\.(?:php&#124;jsp&#124;jspx&#124;asp&#124;aspx&#124;exe&#124;bat&#124;cmd&#124;ps1&#124;sh)\b",</code> |
| L0116 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            r"(?s)(?=.*[\"']?filename[\"']?\s*[:=]\s*[\"'][^\"']+\.(?:php&#124;phtml&#124;php[3457]?&#124;phar&#124;jsp&#124;jspx&#124;asp&#124;aspx&#124;ashx&#124;asmx)[\"'])(?=.*(?:&lt;\?php&#124;&lt;%@\s*page&#124;&lt;%\s*(?:eval&#124;runtime)&#124;runtime\.getruntime\(\)\.exec&#124;processbuilder\s*\(&#124;(?:system&#124;exec&#124;passthru&#124;shell_exec)\s*\())",</code> |
| L0117 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>        ],</code> |
| L0118 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0119 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>]</code> |
| L0120 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0121 | 定义检测request攻击函数 &#96;detect_request_attack&#96;，封装可复用业务逻辑。 | <code>def detect_request_attack(candidate: dict) -&gt; Optional[AttackSignal]:</code> |
| L0122 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 detect_request_attack。 | <code>    text = normalize_attack_text(request_only_text(candidate))</code> |
| L0123 | 遍历集合中的数据项并逐项处理，当前位于函数 detect_request_attack。 | <code>    for rule in ATTACK_RULES:</code> |
| L0124 | 遍历集合中的数据项并逐项处理，当前位于函数 detect_request_attack。 | <code>        for pattern in rule["patterns"]:</code> |
| L0125 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 detect_request_attack。 | <code>            if re.search(pattern, text, flags=re.IGNORECASE &#124; re.DOTALL):</code> |
| L0126 | 结束当前函数并把结果返回给调用方，当前位于函数 detect_request_attack。 | <code>                return {</code> |
| L0127 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detect_request_attack。 | <code>                    "attack_type": rule["attack_type"],</code> |
| L0128 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detect_request_attack。 | <code>                    "rule_score": float(rule["rule_score"]),</code> |
| L0129 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detect_request_attack。 | <code>                    "rule_reason": rule["reason"],</code> |
| L0130 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detect_request_attack。 | <code>                    "rule_pattern": pattern,</code> |
| L0131 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 detect_request_attack。 | <code>                }</code> |
| L0132 | 结束当前函数并把结果返回给调用方，当前位于函数 detect_request_attack。 | <code>    return None</code> |
| L0133 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0134 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0135 | 定义isplainauthattempt函数 &#96;is_plain_auth_attempt&#96;，封装可复用业务逻辑。 | <code>def is_plain_auth_attempt(candidate: dict) -&gt; bool:</code> |
| L0136 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 is_plain_auth_attempt。 | <code>    """Return True for a single ordinary login attempt without attack/rate-limit signals."""</code> |
| L0137 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 is_plain_auth_attempt。 | <code>    method = str(candidate.get("method") or "").upper()</code> |
| L0138 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 is_plain_auth_attempt。 | <code>    uri = str(candidate.get("uri") or "").lower()</code> |
| L0139 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_plain_auth_attempt。 | <code>    if method not in {"POST", "PUT"}:</code> |
| L0140 | 结束当前函数并把结果返回给调用方，当前位于函数 is_plain_auth_attempt。 | <code>        return False</code> |
| L0141 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_plain_auth_attempt。 | <code>    if not re.search(r"(?:/login&#124;/auth&#124;/signin&#124;/session&#124;/api/auth/login)", uri, flags=re.I):</code> |
| L0142 | 结束当前函数并把结果返回给调用方，当前位于函数 is_plain_auth_attempt。 | <code>        return False</code> |
| L0143 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0144 | 源码原注释：Payload attacks on login endpoints must still be exported. | <code>    # Payload attacks on login endpoints must still be exported.</code> |
| L0145 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_plain_auth_attempt。 | <code>    if detect_request_attack(candidate):</code> |
| L0146 | 结束当前函数并把结果返回给调用方，当前位于函数 is_plain_auth_attempt。 | <code>        return False</code> |
| L0147 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0148 | 计算并保存 &#96;request_text&#96;（requesttext），供后续逻辑使用，当前位于函数 is_plain_auth_attempt。 | <code>    request_text = normalize_attack_text(request_only_text(candidate))</code> |
| L0149 | 计算并保存 &#96;full_text&#96;（fulltext），供后续逻辑使用，当前位于函数 is_plain_auth_attempt。 | <code>    full_text = normalize_attack_text(candidate_full_text(candidate))</code> |
| L0150 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_plain_auth_attempt。 | <code>    if not re.search(r"(?:username&#124;user&#124;account&#124;login&#124;password&#124;passwd&#124;pwd)", request_text, flags=re.I):</code> |
| L0151 | 结束当前函数并把结果返回给调用方，当前位于函数 is_plain_auth_attempt。 | <code>        return False</code> |
| L0152 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0153 | 源码原注释：Multiple failures / throttling can be a real brute-force signal, so do not whitelist it. | <code>    # Multiple failures / throttling can be a real brute-force signal, so do not whitelist it.</code> |
| L0154 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_plain_auth_attempt。 | <code>    if re.search(</code> |
| L0155 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 is_plain_auth_attempt。 | <code>        r"(?:too\s+many&#124;rate\s*limit&#124;brute\s*force&#124;errauth&#124;captcha&#124;locked&#124;blocked&#124;attempts?\s*[:=]\s*(?:[5-9]&#124;\d{2,}))",</code> |
| L0156 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 is_plain_auth_attempt。 | <code>        full_text,</code> |
| L0157 | 计算并保存 &#96;flags&#96;（flags），供后续逻辑使用，当前位于函数 is_plain_auth_attempt。 | <code>        flags=re.I,</code> |
| L0158 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 is_plain_auth_attempt。 | <code>    ):</code> |
| L0159 | 结束当前函数并把结果返回给调用方，当前位于函数 is_plain_auth_attempt。 | <code>        return False</code> |
| L0160 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0161 | 结束当前函数并把结果返回给调用方，当前位于函数 is_plain_auth_attempt。 | <code>    return True</code> |
| L0162 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0163 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0164 | 定义numericscore函数 &#96;numeric_score&#96;，封装可复用业务逻辑。 | <code>def numeric_score(value, default: float = 0.0) -&gt; float:</code> |
| L0165 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 numeric_score。 | <code>    try:</code> |
| L0166 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 numeric_score。 | <code>        if value is None:</code> |
| L0167 | 结束当前函数并把结果返回给调用方，当前位于函数 numeric_score。 | <code>            return default</code> |
| L0168 | 结束当前函数并把结果返回给调用方，当前位于函数 numeric_score。 | <code>        return float(value)</code> |
| L0169 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 numeric_score。 | <code>    except Exception:</code> |
| L0170 | 结束当前函数并把结果返回给调用方，当前位于函数 numeric_score。 | <code>        return default</code> |
| L0171 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0172 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0173 | 定义applyrulesignal函数 &#96;apply_rule_signal&#96;，封装可复用业务逻辑。 | <code>def apply_rule_signal(candidate: dict, signal: Optional[AttackSignal]) -&gt; dict:</code> |
| L0174 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 apply_rule_signal。 | <code>    if not signal:</code> |
| L0175 | 结束当前函数并把结果返回给调用方，当前位于函数 apply_rule_signal。 | <code>        return candidate</code> |
| L0176 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0177 | 计算并保存 &#96;original_score&#96;（originalscore），供后续逻辑使用，当前位于函数 apply_rule_signal。 | <code>    original_score = numeric_score(</code> |
| L0178 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 apply_rule_signal。 | <code>        candidate.get("original_model_score", candidate.get("raw_score", candidate.get("score")))</code> |
| L0179 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 apply_rule_signal。 | <code>    )</code> |
| L0180 | 计算并保存 &#96;rule_score&#96;（rulescore），供后续逻辑使用，当前位于函数 apply_rule_signal。 | <code>    rule_score = numeric_score(signal.get("rule_score"))</code> |
| L0181 | 计算并保存 &#96;effective_score&#96;（effectivescore），供后续逻辑使用，当前位于函数 apply_rule_signal。 | <code>    effective_score = max(original_score, rule_score)</code> |
| L0182 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0183 | 计算并保存 &#96;updated&#96;（updated），供后续逻辑使用，当前位于函数 apply_rule_signal。 | <code>    updated = dict(candidate)</code> |
| L0184 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 apply_rule_signal。 | <code>    updated["original_model_score"] = original_score</code> |
| L0185 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 apply_rule_signal。 | <code>    updated["raw_score"] = round(effective_score, 6)</code> |
| L0186 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 apply_rule_signal。 | <code>    updated["rule_score"] = rule_score</code> |
| L0187 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 apply_rule_signal。 | <code>    updated["rule_reason"] = signal.get("rule_reason")</code> |
| L0188 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 apply_rule_signal。 | <code>    updated["rule_pattern"] = signal.get("rule_pattern")</code> |
| L0189 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 apply_rule_signal。 | <code>    updated["attack_type"] = signal.get("attack_type")</code> |
| L0190 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 apply_rule_signal。 | <code>    updated["label"] = "suspicious"</code> |
| L0191 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 apply_rule_signal。 | <code>    updated["detection_source"] = "model+rule" if original_score &gt;= rule_score else "rule"</code> |
| L0192 | 结束当前函数并把结果返回给调用方，当前位于函数 apply_rule_signal。 | <code>    return updated</code> |
