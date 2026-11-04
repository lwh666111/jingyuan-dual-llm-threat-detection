# `scripts/fast_defense.py` 逐行注释

**脚本用途：** 自动防御快速路径：匹配高确定性规则并调用防火墙控制，缩短封禁时间。

**源码行数：** 352　**函数/类数量：** 19

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import hashlib&#96;。 | <code>import hashlib</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import html&#96;。 | <code>import html</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;import queue&#96;。 | <code>import queue</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;import re&#96;。 | <code>import re</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;import threading&#96;。 | <code>import threading</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;import time&#96;。 | <code>import time</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;import unicodedata&#96;。 | <code>import unicodedata</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.parse&#96;。 | <code>import urllib.parse</code> |
| L0012 | 导入后续逻辑所需的模块、类或函数：&#96;from dataclasses import dataclass&#96;。 | <code>from dataclasses import dataclass</code> |
| L0013 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime&#96;。 | <code>from datetime import datetime</code> |
| L0014 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0015 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, Iterable, List, Optional, Sequence&#96;。 | <code>from typing import Any, Dict, Iterable, List, Optional, Sequence</code> |
| L0016 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0017 | 导入后续逻辑所需的模块、类或函数：&#96;import pymysql&#96;。 | <code>import pymysql</code> |
| L0018 | 导入后续逻辑所需的模块、类或函数：&#96;from pymysql.cursors import DictCursor&#96;。 | <code>from pymysql.cursors import DictCursor</code> |
| L0019 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0020 | 开始受保护操作，异常会交给后续分支处理。 | <code>try:</code> |
| L0021 | 导入后续逻辑所需的模块、类或函数：&#96;from firewall_control import firewall_block_ip, firewall_status, is_safe_automatic_target, normalize_ip_literal&#96;。 | <code>    from firewall_control import firewall_block_ip, firewall_status, is_safe_automatic_target, normalize_ip_literal</code> |
| L0022 | 捕获异常，避免单次错误导致整个服务退出。 | <code>except ImportError:  # package import during tests</code> |
| L0023 | 导入后续逻辑所需的模块、类或函数：&#96;from scripts.firewall_control import firewall_block_ip, firewall_status, is_safe_automatic_target, normalize_ip_literal&#96;。 | <code>    from scripts.firewall_control import firewall_block_ip, firewall_status, is_safe_automatic_target, normalize_ip_literal</code> |
| L0024 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0025 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0026 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>AUDIT_DDL = """</code> |
| L0027 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>CREATE TABLE IF NOT EXISTS demo_fast_defense_audit (</code> |
| L0028 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  id BIGINT AUTO_INCREMENT PRIMARY KEY,</code> |
| L0029 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  request_fingerprint CHAR(64) NOT NULL,</code> |
| L0030 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  source_ip VARCHAR(64) NOT NULL,</code> |
| L0031 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  destination_ip VARCHAR(64) NOT NULL DEFAULT '',</code> |
| L0032 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  method VARCHAR(16) NOT NULL DEFAULT '',</code> |
| L0033 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  uri TEXT NOT NULL,</code> |
| L0034 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  category VARCHAR(64) NOT NULL,</code> |
| L0035 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  score INT NOT NULL,</code> |
| L0036 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  rule_ids_json TEXT NOT NULL,</code> |
| L0037 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  decision VARCHAR(32) NOT NULL,</code> |
| L0038 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  firewall_success TINYINT(1) NOT NULL DEFAULT 0,</code> |
| L0039 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  firewall_detail TEXT NOT NULL,</code> |
| L0040 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  defense_latency_ms DOUBLE NULL,</code> |
| L0041 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  request_time DATETIME(3) NULL,</code> |
| L0042 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0043 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  KEY idx_fast_ip_time (source_ip, created_at),</code> |
| L0044 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  KEY idx_fast_category_time (category, created_at)</code> |
| L0045 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L0046 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>"""</code> |
| L0047 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0048 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0049 | 应用装饰器 &#96;@dataclass(frozen=True)&#96;，为下一定义附加权限、缓存或注册行为。 | <code>@dataclass(frozen=True)</code> |
| L0050 | 定义类 &#96;FastRule&#96;，集中保存相关状态与操作。 | <code>class FastRule:</code> |
| L0051 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 FastRule。 | <code>    rule_id: str</code> |
| L0052 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 FastRule。 | <code>    category: str</code> |
| L0053 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 FastRule。 | <code>    score: int</code> |
| L0054 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 FastRule。 | <code>    all_patterns: Sequence[re.Pattern[str]]</code> |
| L0055 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 FastRule。 | <code>    any_patterns: Sequence[re.Pattern[str]]</code> |
| L0056 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 FastRule。 | <code>    exclude_patterns: Sequence[re.Pattern[str]]</code> |
| L0057 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0058 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0059 | 应用装饰器 &#96;@dataclass(frozen=True)&#96;，为下一定义附加权限、缓存或注册行为。 | <code>@dataclass(frozen=True)</code> |
| L0060 | 定义类 &#96;FastDecision&#96;，集中保存相关状态与操作。 | <code>class FastDecision:</code> |
| L0061 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 FastDecision。 | <code>    source_ip: str</code> |
| L0062 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 FastDecision。 | <code>    destination_ip: str</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 FastDecision。 | <code>    method: str</code> |
| L0064 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 FastDecision。 | <code>    uri: str</code> |
| L0065 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 FastDecision。 | <code>    request_time: Optional[datetime]</code> |
| L0066 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 FastDecision。 | <code>    category: str</code> |
| L0067 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 FastDecision。 | <code>    score: int</code> |
| L0068 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 FastDecision。 | <code>    rule_ids: Sequence[str]</code> |
| L0069 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 FastDecision。 | <code>    fingerprint: str</code> |
| L0070 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0071 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0072 | 定义compilemany函数 &#96;_compile_many&#96;，封装可复用业务逻辑。 | <code>def _compile_many(values: Iterable[str]) -&gt; List[re.Pattern[str]]:</code> |
| L0073 | 结束当前函数并把结果返回给调用方，当前位于函数 _compile_many。 | <code>    return [re.compile(str(value), re.I &#124; re.S) for value in values if str(value).strip()]</code> |
| L0074 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0075 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0076 | 定义标准化requesttext函数 &#96;normalize_request_text&#96;，封装可复用业务逻辑。 | <code>def normalize_request_text(request: Dict[str, Any]) -&gt; str:</code> |
| L0077 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 normalize_request_text。 | <code>    raw = "\n".join(</code> |
| L0078 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_request_text。 | <code>        str(request.get(key) or "")</code> |
| L0079 | 遍历集合中的数据项并逐项处理，当前位于函数 normalize_request_text。 | <code>        for key in ("method", "uri", "host", "content_type", "request_body")</code> |
| L0080 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_request_text。 | <code>    )</code> |
| L0081 | 计算并保存 &#96;variants&#96;（variants），供后续逻辑使用，当前位于函数 normalize_request_text。 | <code>    variants: List[str] = []</code> |
| L0082 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 normalize_request_text。 | <code>    current = raw</code> |
| L0083 | 遍历集合中的数据项并逐项处理，当前位于函数 normalize_request_text。 | <code>    for _ in range(4):</code> |
| L0084 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 normalize_request_text。 | <code>        current = html.unescape(urllib.parse.unquote_plus(current))</code> |
| L0085 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 normalize_request_text。 | <code>        current = unicodedata.normalize("NFKC", current).replace("\x00", "")</code> |
| L0086 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 normalize_request_text。 | <code>        current = re.sub(r"[\t\r\f\v]+", " ", current)</code> |
| L0087 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 normalize_request_text。 | <code>        current = re.sub(r" +", " ", current).lower()</code> |
| L0088 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_request_text。 | <code>        if current in variants:</code> |
| L0089 | 控制当前循环或占位分支的执行流程，当前位于函数 normalize_request_text。 | <code>            break</code> |
| L0090 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 normalize_request_text。 | <code>        variants.append(current)</code> |
| L0091 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_request_text。 | <code>    return "\n".join(variants)</code> |
| L0092 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0093 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0094 | 定义类 &#96;FastRuleEngine&#96;，集中保存相关状态与操作。 | <code>class FastRuleEngine:</code> |
| L0095 | 定义init函数 &#96;__init__&#96;，封装可复用业务逻辑。 | <code>    def __init__(self, rules_path: Path &#124; str):</code> |
| L0096 | 计算并保存 &#96;rules_path&#96;（rulespath），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.rules_path = Path(rules_path)</code> |
| L0097 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 __init__。 | <code>        rows = json.loads(self.rules_path.read_text(encoding="utf-8-sig"))</code> |
| L0098 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 __init__。 | <code>        if not isinstance(rows, list) or not rows:</code> |
| L0099 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 __init__。 | <code>            raise ValueError(f"fast defense rules are empty: {self.rules_path}")</code> |
| L0100 | 计算并保存 &#96;rules&#96;（rules），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.rules = [</code> |
| L0101 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            FastRule(</code> |
| L0102 | 计算并保存 &#96;rule_id&#96;（ruleid），供后续逻辑使用，当前位于函数 __init__。 | <code>                rule_id=str(row["id"]),</code> |
| L0103 | 计算并保存 &#96;category&#96;（category），供后续逻辑使用，当前位于函数 __init__。 | <code>                category=str(row["category"]),</code> |
| L0104 | 计算并保存 &#96;score&#96;（score），供后续逻辑使用，当前位于函数 __init__。 | <code>                score=int(row.get("score", 10)),</code> |
| L0105 | 计算并保存 &#96;all_patterns&#96;（allpatterns），供后续逻辑使用，当前位于函数 __init__。 | <code>                all_patterns=_compile_many(row.get("all_regex") or []),</code> |
| L0106 | 计算并保存 &#96;any_patterns&#96;（anypatterns），供后续逻辑使用，当前位于函数 __init__。 | <code>                any_patterns=_compile_many(row.get("any_regex") or []),</code> |
| L0107 | 计算并保存 &#96;exclude_patterns&#96;（excludepatterns），供后续逻辑使用，当前位于函数 __init__。 | <code>                exclude_patterns=_compile_many(row.get("exclude_regex") or []),</code> |
| L0108 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 __init__。 | <code>            )</code> |
| L0109 | 遍历集合中的数据项并逐项处理，当前位于函数 __init__。 | <code>            for row in rows</code> |
| L0110 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 __init__。 | <code>            if bool(row.get("instant_block", True))</code> |
| L0111 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 __init__。 | <code>        ]</code> |
| L0112 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0113 | 定义match函数 &#96;match&#96;，封装可复用业务逻辑。 | <code>    def match(self, request: Dict[str, Any]) -&gt; List[FastRule]:</code> |
| L0114 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 match。 | <code>        text = normalize_request_text(request)</code> |
| L0115 | 计算并保存 &#96;matches&#96;（matches），供后续逻辑使用，当前位于函数 match。 | <code>        matches: List[FastRule] = []</code> |
| L0116 | 遍历集合中的数据项并逐项处理，当前位于函数 match。 | <code>        for rule in self.rules:</code> |
| L0117 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 match。 | <code>            if rule.exclude_patterns and any(pattern.search(text) for pattern in rule.exclude_patterns):</code> |
| L0118 | 控制当前循环或占位分支的执行流程，当前位于函数 match。 | <code>                continue</code> |
| L0119 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 match。 | <code>            if rule.all_patterns and not all(pattern.search(text) for pattern in rule.all_patterns):</code> |
| L0120 | 控制当前循环或占位分支的执行流程，当前位于函数 match。 | <code>                continue</code> |
| L0121 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 match。 | <code>            if rule.any_patterns and not any(pattern.search(text) for pattern in rule.any_patterns):</code> |
| L0122 | 控制当前循环或占位分支的执行流程，当前位于函数 match。 | <code>                continue</code> |
| L0123 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 match。 | <code>            if rule.all_patterns or rule.any_patterns:</code> |
| L0124 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 match。 | <code>                matches.append(rule)</code> |
| L0125 | 结束当前函数并把结果返回给调用方，当前位于函数 match。 | <code>        return matches</code> |
| L0126 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0127 | 定义decide函数 &#96;decide&#96;，封装可复用业务逻辑。 | <code>    def decide(self, request: Dict[str, Any]) -&gt; Optional[FastDecision]:</code> |
| L0128 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 decide。 | <code>        source_ip = normalize_ip_literal(request.get("src_ip"))</code> |
| L0129 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decide。 | <code>        if not is_safe_automatic_target(source_ip, allow_private=False):</code> |
| L0130 | 结束当前函数并把结果返回给调用方，当前位于函数 decide。 | <code>            return None</code> |
| L0131 | 计算并保存 &#96;matches&#96;（matches），供后续逻辑使用，当前位于函数 decide。 | <code>        matches = self.match(request)</code> |
| L0132 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decide。 | <code>        if not matches:</code> |
| L0133 | 结束当前函数并把结果返回给调用方，当前位于函数 decide。 | <code>            return None</code> |
| L0134 | 计算并保存 &#96;highest&#96;（highest），供后续逻辑使用，当前位于函数 decide。 | <code>        highest = max(matches, key=lambda item: item.score)</code> |
| L0135 | 计算并保存 &#96;rule_ids&#96;（ruleids），供后续逻辑使用，当前位于函数 decide。 | <code>        rule_ids = tuple(dict.fromkeys(rule.rule_id for rule in matches))</code> |
| L0136 | 计算并保存 &#96;fingerprint_text&#96;（fingerprinttext），供后续逻辑使用，当前位于函数 decide。 | <code>        fingerprint_text = "&#124;".join(</code> |
| L0137 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decide。 | <code>            [</code> |
| L0138 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decide。 | <code>                source_ip,</code> |
| L0139 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decide。 | <code>                str(request.get("frame_no") or ""),</code> |
| L0140 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decide。 | <code>                str(request.get("time") or ""),</code> |
| L0141 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decide。 | <code>                str(request.get("method") or ""),</code> |
| L0142 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decide。 | <code>                str(request.get("uri") or ""),</code> |
| L0143 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decide。 | <code>                str(request.get("request_body") or ""),</code> |
| L0144 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 decide。 | <code>            ]</code> |
| L0145 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 decide。 | <code>        )</code> |
| L0146 | 计算并保存 &#96;request_time&#96;（requesttime），供后续逻辑使用，当前位于函数 decide。 | <code>        request_time = None</code> |
| L0147 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 decide。 | <code>        try:</code> |
| L0148 | 计算并保存 &#96;timestamp&#96;（timestamp），供后续逻辑使用，当前位于函数 decide。 | <code>            timestamp = float(request.get("time") or 0)</code> |
| L0149 | 计算并保存 &#96;request_time&#96;（requesttime），供后续逻辑使用，当前位于函数 decide。 | <code>            request_time = datetime.fromtimestamp(timestamp) if timestamp &gt; 0 else None</code> |
| L0150 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 decide。 | <code>        except (TypeError, ValueError, OSError):</code> |
| L0151 | 控制当前循环或占位分支的执行流程，当前位于函数 decide。 | <code>            pass</code> |
| L0152 | 结束当前函数并把结果返回给调用方，当前位于函数 decide。 | <code>        return FastDecision(</code> |
| L0153 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 decide。 | <code>            source_ip=source_ip,</code> |
| L0154 | 计算并保存 &#96;destination_ip&#96;（destinationip），供后续逻辑使用，当前位于函数 decide。 | <code>            destination_ip=normalize_ip_literal(request.get("dst_ip")),</code> |
| L0155 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 decide。 | <code>            method=str(request.get("method") or "").upper(),</code> |
| L0156 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 decide。 | <code>            uri=str(request.get("uri") or "")[:8192],</code> |
| L0157 | 计算并保存 &#96;request_time&#96;（requesttime），供后续逻辑使用，当前位于函数 decide。 | <code>            request_time=request_time,</code> |
| L0158 | 计算并保存 &#96;category&#96;（category），供后续逻辑使用，当前位于函数 decide。 | <code>            category=highest.category,</code> |
| L0159 | 计算并保存 &#96;score&#96;（score），供后续逻辑使用，当前位于函数 decide。 | <code>            score=max(rule.score for rule in matches),</code> |
| L0160 | 计算并保存 &#96;rule_ids&#96;（ruleids），供后续逻辑使用，当前位于函数 decide。 | <code>            rule_ids=rule_ids,</code> |
| L0161 | 计算并保存 &#96;fingerprint&#96;（fingerprint），供后续逻辑使用，当前位于函数 decide。 | <code>            fingerprint=hashlib.sha256(fingerprint_text.encode("utf-8", errors="replace")).hexdigest(),</code> |
| L0162 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 decide。 | <code>        )</code> |
| L0163 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0164 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0165 | 定义类 &#96;FastDefenseGuard&#96;，集中保存相关状态与操作。 | <code>class FastDefenseGuard:</code> |
| L0166 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 FastDefenseGuard。 | <code>    """Evaluate requests inline and enforce decisions on a bounded worker queue."""</code> |
| L0167 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0168 | 定义init函数 &#96;__init__&#96;，封装可复用业务逻辑。 | <code>    def __init__(</code> |
| L0169 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>        self,</code> |
| L0170 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>        rules_path: Path &#124; str,</code> |
| L0171 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>        mysql_config: Dict[str, Any],</code> |
| L0172 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>        log_path: Path &#124; str,</code> |
| L0173 | 计算并保存 &#96;policy_cache_seconds&#96;（policycacheseconds），供后续逻辑使用，当前位于函数 __init__。 | <code>        policy_cache_seconds: float = 1.0,</code> |
| L0174 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 __init__。 | <code>    ):</code> |
| L0175 | 计算并保存 &#96;engine&#96;（engine），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.engine = FastRuleEngine(rules_path)</code> |
| L0176 | 计算并保存 &#96;mysql_config&#96;（mysql配置），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.mysql_config = dict(mysql_config)</code> |
| L0177 | 计算并保存 &#96;log_path&#96;（logpath），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.log_path = Path(log_path)</code> |
| L0178 | 计算并保存 &#96;policy_cache_seconds&#96;（policycacheseconds），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.policy_cache_seconds = max(0.2, float(policy_cache_seconds))</code> |
| L0179 | 计算并保存 &#96;_enabled&#96;（enabled），供后续逻辑使用，当前位于函数 __init__。 | <code>        self._enabled = False</code> |
| L0180 | 计算并保存 &#96;_policy_checked_at&#96;（policycheckedat），供后续逻辑使用，当前位于函数 __init__。 | <code>        self._policy_checked_at = 0.0</code> |
| L0181 | 计算并保存 &#96;_queue&#96;（queue），供后续逻辑使用，当前位于函数 __init__。 | <code>        self._queue: queue.Queue[Optional[FastDecision]] = queue.Queue(maxsize=256)</code> |
| L0182 | 计算并保存 &#96;_pending_ips&#96;（pendingips），供后续逻辑使用，当前位于函数 __init__。 | <code>        self._pending_ips: set[str] = set()</code> |
| L0183 | 计算并保存 &#96;_lock&#96;（lock），供后续逻辑使用，当前位于函数 __init__。 | <code>        self._lock = threading.Lock()</code> |
| L0184 | 计算并保存 &#96;_closed&#96;（closed），供后续逻辑使用，当前位于函数 __init__。 | <code>        self._closed = False</code> |
| L0185 | 计算并保存 &#96;_schema_ready&#96;（schemaready），供后续逻辑使用，当前位于函数 __init__。 | <code>        self._schema_ready = False</code> |
| L0186 | 计算并保存 &#96;_worker&#96;（worker），供后续逻辑使用，当前位于函数 __init__。 | <code>        self._worker = threading.Thread(target=self._worker_loop, name="fast-defense", daemon=True)</code> |
| L0187 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>        self._worker.start()</code> |
| L0188 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0189 | 定义connect函数 &#96;_connect&#96;，封装可复用业务逻辑。 | <code>    def _connect(self, autocommit: bool = False):</code> |
| L0190 | 结束当前函数并把结果返回给调用方，当前位于函数 _connect。 | <code>        return pymysql.connect(</code> |
| L0191 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 _connect。 | <code>            host=self.mysql_config["host"],</code> |
| L0192 | 计算并保存 &#96;port&#96;（port），供后续逻辑使用，当前位于函数 _connect。 | <code>            port=int(self.mysql_config["port"]),</code> |
| L0193 | 计算并保存 &#96;user&#96;（user），供后续逻辑使用，当前位于函数 _connect。 | <code>            user=self.mysql_config["user"],</code> |
| L0194 | 控制当前循环或占位分支的执行流程，当前位于函数 _connect。 | <code>            password=self.mysql_config["password"],</code> |
| L0195 | 计算并保存 &#96;database&#96;（数据库），供后续逻辑使用，当前位于函数 _connect。 | <code>            database=self.mysql_config["database"],</code> |
| L0196 | 计算并保存 &#96;charset&#96;（charset），供后续逻辑使用，当前位于函数 _connect。 | <code>            charset="utf8mb4",</code> |
| L0197 | 计算并保存 &#96;cursorclass&#96;（cursorclass），供后续逻辑使用，当前位于函数 _connect。 | <code>            cursorclass=DictCursor,</code> |
| L0198 | 计算并保存 &#96;autocommit&#96;（autocommit），供后续逻辑使用，当前位于函数 _connect。 | <code>            autocommit=autocommit,</code> |
| L0199 | 计算并保存 &#96;connect_timeout&#96;（connecttimeout），供后续逻辑使用，当前位于函数 _connect。 | <code>            connect_timeout=2,</code> |
| L0200 | 计算并保存 &#96;read_timeout&#96;（读取timeout），供后续逻辑使用，当前位于函数 _connect。 | <code>            read_timeout=3,</code> |
| L0201 | 计算并保存 &#96;write_timeout&#96;（写入timeout），供后续逻辑使用，当前位于函数 _connect。 | <code>            write_timeout=3,</code> |
| L0202 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _connect。 | <code>        )</code> |
| L0203 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0204 | 定义log函数 &#96;_log&#96;，封装可复用业务逻辑。 | <code>    def _log(self, message: str) -&gt; None:</code> |
| L0205 | 计算并保存 &#96;line&#96;（line），供后续逻辑使用，当前位于函数 _log。 | <code>        line = f"[{datetime.now().isoformat(timespec='seconds')}] {message}"</code> |
| L0206 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 _log。 | <code>        print(line, flush=True)</code> |
| L0207 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _log。 | <code>        self.log_path.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0208 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 _log。 | <code>        with self.log_path.open("a", encoding="utf-8") as handle:</code> |
| L0209 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _log。 | <code>            handle.write(line + "\n")</code> |
| L0210 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0211 | 定义enabled函数 &#96;enabled&#96;，封装可复用业务逻辑。 | <code>    def enabled(self) -&gt; bool:</code> |
| L0212 | 计算并保存 &#96;now&#96;（now），供后续逻辑使用，当前位于函数 enabled。 | <code>        now = time.monotonic()</code> |
| L0213 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 enabled。 | <code>        if now - self._policy_checked_at &lt; self.policy_cache_seconds:</code> |
| L0214 | 结束当前函数并把结果返回给调用方，当前位于函数 enabled。 | <code>            return self._enabled</code> |
| L0215 | 计算并保存 &#96;_policy_checked_at&#96;（policycheckedat），供后续逻辑使用，当前位于函数 enabled。 | <code>        self._policy_checked_at = now</code> |
| L0216 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 enabled。 | <code>        try:</code> |
| L0217 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 enabled。 | <code>            conn = self._connect(autocommit=True)</code> |
| L0218 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 enabled。 | <code>            try:</code> |
| L0219 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 enabled。 | <code>                with conn.cursor() as cur:</code> |
| L0220 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 enabled。 | <code>                    cur.execute(</code> |
| L0221 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 enabled。 | <code>                        "SELECT config_value FROM demo_system_config WHERE config_key='auto_defense_enabled' LIMIT 1"</code> |
| L0222 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 enabled。 | <code>                    )</code> |
| L0223 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 enabled。 | <code>                    row = cur.fetchone() or {}</code> |
| L0224 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 enabled。 | <code>                self._enabled = str(row.get("config_value") or "0") == "1"</code> |
| L0225 | 无论成功或异常都执行资源清理，当前位于函数 enabled。 | <code>            finally:</code> |
| L0226 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 enabled。 | <code>                conn.close()</code> |
| L0227 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 enabled。 | <code>        except Exception as exc:</code> |
| L0228 | 计算并保存 &#96;_enabled&#96;（enabled），供后续逻辑使用，当前位于函数 enabled。 | <code>            self._enabled = False</code> |
| L0229 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 enabled。 | <code>            self._log(f"policy read failed; fast path disabled: {type(exc).__name__}: {exc}")</code> |
| L0230 | 结束当前函数并把结果返回给调用方，当前位于函数 enabled。 | <code>        return self._enabled</code> |
| L0231 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0232 | 定义inspect函数 &#96;inspect&#96;，封装可复用业务逻辑。 | <code>    def inspect(self, request: Dict[str, Any]) -&gt; Optional[FastDecision]:</code> |
| L0233 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 inspect。 | <code>        if self._closed or not self.enabled():</code> |
| L0234 | 结束当前函数并把结果返回给调用方，当前位于函数 inspect。 | <code>            return None</code> |
| L0235 | 计算并保存 &#96;decision&#96;（decision），供后续逻辑使用，当前位于函数 inspect。 | <code>        decision = self.engine.decide(request)</code> |
| L0236 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 inspect。 | <code>        if decision is None:</code> |
| L0237 | 结束当前函数并把结果返回给调用方，当前位于函数 inspect。 | <code>            return None</code> |
| L0238 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 inspect。 | <code>        with self._lock:</code> |
| L0239 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 inspect。 | <code>            if decision.source_ip in self._pending_ips:</code> |
| L0240 | 结束当前函数并把结果返回给调用方，当前位于函数 inspect。 | <code>                return decision</code> |
| L0241 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 inspect。 | <code>            self._pending_ips.add(decision.source_ip)</code> |
| L0242 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 inspect。 | <code>        try:</code> |
| L0243 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 inspect。 | <code>            self._queue.put_nowait(decision)</code> |
| L0244 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 inspect。 | <code>        except queue.Full:</code> |
| L0245 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 inspect。 | <code>            with self._lock:</code> |
| L0246 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 inspect。 | <code>                self._pending_ips.discard(decision.source_ip)</code> |
| L0247 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 inspect。 | <code>            self._log(f"decision queue full; ip={decision.source_ip}")</code> |
| L0248 | 结束当前函数并把结果返回给调用方，当前位于函数 inspect。 | <code>        return decision</code> |
| L0249 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0250 | 定义alreadyblocked函数 &#96;_already_blocked&#96;，封装可复用业务逻辑。 | <code>    def _already_blocked(self, cur: Any, ip_address: str) -&gt; bool:</code> |
| L0251 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 _already_blocked。 | <code>        cur.execute("SELECT id FROM demo_blocked_ips WHERE ip_address=%s LIMIT 1", (ip_address,))</code> |
| L0252 | 结束当前函数并把结果返回给调用方，当前位于函数 _already_blocked。 | <code>        return bool(cur.fetchone()) and bool(firewall_status(ip_address).get("active"))</code> |
| L0253 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0254 | 定义ensureschema函数 &#96;_ensure_schema&#96;，封装可复用业务逻辑。 | <code>    def _ensure_schema(self, cur: Any) -&gt; None:</code> |
| L0255 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _ensure_schema。 | <code>        if getattr(self, "_schema_ready", False):</code> |
| L0256 | 结束当前函数并把结果返回给调用方，当前位于函数 _ensure_schema。 | <code>            return</code> |
| L0257 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 _ensure_schema。 | <code>        cur.execute("SHOW COLUMNS FROM demo_fast_defense_audit LIKE 'defense_latency_ms'")</code> |
| L0258 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _ensure_schema。 | <code>        if not cur.fetchone():</code> |
| L0259 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 _ensure_schema。 | <code>            cur.execute(</code> |
| L0260 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _ensure_schema。 | <code>                "ALTER TABLE demo_fast_defense_audit "</code> |
| L0261 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _ensure_schema。 | <code>                "ADD COLUMN defense_latency_ms DOUBLE NULL AFTER firewall_detail"</code> |
| L0262 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _ensure_schema。 | <code>            )</code> |
| L0263 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 _ensure_schema。 | <code>        cur.execute("SHOW COLUMNS FROM demo_blocked_ips LIKE 'defense_latency_ms'")</code> |
| L0264 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _ensure_schema。 | <code>        if not cur.fetchone():</code> |
| L0265 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 _ensure_schema。 | <code>            cur.execute(</code> |
| L0266 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _ensure_schema。 | <code>                "ALTER TABLE demo_blocked_ips "</code> |
| L0267 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _ensure_schema。 | <code>                "ADD COLUMN defense_latency_ms DOUBLE NULL AFTER blocked_role"</code> |
| L0268 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _ensure_schema。 | <code>            )</code> |
| L0269 | 计算并保存 &#96;_schema_ready&#96;（schemaready），供后续逻辑使用，当前位于函数 _ensure_schema。 | <code>        self._schema_ready = True</code> |
| L0270 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0271 | 定义enforce函数 &#96;_enforce&#96;，封装可复用业务逻辑。 | <code>    def _enforce(self, decision: FastDecision) -&gt; None:</code> |
| L0272 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 _enforce。 | <code>        conn = self._connect(autocommit=False)</code> |
| L0273 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _enforce。 | <code>        try:</code> |
| L0274 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 _enforce。 | <code>            with conn.cursor() as cur:</code> |
| L0275 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 _enforce。 | <code>                cur.execute(AUDIT_DDL)</code> |
| L0276 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                self._ensure_schema(cur)</code> |
| L0277 | 计算并保存 &#96;already_blocked&#96;（alreadyblocked），供后续逻辑使用，当前位于函数 _enforce。 | <code>                already_blocked = self._already_blocked(cur, decision.source_ip)</code> |
| L0278 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _enforce。 | <code>                if already_blocked:</code> |
| L0279 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                    firewall_ok, firewall_detail, defense_latency_ms = True, "already_blocked", None</code> |
| L0280 | 处理前述条件均未命中的情况，当前位于函数 _enforce。 | <code>                else:</code> |
| L0281 | 计算并保存 &#96;defense_started&#96;（defensestarted），供后续逻辑使用，当前位于函数 _enforce。 | <code>                    defense_started = time.perf_counter()</code> |
| L0282 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                    firewall_ok, firewall_detail = firewall_block_ip(decision.source_ip)</code> |
| L0283 | 计算并保存 &#96;defense_latency_ms&#96;（defenselatencyms），供后续逻辑使用，当前位于函数 _enforce。 | <code>                    defense_latency_ms = (time.perf_counter() - defense_started) * 1000.0</code> |
| L0284 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 _enforce。 | <code>                cur.execute(</code> |
| L0285 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 _enforce。 | <code>                    """</code> |
| L0286 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 _enforce。 | <code>                    INSERT INTO demo_fast_defense_audit(</code> |
| L0287 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 _enforce。 | <code>                      request_fingerprint,source_ip,destination_ip,method,uri,category,score,</code> |
| L0288 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 _enforce。 | <code>                      rule_ids_json,decision,firewall_success,firewall_detail,defense_latency_ms,request_time</code> |
| L0289 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 _enforce。 | <code>                    ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)</code> |
| L0290 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 _enforce。 | <code>                    """,</code> |
| L0291 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                    (</code> |
| L0292 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                        decision.fingerprint,</code> |
| L0293 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                        decision.source_ip,</code> |
| L0294 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                        decision.destination_ip,</code> |
| L0295 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                        decision.method,</code> |
| L0296 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                        decision.uri,</code> |
| L0297 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                        decision.category,</code> |
| L0298 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                        decision.score,</code> |
| L0299 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                        json.dumps(list(decision.rule_ids), ensure_ascii=False),</code> |
| L0300 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                        "silent_block" if firewall_ok else "block_failed",</code> |
| L0301 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                        1 if firewall_ok else 0,</code> |
| L0302 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                        firewall_detail[:4000],</code> |
| L0303 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                        defense_latency_ms,</code> |
| L0304 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                        decision.request_time,</code> |
| L0305 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _enforce。 | <code>                    ),</code> |
| L0306 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _enforce。 | <code>                )</code> |
| L0307 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _enforce。 | <code>                if firewall_ok:</code> |
| L0308 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 _enforce。 | <code>                    cur.execute("DELETE FROM demo_auto_defense_releases WHERE ip_address=%s", (decision.source_ip,))</code> |
| L0309 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 _enforce。 | <code>                    cur.execute(</code> |
| L0310 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 _enforce。 | <code>                        """</code> |
| L0311 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 _enforce。 | <code>                        INSERT INTO demo_blocked_ips(</code> |
| L0312 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 _enforce。 | <code>                          ip_address,source_event_id,reason,blocked_by,blocked_role,defense_latency_ms</code> |
| L0313 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 _enforce。 | <code>                        ) VALUES(%s,'','automatic_protection','auto-defense','system',%s)</code> |
| L0314 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 _enforce。 | <code>                        ON DUPLICATE KEY UPDATE source_event_id='',reason='automatic_protection',</code> |
| L0315 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 _enforce。 | <code>                          blocked_by='auto-defense',blocked_role='system',</code> |
| L0316 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 _enforce。 | <code>                          defense_latency_ms=VALUES(defense_latency_ms),blocked_at=CURRENT_TIMESTAMP</code> |
| L0317 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 _enforce。 | <code>                        """,</code> |
| L0318 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                        (decision.source_ip, defense_latency_ms),</code> |
| L0319 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _enforce。 | <code>                    )</code> |
| L0320 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>            conn.commit()</code> |
| L0321 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 _enforce。 | <code>            self._log(</code> |
| L0322 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                f"silent decision ip={decision.source_ip} category={decision.category} "</code> |
| L0323 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>                f"rules={','.join(decision.rule_ids)} success={int(firewall_ok)}"</code> |
| L0324 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _enforce。 | <code>            )</code> |
| L0325 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _enforce。 | <code>        except Exception:</code> |
| L0326 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>            conn.rollback()</code> |
| L0327 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>            raise</code> |
| L0328 | 无论成功或异常都执行资源清理，当前位于函数 _enforce。 | <code>        finally:</code> |
| L0329 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _enforce。 | <code>            conn.close()</code> |
| L0330 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0331 | 定义workerloop函数 &#96;_worker_loop&#96;，封装可复用业务逻辑。 | <code>    def _worker_loop(self) -&gt; None:</code> |
| L0332 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 _worker_loop。 | <code>        while True:</code> |
| L0333 | 计算并保存 &#96;decision&#96;（decision），供后续逻辑使用，当前位于函数 _worker_loop。 | <code>            decision = self._queue.get()</code> |
| L0334 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _worker_loop。 | <code>            if decision is None:</code> |
| L0335 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _worker_loop。 | <code>                self._queue.task_done()</code> |
| L0336 | 结束当前函数并把结果返回给调用方，当前位于函数 _worker_loop。 | <code>                return</code> |
| L0337 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _worker_loop。 | <code>            try:</code> |
| L0338 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _worker_loop。 | <code>                self._enforce(decision)</code> |
| L0339 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _worker_loop。 | <code>            except Exception as exc:</code> |
| L0340 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 _worker_loop。 | <code>                self._log(f"enforcement failed ip={decision.source_ip}: {type(exc).__name__}: {exc}")</code> |
| L0341 | 无论成功或异常都执行资源清理，当前位于函数 _worker_loop。 | <code>            finally:</code> |
| L0342 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 _worker_loop。 | <code>                with self._lock:</code> |
| L0343 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _worker_loop。 | <code>                    self._pending_ips.discard(decision.source_ip)</code> |
| L0344 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _worker_loop。 | <code>                self._queue.task_done()</code> |
| L0345 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0346 | 定义close函数 &#96;close&#96;，封装可复用业务逻辑。 | <code>    def close(self, timeout: float = 8.0) -&gt; None:</code> |
| L0347 | 计算并保存 &#96;_closed&#96;（closed），供后续逻辑使用，当前位于函数 close。 | <code>        self._closed = True</code> |
| L0348 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 close。 | <code>        try:</code> |
| L0349 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 close。 | <code>            self._queue.put_nowait(None)</code> |
| L0350 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 close。 | <code>        except queue.Full:</code> |
| L0351 | 结束当前函数并把结果返回给调用方，当前位于函数 close。 | <code>            return</code> |
| L0352 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 close。 | <code>        self._worker.join(timeout=max(0.1, timeout))</code> |
