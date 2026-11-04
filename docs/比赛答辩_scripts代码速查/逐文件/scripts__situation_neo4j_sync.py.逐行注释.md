# `scripts/situation_neo4j_sync.py` 逐行注释

**脚本用途：** 可选 Neo4j 图数据同步，实现攻击者、动作和资产关系映射。

**源码行数：** 239　**函数/类数量：** 9

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import base64&#96;。 | <code>import base64</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;import time&#96;。 | <code>import time</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.request&#96;。 | <code>import urllib.request</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime&#96;。 | <code>from datetime import datetime</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, List, Sequence&#96;。 | <code>from typing import Any, Dict, List, Sequence</code> |
| L0010 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;from situation_store import MySQLSettings, MySQLSituationStore, json_value&#96;。 | <code>from situation_store import MySQLSettings, MySQLSituationStore, json_value</code> |
| L0012 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0013 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0014 | 定义log函数 &#96;log&#96;，封装可复用业务逻辑。 | <code>def log(message: str) -&gt; None:</code> |
| L0015 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 log。 | <code>    print(f"[{datetime.now().isoformat(timespec='seconds')}] {message}", flush=True)</code> |
| L0016 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0017 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0018 | 定义类 &#96;Neo4jHTTPClient&#96;，集中保存相关状态与操作。 | <code>class Neo4jHTTPClient:</code> |
| L0019 | 定义init函数 &#96;__init__&#96;，封装可复用业务逻辑。 | <code>    def __init__(self, url: str, user: str, password: str, database: str = "neo4j", timeout: int = 15) -&gt; None:</code> |
| L0020 | 计算并保存 &#96;base&#96;（base），供后续逻辑使用，当前位于函数 __init__。 | <code>        base = str(url or "").strip().rstrip("/")</code> |
| L0021 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 __init__。 | <code>        if not base.startswith(("http://", "https://")):</code> |
| L0022 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 __init__。 | <code>            raise ValueError("Neo4j 地址必须以 http:// 或 https:// 开头")</code> |
| L0023 | 计算并保存 &#96;endpoint&#96;（endpoint），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.endpoint = f"{base}/db/{database or 'neo4j'}/tx/commit"</code> |
| L0024 | 计算并保存 &#96;token&#96;（token），供后续逻辑使用，当前位于函数 __init__。 | <code>        token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")</code> |
| L0025 | 计算并保存 &#96;headers&#96;（headers），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.headers = {"Content-Type": "application/json", "Authorization": f"Basic {token}"}</code> |
| L0026 | 计算并保存 &#96;timeout&#96;（timeout），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.timeout = max(3, int(timeout))</code> |
| L0027 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0028 | 定义execute函数 &#96;execute&#96;，封装可复用业务逻辑。 | <code>    def execute(self, statements: Sequence[Dict[str, Any]]) -&gt; None:</code> |
| L0029 | 计算并保存 &#96;request&#96;（request），供后续逻辑使用，当前位于函数 execute。 | <code>        request = urllib.request.Request(</code> |
| L0030 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 execute。 | <code>            self.endpoint,</code> |
| L0031 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 execute。 | <code>            data=json.dumps({"statements": list(statements)}, ensure_ascii=False, default=str).encode("utf-8"),</code> |
| L0032 | 计算并保存 &#96;headers&#96;（headers），供后续逻辑使用，当前位于函数 execute。 | <code>            headers=self.headers,</code> |
| L0033 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 execute。 | <code>            method="POST",</code> |
| L0034 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 execute。 | <code>        )</code> |
| L0035 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 execute。 | <code>        with urllib.request.urlopen(request, timeout=self.timeout) as response:</code> |
| L0036 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 execute。 | <code>            result = json.loads(response.read().decode("utf-8"))</code> |
| L0037 | 计算并保存 &#96;errors&#96;（errors），供后续逻辑使用，当前位于函数 execute。 | <code>        errors = result.get("errors") if isinstance(result, dict) else None</code> |
| L0038 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 execute。 | <code>        if errors:</code> |
| L0039 | 计算并保存 &#96;first&#96;（first），供后续逻辑使用，当前位于函数 execute。 | <code>            first = errors[0] if isinstance(errors, list) else errors</code> |
| L0040 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 execute。 | <code>            raise RuntimeError(f"Neo4j 写入失败: {first}")</code> |
| L0041 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0042 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0043 | 定义构建statements函数 &#96;build_statements&#96;，封装可复用业务逻辑。 | <code>def build_statements(payload: Dict[str, Any]) -&gt; List[Dict[str, Any]]:</code> |
| L0044 | 计算并保存 &#96;actions&#96;（actions），供后续逻辑使用，当前位于函数 build_statements。 | <code>    actions = list(payload.get("actions") or [])</code> |
| L0045 | 计算并保存 &#96;normalized_actions&#96;（normalizedactions），供后续逻辑使用，当前位于函数 build_statements。 | <code>    normalized_actions: List[Dict[str, Any]] = []</code> |
| L0046 | 遍历集合中的数据项并逐项处理，当前位于函数 build_statements。 | <code>    for index, row in enumerate(actions, start=1):</code> |
| L0047 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_statements。 | <code>        normalized_actions.append(</code> |
| L0048 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>            {</code> |
| L0049 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>                "action_id": str(row.get("action_id") or f"{payload.get('situation_id')}:action:{index}"),</code> |
| L0050 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>                "action_type": str(row.get("action_type") or "UNKNOWN"),</code> |
| L0051 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>                "stage": str(row.get("stage") or "unknown"),</code> |
| L0052 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>                "sensor": str(row.get("sensor") or "unknown"),</code> |
| L0053 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>                "occurred_at": str(row.get("occurred_at") or ""),</code> |
| L0054 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>                "last_seen_at": str(row.get("last_seen_at") or row.get("occurred_at") or ""),</code> |
| L0055 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>                "count": int(row.get("count") or row.get("action_count") or 1),</code> |
| L0056 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>                "confidence": float(row.get("confidence") or 0),</code> |
| L0057 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>                "sequence": index,</code> |
| L0058 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_statements。 | <code>            }</code> |
| L0059 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_statements。 | <code>        )</code> |
| L0060 | 计算并保存 &#96;links&#96;（links），供后续逻辑使用，当前位于函数 build_statements。 | <code>    links = [</code> |
| L0061 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>        {"from_id": normalized_actions[i]["action_id"], "to_id": normalized_actions[i + 1]["action_id"]}</code> |
| L0062 | 遍历集合中的数据项并逐项处理，当前位于函数 build_statements。 | <code>        for i in range(max(0, len(normalized_actions) - 1))</code> |
| L0063 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_statements。 | <code>    ]</code> |
| L0064 | 计算并保存 &#96;common&#96;（common），供后续逻辑使用，当前位于函数 build_statements。 | <code>    common = {</code> |
| L0065 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>        "situation_id": str(payload.get("situation_id") or ""),</code> |
| L0066 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>        "source_ip": str(payload.get("source_ip") or ""),</code> |
| L0067 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>        "target_asset": str(payload.get("target_asset") or "local-server"),</code> |
| L0068 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>        "started_at": str(payload.get("started_at") or ""),</code> |
| L0069 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>        "last_action_at": str(payload.get("last_action_at") or ""),</code> |
| L0070 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>        "status": str(payload.get("status") or "observing"),</code> |
| L0071 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>        "current_stage": str(payload.get("current_stage") or "unknown"),</code> |
| L0072 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>        "risk_score": float(payload.get("risk_score") or 0),</code> |
| L0073 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>        "risk_level": str(payload.get("risk_level") or "low"),</code> |
| L0074 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>        "total_action_count": int(payload.get("total_action_count") or 0),</code> |
| L0075 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>        "distinct_action_types": int(payload.get("distinct_action_types") or 0),</code> |
| L0076 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>        "actions": normalized_actions,</code> |
| L0077 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>        "links": links,</code> |
| L0078 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_statements。 | <code>    }</code> |
| L0079 | 结束当前函数并把结果返回给调用方，当前位于函数 build_statements。 | <code>    return [</code> |
| L0080 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>        {</code> |
| L0081 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>            "statement": """</code> |
| L0082 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                MERGE (src:SourceIP {address:$source_ip})</code> |
| L0083 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                MERGE (asset:Asset {name:$target_asset})</code> |
| L0084 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                MERGE (s:Situation {id:$situation_id})</code> |
| L0085 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                SET s.started_at=$started_at, s.last_action_at=$last_action_at,</code> |
| L0086 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                    s.status=$status, s.current_stage=$current_stage,</code> |
| L0087 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                    s.risk_score=$risk_score, s.risk_level=$risk_level,</code> |
| L0088 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                    s.total_action_count=$total_action_count,</code> |
| L0089 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                    s.distinct_action_types=$distinct_action_types</code> |
| L0090 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                MERGE (src)-[:GENERATED]-&gt;(s)</code> |
| L0091 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                MERGE (s)-[:TARGETED]-&gt;(asset)</code> |
| L0092 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>            """,</code> |
| L0093 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>            "parameters": common,</code> |
| L0094 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_statements。 | <code>        },</code> |
| L0095 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>        {</code> |
| L0096 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>            "statement": """</code> |
| L0097 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                MATCH (s:Situation {id:$situation_id})</code> |
| L0098 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                MATCH (s)-[:HAS_ACTION]-&gt;(a:Action)</code> |
| L0099 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                OPTIONAL MATCH (a)-[next:NEXT]-&gt;()</code> |
| L0100 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 build_statements。 | <code>                DELETE next</code> |
| L0101 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>            """,</code> |
| L0102 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>            "parameters": common,</code> |
| L0103 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_statements。 | <code>        },</code> |
| L0104 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>        {</code> |
| L0105 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>            "statement": """</code> |
| L0106 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                MATCH (s:Situation {id:$situation_id})</code> |
| L0107 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                OPTIONAL MATCH (s)-[r:HAS_ACTION]-&gt;(:Action)</code> |
| L0108 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 build_statements。 | <code>                DELETE r</code> |
| L0109 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>            """,</code> |
| L0110 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>            "parameters": common,</code> |
| L0111 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_statements。 | <code>        },</code> |
| L0112 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>        {</code> |
| L0113 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>            "statement": """</code> |
| L0114 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                MATCH (s:Situation {id:$situation_id})</code> |
| L0115 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                UNWIND $actions AS row</code> |
| L0116 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                MERGE (a:Action {id:row.action_id})</code> |
| L0117 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                SET a.action_type=row.action_type, a.stage=row.stage, a.sensor=row.sensor,</code> |
| L0118 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                    a.occurred_at=row.occurred_at, a.last_seen_at=row.last_seen_at,</code> |
| L0119 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                    a.count=row.count, a.confidence=row.confidence</code> |
| L0120 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                MERGE (s)-[:HAS_ACTION {sequence:row.sequence}]-&gt;(a)</code> |
| L0121 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>            """,</code> |
| L0122 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>            "parameters": common,</code> |
| L0123 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_statements。 | <code>        },</code> |
| L0124 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>        {</code> |
| L0125 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>            "statement": """</code> |
| L0126 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                UNWIND $links AS link</code> |
| L0127 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                MATCH (a:Action {id:link.from_id}), (b:Action {id:link.to_id})</code> |
| L0128 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>                MERGE (a)-[:NEXT]-&gt;(b)</code> |
| L0129 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_statements。 | <code>            """,</code> |
| L0130 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_statements。 | <code>            "parameters": common,</code> |
| L0131 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_statements。 | <code>        },</code> |
| L0132 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_statements。 | <code>    ]</code> |
| L0133 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0134 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0135 | 定义claimoutbox函数 &#96;claim_outbox&#96;，封装可复用业务逻辑。 | <code>def claim_outbox(store: MySQLSituationStore, limit: int) -&gt; List[Dict[str, Any]]:</code> |
| L0136 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 claim_outbox。 | <code>    conn = store.connect()</code> |
| L0137 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 claim_outbox。 | <code>    try:</code> |
| L0138 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 claim_outbox。 | <code>        with conn.cursor() as cur:</code> |
| L0139 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 claim_outbox。 | <code>            cur.execute(</code> |
| L0140 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_outbox。 | <code>                "UPDATE situation_outbox SET status='retry' WHERE status='processing' AND created_at &lt; UTC_TIMESTAMP() - INTERVAL 10 MINUTE"</code> |
| L0141 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 claim_outbox。 | <code>            )</code> |
| L0142 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 claim_outbox。 | <code>            cur.execute(</code> |
| L0143 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_outbox。 | <code>                """</code> |
| L0144 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 claim_outbox。 | <code>                SELECT id,aggregate_id,payload_json,retry_count</code> |
| L0145 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_outbox。 | <code>                FROM situation_outbox</code> |
| L0146 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_outbox。 | <code>                WHERE status IN ('pending','retry') AND retry_count &lt; 10</code> |
| L0147 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_outbox。 | <code>                ORDER BY id LIMIT %s FOR UPDATE</code> |
| L0148 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_outbox。 | <code>                """,</code> |
| L0149 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_outbox。 | <code>                (max(1, min(100, int(limit))),),</code> |
| L0150 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 claim_outbox。 | <code>            )</code> |
| L0151 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 claim_outbox。 | <code>            rows = list(cur.fetchall())</code> |
| L0152 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 claim_outbox。 | <code>            if rows:</code> |
| L0153 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_outbox。 | <code>                cur.executemany(</code> |
| L0154 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_outbox。 | <code>                    "UPDATE situation_outbox SET status='processing' WHERE id=%s",</code> |
| L0155 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_outbox。 | <code>                    [(row["id"],) for row in rows],</code> |
| L0156 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 claim_outbox。 | <code>                )</code> |
| L0157 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_outbox。 | <code>        conn.commit()</code> |
| L0158 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 claim_outbox。 | <code>    except Exception:</code> |
| L0159 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_outbox。 | <code>        conn.rollback()</code> |
| L0160 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_outbox。 | <code>        raise</code> |
| L0161 | 遍历集合中的数据项并逐项处理，当前位于函数 claim_outbox。 | <code>    for row in rows:</code> |
| L0162 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_outbox。 | <code>        row["payload"] = json_value(row.pop("payload_json", None), {})</code> |
| L0163 | 结束当前函数并把结果返回给调用方，当前位于函数 claim_outbox。 | <code>    return rows</code> |
| L0164 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0165 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0166 | 定义finishoutbox函数 &#96;finish_outbox&#96;，封装可复用业务逻辑。 | <code>def finish_outbox(store: MySQLSituationStore, outbox_id: int, error: str = "") -&gt; None:</code> |
| L0167 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 finish_outbox。 | <code>    conn = store.connect()</code> |
| L0168 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 finish_outbox。 | <code>    try:</code> |
| L0169 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 finish_outbox。 | <code>        with conn.cursor() as cur:</code> |
| L0170 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 finish_outbox。 | <code>            if error:</code> |
| L0171 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 finish_outbox。 | <code>                cur.execute(</code> |
| L0172 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 finish_outbox。 | <code>                    """UPDATE situation_outbox</code> |
| L0173 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 finish_outbox。 | <code>                       SET status='retry',retry_count=retry_count+1,last_error=%s</code> |
| L0174 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 finish_outbox。 | <code>                       WHERE id=%s""",</code> |
| L0175 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 finish_outbox。 | <code>                    (error[:2000], outbox_id),</code> |
| L0176 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 finish_outbox。 | <code>                )</code> |
| L0177 | 处理前述条件均未命中的情况，当前位于函数 finish_outbox。 | <code>            else:</code> |
| L0178 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 finish_outbox。 | <code>                cur.execute(</code> |
| L0179 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 finish_outbox。 | <code>                    """UPDATE situation_outbox</code> |
| L0180 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 finish_outbox。 | <code>                       SET status='processed',processed_at=UTC_TIMESTAMP(3),last_error=NULL</code> |
| L0181 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 finish_outbox。 | <code>                       WHERE id=%s""",</code> |
| L0182 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 finish_outbox。 | <code>                    (outbox_id,),</code> |
| L0183 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 finish_outbox。 | <code>                )</code> |
| L0184 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 finish_outbox。 | <code>        conn.commit()</code> |
| L0185 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 finish_outbox。 | <code>    except Exception:</code> |
| L0186 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 finish_outbox。 | <code>        conn.rollback()</code> |
| L0187 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 finish_outbox。 | <code>        raise</code> |
| L0188 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0189 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0190 | 定义同步once函数 &#96;sync_once&#96;，封装可复用业务逻辑。 | <code>def sync_once(store: MySQLSituationStore, client: Neo4jHTTPClient, batch_size: int = 20) -&gt; Dict[str, int]:</code> |
| L0191 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 sync_once。 | <code>    rows = claim_outbox(store, batch_size)</code> |
| L0192 | 计算并保存 &#96;success&#96;（success），供后续逻辑使用，当前位于函数 sync_once。 | <code>    success = 0</code> |
| L0193 | 计算并保存 &#96;failed&#96;（failed），供后续逻辑使用，当前位于函数 sync_once。 | <code>    failed = 0</code> |
| L0194 | 遍历集合中的数据项并逐项处理，当前位于函数 sync_once。 | <code>    for row in rows:</code> |
| L0195 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 sync_once。 | <code>        try:</code> |
| L0196 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 sync_once。 | <code>            client.execute(build_statements(row["payload"]))</code> |
| L0197 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_once。 | <code>            finish_outbox(store, int(row["id"]))</code> |
| L0198 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_once。 | <code>            success += 1</code> |
| L0199 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 sync_once。 | <code>        except Exception as exc:</code> |
| L0200 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_once。 | <code>            finish_outbox(store, int(row["id"]), f"{type(exc).__name__}: {exc}")</code> |
| L0201 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_once。 | <code>            failed += 1</code> |
| L0202 | 结束当前函数并把结果返回给调用方，当前位于函数 sync_once。 | <code>    return {"claimed": len(rows), "success": success, "failed": failed}</code> |
| L0203 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0204 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0205 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; None:</code> |
| L0206 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="Mirror MySQL attack situations to optional Neo4j")</code> |
| L0207 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-host", default="127.0.0.1")</code> |
| L0208 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-port", type=int, default=3306)</code> |
| L0209 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-user", default="root")</code> |
| L0210 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-password", default="123456")</code> |
| L0211 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-database", default="traffic_pipeline")</code> |
| L0212 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--neo4j-url", required=True)</code> |
| L0213 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--neo4j-user", default="neo4j")</code> |
| L0214 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--neo4j-password", required=True)</code> |
| L0215 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--neo4j-database", default="neo4j")</code> |
| L0216 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--batch-size", type=int, default=20)</code> |
| L0217 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--poll-seconds", type=int, default=10)</code> |
| L0218 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--once", action="store_true")</code> |
| L0219 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0220 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0221 | 计算并保存 &#96;store&#96;（store），供后续逻辑使用，当前位于函数 main。 | <code>    store = MySQLSituationStore(</code> |
| L0222 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        MySQLSettings(args.mysql_host, args.mysql_port, args.mysql_user, args.mysql_password, args.mysql_database)</code> |
| L0223 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0224 | 计算并保存 &#96;client&#96;（client），供后续逻辑使用，当前位于函数 main。 | <code>    client = Neo4jHTTPClient(args.neo4j_url, args.neo4j_user, args.neo4j_password, args.neo4j_database)</code> |
| L0225 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    store.ensure_schema()</code> |
| L0226 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>    try:</code> |
| L0227 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 main。 | <code>        while True:</code> |
| L0228 | 计算并保存 &#96;stats&#96;（stats），供后续逻辑使用，当前位于函数 main。 | <code>            stats = sync_once(store, client, args.batch_size)</code> |
| L0229 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if stats["claimed"] or stats["failed"]:</code> |
| L0230 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                log("neo4j sync " + json.dumps(stats, ensure_ascii=False))</code> |
| L0231 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if args.once:</code> |
| L0232 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                break</code> |
| L0233 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            time.sleep(max(1, int(args.poll_seconds)))</code> |
| L0234 | 无论成功或异常都执行资源清理，当前位于函数 main。 | <code>    finally:</code> |
| L0235 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        store.close()</code> |
| L0236 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0237 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0238 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0239 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
