# `scripts/seed_situation_demo.py` 逐行注释

**脚本用途：** 辅助脚本：根据文件名 `seed_situation_demo.py` 完成对应的数据处理或运维任务。

**源码行数：** 217　**函数/类数量：** 4

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime, timedelta, timezone&#96;。 | <code>from datetime import datetime, timedelta, timezone</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, List&#96;。 | <code>from typing import Any, Dict, List</code> |
| L0006 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;from situation_ai import fallback_report&#96;。 | <code>from situation_ai import fallback_report</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;from situation_core import SecurityAction, SituationCorrelator&#96;。 | <code>from situation_core import SecurityAction, SituationCorrelator</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;from situation_store import MySQLSettings, MySQLSituationStore&#96;。 | <code>from situation_store import MySQLSettings, MySQLSituationStore</code> |
| L0010 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0011 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0012 | 计算并保存 &#96;DEMO_ASSET&#96;（DEMOASSET），供后续逻辑使用。 | <code>DEMO_ASSET = "demo-finals-server"</code> |
| L0013 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0014 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0015 | 计算并保存 &#96;SCENARIOS&#96;（SCENARIOS），供后续逻辑使用。 | <code>SCENARIOS: List[Dict[str, Any]] = [</code> |
| L0016 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    {</code> |
| L0017 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "source_ip": "203.0.113.84",</code> |
| L0018 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "age_minutes": 4,</code> |
| L0019 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "status": "open",</code> |
| L0020 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "actions": [</code> |
| L0021 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("PORT_SCAN", 286, 0.91, "tcp:multiple", "tshark_syn_scan"),</code> |
| L0022 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("SERVICE_PROBE", 43, 0.86, "tcp:22,80,443,3306", "service_probe"),</code> |
| L0023 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("SSH_BRUTEFORCE", 67, 0.95, "tcp:22", "windows_ssh_log"),</code> |
| L0024 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("SQL_INJECTION", 12, 0.98, "/api/auth/login", "detection_v2"),</code> |
| L0025 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>        ],</code> |
| L0026 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "intent": "从暴露面侦察逐步转向凭据获取与数据库访问尝试",</code> |
| L0027 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "conclusion": "该来源呈现完整的侦察、凭据攻击和漏洞利用链，属于正在推进的高置信连续攻击尝试。",</code> |
| L0028 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0029 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    {</code> |
| L0030 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "source_ip": "198.51.100.27",</code> |
| L0031 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "age_minutes": 18,</code> |
| L0032 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "status": "closed",</code> |
| L0033 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "actions": [</code> |
| L0034 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("DIRECTORY_SCAN", 1428, 0.94, "/*", "behavior_window"),</code> |
| L0035 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("HTTP_BRUTEFORCE", 83, 0.92, "/login", "behavior_window"),</code> |
| L0036 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("XSS", 19, 0.96, "/search?q=", "detection_v2"),</code> |
| L0037 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("FILE_UPLOAD", 4, 0.97, "/api/upload", "poc_rule_engine"),</code> |
| L0038 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>        ],</code> |
| L0039 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "intent": "枚举 Web 资产并尝试获取账户后上传可执行内容",</code> |
| L0040 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "conclusion": "该会话已停止活动，但动作从目录枚举推进至危险上传，应检查上传目录和认证日志。",</code> |
| L0041 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0042 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    {</code> |
| L0043 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "source_ip": "192.0.2.146",</code> |
| L0044 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "age_minutes": 33,</code> |
| L0045 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "status": "closed",</code> |
| L0046 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "actions": [</code> |
| L0047 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("PORT_SCAN", 96, 0.88, "tcp:multiple", "tshark_syn_scan"),</code> |
| L0048 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("PATH_TRAVERSAL", 22, 0.95, "/download?file=", "detection_v2"),</code> |
| L0049 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("COMMAND_INJECTION", 7, 0.99, "/api/tools/ping", "poc_rule_engine"),</code> |
| L0050 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("WEB_SHELL", 3, 0.99, "/uploads/shell.jsp", "detection_v2"),</code> |
| L0051 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>        ],</code> |
| L0052 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "intent": "读取敏感文件并尝试获得远程命令执行能力",</code> |
| L0053 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "conclusion": "链路已进入执行控制阶段，存在 WebShell 行为证据，需按严重事件立即开展主机排查。",</code> |
| L0054 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0055 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    {</code> |
| L0056 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "source_ip": "203.0.113.9",</code> |
| L0057 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "age_minutes": 52,</code> |
| L0058 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "status": "handled",</code> |
| L0059 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "actions": [</code> |
| L0060 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("SERVICE_PROBE", 54, 0.84, "tcp:80,443", "service_probe"),</code> |
| L0061 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("GRAPHQL_PROBE", 16, 0.92, "/graphql", "detection_v2"),</code> |
| L0062 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("SSRF", 5, 0.96, "/api/fetch", "poc_rule_engine"),</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("IP_BLOCKED", 1, 1.0, "windows-firewall", "response_action"),</code> |
| L0064 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>        ],</code> |
| L0065 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "intent": "发现 GraphQL 接口后尝试借助服务端请求访问内部资源",</code> |
| L0066 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "conclusion": "该来源命中 SSRF 证据后已完成双向封禁，当前进入持续观察阶段。",</code> |
| L0067 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0068 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    {</code> |
| L0069 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "source_ip": "198.51.100.91",</code> |
| L0070 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "age_minutes": 78,</code> |
| L0071 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "status": "closed",</code> |
| L0072 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "actions": [</code> |
| L0073 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("PORT_SCAN", 72, 0.87, "tcp:multiple", "tshark_syn_scan"),</code> |
| L0074 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("XXE", 9, 0.95, "/api/xml/import", "poc_rule_engine"),</code> |
| L0075 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("DESERIALIZATION", 3, 0.98, "/api/session/restore", "detection_v2"),</code> |
| L0076 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>        ],</code> |
| L0077 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "intent": "利用 XML 外部实体和不安全反序列化读取数据或执行代码",</code> |
| L0078 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "conclusion": "三类动作构成从探测到高危执行前置条件的连续链，应核查 XML 解析器与反序列化入口。",</code> |
| L0079 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0080 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    {</code> |
| L0081 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "source_ip": "192.0.2.58",</code> |
| L0082 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "age_minutes": 118,</code> |
| L0083 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "status": "closed",</code> |
| L0084 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "actions": [</code> |
| L0085 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("DIRECTORY_SCAN", 616, 0.90, "/*", "behavior_window"),</code> |
| L0086 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("AUTH_ABUSE", 41, 0.91, "/admin/login", "behavior_window"),</code> |
| L0087 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("SSTI", 8, 0.96, "/preview", "poc_rule_engine"),</code> |
| L0088 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>            ("COMMAND_INJECTION", 2, 0.98, "/admin/task", "detection_v2"),</code> |
| L0089 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>        ],</code> |
| L0090 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "intent": "寻找管理入口并利用模板执行链进一步尝试命令执行",</code> |
| L0091 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "conclusion": "该来源动作类型多样且阶段持续升级，虽然会话已结束，仍建议检查管理账户和模板渲染日志。",</code> |
| L0092 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    },</code> |
| L0093 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>]</code> |
| L0094 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0095 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0096 | 定义cleardemo函数 &#96;clear_demo&#96;，封装可复用业务逻辑。 | <code>def clear_demo(store: MySQLSituationStore) -&gt; Dict[str, int]:</code> |
| L0097 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 clear_demo。 | <code>    conn = store.connect()</code> |
| L0098 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 clear_demo。 | <code>    with conn.cursor() as cur:</code> |
| L0099 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 clear_demo。 | <code>        cur.execute("SELECT situation_id FROM attack_situations WHERE target_asset=%s", (DEMO_ASSET,))</code> |
| L0100 | 计算并保存 &#96;ids&#96;（ids），供后续逻辑使用，当前位于函数 clear_demo。 | <code>        ids = [str(row["situation_id"]) for row in cur.fetchall()]</code> |
| L0101 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 clear_demo。 | <code>        if ids:</code> |
| L0102 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 clear_demo。 | <code>            cur.executemany("DELETE FROM situation_outbox WHERE aggregate_id=%s", [(item,) for item in ids])</code> |
| L0103 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 clear_demo。 | <code>        cur.execute("DELETE FROM attack_situations WHERE target_asset=%s", (DEMO_ASSET,))</code> |
| L0104 | 计算并保存 &#96;situations&#96;（situations），供后续逻辑使用，当前位于函数 clear_demo。 | <code>        situations = int(cur.rowcount)</code> |
| L0105 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 clear_demo。 | <code>        cur.execute("DELETE FROM security_actions WHERE target_asset=%s", (DEMO_ASSET,))</code> |
| L0106 | 计算并保存 &#96;actions&#96;（actions），供后续逻辑使用，当前位于函数 clear_demo。 | <code>        actions = int(cur.rowcount)</code> |
| L0107 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 clear_demo。 | <code>    conn.commit()</code> |
| L0108 | 结束当前函数并把结果返回给调用方，当前位于函数 clear_demo。 | <code>    return {"situations": situations, "actions": actions}</code> |
| L0109 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0110 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0111 | 定义构建actions函数 &#96;build_actions&#96;，封装可复用业务逻辑。 | <code>def build_actions(index: int, scenario: Dict[str, Any], now: datetime) -&gt; List[SecurityAction]:</code> |
| L0112 | 计算并保存 &#96;action_specs&#96;（actionspecs），供后续逻辑使用，当前位于函数 build_actions。 | <code>    action_specs = list(scenario["actions"])</code> |
| L0113 | 计算并保存 &#96;end_time&#96;（endtime），供后续逻辑使用，当前位于函数 build_actions。 | <code>    end_time = now - timedelta(minutes=int(scenario["age_minutes"]))</code> |
| L0114 | 计算并保存 &#96;start_time&#96;（启动time），供后续逻辑使用，当前位于函数 build_actions。 | <code>    start_time = end_time - timedelta(minutes=max(2, (len(action_specs) - 1) * 3))</code> |
| L0115 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 build_actions。 | <code>    rows: List[SecurityAction] = []</code> |
| L0116 | 遍历集合中的数据项并逐项处理，当前位于函数 build_actions。 | <code>    for action_index, (action_type, count, confidence, target_interface, sensor) in enumerate(action_specs, start=1):</code> |
| L0117 | 计算并保存 &#96;occurred_at&#96;（occurredat），供后续逻辑使用，当前位于函数 build_actions。 | <code>        occurred_at = start_time + timedelta(minutes=(action_index - 1) * 3)</code> |
| L0118 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_actions。 | <code>        rows.append(</code> |
| L0119 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_actions。 | <code>            SecurityAction(</code> |
| L0120 | 计算并保存 &#96;action_id&#96;（actionid），供后续逻辑使用，当前位于函数 build_actions。 | <code>                action_id=f"ACT-DEMO-{index:02d}-{action_index:02d}",</code> |
| L0121 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 build_actions。 | <code>                source_ip=str(scenario["source_ip"]),</code> |
| L0122 | 计算并保存 &#96;target_asset&#96;（targetasset），供后续逻辑使用，当前位于函数 build_actions。 | <code>                target_asset=DEMO_ASSET,</code> |
| L0123 | 计算并保存 &#96;action_type&#96;（actiontype），供后续逻辑使用，当前位于函数 build_actions。 | <code>                action_type=str(action_type),</code> |
| L0124 | 计算并保存 &#96;occurred_at&#96;（occurredat），供后续逻辑使用，当前位于函数 build_actions。 | <code>                occurred_at=occurred_at,</code> |
| L0125 | 计算并保存 &#96;last_seen_at&#96;（lastseenat），供后续逻辑使用，当前位于函数 build_actions。 | <code>                last_seen_at=occurred_at + timedelta(seconds=min(90, max(1, int(count) // 3))),</code> |
| L0126 | 计算并保存 &#96;target_interface&#96;（targetinterface），供后续逻辑使用，当前位于函数 build_actions。 | <code>                target_interface=str(target_interface),</code> |
| L0127 | 计算并保存 &#96;protocol&#96;（protocol），供后续逻辑使用，当前位于函数 build_actions。 | <code>                protocol="TCP" if str(target_interface).startswith("tcp:") else "HTTP",</code> |
| L0128 | 计算并保存 &#96;sensor&#96;（sensor），供后续逻辑使用，当前位于函数 build_actions。 | <code>                sensor=str(sensor),</code> |
| L0129 | 计算并保存 &#96;count&#96;（count），供后续逻辑使用，当前位于函数 build_actions。 | <code>                count=int(count),</code> |
| L0130 | 计算并保存 &#96;confidence&#96;（confidence），供后续逻辑使用，当前位于函数 build_actions。 | <code>                confidence=float(confidence),</code> |
| L0131 | 计算并保存 &#96;severity&#96;（severity），供后续逻辑使用，当前位于函数 build_actions。 | <code>                severity="critical" if float(confidence) &gt;= 0.98 else "high",</code> |
| L0132 | 计算并保存 &#96;evidence_refs&#96;（evidencerefs），供后续逻辑使用，当前位于函数 build_actions。 | <code>                evidence_refs=[f"DEMO-EVIDENCE-{index:02d}-{action_index:02d}"],</code> |
| L0133 | 计算并保存 &#96;metadata&#96;（metadata），供后续逻辑使用，当前位于函数 build_actions。 | <code>                metadata={"demo": True, "scenario": index, "description": "决赛态势展示样例"},</code> |
| L0134 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_actions。 | <code>            )</code> |
| L0135 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_actions。 | <code>        )</code> |
| L0136 | 结束当前函数并把结果返回给调用方，当前位于函数 build_actions。 | <code>    return rows</code> |
| L0137 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0138 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0139 | 定义seeddemo函数 &#96;seed_demo&#96;，封装可复用业务逻辑。 | <code>def seed_demo(store: MySQLSituationStore) -&gt; List[Dict[str, Any]]:</code> |
| L0140 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>    clear_demo(store)</code> |
| L0141 | 源码原注释：MySQL DATETIME(3) stores milliseconds. Align before hashing so the | <code>    # MySQL DATETIME(3) stores milliseconds. Align before hashing so the</code> |
| L0142 | 源码原注释：continuously running correlator derives the same situation ID on reload. | <code>    # continuously running correlator derives the same situation ID on reload.</code> |
| L0143 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 seed_demo。 | <code>    current = datetime.now(timezone.utc)</code> |
| L0144 | 计算并保存 &#96;now&#96;（now），供后续逻辑使用，当前位于函数 seed_demo。 | <code>    now = current.replace(microsecond=(current.microsecond // 1000) * 1000)</code> |
| L0145 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 seed_demo。 | <code>    result: List[Dict[str, Any]] = []</code> |
| L0146 | 计算并保存 &#96;correlator&#96;（correlator），供后续逻辑使用，当前位于函数 seed_demo。 | <code>    correlator = SituationCorrelator(minimum_distinct_actions=3, window_minutes=30, inactivity_minutes=15)</code> |
| L0147 | 遍历集合中的数据项并逐项处理，当前位于函数 seed_demo。 | <code>    for index, scenario in enumerate(SCENARIOS, start=1):</code> |
| L0148 | 计算并保存 &#96;actions&#96;（actions），供后续逻辑使用，当前位于函数 seed_demo。 | <code>        actions = build_actions(index, scenario, now)</code> |
| L0149 | 计算并保存 &#96;situation&#96;（态势），供后续逻辑使用，当前位于函数 seed_demo。 | <code>        situation = correlator.correlate(actions, include_observing=False)[0]</code> |
| L0150 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>        store.save([situation])</code> |
| L0151 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 seed_demo。 | <code>        if scenario["status"] != "open":</code> |
| L0152 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>            store.update_status(situation.situation_id, str(scenario["status"]))</code> |
| L0153 | 计算并保存 &#96;report&#96;（报告），供后续逻辑使用，当前位于函数 seed_demo。 | <code>        report = fallback_report(situation.as_dict())</code> |
| L0154 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>        report.update(</code> |
| L0155 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>            {</code> |
| L0156 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                "narrative": (</code> |
| L0157 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                    f"来源 {scenario['source_ip']} 在同一关联窗口内依次出现 "</code> |
| L0158 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                    + "、".join(action.label for action in actions)</code> |
| L0159 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                    + "，动作按时间持续推进。"</code> |
| L0160 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo。 | <code>                ),</code> |
| L0161 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                "analysis": "来源地址与目标资产一致，动作间隔均小于静默切段阈值；不同传感器证据形成连续阶段链，重复流量已按窗口聚合。",</code> |
| L0162 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                "conclusion": str(scenario["conclusion"]),</code> |
| L0163 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                "likely_intent": str(scenario["intent"]),</code> |
| L0164 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                "protection_measures": [</code> |
| L0165 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                    f"限制来源 IP {scenario['source_ip']} 访问并保留处置前证据。",</code> |
| L0166 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                    "核查认证、应用、数据库与主机日志，确认是否存在成功响应或持久化行为。",</code> |
| L0167 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                    "对暴露接口实施最小权限、速率限制和输入校验。",</code> |
| L0168 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo。 | <code>                ],</code> |
| L0169 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                "improvement_suggestions": [</code> |
| L0170 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                    "将本次链路加入回归样本和处置剧本。",</code> |
| L0171 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                    "按攻击阶段联动网络、应用与主机侧检测规则。",</code> |
| L0172 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                    "持续观察来源地址及关联网段的后续活动。",</code> |
| L0173 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo。 | <code>                ],</code> |
| L0174 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                "generated_by": "finals_demo_seed",</code> |
| L0175 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                "rag_hits": 3,</code> |
| L0176 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                "rag_refs": ["OWASP Web Security", "MITRE ATT&amp;CK", "平台处置知识库"],</code> |
| L0177 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo。 | <code>            }</code> |
| L0178 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo。 | <code>        )</code> |
| L0179 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>        store.update_ai_report(situation.situation_id, report, "complete")</code> |
| L0180 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 seed_demo。 | <code>        result.append(</code> |
| L0181 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>            {</code> |
| L0182 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                "situation_id": situation.situation_id,</code> |
| L0183 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                "source_ip": scenario["source_ip"],</code> |
| L0184 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                "status": scenario["status"],</code> |
| L0185 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                "actions": len(actions),</code> |
| L0186 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 seed_demo。 | <code>                "risk_score": situation.risk_score,</code> |
| L0187 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo。 | <code>            }</code> |
| L0188 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 seed_demo。 | <code>        )</code> |
| L0189 | 结束当前函数并把结果返回给调用方，当前位于函数 seed_demo。 | <code>    return result</code> |
| L0190 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0191 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0192 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; None:</code> |
| L0193 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="Seed or clear comprehensive attack-situation demo data")</code> |
| L0194 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-host", default="127.0.0.1")</code> |
| L0195 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-port", type=int, default=3306)</code> |
| L0196 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-user", default="root")</code> |
| L0197 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-password", default="123456")</code> |
| L0198 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-database", default="traffic_pipeline")</code> |
| L0199 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--clear", action="store_true", help="Remove demo situations and actions")</code> |
| L0200 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0201 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0202 | 计算并保存 &#96;store&#96;（store），供后续逻辑使用，当前位于函数 main。 | <code>    store = MySQLSituationStore(</code> |
| L0203 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        MySQLSettings(args.mysql_host, args.mysql_port, args.mysql_user, args.mysql_password, args.mysql_database)</code> |
| L0204 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0205 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    store.ensure_schema()</code> |
| L0206 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>    try:</code> |
| L0207 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if args.clear:</code> |
| L0208 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>            print(clear_demo(store))</code> |
| L0209 | 处理前述条件均未命中的情况，当前位于函数 main。 | <code>        else:</code> |
| L0210 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>            for row in seed_demo(store):</code> |
| L0211 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                print(row)</code> |
| L0212 | 无论成功或异常都执行资源清理，当前位于函数 main。 | <code>    finally:</code> |
| L0213 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        store.close()</code> |
| L0214 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0215 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0216 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0217 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
