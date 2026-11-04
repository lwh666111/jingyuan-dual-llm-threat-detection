# `scripts/auto_defense_daemon.py` 逐行注释

**脚本用途：** 根据已确认攻击事件执行自动封禁，并处理配置开关与重复操作。

**源码行数：** 161　**函数/类数量：** 6

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import time&#96;。 | <code>import time</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime&#96;。 | <code>from datetime import datetime</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, List&#96;。 | <code>from typing import Any, Dict, List</code> |
| L0009 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;import pymysql&#96;。 | <code>import pymysql</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;from pymysql.cursors import DictCursor&#96;。 | <code>from pymysql.cursors import DictCursor</code> |
| L0012 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0013 | 导入后续逻辑所需的模块、类或函数：&#96;from firewall_control import firewall_block_ip, firewall_status, is_safe_automatic_target, normalize_ip_literal&#96;。 | <code>from firewall_control import firewall_block_ip, firewall_status, is_safe_automatic_target, normalize_ip_literal</code> |
| L0014 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0015 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0016 | 定义log函数 &#96;log&#96;，封装可复用业务逻辑。 | <code>def log(message: str, path: Path) -&gt; None:</code> |
| L0017 | 计算并保存 &#96;line&#96;（line），供后续逻辑使用，当前位于函数 log。 | <code>    line = f"[{datetime.now().isoformat(timespec='seconds')}] {message}"</code> |
| L0018 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 log。 | <code>    print(line, flush=True)</code> |
| L0019 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 log。 | <code>    path.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0020 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 log。 | <code>    with path.open("a", encoding="utf-8") as handle:</code> |
| L0021 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 log。 | <code>        handle.write(line + "\n")</code> |
| L0022 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0023 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0024 | 定义ensureschema函数 &#96;ensure_schema&#96;，封装可复用业务逻辑。 | <code>def ensure_schema(conn: Any) -&gt; None:</code> |
| L0025 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 ensure_schema。 | <code>    with conn.cursor() as cur:</code> |
| L0026 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>        cur.execute("SHOW COLUMNS FROM demo_blocked_ips LIKE 'defense_latency_ms'")</code> |
| L0027 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema。 | <code>        if not cur.fetchone():</code> |
| L0028 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>            cur.execute(</code> |
| L0029 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema。 | <code>                "ALTER TABLE demo_blocked_ips "</code> |
| L0030 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema。 | <code>                "ADD COLUMN defense_latency_ms DOUBLE NULL AFTER blocked_role"</code> |
| L0031 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ensure_schema。 | <code>            )</code> |
| L0032 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema。 | <code>    conn.commit()</code> |
| L0033 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0034 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0035 | 定义加载policy函数 &#96;load_policy&#96;，封装可复用业务逻辑。 | <code>def load_policy(conn: Any) -&gt; Dict[str, Any]:</code> |
| L0036 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 load_policy。 | <code>    with conn.cursor() as cur:</code> |
| L0037 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 load_policy。 | <code>        cur.execute(</code> |
| L0038 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 load_policy。 | <code>            """SELECT config_key,config_value FROM demo_system_config</code> |
| L0039 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_policy。 | <code>               WHERE config_key IN ('auto_defense_enabled','auto_defense_min_risk','auto_defense_allow_private')"""</code> |
| L0040 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_policy。 | <code>        )</code> |
| L0041 | 计算并保存 &#96;values&#96;（values），供后续逻辑使用，当前位于函数 load_policy。 | <code>        values = {str(row["config_key"]): str(row["config_value"] or "") for row in cur.fetchall()}</code> |
| L0042 | 结束当前函数并把结果返回给调用方，当前位于函数 load_policy。 | <code>    return {</code> |
| L0043 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_policy。 | <code>        "enabled": values.get("auto_defense_enabled", "0") == "1",</code> |
| L0044 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_policy。 | <code>        "minimum_risk": values.get("auto_defense_min_risk", "critical") if values.get("auto_defense_min_risk") in {"high", "critical"} else "critical",</code> |
| L0045 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_policy。 | <code>        "allow_private": values.get("auto_defense_allow_private", "0") == "1",</code> |
| L0046 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_policy。 | <code>    }</code> |
| L0047 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0048 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0049 | 定义列出candidates函数 &#96;list_candidates&#96;，封装可复用业务逻辑。 | <code>def list_candidates(conn: Any, policy: Dict[str, Any], limit: int = 100) -&gt; List[Dict[str, Any]]:</code> |
| L0050 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_candidates。 | <code>    levels = ("critical", "high") if policy["minimum_risk"] == "high" else ("critical",)</code> |
| L0051 | 计算并保存 &#96;placeholders&#96;（placeholders），供后续逻辑使用，当前位于函数 list_candidates。 | <code>    placeholders = ",".join(["%s"] * len(levels))</code> |
| L0052 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 list_candidates。 | <code>    with conn.cursor() as cur:</code> |
| L0053 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 list_candidates。 | <code>        cur.execute(</code> |
| L0054 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_candidates。 | <code>            f"""SELECT s.source_ip,s.situation_id,s.risk_level,s.risk_score,s.last_action_at,b.id AS blocked_id</code> |
| L0055 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_candidates。 | <code>                FROM attack_situations s</code> |
| L0056 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_candidates。 | <code>                LEFT JOIN demo_blocked_ips b ON b.ip_address=s.source_ip</code> |
| L0057 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_candidates。 | <code>                LEFT JOIN demo_auto_defense_releases r ON r.ip_address=s.source_ip</code> |
| L0058 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_candidates。 | <code>                WHERE s.status = 'open' AND s.risk_level IN ({placeholders})</code> |
| L0059 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_candidates。 | <code>                  AND s.last_action_at &gt;= UTC_TIMESTAMP(3) - INTERVAL 24 HOUR</code> |
| L0060 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_candidates。 | <code>                  AND (r.ip_address IS NULL OR r.released_action_at IS NULL</code> |
| L0061 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_candidates。 | <code>                       OR s.last_action_at &gt; r.released_action_at)</code> |
| L0062 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_candidates。 | <code>                ORDER BY s.risk_score DESC,s.last_action_at DESC LIMIT %s""",</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_candidates。 | <code>            (*levels, max(1, min(500, int(limit)))),</code> |
| L0064 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 list_candidates。 | <code>        )</code> |
| L0065 | 结束当前函数并把结果返回给调用方，当前位于函数 list_candidates。 | <code>        return list(cur.fetchall())</code> |
| L0066 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0067 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0068 | 定义运行once函数 &#96;run_once&#96;，封装可复用业务逻辑。 | <code>def run_once(conn: Any) -&gt; Dict[str, int]:</code> |
| L0069 | 计算并保存 &#96;policy&#96;（policy），供后续逻辑使用，当前位于函数 run_once。 | <code>    policy = load_policy(conn)</code> |
| L0070 | 源码原注释：End the read-only transaction so a long-running daemon observes policy | <code>    # End the read-only transaction so a long-running daemon observes policy</code> |
| L0071 | 源码原注释：changes made by the API instead of retaining MySQL's REPEATABLE READ snapshot. | <code>    # changes made by the API instead of retaining MySQL's REPEATABLE READ snapshot.</code> |
| L0072 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_once。 | <code>    conn.commit()</code> |
| L0073 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 run_once。 | <code>    if not policy["enabled"]:</code> |
| L0074 | 结束当前函数并把结果返回给调用方，当前位于函数 run_once。 | <code>        return {"enabled": 0, "candidates": 0, "blocked": 0, "skipped": 0, "failed": 0}</code> |
| L0075 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 run_once。 | <code>    rows = list_candidates(conn, policy)</code> |
| L0076 | 源码原注释：Candidate reads also open a transaction. Release it before the next poll. | <code>    # Candidate reads also open a transaction. Release it before the next poll.</code> |
| L0077 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_once。 | <code>    conn.commit()</code> |
| L0078 | 计算并保存 &#96;stats&#96;（stats），供后续逻辑使用，当前位于函数 run_once。 | <code>    stats = {"enabled": 1, "candidates": len(rows), "blocked": 0, "skipped": 0, "failed": 0}</code> |
| L0079 | 计算并保存 &#96;seen_ips&#96;（seenips），供后续逻辑使用，当前位于函数 run_once。 | <code>    seen_ips = set()</code> |
| L0080 | 遍历集合中的数据项并逐项处理，当前位于函数 run_once。 | <code>    for row in rows:</code> |
| L0081 | 计算并保存 &#96;ip_value&#96;（ipvalue），供后续逻辑使用，当前位于函数 run_once。 | <code>        ip_value = normalize_ip_literal(row.get("source_ip"))</code> |
| L0082 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 run_once。 | <code>        if ip_value in seen_ips:</code> |
| L0083 | 控制当前循环或占位分支的执行流程，当前位于函数 run_once。 | <code>            continue</code> |
| L0084 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 run_once。 | <code>        seen_ips.add(ip_value)</code> |
| L0085 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 run_once。 | <code>        if not is_safe_automatic_target(ip_value, allow_private=policy["allow_private"]):</code> |
| L0086 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_once。 | <code>            stats["skipped"] += 1</code> |
| L0087 | 控制当前循环或占位分支的执行流程，当前位于函数 run_once。 | <code>            continue</code> |
| L0088 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 run_once。 | <code>        if row.get("blocked_id") and firewall_status(ip_value).get("active"):</code> |
| L0089 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_once。 | <code>            stats["skipped"] += 1</code> |
| L0090 | 控制当前循环或占位分支的执行流程，当前位于函数 run_once。 | <code>            continue</code> |
| L0091 | 计算并保存 &#96;defense_started&#96;（defensestarted），供后续逻辑使用，当前位于函数 run_once。 | <code>        defense_started = time.perf_counter()</code> |
| L0092 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_once。 | <code>        ok, detail = firewall_block_ip(ip_value)</code> |
| L0093 | 计算并保存 &#96;defense_latency_ms&#96;（defenselatencyms），供后续逻辑使用，当前位于函数 run_once。 | <code>        defense_latency_ms = (time.perf_counter() - defense_started) * 1000.0</code> |
| L0094 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 run_once。 | <code>        if not ok:</code> |
| L0095 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_once。 | <code>            stats["failed"] += 1</code> |
| L0096 | 控制当前循环或占位分支的执行流程，当前位于函数 run_once。 | <code>            continue</code> |
| L0097 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 run_once。 | <code>        with conn.cursor() as cur:</code> |
| L0098 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 run_once。 | <code>            cur.execute("DELETE FROM demo_auto_defense_releases WHERE ip_address=%s", (ip_value,))</code> |
| L0099 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 run_once。 | <code>            cur.execute(</code> |
| L0100 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 run_once。 | <code>                """INSERT INTO demo_blocked_ips(</code> |
| L0101 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 run_once。 | <code>                     ip_address,source_event_id,reason,blocked_by,blocked_role,defense_latency_ms</code> |
| L0102 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 run_once。 | <code>                   ) VALUES(%s,%s,%s,'auto-defense','system',%s)</code> |
| L0103 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 run_once。 | <code>                   ON DUPLICATE KEY UPDATE source_event_id=VALUES(source_event_id),reason=VALUES(reason),</code> |
| L0104 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 run_once。 | <code>                     blocked_by='auto-defense',blocked_role='system',</code> |
| L0105 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 run_once。 | <code>                     defense_latency_ms=VALUES(defense_latency_ms),blocked_at=CURRENT_TIMESTAMP""",</code> |
| L0106 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_once。 | <code>                (</code> |
| L0107 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_once。 | <code>                    ip_value,</code> |
| L0108 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_once。 | <code>                    str(row.get("situation_id") or ""),</code> |
| L0109 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_once。 | <code>                    f"auto_{row.get('risk_level')}_situation",</code> |
| L0110 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_once。 | <code>                    defense_latency_ms,</code> |
| L0111 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_once。 | <code>                ),</code> |
| L0112 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_once。 | <code>            )</code> |
| L0113 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_once。 | <code>        conn.commit()</code> |
| L0114 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_once。 | <code>        stats["blocked"] += 1</code> |
| L0115 | 结束当前函数并把结果返回给调用方，当前位于函数 run_once。 | <code>    return stats</code> |
| L0116 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0117 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0118 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; None:</code> |
| L0119 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="Continuously enforce automatic bidirectional IP blocking")</code> |
| L0120 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-host", default="127.0.0.1")</code> |
| L0121 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-port", type=int, default=3306)</code> |
| L0122 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-user", default="root")</code> |
| L0123 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-password", default="123456")</code> |
| L0124 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-database", default="traffic_pipeline")</code> |
| L0125 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--poll-seconds", type=int, default=5)</code> |
| L0126 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--once", action="store_true")</code> |
| L0127 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--log-file", default="output/auto_defense_daemon.log")</code> |
| L0128 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0129 | 计算并保存 &#96;log_path&#96;（logpath），供后续逻辑使用，当前位于函数 main。 | <code>    log_path = Path(args.log_file)</code> |
| L0130 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 main。 | <code>    conn = None</code> |
| L0131 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>    try:</code> |
| L0132 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 main。 | <code>        while True:</code> |
| L0133 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>            try:</code> |
| L0134 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if conn is None or not conn.open:</code> |
| L0135 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 main。 | <code>                    conn = pymysql.connect(</code> |
| L0136 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 main。 | <code>                        host=args.mysql_host, port=args.mysql_port, user=args.mysql_user,</code> |
| L0137 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                        password=args.mysql_password, database=args.mysql_database,</code> |
| L0138 | 计算并保存 &#96;charset&#96;（charset），供后续逻辑使用，当前位于函数 main。 | <code>                        charset="utf8mb4", cursorclass=DictCursor, autocommit=False,</code> |
| L0139 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>                    )</code> |
| L0140 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    ensure_schema(conn)</code> |
| L0141 | 计算并保存 &#96;stats&#96;（stats），供后续逻辑使用，当前位于函数 main。 | <code>                stats = run_once(conn)</code> |
| L0142 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if stats["blocked"] or stats["failed"]:</code> |
| L0143 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                    log(json.dumps(stats, ensure_ascii=False), log_path)</code> |
| L0144 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>            except Exception as exc:</code> |
| L0145 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                log(f"auto defense failed: {type(exc).__name__}: {exc}", log_path)</code> |
| L0146 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>                try:</code> |
| L0147 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                    if conn:</code> |
| L0148 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                        conn.close()</code> |
| L0149 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>                except Exception:</code> |
| L0150 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                    pass</code> |
| L0151 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 main。 | <code>                conn = None</code> |
| L0152 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if args.once:</code> |
| L0153 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                break</code> |
| L0154 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            time.sleep(max(2, int(args.poll_seconds)))</code> |
| L0155 | 无论成功或异常都执行资源清理，当前位于函数 main。 | <code>    finally:</code> |
| L0156 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if conn:</code> |
| L0157 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            conn.close()</code> |
| L0158 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0159 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0160 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0161 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
