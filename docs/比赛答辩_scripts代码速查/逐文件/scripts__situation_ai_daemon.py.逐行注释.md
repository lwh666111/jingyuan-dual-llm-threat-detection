# `scripts/situation_ai_daemon.py` 逐行注释

**脚本用途：** 消费普通态势报告队列，处理优先级、重试、超时和状态回写。

**源码行数：** 149　**函数/类数量：** 3

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import os&#96;。 | <code>import os</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import time&#96;。 | <code>import time</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime&#96;。 | <code>from datetime import datetime</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0009 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;from situation_ai import analyze_situation&#96;。 | <code>from situation_ai import analyze_situation</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;from situation_store import MySQLSettings, MySQLSituationStore&#96;。 | <code>from situation_store import MySQLSettings, MySQLSituationStore</code> |
| L0012 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0013 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0014 | 定义log函数 &#96;log&#96;，封装可复用业务逻辑。 | <code>def log(message: str, path: Path) -&gt; None:</code> |
| L0015 | 计算并保存 &#96;line&#96;（line），供后续逻辑使用，当前位于函数 log。 | <code>    line = f"[{datetime.now().isoformat(timespec='seconds')}] {message}"</code> |
| L0016 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 log。 | <code>    print(line, flush=True)</code> |
| L0017 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 log。 | <code>    path.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0018 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 log。 | <code>    with path.open("a", encoding="utf-8") as handle:</code> |
| L0019 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 log。 | <code>        handle.write(line + "\n")</code> |
| L0020 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0021 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0022 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; None:</code> |
| L0023 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="Generate explainable Bailian/RAG reports for attack situations")</code> |
| L0024 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-host", default="127.0.0.1")</code> |
| L0025 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-port", type=int, default=3306)</code> |
| L0026 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-user", default="root")</code> |
| L0027 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-password", default="123456")</code> |
| L0028 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-database", default="traffic_pipeline")</code> |
| L0029 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")</code> |
| L0030 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--model", default="qwen2.5:3b")</code> |
| L0031 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-db-path", default="llm/rag/rag_knowledge.db")</code> |
| L0032 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-data-dir", default="D:/JingyuanTrafficPipelineData/rag")</code> |
| L0033 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-api-config", default="config/ai_api.local.json")</code> |
| L0034 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-top-k", type=int, default=4)</code> |
| L0035 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--timeout-sec", type=int, default=120)</code> |
| L0036 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--poll-seconds", type=int, default=10)</code> |
| L0037 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--batch-size", type=int, default=1)</code> |
| L0038 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--idle-grace-seconds", type=int, default=8)</code> |
| L0039 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--report-cooldown-seconds", type=int, default=5)</code> |
| L0040 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--recent-minutes", type=int, default=1440)</code> |
| L0041 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--once", action="store_true")</code> |
| L0042 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--heartbeat-file", default="output/situation_ai_heartbeat.json")</code> |
| L0043 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--log-file", default="output/situation_ai_daemon.log")</code> |
| L0044 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0045 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0046 | 计算并保存 &#96;store&#96;（store），供后续逻辑使用，当前位于函数 main。 | <code>    store = MySQLSituationStore(MySQLSettings(args.mysql_host, args.mysql_port, args.mysql_user, args.mysql_password, args.mysql_database))</code> |
| L0047 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    store.ensure_schema()</code> |
| L0048 | 计算并保存 &#96;log_file&#96;（logfile），供后续逻辑使用，当前位于函数 main。 | <code>    log_file = Path(args.log_file)</code> |
| L0049 | 计算并保存 &#96;heartbeat_file&#96;（heartbeatfile），供后续逻辑使用，当前位于函数 main。 | <code>    heartbeat_file = Path(args.heartbeat_file)</code> |
| L0050 | 计算并保存 &#96;recovered&#96;（recovered），供后续逻辑使用，当前位于函数 main。 | <code>    recovered = store.recover_interrupted_ai()</code> |
| L0051 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if recovered:</code> |
| L0052 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        log(f"recovered {recovered} interrupted AI report task(s)", log_file)</code> |
| L0053 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0054 | 定义heartbeat函数 &#96;heartbeat&#96;，封装可复用业务逻辑。 | <code>    def heartbeat(status: str, **extra: object) -&gt; None:</code> |
| L0055 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 heartbeat。 | <code>        heartbeat_file.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0056 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 heartbeat。 | <code>        payload = {</code> |
| L0057 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 heartbeat。 | <code>            "pid": os.getpid(),</code> |
| L0058 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 heartbeat。 | <code>            "updated_at": datetime.now().isoformat(timespec="seconds"),</code> |
| L0059 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 heartbeat。 | <code>            "status": status,</code> |
| L0060 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 heartbeat。 | <code>            **extra,</code> |
| L0061 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 heartbeat。 | <code>        }</code> |
| L0062 | 计算并保存 &#96;temporary&#96;（temporary），供后续逻辑使用，当前位于函数 heartbeat。 | <code>        temporary = heartbeat_file.with_suffix(heartbeat_file.suffix + ".tmp")</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 heartbeat。 | <code>        temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")</code> |
| L0064 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 heartbeat。 | <code>        temporary.replace(heartbeat_file)</code> |
| L0065 | 计算并保存 &#96;rag_path&#96;（ragpath），供后续逻辑使用，当前位于函数 main。 | <code>    rag_path = Path(args.rag_db_path).resolve()</code> |
| L0066 | 计算并保存 &#96;rag_data_dir&#96;（ragdatadir），供后续逻辑使用，当前位于函数 main。 | <code>    rag_data_dir = Path(args.rag_data_dir).resolve()</code> |
| L0067 | 计算并保存 &#96;rag_api_config&#96;（rag接口配置），供后续逻辑使用，当前位于函数 main。 | <code>    rag_api_config = Path(args.rag_api_config).resolve()</code> |
| L0068 | 计算并保存 &#96;rag_mysql_conf&#96;（ragmysqlconf），供后续逻辑使用，当前位于函数 main。 | <code>    rag_mysql_conf = {</code> |
| L0069 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "host": args.mysql_host,</code> |
| L0070 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "port": args.mysql_port,</code> |
| L0071 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "user": args.mysql_user,</code> |
| L0072 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "password": args.mysql_password,</code> |
| L0073 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "database": args.mysql_database,</code> |
| L0074 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    }</code> |
| L0075 | 计算并保存 &#96;idle_since&#96;（idlesince），供后续逻辑使用，当前位于函数 main。 | <code>    idle_since = time.monotonic()</code> |
| L0076 | 计算并保存 &#96;next_report_at&#96;（next报告at），供后续逻辑使用，当前位于函数 main。 | <code>    next_report_at = 0.0</code> |
| L0077 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>    try:</code> |
| L0078 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 main。 | <code>        while True:</code> |
| L0079 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            heartbeat("polling")</code> |
| L0080 | 计算并保存 &#96;rag_enabled&#96;（ragenabled），供后续逻辑使用，当前位于函数 main。 | <code>            rag_enabled = True</code> |
| L0081 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>            try:</code> |
| L0082 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 main。 | <code>                with store.connect().cursor() as cur:</code> |
| L0083 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 main。 | <code>                    cur.execute("SELECT config_value FROM demo_system_config WHERE config_key='rag_enabled' LIMIT 1")</code> |
| L0084 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 main。 | <code>                    row = cur.fetchone() or {}</code> |
| L0085 | 计算并保存 &#96;rag_enabled&#96;（ragenabled），供后续逻辑使用，当前位于函数 main。 | <code>                rag_enabled = str(row.get("config_value", "1")).strip().lower() in {"1", "true", "yes", "on"}</code> |
| L0086 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>            except Exception:</code> |
| L0087 | 计算并保存 &#96;rag_enabled&#96;（ragenabled），供后续逻辑使用，当前位于函数 main。 | <code>                rag_enabled = True</code> |
| L0088 | 计算并保存 &#96;now&#96;（now），供后续逻辑使用，当前位于函数 main。 | <code>            now = time.monotonic()</code> |
| L0089 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if now &lt; next_report_at or now - idle_since &lt; max(0, args.idle_grace_seconds):</code> |
| L0090 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if args.once:</code> |
| L0091 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                    break</code> |
| L0092 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                time.sleep(2)</code> |
| L0093 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                continue</code> |
| L0094 | 源码原注释：Situation reports use the external Bailian endpoint and therefore | <code>            # Situation reports use the external Bailian endpoint and therefore</code> |
| L0095 | 源码原注释：run independently from the local packet-review Ollama worker. | <code>            # run independently from the local packet-review Ollama worker.</code> |
| L0096 | 源码原注释：Keep a one-day recovery window so a transient outage cannot leave | <code>            # Keep a one-day recovery window so a transient outage cannot leave</code> |
| L0097 | 源码原注释：a visible situation permanently labelled as queued. | <code>            # a visible situation permanently labelled as queued.</code> |
| L0098 | 计算并保存 &#96;pending&#96;（pending），供后续逻辑使用，当前位于函数 main。 | <code>            pending = store.list_pending_ai(</code> |
| L0099 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                args.batch_size,</code> |
| L0100 | 计算并保存 &#96;recent_minutes&#96;（recentminutes），供后续逻辑使用，当前位于函数 main。 | <code>                recent_minutes=args.recent_minutes,</code> |
| L0101 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>            )</code> |
| L0102 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>            for situation in pending:</code> |
| L0103 | 计算并保存 &#96;situation_id&#96;（态势id），供后续逻辑使用，当前位于函数 main。 | <code>                situation_id = str(situation["situation_id"])</code> |
| L0104 | 计算并保存 &#96;sequence_hash&#96;（sequencehash），供后续逻辑使用，当前位于函数 main。 | <code>                sequence_hash = str(situation.get("sequence_hash") or "")</code> |
| L0105 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if not store.mark_ai_processing(situation_id, sequence_hash):</code> |
| L0106 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                    continue</code> |
| L0107 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                heartbeat("analyzing", situation_id=situation_id)</code> |
| L0108 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>                try:</code> |
| L0109 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    report, status = analyze_situation(</code> |
| L0110 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                        situation,</code> |
| L0111 | 计算并保存 &#96;ollama_url&#96;（ollamaurl），供后续逻辑使用，当前位于函数 main。 | <code>                        ollama_url=args.ollama_url,</code> |
| L0112 | 计算并保存 &#96;model&#96;（模型），供后续逻辑使用，当前位于函数 main。 | <code>                        model=args.model,</code> |
| L0113 | 计算并保存 &#96;rag_db_path&#96;（rag数据库path），供后续逻辑使用，当前位于函数 main。 | <code>                        rag_db_path=rag_path,</code> |
| L0114 | 计算并保存 &#96;rag_mysql_conf&#96;（ragmysqlconf），供后续逻辑使用，当前位于函数 main。 | <code>                        rag_mysql_conf=rag_mysql_conf,</code> |
| L0115 | 计算并保存 &#96;rag_data_dir&#96;（ragdatadir），供后续逻辑使用，当前位于函数 main。 | <code>                        rag_data_dir=rag_data_dir,</code> |
| L0116 | 计算并保存 &#96;rag_api_config&#96;（rag接口配置），供后续逻辑使用，当前位于函数 main。 | <code>                        rag_api_config=rag_api_config,</code> |
| L0117 | 计算并保存 &#96;rag_enabled&#96;（ragenabled），供后续逻辑使用，当前位于函数 main。 | <code>                        rag_enabled=rag_enabled,</code> |
| L0118 | 计算并保存 &#96;rag_top_k&#96;（ragtopk），供后续逻辑使用，当前位于函数 main。 | <code>                        rag_top_k=args.rag_top_k,</code> |
| L0119 | 计算并保存 &#96;timeout_sec&#96;（timeoutsec），供后续逻辑使用，当前位于函数 main。 | <code>                        timeout_sec=args.timeout_sec,</code> |
| L0120 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>                    )</code> |
| L0121 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>                except Exception as exc:</code> |
| L0122 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    store.mark_ai_retry(situation_id, sequence_hash)</code> |
| L0123 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    heartbeat("retry", situation_id=situation_id, error=str(exc))</code> |
| L0124 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                    log(f"AI report failed {situation_id}: {exc}", log_file)</code> |
| L0125 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                    continue</code> |
| L0126 | 计算并保存 &#96;updated&#96;（updated），供后续逻辑使用，当前位于函数 main。 | <code>                updated = store.update_ai_report(</code> |
| L0127 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    situation_id,</code> |
| L0128 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    report,</code> |
| L0129 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    status,</code> |
| L0130 | 计算并保存 &#96;expected_sequence_hash&#96;（expectedsequencehash），供后续逻辑使用，当前位于函数 main。 | <code>                    expected_sequence_hash=sequence_hash,</code> |
| L0131 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>                )</code> |
| L0132 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if not updated:</code> |
| L0133 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    heartbeat("superseded", situation_id=str(situation["situation_id"]))</code> |
| L0134 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                    log(f"discarded stale report {situation['situation_id']} because the attack chain changed", log_file)</code> |
| L0135 | 计算并保存 &#96;idle_since&#96;（idlesince），供后续逻辑使用，当前位于函数 main。 | <code>                    idle_since = time.monotonic()</code> |
| L0136 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                    continue</code> |
| L0137 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                heartbeat("completed", situation_id=str(situation["situation_id"]), result=status)</code> |
| L0138 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                log(f"analyzed {situation['situation_id']} status={status}", log_file)</code> |
| L0139 | 计算并保存 &#96;next_report_at&#96;（next报告at），供后续逻辑使用，当前位于函数 main。 | <code>                next_report_at = time.monotonic() + max(0, args.report_cooldown_seconds)</code> |
| L0140 | 计算并保存 &#96;idle_since&#96;（idlesince），供后续逻辑使用，当前位于函数 main。 | <code>                idle_since = time.monotonic()</code> |
| L0141 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if args.once:</code> |
| L0142 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                break</code> |
| L0143 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            time.sleep(max(2, args.poll_seconds))</code> |
| L0144 | 无论成功或异常都执行资源清理，当前位于函数 main。 | <code>    finally:</code> |
| L0145 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        store.close()</code> |
| L0146 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0147 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0148 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0149 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
