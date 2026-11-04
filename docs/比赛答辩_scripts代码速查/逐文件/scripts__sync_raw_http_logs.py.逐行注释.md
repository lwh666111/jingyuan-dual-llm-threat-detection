# `scripts/sync_raw_http_logs.py` 逐行注释

**脚本用途：** 将原始 HTTP 流量同步到 MySQL，供新检测链路和审计回溯使用。

**源码行数：** 532　**函数/类数量：** 18

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import hashlib&#96;。 | <code>import hashlib</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;import sys&#96;。 | <code>import sys</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime, timedelta&#96;。 | <code>from datetime import datetime, timedelta</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, Iterable, Optional&#96;。 | <code>from typing import Any, Dict, Iterable, Optional</code> |
| L0010 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0011 | 开始受保护操作，异常会交给后续分支处理。 | <code>try:</code> |
| L0012 | 导入后续逻辑所需的模块、类或函数：&#96;import pymysql&#96;。 | <code>    import pymysql</code> |
| L0013 | 捕获异常，避免单次错误导致整个服务退出。 | <code>except Exception:  # pragma: no cover</code> |
| L0014 | 计算并保存 &#96;pymysql&#96;（pymysql），供后续逻辑使用。 | <code>    pymysql = None</code> |
| L0015 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0016 | 导入后续逻辑所需的模块、类或函数：&#96;from build_result_db import MySQLConfig&#96;。 | <code>from build_result_db import MySQLConfig</code> |
| L0017 | 导入后续逻辑所需的模块、类或函数：&#96;from extract_old_model_features_from_txt import build_request_text, parse_records, read_text_file&#96;。 | <code>from extract_old_model_features_from_txt import build_request_text, parse_records, read_text_file</code> |
| L0018 | 导入后续逻辑所需的模块、类或函数：&#96;from security_detection_v2 import DetectionEngineV2&#96;。 | <code>from security_detection_v2 import DetectionEngineV2</code> |
| L0019 | 导入后续逻辑所需的模块、类或函数：&#96;from raw_llm_review import enqueue_review, ensure_review_schema, find_cached_review, prioritize_cached_review, remove_review&#96;。 | <code>from raw_llm_review import enqueue_review, ensure_review_schema, find_cached_review, prioritize_cached_review, remove_review</code> |
| L0020 | 导入后续逻辑所需的模块、类或函数：&#96;from sync_detection_v2_db import ensure_mysql, mysql_connect, upsert_mysql&#96;。 | <code>from sync_detection_v2_db import ensure_mysql, mysql_connect, upsert_mysql</code> |
| L0021 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0022 | 计算并保存 &#96;BEHAVIOR_AGG_BUCKET_MINUTES&#96;（BEHAVIORAGGBUCKETMINUTES），供后续逻辑使用。 | <code>BEHAVIOR_AGG_BUCKET_MINUTES = 10</code> |
| L0023 | 计算并保存 &#96;AGGREGATED_BEHAVIOR_KEYWORDS&#96;（AGGREGATEDBEHAVIORKEYWORDS），供后续逻辑使用。 | <code>AGGREGATED_BEHAVIOR_KEYWORDS = (</code> |
| L0024 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "扫描",</code> |
| L0025 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "探测",</code> |
| L0026 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "目录",</code> |
| L0027 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "高频",</code> |
| L0028 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "暴力破解",</code> |
| L0029 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "爆破",</code> |
| L0030 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "Payload异常突增",</code> |
| L0031 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>)</code> |
| L0032 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0033 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0034 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>DEMO_ATTACK_EVENTS_DDL = """</code> |
| L0035 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>CREATE TABLE IF NOT EXISTS demo_attack_events (</code> |
| L0036 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  event_id VARCHAR(40) PRIMARY KEY,</code> |
| L0037 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  occurred_at DATETIME(3) NOT NULL,</code> |
| L0038 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  risk_level VARCHAR(16) NOT NULL,</code> |
| L0039 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  attack_type VARCHAR(64) NOT NULL,</code> |
| L0040 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  source_ip VARCHAR(64) NOT NULL,</code> |
| L0041 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  source_region VARCHAR(64) NOT NULL,</code> |
| L0042 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  target_node VARCHAR(64) NOT NULL,</code> |
| L0043 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  target_port INT NULL,</code> |
| L0044 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  target_interface VARCHAR(255) NOT NULL,</code> |
| L0045 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  attack_result VARCHAR(16) NOT NULL,</code> |
| L0046 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  process_status VARCHAR(16) NOT NULL,</code> |
| L0047 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  acked TINYINT(1) NOT NULL DEFAULT 0,</code> |
| L0048 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  attack_payload LONGTEXT,</code> |
| L0049 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  request_log LONGTEXT,</code> |
| L0050 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  protection_action TEXT,</code> |
| L0051 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  handling_suggestion TEXT,</code> |
| L0052 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  note TEXT,</code> |
| L0053 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  response_ms INT NOT NULL DEFAULT 0,</code> |
| L0054 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  anomaly_detected TINYINT(1) NOT NULL DEFAULT 0,</code> |
| L0055 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  machine_id INT NULL,</code> |
| L0056 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0057 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,</code> |
| L0058 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  KEY idx_event_time (occurred_at),</code> |
| L0059 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  KEY idx_event_risk (risk_level),</code> |
| L0060 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  KEY idx_event_type (attack_type),</code> |
| L0061 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  KEY idx_event_node (target_node)</code> |
| L0062 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L0063 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>"""</code> |
| L0064 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0065 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0066 | 定义iterinputfiles函数 &#96;iter_input_files&#96;，封装可复用业务逻辑。 | <code>def iter_input_files(input_dir: Path) -&gt; Iterable[Path]:</code> |
| L0067 | 定义key函数 &#96;key&#96;，封装可复用业务逻辑。 | <code>    def key(path: Path) -&gt; int:</code> |
| L0068 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 key。 | <code>        try:</code> |
| L0069 | 结束当前函数并把结果返回给调用方，当前位于函数 key。 | <code>            return int(path.stem.split(".")[-1])</code> |
| L0070 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 key。 | <code>        except Exception:</code> |
| L0071 | 结束当前函数并把结果返回给调用方，当前位于函数 key。 | <code>            return 10**9</code> |
| L0072 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0073 | 遍历集合中的数据项并逐项处理，当前位于函数 iter_input_files。 | <code>    for path in sorted(input_dir.glob("1.1.*.txt"), key=key):</code> |
| L0074 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 iter_input_files。 | <code>        if path.is_file():</code> |
| L0075 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 iter_input_files。 | <code>            yield path</code> |
| L0076 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0077 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0078 | 定义epochtoiso函数 &#96;epoch_to_iso&#96;，封装可复用业务逻辑。 | <code>def epoch_to_iso(value: Any) -&gt; str:</code> |
| L0079 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 epoch_to_iso。 | <code>    try:</code> |
| L0080 | 计算并保存 &#96;ts&#96;（ts），供后续逻辑使用，当前位于函数 epoch_to_iso。 | <code>        ts = float(value)</code> |
| L0081 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 epoch_to_iso。 | <code>    except Exception:</code> |
| L0082 | 结束当前函数并把结果返回给调用方，当前位于函数 epoch_to_iso。 | <code>        return ""</code> |
| L0083 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 epoch_to_iso。 | <code>    try:</code> |
| L0084 | 结束当前函数并把结果返回给调用方，当前位于函数 epoch_to_iso。 | <code>        return datetime.fromtimestamp(ts).isoformat(timespec="seconds")</code> |
| L0085 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 epoch_to_iso。 | <code>    except Exception:</code> |
| L0086 | 结束当前函数并把结果返回给调用方，当前位于函数 epoch_to_iso。 | <code>        return ""</code> |
| L0087 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0088 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0089 | 定义toint函数 &#96;to_int&#96;，封装可复用业务逻辑。 | <code>def to_int(value: Any) -&gt; Optional[int]:</code> |
| L0090 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 to_int。 | <code>    try:</code> |
| L0091 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 to_int。 | <code>        if value is None or value == "":</code> |
| L0092 | 结束当前函数并把结果返回给调用方，当前位于函数 to_int。 | <code>            return None</code> |
| L0093 | 结束当前函数并把结果返回给调用方，当前位于函数 to_int。 | <code>        return int(float(value))</code> |
| L0094 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 to_int。 | <code>    except Exception:</code> |
| L0095 | 结束当前函数并把结果返回给调用方，当前位于函数 to_int。 | <code>        return None</code> |
| L0096 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0097 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0098 | 定义cleanlayeredcase数据库记录函数 &#96;clean_layered_case_rows&#96;，封装可复用业务逻辑。 | <code>def clean_layered_case_rows(conn: Any, case_id: str) -&gt; None:</code> |
| L0099 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 clean_layered_case_rows。 | <code>    with conn.cursor() as cur:</code> |
| L0100 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 clean_layered_case_rows。 | <code>        cur.execute("DELETE FROM model_predictions WHERE case_id=%s", (case_id,))</code> |
| L0101 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 clean_layered_case_rows。 | <code>        cur.execute("DELETE FROM poc_matches WHERE case_id=%s", (case_id,))</code> |
| L0102 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 clean_layered_case_rows。 | <code>        cur.execute("DELETE FROM behavior_windows WHERE case_id=%s", (case_id,))</code> |
| L0103 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0104 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0105 | 定义ensuredemo攻击事件函数 &#96;ensure_demo_attack_events&#96;，封装可复用业务逻辑。 | <code>def ensure_demo_attack_events(conn: Any) -&gt; None:</code> |
| L0106 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 ensure_demo_attack_events。 | <code>    with conn.cursor() as cur:</code> |
| L0107 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_demo_attack_events。 | <code>        cur.execute(DEMO_ATTACK_EVENTS_DDL)</code> |
| L0108 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_demo_attack_events。 | <code>        cur.execute("SHOW COLUMNS FROM demo_attack_events LIKE 'target_port'")</code> |
| L0109 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_demo_attack_events。 | <code>        if not cur.fetchone():</code> |
| L0110 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_demo_attack_events。 | <code>            cur.execute("ALTER TABLE demo_attack_events ADD COLUMN target_port INT NULL AFTER target_node")</code> |
| L0111 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0112 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0113 | 定义mysqldatetime函数 &#96;mysql_datetime&#96;，封装可复用业务逻辑。 | <code>def mysql_datetime(value: Any) -&gt; str:</code> |
| L0114 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 mysql_datetime。 | <code>    text = str(value or "").strip()</code> |
| L0115 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 mysql_datetime。 | <code>    if not text:</code> |
| L0116 | 结束当前函数并把结果返回给调用方，当前位于函数 mysql_datetime。 | <code>        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]</code> |
| L0117 | 结束当前函数并把结果返回给调用方，当前位于函数 mysql_datetime。 | <code>    return text.replace("T", " ").replace("Z", "")[:23]</code> |
| L0118 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0119 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0120 | 定义解析dt函数 &#96;parse_dt&#96;，封装可复用业务逻辑。 | <code>def parse_dt(value: Any) -&gt; datetime:</code> |
| L0121 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 parse_dt。 | <code>    text = str(value or "").strip()</code> |
| L0122 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_dt。 | <code>    if not text:</code> |
| L0123 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_dt。 | <code>        return datetime.now()</code> |
| L0124 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 parse_dt。 | <code>    text = text.replace("Z", "").replace("T", " ")</code> |
| L0125 | 遍历集合中的数据项并逐项处理，当前位于函数 parse_dt。 | <code>    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):</code> |
| L0126 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 parse_dt。 | <code>        try:</code> |
| L0127 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_dt。 | <code>            return datetime.strptime(text[:26], fmt)</code> |
| L0128 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 parse_dt。 | <code>        except Exception:</code> |
| L0129 | 控制当前循环或占位分支的执行流程，当前位于函数 parse_dt。 | <code>            continue</code> |
| L0130 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 parse_dt。 | <code>    try:</code> |
| L0131 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_dt。 | <code>        return datetime.fromisoformat(text)</code> |
| L0132 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 parse_dt。 | <code>    except Exception:</code> |
| L0133 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_dt。 | <code>        return datetime.now()</code> |
| L0134 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0135 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0136 | 定义bucket启动函数 &#96;bucket_start&#96;，封装可复用业务逻辑。 | <code>def bucket_start(value: Any, minutes: int = BEHAVIOR_AGG_BUCKET_MINUTES) -&gt; datetime:</code> |
| L0137 | 计算并保存 &#96;dt&#96;（dt），供后续逻辑使用，当前位于函数 bucket_start。 | <code>    dt = parse_dt(value)</code> |
| L0138 | 计算并保存 &#96;minute&#96;（minute），供后续逻辑使用，当前位于函数 bucket_start。 | <code>    minute = (dt.minute // minutes) * minutes</code> |
| L0139 | 结束当前函数并把结果返回给调用方，当前位于函数 bucket_start。 | <code>    return dt.replace(minute=minute, second=0, microsecond=0)</code> |
| L0140 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0141 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0142 | 定义should聚合behavior函数 &#96;should_aggregate_behavior&#96;，封装可复用业务逻辑。 | <code>def should_aggregate_behavior(attack_type: str, detection: Dict[str, Any]) -&gt; bool:</code> |
| L0143 | 源码原注释：A concrete high-confidence payload/POC describes the current request more | <code>    # A concrete high-confidence payload/POC describes the current request more</code> |
| L0144 | 源码原注释：precisely than a historical behavior window. Keep that event independent | <code>    # precisely than a historical behavior window. Keep that event independent</code> |
| L0145 | 源码原注释：instead of relabelling it as a scan or brute-force aggregate. | <code>    # instead of relabelling it as a scan or brute-force aggregate.</code> |
| L0146 | 计算并保存 &#96;poc_matches&#96;（pocmatches），供后续逻辑使用，当前位于函数 should_aggregate_behavior。 | <code>    poc_matches = detection.get("poc_matches") or []</code> |
| L0147 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 should_aggregate_behavior。 | <code>    if any(str(match.get("severity") or "").lower() in {"high", "critical"} for match in poc_matches):</code> |
| L0148 | 结束当前函数并把结果返回给调用方，当前位于函数 should_aggregate_behavior。 | <code>        return False</code> |
| L0149 | 计算并保存 &#96;behavior&#96;（behavior），供后续逻辑使用，当前位于函数 should_aggregate_behavior。 | <code>    behavior = detection.get("behavior") or {}</code> |
| L0150 | 计算并保存 &#96;behavior_type&#96;（behaviortype），供后续逻辑使用，当前位于函数 should_aggregate_behavior。 | <code>    behavior_type = str(behavior.get("type") or "")</code> |
| L0151 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 should_aggregate_behavior。 | <code>    text = f"{attack_type} {behavior_type}"</code> |
| L0152 | 计算并保存 &#96;score&#96;（score），供后续逻辑使用，当前位于函数 should_aggregate_behavior。 | <code>    score = float(behavior.get("score") or 0.0)</code> |
| L0153 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 should_aggregate_behavior。 | <code>    if score &lt; 0.72:</code> |
| L0154 | 结束当前函数并把结果返回给调用方，当前位于函数 should_aggregate_behavior。 | <code>        return False</code> |
| L0155 | 结束当前函数并把结果返回给调用方，当前位于函数 should_aggregate_behavior。 | <code>    return any(x in text for x in AGGREGATED_BEHAVIOR_KEYWORDS)</code> |
| L0156 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0157 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0158 | 定义聚合事件id函数 &#96;aggregate_event_id&#96;，封装可复用业务逻辑。 | <code>def aggregate_event_id(record: Dict[str, Any], attack_type: str) -&gt; str:</code> |
| L0159 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 aggregate_event_id。 | <code>    source_ip = str(record.get("source_ip") or "unknown")</code> |
| L0160 | 计算并保存 &#96;start&#96;（启动），供后续逻辑使用，当前位于函数 aggregate_event_id。 | <code>    start = bucket_start(record.get("event_time"))</code> |
| L0161 | 计算并保存 &#96;key&#96;（key），供后续逻辑使用，当前位于函数 aggregate_event_id。 | <code>    key = f"{source_ip}&#124;{attack_type}&#124;{start.isoformat()}&#124;{BEHAVIOR_AGG_BUCKET_MINUTES}"</code> |
| L0162 | 计算并保存 &#96;digest&#96;（digest），供后续逻辑使用，当前位于函数 aggregate_event_id。 | <code>    digest = hashlib.sha1(key.encode("utf-8", errors="ignore")).hexdigest()[:22].upper()</code> |
| L0163 | 结束当前函数并把结果返回给调用方，当前位于函数 aggregate_event_id。 | <code>    return f"AGG{digest}"</code> |
| L0164 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0165 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0166 | 定义聚合evidence函数 &#96;aggregate_evidence&#96;，封装可复用业务逻辑。 | <code>def aggregate_evidence(record: Dict[str, Any], detection: Dict[str, Any], evidence: Iterable[str]) -&gt; list[str]:</code> |
| L0167 | 计算并保存 &#96;behavior&#96;（behavior），供后续逻辑使用，当前位于函数 aggregate_evidence。 | <code>    behavior = detection.get("behavior") or {}</code> |
| L0168 | 计算并保存 &#96;features&#96;（features），供后续逻辑使用，当前位于函数 aggregate_evidence。 | <code>    features = behavior.get("features") or {}</code> |
| L0169 | 计算并保存 &#96;start&#96;（启动），供后续逻辑使用，当前位于函数 aggregate_evidence。 | <code>    start = bucket_start(record.get("event_time"))</code> |
| L0170 | 计算并保存 &#96;end&#96;（end），供后续逻辑使用，当前位于函数 aggregate_evidence。 | <code>    end = start + timedelta(minutes=BEHAVIOR_AGG_BUCKET_MINUTES)</code> |
| L0171 | 计算并保存 &#96;lines&#96;（lines），供后续逻辑使用，当前位于函数 aggregate_evidence。 | <code>    lines = [</code> |
| L0172 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_evidence。 | <code>        f"聚合窗口：{start.strftime('%Y-%m-%d %H:%M:%S')} ~ {end.strftime('%H:%M:%S')}",</code> |
| L0173 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_evidence。 | <code>        f"来源IP：{record.get('source_ip') or 'unknown'}",</code> |
| L0174 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_evidence。 | <code>        f"窗口请求数：{features.get('request_count', 0)}",</code> |
| L0175 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_evidence。 | <code>        f"不同路径数：{features.get('distinct_path_count', 0)}",</code> |
| L0176 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_evidence。 | <code>        f"404次数：{features.get('not_found_count', 0)}",</code> |
| L0177 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 aggregate_evidence。 | <code>        f"登录失败次数：{features.get('login_fail_count', 0)}",</code> |
| L0178 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 aggregate_evidence。 | <code>    ]</code> |
| L0179 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 aggregate_evidence。 | <code>    lines.extend(str(x) for x in evidence)</code> |
| L0180 | 计算并保存 &#96;deduped&#96;（deduped），供后续逻辑使用，当前位于函数 aggregate_evidence。 | <code>    deduped: list[str] = []</code> |
| L0181 | 计算并保存 &#96;seen&#96;（seen），供后续逻辑使用，当前位于函数 aggregate_evidence。 | <code>    seen = set()</code> |
| L0182 | 遍历集合中的数据项并逐项处理，当前位于函数 aggregate_evidence。 | <code>    for line in lines:</code> |
| L0183 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 aggregate_evidence。 | <code>        if line in seen:</code> |
| L0184 | 控制当前循环或占位分支的执行流程，当前位于函数 aggregate_evidence。 | <code>            continue</code> |
| L0185 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 aggregate_evidence。 | <code>        seen.add(line)</code> |
| L0186 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 aggregate_evidence。 | <code>        deduped.append(line)</code> |
| L0187 | 结束当前函数并把结果返回给调用方，当前位于函数 aggregate_evidence。 | <code>    return deduped[:20]</code> |
| L0188 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0189 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0190 | 定义删除demo事件函数 &#96;delete_demo_event&#96;，封装可复用业务逻辑。 | <code>def delete_demo_event(conn: Any, event_id: str) -&gt; None:</code> |
| L0191 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 delete_demo_event。 | <code>    with conn.cursor() as cur:</code> |
| L0192 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 delete_demo_event。 | <code>        cur.execute("DELETE FROM demo_attack_events WHERE event_id=%s", (event_id[:40],))</code> |
| L0193 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0194 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0195 | 定义upsertdemo事件函数 &#96;upsert_demo_event&#96;，封装可复用业务逻辑。 | <code>def upsert_demo_event(</code> |
| L0196 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>    conn: Any,</code> |
| L0197 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>    event_id: str,</code> |
| L0198 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>    record: Dict[str, Any],</code> |
| L0199 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>    attack_type: str,</code> |
| L0200 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>    risk_level: str,</code> |
| L0201 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>    evidence: Iterable[str],</code> |
| L0202 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 upsert_demo_event。 | <code>) -&gt; None:</code> |
| L0203 | 计算并保存 &#96;request_log&#96;（requestlog），供后续逻辑使用，当前位于函数 upsert_demo_event。 | <code>    request_log = record.get("request_text") or record.get("raw_request_block") or ""</code> |
| L0204 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 upsert_demo_event。 | <code>    payload = record.get("request_body") or request_log</code> |
| L0205 | 计算并保存 &#96;suggestion&#96;（suggestion），供后续逻辑使用，当前位于函数 upsert_demo_event。 | <code>    suggestion = "V2\u878d\u5408\u68c0\u6d4b\u547d\u4e2d\uff0c\u8bf7\u7ed3\u5408\u8bf7\u6c42\u8f7d\u8377\u3001POC\u8bc1\u636e\u548c\u884c\u4e3a\u7a97\u53e3\u590d\u6838\u5904\u7f6e\u3002"</code> |
| L0206 | 计算并保存 &#96;source_region&#96;（来源region），供后续逻辑使用，当前位于函数 upsert_demo_event。 | <code>    source_region = "\u672a\u77e5\u5730\u533a"</code> |
| L0207 | 计算并保存 &#96;target_node&#96;（targetnode），供后续逻辑使用，当前位于函数 upsert_demo_event。 | <code>    target_node = record.get("host") or "\u672c\u673a\u8282\u70b9"</code> |
| L0208 | 计算并保存 &#96;target_interface&#96;（targetinterface），供后续逻辑使用，当前位于函数 upsert_demo_event。 | <code>    target_interface = record.get("target_interface_override") or record.get("uri") or ""</code> |
| L0209 | 计算并保存 &#96;protection_action&#96;（protectionaction），供后续逻辑使用，当前位于函数 upsert_demo_event。 | <code>    protection_action = "V2\u878d\u5408\u68c0\u6d4b\uff1aPayload\u6a21\u578b + POC\u89c4\u5219 + \u884c\u4e3a\u7a97\u53e3"</code> |
| L0210 | 计算并保存 &#96;evidence_text&#96;（evidencetext），供后续逻辑使用，当前位于函数 upsert_demo_event。 | <code>    evidence_text = "\uff1b".join(str(x) for x in evidence)</code> |
| L0211 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 upsert_demo_event。 | <code>    with conn.cursor() as cur:</code> |
| L0212 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 upsert_demo_event。 | <code>        cur.execute(</code> |
| L0213 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>            """</code> |
| L0214 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 upsert_demo_event。 | <code>            INSERT INTO demo_attack_events(</code> |
| L0215 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>              event_id, occurred_at, risk_level, attack_type, source_ip, source_region,</code> |
| L0216 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>              target_node, target_interface, attack_result, process_status,</code> |
| L0217 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>              attack_payload, request_log, protection_action, handling_suggestion,</code> |
| L0218 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>              response_ms, anomaly_detected</code> |
| L0219 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>            )</code> |
| L0220 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)</code> |
| L0221 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>            ON DUPLICATE KEY UPDATE</code> |
| L0222 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>              occurred_at=VALUES(occurred_at),</code> |
| L0223 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>              risk_level=VALUES(risk_level),</code> |
| L0224 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>              attack_type=VALUES(attack_type),</code> |
| L0225 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>              source_ip=VALUES(source_ip),</code> |
| L0226 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>              source_region=VALUES(source_region),</code> |
| L0227 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>              target_node=VALUES(target_node),</code> |
| L0228 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>              target_interface=VALUES(target_interface),</code> |
| L0229 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>              attack_result=VALUES(attack_result),</code> |
| L0230 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>              attack_payload=VALUES(attack_payload),</code> |
| L0231 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>              request_log=VALUES(request_log),</code> |
| L0232 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>              protection_action=VALUES(protection_action),</code> |
| L0233 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>              handling_suggestion=VALUES(handling_suggestion),</code> |
| L0234 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>              response_ms=VALUES(response_ms),</code> |
| L0235 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>              anomaly_detected=VALUES(anomaly_detected)</code> |
| L0236 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_event。 | <code>            """,</code> |
| L0237 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>            (</code> |
| L0238 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>                event_id[:40],</code> |
| L0239 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>                mysql_datetime(record.get("event_time")),</code> |
| L0240 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>                risk_level,</code> |
| L0241 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>                attack_type,</code> |
| L0242 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>                record.get("source_ip") or "unknown",</code> |
| L0243 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>                source_region,</code> |
| L0244 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>                target_node,</code> |
| L0245 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>                target_interface,</code> |
| L0246 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>                "\u5df2\u62e6\u622a",</code> |
| L0247 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>                "unprocessed",</code> |
| L0248 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>                payload,</code> |
| L0249 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>                request_log,</code> |
| L0250 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>                protection_action,</code> |
| L0251 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>                suggestion + "\n\u8bc1\u636e\uff1a" + evidence_text,</code> |
| L0252 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>                0,</code> |
| L0253 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_event。 | <code>                1,</code> |
| L0254 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 upsert_demo_event。 | <code>            ),</code> |
| L0255 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 upsert_demo_event。 | <code>        )</code> |
| L0256 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0257 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0258 | 定义同步detection数据库记录mysql函数 &#96;sync_detection_rows_mysql&#96;，封装可复用业务逻辑。 | <code>def sync_detection_rows_mysql(</code> |
| L0259 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>    conn: Any,</code> |
| L0260 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>    case_id: str,</code> |
| L0261 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>    event_id: str,</code> |
| L0262 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>    record: Dict[str, Any],</code> |
| L0263 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>    detection: Dict[str, Any],</code> |
| L0264 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_detection_rows_mysql。 | <code>) -&gt; Dict[str, int]:</code> |
| L0265 | 计算并保存 &#96;fusion&#96;（fusion），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>    fusion = detection.get("fusion") or {}</code> |
| L0266 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>    payload = detection.get("payload") or {}</code> |
| L0267 | 计算并保存 &#96;behavior&#96;（behavior），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>    behavior = detection.get("behavior") or {}</code> |
| L0268 | 计算并保存 &#96;poc_matches&#96;（pocmatches），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>    poc_matches = fusion.get("poc_matches") or detection.get("poc_matches") or []</code> |
| L0269 | 计算并保存 &#96;decision&#96;（decision），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>    decision = str(fusion.get("decision") or "raw_only")</code> |
| L0270 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_detection_rows_mysql。 | <code>    if decision == "raw_only":</code> |
| L0271 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>        clean_layered_case_rows(conn, case_id)</code> |
| L0272 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 sync_detection_rows_mysql。 | <code>        with conn.cursor() as cur:</code> |
| L0273 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 sync_detection_rows_mysql。 | <code>            cur.execute("DELETE FROM detection_candidates WHERE event_id=%s", (event_id,))</code> |
| L0274 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 sync_detection_rows_mysql。 | <code>            cur.execute("DELETE FROM attack_events WHERE event_id=%s", (event_id,))</code> |
| L0275 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>        remove_review(conn, event_id, case_id)</code> |
| L0276 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>        delete_demo_event(conn, event_id)</code> |
| L0277 | 结束当前函数并把结果返回给调用方，当前位于函数 sync_detection_rows_mysql。 | <code>        return {"candidate": 0, "attack": 0, "model": 0, "poc": 0, "behavior": 0}</code> |
| L0278 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0279 | 计算并保存 &#96;final_score&#96;（finalscore），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>    final_score = fusion.get("final_score")</code> |
| L0280 | 计算并保存 &#96;risk_level&#96;（risklevel），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>    risk_level = fusion.get("risk_level") or "medium"</code> |
| L0281 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>    attack_type = fusion.get("attack_type") or payload.get("label") or "可疑流量"</code> |
| L0282 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>    evidence = fusion.get("evidence") or []</code> |
| L0283 | 计算并保存 &#96;raw_event_id&#96;（raw事件id），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>    raw_event_id = event_id</code> |
| L0284 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>    is_aggregated = decision == "attack_event" and should_aggregate_behavior(str(attack_type), detection)</code> |
| L0285 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_detection_rows_mysql。 | <code>    if is_aggregated:</code> |
| L0286 | 计算并保存 &#96;event_id&#96;（事件id），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>        event_id = aggregate_event_id(record, str(attack_type))</code> |
| L0287 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>        evidence = aggregate_evidence(record, detection, evidence)</code> |
| L0288 | 计算并保存 &#96;record&#96;（record），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>        record = dict(record)</code> |
| L0289 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>        record["event_time"] = bucket_start(record.get("event_time")).isoformat(timespec="seconds")</code> |
| L0290 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>        record["target_interface_override"] = "聚合行为窗口"</code> |
| L0291 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 sync_detection_rows_mysql。 | <code>        with conn.cursor() as cur:</code> |
| L0292 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 sync_detection_rows_mysql。 | <code>            cur.execute("DELETE FROM detection_candidates WHERE event_id=%s", (raw_event_id,))</code> |
| L0293 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 sync_detection_rows_mysql。 | <code>            cur.execute("DELETE FROM attack_events WHERE event_id=%s", (raw_event_id,))</code> |
| L0294 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>        delete_demo_event(conn, raw_event_id)</code> |
| L0295 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0296 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 sync_detection_rows_mysql。 | <code>    with conn.cursor() as cur:</code> |
| L0297 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 sync_detection_rows_mysql。 | <code>        cur.execute("SELECT status FROM llm_review_jobs WHERE event_id=%s LIMIT 1", (event_id,))</code> |
| L0298 | 计算并保存 &#96;existing_review&#96;（existingreview），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>        existing_review = cur.fetchone() or {}</code> |
| L0299 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>    review_done = str(existing_review.get("status") or "") == "done"</code> |
| L0300 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0301 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>    upsert_mysql(</code> |
| L0302 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>        conn,</code> |
| L0303 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>        "detection_candidates",</code> |
| L0304 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>        {</code> |
| L0305 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            "event_id": event_id,</code> |
| L0306 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            "case_id": case_id,</code> |
| L0307 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            "file_id": record.get("file_id"),</code> |
| L0308 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            "seq_id": record.get("seq_id"),</code> |
| L0309 | 源码原注释：A suspicious RAW event remains a candidate until the LLM returns | <code>            # A suspicious RAW event remains a candidate until the LLM returns</code> |
| L0310 | 源码原注释：verdict=attack. The preliminary fusion decision is kept in the job. | <code>            # verdict=attack. The preliminary fusion decision is kept in the job.</code> |
| L0311 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            "decision": decision if review_done else "candidate",</code> |
| L0312 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            "final_score": final_score,</code> |
| L0313 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            "risk_level": risk_level,</code> |
| L0314 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            "attack_type": attack_type,</code> |
| L0315 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            "source_ip": record.get("source_ip"),</code> |
| L0316 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            "target_interface": record.get("target_interface_override") or record.get("uri"),</code> |
| L0317 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            "evidence_json": json.dumps(evidence, ensure_ascii=False),</code> |
| L0318 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_detection_rows_mysql。 | <code>        },</code> |
| L0319 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_detection_rows_mysql。 | <code>    )</code> |
| L0320 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0321 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>    clean_layered_case_rows(conn, case_id)</code> |
| L0322 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 sync_detection_rows_mysql。 | <code>    with conn.cursor() as cur:</code> |
| L0323 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 sync_detection_rows_mysql。 | <code>        cur.execute(</code> |
| L0324 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 sync_detection_rows_mysql。 | <code>            """INSERT INTO model_predictions(case_id,model_name,label,score,proba_json)</code> |
| L0325 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 sync_detection_rows_mysql。 | <code>               VALUES(%s,%s,%s,%s,%s)""",</code> |
| L0326 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            (</code> |
| L0327 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                case_id,</code> |
| L0328 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                "payload_model_v2",</code> |
| L0329 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                payload.get("label"),</code> |
| L0330 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                payload.get("score"),</code> |
| L0331 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                json.dumps(payload.get("proba") or {}, ensure_ascii=False),</code> |
| L0332 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_detection_rows_mysql。 | <code>            ),</code> |
| L0333 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_detection_rows_mysql。 | <code>        )</code> |
| L0334 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0335 | 计算并保存 &#96;poc_count&#96;（poccount），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>    poc_count = 0</code> |
| L0336 | 遍历集合中的数据项并逐项处理，当前位于函数 sync_detection_rows_mysql。 | <code>    for match in poc_matches:</code> |
| L0337 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 sync_detection_rows_mysql。 | <code>        with conn.cursor() as cur:</code> |
| L0338 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 sync_detection_rows_mysql。 | <code>            cur.execute(</code> |
| L0339 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 sync_detection_rows_mysql。 | <code>                """INSERT INTO poc_matches(case_id,rule_id,rule_name,attack_type,severity,score,evidence_json)</code> |
| L0340 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 sync_detection_rows_mysql。 | <code>                   VALUES(%s,%s,%s,%s,%s,%s,%s)""",</code> |
| L0341 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                (</code> |
| L0342 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                    case_id,</code> |
| L0343 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                    match.get("rule_id"),</code> |
| L0344 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                    match.get("name"),</code> |
| L0345 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                    match.get("attack_type"),</code> |
| L0346 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                    match.get("severity"),</code> |
| L0347 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                    match.get("score"),</code> |
| L0348 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                    json.dumps(match.get("evidence") or [], ensure_ascii=False),</code> |
| L0349 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_detection_rows_mysql。 | <code>                ),</code> |
| L0350 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_detection_rows_mysql。 | <code>            )</code> |
| L0351 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>        poc_count += 1</code> |
| L0352 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0353 | 计算并保存 &#96;behavior_count&#96;（behaviorcount），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>    behavior_count = 0</code> |
| L0354 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_detection_rows_mysql。 | <code>    if behavior.get("score") is not None:</code> |
| L0355 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 sync_detection_rows_mysql。 | <code>        with conn.cursor() as cur:</code> |
| L0356 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 sync_detection_rows_mysql。 | <code>            cur.execute(</code> |
| L0357 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 sync_detection_rows_mysql。 | <code>                """INSERT INTO behavior_windows(case_id,source_ip,behavior_type,score,features_json,evidence_json)</code> |
| L0358 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 sync_detection_rows_mysql。 | <code>                   VALUES(%s,%s,%s,%s,%s,%s)""",</code> |
| L0359 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                (</code> |
| L0360 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                    case_id,</code> |
| L0361 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                    record.get("source_ip"),</code> |
| L0362 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                    behavior.get("type"),</code> |
| L0363 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                    behavior.get("score"),</code> |
| L0364 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                    json.dumps(behavior.get("features") or {}, ensure_ascii=False),</code> |
| L0365 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                    json.dumps(behavior.get("evidence") or [], ensure_ascii=False),</code> |
| L0366 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_detection_rows_mysql。 | <code>                ),</code> |
| L0367 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_detection_rows_mysql。 | <code>            )</code> |
| L0368 | 计算并保存 &#96;behavior_count&#96;（behaviorcount），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>        behavior_count = 1</code> |
| L0369 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0370 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>    attack_count = 1 if decision == "attack_event" else 0</code> |
| L0371 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_detection_rows_mysql。 | <code>    if not review_done:</code> |
| L0372 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 sync_detection_rows_mysql。 | <code>        with conn.cursor() as cur:</code> |
| L0373 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 sync_detection_rows_mysql。 | <code>            cur.execute("DELETE FROM attack_events WHERE event_id=%s", (event_id,))</code> |
| L0374 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>        delete_demo_event(conn, event_id)</code> |
| L0375 | 计算并保存 &#96;review_priority_score&#96;（reviewpriorityscore），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>        review_priority_score = max(</code> |
| L0376 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            float(final_score or 0.0),</code> |
| L0377 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            float(payload.get("score") or 0.0),</code> |
| L0378 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            float(behavior.get("score") or 0.0),</code> |
| L0379 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            max((float(match.get("score") or 0.0) for match in poc_matches), default=0.0),</code> |
| L0380 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_detection_rows_mysql。 | <code>        )</code> |
| L0381 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_detection_rows_mysql。 | <code>        if any(</code> |
| L0382 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            str(match.get("severity") or "").lower() in {"high", "critical"}</code> |
| L0383 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            and float(match.get("score") or 0.0) &gt;= 0.8</code> |
| L0384 | 遍历集合中的数据项并逐项处理，当前位于函数 sync_detection_rows_mysql。 | <code>            for match in poc_matches</code> |
| L0385 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_detection_rows_mysql。 | <code>        ):</code> |
| L0386 | 源码原注释：Reserve 1000 for the explicit UI "prioritize" action. Concrete | <code>            # Reserve 1000 for the explicit UI "prioritize" action. Concrete</code> |
| L0387 | 源码原注释：high-risk POCs outrank noisy behavioral jobs but remain below it. | <code>            # high-risk POCs outrank noisy behavioral jobs but remain below it.</code> |
| L0388 | 计算并保存 &#96;review_priority_score&#96;（reviewpriorityscore），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>            review_priority_score = max(review_priority_score, 5.0)</code> |
| L0389 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>        enqueue_review(</code> |
| L0390 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            conn,</code> |
| L0391 | 计算并保存 &#96;event_id&#96;（事件id），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>            event_id=event_id,</code> |
| L0392 | 计算并保存 &#96;case_id&#96;（caseid），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>            case_id=case_id,</code> |
| L0393 | 计算并保存 &#96;preliminary_decision&#96;（preliminarydecision），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>            preliminary_decision=decision,</code> |
| L0394 | 计算并保存 &#96;final_score&#96;（finalscore），供后续逻辑使用，当前位于函数 sync_detection_rows_mysql。 | <code>            final_score=review_priority_score,</code> |
| L0395 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_detection_rows_mysql。 | <code>        )</code> |
| L0396 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>        prioritize_cached_review(</code> |
| L0397 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            conn,</code> |
| L0398 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            event_id,</code> |
| L0399 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>            {</code> |
| L0400 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                **record,</code> |
| L0401 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                "attack_type": detection.get("attack_type"),</code> |
| L0402 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_detection_rows_mysql。 | <code>                "final_score": final_score,</code> |
| L0403 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_detection_rows_mysql。 | <code>            },</code> |
| L0404 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_detection_rows_mysql。 | <code>        )</code> |
| L0405 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0406 | 结束当前函数并把结果返回给调用方，当前位于函数 sync_detection_rows_mysql。 | <code>    return {"candidate": 1, "attack": attack_count, "model": 1, "poc": poc_count, "behavior": behavior_count}</code> |
| L0407 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0408 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0409 | 定义同步inputfilemysql函数 &#96;sync_input_file_mysql&#96;，封装可复用业务逻辑。 | <code>def sync_input_file_mysql(conn: Any, input_file: Path, engine: DetectionEngineV2) -&gt; Dict[str, int]:</code> |
| L0410 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>    text = read_text_file(input_file)</code> |
| L0411 | 计算并保存 &#96;file_id&#96;（fileid），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>    file_id = input_file.stem</code> |
| L0412 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>    requests, responses, mode = parse_records(text, file_id)</code> |
| L0413 | 计算并保存 &#96;response_by_req&#96;（responsebyreq），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>    response_by_req = {r.get("request_frame"): r for r in responses.values() if r.get("request_frame") is not None}</code> |
| L0414 | 计算并保存 &#96;totals&#96;（totals），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>    totals = {"files": 1, "raw": 0, "candidate": 0, "attack": 0, "model": 0, "poc": 0, "behavior": 0}</code> |
| L0415 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0416 | 遍历集合中的数据项并逐项处理，当前位于函数 sync_input_file_mysql。 | <code>    for seq_id, frame_req in enumerate(sorted(requests.keys()), start=1):</code> |
| L0417 | 计算并保存 &#96;req&#96;（req），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>        req = requests[frame_req]</code> |
| L0418 | 计算并保存 &#96;resp&#96;（resp），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>        resp = response_by_req.get(frame_req)</code> |
| L0419 | 计算并保存 &#96;request_text&#96;（requesttext），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>        request_text = req.get("_request_text") or build_request_text(req, resp)</code> |
| L0420 | 计算并保存 &#96;response_text&#96;（responsetext），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>        response_text = resp.get("_response_text", "") if resp else ""</code> |
| L0421 | 计算并保存 &#96;case_id&#96;（caseid），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>        case_id = f"raw:{file_id}:{seq_id}"</code> |
| L0422 | 计算并保存 &#96;event_id&#96;（事件id），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>        event_id = f"RAW{file_id.replace('.', '_')}_{seq_id}"</code> |
| L0423 | 计算并保存 &#96;event_time&#96;（事件time），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>        event_time = epoch_to_iso(req.get("time"))</code> |
| L0424 | 计算并保存 &#96;record&#96;（record），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>        record = {</code> |
| L0425 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            "case_id": case_id,</code> |
| L0426 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            "file_id": file_id,</code> |
| L0427 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            "seq_id": seq_id,</code> |
| L0428 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            "event_time": event_time,</code> |
| L0429 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            "time": event_time,</code> |
| L0430 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            "source_ip": req.get("src_ip"),</code> |
| L0431 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            "destination_ip": req.get("dst_ip"),</code> |
| L0432 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            "source_port": req.get("src_port"),</code> |
| L0433 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            "destination_port": req.get("dst_port"),</code> |
| L0434 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            "method": req.get("method"),</code> |
| L0435 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            "uri": req.get("uri"),</code> |
| L0436 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            "host": req.get("host"),</code> |
| L0437 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            "status_code": to_int(resp.get("status_code") if resp else None),</code> |
| L0438 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            "request_text": request_text,</code> |
| L0439 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            "response_text": response_text,</code> |
| L0440 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            "raw_request_block": req.get("raw_block"),</code> |
| L0441 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            "raw_response_block": resp.get("raw_block") if resp else "",</code> |
| L0442 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_input_file_mysql。 | <code>        }</code> |
| L0443 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>        upsert_mysql(</code> |
| L0444 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            conn,</code> |
| L0445 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            "raw_http_logs",</code> |
| L0446 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            {</code> |
| L0447 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                "case_id": case_id,</code> |
| L0448 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                "file_id": file_id,</code> |
| L0449 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                "seq_id": seq_id,</code> |
| L0450 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                "event_time": event_time,</code> |
| L0451 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                "source_ip": record.get("source_ip"),</code> |
| L0452 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                "destination_ip": record.get("destination_ip"),</code> |
| L0453 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                "method": record.get("method"),</code> |
| L0454 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                "uri": record.get("uri"),</code> |
| L0455 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                "host": str(record.get("host") or "")[:255],</code> |
| L0456 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                "status_code": record.get("status_code"),</code> |
| L0457 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                "request_text": request_text,</code> |
| L0458 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                "response_text": response_text,</code> |
| L0459 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_input_file_mysql。 | <code>            },</code> |
| L0460 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_input_file_mysql。 | <code>        )</code> |
| L0461 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>        totals["raw"] += 1</code> |
| L0462 | 计算并保存 &#96;cached&#96;（cached），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>        cached = find_cached_review(conn, record)</code> |
| L0463 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_input_file_mysql。 | <code>        if cached:</code> |
| L0464 | 计算并保存 &#96;template&#96;（template），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>            template = cached.get("analysis") or {}</code> |
| L0465 | 计算并保存 &#96;confidence&#96;（confidence），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>            confidence = max(0.75, min(1.0, float(template.get("confidence") or 0.95)))</code> |
| L0466 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>            attack_type = str(template.get("attack_method") or template.get("attack_type") or "可疑流量")</code> |
| L0467 | 计算并保存 &#96;severity&#96;（severity），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>            severity = str(template.get("severity") or "high")</code> |
| L0468 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>            evidence = list(template.get("evidence") or template.get("decision_evidence") or [])</code> |
| L0469 | 计算并保存 &#96;detection&#96;（detection），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>            detection = {</code> |
| L0470 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                "payload": {"label": attack_type, "score": confidence, "proba": {attack_type: confidence}},</code> |
| L0471 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                "behavior": {"type": "normal", "score": 0.0, "features": {}, "evidence": []},</code> |
| L0472 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                "poc_matches": [],</code> |
| L0473 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                "fusion": {</code> |
| L0474 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                    "decision": "attack_event",</code> |
| L0475 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                    "final_score": confidence,</code> |
| L0476 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                    "risk_level": severity,</code> |
| L0477 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                    "attack_type": attack_type,</code> |
| L0478 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                    "evidence": evidence[:8] or ["已验证攻击指纹精确命中"],</code> |
| L0479 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                    "poc_matches": [],</code> |
| L0480 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_input_file_mysql。 | <code>                },</code> |
| L0481 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>                "verified_cache": True,</code> |
| L0482 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_input_file_mysql。 | <code>            }</code> |
| L0483 | 处理前述条件均未命中的情况，当前位于函数 sync_input_file_mysql。 | <code>        else:</code> |
| L0484 | 计算并保存 &#96;detection&#96;（detection），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>            detection = engine.detect(record)</code> |
| L0485 | 计算并保存 &#96;row_stats&#96;（rowstats），供后续逻辑使用，当前位于函数 sync_input_file_mysql。 | <code>        row_stats = sync_detection_rows_mysql(conn, case_id, event_id, record, detection)</code> |
| L0486 | 遍历集合中的数据项并逐项处理，当前位于函数 sync_input_file_mysql。 | <code>        for key in ("candidate", "attack", "model", "poc", "behavior"):</code> |
| L0487 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>            totals[key] += int(row_stats.get(key, 0))</code> |
| L0488 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0489 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_file_mysql。 | <code>    totals["mode"] = mode  # type: ignore[assignment]</code> |
| L0490 | 结束当前函数并把结果返回给调用方，当前位于函数 sync_input_file_mysql。 | <code>    return totals</code> |
| L0491 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0492 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0493 | 定义同步inputdirmysql函数 &#96;sync_input_dir_mysql&#96;，封装可复用业务逻辑。 | <code>def sync_input_dir_mysql(conn: Any, input_dir: Path) -&gt; Dict[str, int]:</code> |
| L0494 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_dir_mysql。 | <code>    ensure_mysql(conn)</code> |
| L0495 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_dir_mysql。 | <code>    ensure_demo_attack_events(conn)</code> |
| L0496 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_dir_mysql。 | <code>    ensure_review_schema(conn)</code> |
| L0497 | 计算并保存 &#96;engine&#96;（engine），供后续逻辑使用，当前位于函数 sync_input_dir_mysql。 | <code>    engine = DetectionEngineV2()</code> |
| L0498 | 计算并保存 &#96;totals&#96;（totals），供后续逻辑使用，当前位于函数 sync_input_dir_mysql。 | <code>    totals = {"files": 0, "raw": 0, "candidate": 0, "attack": 0, "model": 0, "poc": 0, "behavior": 0, "errors": 0}</code> |
| L0499 | 遍历集合中的数据项并逐项处理，当前位于函数 sync_input_dir_mysql。 | <code>    for input_file in iter_input_files(input_dir):</code> |
| L0500 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 sync_input_dir_mysql。 | <code>        try:</code> |
| L0501 | 计算并保存 &#96;stats&#96;（stats），供后续逻辑使用，当前位于函数 sync_input_dir_mysql。 | <code>            stats = sync_input_file_mysql(conn, input_file, engine)</code> |
| L0502 | 遍历集合中的数据项并逐项处理，当前位于函数 sync_input_dir_mysql。 | <code>            for key in ("files", "raw", "candidate", "attack", "model", "poc", "behavior"):</code> |
| L0503 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_dir_mysql。 | <code>                totals[key] += int(stats.get(key, 0))</code> |
| L0504 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 sync_input_dir_mysql。 | <code>        except Exception as exc:  # noqa: BLE001</code> |
| L0505 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_input_dir_mysql。 | <code>            totals["errors"] += 1</code> |
| L0506 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 sync_input_dir_mysql。 | <code>            print(f"[warn] raw sync failed file={input_file}: {exc}", file=sys.stderr)</code> |
| L0507 | 结束当前函数并把结果返回给调用方，当前位于函数 sync_input_dir_mysql。 | <code>    return totals</code> |
| L0508 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0509 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0510 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; None:</code> |
| L0511 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="Sync input/1.1.n.txt into raw_http_logs")</code> |
| L0512 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--input-dir", default="input")</code> |
| L0513 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-host", default="127.0.0.1")</code> |
| L0514 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-port", type=int, default=3306)</code> |
| L0515 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-user", default="root")</code> |
| L0516 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-password", default="123456")</code> |
| L0517 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-database", default="traffic_pipeline")</code> |
| L0518 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0519 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0520 | 计算并保存 &#96;project_root&#96;（projectroot），供后续逻辑使用，当前位于函数 main。 | <code>    project_root = Path(__file__).resolve().parent.parent</code> |
| L0521 | 计算并保存 &#96;input_dir&#96;（inputdir），供后续逻辑使用，当前位于函数 main。 | <code>    input_dir = (project_root / args.input_dir).resolve()</code> |
| L0522 | 计算并保存 &#96;cfg&#96;（cfg），供后续逻辑使用，当前位于函数 main。 | <code>    cfg = MySQLConfig(args.mysql_host, args.mysql_port, args.mysql_user, args.mysql_password, args.mysql_database)</code> |
| L0523 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 main。 | <code>    conn = mysql_connect(cfg)</code> |
| L0524 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>    try:</code> |
| L0525 | 计算并保存 &#96;totals&#96;（totals），供后续逻辑使用，当前位于函数 main。 | <code>        totals = sync_input_dir_mysql(conn, input_dir)</code> |
| L0526 | 无论成功或异常都执行资源清理，当前位于函数 main。 | <code>    finally:</code> |
| L0527 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        conn.close()</code> |
| L0528 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(json.dumps(totals, ensure_ascii=False, indent=2))</code> |
| L0529 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0530 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0531 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0532 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
