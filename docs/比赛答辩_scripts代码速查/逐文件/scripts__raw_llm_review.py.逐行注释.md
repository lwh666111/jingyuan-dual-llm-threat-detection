# `scripts/raw_llm_review.py` 逐行注释

**脚本用途：** RAW 候选事件并发复核、DeepSeek/OpenAI 兼容 API 调用、缓存与任务状态管理。

**源码行数：** 616　**函数/类数量：** 18

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import hashlib&#96;。 | <code>import hashlib</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import re&#96;。 | <code>import re</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.parse&#96;。 | <code>import urllib.parse</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;from contextlib import contextmanager&#96;。 | <code>from contextlib import contextmanager</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime&#96;。 | <code>from datetime import datetime</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, List, Optional&#96;。 | <code>from typing import Any, Dict, List, Optional</code> |
| L0010 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0011 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0012 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>QUEUE_DDL = """</code> |
| L0013 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>CREATE TABLE IF NOT EXISTS llm_review_jobs (</code> |
| L0014 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  event_id VARCHAR(64) PRIMARY KEY,</code> |
| L0015 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  case_id VARCHAR(64) NOT NULL,</code> |
| L0016 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  preliminary_decision VARCHAR(32) NOT NULL,</code> |
| L0017 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  priority INT NOT NULL DEFAULT 50,</code> |
| L0018 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  status VARCHAR(24) NOT NULL DEFAULT 'pending',</code> |
| L0019 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  attempts INT NOT NULL DEFAULT 0,</code> |
| L0020 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  next_retry_at DATETIME NULL,</code> |
| L0021 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  started_at DATETIME NULL,</code> |
| L0022 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  completed_at DATETIME NULL,</code> |
| L0023 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  model_name VARCHAR(255) NULL,</code> |
| L0024 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  error_message TEXT NULL,</code> |
| L0025 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0026 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,</code> |
| L0027 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  UNIQUE KEY uniq_llm_review_case (case_id),</code> |
| L0028 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  KEY idx_llm_review_ready (status, next_retry_at, priority, created_at)</code> |
| L0029 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L0030 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>"""</code> |
| L0031 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0032 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>CACHE_DDL = """</code> |
| L0033 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>CREATE TABLE IF NOT EXISTS llm_review_cache (</code> |
| L0034 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  fingerprint CHAR(64) PRIMARY KEY,</code> |
| L0035 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  target_port INT NOT NULL,</code> |
| L0036 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  method VARCHAR(16) NOT NULL,</code> |
| L0037 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  uri TEXT NOT NULL,</code> |
| L0038 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  template_json LONGTEXT NOT NULL,</code> |
| L0039 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  model_name VARCHAR(255) NULL,</code> |
| L0040 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  hit_count INT NOT NULL DEFAULT 0,</code> |
| L0041 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  enabled TINYINT(1) NOT NULL DEFAULT 1,</code> |
| L0042 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0043 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,</code> |
| L0044 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  KEY idx_review_cache_port (target_port, enabled)</code> |
| L0045 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L0046 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>"""</code> |
| L0047 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0048 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>ANALYSES_DDL = """</code> |
| L0049 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>CREATE TABLE IF NOT EXISTS analyses (</code> |
| L0050 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  id BIGINT AUTO_INCREMENT PRIMARY KEY,</code> |
| L0051 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  case_id VARCHAR(64) NOT NULL UNIQUE,</code> |
| L0052 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  file_id VARCHAR(128) NULL,</code> |
| L0053 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  seq_id INT NULL,</code> |
| L0054 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  llm_status VARCHAR(32) NULL,</code> |
| L0055 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  llm_error TEXT NULL,</code> |
| L0056 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  llm_started_at DATETIME NULL,</code> |
| L0057 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  llm_failed_at DATETIME NULL,</code> |
| L0058 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  analyzed_at DATETIME NULL,</code> |
| L0059 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  model_name VARCHAR(255) NULL,</code> |
| L0060 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  verdict VARCHAR(32) NULL,</code> |
| L0061 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  source_ip VARCHAR(64) NULL,</code> |
| L0062 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  destination_ip VARCHAR(64) NULL,</code> |
| L0063 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  attack_interface TEXT NULL,</code> |
| L0064 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  attack_method VARCHAR(255) NULL,</code> |
| L0065 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  attack_path TEXT NULL,</code> |
| L0066 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  attack_time DATETIME NULL,</code> |
| L0067 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  severity VARCHAR(32) NULL,</code> |
| L0068 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  confidence DOUBLE NULL,</code> |
| L0069 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  summary LONGTEXT NULL,</code> |
| L0070 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  evidence_json LONGTEXT NULL,</code> |
| L0071 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  analysis_raw LONGTEXT NULL,</code> |
| L0072 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  attack_event_time DATETIME NULL,</code> |
| L0073 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  attack_ip VARCHAR(64) NULL,</code> |
| L0074 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  target_interface TEXT NULL,</code> |
| L0075 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  attack_type VARCHAR(255) NULL,</code> |
| L0076 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  attack_confidence DOUBLE NULL,</code> |
| L0077 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  rag_enabled TINYINT(1) NOT NULL DEFAULT 0,</code> |
| L0078 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  rag_hits INT NOT NULL DEFAULT 0,</code> |
| L0079 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  review_latency_ms INT NULL,</code> |
| L0080 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  handling_suggestion LONGTEXT NULL,</code> |
| L0081 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0082 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,</code> |
| L0083 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  KEY idx_analyses_status (llm_status),</code> |
| L0084 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  KEY idx_analyses_verdict (verdict)</code> |
| L0085 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L0086 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>"""</code> |
| L0087 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0088 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0089 | 定义columnexists函数 &#96;_column_exists&#96;，封装可复用业务逻辑。 | <code>def _column_exists(cur: Any, table: str, column: str) -&gt; bool:</code> |
| L0090 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 _column_exists。 | <code>    cur.execute(f"SHOW COLUMNS FROM &#96;{table}&#96; LIKE %s", (column,))</code> |
| L0091 | 结束当前函数并把结果返回给调用方，当前位于函数 _column_exists。 | <code>    return bool(cur.fetchone())</code> |
| L0092 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0093 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0094 | 定义ensurereviewschema函数 &#96;ensure_review_schema&#96;，封装可复用业务逻辑。 | <code>def ensure_review_schema(conn: Any) -&gt; None:</code> |
| L0095 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 ensure_review_schema。 | <code>    with conn.cursor() as cur:</code> |
| L0096 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_review_schema。 | <code>        cur.execute(ANALYSES_DDL)</code> |
| L0097 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_review_schema。 | <code>        cur.execute(QUEUE_DDL)</code> |
| L0098 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_review_schema。 | <code>        cur.execute(CACHE_DDL)</code> |
| L0099 | 计算并保存 &#96;additions&#96;（additions），供后续逻辑使用，当前位于函数 ensure_review_schema。 | <code>        additions = {</code> |
| L0100 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_review_schema。 | <code>            "rag_enabled": "TINYINT(1) NOT NULL DEFAULT 0",</code> |
| L0101 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_review_schema。 | <code>            "rag_hits": "INT NOT NULL DEFAULT 0",</code> |
| L0102 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_review_schema。 | <code>            "review_latency_ms": "INT NULL",</code> |
| L0103 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_review_schema。 | <code>            "handling_suggestion": "LONGTEXT NULL",</code> |
| L0104 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_review_schema。 | <code>            "review_source": "VARCHAR(32) NULL",</code> |
| L0105 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_review_schema。 | <code>            "request_fingerprint": "CHAR(64) NULL",</code> |
| L0106 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ensure_review_schema。 | <code>        }</code> |
| L0107 | 遍历集合中的数据项并逐项处理，当前位于函数 ensure_review_schema。 | <code>        for column, sql_type in additions.items():</code> |
| L0108 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_review_schema。 | <code>            if not _column_exists(cur, "analyses", column):</code> |
| L0109 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_review_schema。 | <code>                cur.execute(f"ALTER TABLE analyses ADD COLUMN &#96;{column}&#96; {sql_type}")</code> |
| L0110 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0111 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0112 | 定义requestfingerprint函数 &#96;request_fingerprint&#96;，封装可复用业务逻辑。 | <code>def request_fingerprint(row: Dict[str, Any]) -&gt; str:</code> |
| L0113 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_fingerprint。 | <code>    """Strict target-lab signature, excluding source identity and capture time."""</code> |
| L0114 | 计算并保存 &#96;request_text&#96;（requesttext），供后续逻辑使用，当前位于函数 request_fingerprint。 | <code>    request_text = str(row.get("request_text") or "")</code> |
| L0115 | 计算并保存 &#96;content_type_match&#96;（contenttypematch），供后续逻辑使用，当前位于函数 request_fingerprint。 | <code>    content_type_match = re.search(r"(?m)^CONTENT_TYPE=(.*)$", request_text)</code> |
| L0116 | 计算并保存 &#96;request_body_match&#96;（requestbodymatch），供后续逻辑使用，当前位于函数 request_fingerprint。 | <code>    request_body_match = re.search(</code> |
| L0117 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_fingerprint。 | <code>        r"(?ms)^REQUEST_BODY=(.*?)(?=^RESPONSE_EXCERPT=&#124;\Z)", request_text</code> |
| L0118 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 request_fingerprint。 | <code>    )</code> |
| L0119 | 计算并保存 &#96;content_type&#96;（contenttype），供后续逻辑使用，当前位于函数 request_fingerprint。 | <code>    content_type = content_type_match.group(1).rstrip("\r") if content_type_match else ""</code> |
| L0120 | 计算并保存 &#96;request_body&#96;（requestbody），供后续逻辑使用，当前位于函数 request_fingerprint。 | <code>    request_body = request_body_match.group(1).rstrip("\r\n") if request_body_match else ""</code> |
| L0121 | 计算并保存 &#96;canonical&#96;（canonical），供后续逻辑使用，当前位于函数 request_fingerprint。 | <code>    canonical = "\n".join(</code> |
| L0122 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_fingerprint。 | <code>        [</code> |
| L0123 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_fingerprint。 | <code>            str(_target_port(row) or ""),</code> |
| L0124 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_fingerprint。 | <code>            str(row.get("method") or "").upper(),</code> |
| L0125 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_fingerprint。 | <code>            urllib.parse.unquote(str(row.get("uri") or "")),</code> |
| L0126 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_fingerprint。 | <code>            content_type,</code> |
| L0127 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_fingerprint。 | <code>            request_body,</code> |
| L0128 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 request_fingerprint。 | <code>        ]</code> |
| L0129 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 request_fingerprint。 | <code>    )</code> |
| L0130 | 结束当前函数并把结果返回给调用方，当前位于函数 request_fingerprint。 | <code>    return hashlib.sha256(canonical.encode("utf-8", errors="surrogatepass")).hexdigest()</code> |
| L0131 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0132 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0133 | 定义realtimellmenabled函数 &#96;realtime_llm_enabled&#96;，封装可复用业务逻辑。 | <code>def realtime_llm_enabled(conn: Any) -&gt; bool:</code> |
| L0134 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 realtime_llm_enabled。 | <code>    try:</code> |
| L0135 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 realtime_llm_enabled。 | <code>        with conn.cursor() as cur:</code> |
| L0136 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 realtime_llm_enabled。 | <code>            cur.execute(</code> |
| L0137 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 realtime_llm_enabled。 | <code>                "SELECT config_value FROM demo_system_config WHERE config_key='llm_realtime_enabled' LIMIT 1"</code> |
| L0138 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 realtime_llm_enabled。 | <code>            )</code> |
| L0139 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 realtime_llm_enabled。 | <code>            row = cur.fetchone() or {}</code> |
| L0140 | 结束当前函数并把结果返回给调用方，当前位于函数 realtime_llm_enabled。 | <code>        return str(row.get("config_value", "1")).strip().lower() in {"1", "true", "yes", "on"}</code> |
| L0141 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 realtime_llm_enabled。 | <code>    except Exception:</code> |
| L0142 | 结束当前函数并把结果返回给调用方，当前位于函数 realtime_llm_enabled。 | <code>        return True</code> |
| L0143 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0144 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0145 | 定义findcachedreview函数 &#96;find_cached_review&#96;，封装可复用业务逻辑。 | <code>def find_cached_review(conn: Any, row: Dict[str, Any]) -&gt; Optional[Dict[str, Any]]:</code> |
| L0146 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 find_cached_review。 | <code>    if _target_port(row) != 4000:</code> |
| L0147 | 结束当前函数并把结果返回给调用方，当前位于函数 find_cached_review。 | <code>        return None</code> |
| L0148 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 find_cached_review。 | <code>    fingerprint = request_fingerprint(row)</code> |
| L0149 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 find_cached_review。 | <code>    with conn.cursor() as cur:</code> |
| L0150 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 find_cached_review。 | <code>        cur.execute(</code> |
| L0151 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 find_cached_review。 | <code>            """SELECT fingerprint,template_json,model_name FROM llm_review_cache</code> |
| L0152 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_cached_review。 | <code>               WHERE fingerprint=%s AND target_port=4000 AND enabled=1 LIMIT 1""",</code> |
| L0153 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_cached_review。 | <code>            (fingerprint,),</code> |
| L0154 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 find_cached_review。 | <code>        )</code> |
| L0155 | 计算并保存 &#96;cached&#96;（cached），供后续逻辑使用，当前位于函数 find_cached_review。 | <code>        cached = cur.fetchone()</code> |
| L0156 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 find_cached_review。 | <code>    if not cached:</code> |
| L0157 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 find_cached_review。 | <code>        with conn.cursor() as cur:</code> |
| L0158 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 find_cached_review。 | <code>            cur.execute(</code> |
| L0159 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 find_cached_review。 | <code>                """SELECT a.request_fingerprint AS fingerprint,</code> |
| L0160 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_cached_review。 | <code>                          a.analysis_raw AS template_json,a.model_name</code> |
| L0161 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_cached_review。 | <code>                   FROM analyses a</code> |
| L0162 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_cached_review。 | <code>                   WHERE a.verdict='attack' AND a.llm_status='done'</code> |
| L0163 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_cached_review。 | <code>                     AND a.review_source='realtime_llm'</code> |
| L0164 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_cached_review。 | <code>                     AND a.request_fingerprint IS NOT NULL</code> |
| L0165 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_cached_review。 | <code>                     AND a.request_fingerprint=%s</code> |
| L0166 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_cached_review。 | <code>                   ORDER BY a.analyzed_at DESC LIMIT 1""",</code> |
| L0167 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_cached_review。 | <code>                (fingerprint,),</code> |
| L0168 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 find_cached_review。 | <code>            )</code> |
| L0169 | 计算并保存 &#96;cached&#96;（cached），供后续逻辑使用，当前位于函数 find_cached_review。 | <code>            cached = cur.fetchone()</code> |
| L0170 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 find_cached_review。 | <code>        if cached:</code> |
| L0171 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 find_cached_review。 | <code>            with conn.cursor() as cur:</code> |
| L0172 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 find_cached_review。 | <code>                cur.execute(</code> |
| L0173 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 find_cached_review。 | <code>                    """INSERT IGNORE INTO llm_review_cache(</code> |
| L0174 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_cached_review。 | <code>                         fingerprint,target_port,method,uri,template_json,model_name,enabled</code> |
| L0175 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_cached_review。 | <code>                       ) VALUES(%s,4000,%s,%s,%s,%s,1)""",</code> |
| L0176 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_cached_review。 | <code>                    (</code> |
| L0177 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_cached_review。 | <code>                        fingerprint, str(row.get("method") or "")[:16], str(row.get("uri") or ""),</code> |
| L0178 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_cached_review。 | <code>                        cached.get("template_json"), cached.get("model_name"),</code> |
| L0179 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 find_cached_review。 | <code>                    ),</code> |
| L0180 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 find_cached_review。 | <code>                )</code> |
| L0181 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 find_cached_review。 | <code>    if not cached:</code> |
| L0182 | 结束当前函数并把结果返回给调用方，当前位于函数 find_cached_review。 | <code>        return None</code> |
| L0183 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 find_cached_review。 | <code>    try:</code> |
| L0184 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_cached_review。 | <code>        cached["analysis"] = json.loads(str(cached.get("template_json") or "{}"))</code> |
| L0185 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 find_cached_review。 | <code>    except (TypeError, ValueError, json.JSONDecodeError):</code> |
| L0186 | 结束当前函数并把结果返回给调用方，当前位于函数 find_cached_review。 | <code>        return None</code> |
| L0187 | 结束当前函数并把结果返回给调用方，当前位于函数 find_cached_review。 | <code>    return cached</code> |
| L0188 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0189 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0190 | 定义deferreview函数 &#96;defer_review&#96;，封装可复用业务逻辑。 | <code>def defer_review(conn: Any, event_id: str, ready_at: datetime) -&gt; None:</code> |
| L0191 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 defer_review。 | <code>    with conn.cursor() as cur:</code> |
| L0192 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 defer_review。 | <code>        cur.execute(</code> |
| L0193 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 defer_review。 | <code>            """UPDATE llm_review_jobs SET status='pending',started_at=NULL,</code> |
| L0194 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 defer_review。 | <code>               attempts=GREATEST(0,attempts-1),next_retry_at=%s WHERE event_id=%s""",</code> |
| L0195 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 defer_review。 | <code>            (ready_at, event_id),</code> |
| L0196 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 defer_review。 | <code>        )</code> |
| L0197 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0198 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0199 | 定义markcachehit函数 &#96;mark_cache_hit&#96;，封装可复用业务逻辑。 | <code>def mark_cache_hit(conn: Any, fingerprint: str) -&gt; None:</code> |
| L0200 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 mark_cache_hit。 | <code>    with conn.cursor() as cur:</code> |
| L0201 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 mark_cache_hit。 | <code>        cur.execute("UPDATE llm_review_cache SET hit_count=hit_count+1 WHERE fingerprint=%s", (fingerprint,))</code> |
| L0202 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0203 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0204 | 定义enqueuereview函数 &#96;enqueue_review&#96;，封装可复用业务逻辑。 | <code>def enqueue_review(</code> |
| L0205 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 enqueue_review。 | <code>    conn: Any,</code> |
| L0206 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 enqueue_review。 | <code>    *,</code> |
| L0207 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 enqueue_review。 | <code>    event_id: str,</code> |
| L0208 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 enqueue_review。 | <code>    case_id: str,</code> |
| L0209 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 enqueue_review。 | <code>    preliminary_decision: str,</code> |
| L0210 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 enqueue_review。 | <code>    final_score: Any,</code> |
| L0211 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 enqueue_review。 | <code>) -&gt; None:</code> |
| L0212 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 enqueue_review。 | <code>    try:</code> |
| L0213 | 计算并保存 &#96;score&#96;（score），供后续逻辑使用，当前位于函数 enqueue_review。 | <code>        score = float(final_score or 0.0)</code> |
| L0214 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 enqueue_review。 | <code>    except Exception:</code> |
| L0215 | 计算并保存 &#96;score&#96;（score），供后续逻辑使用，当前位于函数 enqueue_review。 | <code>        score = 0.0</code> |
| L0216 | 计算并保存 &#96;priority&#96;（priority），供后续逻辑使用，当前位于函数 enqueue_review。 | <code>    priority = max(1, min(999, int(round(score * 100))))</code> |
| L0217 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 enqueue_review。 | <code>    with conn.cursor() as cur:</code> |
| L0218 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 enqueue_review。 | <code>        cur.execute(</code> |
| L0219 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 enqueue_review。 | <code>            """</code> |
| L0220 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 enqueue_review。 | <code>            INSERT INTO llm_review_jobs(event_id, case_id, preliminary_decision, priority, status, next_retry_at)</code> |
| L0221 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 enqueue_review。 | <code>            VALUES(%s,%s,%s,%s,'pending',NOW())</code> |
| L0222 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 enqueue_review。 | <code>            ON DUPLICATE KEY UPDATE</code> |
| L0223 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 enqueue_review。 | <code>              case_id=VALUES(case_id),</code> |
| L0224 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 enqueue_review。 | <code>              preliminary_decision=VALUES(preliminary_decision),</code> |
| L0225 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 enqueue_review。 | <code>              priority=VALUES(priority),</code> |
| L0226 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 enqueue_review。 | <code>              status=CASE</code> |
| L0227 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 enqueue_review。 | <code>                WHEN status IN ('processing','done') THEN status</code> |
| L0228 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 enqueue_review。 | <code>                ELSE 'pending'</code> |
| L0229 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 enqueue_review。 | <code>              END,</code> |
| L0230 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 enqueue_review。 | <code>              next_retry_at=CASE WHEN status IN ('processing','done') THEN next_retry_at ELSE NOW() END,</code> |
| L0231 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 enqueue_review。 | <code>              error_message=CASE WHEN status IN ('processing','done') THEN error_message ELSE NULL END</code> |
| L0232 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 enqueue_review。 | <code>            """,</code> |
| L0233 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 enqueue_review。 | <code>            (event_id, case_id, preliminary_decision, priority),</code> |
| L0234 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 enqueue_review。 | <code>        )</code> |
| L0235 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0236 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0237 | 定义prioritizecachedreview函数 &#96;prioritize_cached_review&#96;，封装可复用业务逻辑。 | <code>def prioritize_cached_review(conn: Any, event_id: str, row: Dict[str, Any]) -&gt; bool:</code> |
| L0238 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 prioritize_cached_review。 | <code>    """Promote an exact verified fingerprint without changing normal queue order."""</code> |
| L0239 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 prioritize_cached_review。 | <code>    fingerprint = request_fingerprint(row)</code> |
| L0240 | 计算并保存 &#96;target_port&#96;（targetport），供后续逻辑使用，当前位于函数 prioritize_cached_review。 | <code>    target_port = _target_port(row)</code> |
| L0241 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 prioritize_cached_review。 | <code>    if not fingerprint or target_port != 4000:</code> |
| L0242 | 结束当前函数并把结果返回给调用方，当前位于函数 prioritize_cached_review。 | <code>        return False</code> |
| L0243 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 prioritize_cached_review。 | <code>    with conn.cursor() as cur:</code> |
| L0244 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 prioritize_cached_review。 | <code>        cur.execute(</code> |
| L0245 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 prioritize_cached_review。 | <code>            "SELECT 1 FROM llm_review_cache WHERE fingerprint=%s AND target_port=4000 AND enabled=1 LIMIT 1",</code> |
| L0246 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 prioritize_cached_review。 | <code>            (fingerprint,),</code> |
| L0247 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 prioritize_cached_review。 | <code>        )</code> |
| L0248 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 prioritize_cached_review。 | <code>        if not cur.fetchone():</code> |
| L0249 | 结束当前函数并把结果返回给调用方，当前位于函数 prioritize_cached_review。 | <code>            return False</code> |
| L0250 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 prioritize_cached_review。 | <code>        cur.execute(</code> |
| L0251 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 prioritize_cached_review。 | <code>            "UPDATE llm_review_jobs SET priority=1000,next_retry_at=NOW() WHERE event_id=%s AND status='pending'",</code> |
| L0252 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 prioritize_cached_review。 | <code>            (event_id,),</code> |
| L0253 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 prioritize_cached_review。 | <code>        )</code> |
| L0254 | 结束当前函数并把结果返回给调用方，当前位于函数 prioritize_cached_review。 | <code>    return True</code> |
| L0255 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0256 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0257 | 定义移除review函数 &#96;remove_review&#96;，封装可复用业务逻辑。 | <code>def remove_review(conn: Any, event_id: str, case_id: str) -&gt; None:</code> |
| L0258 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 remove_review。 | <code>    with conn.cursor() as cur:</code> |
| L0259 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 remove_review。 | <code>        cur.execute("DELETE FROM llm_review_jobs WHERE event_id=%s OR case_id=%s", (event_id, case_id))</code> |
| L0260 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 remove_review。 | <code>        cur.execute("DELETE FROM analyses WHERE case_id=%s", (case_id,))</code> |
| L0261 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0262 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0263 | 定义claimnextreview函数 &#96;claim_next_review&#96;，封装可复用业务逻辑。 | <code>def claim_next_review(conn: Any, *, max_attempts: int = 3) -&gt; Optional[Dict[str, Any]]:</code> |
| L0264 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_next_review。 | <code>    conn.begin()</code> |
| L0265 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 claim_next_review。 | <code>    try:</code> |
| L0266 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 claim_next_review。 | <code>        with conn.cursor() as cur:</code> |
| L0267 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 claim_next_review。 | <code>            cur.execute(</code> |
| L0268 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                """</code> |
| L0269 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 claim_next_review。 | <code>                UPDATE llm_review_jobs</code> |
| L0270 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                SET status='pending', started_at=NULL,</code> |
| L0271 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                    attempts=GREATEST(0,attempts-1),</code> |
| L0272 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                    error_message=CONCAT(COALESCE(error_message,''), ' [recovered stale job]')</code> |
| L0273 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                WHERE status='processing' AND started_at &lt; NOW() - INTERVAL 10 MINUTE</code> |
| L0274 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                """</code> |
| L0275 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 claim_next_review。 | <code>            )</code> |
| L0276 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 claim_next_review。 | <code>            cur.execute(</code> |
| L0277 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                """</code> |
| L0278 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 claim_next_review。 | <code>                SELECT event_id,case_id,preliminary_decision,priority,attempts,</code> |
| L0279 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                       created_at AS review_created_at</code> |
| L0280 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                FROM llm_review_jobs</code> |
| L0281 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                WHERE status IN ('pending','failed')</code> |
| L0282 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                  AND attempts &lt; %s</code> |
| L0283 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                  AND (next_retry_at IS NULL OR next_retry_at &lt;= NOW())</code> |
| L0284 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                ORDER BY (priority &gt;= 1000) DESC,priority DESC,created_at ASC</code> |
| L0285 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                LIMIT 1 FOR UPDATE</code> |
| L0286 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                """,</code> |
| L0287 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_next_review。 | <code>                (max(1, int(max_attempts)),),</code> |
| L0288 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 claim_next_review。 | <code>            )</code> |
| L0289 | 计算并保存 &#96;job&#96;（job），供后续逻辑使用，当前位于函数 claim_next_review。 | <code>            job = cur.fetchone()</code> |
| L0290 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 claim_next_review。 | <code>            if not job:</code> |
| L0291 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_next_review。 | <code>                conn.commit()</code> |
| L0292 | 结束当前函数并把结果返回给调用方，当前位于函数 claim_next_review。 | <code>                return None</code> |
| L0293 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 claim_next_review。 | <code>            cur.execute(</code> |
| L0294 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                """</code> |
| L0295 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 claim_next_review。 | <code>                UPDATE llm_review_jobs</code> |
| L0296 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                SET status='processing', attempts=attempts+1, started_at=NOW(),</code> |
| L0297 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                    completed_at=NULL, error_message=NULL</code> |
| L0298 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                WHERE event_id=%s</code> |
| L0299 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                """,</code> |
| L0300 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_next_review。 | <code>                (job["event_id"],),</code> |
| L0301 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 claim_next_review。 | <code>            )</code> |
| L0302 | 源码原注释：Point lookups use indexed keys. The old cross-collation joins | <code>            # Point lookups use indexed keys. The old cross-collation joins</code> |
| L0303 | 源码原注释：scanned the full RAW table as it grew beyond 600k records. | <code>            # scanned the full RAW table as it grew beyond 600k records.</code> |
| L0304 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 claim_next_review。 | <code>            cur.execute(</code> |
| L0305 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 claim_next_review。 | <code>                """SELECT file_id,seq_id,final_score,risk_level,attack_type,</code> |
| L0306 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                          source_ip,target_interface,evidence_json</code> |
| L0307 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                   FROM detection_candidates WHERE event_id=%s LIMIT 1""",</code> |
| L0308 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_next_review。 | <code>                (job["event_id"],),</code> |
| L0309 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 claim_next_review。 | <code>            )</code> |
| L0310 | 计算并保存 &#96;candidate&#96;（candidate），供后续逻辑使用，当前位于函数 claim_next_review。 | <code>            candidate = cur.fetchone()</code> |
| L0311 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 claim_next_review。 | <code>            cur.execute(</code> |
| L0312 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 claim_next_review。 | <code>                """SELECT event_time,destination_ip,method,uri,host,status_code,</code> |
| L0313 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                          request_text,response_text</code> |
| L0314 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>                   FROM raw_http_logs WHERE case_id=%s LIMIT 1""",</code> |
| L0315 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_next_review。 | <code>                (job["case_id"],),</code> |
| L0316 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 claim_next_review。 | <code>            )</code> |
| L0317 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 claim_next_review。 | <code>            raw = cur.fetchone()</code> |
| L0318 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 claim_next_review。 | <code>            if not candidate or not raw:</code> |
| L0319 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 claim_next_review。 | <code>                cur.execute("DELETE FROM llm_review_jobs WHERE event_id=%s", (job["event_id"],))</code> |
| L0320 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_next_review。 | <code>                conn.commit()</code> |
| L0321 | 结束当前函数并把结果返回给调用方，当前位于函数 claim_next_review。 | <code>                return None</code> |
| L0322 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 claim_next_review。 | <code>            row = {**job, **candidate, **raw}</code> |
| L0323 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_next_review。 | <code>        conn.commit()</code> |
| L0324 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 claim_next_review。 | <code>    except Exception:</code> |
| L0325 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_next_review。 | <code>        conn.rollback()</code> |
| L0326 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_next_review。 | <code>        raise</code> |
| L0327 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0328 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 claim_next_review。 | <code>    with conn.cursor() as cur:</code> |
| L0329 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 claim_next_review。 | <code>        cur.execute(</code> |
| L0330 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>            """</code> |
| L0331 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 claim_next_review。 | <code>            SELECT model_name, label, score, proba_json</code> |
| L0332 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>            FROM model_predictions WHERE case_id=%s ORDER BY id DESC LIMIT 10</code> |
| L0333 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>            """,</code> |
| L0334 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_next_review。 | <code>            (row["case_id"],),</code> |
| L0335 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 claim_next_review。 | <code>        )</code> |
| L0336 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_next_review。 | <code>        row["model_predictions"] = list(cur.fetchall())</code> |
| L0337 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 claim_next_review。 | <code>        cur.execute(</code> |
| L0338 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>            """</code> |
| L0339 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 claim_next_review。 | <code>            SELECT rule_id, rule_name, attack_type, severity, score, evidence_json</code> |
| L0340 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>            FROM poc_matches WHERE case_id=%s ORDER BY score DESC LIMIT 20</code> |
| L0341 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>            """,</code> |
| L0342 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_next_review。 | <code>            (row["case_id"],),</code> |
| L0343 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 claim_next_review。 | <code>        )</code> |
| L0344 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_next_review。 | <code>        row["poc_matches"] = list(cur.fetchall())</code> |
| L0345 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 claim_next_review。 | <code>        cur.execute(</code> |
| L0346 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>            """</code> |
| L0347 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 claim_next_review。 | <code>            SELECT source_ip, behavior_type, score, features_json, evidence_json</code> |
| L0348 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>            FROM behavior_windows WHERE case_id=%s ORDER BY score DESC LIMIT 10</code> |
| L0349 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 claim_next_review。 | <code>            """,</code> |
| L0350 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_next_review。 | <code>            (row["case_id"],),</code> |
| L0351 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 claim_next_review。 | <code>        )</code> |
| L0352 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 claim_next_review。 | <code>        row["behavior_windows"] = list(cur.fetchall())</code> |
| L0353 | 结束当前函数并把结果返回给调用方，当前位于函数 claim_next_review。 | <code>    return row</code> |
| L0354 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0355 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0356 | 定义detectioncontext函数 &#96;detection_context&#96;，封装可复用业务逻辑。 | <code>def detection_context(row: Dict[str, Any]) -&gt; Dict[str, Any]:</code> |
| L0357 | 定义decode函数 &#96;decode&#96;，封装可复用业务逻辑。 | <code>    def decode(value: Any, default: Any) -&gt; Any:</code> |
| L0358 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode。 | <code>        if isinstance(value, (dict, list)):</code> |
| L0359 | 结束当前函数并把结果返回给调用方，当前位于函数 decode。 | <code>            return value</code> |
| L0360 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 decode。 | <code>        try:</code> |
| L0361 | 结束当前函数并把结果返回给调用方，当前位于函数 decode。 | <code>            return json.loads(str(value or ""))</code> |
| L0362 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 decode。 | <code>        except Exception:</code> |
| L0363 | 结束当前函数并把结果返回给调用方，当前位于函数 decode。 | <code>            return default</code> |
| L0364 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0365 | 计算并保存 &#96;predictions&#96;（predictions），供后续逻辑使用，当前位于函数 detection_context。 | <code>    predictions = []</code> |
| L0366 | 遍历集合中的数据项并逐项处理，当前位于函数 detection_context。 | <code>    for item in row.get("model_predictions") or []:</code> |
| L0367 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 detection_context。 | <code>        predictions.append(</code> |
| L0368 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>            {</code> |
| L0369 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>                "model_name": item.get("model_name"),</code> |
| L0370 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>                "label": item.get("label"),</code> |
| L0371 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>                "score": item.get("score"),</code> |
| L0372 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>                "probabilities": decode(item.get("proba_json"), {}),</code> |
| L0373 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 detection_context。 | <code>            }</code> |
| L0374 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 detection_context。 | <code>        )</code> |
| L0375 | 计算并保存 &#96;pocs&#96;（pocs），供后续逻辑使用，当前位于函数 detection_context。 | <code>    pocs = []</code> |
| L0376 | 遍历集合中的数据项并逐项处理，当前位于函数 detection_context。 | <code>    for item in row.get("poc_matches") or []:</code> |
| L0377 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 detection_context。 | <code>        pocs.append(</code> |
| L0378 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>            {</code> |
| L0379 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>                "rule_id": item.get("rule_id"),</code> |
| L0380 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>                "rule_name": item.get("rule_name"),</code> |
| L0381 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>                "attack_type": item.get("attack_type"),</code> |
| L0382 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>                "severity": item.get("severity"),</code> |
| L0383 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>                "score": item.get("score"),</code> |
| L0384 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>                "evidence": decode(item.get("evidence_json"), []),</code> |
| L0385 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 detection_context。 | <code>            }</code> |
| L0386 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 detection_context。 | <code>        )</code> |
| L0387 | 计算并保存 &#96;behaviors&#96;（behaviors），供后续逻辑使用，当前位于函数 detection_context。 | <code>    behaviors = []</code> |
| L0388 | 遍历集合中的数据项并逐项处理，当前位于函数 detection_context。 | <code>    for item in row.get("behavior_windows") or []:</code> |
| L0389 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 detection_context。 | <code>        behaviors.append(</code> |
| L0390 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>            {</code> |
| L0391 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>                "source_ip": item.get("source_ip"),</code> |
| L0392 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>                "behavior_type": item.get("behavior_type"),</code> |
| L0393 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>                "score": item.get("score"),</code> |
| L0394 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>                "features": decode(item.get("features_json"), {}),</code> |
| L0395 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>                "evidence": decode(item.get("evidence_json"), []),</code> |
| L0396 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 detection_context。 | <code>            }</code> |
| L0397 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 detection_context。 | <code>        )</code> |
| L0398 | 结束当前函数并把结果返回给调用方，当前位于函数 detection_context。 | <code>    return {</code> |
| L0399 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>        "preliminary_decision": row.get("preliminary_decision"),</code> |
| L0400 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>        "fusion_score": row.get("final_score"),</code> |
| L0401 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>        "fusion_risk": row.get("risk_level"),</code> |
| L0402 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>        "fusion_attack_type": row.get("attack_type"),</code> |
| L0403 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>        "fusion_evidence": decode(row.get("evidence_json"), []),</code> |
| L0404 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>        "payload_models": predictions,</code> |
| L0405 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>        "poc_matches": pocs,</code> |
| L0406 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detection_context。 | <code>        "behavior_windows": behaviors,</code> |
| L0407 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 detection_context。 | <code>    }</code> |
| L0408 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0409 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0410 | 定义targetport函数 &#96;_target_port&#96;，封装可复用业务逻辑。 | <code>def _target_port(row: Dict[str, Any]) -&gt; Optional[int]:</code> |
| L0411 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 _target_port。 | <code>    host = str(row.get("host") or "")</code> |
| L0412 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _target_port。 | <code>    if ":" in host:</code> |
| L0413 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _target_port。 | <code>        try:</code> |
| L0414 | 计算并保存 &#96;port&#96;（port），供后续逻辑使用，当前位于函数 _target_port。 | <code>            port = int(host.rsplit(":", 1)[1])</code> |
| L0415 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _target_port。 | <code>            if 1 &lt;= port &lt;= 65535:</code> |
| L0416 | 结束当前函数并把结果返回给调用方，当前位于函数 _target_port。 | <code>                return port</code> |
| L0417 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _target_port。 | <code>        except Exception:</code> |
| L0418 | 控制当前循环或占位分支的执行流程，当前位于函数 _target_port。 | <code>            pass</code> |
| L0419 | 结束当前函数并把结果返回给调用方，当前位于函数 _target_port。 | <code>    return None</code> |
| L0420 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0421 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0422 | 定义标准化reviewevidence函数 &#96;normalize_review_evidence&#96;，封装可复用业务逻辑。 | <code>def normalize_review_evidence(</code> |
| L0423 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_review_evidence。 | <code>    analysis: Dict[str, Any], *, row: Dict[str, Any], summary: str</code> |
| L0424 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_review_evidence。 | <code>) -&gt; List[str]:</code> |
| L0425 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_review_evidence。 | <code>    """Keep LLM evidence visible even when a small model omits the optional-looking field."""</code> |
| L0426 | 计算并保存 &#96;values&#96;（values），供后续逻辑使用，当前位于函数 normalize_review_evidence。 | <code>    values: List[str] = []</code> |
| L0427 | 计算并保存 &#96;raw_evidence&#96;（rawevidence），供后续逻辑使用，当前位于函数 normalize_review_evidence。 | <code>    raw_evidence = analysis.get("evidence")</code> |
| L0428 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_review_evidence。 | <code>    if isinstance(raw_evidence, list):</code> |
| L0429 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 normalize_review_evidence。 | <code>        values.extend(str(item).strip() for item in raw_evidence if str(item).strip())</code> |
| L0430 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0431 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_review_evidence。 | <code>    if not values:</code> |
| L0432 | 计算并保存 &#96;fused&#96;（fused），供后续逻辑使用，当前位于函数 normalize_review_evidence。 | <code>        fused = row.get("evidence_json")</code> |
| L0433 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 normalize_review_evidence。 | <code>        try:</code> |
| L0434 | 计算并保存 &#96;fused&#96;（fused），供后续逻辑使用，当前位于函数 normalize_review_evidence。 | <code>            fused = json.loads(fused) if isinstance(fused, str) else fused</code> |
| L0435 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 normalize_review_evidence。 | <code>        except (TypeError, ValueError, json.JSONDecodeError):</code> |
| L0436 | 计算并保存 &#96;fused&#96;（fused），供后续逻辑使用，当前位于函数 normalize_review_evidence。 | <code>            fused = []</code> |
| L0437 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_review_evidence。 | <code>        if isinstance(fused, list):</code> |
| L0438 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 normalize_review_evidence。 | <code>            values.extend(f"融合证据：{str(item).strip()}" for item in fused if str(item).strip())</code> |
| L0439 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0440 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_review_evidence。 | <code>    if not values and summary:</code> |
| L0441 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 normalize_review_evidence。 | <code>        values.append(f"大模型研判说明：{summary}")</code> |
| L0442 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_review_evidence。 | <code>    return values[:8]</code> |
| L0443 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0444 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0445 | 应用装饰器 &#96;@contextmanager&#96;，为下一定义附加权限、缓存或注册行为。 | <code>@contextmanager</code> |
| L0446 | 定义transactioncursor函数 &#96;_transaction_cursor&#96;，封装可复用业务逻辑。 | <code>def _transaction_cursor(conn: Any):</code> |
| L0447 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _transaction_cursor。 | <code>    conn.begin()</code> |
| L0448 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _transaction_cursor。 | <code>    try:</code> |
| L0449 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 _transaction_cursor。 | <code>        with conn.cursor() as cur:</code> |
| L0450 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _transaction_cursor。 | <code>            yield cur</code> |
| L0451 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _transaction_cursor。 | <code>        conn.commit()</code> |
| L0452 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _transaction_cursor。 | <code>    except Exception:</code> |
| L0453 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _transaction_cursor。 | <code>        conn.rollback()</code> |
| L0454 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _transaction_cursor。 | <code>        raise</code> |
| L0455 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0456 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0457 | 定义completereview函数 &#96;complete_review&#96;，封装可复用业务逻辑。 | <code>def complete_review(</code> |
| L0458 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>    conn: Any,</code> |
| L0459 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>    *,</code> |
| L0460 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>    row: Dict[str, Any],</code> |
| L0461 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>    analysis: Dict[str, Any],</code> |
| L0462 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>    raw_content: str,</code> |
| L0463 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>    model_name: str,</code> |
| L0464 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>    rag_enabled: bool,</code> |
| L0465 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>    rag_hits: int,</code> |
| L0466 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>    latency_ms: int,</code> |
| L0467 | 计算并保存 &#96;review_source&#96;（review来源），供后续逻辑使用，当前位于函数 complete_review。 | <code>    review_source: str = "realtime_llm",</code> |
| L0468 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 complete_review。 | <code>) -&gt; bool:</code> |
| L0469 | 计算并保存 &#96;verdict&#96;（verdict），供后续逻辑使用，当前位于函数 complete_review。 | <code>    verdict = str(analysis.get("verdict") or "unknown").strip().lower()</code> |
| L0470 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>    is_attack = verdict == "attack"</code> |
| L0471 | 计算并保存 &#96;summary&#96;（summary），供后续逻辑使用，当前位于函数 complete_review。 | <code>    summary = str(analysis.get("summary") or analysis.get("llm_explanation") or "").strip()</code> |
| L0472 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 complete_review。 | <code>    evidence = normalize_review_evidence(analysis, row=row, summary=summary)</code> |
| L0473 | 计算并保存 &#96;severity&#96;（severity），供后续逻辑使用，当前位于函数 complete_review。 | <code>    severity = str(analysis.get("severity") or row.get("risk_level") or "unknown")</code> |
| L0474 | 计算并保存 &#96;confidence&#96;（confidence），供后续逻辑使用，当前位于函数 complete_review。 | <code>    confidence = float(analysis.get("confidence") or 0.0)</code> |
| L0475 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 complete_review。 | <code>    attack_type = str(analysis.get("attack_method") or row.get("attack_type") or "可疑流量")</code> |
| L0476 | 计算并保存 &#96;analyzed_at&#96;（analyzedat），供后续逻辑使用，当前位于函数 complete_review。 | <code>    analyzed_at = str(analysis.get("analyzed_at") or datetime.now().isoformat(timespec="seconds"))</code> |
| L0477 | 计算并保存 &#96;immediate_actions&#96;（immediateactions），供后续逻辑使用，当前位于函数 complete_review。 | <code>    immediate_actions = analysis.get("immediate_actions") if isinstance(analysis.get("immediate_actions"), list) else []</code> |
| L0478 | 计算并保存 &#96;hardening_actions&#96;（hardeningactions），供后续逻辑使用，当前位于函数 complete_review。 | <code>    hardening_actions = analysis.get("hardening_actions") if isinstance(analysis.get("hardening_actions"), list) else []</code> |
| L0479 | 计算并保存 &#96;handling_suggestion&#96;（handlingsuggestion），供后续逻辑使用，当前位于函数 complete_review。 | <code>    handling_suggestion = "\n".join(</code> |
| L0480 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>        [f"立即处置：{item}" for item in immediate_actions]</code> |
| L0481 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>        + [f"长期加固：{item}" for item in hardening_actions]</code> |
| L0482 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 complete_review。 | <code>    ) or summary</code> |
| L0483 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0484 | 源码原注释：Persist the post-validation structure used by the UI, not unchecked model text. | <code>    # Persist the post-validation structure used by the UI, not unchecked model text.</code> |
| L0485 | 计算并保存 &#96;validated_raw_content&#96;（validatedrawcontent），供后续逻辑使用，当前位于函数 complete_review。 | <code>    validated_raw_content = json.dumps(analysis, ensure_ascii=False)</code> |
| L0486 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 complete_review。 | <code>    with _transaction_cursor(conn) as cur:</code> |
| L0487 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 complete_review。 | <code>        cur.execute(</code> |
| L0488 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>            """</code> |
| L0489 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 complete_review。 | <code>            INSERT INTO analyses(</code> |
| L0490 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>              case_id,file_id,seq_id,llm_status,analyzed_at,model_name,verdict,</code> |
| L0491 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>              source_ip,destination_ip,attack_interface,attack_method,attack_path,</code> |
| L0492 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>              attack_time,severity,confidence,summary,evidence_json,analysis_raw,</code> |
| L0493 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>              attack_event_time,attack_ip,target_interface,attack_type,attack_confidence,</code> |
| L0494 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>              rag_enabled,rag_hits,review_latency_ms,handling_suggestion,</code> |
| L0495 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>              review_source,request_fingerprint</code> |
| L0496 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>            ) VALUES(</code> |
| L0497 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>              %s,%s,%s,'done',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s</code> |
| L0498 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>            )</code> |
| L0499 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>            ON DUPLICATE KEY UPDATE</code> |
| L0500 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>              llm_status='done',llm_error=NULL,llm_failed_at=NULL,analyzed_at=VALUES(analyzed_at),</code> |
| L0501 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>              model_name=VALUES(model_name),verdict=VALUES(verdict),source_ip=VALUES(source_ip),</code> |
| L0502 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>              destination_ip=VALUES(destination_ip),attack_interface=VALUES(attack_interface),</code> |
| L0503 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>              attack_method=VALUES(attack_method),attack_path=VALUES(attack_path),</code> |
| L0504 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>              attack_time=VALUES(attack_time),severity=VALUES(severity),confidence=VALUES(confidence),</code> |
| L0505 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>              summary=VALUES(summary),evidence_json=VALUES(evidence_json),analysis_raw=VALUES(analysis_raw),</code> |
| L0506 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>              attack_event_time=VALUES(attack_event_time),attack_ip=VALUES(attack_ip),</code> |
| L0507 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>              target_interface=VALUES(target_interface),attack_type=VALUES(attack_type),</code> |
| L0508 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>              attack_confidence=VALUES(attack_confidence),rag_enabled=VALUES(rag_enabled),</code> |
| L0509 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>              rag_hits=VALUES(rag_hits),review_latency_ms=VALUES(review_latency_ms),</code> |
| L0510 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>              handling_suggestion=VALUES(handling_suggestion),review_source=VALUES(review_source),</code> |
| L0511 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>              request_fingerprint=VALUES(request_fingerprint)</code> |
| L0512 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>            """,</code> |
| L0513 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>            (</code> |
| L0514 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>                row["case_id"], row.get("file_id"), row.get("seq_id"), analyzed_at, model_name,</code> |
| L0515 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>                verdict, row.get("source_ip"), row.get("destination_ip"), row.get("uri"),</code> |
| L0516 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>                attack_type, f"{row.get('method') or ''} {row.get('uri') or ''}".strip(),</code> |
| L0517 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>                row.get("event_time"), severity, confidence, summary,</code> |
| L0518 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>                json.dumps(evidence, ensure_ascii=False), validated_raw_content, row.get("event_time"),</code> |
| L0519 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>                row.get("source_ip"), row.get("uri"), attack_type, confidence,</code> |
| L0520 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>                1 if rag_enabled else 0, int(rag_hits), int(latency_ms), handling_suggestion,</code> |
| L0521 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 complete_review。 | <code>                review_source, request_fingerprint(row),</code> |
| L0522 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 complete_review。 | <code>            ),</code> |
| L0523 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 complete_review。 | <code>        )</code> |
| L0524 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 complete_review。 | <code>        if is_attack and review_source == "realtime_llm" and _target_port(row) == 4000:</code> |
| L0525 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 complete_review。 | <code>            cur.execute(</code> |
| L0526 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 complete_review。 | <code>                """INSERT INTO llm_review_cache(</code> |
| L0527 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                     fingerprint,target_port,method,uri,template_json,model_name,enabled</code> |
| L0528 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                   ) VALUES(%s,4000,%s,%s,%s,%s,1)</code> |
| L0529 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 complete_review。 | <code>                   ON DUPLICATE KEY UPDATE template_json=VALUES(template_json),</code> |
| L0530 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                     model_name=VALUES(model_name),enabled=1""",</code> |
| L0531 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>                (</code> |
| L0532 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 complete_review。 | <code>                    request_fingerprint(row), str(row.get("method") or "")[:16],</code> |
| L0533 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>                    str(row.get("uri") or ""), validated_raw_content, model_name,</code> |
| L0534 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 complete_review。 | <code>                ),</code> |
| L0535 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 complete_review。 | <code>            )</code> |
| L0536 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 complete_review。 | <code>        cur.execute(</code> |
| L0537 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>            """</code> |
| L0538 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 complete_review。 | <code>            UPDATE llm_review_jobs</code> |
| L0539 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>            SET status='done', completed_at=NOW(), model_name=%s, error_message=NULL</code> |
| L0540 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>            WHERE event_id=%s</code> |
| L0541 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>            """,</code> |
| L0542 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>            (model_name, row["event_id"]),</code> |
| L0543 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 complete_review。 | <code>        )</code> |
| L0544 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 complete_review。 | <code>        if is_attack:</code> |
| L0545 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 complete_review。 | <code>            cur.execute("UPDATE detection_candidates SET decision='attack_event' WHERE event_id=%s", (row["event_id"],))</code> |
| L0546 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 complete_review。 | <code>            cur.execute(</code> |
| L0547 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                """</code> |
| L0548 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 complete_review。 | <code>                INSERT INTO attack_events(event_id,case_id,occurred_at,source_ip,target_interface,</code> |
| L0549 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                  attack_type,risk_level,confidence,status,evidence_json)</code> |
| L0550 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,'unprocessed',%s)</code> |
| L0551 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 complete_review。 | <code>                ON DUPLICATE KEY UPDATE occurred_at=VALUES(occurred_at),source_ip=VALUES(source_ip),</code> |
| L0552 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                  target_interface=VALUES(target_interface),attack_type=VALUES(attack_type),</code> |
| L0553 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                  risk_level=VALUES(risk_level),confidence=VALUES(confidence),</code> |
| L0554 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                  evidence_json=VALUES(evidence_json)</code> |
| L0555 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                """,</code> |
| L0556 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>                (</code> |
| L0557 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>                    row["event_id"], row["case_id"], row.get("event_time"), row.get("source_ip"),</code> |
| L0558 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>                    row.get("uri"), attack_type, severity, confidence,</code> |
| L0559 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>                    json.dumps(evidence, ensure_ascii=False),</code> |
| L0560 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 complete_review。 | <code>                ),</code> |
| L0561 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 complete_review。 | <code>            )</code> |
| L0562 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 complete_review。 | <code>            cur.execute(</code> |
| L0563 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                """</code> |
| L0564 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 complete_review。 | <code>                INSERT INTO demo_attack_events(</code> |
| L0565 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                  event_id,occurred_at,risk_level,attack_type,source_ip,source_region,</code> |
| L0566 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                  target_node,target_port,target_interface,attack_result,process_status,</code> |
| L0567 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                  attack_payload,request_log,protection_action,handling_suggestion,</code> |
| L0568 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                  response_ms,anomaly_detected</code> |
| L0569 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                ) VALUES(%s,%s,%s,%s,%s,'未知地区','本机服务器',%s,%s,'detected','unprocessed',</code> |
| L0570 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                  %s,%s,'Payload/POC/行为窗口筛选 + 大模型最终研判',%s,%s,1)</code> |
| L0571 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 complete_review。 | <code>                ON DUPLICATE KEY UPDATE occurred_at=VALUES(occurred_at),risk_level=VALUES(risk_level),</code> |
| L0572 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                  attack_type=VALUES(attack_type),source_ip=VALUES(source_ip),target_port=VALUES(target_port),</code> |
| L0573 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                  target_interface=VALUES(target_interface),attack_payload=VALUES(attack_payload),</code> |
| L0574 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                  request_log=VALUES(request_log),protection_action=VALUES(protection_action),</code> |
| L0575 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                  handling_suggestion=VALUES(handling_suggestion),response_ms=VALUES(response_ms),</code> |
| L0576 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                  anomaly_detected=1</code> |
| L0577 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 complete_review。 | <code>                """,</code> |
| L0578 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>                (</code> |
| L0579 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>                    row["event_id"][:40], row.get("event_time"), severity, attack_type,</code> |
| L0580 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>                    row.get("source_ip") or "unknown", _target_port(row), row.get("uri") or "",</code> |
| L0581 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>                    row.get("request_text") or "", row.get("request_text") or "", handling_suggestion,</code> |
| L0582 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>                    int(latency_ms),</code> |
| L0583 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 complete_review。 | <code>                ),</code> |
| L0584 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 complete_review。 | <code>            )</code> |
| L0585 | 处理前述条件均未命中的情况，当前位于函数 complete_review。 | <code>        else:</code> |
| L0586 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 complete_review。 | <code>            next_decision = "raw_only" if verdict == "benign" else "candidate"</code> |
| L0587 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 complete_review。 | <code>            cur.execute("UPDATE detection_candidates SET decision=%s WHERE event_id=%s", (next_decision, row["event_id"]))</code> |
| L0588 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 complete_review。 | <code>            cur.execute("DELETE FROM attack_events WHERE event_id=%s", (row["event_id"],))</code> |
| L0589 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 complete_review。 | <code>            cur.execute("DELETE FROM demo_attack_events WHERE event_id=%s", (row["event_id"][:40],))</code> |
| L0590 | 结束当前函数并把结果返回给调用方，当前位于函数 complete_review。 | <code>    return is_attack</code> |
| L0591 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0592 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0593 | 定义failreview函数 &#96;fail_review&#96;，封装可复用业务逻辑。 | <code>def fail_review(conn: Any, *, event_id: str, case_id: str, error: str, max_attempts: int = 3) -&gt; None:</code> |
| L0594 | 计算并保存 &#96;message&#96;（message），供后续逻辑使用，当前位于函数 fail_review。 | <code>    message = str(error or "unknown_error")[:4000]</code> |
| L0595 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 fail_review。 | <code>    with conn.cursor() as cur:</code> |
| L0596 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 fail_review。 | <code>        cur.execute("SELECT attempts FROM llm_review_jobs WHERE event_id=%s LIMIT 1", (event_id,))</code> |
| L0597 | 计算并保存 &#96;attempts&#96;（attempts），供后续逻辑使用，当前位于函数 fail_review。 | <code>        attempts = int((cur.fetchone() or {}).get("attempts") or 1)</code> |
| L0598 | 计算并保存 &#96;retry_minutes&#96;（retryminutes），供后续逻辑使用，当前位于函数 fail_review。 | <code>        retry_minutes = min(10, max(1, 2 ** max(0, attempts - 1)))</code> |
| L0599 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 fail_review。 | <code>        cur.execute(</code> |
| L0600 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 fail_review。 | <code>            """</code> |
| L0601 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 fail_review。 | <code>            UPDATE llm_review_jobs</code> |
| L0602 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 fail_review。 | <code>            SET status='failed', completed_at=NOW(), error_message=%s,</code> |
| L0603 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 fail_review。 | <code>                next_retry_at=CASE WHEN attempts &lt; %s THEN DATE_ADD(NOW(), INTERVAL %s MINUTE) ELSE NULL END</code> |
| L0604 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 fail_review。 | <code>            WHERE event_id=%s</code> |
| L0605 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 fail_review。 | <code>            """,</code> |
| L0606 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fail_review。 | <code>            (message, max(1, int(max_attempts)), retry_minutes, event_id),</code> |
| L0607 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fail_review。 | <code>        )</code> |
| L0608 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 fail_review。 | <code>        cur.execute(</code> |
| L0609 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 fail_review。 | <code>            """</code> |
| L0610 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 fail_review。 | <code>            INSERT INTO analyses(case_id,llm_status,llm_error,llm_failed_at)</code> |
| L0611 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 fail_review。 | <code>            VALUES(%s,'failed',%s,%s)</code> |
| L0612 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 fail_review。 | <code>            ON DUPLICATE KEY UPDATE llm_status='failed',llm_error=VALUES(llm_error),</code> |
| L0613 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 fail_review。 | <code>              llm_failed_at=VALUES(llm_failed_at)</code> |
| L0614 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 fail_review。 | <code>            """,</code> |
| L0615 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fail_review。 | <code>            (case_id, message, datetime.now().isoformat(timespec="seconds")),</code> |
| L0616 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fail_review。 | <code>        )</code> |
