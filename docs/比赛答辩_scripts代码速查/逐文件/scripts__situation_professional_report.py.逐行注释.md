# `scripts/situation_professional_report.py` 逐行注释

**脚本用途：** 生成专业态势报告及 PDF/Word 文档，负责模板、表格、图形和版式。

**源码行数：** 847　**函数/类数量：** 50

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import hashlib&#96;。 | <code>import hashlib</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import re&#96;。 | <code>import re</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;import threading&#96;。 | <code>import threading</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.error&#96;。 | <code>import urllib.error</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.request&#96;。 | <code>import urllib.request</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;import uuid&#96;。 | <code>import uuid</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;from xml.sax.saxutils import escape&#96;。 | <code>from xml.sax.saxutils import escape</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime&#96;。 | <code>from datetime import datetime</code> |
| L0012 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0013 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, List, Optional&#96;。 | <code>from typing import Any, Dict, List, Optional</code> |
| L0014 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0015 | 导入后续逻辑所需的模块、类或函数：&#96;import pymysql&#96;。 | <code>import pymysql</code> |
| L0016 | 导入后续逻辑所需的模块、类或函数：&#96;from pymysql.cursors import DictCursor&#96;。 | <code>from pymysql.cursors import DictCursor</code> |
| L0017 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0018 | 开始受保护操作，异常会交给后续分支处理。 | <code>try:</code> |
| L0019 | 导入后续逻辑所需的模块、类或函数：&#96;from rag_service import hybrid_search, list_kbs, load_api_config, mysql_connect&#96;。 | <code>    from rag_service import hybrid_search, list_kbs, load_api_config, mysql_connect</code> |
| L0020 | 导入后续逻辑所需的模块、类或函数：&#96;from situation_store import MySQLSettings, MySQLSituationStore&#96;。 | <code>    from situation_store import MySQLSettings, MySQLSituationStore</code> |
| L0021 | 捕获异常，避免单次错误导致整个服务退出。 | <code>except ImportError:  # Support package-style imports in tests and maintenance tools.</code> |
| L0022 | 导入后续逻辑所需的模块、类或函数：&#96;from scripts.rag_service import hybrid_search, list_kbs, load_api_config, mysql_connect&#96;。 | <code>    from scripts.rag_service import hybrid_search, list_kbs, load_api_config, mysql_connect</code> |
| L0023 | 导入后续逻辑所需的模块、类或函数：&#96;from scripts.situation_store import MySQLSettings, MySQLSituationStore&#96;。 | <code>    from scripts.situation_store import MySQLSettings, MySQLSituationStore</code> |
| L0024 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0025 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0026 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>REPORT_SCHEMA = """</code> |
| L0027 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>CREATE TABLE IF NOT EXISTS situation_professional_reports (</code> |
| L0028 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  job_id VARCHAR(40) PRIMARY KEY,</code> |
| L0029 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  situation_id VARCHAR(64) NOT NULL,</code> |
| L0030 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  sequence_hash VARCHAR(64) NOT NULL,</code> |
| L0031 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  status VARCHAR(24) NOT NULL DEFAULT 'queued',</code> |
| L0032 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  progress INT NOT NULL DEFAULT 0,</code> |
| L0033 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  stage VARCHAR(80) NOT NULL DEFAULT '任务已创建',</code> |
| L0034 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  model_name VARCHAR(80) NULL,</code> |
| L0035 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  snapshot_json LONGTEXT NULL,</code> |
| L0036 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  rag_references_json LONGTEXT NULL,</code> |
| L0037 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  report_markdown LONGTEXT NULL,</code> |
| L0038 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  pdf_path TEXT NULL,</code> |
| L0039 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  pdf_sha256 VARCHAR(64) NULL,</code> |
| L0040 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  input_tokens INT NOT NULL DEFAULT 0,</code> |
| L0041 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  output_tokens INT NOT NULL DEFAULT 0,</code> |
| L0042 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  error_message TEXT NULL,</code> |
| L0043 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  requested_by VARCHAR(80) NOT NULL,</code> |
| L0044 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),</code> |
| L0045 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  started_at DATETIME(3) NULL,</code> |
| L0046 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  completed_at DATETIME(3) NULL,</code> |
| L0047 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),</code> |
| L0048 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  UNIQUE KEY uniq_situation_revision (situation_id, sequence_hash),</code> |
| L0049 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>  KEY idx_report_status (status, updated_at)</code> |
| L0050 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4</code> |
| L0051 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>"""</code> |
| L0052 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0053 | 计算并保存 &#96;REQUIRED_REPORT_HEADINGS&#96;（REQUIRED报告HEADINGS），供后续逻辑使用。 | <code>REQUIRED_REPORT_HEADINGS = (</code> |
| L0054 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "## 一、基本信息",</code> |
| L0055 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "## 二、报告目的",</code> |
| L0056 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "## 三、分析方法",</code> |
| L0057 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "## 四、攻击态势分析",</code> |
| L0058 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "## 五、证据交叉验证",</code> |
| L0059 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "## 六、风险判断与行动建议",</code> |
| L0060 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "## 七、补充说明",</code> |
| L0061 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>)</code> |
| L0062 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0063 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0064 | 定义connect函数 &#96;connect&#96;，封装可复用业务逻辑。 | <code>def connect(conf: Dict[str, Any], autocommit: bool = False):</code> |
| L0065 | 结束当前函数并把结果返回给调用方，当前位于函数 connect。 | <code>    return pymysql.connect(</code> |
| L0066 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 connect。 | <code>        host=conf["host"], port=int(conf["port"]), user=conf["user"], password=conf["password"],</code> |
| L0067 | 计算并保存 &#96;database&#96;（数据库），供后续逻辑使用，当前位于函数 connect。 | <code>        database=conf["database"], charset="utf8mb4", cursorclass=DictCursor, autocommit=autocommit,</code> |
| L0068 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 connect。 | <code>    )</code> |
| L0069 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0070 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0071 | 定义ensureschema函数 &#96;ensure_schema&#96;，封装可复用业务逻辑。 | <code>def ensure_schema(conn: Any) -&gt; None:</code> |
| L0072 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 ensure_schema。 | <code>    with conn.cursor() as cur:</code> |
| L0073 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>        cur.execute(REPORT_SCHEMA)</code> |
| L0074 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>        cur.execute("UPDATE situation_professional_reports SET status='failed',stage='服务重启，任务已中断',error_message='service_restarted' WHERE status IN ('queued','running')")</code> |
| L0075 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema。 | <code>    conn.commit()</code> |
| L0076 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0077 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0078 | 定义publicjob函数 &#96;public_job&#96;，封装可复用业务逻辑。 | <code>def public_job(row: Optional[Dict[str, Any]]) -&gt; Optional[Dict[str, Any]]:</code> |
| L0079 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 public_job。 | <code>    if not row:</code> |
| L0080 | 结束当前函数并把结果返回给调用方，当前位于函数 public_job。 | <code>        return None</code> |
| L0081 | 结束当前函数并把结果返回给调用方，当前位于函数 public_job。 | <code>    return {</code> |
| L0082 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 public_job。 | <code>        "job_id": row.get("job_id"), "situation_id": row.get("situation_id"),</code> |
| L0083 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 public_job。 | <code>        "sequence_hash": row.get("sequence_hash"), "status": row.get("status"),</code> |
| L0084 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 public_job。 | <code>        "progress": int(row.get("progress") or 0), "stage": row.get("stage"),</code> |
| L0085 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 public_job。 | <code>        "model_name": row.get("model_name"), "input_tokens": int(row.get("input_tokens") or 0),</code> |
| L0086 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 public_job。 | <code>        "output_tokens": int(row.get("output_tokens") or 0), "error_message": row.get("error_message"),</code> |
| L0087 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 public_job。 | <code>        "created_at": row.get("created_at"), "started_at": row.get("started_at"),</code> |
| L0088 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 public_job。 | <code>        "completed_at": row.get("completed_at"), "updated_at": row.get("updated_at"),</code> |
| L0089 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 public_job。 | <code>        "ready": row.get("status") == "completed" and bool(row.get("pdf_path")),</code> |
| L0090 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 public_job。 | <code>    }</code> |
| L0091 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0092 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0093 | 定义findjob函数 &#96;find_job&#96;，封装可复用业务逻辑。 | <code>def find_job(conn: Any, situation_id: str, sequence_hash: str = "") -&gt; Optional[Dict[str, Any]]:</code> |
| L0094 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 find_job。 | <code>    with conn.cursor() as cur:</code> |
| L0095 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 find_job。 | <code>        if sequence_hash:</code> |
| L0096 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 find_job。 | <code>            cur.execute("SELECT * FROM situation_professional_reports WHERE situation_id=%s AND sequence_hash=%s LIMIT 1", (situation_id, sequence_hash))</code> |
| L0097 | 处理前述条件均未命中的情况，当前位于函数 find_job。 | <code>        else:</code> |
| L0098 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 find_job。 | <code>            cur.execute("SELECT * FROM situation_professional_reports WHERE situation_id=%s ORDER BY created_at DESC LIMIT 1", (situation_id,))</code> |
| L0099 | 结束当前函数并把结果返回给调用方，当前位于函数 find_job。 | <code>        return cur.fetchone()</code> |
| L0100 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0101 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0102 | 定义findlatestcompletedjob函数 &#96;find_latest_completed_job&#96;，封装可复用业务逻辑。 | <code>def find_latest_completed_job(conn: Any, situation_id: str) -&gt; Optional[Dict[str, Any]]:</code> |
| L0103 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_latest_completed_job。 | <code>    """Return the newest downloadable report even if the live chain has advanced."""</code> |
| L0104 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 find_latest_completed_job。 | <code>    with conn.cursor() as cur:</code> |
| L0105 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 find_latest_completed_job。 | <code>        cur.execute(</code> |
| L0106 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 find_latest_completed_job。 | <code>            """SELECT * FROM situation_professional_reports</code> |
| L0107 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_latest_completed_job。 | <code>               WHERE situation_id=%s AND status='completed' AND pdf_path IS NOT NULL</code> |
| L0108 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 find_latest_completed_job。 | <code>               ORDER BY completed_at DESC,created_at DESC LIMIT 1""",</code> |
| L0109 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_latest_completed_job。 | <code>            (situation_id,),</code> |
| L0110 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 find_latest_completed_job。 | <code>        )</code> |
| L0111 | 结束当前函数并把结果返回给调用方，当前位于函数 find_latest_completed_job。 | <code>        return cur.fetchone()</code> |
| L0112 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0113 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0114 | 定义读取job函数 &#96;get_job&#96;，封装可复用业务逻辑。 | <code>def get_job(conn: Any, job_id: str) -&gt; Optional[Dict[str, Any]]:</code> |
| L0115 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 get_job。 | <code>    with conn.cursor() as cur:</code> |
| L0116 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 get_job。 | <code>        cur.execute("SELECT * FROM situation_professional_reports WHERE job_id=%s LIMIT 1", (job_id,))</code> |
| L0117 | 结束当前函数并把结果返回给调用方，当前位于函数 get_job。 | <code>        return cur.fetchone()</code> |
| L0118 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0119 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0120 | 定义expirestalejobs函数 &#96;expire_stale_jobs&#96;，封装可复用业务逻辑。 | <code>def expire_stale_jobs(conn: Any, stale_seconds: int = 180) -&gt; int:</code> |
| L0121 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 expire_stale_jobs。 | <code>    """Fail abandoned jobs while live workers keep their row fresh via progress heartbeats."""</code> |
| L0122 | 计算并保存 &#96;cutoff_seconds&#96;（cutoffseconds），供后续逻辑使用，当前位于函数 expire_stale_jobs。 | <code>    cutoff_seconds = max(60, int(stale_seconds))</code> |
| L0123 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 expire_stale_jobs。 | <code>    with conn.cursor() as cur:</code> |
| L0124 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 expire_stale_jobs。 | <code>        cur.execute(</code> |
| L0125 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 expire_stale_jobs。 | <code>            """UPDATE situation_professional_reports</code> |
| L0126 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 expire_stale_jobs。 | <code>               SET status='failed',progress=100,stage='报告任务超时，请重新生成',</code> |
| L0127 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 expire_stale_jobs。 | <code>                   error_message='report_task_stalled',completed_at=NOW(3)</code> |
| L0128 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 expire_stale_jobs。 | <code>               WHERE status IN ('queued','running')</code> |
| L0129 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 expire_stale_jobs。 | <code>                 AND updated_at &lt; DATE_SUB(NOW(3), INTERVAL %s SECOND)""",</code> |
| L0130 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 expire_stale_jobs。 | <code>            (cutoff_seconds,),</code> |
| L0131 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 expire_stale_jobs。 | <code>        )</code> |
| L0132 | 结束当前函数并把结果返回给调用方，当前位于函数 expire_stale_jobs。 | <code>        return int(cur.rowcount or 0)</code> |
| L0133 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0134 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0135 | 定义创建job函数 &#96;create_job&#96;，封装可复用业务逻辑。 | <code>def create_job(conn: Any, situation: Dict[str, Any], username: str) -&gt; Dict[str, Any]:</code> |
| L0136 | 计算并保存 &#96;situation_id&#96;（态势id），供后续逻辑使用，当前位于函数 create_job。 | <code>    situation_id = str(situation["situation_id"])</code> |
| L0137 | 计算并保存 &#96;sequence_hash&#96;（sequencehash），供后续逻辑使用，当前位于函数 create_job。 | <code>    sequence_hash = str(situation.get("sequence_hash") or "")</code> |
| L0138 | 计算并保存 &#96;existing&#96;（existing），供后续逻辑使用，当前位于函数 create_job。 | <code>    existing = find_job(conn, situation_id, sequence_hash)</code> |
| L0139 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 create_job。 | <code>    if existing and existing.get("status") != "failed":</code> |
| L0140 | 结束当前函数并把结果返回给调用方，当前位于函数 create_job。 | <code>        return existing</code> |
| L0141 | 计算并保存 &#96;job_id&#96;（jobid），供后续逻辑使用，当前位于函数 create_job。 | <code>    job_id = f"SPR-{uuid.uuid4().hex[:24].upper()}"</code> |
| L0142 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 create_job。 | <code>    if existing:</code> |
| L0143 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 create_job。 | <code>        with conn.cursor() as cur:</code> |
| L0144 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 create_job。 | <code>            cur.execute(</code> |
| L0145 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 create_job。 | <code>                """UPDATE situation_professional_reports SET job_id=%s,status='queued',progress=2,stage='任务已创建',</code> |
| L0146 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 create_job。 | <code>                   error_message=NULL,requested_by=%s,started_at=NULL,completed_at=NULL,pdf_path=NULL WHERE situation_id=%s AND sequence_hash=%s""",</code> |
| L0147 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_job。 | <code>                (job_id, username, situation_id, sequence_hash),</code> |
| L0148 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 create_job。 | <code>            )</code> |
| L0149 | 处理前述条件均未命中的情况，当前位于函数 create_job。 | <code>    else:</code> |
| L0150 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 create_job。 | <code>        with conn.cursor() as cur:</code> |
| L0151 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 create_job。 | <code>            cur.execute(</code> |
| L0152 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 create_job。 | <code>                """INSERT INTO situation_professional_reports(job_id,situation_id,sequence_hash,status,progress,stage,requested_by)</code> |
| L0153 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 create_job。 | <code>                   VALUES(%s,%s,%s,'queued',2,'任务已创建',%s)""",</code> |
| L0154 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_job。 | <code>                (job_id, situation_id, sequence_hash, username),</code> |
| L0155 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 create_job。 | <code>            )</code> |
| L0156 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 create_job。 | <code>    conn.commit()</code> |
| L0157 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 create_job。 | <code>    with conn.cursor() as cur:</code> |
| L0158 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 create_job。 | <code>        cur.execute("SELECT * FROM situation_professional_reports WHERE job_id=%s", (job_id,))</code> |
| L0159 | 结束当前函数并把结果返回给调用方，当前位于函数 create_job。 | <code>        return cur.fetchone()</code> |
| L0160 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0161 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0162 | 定义更新job函数 &#96;update_job&#96;，封装可复用业务逻辑。 | <code>def update_job(conf: Dict[str, Any], job_id: str, progress: int, stage: str, **fields: Any) -&gt; None:</code> |
| L0163 | 计算并保存 &#96;allowed&#96;（allowed），供后续逻辑使用，当前位于函数 update_job。 | <code>    allowed = {"status", "model_name", "snapshot_json", "rag_references_json", "report_markdown", "pdf_path", "pdf_sha256", "input_tokens", "output_tokens", "error_message", "started_at", "completed_at"}</code> |
| L0164 | 计算并保存 &#96;values&#96;（values），供后续逻辑使用，当前位于函数 update_job。 | <code>    values: List[Any] = [max(0, min(100, int(progress))), stage[:80]]</code> |
| L0165 | 计算并保存 &#96;sets&#96;（sets），供后续逻辑使用，当前位于函数 update_job。 | <code>    sets = ["progress=%s", "stage=%s"]</code> |
| L0166 | 遍历集合中的数据项并逐项处理，当前位于函数 update_job。 | <code>    for key, value in fields.items():</code> |
| L0167 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 update_job。 | <code>        if key in allowed:</code> |
| L0168 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 update_job。 | <code>            sets.append(f"{key}=%s")</code> |
| L0169 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 update_job。 | <code>            values.append(value)</code> |
| L0170 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 update_job。 | <code>    values.append(job_id)</code> |
| L0171 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 update_job。 | <code>    with connect(conf, autocommit=True) as conn:</code> |
| L0172 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 update_job。 | <code>        with conn.cursor() as cur:</code> |
| L0173 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 update_job。 | <code>            cur.execute(f"UPDATE situation_professional_reports SET {','.join(sets)} WHERE job_id=%s", tuple(values))</code> |
| L0174 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0175 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0176 | 定义jsonsafe函数 &#96;json_safe&#96;，封装可复用业务逻辑。 | <code>def json_safe(value: Any) -&gt; Any:</code> |
| L0177 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 json_safe。 | <code>    if isinstance(value, dict): return {str(k): json_safe(v) for k, v in value.items()}</code> |
| L0178 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 json_safe。 | <code>    if isinstance(value, list): return [json_safe(v) for v in value]</code> |
| L0179 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 json_safe。 | <code>    if isinstance(value, (datetime,)): return value.isoformat(timespec="milliseconds")</code> |
| L0180 | 结束当前函数并把结果返回给调用方，当前位于函数 json_safe。 | <code>    return value</code> |
| L0181 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0182 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0183 | 定义构建snapshot函数 &#96;build_snapshot&#96;，封装可复用业务逻辑。 | <code>def build_snapshot(situation: Dict[str, Any]) -&gt; Dict[str, Any]:</code> |
| L0184 | 计算并保存 &#96;report&#96;（报告），供后续逻辑使用，当前位于函数 build_snapshot。 | <code>    report = situation.get("ai_report") or {}</code> |
| L0185 | 计算并保存 &#96;actions&#96;（actions），供后续逻辑使用，当前位于函数 build_snapshot。 | <code>    actions = []</code> |
| L0186 | 遍历集合中的数据项并逐项处理，当前位于函数 build_snapshot。 | <code>    for source in (situation.get("actions") or [])[:120]:</code> |
| L0187 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_snapshot。 | <code>        actions.append({</code> |
| L0188 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_snapshot。 | <code>            "sequence_no": source.get("sequence_no"), "action_id": source.get("action_id"),</code> |
| L0189 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_snapshot。 | <code>            "action_type": source.get("action_type"), "stage": source.get("stage"),</code> |
| L0190 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_snapshot。 | <code>            "sensor_type": source.get("sensor_type"), "occurred_at": source.get("occurred_at"),</code> |
| L0191 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_snapshot。 | <code>            "last_seen_at": source.get("last_seen_at"), "action_count": source.get("action_count"),</code> |
| L0192 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_snapshot。 | <code>            "confidence": source.get("confidence"), "severity": source.get("severity"),</code> |
| L0193 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_snapshot。 | <code>            "target_port": source.get("target_port"), "target_interface": source.get("target_interface"),</code> |
| L0194 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_snapshot。 | <code>            "evidence_refs": source.get("evidence_refs") or [],</code> |
| L0195 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_snapshot。 | <code>        })</code> |
| L0196 | 结束当前函数并把结果返回给调用方，当前位于函数 build_snapshot。 | <code>    return json_safe({</code> |
| L0197 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_snapshot。 | <code>        "schema_version": "1.0", "report_generated_for": situation.get("situation_id"),</code> |
| L0198 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_snapshot。 | <code>        "source_ip": situation.get("source_ip"), "target_asset": situation.get("target_asset"),</code> |
| L0199 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_snapshot。 | <code>        "started_at": situation.get("started_at"), "last_action_at": situation.get("last_action_at"),</code> |
| L0200 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_snapshot。 | <code>        "status": situation.get("status"), "risk_score": situation.get("risk_score"),</code> |
| L0201 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_snapshot。 | <code>        "risk_level": situation.get("risk_level"), "distinct_action_types": situation.get("distinct_action_types"),</code> |
| L0202 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_snapshot。 | <code>        "total_action_count": situation.get("total_action_count"), "current_stage": situation.get("current_stage"),</code> |
| L0203 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_snapshot。 | <code>        "actions": actions, "existing_ai_assessment": report,</code> |
| L0204 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_snapshot。 | <code>        "evidence_boundary": "网络侧证据证明请求或连接行为发生，不单独证明命令执行、数据泄露或主机失陷。",</code> |
| L0205 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_snapshot。 | <code>    })</code> |
| L0206 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0207 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0208 | 定义召回context函数 &#96;retrieve_context&#96;，封装可复用业务逻辑。 | <code>def retrieve_context(mysql_conf: Dict[str, Any], data_dir: Path, api_path: Path, snapshot: Dict[str, Any]) -&gt; List[Dict[str, Any]]:</code> |
| L0209 | 计算并保存 &#96;api_config&#96;（接口配置），供后续逻辑使用，当前位于函数 retrieve_context。 | <code>    api_config = load_api_config(api_path)</code> |
| L0210 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 retrieve_context。 | <code>    conn = mysql_connect(mysql_conf, autocommit=True)</code> |
| L0211 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 retrieve_context。 | <code>    try:</code> |
| L0212 | 计算并保存 &#96;bases&#96;（bases），供后续逻辑使用，当前位于函数 retrieve_context。 | <code>        bases = list_kbs(conn, include_disabled=False)</code> |
| L0213 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 retrieve_context。 | <code>        if not bases: return []</code> |
| L0214 | 计算并保存 &#96;query&#96;（query），供后续逻辑使用，当前位于函数 retrieve_context。 | <code>        query = " ".join([str(snapshot.get("current_stage") or ""), *[str(a.get("action_type") or "") for a in snapshot.get("actions") or []], "应急响应 防护 加固 证据边界"])</code> |
| L0215 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 retrieve_context。 | <code>        result = hybrid_search(conn, data_dir, api_config, int(bases[0]["id"]), query, "professional-report", save_test=False)</code> |
| L0216 | 结束当前函数并把结果返回给调用方，当前位于函数 retrieve_context。 | <code>        return list(result.get("items") or [])[:6]</code> |
| L0217 | 无论成功或异常都执行资源清理，当前位于函数 retrieve_context。 | <code>    finally:</code> |
| L0218 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_context。 | <code>        conn.close()</code> |
| L0219 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0220 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0221 | 定义callbailian函数 &#96;call_bailian&#96;，封装可复用业务逻辑。 | <code>def call_bailian(api_config: Dict[str, Any], model: str, system_prompt: str, snapshot: Dict[str, Any], rag_rows: List[Dict[str, Any]]) -&gt; tuple[str, Dict[str, int]]:</code> |
| L0222 | 计算并保存 &#96;references&#96;（references），供后续逻辑使用，当前位于函数 call_bailian。 | <code>    references = [{"document": x.get("document_name"), "title": x.get("title_path"), "content": str(x.get("content") or "")[:1800], "score": x.get("score")} for x in rag_rows]</code> |
| L0223 | 计算并保存 &#96;user_content&#96;（usercontent），供后续逻辑使用，当前位于函数 call_bailian。 | <code>    user_content = "请严格依据以下不可变事件快照和RAG参考资料生成最终Markdown报告。不得把攻击尝试写成攻击成功；证据不足时必须明确写明。\n\n事件快照：\n" + json.dumps(snapshot, ensure_ascii=False) + "\n\nRAG参考资料：\n" + json.dumps(references, ensure_ascii=False)</code> |
| L0224 | 计算并保存 &#96;max_tokens&#96;（maxtokens），供后续逻辑使用，当前位于函数 call_bailian。 | <code>    max_tokens = max(1024, min(8192, int(api_config.get("professional_report_max_tokens") or 4096)))</code> |
| L0225 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 call_bailian。 | <code>    payload = {</code> |
| L0226 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_bailian。 | <code>        "model": model,</code> |
| L0227 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_bailian。 | <code>        "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_content}],</code> |
| L0228 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_bailian。 | <code>        "temperature": 0.1,</code> |
| L0229 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_bailian。 | <code>        "enable_thinking": False,</code> |
| L0230 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_bailian。 | <code>        "max_tokens": max_tokens,</code> |
| L0231 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_bailian。 | <code>        "stream": False,</code> |
| L0232 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_bailian。 | <code>    }</code> |
| L0233 | 计算并保存 &#96;req&#96;（req），供后续逻辑使用，当前位于函数 call_bailian。 | <code>    req = urllib.request.Request(</code> |
| L0234 | 调用外部 HTTP/大模型 API，并等待远端返回结果，当前位于函数 call_bailian。 | <code>        f"{api_config['base_url']}/chat/completions", data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),</code> |
| L0235 | 计算并保存 &#96;headers&#96;（headers），供后续逻辑使用，当前位于函数 call_bailian。 | <code>        headers={"Authorization": f"Bearer {api_config['api_key']}", "Content-Type": "application/json"}, method="POST",</code> |
| L0236 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_bailian。 | <code>    )</code> |
| L0237 | 计算并保存 &#96;timeout_seconds&#96;（timeoutseconds），供后续逻辑使用，当前位于函数 call_bailian。 | <code>    timeout_seconds = max(30, min(120, int(api_config.get("professional_report_timeout_seconds") or 90)))</code> |
| L0238 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 call_bailian。 | <code>    try:</code> |
| L0239 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 call_bailian。 | <code>        with urllib.request.urlopen(req, timeout=timeout_seconds) as response:</code> |
| L0240 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 call_bailian。 | <code>            data = json.loads(response.read().decode("utf-8"))</code> |
| L0241 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 call_bailian。 | <code>    except urllib.error.HTTPError as exc:</code> |
| L0242 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 call_bailian。 | <code>        raise RuntimeError(f"百炼 HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')[:500]}") from exc</code> |
| L0243 | 计算并保存 &#96;content&#96;（content），供后续逻辑使用，当前位于函数 call_bailian。 | <code>    content = str((((data.get("choices") or [{}])[0].get("message") or {}).get("content") or "")).strip()</code> |
| L0244 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 call_bailian。 | <code>    if len(content) &lt; 500: raise RuntimeError("专业报告内容过短，未通过质量检查")</code> |
| L0245 | 计算并保存 &#96;missing_headings&#96;（missingheadings），供后续逻辑使用，当前位于函数 call_bailian。 | <code>    missing_headings = [heading for heading in REQUIRED_REPORT_HEADINGS if heading not in content]</code> |
| L0246 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 call_bailian。 | <code>    if missing_headings:</code> |
| L0247 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 call_bailian。 | <code>        raise RuntimeError(f"专业报告格式不完整，缺少章节：{'、'.join(missing_headings)}")</code> |
| L0248 | 计算并保存 &#96;usage&#96;（usage），供后续逻辑使用，当前位于函数 call_bailian。 | <code>    usage = data.get("usage") or {}</code> |
| L0249 | 结束当前函数并把结果返回给调用方，当前位于函数 call_bailian。 | <code>    return content, {"input": int(usage.get("prompt_tokens") or 0), "output": int(usage.get("completion_tokens") or 0)}</code> |
| L0250 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0251 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0252 | 定义报告text函数 &#96;_report_text&#96;，封装可复用业务逻辑。 | <code>def _report_text(value: Any, fallback: str = "输入数据未提供", limit: int = 300) -&gt; str:</code> |
| L0253 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 _report_text。 | <code>    text = re.sub(r"\s+", " ", str(value or "")).strip()</code> |
| L0254 | 结束当前函数并把结果返回给调用方，当前位于函数 _report_text。 | <code>    return (text or fallback)[:limit]</code> |
| L0255 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0256 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0257 | 定义构建fallbackmarkdown函数 &#96;build_fallback_markdown&#96;，封装可复用业务逻辑。 | <code>def build_fallback_markdown(snapshot: Dict[str, Any], rag_rows: List[Dict[str, Any]]) -&gt; str:</code> |
| L0258 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>    """Build a complete, evidence-bounded report without a second model request."""</code> |
| L0259 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 build_fallback_markdown。 | <code>    source_ip = _report_text(snapshot.get("source_ip"))</code> |
| L0260 | 计算并保存 &#96;target_asset&#96;（targetasset），供后续逻辑使用，当前位于函数 build_fallback_markdown。 | <code>    target_asset = _report_text(snapshot.get("target_asset"))</code> |
| L0261 | 计算并保存 &#96;risk_level&#96;（risklevel），供后续逻辑使用，当前位于函数 build_fallback_markdown。 | <code>    risk_level = _report_text(snapshot.get("risk_level"), "未评级")</code> |
| L0262 | 计算并保存 &#96;risk_score&#96;（riskscore），供后续逻辑使用，当前位于函数 build_fallback_markdown。 | <code>    risk_score = snapshot.get("risk_score")</code> |
| L0263 | 计算并保存 &#96;risk_score_text&#96;（riskscoretext），供后续逻辑使用，当前位于函数 build_fallback_markdown。 | <code>    risk_score_text = _report_text(risk_score, "输入数据未提供")</code> |
| L0264 | 计算并保存 &#96;current_stage&#96;（currentstage），供后续逻辑使用，当前位于函数 build_fallback_markdown。 | <code>    current_stage = _report_text(snapshot.get("current_stage"), "未归类阶段")</code> |
| L0265 | 计算并保存 &#96;actions&#96;（actions），供后续逻辑使用，当前位于函数 build_fallback_markdown。 | <code>    actions = sorted(</code> |
| L0266 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        list(snapshot.get("actions") or []),</code> |
| L0267 | 计算并保存 &#96;key&#96;（key），供后续逻辑使用，当前位于函数 build_fallback_markdown。 | <code>        key=lambda item: int(item.get("sequence_no") or 0),</code> |
| L0268 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_fallback_markdown。 | <code>    )</code> |
| L0269 | 计算并保存 &#96;action_lines&#96;（actionlines），供后续逻辑使用，当前位于函数 build_fallback_markdown。 | <code>    action_lines = []</code> |
| L0270 | 遍历集合中的数据项并逐项处理，当前位于函数 build_fallback_markdown。 | <code>    for index, action in enumerate(actions, 1):</code> |
| L0271 | 计算并保存 &#96;sequence_no&#96;（sequenceno），供后续逻辑使用，当前位于函数 build_fallback_markdown。 | <code>        sequence_no = int(action.get("sequence_no") or index)</code> |
| L0272 | 计算并保存 &#96;action_type&#96;（actiontype），供后续逻辑使用，当前位于函数 build_fallback_markdown。 | <code>        action_type = _action_label(action.get("action_type"))</code> |
| L0273 | 计算并保存 &#96;stage&#96;（stage），供后续逻辑使用，当前位于函数 build_fallback_markdown。 | <code>        stage = _stage_label(action.get("stage"))</code> |
| L0274 | 计算并保存 &#96;seen_at&#96;（seenat），供后续逻辑使用，当前位于函数 build_fallback_markdown。 | <code>        seen_at = _report_text(action.get("first_seen_at") or action.get("last_seen_at"), "时间未提供")</code> |
| L0275 | 计算并保存 &#96;target&#96;（target），供后续逻辑使用，当前位于函数 build_fallback_markdown。 | <code>        target = _report_text(action.get("target_interface") or action.get("target_port"), "目标细节未提供")</code> |
| L0276 | 计算并保存 &#96;count&#96;（count），供后续逻辑使用，当前位于函数 build_fallback_markdown。 | <code>        count = int(action.get("action_count") or 0)</code> |
| L0277 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_fallback_markdown。 | <code>        action_lines.append(</code> |
| L0278 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>            f"- 动作 {sequence_no}：{action_type}，阶段为{stage}，首次/最近观测时间为 {seen_at}，"</code> |
| L0279 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>            f"目标为 {target}，系统记录 {count} 次。该记录证明相关网络行为被观测到，不单独证明利用成功。"</code> |
| L0280 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_fallback_markdown。 | <code>        )</code> |
| L0281 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_fallback_markdown。 | <code>    if not action_lines:</code> |
| L0282 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_fallback_markdown。 | <code>        action_lines.append("- 输入快照未提供可展开的攻击动作，无法形成更细的阶段判断。")</code> |
| L0283 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0284 | 计算并保存 &#96;rag_note&#96;（ragnote），供后续逻辑使用，当前位于函数 build_fallback_markdown。 | <code>    rag_note = (</code> |
| L0285 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        f"本次检索到 {len(rag_rows)} 条知识库参考资料，仅用于解释调查和加固方向，不作为事件事实。"</code> |
| L0286 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_fallback_markdown。 | <code>        if rag_rows else</code> |
| L0287 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "本次未召回知识库参考资料，报告仅依据事件快照生成。"</code> |
| L0288 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_fallback_markdown。 | <code>    )</code> |
| L0289 | 计算并保存 &#96;action_types&#96;（actiontypes），供后续逻辑使用，当前位于函数 build_fallback_markdown。 | <code>    action_types = "、".join(dict.fromkeys(_action_label(item.get("action_type")) for item in actions)) or "未提供"</code> |
| L0290 | 结束当前函数并把结果返回给调用方，当前位于函数 build_fallback_markdown。 | <code>    return "\n".join([</code> |
| L0291 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "## 一、基本信息",</code> |
| L0292 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "",</code> |
| L0293 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "## 二、报告目的",</code> |
| L0294 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        f"本报告面向安全运营和技术管理人员，对来源 {source_ip} 针对 {target_asset} 的连续网络行为进行证据化说明，明确当前风险、证据边界和可执行处置动作。",</code> |
| L0295 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "",</code> |
| L0296 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "## 三、分析方法",</code> |
| L0297 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "报告保持系统给出的动作顺序、阶段、风险分值和次数不变，按事件快照核对时间线，并将网络侧事实、辅助研判和知识库建议分开表述。",</code> |
| L0298 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "",</code> |
| L0299 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "## 四、攻击态势分析",</code> |
| L0300 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "### 4.1 攻击时间线总览",</code> |
| L0301 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "### 4.2 分阶段解读",</code> |
| L0302 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        *action_lines,</code> |
| L0303 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "### 4.3 态势综合分析",</code> |
| L0304 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        f"当前阶段为{current_stage}，已记录的动作类型包括{action_types}。这些记录能够确认存在连续攻击或探测行为，但现有快照不足以单独确认主机失陷、命令成功执行或数据泄露。",</code> |
| L0305 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "",</code> |
| L0306 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "## 五、证据交叉验证",</code> |
| L0307 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "### 5.1 多源证据总览",</code> |
| L0308 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "### 5.2 关键证据分析",</code> |
| L0309 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "系统关联结果和网络侧事件支持上述攻击行为已经被检测；若缺少主机进程、认证成功、文件落地或数据库审计证据，则相关攻击结果仍需进一步核查。",</code> |
| L0310 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "### 5.3 安全知识参照",</code> |
| L0311 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        rag_note,</code> |
| L0312 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "",</code> |
| L0313 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "## 六、风险判断与行动建议",</code> |
| L0314 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "### 6.1 风险与失陷判断",</code> |
| L0315 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        f"系统风险等级为{risk_level}，风险评分为 {risk_score_text}。该评分是风险评价结果，不是攻击成功概率；当前证据不足以确认攻击已经成功。",</code> |
| L0316 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "### 6.2 优先调查与处置建议",</code> |
| L0317 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        f"- 立即核查 {target_asset} 在报告时间窗内与 {source_ip} 相关的访问、认证、应用和主机日志，以找到成功会话、异常进程、文件变化或数据库操作作为完成标志。",</code> |
| L0318 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        f"- 在不影响业务的前提下限制来源 {source_ip} 的访问，并持续观察同目标、同接口和相邻来源的后续行为；以高风险请求停止且无新增关联动作作为阶段性验收依据。",</code> |
| L0319 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "- 对涉及的接口执行参数校验、最小权限和规则复核；以复测攻击请求被阻断、正常请求不受影响作为验收依据。",</code> |
| L0320 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "### 6.3 检测与长期优化",</code> |
| L0321 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "保留原始请求、响应摘要、规则命中和模型结果的关联标识，补充主机及应用侧遥测，并对同类攻击链定期回放验证检测覆盖。",</code> |
| L0322 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "",</code> |
| L0323 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "## 七、补充说明",</code> |
| L0324 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "### 7.1 风险评分说明",</code> |
| L0325 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "风险分值直接采用系统输入，不在报告中重新计算，也不用于推断攻击成功概率。",</code> |
| L0326 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "### 7.2 数据质量与证据缺口",</code> |
| L0327 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "输入未覆盖的日志、资产信息和攻击结果均保持未知；没有发现相关证据不等于确认相关行为没有发生。",</code> |
| L0328 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        "### 7.3 证据边界",</code> |
| L0329 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fallback_markdown。 | <code>        _report_text(snapshot.get("evidence_boundary"), "网络侧证据证明请求或连接行为发生，不单独证明命令执行、数据泄露或主机失陷。"),</code> |
| L0330 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_fallback_markdown。 | <code>    ])</code> |
| L0331 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0332 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0333 | 定义解析并确定professional报告options函数 &#96;resolve_professional_report_options&#96;，封装可复用业务逻辑。 | <code>def resolve_professional_report_options(config_payload: Dict[str, Any]) -&gt; Dict[str, Any]:</code> |
| L0334 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_professional_report_options。 | <code>    return {</code> |
| L0335 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 resolve_professional_report_options。 | <code>        "model": str(config_payload.get("professional_report_model") or "qwen3.7-flash"),</code> |
| L0336 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 resolve_professional_report_options。 | <code>        "timeout_seconds": max(30, min(120, int(config_payload.get("professional_report_timeout_seconds") or 90))),</code> |
| L0337 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 resolve_professional_report_options。 | <code>        "max_tokens": max(1024, min(8192, int(config_payload.get("professional_report_max_tokens") or 4096))),</code> |
| L0338 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 resolve_professional_report_options。 | <code>    }</code> |
| L0339 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0340 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0341 | 定义generateprofessionalmarkdown函数 &#96;generate_professional_markdown&#96;，封装可复用业务逻辑。 | <code>def generate_professional_markdown(</code> |
| L0342 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 generate_professional_markdown。 | <code>    api: Dict[str, Any],</code> |
| L0343 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 generate_professional_markdown。 | <code>    model: str,</code> |
| L0344 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 generate_professional_markdown。 | <code>    prompt: str,</code> |
| L0345 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 generate_professional_markdown。 | <code>    snapshot: Dict[str, Any],</code> |
| L0346 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 generate_professional_markdown。 | <code>    rag_rows: List[Dict[str, Any]],</code> |
| L0347 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 generate_professional_markdown。 | <code>) -&gt; tuple[str, Dict[str, int], str, Optional[str]]:</code> |
| L0348 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 generate_professional_markdown。 | <code>    try:</code> |
| L0349 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 generate_professional_markdown。 | <code>        markdown, usage = call_bailian(api, model, prompt, snapshot, rag_rows)</code> |
| L0350 | 结束当前函数并把结果返回给调用方，当前位于函数 generate_professional_markdown。 | <code>        return markdown, usage, model, None</code> |
| L0351 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 generate_professional_markdown。 | <code>    except Exception as exc:</code> |
| L0352 | 计算并保存 &#96;error&#96;（error），供后续逻辑使用，当前位于函数 generate_professional_markdown。 | <code>        error = f"{type(exc).__name__}: {exc}"[:500]</code> |
| L0353 | 结束当前函数并把结果返回给调用方，当前位于函数 generate_professional_markdown。 | <code>        return build_fallback_markdown(snapshot, rag_rows), {"input": 0, "output": 0}, f"{model} / local-template", error</code> |
| L0354 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0355 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0356 | 定义fonts函数 &#96;_fonts&#96;，封装可复用业务逻辑。 | <code>def _fonts() -&gt; Dict[str, str]:</code> |
| L0357 | 导入后续逻辑所需的模块、类或函数：&#96;from reportlab.pdfbase import pdfmetrics&#96;。 | <code>    from reportlab.pdfbase import pdfmetrics</code> |
| L0358 | 导入后续逻辑所需的模块、类或函数：&#96;from reportlab.pdfbase.ttfonts import TTFont&#96;。 | <code>    from reportlab.pdfbase.ttfonts import TTFont</code> |
| L0359 | 计算并保存 &#96;regular_candidates&#96;（regularcandidates），供后续逻辑使用，当前位于函数 _fonts。 | <code>    regular_candidates = [Path(r"C:\Windows\Fonts\msyh.ttc"), Path(r"C:\Windows\Fonts\simsun.ttc"), Path(r"C:\Windows\Fonts\simhei.ttf")]</code> |
| L0360 | 计算并保存 &#96;bold_candidates&#96;（boldcandidates），供后续逻辑使用，当前位于函数 _fonts。 | <code>    bold_candidates = [Path(r"C:\Windows\Fonts\msyhbd.ttc"), Path(r"C:\Windows\Fonts\simhei.ttf")]</code> |
| L0361 | 计算并保存 &#96;regular&#96;（regular），供后续逻辑使用，当前位于函数 _fonts。 | <code>    regular = "Helvetica"</code> |
| L0362 | 计算并保存 &#96;bold&#96;（bold），供后续逻辑使用，当前位于函数 _fonts。 | <code>    bold = "Helvetica-Bold"</code> |
| L0363 | 遍历集合中的数据项并逐项处理，当前位于函数 _fonts。 | <code>    for path in regular_candidates:</code> |
| L0364 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _fonts。 | <code>        if path.exists():</code> |
| L0365 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _fonts。 | <code>            pdfmetrics.registerFont(TTFont("ReportCN", str(path), subfontIndex=0))</code> |
| L0366 | 计算并保存 &#96;regular&#96;（regular），供后续逻辑使用，当前位于函数 _fonts。 | <code>            regular = "ReportCN"</code> |
| L0367 | 控制当前循环或占位分支的执行流程，当前位于函数 _fonts。 | <code>            break</code> |
| L0368 | 遍历集合中的数据项并逐项处理，当前位于函数 _fonts。 | <code>    for path in bold_candidates:</code> |
| L0369 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _fonts。 | <code>        if path.exists():</code> |
| L0370 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _fonts。 | <code>            pdfmetrics.registerFont(TTFont("ReportCNBold", str(path), subfontIndex=0))</code> |
| L0371 | 计算并保存 &#96;bold&#96;（bold），供后续逻辑使用，当前位于函数 _fonts。 | <code>            bold = "ReportCNBold"</code> |
| L0372 | 控制当前循环或占位分支的执行流程，当前位于函数 _fonts。 | <code>            break</code> |
| L0373 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _fonts。 | <code>    if regular == "ReportCN":</code> |
| L0374 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _fonts。 | <code>        pdfmetrics.registerFontFamily(</code> |
| L0375 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _fonts。 | <code>            "ReportCN", normal=regular, bold=bold,</code> |
| L0376 | 计算并保存 &#96;italic&#96;（italic），供后续逻辑使用，当前位于函数 _fonts。 | <code>            italic=regular, boldItalic=bold,</code> |
| L0377 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _fonts。 | <code>        )</code> |
| L0378 | 结束当前函数并把结果返回给调用方，当前位于函数 _fonts。 | <code>    return {"regular": regular, "bold": bold}</code> |
| L0379 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0380 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0381 | 定义font函数 &#96;_font&#96;，封装可复用业务逻辑。 | <code>def _font() -&gt; str:</code> |
| L0382 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _font。 | <code>    """Backward-compatible regular font accessor used by older integrations."""</code> |
| L0383 | 结束当前函数并把结果返回给调用方，当前位于函数 _font。 | <code>    return _fonts()["regular"]</code> |
| L0384 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0385 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0386 | 定义actionlabel函数 &#96;_action_label&#96;，封装可复用业务逻辑。 | <code>def _action_label(value: Any) -&gt; str:</code> |
| L0387 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 _action_label。 | <code>    raw = str(value or "未知动作")</code> |
| L0388 | 计算并保存 &#96;labels&#96;（labels），供后续逻辑使用，当前位于函数 _action_label。 | <code>    labels = {</code> |
| L0389 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _action_label。 | <code>        "PORTSCAN": "端口扫描", "DIRSCAN": "目录扫描", "RECON": "信息探测",</code> |
| L0390 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _action_label。 | <code>        "BRUTE_FORCE": "暴力破解", "SSH_BRUTE_FORCE": "SSH 暴力破解",</code> |
| L0391 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _action_label。 | <code>        "SQL_INJECTION": "SQL 注入", "XSS": "XSS 跨站脚本", "COMMAND_INJECTION": "命令注入",</code> |
| L0392 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _action_label。 | <code>        "FILE_UPLOAD": "文件上传", "PATH_TRAVERSAL": "路径遍历", "SSRF": "SSRF",</code> |
| L0393 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _action_label。 | <code>        "XXE": "XXE", "DESERIALIZATION": "反序列化", "RCE": "远程代码执行",</code> |
| L0394 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _action_label。 | <code>    }</code> |
| L0395 | 结束当前函数并把结果返回给调用方，当前位于函数 _action_label。 | <code>    return labels.get(raw.upper(), raw.replace("_", " "))</code> |
| L0396 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0397 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0398 | 定义stagelabel函数 &#96;_stage_label&#96;，封装可复用业务逻辑。 | <code>def _stage_label(value: Any) -&gt; str:</code> |
| L0399 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 _stage_label。 | <code>    raw = str(value or "未归类阶段")</code> |
| L0400 | 计算并保存 &#96;labels&#96;（labels），供后续逻辑使用，当前位于函数 _stage_label。 | <code>    labels = {</code> |
| L0401 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _stage_label。 | <code>        "RECONNAISSANCE": "侦察探测", "RECON": "侦察探测", "INITIAL_ACCESS": "初始访问",</code> |
| L0402 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _stage_label。 | <code>        "CREDENTIAL_ACCESS": "凭据攻击", "EXPLOITATION": "漏洞利用", "EXECUTION": "执行控制",</code> |
| L0403 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _stage_label。 | <code>        "PERSISTENCE": "持久化", "LATERAL_MOVEMENT": "横向移动", "IMPACT": "影响处置",</code> |
| L0404 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _stage_label。 | <code>    }</code> |
| L0405 | 结束当前函数并把结果返回给调用方，当前位于函数 _stage_label。 | <code>    return labels.get(raw.upper(), raw.replace("_", " "))</code> |
| L0406 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0407 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0408 | 定义plainmarkdown函数 &#96;_plain_markdown&#96;，封装可复用业务逻辑。 | <code>def _plain_markdown(text: Any) -&gt; str:</code> |
| L0409 | 计算并保存 &#96;value&#96;（value），供后续逻辑使用，当前位于函数 _plain_markdown。 | <code>    value = escape(_sanitize_pdf_text(text))</code> |
| L0410 | 计算并保存 &#96;value&#96;（value），供后续逻辑使用，当前位于函数 _plain_markdown。 | <code>    value = re.sub(r"\*\*(.+?)\*\*", r"&lt;b&gt;\1&lt;/b&gt;", value)</code> |
| L0411 | 计算并保存 &#96;value&#96;（value），供后续逻辑使用，当前位于函数 _plain_markdown。 | <code>    value = re.sub(r"&#96;(.+?)&#96;", r"&lt;font face='Courier'&gt;\1&lt;/font&gt;", value)</code> |
| L0412 | 结束当前函数并把结果返回给调用方，当前位于函数 _plain_markdown。 | <code>    return value</code> |
| L0413 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0414 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0415 | 定义sanitizepdftext函数 &#96;_sanitize_pdf_text&#96;，封装可复用业务逻辑。 | <code>def _sanitize_pdf_text(value: Any) -&gt; str:</code> |
| L0416 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _sanitize_pdf_text。 | <code>    """Normalize model-authored decorations that CJK PDF fonts cannot render."""</code> |
| L0417 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 _sanitize_pdf_text。 | <code>    text = str(value if value is not None else "-")</code> |
| L0418 | 计算并保存 &#96;circled&#96;（circled），供后续逻辑使用，当前位于函数 _sanitize_pdf_text。 | <code>    circled = "①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳"</code> |
| L0419 | 遍历集合中的数据项并逐项处理，当前位于函数 _sanitize_pdf_text。 | <code>    for index, symbol in enumerate(circled, 1):</code> |
| L0420 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 _sanitize_pdf_text。 | <code>        text = text.replace(symbol, f"{index}.")</code> |
| L0421 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 _sanitize_pdf_text。 | <code>    text = re.sub(r"([0-9])\ufe0f?\u20e3", r"\1.", text)</code> |
| L0422 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 _sanitize_pdf_text。 | <code>    text = re.sub(r"[\U0001F000-\U0001FAFF]", "", text)</code> |
| L0423 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 _sanitize_pdf_text。 | <code>    text = re.sub(r"[\u2600-\u27BF\u2B00-\u2BFF]", "", text)</code> |
| L0424 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 _sanitize_pdf_text。 | <code>    text = text.replace("\ufe0f", "").replace("\u200d", "")</code> |
| L0425 | 结束当前函数并把结果返回给调用方，当前位于函数 _sanitize_pdf_text。 | <code>    return re.sub(r"[ \t]{2,}", " ", text).strip() or "-"</code> |
| L0426 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0427 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0428 | 定义列出itemtext函数 &#96;_list_item_text&#96;，封装可复用业务逻辑。 | <code>def _list_item_text(value: Any) -&gt; str:</code> |
| L0429 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 _list_item_text。 | <code>    text = _sanitize_pdf_text(value)</code> |
| L0430 | 结束当前函数并把结果返回给调用方，当前位于函数 _list_item_text。 | <code>    return re.sub(r"^(?:\d+[.)、]\s*)+", "", text).strip() or "-"</code> |
| L0431 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0432 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0433 | 定义timetext函数 &#96;_time_text&#96;，封装可复用业务逻辑。 | <code>def _time_text(value: Any) -&gt; str:</code> |
| L0434 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _time_text。 | <code>    if value in (None, ""): return "-"</code> |
| L0435 | 结束当前函数并把结果返回给调用方，当前位于函数 _time_text。 | <code>    return str(value).replace("T", " ")</code> |
| L0436 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0437 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0438 | 定义报告titleline函数 &#96;_report_title_line&#96;，封装可复用业务逻辑。 | <code>def _report_title_line(text: str) -&gt; bool:</code> |
| L0439 | 计算并保存 &#96;normalized&#96;（normalized），供后续逻辑使用，当前位于函数 _report_title_line。 | <code>    normalized = re.sub(r"[\s#*_&#96;]+", "", text)</code> |
| L0440 | 结束当前函数并把结果返回给调用方，当前位于函数 _report_title_line。 | <code>    return normalized in {"网络攻击态势感知分析报告", "专业态势感知分析报告", "专业态势感知报告"}</code> |
| L0441 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0442 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0443 | 定义渲染pdf函数 &#96;render_pdf&#96;，封装可复用业务逻辑。 | <code>def render_pdf(</code> |
| L0444 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>    output: Path,</code> |
| L0445 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>    snapshot: Dict[str, Any],</code> |
| L0446 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>    markdown: str,</code> |
| L0447 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>    rag_rows: List[Dict[str, Any]],</code> |
| L0448 | 计算并保存 &#96;report_meta&#96;（报告meta），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    report_meta: Optional[Dict[str, Any]] = None,</code> |
| L0449 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 render_pdf。 | <code>) -&gt; str:</code> |
| L0450 | 导入后续逻辑所需的模块、类或函数：&#96;from reportlab.lib import colors&#96;。 | <code>    from reportlab.lib import colors</code> |
| L0451 | 导入后续逻辑所需的模块、类或函数：&#96;from reportlab.lib.enums import TA_CENTER&#96;。 | <code>    from reportlab.lib.enums import TA_CENTER</code> |
| L0452 | 导入后续逻辑所需的模块、类或函数：&#96;from reportlab.lib.pagesizes import A4&#96;。 | <code>    from reportlab.lib.pagesizes import A4</code> |
| L0453 | 导入后续逻辑所需的模块、类或函数：&#96;from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet&#96;。 | <code>    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet</code> |
| L0454 | 导入后续逻辑所需的模块、类或函数：&#96;from reportlab.lib.units import mm&#96;。 | <code>    from reportlab.lib.units import mm</code> |
| L0455 | 导入后续逻辑所需的模块、类或函数：&#96;from reportlab.platypus import CondPageBreak, Flowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle&#96;。 | <code>    from reportlab.platypus import CondPageBreak, Flowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle</code> |
| L0456 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0457 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>    output.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0458 | 计算并保存 &#96;fonts&#96;（fonts），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    fonts = _fonts(); font = fonts["regular"]; bold_font = fonts["bold"]</code> |
| L0459 | 计算并保存 &#96;styles&#96;（styles），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    styles = getSampleStyleSheet()</code> |
| L0460 | 计算并保存 &#96;ink&#96;（ink），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    ink = colors.HexColor("#20252B"); muted = colors.HexColor("#7B858F")</code> |
| L0461 | 计算并保存 &#96;blue&#96;（blue），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    blue = colors.HexColor("#2288F5"); pale = colors.HexColor("#F5F8FC")</code> |
| L0462 | 计算并保存 &#96;line_color&#96;（linecolor），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    line_color = colors.HexColor("#E2E8F0")</code> |
| L0463 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    body = ParagraphStyle("cn", parent=styles["BodyText"], fontName=font, fontSize=9.2, leading=15.8, textColor=ink, spaceAfter=4.5, wordWrap="CJK")</code> |
| L0464 | 计算并保存 &#96;small&#96;（small），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    small = ParagraphStyle("small", parent=body, fontSize=7.7, leading=11.5, textColor=muted)</code> |
| L0465 | 计算并保存 &#96;h1&#96;（h1），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    h1 = ParagraphStyle("h1cn", parent=body, fontName=bold_font, fontSize=13.2, leading=19, textColor=ink, spaceBefore=11, spaceAfter=8, keepWithNext=True)</code> |
| L0466 | 计算并保存 &#96;h2&#96;（h2），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    h2 = ParagraphStyle("h2cn", parent=body, fontName=bold_font, fontSize=10.8, leading=16, textColor=ink, spaceBefore=8, spaceAfter=5, keepWithNext=False)</code> |
| L0467 | 计算并保存 &#96;h3&#96;（h3），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    h3 = ParagraphStyle("h3cn", parent=body, fontName=bold_font, fontSize=9.5, leading=14.5, textColor=ink, spaceBefore=6, spaceAfter=4, keepWithNext=False)</code> |
| L0468 | 计算并保存 &#96;title&#96;（title），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    title = ParagraphStyle("titlecn", parent=body, fontName=bold_font, alignment=TA_CENTER, fontSize=25, leading=34, textColor=colors.HexColor("#222222"))</code> |
| L0469 | 计算并保存 &#96;cover_brand&#96;（coverbrand），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    cover_brand = ParagraphStyle("coverbrand", parent=title, fontSize=18, leading=24)</code> |
| L0470 | 计算并保存 &#96;cover_meta&#96;（covermeta），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    cover_meta = ParagraphStyle("covermeta", parent=body, alignment=TA_CENTER, fontSize=9.2, leading=14, textColor=colors.HexColor("#31363B"))</code> |
| L0471 | 计算并保存 &#96;bullet&#96;（bullet），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    bullet = ParagraphStyle("bullet", parent=body, leftIndent=8, firstLineIndent=-7, bulletIndent=0, spaceAfter=4)</code> |
| L0472 | 计算并保存 &#96;table_head&#96;（tablehead），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    table_head = ParagraphStyle("tablehead", parent=body, fontName=bold_font, fontSize=8.4, leading=12)</code> |
| L0473 | 计算并保存 &#96;table_cell&#96;（tablecell），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    table_cell = ParagraphStyle("tablecell", parent=body, fontSize=8.2, leading=12.5)</code> |
| L0474 | 计算并保存 &#96;caption&#96;（caption），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    caption = ParagraphStyle(</code> |
| L0475 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        "caption", parent=small, fontSize=8.2, leading=12,</code> |
| L0476 | 计算并保存 &#96;alignment&#96;（alignment），供后续逻辑使用，当前位于函数 render_pdf。 | <code>        alignment=TA_CENTER, textColor=colors.HexColor("#5E6A75"),</code> |
| L0477 | 计算并保存 &#96;spaceBefore&#96;（spaceBefore），供后续逻辑使用，当前位于函数 render_pdf。 | <code>        spaceBefore=3, spaceAfter=6,</code> |
| L0478 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 render_pdf。 | <code>    )</code> |
| L0479 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0480 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>    page_width, page_height = A4</code> |
| L0481 | 计算并保存 &#96;left&#96;（left），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    left = 18*mm; right = page_width - 18*mm</code> |
| L0482 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0483 | 定义drawcover函数 &#96;draw_cover&#96;，封装可复用业务逻辑。 | <code>    def draw_cover(canvas: Any) -&gt; None:</code> |
| L0484 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 draw_cover。 | <code>        canvas.saveState()</code> |
| L0485 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 draw_cover。 | <code>        canvas.setFillColor(colors.white); canvas.rect(0, 0, page_width, page_height, fill=1, stroke=0)</code> |
| L0486 | 源码原注释：Pale orbit system copied from the reference's visual language. | <code>        # Pale orbit system copied from the reference's visual language.</code> |
| L0487 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 draw_cover。 | <code>        canvas.translate(page_width * .48, page_height * .33); canvas.rotate(13)</code> |
| L0488 | 计算并保存 &#96;orbit_colors&#96;（orbitcolors），供后续逻辑使用，当前位于函数 draw_cover。 | <code>        orbit_colors = [colors.HexColor("#D6F5F8"), colors.HexColor("#CDEEF7"), colors.HexColor("#DDF7FA")]</code> |
| L0489 | 遍历集合中的数据项并逐项处理，当前位于函数 draw_cover。 | <code>        for idx, (w, h) in enumerate([(235*mm, 73*mm), (180*mm, 54*mm), (126*mm, 38*mm), (74*mm, 22*mm)]):</code> |
| L0490 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 draw_cover。 | <code>            canvas.setStrokeColor(orbit_colors[idx % len(orbit_colors)]); canvas.setLineWidth(0.7 if idx else 1.5)</code> |
| L0491 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 draw_cover。 | <code>            if idx in (1, 3): canvas.setDash(1.2, 3.2)</code> |
| L0492 | 处理前述条件均未命中的情况，当前位于函数 draw_cover。 | <code>            else: canvas.setDash()</code> |
| L0493 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 draw_cover。 | <code>            canvas.ellipse(-w/2, -h/2, w/2, h/2, stroke=1, fill=0)</code> |
| L0494 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 draw_cover。 | <code>        canvas.setDash()</code> |
| L0495 | 计算并保存 &#96;nodes&#96;（nodes），供后续逻辑使用，当前位于函数 draw_cover。 | <code>        nodes = [(-88, -3, 10), (-24, 30, 7), (39, 58, 5), (101, -28, 7), (2, -60, 9), (145, 35, 5)]</code> |
| L0496 | 遍历集合中的数据项并逐项处理，当前位于函数 draw_cover。 | <code>        for x, y, radius in nodes:</code> |
| L0497 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 draw_cover。 | <code>            canvas.setFillColor(colors.HexColor("#3F9AF5")); canvas.circle(x, y, radius, fill=1, stroke=0)</code> |
| L0498 | 遍历集合中的数据项并逐项处理，当前位于函数 draw_cover。 | <code>        for x, y, color in [(-61, 52, "#FFB500"), (41, -37, "#FF7078"), (124, -16, "#88DA40"), (87, -69, "#835AF2")]:</code> |
| L0499 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 draw_cover。 | <code>            canvas.setFillColor(colors.HexColor(color)); canvas.rect(x-2, y-2, 4, 4, fill=1, stroke=0)</code> |
| L0500 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 draw_cover。 | <code>        canvas.restoreState()</code> |
| L0501 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0502 | 定义decorate函数 &#96;decorate&#96;，封装可复用业务逻辑。 | <code>    def decorate(canvas: Any, doc_obj: Any) -&gt; None:</code> |
| L0503 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decorate。 | <code>        if doc_obj.page == 1:</code> |
| L0504 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decorate。 | <code>            draw_cover(canvas)</code> |
| L0505 | 结束当前函数并把结果返回给调用方，当前位于函数 decorate。 | <code>            return</code> |
| L0506 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decorate。 | <code>        canvas.saveState()</code> |
| L0507 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decorate。 | <code>        canvas.setStrokeColor(line_color); canvas.setLineWidth(.35)</code> |
| L0508 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decorate。 | <code>        canvas.line(left, page_height-17*mm, right, page_height-17*mm)</code> |
| L0509 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decorate。 | <code>        canvas.line(left, 15*mm, right, 15*mm)</code> |
| L0510 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decorate。 | <code>        canvas.setFont(font, 6.7); canvas.setFillColor(colors.HexColor("#3B4147"))</code> |
| L0511 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decorate。 | <code>        canvas.drawString(left, page_height-12.2*mm, "靖渊智御：AI 驱动的外部 Web 威胁态势感知平台")</code> |
| L0512 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decorate。 | <code>        canvas.drawRightString(right, page_height-12.2*mm, "Situation Report")</code> |
| L0513 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decorate。 | <code>        canvas.setFillColor(colors.HexColor("#8A929A")); canvas.setFont(font, 6.5)</code> |
| L0514 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decorate。 | <code>        canvas.drawString(left, 9.3*mm, "注：本报告由 AI 辅助生成，仅供安全研判与处置参考。")</code> |
| L0515 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decorate。 | <code>        canvas.setFillColor(ink); canvas.drawRightString(right, 9.3*mm, str(doc_obj.page - 1))</code> |
| L0516 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decorate。 | <code>        canvas.restoreState()</code> |
| L0517 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0518 | 定义类 &#96;AttackChain&#96;，集中保存相关状态与操作。 | <code>    class AttackChain(Flowable):</code> |
| L0519 | 定义init函数 &#96;__init__&#96;，封装可复用业务逻辑。 | <code>        def __init__(self, actions: List[Dict[str, Any]], width: float):</code> |
| L0520 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            super().__init__(); self.actions = actions[:8]; self.width = width; self.height = 24*mm</code> |
| L0521 | 定义wrap函数 &#96;wrap&#96;，封装可复用业务逻辑。 | <code>        def wrap(self, availWidth: float, availHeight: float): return min(self.width, availWidth), self.height</code> |
| L0522 | 定义draw函数 &#96;draw&#96;，封装可复用业务逻辑。 | <code>        def draw(self):</code> |
| L0523 | 计算并保存 &#96;c&#96;（c），供后续逻辑使用，当前位于函数 draw。 | <code>            c = self.canv; actions = self.actions or [{"action_type": "暂无动作", "stage": "待研判"}]</code> |
| L0524 | 计算并保存 &#96;n&#96;（n），供后续逻辑使用，当前位于函数 draw。 | <code>            n = len(actions); gap = 4*mm; node_w = (self.width-gap*(n-1))/n; y = 6*mm</code> |
| L0525 | 遍历集合中的数据项并逐项处理，当前位于函数 draw。 | <code>            for i, action in enumerate(actions):</code> |
| L0526 | 计算并保存 &#96;x&#96;（x），供后续逻辑使用，当前位于函数 draw。 | <code>                x = i*(node_w+gap)</code> |
| L0527 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 draw。 | <code>                if i &lt; n-1:</code> |
| L0528 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 draw。 | <code>                    c.setStrokeColor(colors.HexColor("#B8DDF8")); c.setLineWidth(1.2)</code> |
| L0529 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 draw。 | <code>                    c.line(x+node_w, y+6*mm, x+node_w+gap, y+6*mm)</code> |
| L0530 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 draw。 | <code>                    c.setFillColor(colors.HexColor("#B8DDF8")); c.wedge(x+node_w+gap-2.2*mm, y+4.8*mm, x+node_w+gap+.2*mm, y+7.2*mm, 270, 180, fill=1, stroke=0)</code> |
| L0531 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 draw。 | <code>                c.setFillColor(colors.HexColor("#F4F8FC")); c.setStrokeColor(colors.HexColor("#D7E8F5")); c.roundRect(x, y, node_w, 12*mm, 2.2*mm, fill=1, stroke=1)</code> |
| L0532 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 draw。 | <code>                c.setFont(bold_font, 7.2); c.setFillColor(ink)</code> |
| L0533 | 计算并保存 &#96;label&#96;（label），供后续逻辑使用，当前位于函数 draw。 | <code>                label = _action_label(action.get("action_type"))[:9]</code> |
| L0534 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 draw。 | <code>                c.drawCentredString(x+node_w/2, y+6.8*mm, label)</code> |
| L0535 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 draw。 | <code>                c.setFont(font, 5.8); c.setFillColor(muted)</code> |
| L0536 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 draw。 | <code>                c.drawCentredString(x+node_w/2, y+3.3*mm, _stage_label(action.get("stage"))[:10])</code> |
| L0537 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 draw。 | <code>                c.setFillColor(blue); c.circle(x+node_w/2, y+12*mm, 1.5*mm, fill=1, stroke=0)</code> |
| L0538 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0539 | 计算并保存 &#96;doc&#96;（doc），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    doc = SimpleDocTemplate(</code> |
| L0540 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        str(output), pagesize=A4, rightMargin=18*mm, leftMargin=18*mm,</code> |
| L0541 | 计算并保存 &#96;topMargin&#96;（topMargin），供后续逻辑使用，当前位于函数 render_pdf。 | <code>        topMargin=22*mm, bottomMargin=19*mm, title="专业态势感知报告",</code> |
| L0542 | 计算并保存 &#96;author&#96;（author），供后续逻辑使用，当前位于函数 render_pdf。 | <code>        author="靖渊智御：AI 驱动的外部 Web 威胁态势感知平台",</code> |
| L0543 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 render_pdf。 | <code>    )</code> |
| L0544 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0545 | 定义p函数 &#96;p&#96;，封装可复用业务逻辑。 | <code>    def p(value: Any, style: ParagraphStyle = body) -&gt; Paragraph:</code> |
| L0546 | 结束当前函数并把结果返回给调用方，当前位于函数 p。 | <code>        return Paragraph(_plain_markdown(value), style)</code> |
| L0547 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0548 | 定义maketable函数 &#96;make_table&#96;，封装可复用业务逻辑。 | <code>    def make_table(rows: List[List[Any]], widths: Optional[List[float]] = None, header: bool = True, font_size: float = 8.1) -&gt; Table:</code> |
| L0549 | 计算并保存 &#96;converted&#96;（converted），供后续逻辑使用，当前位于函数 make_table。 | <code>        converted = []</code> |
| L0550 | 遍历集合中的数据项并逐项处理，当前位于函数 make_table。 | <code>        for ri, row in enumerate(rows):</code> |
| L0551 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 make_table。 | <code>            converted.append([p(cell, table_head if header and ri == 0 else table_cell) for cell in row])</code> |
| L0552 | 计算并保存 &#96;table&#96;（table），供后续逻辑使用，当前位于函数 make_table。 | <code>        table = Table(converted, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")</code> |
| L0553 | 计算并保存 &#96;commands&#96;（commands），供后续逻辑使用，当前位于函数 make_table。 | <code>        commands = [</code> |
| L0554 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_table。 | <code>            ("FONTNAME", (0,0), (-1,-1), font), ("FONTSIZE", (0,0), (-1,-1), font_size),</code> |
| L0555 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_table。 | <code>            ("VALIGN", (0,0), (-1,-1), "MIDDLE"), ("LEFTPADDING", (0,0), (-1,-1), 8),</code> |
| L0556 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_table。 | <code>            ("RIGHTPADDING", (0,0), (-1,-1), 8), ("TOPPADDING", (0,0), (-1,-1), 6.5),</code> |
| L0557 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_table。 | <code>            ("BOTTOMPADDING", (0,0), (-1,-1), 6.5), ("GRID", (0,0), (-1,-1), .35, line_color),</code> |
| L0558 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 make_table。 | <code>        ]</code> |
| L0559 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 make_table。 | <code>        if header: commands += [("BACKGROUND", (0,0), (-1,0), colors.HexColor("#F1F5FB")), ("FONTNAME", (0,0), (-1,0), bold_font)]</code> |
| L0560 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_table。 | <code>        table.setStyle(TableStyle(commands)); return table</code> |
| L0561 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0562 | 定义table封禁函数 &#96;table_block&#96;，封装可复用业务逻辑。 | <code>    def table_block(label: str, table: Table, gap_after: float = 5*mm) -&gt; List[Any]:</code> |
| L0563 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 table_block。 | <code>        """Render a centered table caption above an editable data table."""</code> |
| L0564 | 源码原注释：Reserve enough room for the caption, header and at least two rows. | <code>        # Reserve enough room for the caption, header and at least two rows.</code> |
| L0565 | 源码原注释：Unlike keepWithNext, this still lets a long table split across pages. | <code>        # Unlike keepWithNext, this still lets a long table split across pages.</code> |
| L0566 | 结束当前函数并把结果返回给调用方，当前位于函数 table_block。 | <code>        return [CondPageBreak(35*mm), p(label, caption), table, Spacer(1, gap_after)]</code> |
| L0567 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0568 | 定义figure封禁函数 &#96;figure_block&#96;，封装可复用业务逻辑。 | <code>    def figure_block(label: str, figure: Flowable, gap_after: float = 5*mm) -&gt; List[Any]:</code> |
| L0569 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 figure_block。 | <code>        """Keep a compact figure and its centered caption on the same page."""</code> |
| L0570 | 结束当前函数并把结果返回给调用方，当前位于函数 figure_block。 | <code>        return [KeepTogether([figure, p(label, caption)]), Spacer(1, gap_after)]</code> |
| L0571 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0572 | 定义card函数 &#96;card&#96;，封装可复用业务逻辑。 | <code>    def card(items: List[Any], tint: Any = pale) -&gt; Table:</code> |
| L0573 | 源码原注释：One item per row allows long cards to split across pages instead of | <code>        # One item per row allows long cards to split across pages instead of</code> |
| L0574 | 源码原注释：pushing the whole card forward and leaving a mostly empty page. | <code>        # pushing the whole card forward and leaving a mostly empty page.</code> |
| L0575 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 card。 | <code>        rows = [[item] for item in items] or [[p("-", body)]]</code> |
| L0576 | 计算并保存 &#96;t&#96;（t），供后续逻辑使用，当前位于函数 card。 | <code>        t = Table(rows, colWidths=[doc.width], hAlign="LEFT", splitByRow=1)</code> |
| L0577 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 card。 | <code>        t.setStyle(TableStyle([</code> |
| L0578 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 card。 | <code>            ("BACKGROUND", (0,0), (-1,-1), tint), ("BOX", (0,0), (-1,-1), .25, colors.HexColor("#EDF2F7")),</code> |
| L0579 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 card。 | <code>            ("LEFTPADDING", (0,0), (-1,-1), 12), ("RIGHTPADDING", (0,0), (-1,-1), 12),</code> |
| L0580 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 card。 | <code>            ("TOPPADDING", (0,0), (-1,0), 10), ("BOTTOMPADDING", (0,-1), (-1,-1), 8),</code> |
| L0581 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 card。 | <code>            ("TOPPADDING", (0,1), (-1,-1), 3), ("BOTTOMPADDING", (0,0), (-1,-2), 3),</code> |
| L0582 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 card。 | <code>        ])); return t</code> |
| L0583 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0584 | 计算并保存 &#96;generated_at&#96;（generatedat），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")</code> |
| L0585 | 计算并保存 &#96;story&#96;（story），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    story: List[Any] = [</code> |
| L0586 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        Spacer(1, 44*mm), p("[靖渊智御]", cover_brand), Spacer(1, 3*mm),</code> |
| L0587 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        p("专业态势感知分析报告", title), Spacer(1, 12*mm),</code> |
| L0588 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        p(f"生成时间：{generated_at}", cover_meta), Spacer(1, 114*mm),</code> |
| L0589 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        p("来自靖渊智御：AI 驱动的外部 Web 威胁态势感知平台", ParagraphStyle("coverbottom", parent=cover_meta, fontSize=8.4, textColor=muted)),</code> |
| L0590 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        p("内容由 AI 基于真实传感器证据生成，请结合原始日志审慎使用", ParagraphStyle("coverbottom2", parent=cover_meta, fontSize=8.4, textColor=muted)),</code> |
| L0591 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        PageBreak(),</code> |
| L0592 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 render_pdf。 | <code>    ]</code> |
| L0593 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0594 | 计算并保存 &#96;info&#96;（info），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    info = [</code> |
| L0595 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        ["基本信息", "内容说明"],</code> |
| L0596 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        ["态势编号", snapshot.get("report_generated_for") or "-"],</code> |
| L0597 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        ["来源 IP", snapshot.get("source_ip") or "-"],</code> |
| L0598 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        ["目标资产", snapshot.get("target_asset") or "本机受监测服务"],</code> |
| L0599 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        ["风险等级", str(snapshot.get("risk_level") or "-").upper()],</code> |
| L0600 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        ["综合风险", f"{float(snapshot.get('risk_score') or 0):.1%}"],</code> |
| L0601 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        ["观测区间", f"{_time_text(snapshot.get('started_at'))} 至 {_time_text(snapshot.get('last_action_at'))}"],</code> |
| L0602 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        ["行为规模", f"{int(snapshot.get('distinct_action_types') or 0)} 类动作，共 {int(snapshot.get('total_action_count') or 0)} 次"],</code> |
| L0603 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 render_pdf。 | <code>    ]</code> |
| L0604 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>    story += [p("一、基本信息", h1), *table_block("表1-1 基本信息", make_table(info, [55*mm, 119*mm]), 6*mm)]</code> |
| L0605 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0606 | 计算并保存 &#96;actions&#96;（actions），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    actions = list(snapshot.get("actions") or [])</code> |
| L0607 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0608 | 定义timelinetable函数 &#96;timeline_table&#96;，封装可复用业务逻辑。 | <code>    def timeline_table(action_rows: Optional[List[Dict[str, Any]]] = None) -&gt; Table:</code> |
| L0609 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 timeline_table。 | <code>        rows: List[List[Any]] = [["序号", "时间", "阶段", "动作", "端口/接口", "次数", "置信度"]]</code> |
| L0610 | 遍历集合中的数据项并逐项处理，当前位于函数 timeline_table。 | <code>        for i, action in enumerate(action_rows if action_rows is not None else actions[:30], 1):</code> |
| L0611 | 计算并保存 &#96;confidence&#96;（confidence），供后续逻辑使用，当前位于函数 timeline_table。 | <code>            confidence = action.get("confidence")</code> |
| L0612 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 timeline_table。 | <code>            rows.append([</code> |
| L0613 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 timeline_table。 | <code>                action.get("sequence_no") or i, _time_text(action.get("occurred_at")),</code> |
| L0614 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 timeline_table。 | <code>                _stage_label(action.get("stage")), _action_label(action.get("action_type")),</code> |
| L0615 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 timeline_table。 | <code>                action.get("target_port") or action.get("target_interface") or "-",</code> |
| L0616 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 timeline_table。 | <code>                action.get("action_count") or 1,</code> |
| L0617 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 timeline_table。 | <code>                f"{float(confidence):.1%}" if confidence not in (None, "") else "-",</code> |
| L0618 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 timeline_table。 | <code>            ])</code> |
| L0619 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 timeline_table。 | <code>        if len(rows) == 1: rows.append(["-", "-", "暂无", "暂无动作", "-", "0", "-"])</code> |
| L0620 | 结束当前函数并把结果返回给调用方，当前位于函数 timeline_table。 | <code>        return make_table(rows, [10*mm, 31*mm, 25*mm, 31*mm, 27*mm, 16*mm, 22*mm])</code> |
| L0621 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0622 | 定义evidencetable函数 &#96;evidence_table&#96;，封装可复用业务逻辑。 | <code>    def evidence_table() -&gt; Table:</code> |
| L0623 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 evidence_table。 | <code>        rows: List[List[Any]] = [["证据编号", "检测来源", "对应动作", "证据状态", "说明"]]</code> |
| L0624 | 计算并保存 &#96;ev_no&#96;（evno），供后续逻辑使用，当前位于函数 evidence_table。 | <code>        ev_no = 1</code> |
| L0625 | 遍历集合中的数据项并逐项处理，当前位于函数 evidence_table。 | <code>        for action in actions[:24]:</code> |
| L0626 | 计算并保存 &#96;refs&#96;（refs），供后续逻辑使用，当前位于函数 evidence_table。 | <code>            refs = action.get("evidence_refs") or []</code> |
| L0627 | 计算并保存 &#96;source&#96;（来源），供后续逻辑使用，当前位于函数 evidence_table。 | <code>            source = action.get("sensor_type") or "融合检测"</code> |
| L0628 | 计算并保存 &#96;confidence&#96;（confidence），供后续逻辑使用，当前位于函数 evidence_table。 | <code>            confidence = action.get("confidence")</code> |
| L0629 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 evidence_table。 | <code>            rows.append([</code> |
| L0630 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 evidence_table。 | <code>                f"EV-{ev_no:02d}", source, _action_label(action.get("action_type")),</code> |
| L0631 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 evidence_table。 | <code>                "已采集" if refs else "来源单一",</code> |
| L0632 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 evidence_table。 | <code>                f"动作 {int(action.get('action_count') or 1)} 次" + (f"，置信度 {float(confidence):.1%}" if confidence not in (None, "") else ""),</code> |
| L0633 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 evidence_table。 | <code>            ]); ev_no += 1</code> |
| L0634 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 evidence_table。 | <code>        if len(rows) == 1: rows.append(["EV-00", "-", "暂无", "待补充", "未提供可展示证据"])</code> |
| L0635 | 源码原注释：Exactly match the 174 mm body width used by the following evidence table. | <code>        # Exactly match the 174 mm body width used by the following evidence table.</code> |
| L0636 | 结束当前函数并把结果返回给调用方，当前位于函数 evidence_table。 | <code>        return make_table(rows, [20*mm, 30*mm, 34*mm, 25*mm, 65*mm])</code> |
| L0637 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0638 | 定义appendixactions函数 &#96;appendix_actions&#96;，封装可复用业务逻辑。 | <code>    def appendix_actions() -&gt; List[Any]:</code> |
| L0639 | 结束当前函数并把结果返回给调用方，当前位于函数 appendix_actions。 | <code>        return [timeline_table(actions)] if actions else [card([p("当前快照中未包含可列示的动作记录。", body)])]</code> |
| L0640 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0641 | 定义appendixevidence函数 &#96;appendix_evidence&#96;，封装可复用业务逻辑。 | <code>    def appendix_evidence() -&gt; List[Any]:</code> |
| L0642 | 计算并保存 &#96;entries&#96;（entries），供后续逻辑使用，当前位于函数 appendix_evidence。 | <code>        entries: List[Any] = []</code> |
| L0643 | 计算并保存 &#96;idx&#96;（idx），供后续逻辑使用，当前位于函数 appendix_evidence。 | <code>        idx = 1</code> |
| L0644 | 遍历集合中的数据项并逐项处理，当前位于函数 appendix_evidence。 | <code>        for action in actions:</code> |
| L0645 | 计算并保存 &#96;refs&#96;（refs），供后续逻辑使用，当前位于函数 appendix_evidence。 | <code>            refs = action.get("evidence_refs") or []</code> |
| L0646 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 appendix_evidence。 | <code>            if not refs:</code> |
| L0647 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 appendix_evidence。 | <code>                entries.append(p(f"{idx}. [EV-{idx:02d}] {_action_label(action.get('action_type'))}：由 {action.get('sensor_type') or '融合检测'} 记录，当前未附带独立证据引用。", bullet)); idx += 1</code> |
| L0648 | 控制当前循环或占位分支的执行流程，当前位于函数 appendix_evidence。 | <code>                continue</code> |
| L0649 | 遍历集合中的数据项并逐项处理，当前位于函数 appendix_evidence。 | <code>            for ref in refs[:4]:</code> |
| L0650 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 appendix_evidence。 | <code>                entries.append(p(f"{idx}. [EV-{idx:02d}] {_action_label(action.get('action_type'))}：{ref}", bullet)); idx += 1</code> |
| L0651 | 结束当前函数并把结果返回给调用方，当前位于函数 appendix_evidence。 | <code>        return [card(entries or [p("当前快照中没有可索引的证据引用。", body)])]</code> |
| L0652 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0653 | 定义appendixrag函数 &#96;appendix_rag&#96;，封装可复用业务逻辑。 | <code>    def appendix_rag() -&gt; List[Any]:</code> |
| L0654 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 appendix_rag。 | <code>        if not rag_rows: return [card([p("本次报告未启用或未召回 RAG 安全知识资料。", body)])]</code> |
| L0655 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 appendix_rag。 | <code>        rows = [["序号", "知识库文档", "知识主题", "相关度"]]</code> |
| L0656 | 遍历集合中的数据项并逐项处理，当前位于函数 appendix_rag。 | <code>        for idx, row in enumerate(rag_rows, 1):</code> |
| L0657 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 appendix_rag。 | <code>            rows.append([idx, row.get("document_name") or "知识库文档", row.get("title_path") or "正文", f"{float(row.get('score') or 0):.1%}"])</code> |
| L0658 | 结束当前函数并把结果返回给调用方，当前位于函数 appendix_rag。 | <code>        return [make_table(rows, [13*mm, 52*mm, 76*mm, 21*mm])]</code> |
| L0659 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0660 | 定义appendixgeneration函数 &#96;appendix_generation&#96;，封装可复用业务逻辑。 | <code>    def appendix_generation() -&gt; List[Any]:</code> |
| L0661 | 计算并保存 &#96;meta&#96;（meta），供后续逻辑使用，当前位于函数 appendix_generation。 | <code>        meta = dict(report_meta or {})</code> |
| L0662 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 appendix_generation。 | <code>        rows = [</code> |
| L0663 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 appendix_generation。 | <code>            ["生成项目", "内容说明"], ["报告生成时间", generated_at],</code> |
| L0664 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 appendix_generation。 | <code>            ["分析对象", snapshot.get("report_generated_for") or "-"],</code> |
| L0665 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 appendix_generation。 | <code>            ["模型名称", meta.get("model_name") or "外部大模型 API"],</code> |
| L0666 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 appendix_generation。 | <code>            ["知识增强", "已启用" if rag_rows else "未启用或无召回结果"],</code> |
| L0667 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 appendix_generation。 | <code>            ["证据边界", snapshot.get("evidence_boundary") or "网络侧证据不单独证明主机失陷。"],</code> |
| L0668 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 appendix_generation。 | <code>            ["报告用途", "安全研判、事件调查与处置决策辅助"],</code> |
| L0669 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 appendix_generation。 | <code>        ]</code> |
| L0670 | 结束当前函数并把结果返回给调用方，当前位于函数 appendix_generation。 | <code>        return [make_table(rows, [48*mm, 126*mm])]</code> |
| L0671 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0672 | 计算并保存 &#96;inserted&#96;（inserted），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    inserted = {"chain": False, "timeline": False, "evidence": False, "A": False, "B": False, "C": False, "D": False}</code> |
| L0673 | 计算并保存 &#96;skip_next_table&#96;（skipnexttable），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    skip_next_table = False</code> |
| L0674 | 计算并保存 &#96;suppress_appendix_body&#96;（suppressappendixbody），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    suppress_appendix_body = False</code> |
| L0675 | 计算并保存 &#96;current_chapter&#96;（currentchapter），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    current_chapter = "1"</code> |
| L0676 | 计算并保存 &#96;table_numbers&#96;（tablenumbers），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    table_numbers: Dict[str, int] = {"1": 1, "4": 1, "5": 1, "6": 0, "7": 0, "A": 1, "B": 0, "C": 0, "D": 0}</code> |
| L0677 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0678 | 定义nexttablecaption函数 &#96;next_table_caption&#96;，封装可复用业务逻辑。 | <code>    def next_table_caption(title_hint: str = "数据表") -&gt; str:</code> |
| L0679 | 计算并保存 &#96;chapter&#96;（chapter），供后续逻辑使用，当前位于函数 next_table_caption。 | <code>        chapter = current_chapter</code> |
| L0680 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 next_table_caption。 | <code>        table_numbers[chapter] = table_numbers.get(chapter, 0) + 1</code> |
| L0681 | 结束当前函数并把结果返回给调用方，当前位于函数 next_table_caption。 | <code>        return f"表{chapter}-{table_numbers[chapter]} {title_hint}"</code> |
| L0682 | 计算并保存 &#96;lines&#96;（lines），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    lines = markdown.splitlines(); i = 0</code> |
| L0683 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 render_pdf。 | <code>    while i &lt; len(lines):</code> |
| L0684 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 render_pdf。 | <code>        raw = lines[i]; line = raw.strip(); i += 1</code> |
| L0685 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>        if not line: continue</code> |
| L0686 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>        if _report_title_line(line): continue</code> |
| L0687 | 计算并保存 &#96;caption_text&#96;（captiontext），供后续逻辑使用，当前位于函数 render_pdf。 | <code>        caption_text = re.sub(r"[《》〈〉（()）\s*_&#96;]", "", line)</code> |
| L0688 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>        if len(caption_text) &lt;= 24 and caption_text.startswith("攻击链阶段") and caption_text.endswith("图"):</code> |
| L0689 | 控制当前循环或占位分支的执行流程，当前位于函数 render_pdf。 | <code>            continue</code> |
| L0690 | 计算并保存 &#96;heading&#96;（heading），供后续逻辑使用，当前位于函数 render_pdf。 | <code>        heading = re.match(r"^(#{1,4})\s+(.+)$", line)</code> |
| L0691 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>        if heading:</code> |
| L0692 | 计算并保存 &#96;level&#96;（level），供后续逻辑使用，当前位于函数 render_pdf。 | <code>            level = len(heading.group(1)); text = re.sub(r"[*_&#96;]", "", heading.group(2)).strip()</code> |
| L0693 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>            if suppress_appendix_body and level &gt; 2:</code> |
| L0694 | 控制当前循环或占位分支的执行流程，当前位于函数 render_pdf。 | <code>                continue</code> |
| L0695 | 计算并保存 &#96;suppress_appendix_body&#96;（suppressappendixbody），供后续逻辑使用，当前位于函数 render_pdf。 | <code>            suppress_appendix_body = False</code> |
| L0696 | 计算并保存 &#96;chapter_match&#96;（chaptermatch），供后续逻辑使用，当前位于函数 render_pdf。 | <code>            chapter_match = re.match(r"^(?:附录\s*([A-D])&#124;([一二三四五六七])、&#124;([1-7])(?:\.&#124;、))", text)</code> |
| L0697 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>            if chapter_match:</code> |
| L0698 | 计算并保存 &#96;current_chapter&#96;（currentchapter），供后续逻辑使用，当前位于函数 render_pdf。 | <code>                current_chapter = chapter_match.group(1) or ({"一":"1","二":"2","三":"3","四":"4","五":"5","六":"6","七":"7"}.get(chapter_match.group(2) or "")) or chapter_match.group(3) or current_chapter</code> |
| L0699 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>            if re.match(r"^一[、.]\s*基本信息", text):</code> |
| L0700 | 计算并保存 &#96;skip_next_table&#96;（skipnexttable），供后续逻辑使用，当前位于函数 render_pdf。 | <code>                skip_next_table = True</code> |
| L0701 | 控制当前循环或占位分支的执行流程，当前位于函数 render_pdf。 | <code>                continue</code> |
| L0702 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>            target_style = h1 if level &lt;= 2 else h2 if level == 3 else h3</code> |
| L0703 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>            if text.startswith("附录") and not any(x in text for x in ("附录 A", "附录 B", "附录 C", "附录 D")):</code> |
| L0704 | 计算并保存 &#96;target_style&#96;（targetstyle），供后续逻辑使用，当前位于函数 render_pdf。 | <code>                target_style = h1</code> |
| L0705 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>            if text.startswith("附录 A"):</code> |
| L0706 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>                story += [p("附录 A 完整动作序列", h1), *table_block("表A-1 完整动作序列", timeline_table(actions))]; inserted["A"] = True; suppress_appendix_body = True; continue</code> |
| L0707 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>            if text.startswith("附录 B"):</code> |
| L0708 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>                story += [p("附录 B 关键证据索引", h1), *appendix_evidence()]; inserted["B"] = True; suppress_appendix_body = True; continue</code> |
| L0709 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>            if text.startswith("附录 C"):</code> |
| L0710 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>                story += [p("附录 C RAG 参考资料", h1), *table_block("表C-1 RAG 参考资料", appendix_rag()[0])]; inserted["C"] = True; suppress_appendix_body = True; continue</code> |
| L0711 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>            if text.startswith("附录 D"):</code> |
| L0712 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>                story += [p("附录 D 报告生成信息", h1), *table_block("表D-1 报告生成信息", appendix_generation()[0])]; inserted["D"] = True; suppress_appendix_body = True; continue</code> |
| L0713 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>            if text.startswith(("4.1", "5.1")):</code> |
| L0714 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 render_pdf。 | <code>                story.append(CondPageBreak(35*mm))</code> |
| L0715 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 render_pdf。 | <code>            story.append(p(text, target_style))</code> |
| L0716 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>            if text.startswith("四、") or text.startswith("4、"):</code> |
| L0717 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>                story += figure_block("图4-1 攻击链阶段演进示意图", AttackChain(actions, doc.width), 3*mm); inserted["chain"] = True</code> |
| L0718 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>            if text.startswith("4.1"):</code> |
| L0719 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>                story += table_block("表4-1 攻击时间线总览", timeline_table(), 4*mm); inserted["timeline"] = True; skip_next_table = True</code> |
| L0720 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>            if text.startswith("5.1"):</code> |
| L0721 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>                story += table_block("表5-1 多源证据总览", evidence_table(), 6*mm); inserted["evidence"] = True</code> |
| L0722 | 控制当前循环或占位分支的执行流程，当前位于函数 render_pdf。 | <code>            continue</code> |
| L0723 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>        if suppress_appendix_body:</code> |
| L0724 | 控制当前循环或占位分支的执行流程，当前位于函数 render_pdf。 | <code>            continue</code> |
| L0725 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>        if line.startswith("&#124;"):</code> |
| L0726 | 计算并保存 &#96;table_lines&#96;（tablelines），供后续逻辑使用，当前位于函数 render_pdf。 | <code>            table_lines = [line]</code> |
| L0727 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 render_pdf。 | <code>            while i &lt; len(lines) and lines[i].strip().startswith("&#124;"):</code> |
| L0728 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 render_pdf。 | <code>                table_lines.append(lines[i].strip()); i += 1</code> |
| L0729 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 render_pdf。 | <code>            rows = []</code> |
| L0730 | 遍历集合中的数据项并逐项处理，当前位于函数 render_pdf。 | <code>            for table_line in table_lines:</code> |
| L0731 | 计算并保存 &#96;cells&#96;（cells），供后续逻辑使用，当前位于函数 render_pdf。 | <code>                cells = [c.strip() for c in table_line.strip("&#124;").split("&#124;")]</code> |
| L0732 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>                if all(re.fullmatch(r":?-{3,}:?", c) for c in cells): continue</code> |
| L0733 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 render_pdf。 | <code>                rows.append(cells)</code> |
| L0734 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>            if skip_next_table:</code> |
| L0735 | 计算并保存 &#96;skip_next_table&#96;（skipnexttable），供后续逻辑使用，当前位于函数 render_pdf。 | <code>                skip_next_table = False</code> |
| L0736 | 控制当前循环或占位分支的执行流程，当前位于函数 render_pdf。 | <code>                continue</code> |
| L0737 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>            if rows:</code> |
| L0738 | 计算并保存 &#96;cols&#96;（cols），供后续逻辑使用，当前位于函数 render_pdf。 | <code>                cols = max(len(r) for r in rows); widths = [doc.width/cols]*cols</code> |
| L0739 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>                hint = "关键判断交叉验证" if current_chapter == "5" else "分析数据"</code> |
| L0740 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>                story += table_block(next_table_caption(hint), make_table([r + [""]*(cols-len(r)) for r in rows], widths), 5*mm)</code> |
| L0741 | 控制当前循环或占位分支的执行流程，当前位于函数 render_pdf。 | <code>            continue</code> |
| L0742 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>        if line.startswith(("- ", "* ")):</code> |
| L0743 | 计算并保存 &#96;bullets&#96;（bullets），供后续逻辑使用，当前位于函数 render_pdf。 | <code>            bullets = [line[2:].strip()]</code> |
| L0744 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 render_pdf。 | <code>            while i &lt; len(lines) and lines[i].strip().startswith(("- ", "* ")):</code> |
| L0745 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 render_pdf。 | <code>                bullets.append(lines[i].strip()[2:].strip()); i += 1</code> |
| L0746 | 计算并保存 &#96;bullet_items&#96;（bullet数据项），供后续逻辑使用，当前位于函数 render_pdf。 | <code>            bullet_items = [</code> |
| L0747 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>                Paragraph(f"&lt;font color='#2288F5'&gt;&lt;b&gt;{index}.&lt;/b&gt;&lt;/font&gt;  " + _plain_markdown(_list_item_text(item)), bullet)</code> |
| L0748 | 遍历集合中的数据项并逐项处理，当前位于函数 render_pdf。 | <code>                for index, item in enumerate(bullets, 1)</code> |
| L0749 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 render_pdf。 | <code>            ]</code> |
| L0750 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>            story += [card(bullet_items), Spacer(1, 2.5*mm)]</code> |
| L0751 | 控制当前循环或占位分支的执行流程，当前位于函数 render_pdf。 | <code>            continue</code> |
| L0752 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>        if re.match(r"^\d+[.)]\s", line):</code> |
| L0753 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 render_pdf。 | <code>            story.append(p(line, bullet)); continue</code> |
| L0754 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 render_pdf。 | <code>        story.append(p(line, body))</code> |
| L0755 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0756 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>    if not inserted["chain"] and actions:</code> |
| L0757 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        story += [p("四、攻击态势分析", h1), *figure_block("图4-1 攻击链阶段演进示意图", AttackChain(actions, doc.width))]</code> |
| L0758 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>    if not inserted["timeline"]:</code> |
| L0759 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        story += [p("4.1 攻击时间线总览", h2), *table_block("表4-1 攻击时间线总览", timeline_table())]</code> |
| L0760 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>    if not inserted["evidence"]:</code> |
| L0761 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        story += [p("5.1 多源证据总览", h2), *table_block("表5-1 多源证据总览", evidence_table())]</code> |
| L0762 | 计算并保存 &#96;appendix_builders&#96;（appendixbuilders），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    appendix_builders = [("A", "附录 A 完整动作序列", appendix_actions), ("B", "附录 B 关键证据索引", appendix_evidence), ("C", "附录 C RAG 参考资料", appendix_rag), ("D", "附录 D 报告生成信息", appendix_generation)]</code> |
| L0763 | 计算并保存 &#96;missing&#96;（missing），供后续逻辑使用，当前位于函数 render_pdf。 | <code>    missing = [entry for entry in appendix_builders if not inserted[entry[0]]]</code> |
| L0764 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>    if missing:</code> |
| L0765 | 遍历集合中的数据项并逐项处理，当前位于函数 render_pdf。 | <code>        for _, heading_text, builder in missing:</code> |
| L0766 | 计算并保存 &#96;appendix&#96;（appendix），供后续逻辑使用，当前位于函数 render_pdf。 | <code>            appendix = heading_text.split()[1] if heading_text.startswith("附录 ") else current_chapter</code> |
| L0767 | 计算并保存 &#96;built&#96;（built），供后续逻辑使用，当前位于函数 render_pdf。 | <code>            built = builder()</code> |
| L0768 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_pdf。 | <code>            if built and isinstance(built[0], Table):</code> |
| L0769 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>                story += [p(heading_text, h1), *table_block(f"表{appendix}-1 {heading_text.split(' ', 2)[-1]}", built[0])]</code> |
| L0770 | 处理前述条件均未命中的情况，当前位于函数 render_pdf。 | <code>            else:</code> |
| L0771 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>                story += [p(heading_text, h1), *built]</code> |
| L0772 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>    story += [Spacer(1, 7*mm), card([</code> |
| L0773 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        p("感谢使用靖渊智御外部 Web 威胁态势感知分析系统。", h3),</code> |
| L0774 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>        p("本报告根据系统采集的网络安全事件、检测模型结果、规则证据、行为信息及安全知识资料综合生成，仅作为安全研判、事件调查与防护决策的辅助依据。", small),</code> |
| L0775 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 render_pdf。 | <code>    ], colors.HexColor("#F3F6FC"))]</code> |
| L0776 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_pdf。 | <code>    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)</code> |
| L0777 | 结束当前函数并把结果返回给调用方，当前位于函数 render_pdf。 | <code>    return hashlib.sha256(output.read_bytes()).hexdigest()</code> |
| L0778 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0779 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0780 | 定义类 &#96;ProfessionalReportManager&#96;，集中保存相关状态与操作。 | <code>class ProfessionalReportManager:</code> |
| L0781 | 定义init函数 &#96;__init__&#96;，封装可复用业务逻辑。 | <code>    def __init__(self, mysql_conf: Dict[str, Any], report_dir: Path, prompt_path: Path, rag_data_dir: Path, rag_api_path: Path):</code> |
| L0782 | 计算并保存 &#96;mysql_conf&#96;（mysqlconf），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.mysql_conf = dict(mysql_conf); self.report_dir = report_dir; self.prompt_path = prompt_path</code> |
| L0783 | 计算并保存 &#96;rag_data_dir&#96;（ragdatadir），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.rag_data_dir = rag_data_dir; self.rag_api_path = rag_api_path; self._lock = threading.Lock(); self._active: set[str] = set()</code> |
| L0784 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0785 | 定义启动函数 &#96;start&#96;，封装可复用业务逻辑。 | <code>    def start(self, job_id: str) -&gt; None:</code> |
| L0786 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 start。 | <code>        with self._lock:</code> |
| L0787 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 start。 | <code>            if job_id in self._active: return</code> |
| L0788 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 start。 | <code>            self._active.add(job_id)</code> |
| L0789 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 start。 | <code>        threading.Thread(target=self._run, args=(job_id,), daemon=True, name=f"professional-report-{job_id[-6:]}").start()</code> |
| L0790 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0791 | 定义运行函数 &#96;_run&#96;，封装可复用业务逻辑。 | <code>    def _run(self, job_id: str) -&gt; None:</code> |
| L0792 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _run。 | <code>        try:</code> |
| L0793 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _run。 | <code>            update_job(self.mysql_conf, job_id, 8, "正在整理态势证据", status="running", started_at=datetime.now(), error_message=None)</code> |
| L0794 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 _run。 | <code>            with connect(self.mysql_conf, autocommit=True) as conn:</code> |
| L0795 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 _run。 | <code>                with conn.cursor() as cur: cur.execute("SELECT * FROM situation_professional_reports WHERE job_id=%s", (job_id,)); job = cur.fetchone()</code> |
| L0796 | 计算并保存 &#96;store&#96;（store），供后续逻辑使用，当前位于函数 _run。 | <code>            store = MySQLSituationStore(MySQLSettings(**self.mysql_conf)); situation = store.get_situation(str(job["situation_id"])); store.close()</code> |
| L0797 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _run。 | <code>            if not situation: raise RuntimeError("态势不存在或已被删除")</code> |
| L0798 | 计算并保存 &#96;snapshot&#96;（snapshot），供后续逻辑使用，当前位于函数 _run。 | <code>            snapshot = build_snapshot(situation)</code> |
| L0799 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _run。 | <code>            update_job(self.mysql_conf, job_id, 20, "正在检索安全知识库", snapshot_json=json.dumps(snapshot, ensure_ascii=False))</code> |
| L0800 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _run。 | <code>            try: rag_rows = retrieve_context(self.mysql_conf, self.rag_data_dir, self.rag_api_path, snapshot)</code> |
| L0801 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _run。 | <code>            except Exception: rag_rows = []</code> |
| L0802 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _run。 | <code>            update_job(self.mysql_conf, job_id, 35, "正在调用外部模型生成专业分析", rag_references_json=json.dumps(rag_rows, ensure_ascii=False))</code> |
| L0803 | 计算并保存 &#96;config_payload&#96;（配置payload），供后续逻辑使用，当前位于函数 _run。 | <code>            config_payload = json.loads(self.rag_api_path.read_text(encoding="utf-8-sig")) if self.rag_api_path.exists() else {}</code> |
| L0804 | 计算并保存 &#96;api&#96;（接口），供后续逻辑使用，当前位于函数 _run。 | <code>            api = load_api_config(self.rag_api_path)</code> |
| L0805 | 计算并保存 &#96;report_options&#96;（报告options），供后续逻辑使用，当前位于函数 _run。 | <code>            report_options = resolve_professional_report_options(config_payload)</code> |
| L0806 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _run。 | <code>            api["professional_report_timeout_seconds"] = report_options["timeout_seconds"]</code> |
| L0807 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _run。 | <code>            api["professional_report_max_tokens"] = report_options["max_tokens"]</code> |
| L0808 | 计算并保存 &#96;model&#96;（模型），供后续逻辑使用，当前位于函数 _run。 | <code>            model = report_options["model"]</code> |
| L0809 | 计算并保存 &#96;prompt&#96;（prompt），供后续逻辑使用，当前位于函数 _run。 | <code>            prompt = self.prompt_path.read_text(encoding="utf-8-sig")</code> |
| L0810 | 计算并保存 &#96;progress_stop&#96;（progress停止），供后续逻辑使用，当前位于函数 _run。 | <code>            progress_stop = threading.Event()</code> |
| L0811 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0812 | 定义报告progress函数 &#96;report_progress&#96;，封装可复用业务逻辑。 | <code>            def report_progress() -&gt; None:</code> |
| L0813 | 遍历集合中的数据项并逐项处理，当前位于函数 report_progress。 | <code>                for progress, stage in (</code> |
| L0814 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 report_progress。 | <code>                    (43, "外部模型正在分析攻击链"),</code> |
| L0815 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 report_progress。 | <code>                    (52, "外部模型正在核验证据边界"),</code> |
| L0816 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 report_progress。 | <code>                    (61, "外部模型正在生成处置建议"),</code> |
| L0817 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 report_progress。 | <code>                    (70, "外部模型正在完成专业报告"),</code> |
| L0818 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 report_progress。 | <code>                ):</code> |
| L0819 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 report_progress。 | <code>                    if progress_stop.wait(10):</code> |
| L0820 | 结束当前函数并把结果返回给调用方，当前位于函数 report_progress。 | <code>                        return</code> |
| L0821 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 report_progress。 | <code>                    update_job(self.mysql_conf, job_id, progress, stage)</code> |
| L0822 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0823 | 计算并保存 &#96;ticker&#96;（ticker），供后续逻辑使用，当前位于函数 _run。 | <code>            ticker = threading.Thread(target=report_progress, daemon=True, name=f"professional-progress-{job_id[-6:]}")</code> |
| L0824 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _run。 | <code>            ticker.start()</code> |
| L0825 | 计算并保存 &#96;generation_error&#96;（generationerror），供后续逻辑使用，当前位于函数 _run。 | <code>            generation_error = None</code> |
| L0826 | 计算并保存 &#96;model_name&#96;（模型name），供后续逻辑使用，当前位于函数 _run。 | <code>            model_name = model</code> |
| L0827 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _run。 | <code>            try:</code> |
| L0828 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _run。 | <code>                markdown, usage, model_name, generation_error = generate_professional_markdown(</code> |
| L0829 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _run。 | <code>                    api, model, prompt, snapshot, rag_rows</code> |
| L0830 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _run。 | <code>                )</code> |
| L0831 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _run。 | <code>                if generation_error:</code> |
| L0832 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _run。 | <code>                    update_job(self.mysql_conf, job_id, 76, "模型超时或格式异常，正在使用快速模板")</code> |
| L0833 | 无论成功或异常都执行资源清理，当前位于函数 _run。 | <code>            finally:</code> |
| L0834 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _run。 | <code>                progress_stop.set()</code> |
| L0835 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _run。 | <code>                ticker.join(timeout=1)</code> |
| L0836 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _run。 | <code>            update_job(self.mysql_conf, job_id, 82, "正在排版并校验 PDF", model_name=model_name, report_markdown=markdown, input_tokens=usage["input"], output_tokens=usage["output"])</code> |
| L0837 | 计算并保存 &#96;output&#96;（output），供后续逻辑使用，当前位于函数 _run。 | <code>            output = self.report_dir / f"{job['situation_id']}_{job['sequence_hash']}.pdf"</code> |
| L0838 | 计算并保存 &#96;digest&#96;（digest），供后续逻辑使用，当前位于函数 _run。 | <code>            digest = render_pdf(</code> |
| L0839 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _run。 | <code>                output, snapshot, markdown, rag_rows,</code> |
| L0840 | 计算并保存 &#96;report_meta&#96;（报告meta），供后续逻辑使用，当前位于函数 _run。 | <code>                report_meta={"model_name": model_name, "input_tokens": usage["input"], "output_tokens": usage["output"]},</code> |
| L0841 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _run。 | <code>            )</code> |
| L0842 | 计算并保存 &#96;final_stage&#96;（finalstage），供后续逻辑使用，当前位于函数 _run。 | <code>            final_stage = "专业态势报告已生成（快速模板降级）" if generation_error else "专业态势报告已生成"</code> |
| L0843 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _run。 | <code>            update_job(self.mysql_conf, job_id, 100, final_stage, status="completed", pdf_path=str(output), pdf_sha256=digest, completed_at=datetime.now())</code> |
| L0844 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _run。 | <code>        except Exception as exc:</code> |
| L0845 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _run。 | <code>            update_job(self.mysql_conf, job_id, 100, "报告生成失败", status="failed", error_message=f"{type(exc).__name__}: {exc}"[:2000], completed_at=datetime.now())</code> |
| L0846 | 无论成功或异常都执行资源清理，当前位于函数 _run。 | <code>        finally:</code> |
| L0847 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 _run。 | <code>            with self._lock: self._active.discard(job_id)</code> |
