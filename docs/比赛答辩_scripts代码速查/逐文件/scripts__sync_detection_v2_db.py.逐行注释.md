# `scripts/sync_detection_v2_db.py` 逐行注释

**脚本用途：** 将新架构候选、模型预测、POC 命中和行为窗口同步到数据库。

**源码行数：** 298　**函数/类数量：** 8

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, Iterable&#96;。 | <code>from typing import Any, Dict, Iterable</code> |
| L0007 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0008 | 开始受保护操作，异常会交给后续分支处理。 | <code>try:</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;import pymysql&#96;。 | <code>    import pymysql</code> |
| L0010 | 捕获异常，避免单次错误导致整个服务退出。 | <code>except Exception:  # pragma: no cover</code> |
| L0011 | 计算并保存 &#96;pymysql&#96;（pymysql），供后续逻辑使用。 | <code>    pymysql = None</code> |
| L0012 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0013 | 导入后续逻辑所需的模块、类或函数：&#96;from build_result_db import MySQLConfig&#96;。 | <code>from build_result_db import MySQLConfig</code> |
| L0014 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0015 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0016 | 定义读取json函数 &#96;read_json&#96;，封装可复用业务逻辑。 | <code>def read_json(path: Path) -&gt; Dict[str, Any]:</code> |
| L0017 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_json。 | <code>    if not path.exists():</code> |
| L0018 | 结束当前函数并把结果返回给调用方，当前位于函数 read_json。 | <code>        return {}</code> |
| L0019 | 结束当前函数并把结果返回给调用方，当前位于函数 read_json。 | <code>    return json.loads(path.read_text(encoding="utf-8-sig"))</code> |
| L0020 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0021 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0022 | 定义读取text函数 &#96;read_text&#96;，封装可复用业务逻辑。 | <code>def read_text(path: Path) -&gt; str:</code> |
| L0023 | 结束当前函数并把结果返回给调用方，当前位于函数 read_text。 | <code>    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""</code> |
| L0024 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0025 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0026 | 定义itercasedirs函数 &#96;iter_case_dirs&#96;，封装可复用业务逻辑。 | <code>def iter_case_dirs(result_dir: Path) -&gt; Iterable[Path]:</code> |
| L0027 | 遍历集合中的数据项并逐项处理，当前位于函数 iter_case_dirs。 | <code>    for p in sorted(result_dir.glob("b.*"), key=lambda x: int(x.name.split(".", 1)[1]) if x.name.split(".", 1)[1].isdigit() else 10**9):</code> |
| L0028 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 iter_case_dirs。 | <code>        if p.is_dir():</code> |
| L0029 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 iter_case_dirs。 | <code>            yield p</code> |
| L0030 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0031 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0032 | 定义mysqlconnect函数 &#96;mysql_connect&#96;，封装可复用业务逻辑。 | <code>def mysql_connect(cfg: MySQLConfig):</code> |
| L0033 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 mysql_connect。 | <code>    if pymysql is None:</code> |
| L0034 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 mysql_connect。 | <code>        raise RuntimeError("PyMySQL is not installed")</code> |
| L0035 | 结束当前函数并把结果返回给调用方，当前位于函数 mysql_connect。 | <code>    return pymysql.connect(</code> |
| L0036 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 mysql_connect。 | <code>        host=cfg.host,</code> |
| L0037 | 计算并保存 &#96;port&#96;（port），供后续逻辑使用，当前位于函数 mysql_connect。 | <code>        port=cfg.port,</code> |
| L0038 | 计算并保存 &#96;user&#96;（user），供后续逻辑使用，当前位于函数 mysql_connect。 | <code>        user=cfg.user,</code> |
| L0039 | 控制当前循环或占位分支的执行流程，当前位于函数 mysql_connect。 | <code>        password=cfg.password,</code> |
| L0040 | 计算并保存 &#96;database&#96;（数据库），供后续逻辑使用，当前位于函数 mysql_connect。 | <code>        database=cfg.database,</code> |
| L0041 | 计算并保存 &#96;charset&#96;（charset），供后续逻辑使用，当前位于函数 mysql_connect。 | <code>        charset="utf8mb4",</code> |
| L0042 | 计算并保存 &#96;autocommit&#96;（autocommit），供后续逻辑使用，当前位于函数 mysql_connect。 | <code>        autocommit=True,</code> |
| L0043 | 计算并保存 &#96;cursorclass&#96;（cursorclass），供后续逻辑使用，当前位于函数 mysql_connect。 | <code>        cursorclass=pymysql.cursors.DictCursor,</code> |
| L0044 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 mysql_connect。 | <code>    )</code> |
| L0045 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0046 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0047 | 计算并保存 &#96;MYSQL_DDL&#96;（MYSQLDDL），供后续逻辑使用。 | <code>MYSQL_DDL = [</code> |
| L0048 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """</code> |
| L0049 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>    CREATE TABLE IF NOT EXISTS raw_http_logs (</code> |
| L0050 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      id BIGINT AUTO_INCREMENT PRIMARY KEY,</code> |
| L0051 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      case_id VARCHAR(64) NULL,</code> |
| L0052 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      file_id VARCHAR(128) NULL,</code> |
| L0053 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      seq_id INT NULL,</code> |
| L0054 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      event_time VARCHAR(64) NULL,</code> |
| L0055 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      source_ip VARCHAR(64) NULL,</code> |
| L0056 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      destination_ip VARCHAR(64) NULL,</code> |
| L0057 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      method VARCHAR(16) NULL,</code> |
| L0058 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      uri TEXT NULL,</code> |
| L0059 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      host VARCHAR(255) NULL,</code> |
| L0060 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      status_code INT NULL,</code> |
| L0061 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      request_text LONGTEXT NULL,</code> |
| L0062 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      response_text LONGTEXT NULL,</code> |
| L0063 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0064 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      UNIQUE KEY uniq_raw_case (case_id),</code> |
| L0065 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_raw_file_seq (file_id, seq_id),</code> |
| L0066 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_raw_source_ip (source_ip)</code> |
| L0067 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4</code> |
| L0068 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """,</code> |
| L0069 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """</code> |
| L0070 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>    CREATE TABLE IF NOT EXISTS detection_candidates (</code> |
| L0071 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      event_id VARCHAR(64) PRIMARY KEY,</code> |
| L0072 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      case_id VARCHAR(64) NULL,</code> |
| L0073 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      file_id VARCHAR(128) NULL,</code> |
| L0074 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      seq_id INT NULL,</code> |
| L0075 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      decision VARCHAR(32) NULL,</code> |
| L0076 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      final_score DOUBLE NULL,</code> |
| L0077 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      risk_level VARCHAR(32) NULL,</code> |
| L0078 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      attack_type VARCHAR(128) NULL,</code> |
| L0079 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      source_ip VARCHAR(64) NULL,</code> |
| L0080 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      target_interface VARCHAR(255) NULL,</code> |
| L0081 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      evidence_json LONGTEXT NULL,</code> |
| L0082 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0083 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_candidate_decision (decision),</code> |
| L0084 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_candidate_type (attack_type)</code> |
| L0085 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4</code> |
| L0086 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """,</code> |
| L0087 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """</code> |
| L0088 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>    CREATE TABLE IF NOT EXISTS attack_events (</code> |
| L0089 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      event_id VARCHAR(64) PRIMARY KEY,</code> |
| L0090 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      case_id VARCHAR(64) NULL,</code> |
| L0091 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      occurred_at VARCHAR(64) NULL,</code> |
| L0092 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      source_ip VARCHAR(64) NULL,</code> |
| L0093 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      target_interface VARCHAR(255) NULL,</code> |
| L0094 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      attack_type VARCHAR(128) NULL,</code> |
| L0095 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      risk_level VARCHAR(32) NULL,</code> |
| L0096 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      confidence DOUBLE NULL,</code> |
| L0097 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      status VARCHAR(32) NOT NULL DEFAULT 'unprocessed',</code> |
| L0098 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      evidence_json LONGTEXT NULL,</code> |
| L0099 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0100 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_attack_time (occurred_at),</code> |
| L0101 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_attack_type (attack_type),</code> |
| L0102 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_attack_source_ip (source_ip)</code> |
| L0103 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4</code> |
| L0104 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """,</code> |
| L0105 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """</code> |
| L0106 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>    CREATE TABLE IF NOT EXISTS model_predictions (</code> |
| L0107 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      id BIGINT AUTO_INCREMENT PRIMARY KEY,</code> |
| L0108 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      case_id VARCHAR(64) NULL,</code> |
| L0109 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      model_name VARCHAR(128) NULL,</code> |
| L0110 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      label VARCHAR(128) NULL,</code> |
| L0111 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      score DOUBLE NULL,</code> |
| L0112 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      proba_json LONGTEXT NULL,</code> |
| L0113 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0114 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_model_case (case_id)</code> |
| L0115 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4</code> |
| L0116 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """,</code> |
| L0117 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """</code> |
| L0118 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>    CREATE TABLE IF NOT EXISTS poc_matches (</code> |
| L0119 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      id BIGINT AUTO_INCREMENT PRIMARY KEY,</code> |
| L0120 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      case_id VARCHAR(64) NULL,</code> |
| L0121 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      rule_id VARCHAR(128) NULL,</code> |
| L0122 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      rule_name VARCHAR(255) NULL,</code> |
| L0123 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      attack_type VARCHAR(128) NULL,</code> |
| L0124 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      severity VARCHAR(32) NULL,</code> |
| L0125 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      score DOUBLE NULL,</code> |
| L0126 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      evidence_json LONGTEXT NULL,</code> |
| L0127 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0128 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_poc_case (case_id),</code> |
| L0129 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_poc_rule (rule_id)</code> |
| L0130 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4</code> |
| L0131 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """,</code> |
| L0132 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """</code> |
| L0133 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>    CREATE TABLE IF NOT EXISTS behavior_windows (</code> |
| L0134 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      id BIGINT AUTO_INCREMENT PRIMARY KEY,</code> |
| L0135 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      case_id VARCHAR(64) NULL,</code> |
| L0136 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      source_ip VARCHAR(64) NULL,</code> |
| L0137 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      behavior_type VARCHAR(128) NULL,</code> |
| L0138 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      score DOUBLE NULL,</code> |
| L0139 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      features_json LONGTEXT NULL,</code> |
| L0140 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      evidence_json LONGTEXT NULL,</code> |
| L0141 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0142 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_behavior_case (case_id),</code> |
| L0143 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_behavior_source_ip (source_ip)</code> |
| L0144 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4</code> |
| L0145 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """,</code> |
| L0146 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>]</code> |
| L0147 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0148 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0149 | 定义ensuremysql函数 &#96;ensure_mysql&#96;，封装可复用业务逻辑。 | <code>def ensure_mysql(conn):</code> |
| L0150 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 ensure_mysql。 | <code>    with conn.cursor() as cur:</code> |
| L0151 | 遍历集合中的数据项并逐项处理，当前位于函数 ensure_mysql。 | <code>        for ddl in MYSQL_DDL:</code> |
| L0152 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_mysql。 | <code>            cur.execute(ddl)</code> |
| L0153 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0154 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0155 | 定义upsertmysql函数 &#96;upsert_mysql&#96;，封装可复用业务逻辑。 | <code>def upsert_mysql(conn, table: str, row: Dict[str, Any]) -&gt; None:</code> |
| L0156 | 计算并保存 &#96;keys&#96;（keys），供后续逻辑使用，当前位于函数 upsert_mysql。 | <code>    keys = list(row.keys())</code> |
| L0157 | 计算并保存 &#96;cols&#96;（cols），供后续逻辑使用，当前位于函数 upsert_mysql。 | <code>    cols = ",".join(f"&#96;{k}&#96;" for k in keys)</code> |
| L0158 | 计算并保存 &#96;vals&#96;（vals），供后续逻辑使用，当前位于函数 upsert_mysql。 | <code>    vals = ",".join(["%s"] * len(keys))</code> |
| L0159 | 计算并保存 &#96;updates&#96;（updates），供后续逻辑使用，当前位于函数 upsert_mysql。 | <code>    updates = ",".join(f"&#96;{k}&#96;=VALUES(&#96;{k}&#96;)" for k in keys if k not in {"id", "created_at"})</code> |
| L0160 | 计算并保存 &#96;sql&#96;（sql），供后续逻辑使用，当前位于函数 upsert_mysql。 | <code>    sql = f"INSERT INTO &#96;{table}&#96; ({cols}) VALUES ({vals}) ON DUPLICATE KEY UPDATE {updates}"</code> |
| L0161 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 upsert_mysql。 | <code>    with conn.cursor() as cur:</code> |
| L0162 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 upsert_mysql。 | <code>        cur.execute(sql, tuple(row[k] for k in keys))</code> |
| L0163 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0164 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0165 | 定义同步casemysql函数 &#96;sync_case_mysql&#96;，封装可复用业务逻辑。 | <code>def sync_case_mysql(conn, case_dir: Path) -&gt; Dict[str, int]:</code> |
| L0166 | 计算并保存 &#96;case&#96;（case），供后续逻辑使用，当前位于函数 sync_case_mysql。 | <code>    case = read_json(case_dir / "case.json")</code> |
| L0167 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_case_mysql。 | <code>    if not case:</code> |
| L0168 | 结束当前函数并把结果返回给调用方，当前位于函数 sync_case_mysql。 | <code>        return {"raw": 0, "candidate": 0, "attack": 0, "model": 0, "poc": 0, "behavior": 0}</code> |
| L0169 | 计算并保存 &#96;case_id&#96;（caseid），供后续逻辑使用，当前位于函数 sync_case_mysql。 | <code>    case_id = str(case.get("case_id") or case_dir.name)</code> |
| L0170 | 计算并保存 &#96;analysis&#96;（analysis），供后续逻辑使用，当前位于函数 sync_case_mysql。 | <code>    analysis = read_json(case_dir / "analysis.json")</code> |
| L0171 | 计算并保存 &#96;llm_verdict&#96;（llmverdict），供后续逻辑使用，当前位于函数 sync_case_mysql。 | <code>    llm_verdict = str(analysis.get("verdict") or "").strip().lower()</code> |
| L0172 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>    llm_confirmed = str(case.get("llm_status") or "").strip().lower() == "done" and llm_verdict in {</code> |
| L0173 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "attack",</code> |
| L0174 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "malicious",</code> |
| L0175 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "攻击",</code> |
| L0176 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "恶意",</code> |
| L0177 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_case_mysql。 | <code>    }</code> |
| L0178 | 计算并保存 &#96;event_id&#96;（事件id），供后续逻辑使用，当前位于函数 sync_case_mysql。 | <code>    event_id = case_id.replace("b.", "EVT", 1)</code> |
| L0179 | 计算并保存 &#96;request_text&#96;（requesttext），供后续逻辑使用，当前位于函数 sync_case_mysql。 | <code>    request_text = read_text(case_dir / "request.txt") or str(case.get("request_text") or "")</code> |
| L0180 | 计算并保存 &#96;response_text&#96;（responsetext），供后续逻辑使用，当前位于函数 sync_case_mysql。 | <code>    response_text = read_text(case_dir / "response.txt")</code> |
| L0181 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 sync_case_mysql。 | <code>    evidence = case.get("v2_evidence") or []</code> |
| L0182 | 计算并保存 &#96;poc_matches&#96;（pocmatches），供后续逻辑使用，当前位于函数 sync_case_mysql。 | <code>    poc_matches = case.get("v2_poc_matches") or []</code> |
| L0183 | 计算并保存 &#96;decision&#96;（decision），供后续逻辑使用，当前位于函数 sync_case_mysql。 | <code>    decision = str(case.get("v2_decision") or "attack_event")</code> |
| L0184 | 计算并保存 &#96;final_score&#96;（finalscore），供后续逻辑使用，当前位于函数 sync_case_mysql。 | <code>    final_score = case.get("v2_final_score") if case.get("v2_final_score") is not None else case.get("raw_score")</code> |
| L0185 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 sync_case_mysql。 | <code>    attack_type = case.get("attack_type") or "可疑流量"</code> |
| L0186 | 计算并保存 &#96;risk_level&#96;（risklevel），供后续逻辑使用，当前位于函数 sync_case_mysql。 | <code>    risk_level = case.get("v2_risk_level") or ("high" if float(final_score or 0) &gt;= 0.75 else "medium")</code> |
| L0187 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0188 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>    upsert_mysql(conn, "raw_http_logs", {</code> |
| L0189 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "case_id": case_id,</code> |
| L0190 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "file_id": case.get("file_id"),</code> |
| L0191 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "seq_id": case.get("seq_id"),</code> |
| L0192 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "event_time": case.get("export_time"),</code> |
| L0193 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "source_ip": case.get("source_ip"),</code> |
| L0194 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "destination_ip": case.get("destination_ip"),</code> |
| L0195 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "method": case.get("method"),</code> |
| L0196 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "uri": case.get("uri"),</code> |
| L0197 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "host": case.get("host"),</code> |
| L0198 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "status_code": case.get("status_code"),</code> |
| L0199 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "request_text": request_text,</code> |
| L0200 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "response_text": response_text,</code> |
| L0201 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_case_mysql。 | <code>    })</code> |
| L0202 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>    upsert_mysql(conn, "detection_candidates", {</code> |
| L0203 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "event_id": event_id,</code> |
| L0204 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "case_id": case_id,</code> |
| L0205 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "file_id": case.get("file_id"),</code> |
| L0206 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "seq_id": case.get("seq_id"),</code> |
| L0207 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "decision": decision,</code> |
| L0208 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "final_score": final_score,</code> |
| L0209 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "risk_level": risk_level,</code> |
| L0210 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "attack_type": attack_type,</code> |
| L0211 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "source_ip": case.get("source_ip"),</code> |
| L0212 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "target_interface": case.get("uri"),</code> |
| L0213 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "evidence_json": json.dumps(evidence, ensure_ascii=False),</code> |
| L0214 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_case_mysql。 | <code>    })</code> |
| L0215 | 计算并保存 &#96;attack_count&#96;（攻击count），供后续逻辑使用，当前位于函数 sync_case_mysql。 | <code>    attack_count = 0</code> |
| L0216 | 计算并保存 &#96;raw_canonical_exists&#96;（rawcanonicalexists），供后续逻辑使用，当前位于函数 sync_case_mysql。 | <code>    raw_canonical_exists = False</code> |
| L0217 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 sync_case_mysql。 | <code>    with conn.cursor() as cur:</code> |
| L0218 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 sync_case_mysql。 | <code>        cur.execute(</code> |
| L0219 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 sync_case_mysql。 | <code>            """</code> |
| L0220 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 sync_case_mysql。 | <code>            SELECT 1 FROM detection_candidates</code> |
| L0221 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 sync_case_mysql。 | <code>            WHERE case_id LIKE 'raw:%' AND file_id=%s AND seq_id=%s</code> |
| L0222 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 sync_case_mysql。 | <code>            LIMIT 1</code> |
| L0223 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 sync_case_mysql。 | <code>            """,</code> |
| L0224 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>            (case.get("file_id"), case.get("seq_id")),</code> |
| L0225 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_case_mysql。 | <code>        )</code> |
| L0226 | 计算并保存 &#96;raw_canonical_exists&#96;（rawcanonicalexists），供后续逻辑使用，当前位于函数 sync_case_mysql。 | <code>        raw_canonical_exists = bool(cur.fetchone())</code> |
| L0227 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_case_mysql。 | <code>    if decision == "attack_event" and llm_confirmed and not raw_canonical_exists:</code> |
| L0228 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        upsert_mysql(conn, "attack_events", {</code> |
| L0229 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>            "event_id": event_id,</code> |
| L0230 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>            "case_id": case_id,</code> |
| L0231 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>            "occurred_at": case.get("export_time"),</code> |
| L0232 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>            "source_ip": case.get("source_ip"),</code> |
| L0233 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>            "target_interface": case.get("uri"),</code> |
| L0234 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>            "attack_type": attack_type,</code> |
| L0235 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>            "risk_level": risk_level,</code> |
| L0236 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>            "confidence": final_score,</code> |
| L0237 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>            "status": "unprocessed",</code> |
| L0238 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>            "evidence_json": json.dumps(evidence, ensure_ascii=False),</code> |
| L0239 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_case_mysql。 | <code>        })</code> |
| L0240 | 计算并保存 &#96;attack_count&#96;（攻击count），供后续逻辑使用，当前位于函数 sync_case_mysql。 | <code>        attack_count = 1</code> |
| L0241 | 处理前述条件均未命中的情况，当前位于函数 sync_case_mysql。 | <code>    else:</code> |
| L0242 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 sync_case_mysql。 | <code>        with conn.cursor() as cur:</code> |
| L0243 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 sync_case_mysql。 | <code>            cur.execute("DELETE FROM attack_events WHERE event_id=%s", (event_id,))</code> |
| L0244 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>    upsert_mysql(conn, "model_predictions", {</code> |
| L0245 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "case_id": case_id,</code> |
| L0246 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "model_name": "payload_model_v2",</code> |
| L0247 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "label": case.get("v2_payload_label"),</code> |
| L0248 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "score": case.get("v2_payload_score"),</code> |
| L0249 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        "proba_json": json.dumps({}, ensure_ascii=False),</code> |
| L0250 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_case_mysql。 | <code>    })</code> |
| L0251 | 计算并保存 &#96;poc_count&#96;（poccount），供后续逻辑使用，当前位于函数 sync_case_mysql。 | <code>    poc_count = 0</code> |
| L0252 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 sync_case_mysql。 | <code>    with conn.cursor() as cur:</code> |
| L0253 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 sync_case_mysql。 | <code>        cur.execute("DELETE FROM poc_matches WHERE case_id=%s", (case_id,))</code> |
| L0254 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 sync_case_mysql。 | <code>        cur.execute("DELETE FROM behavior_windows WHERE case_id=%s", (case_id,))</code> |
| L0255 | 遍历集合中的数据项并逐项处理，当前位于函数 sync_case_mysql。 | <code>    for m in poc_matches:</code> |
| L0256 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 sync_case_mysql。 | <code>        with conn.cursor() as cur:</code> |
| L0257 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 sync_case_mysql。 | <code>            cur.execute(</code> |
| L0258 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 sync_case_mysql。 | <code>                """INSERT INTO poc_matches(case_id,rule_id,rule_name,attack_type,severity,score,evidence_json)</code> |
| L0259 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 sync_case_mysql。 | <code>                   VALUES(%s,%s,%s,%s,%s,%s,%s)""",</code> |
| L0260 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>                (case_id, m.get("rule_id"), m.get("name"), m.get("attack_type"), m.get("severity"), m.get("score"), json.dumps(m.get("evidence") or [], ensure_ascii=False)),</code> |
| L0261 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_case_mysql。 | <code>            )</code> |
| L0262 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>        poc_count += 1</code> |
| L0263 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_case_mysql。 | <code>    if case.get("v2_behavior_score") is not None:</code> |
| L0264 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 sync_case_mysql。 | <code>        with conn.cursor() as cur:</code> |
| L0265 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 sync_case_mysql。 | <code>            cur.execute(</code> |
| L0266 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 sync_case_mysql。 | <code>                """INSERT INTO behavior_windows(case_id,source_ip,behavior_type,score,features_json,evidence_json)</code> |
| L0267 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 sync_case_mysql。 | <code>                   VALUES(%s,%s,%s,%s,%s,%s)""",</code> |
| L0268 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_case_mysql。 | <code>                (case_id, case.get("source_ip"), case.get("v2_behavior_type"), case.get("v2_behavior_score"), json.dumps({}, ensure_ascii=False), json.dumps(evidence, ensure_ascii=False)),</code> |
| L0269 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_case_mysql。 | <code>            )</code> |
| L0270 | 结束当前函数并把结果返回给调用方，当前位于函数 sync_case_mysql。 | <code>    return {"raw": 1, "candidate": 1, "attack": attack_count, "model": 1, "poc": poc_count, "behavior": 1 if case.get("v2_behavior_score") is not None else 0}</code> |
| L0271 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0272 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0273 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; None:</code> |
| L0274 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="Sync v2 detection result cases into layered DB tables")</code> |
| L0275 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--result-dir", default="result")</code> |
| L0276 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-host", default="127.0.0.1")</code> |
| L0277 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-port", type=int, default=3306)</code> |
| L0278 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-user", default="root")</code> |
| L0279 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-password", default="123456")</code> |
| L0280 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-database", default="traffic_pipeline")</code> |
| L0281 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0282 | 计算并保存 &#96;project_root&#96;（projectroot），供后续逻辑使用，当前位于函数 main。 | <code>    project_root = Path(__file__).resolve().parent.parent</code> |
| L0283 | 计算并保存 &#96;result_dir&#96;（结果dir），供后续逻辑使用，当前位于函数 main。 | <code>    result_dir = (project_root / args.result_dir).resolve()</code> |
| L0284 | 计算并保存 &#96;cfg&#96;（cfg），供后续逻辑使用，当前位于函数 main。 | <code>    cfg = MySQLConfig(args.mysql_host, args.mysql_port, args.mysql_user, args.mysql_password, args.mysql_database)</code> |
| L0285 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 main。 | <code>    conn = mysql_connect(cfg)</code> |
| L0286 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    ensure_mysql(conn)</code> |
| L0287 | 计算并保存 &#96;totals&#96;（totals），供后续逻辑使用，当前位于函数 main。 | <code>    totals = {"raw": 0, "candidate": 0, "attack": 0, "model": 0, "poc": 0, "behavior": 0, "cases": 0}</code> |
| L0288 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>    for case_dir in iter_case_dirs(result_dir):</code> |
| L0289 | 计算并保存 &#96;stats&#96;（stats），供后续逻辑使用，当前位于函数 main。 | <code>        stats = sync_case_mysql(conn, case_dir)</code> |
| L0290 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        totals["cases"] += 1 if stats.get("raw") else 0</code> |
| L0291 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>        for k in stats:</code> |
| L0292 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            totals[k] += stats[k]</code> |
| L0293 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    conn.close()</code> |
| L0294 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(json.dumps(totals, ensure_ascii=False, indent=2))</code> |
| L0295 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0296 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0297 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0298 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
