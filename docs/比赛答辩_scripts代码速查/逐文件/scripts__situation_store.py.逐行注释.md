# `scripts/situation_store.py` 逐行注释

**脚本用途：** 态势、动作、证据、报告和队列数据的 MySQL 持久化访问层。

**源码行数：** 734　**函数/类数量：** 26

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;from dataclasses import dataclass&#96;。 | <code>from dataclasses import dataclass</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime, timezone&#96;。 | <code>from datetime import datetime, timezone</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, Iterable, List, Optional, Sequence&#96;。 | <code>from typing import Any, Dict, Iterable, List, Optional, Sequence</code> |
| L0007 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0008 | 开始受保护操作，异常会交给后续分支处理。 | <code>try:</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;import pymysql&#96;。 | <code>    import pymysql</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;from pymysql.cursors import DictCursor&#96;。 | <code>    from pymysql.cursors import DictCursor</code> |
| L0011 | 捕获异常，避免单次错误导致整个服务退出。 | <code>except Exception:  # pragma: no cover - handled with a clear runtime error</code> |
| L0012 | 计算并保存 &#96;pymysql&#96;（pymysql），供后续逻辑使用。 | <code>    pymysql = None</code> |
| L0013 | 计算并保存 &#96;DictCursor&#96;（DictCursor），供后续逻辑使用。 | <code>    DictCursor = None</code> |
| L0014 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0015 | 导入后续逻辑所需的模块、类或函数：&#96;from situation_core import SecurityAction, Situation, parse_timestamp&#96;。 | <code>from situation_core import SecurityAction, Situation, parse_timestamp</code> |
| L0016 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0017 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0018 | 计算并保存 &#96;MYSQL_DDL&#96;（MYSQLDDL），供后续逻辑使用。 | <code>MYSQL_DDL = [</code> |
| L0019 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """</code> |
| L0020 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>    CREATE TABLE IF NOT EXISTS security_actions (</code> |
| L0021 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      action_id VARCHAR(80) PRIMARY KEY,</code> |
| L0022 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      source_ip VARCHAR(64) NOT NULL,</code> |
| L0023 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      target_asset VARCHAR(255) NOT NULL,</code> |
| L0024 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      target_port INT NULL,</code> |
| L0025 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      target_interface VARCHAR(512) NULL,</code> |
| L0026 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      protocol VARCHAR(24) NULL,</code> |
| L0027 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      action_type VARCHAR(64) NOT NULL,</code> |
| L0028 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      stage VARCHAR(32) NOT NULL,</code> |
| L0029 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      sensor VARCHAR(64) NOT NULL,</code> |
| L0030 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      occurred_at DATETIME(3) NOT NULL,</code> |
| L0031 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      last_seen_at DATETIME(3) NOT NULL,</code> |
| L0032 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      action_count INT NOT NULL DEFAULT 1,</code> |
| L0033 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      confidence DOUBLE NOT NULL DEFAULT 0,</code> |
| L0034 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      severity VARCHAR(24) NOT NULL DEFAULT 'medium',</code> |
| L0035 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      evidence_json LONGTEXT NULL,</code> |
| L0036 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      metadata_json LONGTEXT NULL,</code> |
| L0037 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),</code> |
| L0038 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>      updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),</code> |
| L0039 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_security_action_source_time (source_ip, occurred_at),</code> |
| L0040 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_security_action_type_time (action_type, occurred_at),</code> |
| L0041 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_security_action_target_time (target_asset, occurred_at)</code> |
| L0042 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L0043 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """,</code> |
| L0044 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """</code> |
| L0045 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>    CREATE TABLE IF NOT EXISTS attack_situations (</code> |
| L0046 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      situation_id VARCHAR(80) PRIMARY KEY,</code> |
| L0047 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      source_ip VARCHAR(64) NOT NULL,</code> |
| L0048 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      target_asset VARCHAR(255) NOT NULL,</code> |
| L0049 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      started_at DATETIME(3) NOT NULL,</code> |
| L0050 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      last_action_at DATETIME(3) NOT NULL,</code> |
| L0051 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      closed_at DATETIME(3) NULL,</code> |
| L0052 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      status VARCHAR(24) NOT NULL DEFAULT 'observing',</code> |
| L0053 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      distinct_action_types INT NOT NULL DEFAULT 0,</code> |
| L0054 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      total_action_count INT NOT NULL DEFAULT 0,</code> |
| L0055 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      current_stage VARCHAR(32) NOT NULL DEFAULT 'unknown',</code> |
| L0056 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      risk_score DOUBLE NOT NULL DEFAULT 0,</code> |
| L0057 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      risk_level VARCHAR(24) NOT NULL DEFAULT 'low',</code> |
| L0058 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      sequence_hash VARCHAR(64) NOT NULL,</code> |
| L0059 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      ai_status VARCHAR(24) NOT NULL DEFAULT 'pending',</code> |
| L0060 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      ai_priority INT NOT NULL DEFAULT 0,</code> |
| L0061 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      ai_queued_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),</code> |
| L0062 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      ai_report_json LONGTEXT NULL,</code> |
| L0063 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),</code> |
| L0064 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>      updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),</code> |
| L0065 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_situation_source_time (source_ip, last_action_at),</code> |
| L0066 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_situation_status_time (status, last_action_at),</code> |
| L0067 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_situation_risk_time (risk_level, last_action_at),</code> |
| L0068 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_situation_ai_queue (ai_status, ai_priority, ai_queued_at)</code> |
| L0069 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L0070 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """,</code> |
| L0071 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """</code> |
| L0072 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>    CREATE TABLE IF NOT EXISTS situation_actions (</code> |
| L0073 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      situation_id VARCHAR(80) NOT NULL,</code> |
| L0074 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      action_id VARCHAR(80) NOT NULL,</code> |
| L0075 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      sequence_no INT NOT NULL,</code> |
| L0076 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      gap_seconds INT NOT NULL DEFAULT 0,</code> |
| L0077 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),</code> |
| L0078 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      PRIMARY KEY (situation_id, action_id),</code> |
| L0079 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      UNIQUE KEY uniq_situation_sequence (situation_id, sequence_no),</code> |
| L0080 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_situation_action_id (action_id),</code> |
| L0081 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      CONSTRAINT fk_situation_action_situation FOREIGN KEY (situation_id)</code> |
| L0082 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>        REFERENCES attack_situations(situation_id) ON DELETE CASCADE,</code> |
| L0083 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      CONSTRAINT fk_situation_action_action FOREIGN KEY (action_id)</code> |
| L0084 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>        REFERENCES security_actions(action_id) ON DELETE CASCADE</code> |
| L0085 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L0086 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """,</code> |
| L0087 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """</code> |
| L0088 | 定义或拼接 MySQL 语句，用于读取或写入业务数据。 | <code>    CREATE TABLE IF NOT EXISTS situation_outbox (</code> |
| L0089 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      id BIGINT AUTO_INCREMENT PRIMARY KEY,</code> |
| L0090 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      aggregate_type VARCHAR(32) NOT NULL,</code> |
| L0091 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      aggregate_id VARCHAR(80) NOT NULL,</code> |
| L0092 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      event_type VARCHAR(64) NOT NULL,</code> |
| L0093 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      event_key VARCHAR(160) NOT NULL,</code> |
| L0094 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      payload_json LONGTEXT NOT NULL,</code> |
| L0095 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      status VARCHAR(24) NOT NULL DEFAULT 'pending',</code> |
| L0096 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      retry_count INT NOT NULL DEFAULT 0,</code> |
| L0097 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      last_error TEXT NULL,</code> |
| L0098 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),</code> |
| L0099 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      processed_at DATETIME(3) NULL,</code> |
| L0100 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      UNIQUE KEY uniq_situation_outbox_event (event_key),</code> |
| L0101 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>      KEY idx_situation_outbox_status (status, created_at)</code> |
| L0102 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L0103 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>    """,</code> |
| L0104 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>]</code> |
| L0105 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0106 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0107 | 应用装饰器 &#96;@dataclass(frozen=True)&#96;，为下一定义附加权限、缓存或注册行为。 | <code>@dataclass(frozen=True)</code> |
| L0108 | 定义类 &#96;MySQLSettings&#96;，集中保存相关状态与操作。 | <code>class MySQLSettings:</code> |
| L0109 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于类 MySQLSettings。 | <code>    host: str = "127.0.0.1"</code> |
| L0110 | 计算并保存 &#96;port&#96;（port），供后续逻辑使用，当前位于类 MySQLSettings。 | <code>    port: int = 3306</code> |
| L0111 | 计算并保存 &#96;user&#96;（user），供后续逻辑使用，当前位于类 MySQLSettings。 | <code>    user: str = "root"</code> |
| L0112 | 控制当前循环或占位分支的执行流程，当前位于类 MySQLSettings。 | <code>    password: str = "123456"</code> |
| L0113 | 计算并保存 &#96;database&#96;（数据库），供后续逻辑使用，当前位于类 MySQLSettings。 | <code>    database: str = "traffic_pipeline"</code> |
| L0114 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0115 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0116 | 定义utcnaive函数 &#96;utc_naive&#96;，封装可复用业务逻辑。 | <code>def utc_naive(value: datetime) -&gt; datetime:</code> |
| L0117 | 结束当前函数并把结果返回给调用方，当前位于函数 utc_naive。 | <code>    return parse_timestamp(value).astimezone(timezone.utc).replace(tzinfo=None)</code> |
| L0118 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0119 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0120 | 定义jsontext函数 &#96;json_text&#96;，封装可复用业务逻辑。 | <code>def json_text(value: Any) -&gt; str:</code> |
| L0121 | 结束当前函数并把结果返回给调用方，当前位于函数 json_text。 | <code>    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)</code> |
| L0122 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0123 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0124 | 定义jsonvalue函数 &#96;json_value&#96;，封装可复用业务逻辑。 | <code>def json_value(value: Any, default: Any) -&gt; Any:</code> |
| L0125 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 json_value。 | <code>    if value is None or value == "":</code> |
| L0126 | 结束当前函数并把结果返回给调用方，当前位于函数 json_value。 | <code>        return default</code> |
| L0127 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 json_value。 | <code>    if isinstance(value, (dict, list)):</code> |
| L0128 | 结束当前函数并把结果返回给调用方，当前位于函数 json_value。 | <code>        return value</code> |
| L0129 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 json_value。 | <code>    try:</code> |
| L0130 | 结束当前函数并把结果返回给调用方，当前位于函数 json_value。 | <code>        return json.loads(value)</code> |
| L0131 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 json_value。 | <code>    except (TypeError, ValueError):</code> |
| L0132 | 结束当前函数并把结果返回给调用方，当前位于函数 json_value。 | <code>        return default</code> |
| L0133 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0134 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0135 | 定义类 &#96;MySQLSituationStore&#96;，集中保存相关状态与操作。 | <code>class MySQLSituationStore:</code> |
| L0136 | 定义init函数 &#96;__init__&#96;，封装可复用业务逻辑。 | <code>    def __init__(self, settings: MySQLSettings, connection: Any = None) -&gt; None:</code> |
| L0137 | 计算并保存 &#96;settings&#96;（settings），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.settings = settings</code> |
| L0138 | 计算并保存 &#96;_connection&#96;（connection），供后续逻辑使用，当前位于函数 __init__。 | <code>        self._connection = connection</code> |
| L0139 | 计算并保存 &#96;_owns_connection&#96;（ownsconnection），供后续逻辑使用，当前位于函数 __init__。 | <code>        self._owns_connection = connection is None</code> |
| L0140 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0141 | 定义connect函数 &#96;connect&#96;，封装可复用业务逻辑。 | <code>    def connect(self) -&gt; Any:</code> |
| L0142 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 connect。 | <code>        if self._connection is not None:</code> |
| L0143 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 connect。 | <code>            if not self._owns_connection:</code> |
| L0144 | 结束当前函数并把结果返回给调用方，当前位于函数 connect。 | <code>                return self._connection</code> |
| L0145 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 connect。 | <code>            try:</code> |
| L0146 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 connect。 | <code>                self._connection.ping(reconnect=True)</code> |
| L0147 | 结束当前函数并把结果返回给调用方，当前位于函数 connect。 | <code>                return self._connection</code> |
| L0148 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 connect。 | <code>            except Exception:</code> |
| L0149 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 connect。 | <code>                try:</code> |
| L0150 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 connect。 | <code>                    self._connection.close()</code> |
| L0151 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 connect。 | <code>                except Exception:</code> |
| L0152 | 控制当前循环或占位分支的执行流程，当前位于函数 connect。 | <code>                    pass</code> |
| L0153 | 计算并保存 &#96;_connection&#96;（connection），供后续逻辑使用，当前位于函数 connect。 | <code>                self._connection = None</code> |
| L0154 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 connect。 | <code>        if pymysql is None:</code> |
| L0155 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 connect。 | <code>            raise RuntimeError("PyMySQL 未安装，无法使用态势数据库")</code> |
| L0156 | 计算并保存 &#96;_connection&#96;（connection），供后续逻辑使用，当前位于函数 connect。 | <code>        self._connection = pymysql.connect(</code> |
| L0157 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 connect。 | <code>            host=self.settings.host,</code> |
| L0158 | 计算并保存 &#96;port&#96;（port），供后续逻辑使用，当前位于函数 connect。 | <code>            port=int(self.settings.port),</code> |
| L0159 | 计算并保存 &#96;user&#96;（user），供后续逻辑使用，当前位于函数 connect。 | <code>            user=self.settings.user,</code> |
| L0160 | 控制当前循环或占位分支的执行流程，当前位于函数 connect。 | <code>            password=self.settings.password,</code> |
| L0161 | 计算并保存 &#96;database&#96;（数据库），供后续逻辑使用，当前位于函数 connect。 | <code>            database=self.settings.database,</code> |
| L0162 | 计算并保存 &#96;charset&#96;（charset），供后续逻辑使用，当前位于函数 connect。 | <code>            charset="utf8mb4",</code> |
| L0163 | 计算并保存 &#96;autocommit&#96;（autocommit），供后续逻辑使用，当前位于函数 connect。 | <code>            autocommit=False,</code> |
| L0164 | 计算并保存 &#96;cursorclass&#96;（cursorclass），供后续逻辑使用，当前位于函数 connect。 | <code>            cursorclass=DictCursor,</code> |
| L0165 | 计算并保存 &#96;connect_timeout&#96;（connecttimeout），供后续逻辑使用，当前位于函数 connect。 | <code>            connect_timeout=5,</code> |
| L0166 | 计算并保存 &#96;read_timeout&#96;（读取timeout），供后续逻辑使用，当前位于函数 connect。 | <code>            read_timeout=15,</code> |
| L0167 | 计算并保存 &#96;write_timeout&#96;（写入timeout），供后续逻辑使用，当前位于函数 connect。 | <code>            write_timeout=15,</code> |
| L0168 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 connect。 | <code>        )</code> |
| L0169 | 结束当前函数并把结果返回给调用方，当前位于函数 connect。 | <code>        return self._connection</code> |
| L0170 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0171 | 定义close函数 &#96;close&#96;，封装可复用业务逻辑。 | <code>    def close(self) -&gt; None:</code> |
| L0172 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 close。 | <code>        if self._connection is not None:</code> |
| L0173 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 close。 | <code>            self._connection.close()</code> |
| L0174 | 计算并保存 &#96;_connection&#96;（connection），供后续逻辑使用，当前位于函数 close。 | <code>            self._connection = None</code> |
| L0175 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0176 | 定义ensureschema函数 &#96;ensure_schema&#96;，封装可复用业务逻辑。 | <code>    def ensure_schema(self) -&gt; None:</code> |
| L0177 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 ensure_schema。 | <code>        conn = self.connect()</code> |
| L0178 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 ensure_schema。 | <code>        try:</code> |
| L0179 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 ensure_schema。 | <code>            with conn.cursor() as cur:</code> |
| L0180 | 遍历集合中的数据项并逐项处理，当前位于函数 ensure_schema。 | <code>                for ddl in MYSQL_DDL:</code> |
| L0181 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>                    cur.execute(ddl)</code> |
| L0182 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>                cur.execute("SHOW COLUMNS FROM attack_situations LIKE 'ai_priority'")</code> |
| L0183 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema。 | <code>                if not cur.fetchone():</code> |
| L0184 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>                    cur.execute("ALTER TABLE attack_situations ADD COLUMN ai_priority INT NOT NULL DEFAULT 0 AFTER ai_status")</code> |
| L0185 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>                cur.execute("SHOW COLUMNS FROM attack_situations LIKE 'ai_queued_at'")</code> |
| L0186 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema。 | <code>                if not cur.fetchone():</code> |
| L0187 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>                    cur.execute(</code> |
| L0188 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema。 | <code>                        "ALTER TABLE attack_situations ADD COLUMN ai_queued_at DATETIME(3) "</code> |
| L0189 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema。 | <code>                        "NOT NULL DEFAULT CURRENT_TIMESTAMP(3) AFTER ai_priority"</code> |
| L0190 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ensure_schema。 | <code>                    )</code> |
| L0191 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>                cur.execute("SHOW INDEX FROM attack_situations WHERE Key_name='idx_situation_ai_queue'")</code> |
| L0192 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema。 | <code>                if not cur.fetchone():</code> |
| L0193 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>                    cur.execute(</code> |
| L0194 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema。 | <code>                        "ALTER TABLE attack_situations ADD INDEX idx_situation_ai_queue "</code> |
| L0195 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema。 | <code>                        "(ai_status,ai_priority,ai_queued_at)"</code> |
| L0196 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ensure_schema。 | <code>                    )</code> |
| L0197 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema。 | <code>            conn.commit()</code> |
| L0198 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 ensure_schema。 | <code>        except Exception:</code> |
| L0199 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema。 | <code>            conn.rollback()</code> |
| L0200 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema。 | <code>            raise</code> |
| L0201 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0202 | 定义upsertactions函数 &#96;upsert_actions&#96;，封装可复用业务逻辑。 | <code>    def upsert_actions(self, actions: Iterable[SecurityAction]) -&gt; int:</code> |
| L0203 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 upsert_actions。 | <code>        rows = list(actions)</code> |
| L0204 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 upsert_actions。 | <code>        if not rows:</code> |
| L0205 | 结束当前函数并把结果返回给调用方，当前位于函数 upsert_actions。 | <code>            return 0</code> |
| L0206 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_actions。 | <code>        sql = """</code> |
| L0207 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 upsert_actions。 | <code>            INSERT INTO security_actions (</code> |
| L0208 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_actions。 | <code>              action_id, source_ip, target_asset, target_port, target_interface,</code> |
| L0209 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_actions。 | <code>              protocol, action_type, stage, sensor, occurred_at, last_seen_at,</code> |
| L0210 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_actions。 | <code>              action_count, confidence, severity, evidence_json, metadata_json</code> |
| L0211 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_actions。 | <code>            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)</code> |
| L0212 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_actions。 | <code>            ON DUPLICATE KEY UPDATE</code> |
| L0213 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_actions。 | <code>              source_ip=VALUES(source_ip), target_asset=VALUES(target_asset),</code> |
| L0214 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_actions。 | <code>              target_port=VALUES(target_port), target_interface=VALUES(target_interface),</code> |
| L0215 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_actions。 | <code>              protocol=VALUES(protocol), action_type=VALUES(action_type), stage=VALUES(stage),</code> |
| L0216 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_actions。 | <code>              sensor=VALUES(sensor), occurred_at=VALUES(occurred_at),</code> |
| L0217 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_actions。 | <code>              last_seen_at=VALUES(last_seen_at), action_count=VALUES(action_count),</code> |
| L0218 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_actions。 | <code>              confidence=VALUES(confidence), severity=VALUES(severity),</code> |
| L0219 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_actions。 | <code>              evidence_json=VALUES(evidence_json), metadata_json=VALUES(metadata_json)</code> |
| L0220 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_actions。 | <code>        """</code> |
| L0221 | 计算并保存 &#96;values&#96;（values），供后续逻辑使用，当前位于函数 upsert_actions。 | <code>        values = [</code> |
| L0222 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>            (</code> |
| L0223 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>                row.action_id,</code> |
| L0224 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>                row.source_ip,</code> |
| L0225 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>                row.target_asset,</code> |
| L0226 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>                row.target_port,</code> |
| L0227 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>                row.target_interface,</code> |
| L0228 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>                row.protocol,</code> |
| L0229 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>                row.action_type,</code> |
| L0230 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>                row.stage,</code> |
| L0231 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>                row.sensor,</code> |
| L0232 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>                utc_naive(row.occurred_at),</code> |
| L0233 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>                utc_naive(row.last_seen_at or row.occurred_at),</code> |
| L0234 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>                row.count,</code> |
| L0235 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>                row.confidence,</code> |
| L0236 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>                row.severity,</code> |
| L0237 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>                json_text(row.evidence_refs),</code> |
| L0238 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>                json_text(row.metadata),</code> |
| L0239 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 upsert_actions。 | <code>            )</code> |
| L0240 | 遍历集合中的数据项并逐项处理，当前位于函数 upsert_actions。 | <code>            for row in rows</code> |
| L0241 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 upsert_actions。 | <code>        ]</code> |
| L0242 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 upsert_actions。 | <code>        conn = self.connect()</code> |
| L0243 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 upsert_actions。 | <code>        try:</code> |
| L0244 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 upsert_actions。 | <code>            with conn.cursor() as cur:</code> |
| L0245 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>                cur.executemany(sql, values)</code> |
| L0246 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>            conn.commit()</code> |
| L0247 | 结束当前函数并把结果返回给调用方，当前位于函数 upsert_actions。 | <code>            return len(rows)</code> |
| L0248 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 upsert_actions。 | <code>        except Exception:</code> |
| L0249 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>            conn.rollback()</code> |
| L0250 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_actions。 | <code>            raise</code> |
| L0251 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0252 | 定义upsert态势函数 &#96;upsert_situation&#96;，封装可复用业务逻辑。 | <code>    def upsert_situation(self, situation: Situation, emit_outbox: bool = True) -&gt; bool:</code> |
| L0253 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 upsert_situation。 | <code>        conn = self.connect()</code> |
| L0254 | 计算并保存 &#96;changed&#96;（changed），供后续逻辑使用，当前位于函数 upsert_situation。 | <code>        changed = True</code> |
| L0255 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 upsert_situation。 | <code>        try:</code> |
| L0256 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 upsert_situation。 | <code>            with conn.cursor() as cur:</code> |
| L0257 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 upsert_situation。 | <code>                cur.execute(</code> |
| L0258 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                    "SELECT sequence_hash FROM attack_situations WHERE situation_id=%s FOR UPDATE",</code> |
| L0259 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                    (situation.situation_id,),</code> |
| L0260 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 upsert_situation。 | <code>                )</code> |
| L0261 | 计算并保存 &#96;existing&#96;（existing），供后续逻辑使用，当前位于函数 upsert_situation。 | <code>                existing = cur.fetchone()</code> |
| L0262 | 计算并保存 &#96;changed&#96;（changed），供后续逻辑使用，当前位于函数 upsert_situation。 | <code>                changed = not existing or existing.get("sequence_hash") != situation.sequence_hash</code> |
| L0263 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 upsert_situation。 | <code>                cur.execute(</code> |
| L0264 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                    """</code> |
| L0265 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 upsert_situation。 | <code>                    INSERT INTO attack_situations (</code> |
| L0266 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                      situation_id, source_ip, target_asset, started_at, last_action_at,</code> |
| L0267 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                      status, distinct_action_types, total_action_count, current_stage,</code> |
| L0268 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                      risk_score, risk_level, sequence_hash, ai_status</code> |
| L0269 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)</code> |
| L0270 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                    ON DUPLICATE KEY UPDATE</code> |
| L0271 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                      source_ip=VALUES(source_ip), target_asset=VALUES(target_asset),</code> |
| L0272 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                      started_at=VALUES(started_at), last_action_at=VALUES(last_action_at),</code> |
| L0273 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                      status=IF(status='handled','handled',VALUES(status)),</code> |
| L0274 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                      distinct_action_types=VALUES(distinct_action_types),</code> |
| L0275 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                      total_action_count=VALUES(total_action_count),</code> |
| L0276 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                      current_stage=VALUES(current_stage), risk_score=VALUES(risk_score),</code> |
| L0277 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                      risk_level=VALUES(risk_level),</code> |
| L0278 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                      ai_status=IF(sequence_hash&lt;&gt;VALUES(sequence_hash),'pending',ai_status),</code> |
| L0279 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                      ai_priority=IF(sequence_hash&lt;&gt;VALUES(sequence_hash),0,ai_priority),</code> |
| L0280 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                      ai_queued_at=IF(sequence_hash&lt;&gt;VALUES(sequence_hash),UTC_TIMESTAMP(3),ai_queued_at),</code> |
| L0281 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                      ai_report_json=IF(sequence_hash&lt;&gt;VALUES(sequence_hash),NULL,ai_report_json),</code> |
| L0282 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                      sequence_hash=VALUES(sequence_hash)</code> |
| L0283 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                    """,</code> |
| L0284 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                    (</code> |
| L0285 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                        situation.situation_id,</code> |
| L0286 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                        situation.source_ip,</code> |
| L0287 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                        situation.target_asset,</code> |
| L0288 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                        utc_naive(situation.started_at),</code> |
| L0289 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                        utc_naive(situation.last_action_at),</code> |
| L0290 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                        situation.status,</code> |
| L0291 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                        situation.distinct_action_types,</code> |
| L0292 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                        situation.total_action_count,</code> |
| L0293 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                        situation.current_stage,</code> |
| L0294 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                        situation.risk_score,</code> |
| L0295 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                        situation.risk_level,</code> |
| L0296 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                        situation.sequence_hash,</code> |
| L0297 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                        "pending",</code> |
| L0298 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 upsert_situation。 | <code>                    ),</code> |
| L0299 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 upsert_situation。 | <code>                )</code> |
| L0300 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 upsert_situation。 | <code>                cur.execute("DELETE FROM situation_actions WHERE situation_id=%s", (situation.situation_id,))</code> |
| L0301 | 计算并保存 &#96;previous&#96;（previous），供后续逻辑使用，当前位于函数 upsert_situation。 | <code>                previous: Optional[SecurityAction] = None</code> |
| L0302 | 遍历集合中的数据项并逐项处理，当前位于函数 upsert_situation。 | <code>                for sequence_no, action in enumerate(situation.actions, start=1):</code> |
| L0303 | 计算并保存 &#96;gap_seconds&#96;（gapseconds），供后续逻辑使用，当前位于函数 upsert_situation。 | <code>                    gap_seconds = 0</code> |
| L0304 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 upsert_situation。 | <code>                    if previous is not None:</code> |
| L0305 | 计算并保存 &#96;gap_seconds&#96;（gapseconds），供后续逻辑使用，当前位于函数 upsert_situation。 | <code>                        gap_seconds = max(</code> |
| L0306 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                            0,</code> |
| L0307 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                            int((action.occurred_at - (previous.last_seen_at or previous.occurred_at)).total_seconds()),</code> |
| L0308 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 upsert_situation。 | <code>                        )</code> |
| L0309 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 upsert_situation。 | <code>                    cur.execute(</code> |
| L0310 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 upsert_situation。 | <code>                        """INSERT INTO situation_actions(situation_id,action_id,sequence_no,gap_seconds)</code> |
| L0311 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                           VALUES(%s,%s,%s,%s)""",</code> |
| L0312 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                        (situation.situation_id, action.action_id, sequence_no, gap_seconds),</code> |
| L0313 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 upsert_situation。 | <code>                    )</code> |
| L0314 | 计算并保存 &#96;previous&#96;（previous），供后续逻辑使用，当前位于函数 upsert_situation。 | <code>                    previous = action</code> |
| L0315 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 upsert_situation。 | <code>                if changed and emit_outbox:</code> |
| L0316 | 计算并保存 &#96;event_key&#96;（事件key），供后续逻辑使用，当前位于函数 upsert_situation。 | <code>                    event_key = f"situation:{situation.situation_id}:{situation.sequence_hash}"</code> |
| L0317 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 upsert_situation。 | <code>                    cur.execute(</code> |
| L0318 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                        """</code> |
| L0319 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 upsert_situation。 | <code>                        INSERT IGNORE INTO situation_outbox(</code> |
| L0320 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                          aggregate_type,aggregate_id,event_type,event_key,payload_json</code> |
| L0321 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                        ) VALUES('situation',%s,'situation.changed',%s,%s)</code> |
| L0322 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_situation。 | <code>                        """,</code> |
| L0323 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>                        (situation.situation_id, event_key, json_text(situation.as_dict())),</code> |
| L0324 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 upsert_situation。 | <code>                    )</code> |
| L0325 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>            conn.commit()</code> |
| L0326 | 结束当前函数并把结果返回给调用方，当前位于函数 upsert_situation。 | <code>            return changed</code> |
| L0327 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 upsert_situation。 | <code>        except Exception:</code> |
| L0328 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>            conn.rollback()</code> |
| L0329 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_situation。 | <code>            raise</code> |
| L0330 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0331 | 定义保存函数 &#96;save&#96;，封装可复用业务逻辑。 | <code>    def save(self, situations: Sequence[Situation], emit_outbox: bool = True) -&gt; Dict[str, int]:</code> |
| L0332 | 计算并保存 &#96;actions&#96;（actions），供后续逻辑使用，当前位于函数 save。 | <code>        actions = {action.action_id: action for situation in situations for action in situation.actions}</code> |
| L0333 | 计算并保存 &#96;action_count&#96;（actioncount），供后续逻辑使用，当前位于函数 save。 | <code>        action_count = self.upsert_actions(actions.values())</code> |
| L0334 | 计算并保存 &#96;changed&#96;（changed），供后续逻辑使用，当前位于函数 save。 | <code>        changed = sum(1 for item in situations if self.upsert_situation(item, emit_outbox=emit_outbox))</code> |
| L0335 | 结束当前函数并把结果返回给调用方，当前位于函数 save。 | <code>        return {"actions": action_count, "situations": len(situations), "changed": changed}</code> |
| L0336 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0337 | 定义列出situations函数 &#96;list_situations&#96;，封装可复用业务逻辑。 | <code>    def list_situations(</code> |
| L0338 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situations。 | <code>        self,</code> |
| L0339 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situations。 | <code>        *,</code> |
| L0340 | 计算并保存 &#96;limit&#96;（limit），供后续逻辑使用，当前位于函数 list_situations。 | <code>        limit: int = 50,</code> |
| L0341 | 计算并保存 &#96;offset&#96;（offset），供后续逻辑使用，当前位于函数 list_situations。 | <code>        offset: int = 0,</code> |
| L0342 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 list_situations。 | <code>        source_ip: str = "",</code> |
| L0343 | 计算并保存 &#96;status&#96;（状态），供后续逻辑使用，当前位于函数 list_situations。 | <code>        status: str = "",</code> |
| L0344 | 计算并保存 &#96;minimum_risk&#96;（minimumrisk），供后续逻辑使用，当前位于函数 list_situations。 | <code>        minimum_risk: float = 0.0,</code> |
| L0345 | 计算并保存 &#96;lookback_hours&#96;（lookbackhours），供后续逻辑使用，当前位于函数 list_situations。 | <code>        lookback_hours: int = 0,</code> |
| L0346 | 计算并保存 &#96;include_observing&#96;（includeobserving），供后续逻辑使用，当前位于函数 list_situations。 | <code>        include_observing: bool = False,</code> |
| L0347 | 计算并保存 &#96;include_ai_report&#96;（includeai报告），供后续逻辑使用，当前位于函数 list_situations。 | <code>        include_ai_report: bool = False,</code> |
| L0348 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 list_situations。 | <code>    ) -&gt; List[Dict[str, Any]]:</code> |
| L0349 | 计算并保存 &#96;where&#96;（where），供后续逻辑使用，当前位于函数 list_situations。 | <code>        where = ["risk_score &gt;= %s"]</code> |
| L0350 | 计算并保存 &#96;values&#96;（values），供后续逻辑使用，当前位于函数 list_situations。 | <code>        values: List[Any] = [max(0.0, min(1.0, float(minimum_risk)))]</code> |
| L0351 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_situations。 | <code>        if source_ip:</code> |
| L0352 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 list_situations。 | <code>            where.append("source_ip = %s")</code> |
| L0353 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 list_situations。 | <code>            values.append(source_ip)</code> |
| L0354 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_situations。 | <code>        if status:</code> |
| L0355 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 list_situations。 | <code>            where.append("status = %s")</code> |
| L0356 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 list_situations。 | <code>            values.append(status)</code> |
| L0357 | 当前一条件未命中时继续判断另一条件，当前位于函数 list_situations。 | <code>        elif not include_observing:</code> |
| L0358 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 list_situations。 | <code>            where.append("status &lt;&gt; 'observing'")</code> |
| L0359 | 计算并保存 &#96;lookback&#96;（lookback），供后续逻辑使用，当前位于函数 list_situations。 | <code>        lookback = max(0, min(24 * 30, int(lookback_hours)))</code> |
| L0360 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_situations。 | <code>        if lookback:</code> |
| L0361 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 list_situations。 | <code>            where.append("last_action_at &gt;= UTC_TIMESTAMP(3) - INTERVAL %s HOUR")</code> |
| L0362 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 list_situations。 | <code>            values.append(lookback)</code> |
| L0363 | 源码原注释：Time-bounded correlation needs more than the latest page; normal list APIs stay capped at 500. | <code>        # Time-bounded correlation needs more than the latest page; normal list APIs stay capped at 500.</code> |
| L0364 | 计算并保存 &#96;limit_cap&#96;（limitcap），供后续逻辑使用，当前位于函数 list_situations。 | <code>        limit_cap = 5000 if lookback else 500</code> |
| L0365 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 list_situations。 | <code>        values.extend([max(1, min(limit_cap, int(limit))), max(0, int(offset))])</code> |
| L0366 | 计算并保存 &#96;report_column&#96;（报告column），供后续逻辑使用，当前位于函数 list_situations。 | <code>        report_column = ",ai_report_json" if include_ai_report else ""</code> |
| L0367 | 计算并保存 &#96;sql&#96;（sql），供后续逻辑使用，当前位于函数 list_situations。 | <code>        sql = f"""</code> |
| L0368 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 list_situations。 | <code>            SELECT situation_id,source_ip,target_asset,started_at,last_action_at,status,</code> |
| L0369 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situations。 | <code>                   distinct_action_types,total_action_count,current_stage,risk_score,</code> |
| L0370 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situations。 | <code>                   risk_level,sequence_hash,ai_status{report_column}</code> |
| L0371 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situations。 | <code>            FROM attack_situations WHERE {' AND '.join(where)}</code> |
| L0372 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situations。 | <code>            ORDER BY last_action_at DESC LIMIT %s OFFSET %s</code> |
| L0373 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situations。 | <code>        """</code> |
| L0374 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 list_situations。 | <code>        conn = self.connect()</code> |
| L0375 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 list_situations。 | <code>        with conn.cursor() as cur:</code> |
| L0376 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 list_situations。 | <code>            cur.execute(sql, tuple(values))</code> |
| L0377 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 list_situations。 | <code>            rows = list(cur.fetchall())</code> |
| L0378 | 源码原注释：PyMySQL starts a transaction for SELECT when autocommit is disabled. | <code>        # PyMySQL starts a transaction for SELECT when autocommit is disabled.</code> |
| L0379 | 源码原注释：End it explicitly so long-running daemons never retain metadata locks. | <code>        # End it explicitly so long-running daemons never retain metadata locks.</code> |
| L0380 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situations。 | <code>        conn.commit()</code> |
| L0381 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_situations。 | <code>        if include_ai_report:</code> |
| L0382 | 遍历集合中的数据项并逐项处理，当前位于函数 list_situations。 | <code>            for row in rows:</code> |
| L0383 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situations。 | <code>                row["ai_report"] = json_value(row.pop("ai_report_json", None), None)</code> |
| L0384 | 结束当前函数并把结果返回给调用方，当前位于函数 list_situations。 | <code>        return rows</code> |
| L0385 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0386 | 定义列出actions函数 &#96;list_actions&#96;，封装可复用业务逻辑。 | <code>    def list_actions(</code> |
| L0387 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_actions。 | <code>        self,</code> |
| L0388 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_actions。 | <code>        *,</code> |
| L0389 | 计算并保存 &#96;lookback_days&#96;（lookbackdays），供后续逻辑使用，当前位于函数 list_actions。 | <code>        lookback_days: int = 30,</code> |
| L0390 | 计算并保存 &#96;lookback_minutes&#96;（lookbackminutes），供后续逻辑使用，当前位于函数 list_actions。 | <code>        lookback_minutes: int = 0,</code> |
| L0391 | 计算并保存 &#96;limit&#96;（limit），供后续逻辑使用，当前位于函数 list_actions。 | <code>        limit: int = 100000,</code> |
| L0392 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 list_actions。 | <code>    ) -&gt; List[SecurityAction]:</code> |
| L0393 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 list_actions。 | <code>        conn = self.connect()</code> |
| L0394 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 list_actions。 | <code>        with conn.cursor() as cur:</code> |
| L0395 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_actions。 | <code>            if int(lookback_minutes) &gt; 0:</code> |
| L0396 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 list_actions。 | <code>                cur.execute(</code> |
| L0397 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_actions。 | <code>                    """</code> |
| L0398 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 list_actions。 | <code>                    SELECT * FROM security_actions</code> |
| L0399 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_actions。 | <code>                    WHERE occurred_at &gt;= UTC_TIMESTAMP(3) - INTERVAL %s MINUTE</code> |
| L0400 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_actions。 | <code>                    ORDER BY occurred_at ASC LIMIT %s</code> |
| L0401 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_actions。 | <code>                    """,</code> |
| L0402 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_actions。 | <code>                    (max(1, int(lookback_minutes)), max(1, min(500000, int(limit)))),</code> |
| L0403 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 list_actions。 | <code>                )</code> |
| L0404 | 处理前述条件均未命中的情况，当前位于函数 list_actions。 | <code>            else:</code> |
| L0405 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 list_actions。 | <code>                cur.execute(</code> |
| L0406 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_actions。 | <code>                    """</code> |
| L0407 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 list_actions。 | <code>                    SELECT * FROM security_actions</code> |
| L0408 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_actions。 | <code>                    WHERE occurred_at &gt;= UTC_TIMESTAMP(3) - INTERVAL %s DAY</code> |
| L0409 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_actions。 | <code>                    ORDER BY occurred_at ASC LIMIT %s</code> |
| L0410 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_actions。 | <code>                    """,</code> |
| L0411 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_actions。 | <code>                    (max(1, int(lookback_days)), max(1, min(500000, int(limit)))),</code> |
| L0412 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 list_actions。 | <code>                )</code> |
| L0413 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 list_actions。 | <code>            rows = list(cur.fetchall())</code> |
| L0414 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_actions。 | <code>        conn.commit()</code> |
| L0415 | 结束当前函数并把结果返回给调用方，当前位于函数 list_actions。 | <code>        return [self._action_from_db(row) for row in rows]</code> |
| L0416 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0417 | 定义列出态势details函数 &#96;list_situation_details&#96;，封装可复用业务逻辑。 | <code>    def list_situation_details(</code> |
| L0418 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situation_details。 | <code>        self,</code> |
| L0419 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situation_details。 | <code>        *,</code> |
| L0420 | 计算并保存 &#96;limit&#96;（limit），供后续逻辑使用，当前位于函数 list_situation_details。 | <code>        limit: int = 500,</code> |
| L0421 | 计算并保存 &#96;status&#96;（状态），供后续逻辑使用，当前位于函数 list_situation_details。 | <code>        status: str = "",</code> |
| L0422 | 计算并保存 &#96;minimum_risk&#96;（minimumrisk），供后续逻辑使用，当前位于函数 list_situation_details。 | <code>        minimum_risk: float = 0.0,</code> |
| L0423 | 计算并保存 &#96;lookback_hours&#96;（lookbackhours），供后续逻辑使用，当前位于函数 list_situation_details。 | <code>        lookback_hours: int = 0,</code> |
| L0424 | 计算并保存 &#96;include_observing&#96;（includeobserving），供后续逻辑使用，当前位于函数 list_situation_details。 | <code>        include_observing: bool = False,</code> |
| L0425 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 list_situation_details。 | <code>    ) -&gt; List[Dict[str, Any]]:</code> |
| L0426 | 计算并保存 &#96;situations&#96;（situations），供后续逻辑使用，当前位于函数 list_situation_details。 | <code>        situations = self.list_situations(</code> |
| L0427 | 计算并保存 &#96;limit&#96;（limit），供后续逻辑使用，当前位于函数 list_situation_details。 | <code>            limit=limit,</code> |
| L0428 | 计算并保存 &#96;status&#96;（状态），供后续逻辑使用，当前位于函数 list_situation_details。 | <code>            status=status,</code> |
| L0429 | 计算并保存 &#96;minimum_risk&#96;（minimumrisk），供后续逻辑使用，当前位于函数 list_situation_details。 | <code>            minimum_risk=minimum_risk,</code> |
| L0430 | 计算并保存 &#96;lookback_hours&#96;（lookbackhours），供后续逻辑使用，当前位于函数 list_situation_details。 | <code>            lookback_hours=lookback_hours,</code> |
| L0431 | 计算并保存 &#96;include_observing&#96;（includeobserving），供后续逻辑使用，当前位于函数 list_situation_details。 | <code>            include_observing=include_observing,</code> |
| L0432 | 计算并保存 &#96;include_ai_report&#96;（includeai报告），供后续逻辑使用，当前位于函数 list_situation_details。 | <code>            include_ai_report=True,</code> |
| L0433 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 list_situation_details。 | <code>        )</code> |
| L0434 | 计算并保存 &#96;ids&#96;（ids），供后续逻辑使用，当前位于函数 list_situation_details。 | <code>        ids = [str(row.get("situation_id") or "") for row in situations if row.get("situation_id")]</code> |
| L0435 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_situation_details。 | <code>        if not ids:</code> |
| L0436 | 结束当前函数并把结果返回给调用方，当前位于函数 list_situation_details。 | <code>            return situations</code> |
| L0437 | 计算并保存 &#96;placeholders&#96;（placeholders），供后续逻辑使用，当前位于函数 list_situation_details。 | <code>        placeholders = ",".join(["%s"] * len(ids))</code> |
| L0438 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 list_situation_details。 | <code>        conn = self.connect()</code> |
| L0439 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 list_situation_details。 | <code>        with conn.cursor() as cur:</code> |
| L0440 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 list_situation_details。 | <code>            cur.execute(</code> |
| L0441 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situation_details。 | <code>                f"""SELECT sa.situation_id,sa.sequence_no,sa.gap_seconds,a.*</code> |
| L0442 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situation_details。 | <code>                    FROM situation_actions sa JOIN security_actions a ON a.action_id=sa.action_id</code> |
| L0443 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situation_details。 | <code>                    WHERE sa.situation_id IN ({placeholders})</code> |
| L0444 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situation_details。 | <code>                    ORDER BY sa.situation_id,sa.sequence_no""",</code> |
| L0445 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situation_details。 | <code>                tuple(ids),</code> |
| L0446 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 list_situation_details。 | <code>            )</code> |
| L0447 | 计算并保存 &#96;actions&#96;（actions），供后续逻辑使用，当前位于函数 list_situation_details。 | <code>            actions = list(cur.fetchall())</code> |
| L0448 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situation_details。 | <code>        conn.commit()</code> |
| L0449 | 计算并保存 &#96;grouped&#96;（grouped），供后续逻辑使用，当前位于函数 list_situation_details。 | <code>        grouped: Dict[str, List[Dict[str, Any]]] = {item_id: [] for item_id in ids}</code> |
| L0450 | 遍历集合中的数据项并逐项处理，当前位于函数 list_situation_details。 | <code>        for action in actions:</code> |
| L0451 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situation_details。 | <code>            action["evidence_refs"] = json_value(action.pop("evidence_json", None), [])</code> |
| L0452 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situation_details。 | <code>            action["metadata"] = json_value(action.pop("metadata_json", None), {})</code> |
| L0453 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 list_situation_details。 | <code>            grouped.setdefault(str(action.get("situation_id") or ""), []).append(action)</code> |
| L0454 | 遍历集合中的数据项并逐项处理，当前位于函数 list_situation_details。 | <code>        for situation in situations:</code> |
| L0455 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_situation_details。 | <code>            situation["actions"] = grouped.get(str(situation.get("situation_id") or ""), [])</code> |
| L0456 | 结束当前函数并把结果返回给调用方，当前位于函数 list_situation_details。 | <code>        return situations</code> |
| L0457 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0458 | 应用装饰器 &#96;@staticmethod&#96;，为下一定义附加权限、缓存或注册行为。 | <code>    @staticmethod</code> |
| L0459 | 定义actionfrom数据库函数 &#96;_action_from_db&#96;，封装可复用业务逻辑。 | <code>    def _action_from_db(row: Dict[str, Any]) -&gt; SecurityAction:</code> |
| L0460 | 计算并保存 &#96;occurred_at&#96;（occurredat），供后续逻辑使用，当前位于函数 _action_from_db。 | <code>        occurred_at = row.get("occurred_at")</code> |
| L0461 | 计算并保存 &#96;last_seen_at&#96;（lastseenat），供后续逻辑使用，当前位于函数 _action_from_db。 | <code>        last_seen_at = row.get("last_seen_at")</code> |
| L0462 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _action_from_db。 | <code>        if isinstance(occurred_at, datetime) and occurred_at.tzinfo is None:</code> |
| L0463 | 计算并保存 &#96;occurred_at&#96;（occurredat），供后续逻辑使用，当前位于函数 _action_from_db。 | <code>            occurred_at = occurred_at.replace(tzinfo=timezone.utc)</code> |
| L0464 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _action_from_db。 | <code>        if isinstance(last_seen_at, datetime) and last_seen_at.tzinfo is None:</code> |
| L0465 | 计算并保存 &#96;last_seen_at&#96;（lastseenat），供后续逻辑使用，当前位于函数 _action_from_db。 | <code>            last_seen_at = last_seen_at.replace(tzinfo=timezone.utc)</code> |
| L0466 | 结束当前函数并把结果返回给调用方，当前位于函数 _action_from_db。 | <code>        return SecurityAction(</code> |
| L0467 | 计算并保存 &#96;action_id&#96;（actionid），供后续逻辑使用，当前位于函数 _action_from_db。 | <code>            action_id=str(row.get("action_id") or ""),</code> |
| L0468 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 _action_from_db。 | <code>            source_ip=str(row.get("source_ip") or ""),</code> |
| L0469 | 计算并保存 &#96;target_asset&#96;（targetasset），供后续逻辑使用，当前位于函数 _action_from_db。 | <code>            target_asset=str(row.get("target_asset") or "local-server"),</code> |
| L0470 | 计算并保存 &#96;target_port&#96;（targetport），供后续逻辑使用，当前位于函数 _action_from_db。 | <code>            target_port=row.get("target_port"),</code> |
| L0471 | 计算并保存 &#96;target_interface&#96;（targetinterface），供后续逻辑使用，当前位于函数 _action_from_db。 | <code>            target_interface=str(row.get("target_interface") or ""),</code> |
| L0472 | 计算并保存 &#96;protocol&#96;（protocol），供后续逻辑使用，当前位于函数 _action_from_db。 | <code>            protocol=str(row.get("protocol") or ""),</code> |
| L0473 | 计算并保存 &#96;action_type&#96;（actiontype），供后续逻辑使用，当前位于函数 _action_from_db。 | <code>            action_type=str(row.get("action_type") or "UNKNOWN"),</code> |
| L0474 | 计算并保存 &#96;occurred_at&#96;（occurredat），供后续逻辑使用，当前位于函数 _action_from_db。 | <code>            occurred_at=occurred_at,</code> |
| L0475 | 计算并保存 &#96;last_seen_at&#96;（lastseenat），供后续逻辑使用，当前位于函数 _action_from_db。 | <code>            last_seen_at=last_seen_at,</code> |
| L0476 | 计算并保存 &#96;sensor&#96;（sensor），供后续逻辑使用，当前位于函数 _action_from_db。 | <code>            sensor=str(row.get("sensor") or "unknown"),</code> |
| L0477 | 计算并保存 &#96;count&#96;（count），供后续逻辑使用，当前位于函数 _action_from_db。 | <code>            count=int(row.get("action_count") or 1),</code> |
| L0478 | 计算并保存 &#96;confidence&#96;（confidence），供后续逻辑使用，当前位于函数 _action_from_db。 | <code>            confidence=float(row.get("confidence") or 0),</code> |
| L0479 | 计算并保存 &#96;severity&#96;（severity），供后续逻辑使用，当前位于函数 _action_from_db。 | <code>            severity=str(row.get("severity") or "medium"),</code> |
| L0480 | 计算并保存 &#96;evidence_refs&#96;（evidencerefs），供后续逻辑使用，当前位于函数 _action_from_db。 | <code>            evidence_refs=json_value(row.get("evidence_json"), []),</code> |
| L0481 | 计算并保存 &#96;metadata&#96;（metadata），供后续逻辑使用，当前位于函数 _action_from_db。 | <code>            metadata=json_value(row.get("metadata_json"), {}),</code> |
| L0482 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _action_from_db。 | <code>        )</code> |
| L0483 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0484 | 定义读取态势函数 &#96;get_situation&#96;，封装可复用业务逻辑。 | <code>    def get_situation(self, situation_id: str) -&gt; Optional[Dict[str, Any]]:</code> |
| L0485 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 get_situation。 | <code>        conn = self.connect()</code> |
| L0486 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 get_situation。 | <code>        with conn.cursor() as cur:</code> |
| L0487 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 get_situation。 | <code>            cur.execute("SELECT * FROM attack_situations WHERE situation_id=%s", (situation_id,))</code> |
| L0488 | 计算并保存 &#96;situation&#96;（态势），供后续逻辑使用，当前位于函数 get_situation。 | <code>            situation = cur.fetchone()</code> |
| L0489 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 get_situation。 | <code>            if not situation:</code> |
| L0490 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_situation。 | <code>                conn.commit()</code> |
| L0491 | 结束当前函数并把结果返回给调用方，当前位于函数 get_situation。 | <code>                return None</code> |
| L0492 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 get_situation。 | <code>            cur.execute(</code> |
| L0493 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 get_situation。 | <code>                """</code> |
| L0494 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 get_situation。 | <code>                SELECT sa.sequence_no,sa.gap_seconds,a.*</code> |
| L0495 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 get_situation。 | <code>                FROM situation_actions sa</code> |
| L0496 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 get_situation。 | <code>                JOIN security_actions a ON a.action_id=sa.action_id</code> |
| L0497 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 get_situation。 | <code>                WHERE sa.situation_id=%s ORDER BY sa.sequence_no</code> |
| L0498 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 get_situation。 | <code>                """,</code> |
| L0499 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_situation。 | <code>                (situation_id,),</code> |
| L0500 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 get_situation。 | <code>            )</code> |
| L0501 | 计算并保存 &#96;actions&#96;（actions），供后续逻辑使用，当前位于函数 get_situation。 | <code>            actions = list(cur.fetchall())</code> |
| L0502 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_situation。 | <code>        conn.commit()</code> |
| L0503 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_situation。 | <code>        situation["ai_report"] = json_value(situation.pop("ai_report_json", None), None)</code> |
| L0504 | 遍历集合中的数据项并逐项处理，当前位于函数 get_situation。 | <code>        for action in actions:</code> |
| L0505 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_situation。 | <code>            action["evidence_refs"] = json_value(action.pop("evidence_json", None), [])</code> |
| L0506 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_situation。 | <code>            action["metadata"] = json_value(action.pop("metadata_json", None), {})</code> |
| L0507 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_situation。 | <code>        situation["actions"] = actions</code> |
| L0508 | 结束当前函数并把结果返回给调用方，当前位于函数 get_situation。 | <code>        return situation</code> |
| L0509 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0510 | 定义列出pendingai函数 &#96;list_pending_ai&#96;，封装可复用业务逻辑。 | <code>    def list_pending_ai(self, limit: int = 10, *, recent_minutes: int = 60) -&gt; List[Dict[str, Any]]:</code> |
| L0511 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 list_pending_ai。 | <code>        conn = self.connect()</code> |
| L0512 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 list_pending_ai。 | <code>        with conn.cursor() as cur:</code> |
| L0513 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 list_pending_ai。 | <code>            cur.execute(</code> |
| L0514 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_pending_ai。 | <code>                """</code> |
| L0515 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 list_pending_ai。 | <code>                SELECT situation_id FROM attack_situations</code> |
| L0516 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_pending_ai。 | <code>                WHERE ai_status IN ('pending','retry')</code> |
| L0517 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_pending_ai。 | <code>                  AND (status IN ('open','closed') OR ai_priority &gt; 0)</code> |
| L0518 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_pending_ai。 | <code>                  AND (last_action_at &gt;= UTC_TIMESTAMP(3) - INTERVAL %s MINUTE OR ai_priority &gt; 0)</code> |
| L0519 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_pending_ai。 | <code>                ORDER BY ai_priority DESC,ai_queued_at ASC,risk_score DESC,situation_id ASC LIMIT %s</code> |
| L0520 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_pending_ai。 | <code>                """,</code> |
| L0521 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_pending_ai。 | <code>                (max(1, int(recent_minutes)), max(1, min(100, int(limit)))),</code> |
| L0522 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 list_pending_ai。 | <code>            )</code> |
| L0523 | 计算并保存 &#96;ids&#96;（ids），供后续逻辑使用，当前位于函数 list_pending_ai。 | <code>            ids = [str(row["situation_id"]) for row in cur.fetchall()]</code> |
| L0524 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_pending_ai。 | <code>        conn.commit()</code> |
| L0525 | 结束当前函数并把结果返回给调用方，当前位于函数 list_pending_ai。 | <code>        return [row for row in (self.get_situation(item_id) for item_id in ids) if row]</code> |
| L0526 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0527 | 定义读取aiqueue状态函数 &#96;get_ai_queue_status&#96;，封装可复用业务逻辑。 | <code>    def get_ai_queue_status(self, situation_id: str, *, recent_minutes: int = 1440) -&gt; Optional[Dict[str, Any]]:</code> |
| L0528 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 get_ai_queue_status。 | <code>        conn = self.connect()</code> |
| L0529 | 计算并保存 &#96;recent_minutes&#96;（recentminutes），供后续逻辑使用，当前位于函数 get_ai_queue_status。 | <code>        recent_minutes = max(1, int(recent_minutes))</code> |
| L0530 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 get_ai_queue_status。 | <code>        with conn.cursor() as cur:</code> |
| L0531 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 get_ai_queue_status。 | <code>            cur.execute(</code> |
| L0532 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>                "SELECT situation_id,ai_status,ai_priority,ai_queued_at,risk_score "</code> |
| L0533 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>                "FROM attack_situations WHERE situation_id=%s",</code> |
| L0534 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>                (situation_id,),</code> |
| L0535 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 get_ai_queue_status。 | <code>            )</code> |
| L0536 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 get_ai_queue_status。 | <code>            row = cur.fetchone()</code> |
| L0537 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 get_ai_queue_status。 | <code>            if not row:</code> |
| L0538 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>                conn.commit()</code> |
| L0539 | 结束当前函数并把结果返回给调用方，当前位于函数 get_ai_queue_status。 | <code>                return None</code> |
| L0540 | 计算并保存 &#96;status&#96;（状态），供后续逻辑使用，当前位于函数 get_ai_queue_status。 | <code>            status = str(row.get("ai_status") or "pending")</code> |
| L0541 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 get_ai_queue_status。 | <code>            if status == "processing":</code> |
| L0542 | 计算并保存 &#96;ahead&#96;（ahead），供后续逻辑使用，当前位于函数 get_ai_queue_status。 | <code>                ahead = 0</code> |
| L0543 | 当前一条件未命中时继续判断另一条件，当前位于函数 get_ai_queue_status。 | <code>            elif status in {"pending", "retry"}:</code> |
| L0544 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 get_ai_queue_status。 | <code>                cur.execute(</code> |
| L0545 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>                    "SELECT COUNT(*) AS total FROM attack_situations "</code> |
| L0546 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>                    "WHERE ai_status='processing' AND (status IN ('open','closed') OR ai_priority &gt; 0)"</code> |
| L0547 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 get_ai_queue_status。 | <code>                )</code> |
| L0548 | 计算并保存 &#96;processing_ahead&#96;（processingahead），供后续逻辑使用，当前位于函数 get_ai_queue_status。 | <code>                processing_ahead = int((cur.fetchone() or {}).get("total") or 0)</code> |
| L0549 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 get_ai_queue_status。 | <code>                cur.execute(</code> |
| L0550 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 get_ai_queue_status。 | <code>                    """SELECT COUNT(*) AS total FROM attack_situations</code> |
| L0551 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 get_ai_queue_status。 | <code>                       WHERE ai_status IN ('pending','retry') AND (status IN ('open','closed') OR ai_priority &gt; 0)</code> |
| L0552 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 get_ai_queue_status。 | <code>                         AND (last_action_at &gt;= UTC_TIMESTAMP(3) - INTERVAL %s MINUTE OR ai_priority &gt; 0)</code> |
| L0553 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 get_ai_queue_status。 | <code>                         AND (</code> |
| L0554 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 get_ai_queue_status。 | <code>                           ai_priority &gt; %s OR</code> |
| L0555 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 get_ai_queue_status。 | <code>                           (ai_priority=%s AND ai_queued_at &lt; %s) OR</code> |
| L0556 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 get_ai_queue_status。 | <code>                           (ai_priority=%s AND ai_queued_at=%s AND risk_score &gt; %s) OR</code> |
| L0557 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 get_ai_queue_status。 | <code>                           (ai_priority=%s AND ai_queued_at=%s AND risk_score=%s AND situation_id &lt; %s)</code> |
| L0558 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 get_ai_queue_status。 | <code>                         )""",</code> |
| L0559 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>                    (</code> |
| L0560 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>                        recent_minutes,</code> |
| L0561 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>                        int(row.get("ai_priority") or 0), int(row.get("ai_priority") or 0), row["ai_queued_at"],</code> |
| L0562 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>                        int(row.get("ai_priority") or 0), row["ai_queued_at"], float(row.get("risk_score") or 0),</code> |
| L0563 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>                        int(row.get("ai_priority") or 0), row["ai_queued_at"], float(row.get("risk_score") or 0), situation_id,</code> |
| L0564 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 get_ai_queue_status。 | <code>                    ),</code> |
| L0565 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 get_ai_queue_status。 | <code>                )</code> |
| L0566 | 计算并保存 &#96;ahead&#96;（ahead），供后续逻辑使用，当前位于函数 get_ai_queue_status。 | <code>                ahead = processing_ahead + int((cur.fetchone() or {}).get("total") or 0)</code> |
| L0567 | 处理前述条件均未命中的情况，当前位于函数 get_ai_queue_status。 | <code>            else:</code> |
| L0568 | 计算并保存 &#96;ahead&#96;（ahead），供后续逻辑使用，当前位于函数 get_ai_queue_status。 | <code>                ahead = 0</code> |
| L0569 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 get_ai_queue_status。 | <code>            cur.execute(</code> |
| L0570 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>                "SELECT COUNT(*) AS total FROM attack_situations "</code> |
| L0571 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>                "WHERE ai_status IN ('pending','retry','processing') "</code> |
| L0572 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>                "AND (status IN ('open','closed') OR ai_priority &gt; 0) "</code> |
| L0573 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>                "AND (ai_status='processing' OR last_action_at &gt;= UTC_TIMESTAMP(3) - INTERVAL %s MINUTE OR ai_priority &gt; 0)",</code> |
| L0574 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>                (recent_minutes,),</code> |
| L0575 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 get_ai_queue_status。 | <code>            )</code> |
| L0576 | 计算并保存 &#96;total&#96;（total），供后续逻辑使用，当前位于函数 get_ai_queue_status。 | <code>            total = int((cur.fetchone() or {}).get("total") or 0)</code> |
| L0577 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>        conn.commit()</code> |
| L0578 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>        position = ahead + 1 if status in {"pending", "retry"} else (1 if status == "processing" else 0)</code> |
| L0579 | 结束当前函数并把结果返回给调用方，当前位于函数 get_ai_queue_status。 | <code>        return {</code> |
| L0580 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>            "status": status,</code> |
| L0581 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>            "queue_ahead": ahead,</code> |
| L0582 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>            "queue_position": position,</code> |
| L0583 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>            "queue_total": total,</code> |
| L0584 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>            "priority": int(row.get("ai_priority") or 0),</code> |
| L0585 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>            "prioritized": int(row.get("ai_priority") or 0) &gt; 0,</code> |
| L0586 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_ai_queue_status。 | <code>            "progress_percent": 100 if status == "processing" else (round(100 / max(1, position)) if position else 100),</code> |
| L0587 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 get_ai_queue_status。 | <code>        }</code> |
| L0588 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0589 | 定义prioritizeai函数 &#96;prioritize_ai&#96;，封装可复用业务逻辑。 | <code>    def prioritize_ai(self, situation_id: str) -&gt; Optional[Dict[str, Any]]:</code> |
| L0590 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 prioritize_ai。 | <code>        conn = self.connect()</code> |
| L0591 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 prioritize_ai。 | <code>        try:</code> |
| L0592 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 prioritize_ai。 | <code>            with conn.cursor() as cur:</code> |
| L0593 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 prioritize_ai。 | <code>                cur.execute(</code> |
| L0594 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 prioritize_ai。 | <code>                    "SELECT ai_status,ai_priority FROM attack_situations WHERE situation_id=%s FOR UPDATE",</code> |
| L0595 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 prioritize_ai。 | <code>                    (situation_id,),</code> |
| L0596 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 prioritize_ai。 | <code>                )</code> |
| L0597 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 prioritize_ai。 | <code>                row = cur.fetchone()</code> |
| L0598 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 prioritize_ai。 | <code>                if not row:</code> |
| L0599 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 prioritize_ai。 | <code>                    conn.rollback()</code> |
| L0600 | 结束当前函数并把结果返回给调用方，当前位于函数 prioritize_ai。 | <code>                    return None</code> |
| L0601 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 prioritize_ai。 | <code>                if str(row.get("ai_status") or "") in {"pending", "retry"} and int(row.get("ai_priority") or 0) &lt;= 0:</code> |
| L0602 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 prioritize_ai。 | <code>                    cur.execute("SELECT COALESCE(MAX(ai_priority),0)+1 AS priority FROM attack_situations")</code> |
| L0603 | 计算并保存 &#96;priority&#96;（priority），供后续逻辑使用，当前位于函数 prioritize_ai。 | <code>                    priority = int((cur.fetchone() or {}).get("priority") or 1)</code> |
| L0604 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 prioritize_ai。 | <code>                    cur.execute(</code> |
| L0605 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 prioritize_ai。 | <code>                        "UPDATE attack_situations SET ai_priority=%s WHERE situation_id=%s",</code> |
| L0606 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 prioritize_ai。 | <code>                        (priority, situation_id),</code> |
| L0607 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 prioritize_ai。 | <code>                    )</code> |
| L0608 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 prioritize_ai。 | <code>            conn.commit()</code> |
| L0609 | 结束当前函数并把结果返回给调用方，当前位于函数 prioritize_ai。 | <code>            return self.get_ai_queue_status(situation_id)</code> |
| L0610 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 prioritize_ai。 | <code>        except Exception:</code> |
| L0611 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 prioritize_ai。 | <code>            conn.rollback()</code> |
| L0612 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 prioritize_ai。 | <code>            raise</code> |
| L0613 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0614 | 定义requeueai函数 &#96;requeue_ai&#96;，封装可复用业务逻辑。 | <code>    def requeue_ai(self, situation_id: str) -&gt; Optional[Dict[str, Any]]:</code> |
| L0615 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 requeue_ai。 | <code>        """Queue a fresh report without blocking the API request on the AI provider."""</code> |
| L0616 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 requeue_ai。 | <code>        conn = self.connect()</code> |
| L0617 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 requeue_ai。 | <code>        try:</code> |
| L0618 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 requeue_ai。 | <code>            with conn.cursor() as cur:</code> |
| L0619 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 requeue_ai。 | <code>                cur.execute(</code> |
| L0620 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 requeue_ai。 | <code>                    "SELECT ai_status,ai_priority FROM attack_situations WHERE situation_id=%s FOR UPDATE",</code> |
| L0621 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 requeue_ai。 | <code>                    (situation_id,),</code> |
| L0622 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 requeue_ai。 | <code>                )</code> |
| L0623 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 requeue_ai。 | <code>                row = cur.fetchone()</code> |
| L0624 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 requeue_ai。 | <code>                if not row:</code> |
| L0625 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 requeue_ai。 | <code>                    conn.rollback()</code> |
| L0626 | 结束当前函数并把结果返回给调用方，当前位于函数 requeue_ai。 | <code>                    return None</code> |
| L0627 | 计算并保存 &#96;status&#96;（状态），供后续逻辑使用，当前位于函数 requeue_ai。 | <code>                status = str(row.get("ai_status") or "")</code> |
| L0628 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 requeue_ai。 | <code>                if status == "processing":</code> |
| L0629 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 requeue_ai。 | <code>                    conn.commit()</code> |
| L0630 | 结束当前函数并把结果返回给调用方，当前位于函数 requeue_ai。 | <code>                    return self.get_ai_queue_status(situation_id)</code> |
| L0631 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 requeue_ai。 | <code>                cur.execute("SELECT COALESCE(MAX(ai_priority),0)+1 AS priority FROM attack_situations")</code> |
| L0632 | 计算并保存 &#96;priority&#96;（priority），供后续逻辑使用，当前位于函数 requeue_ai。 | <code>                priority = int((cur.fetchone() or {}).get("priority") or 1)</code> |
| L0633 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 requeue_ai。 | <code>                cur.execute(</code> |
| L0634 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 requeue_ai。 | <code>                    """UPDATE attack_situations</code> |
| L0635 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 requeue_ai。 | <code>                       SET ai_status='retry',ai_priority=%s,ai_queued_at=UTC_TIMESTAMP(3),ai_report_json=NULL</code> |
| L0636 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 requeue_ai。 | <code>                       WHERE situation_id=%s""",</code> |
| L0637 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 requeue_ai。 | <code>                    (priority, situation_id),</code> |
| L0638 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 requeue_ai。 | <code>                )</code> |
| L0639 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 requeue_ai。 | <code>            conn.commit()</code> |
| L0640 | 结束当前函数并把结果返回给调用方，当前位于函数 requeue_ai。 | <code>            return self.get_ai_queue_status(situation_id)</code> |
| L0641 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 requeue_ai。 | <code>        except Exception:</code> |
| L0642 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 requeue_ai。 | <code>            conn.rollback()</code> |
| L0643 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 requeue_ai。 | <code>            raise</code> |
| L0644 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0645 | 定义recoverinterruptedai函数 &#96;recover_interrupted_ai&#96;，封装可复用业务逻辑。 | <code>    def recover_interrupted_ai(self) -&gt; int:</code> |
| L0646 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 recover_interrupted_ai。 | <code>        """Return work abandoned by a stopped AI daemon to the pending queue."""</code> |
| L0647 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 recover_interrupted_ai。 | <code>        conn = self.connect()</code> |
| L0648 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 recover_interrupted_ai。 | <code>        try:</code> |
| L0649 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 recover_interrupted_ai。 | <code>            with conn.cursor() as cur:</code> |
| L0650 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 recover_interrupted_ai。 | <code>                affected = cur.execute("UPDATE attack_situations SET ai_status='retry' WHERE ai_status='processing'")</code> |
| L0651 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 recover_interrupted_ai。 | <code>            conn.commit()</code> |
| L0652 | 结束当前函数并把结果返回给调用方，当前位于函数 recover_interrupted_ai。 | <code>            return int(affected or 0)</code> |
| L0653 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 recover_interrupted_ai。 | <code>        except Exception:</code> |
| L0654 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 recover_interrupted_ai。 | <code>            conn.rollback()</code> |
| L0655 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 recover_interrupted_ai。 | <code>            raise</code> |
| L0656 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0657 | 定义markairetry函数 &#96;mark_ai_retry&#96;，封装可复用业务逻辑。 | <code>    def mark_ai_retry(self, situation_id: str, expected_sequence_hash: str = "") -&gt; bool:</code> |
| L0658 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 mark_ai_retry。 | <code>        conn = self.connect()</code> |
| L0659 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 mark_ai_retry。 | <code>        try:</code> |
| L0660 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 mark_ai_retry。 | <code>            with conn.cursor() as cur:</code> |
| L0661 | 计算并保存 &#96;sql&#96;（sql），供后续逻辑使用，当前位于函数 mark_ai_retry。 | <code>                sql = "UPDATE attack_situations SET ai_status='retry' WHERE situation_id=%s AND ai_status='processing'"</code> |
| L0662 | 计算并保存 &#96;params&#96;（params），供后续逻辑使用，当前位于函数 mark_ai_retry。 | <code>                params: List[Any] = [situation_id]</code> |
| L0663 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 mark_ai_retry。 | <code>                if expected_sequence_hash:</code> |
| L0664 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 mark_ai_retry。 | <code>                    sql += " AND sequence_hash=%s"</code> |
| L0665 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 mark_ai_retry。 | <code>                    params.append(expected_sequence_hash)</code> |
| L0666 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 mark_ai_retry。 | <code>                affected = cur.execute(sql, tuple(params))</code> |
| L0667 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 mark_ai_retry。 | <code>            conn.commit()</code> |
| L0668 | 结束当前函数并把结果返回给调用方，当前位于函数 mark_ai_retry。 | <code>            return bool(affected)</code> |
| L0669 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 mark_ai_retry。 | <code>        except Exception:</code> |
| L0670 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 mark_ai_retry。 | <code>            conn.rollback()</code> |
| L0671 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 mark_ai_retry。 | <code>            raise</code> |
| L0672 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0673 | 定义markaiprocessing函数 &#96;mark_ai_processing&#96;，封装可复用业务逻辑。 | <code>    def mark_ai_processing(self, situation_id: str, expected_sequence_hash: str = "") -&gt; bool:</code> |
| L0674 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 mark_ai_processing。 | <code>        conn = self.connect()</code> |
| L0675 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 mark_ai_processing。 | <code>        try:</code> |
| L0676 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 mark_ai_processing。 | <code>            with conn.cursor() as cur:</code> |
| L0677 | 计算并保存 &#96;sql&#96;（sql），供后续逻辑使用，当前位于函数 mark_ai_processing。 | <code>                sql = "UPDATE attack_situations SET ai_status='processing' WHERE situation_id=%s AND ai_status IN ('pending','retry')"</code> |
| L0678 | 计算并保存 &#96;params&#96;（params），供后续逻辑使用，当前位于函数 mark_ai_processing。 | <code>                params: List[Any] = [situation_id]</code> |
| L0679 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 mark_ai_processing。 | <code>                if expected_sequence_hash:</code> |
| L0680 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 mark_ai_processing。 | <code>                    sql += " AND sequence_hash=%s"</code> |
| L0681 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 mark_ai_processing。 | <code>                    params.append(expected_sequence_hash)</code> |
| L0682 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 mark_ai_processing。 | <code>                affected = cur.execute(sql, tuple(params))</code> |
| L0683 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 mark_ai_processing。 | <code>            conn.commit()</code> |
| L0684 | 结束当前函数并把结果返回给调用方，当前位于函数 mark_ai_processing。 | <code>            return bool(affected)</code> |
| L0685 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 mark_ai_processing。 | <code>        except Exception:</code> |
| L0686 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 mark_ai_processing。 | <code>            conn.rollback()</code> |
| L0687 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 mark_ai_processing。 | <code>            raise</code> |
| L0688 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0689 | 定义更新ai报告函数 &#96;update_ai_report&#96;，封装可复用业务逻辑。 | <code>    def update_ai_report(</code> |
| L0690 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_ai_report。 | <code>        self,</code> |
| L0691 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_ai_report。 | <code>        situation_id: str,</code> |
| L0692 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_ai_report。 | <code>        report: Dict[str, Any],</code> |
| L0693 | 计算并保存 &#96;status&#96;（状态），供后续逻辑使用，当前位于函数 update_ai_report。 | <code>        status: str = "complete",</code> |
| L0694 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_ai_report。 | <code>        *,</code> |
| L0695 | 计算并保存 &#96;expected_sequence_hash&#96;（expectedsequencehash），供后续逻辑使用，当前位于函数 update_ai_report。 | <code>        expected_sequence_hash: str = "",</code> |
| L0696 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 update_ai_report。 | <code>    ) -&gt; bool:</code> |
| L0697 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 update_ai_report。 | <code>        conn = self.connect()</code> |
| L0698 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 update_ai_report。 | <code>        try:</code> |
| L0699 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 update_ai_report。 | <code>            with conn.cursor() as cur:</code> |
| L0700 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 update_ai_report。 | <code>                if expected_sequence_hash:</code> |
| L0701 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 update_ai_report。 | <code>                    affected = cur.execute(</code> |
| L0702 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 update_ai_report。 | <code>                        """UPDATE attack_situations SET ai_status=%s,ai_priority=0,ai_report_json=%s</code> |
| L0703 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 update_ai_report。 | <code>                           WHERE situation_id=%s AND sequence_hash=%s""",</code> |
| L0704 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_ai_report。 | <code>                        (status, json_text(report), situation_id, expected_sequence_hash),</code> |
| L0705 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 update_ai_report。 | <code>                    )</code> |
| L0706 | 处理前述条件均未命中的情况，当前位于函数 update_ai_report。 | <code>                else:</code> |
| L0707 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 update_ai_report。 | <code>                    affected = cur.execute(</code> |
| L0708 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_ai_report。 | <code>                        "UPDATE attack_situations SET ai_status=%s,ai_priority=0,ai_report_json=%s WHERE situation_id=%s",</code> |
| L0709 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_ai_report。 | <code>                        (status, json_text(report), situation_id),</code> |
| L0710 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 update_ai_report。 | <code>                    )</code> |
| L0711 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_ai_report。 | <code>            conn.commit()</code> |
| L0712 | 结束当前函数并把结果返回给调用方，当前位于函数 update_ai_report。 | <code>            return bool(affected)</code> |
| L0713 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 update_ai_report。 | <code>        except Exception:</code> |
| L0714 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_ai_report。 | <code>            conn.rollback()</code> |
| L0715 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_ai_report。 | <code>            raise</code> |
| L0716 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0717 | 定义更新状态函数 &#96;update_status&#96;，封装可复用业务逻辑。 | <code>    def update_status(self, situation_id: str, status: str) -&gt; bool:</code> |
| L0718 | 计算并保存 &#96;allowed&#96;（allowed），供后续逻辑使用，当前位于函数 update_status。 | <code>        allowed = {"observing", "open", "closed", "handled", "ignored"}</code> |
| L0719 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 update_status。 | <code>        if status not in allowed:</code> |
| L0720 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 update_status。 | <code>            raise ValueError(f"不支持的态势状态: {status}")</code> |
| L0721 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 update_status。 | <code>        conn = self.connect()</code> |
| L0722 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 update_status。 | <code>        try:</code> |
| L0723 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 update_status。 | <code>            with conn.cursor() as cur:</code> |
| L0724 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 update_status。 | <code>                affected = cur.execute(</code> |
| L0725 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 update_status。 | <code>                    """UPDATE attack_situations</code> |
| L0726 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 update_status。 | <code>                       SET status=%s,closed_at=IF(%s IN ('closed','handled','ignored'),UTC_TIMESTAMP(3),NULL)</code> |
| L0727 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 update_status。 | <code>                       WHERE situation_id=%s""",</code> |
| L0728 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_status。 | <code>                    (status, status, situation_id),</code> |
| L0729 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 update_status。 | <code>                )</code> |
| L0730 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_status。 | <code>            conn.commit()</code> |
| L0731 | 结束当前函数并把结果返回给调用方，当前位于函数 update_status。 | <code>            return bool(affected)</code> |
| L0732 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 update_status。 | <code>        except Exception:</code> |
| L0733 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_status。 | <code>            conn.rollback()</code> |
| L0734 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_status。 | <code>            raise</code> |
