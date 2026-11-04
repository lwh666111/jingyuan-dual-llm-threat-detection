# `scripts/build_rag_db.py` 逐行注释

**脚本用途：** 从种子知识文件构建兼容的本地 RAG 索引。

**源码行数：** 85　**函数/类数量：** 4

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0002 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import sqlite3&#96;。 | <code>import sqlite3</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, List&#96;。 | <code>from typing import Any, Dict, List</code> |
| L0006 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0007 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0008 | 定义读取seed函数 &#96;read_seed&#96;，封装可复用业务逻辑。 | <code>def read_seed(path: Path) -&gt; List[Dict[str, Any]]:</code> |
| L0009 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_seed。 | <code>    if not path.exists():</code> |
| L0010 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 read_seed。 | <code>        raise FileNotFoundError(f"seed file not found: {path}")</code> |
| L0011 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 read_seed。 | <code>    data = json.loads(path.read_text(encoding="utf-8"))</code> |
| L0012 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_seed。 | <code>    if not isinstance(data, list):</code> |
| L0013 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 read_seed。 | <code>        raise ValueError("seed JSON must be an array")</code> |
| L0014 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 read_seed。 | <code>    rows: List[Dict[str, Any]] = []</code> |
| L0015 | 遍历集合中的数据项并逐项处理，当前位于函数 read_seed。 | <code>    for idx, row in enumerate(data, start=1):</code> |
| L0016 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_seed。 | <code>        if not isinstance(row, dict):</code> |
| L0017 | 控制当前循环或占位分支的执行流程，当前位于函数 read_seed。 | <code>            continue</code> |
| L0018 | 计算并保存 &#96;doc_id&#96;（docid），供后续逻辑使用，当前位于函数 read_seed。 | <code>        doc_id = str(row.get("doc_id") or f"DOC-{idx:04d}")</code> |
| L0019 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 read_seed。 | <code>        rows.append(</code> |
| L0020 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_seed。 | <code>            {</code> |
| L0021 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_seed。 | <code>                "doc_id": doc_id,</code> |
| L0022 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_seed。 | <code>                "title": str(row.get("title") or ""),</code> |
| L0023 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_seed。 | <code>                "tags": str(row.get("tags") or ""),</code> |
| L0024 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_seed。 | <code>                "attack_type": str(row.get("attack_type") or ""),</code> |
| L0025 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_seed。 | <code>                "content": str(row.get("content") or ""),</code> |
| L0026 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_seed。 | <code>                "evidence": str(row.get("evidence") or ""),</code> |
| L0027 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_seed。 | <code>                "mitigation": str(row.get("mitigation") or ""),</code> |
| L0028 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_seed。 | <code>                "severity": str(row.get("severity") or "medium"),</code> |
| L0029 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_seed。 | <code>                "source": str(row.get("source") or "local_seed"),</code> |
| L0030 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 read_seed。 | <code>            }</code> |
| L0031 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 read_seed。 | <code>        )</code> |
| L0032 | 结束当前函数并把结果返回给调用方，当前位于函数 read_seed。 | <code>    return rows</code> |
| L0033 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0034 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0035 | 定义构建rag数据库函数 &#96;build_rag_db&#96;，封装可复用业务逻辑。 | <code>def build_rag_db(db_path: Path, seed_rows: List[Dict[str, Any]]) -&gt; int:</code> |
| L0036 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_rag_db。 | <code>    db_path.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0037 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 build_rag_db。 | <code>    with sqlite3.connect(str(db_path)) as conn:</code> |
| L0038 | 计算并保存 &#96;cur&#96;（cur），供后续逻辑使用，当前位于函数 build_rag_db。 | <code>        cur = conn.cursor()</code> |
| L0039 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 build_rag_db。 | <code>        cur.execute("DROP TABLE IF EXISTS rag_docs")</code> |
| L0040 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 build_rag_db。 | <code>        cur.execute(</code> |
| L0041 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_rag_db。 | <code>            """</code> |
| L0042 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_rag_db。 | <code>            CREATE VIRTUAL TABLE rag_docs USING fts5(</code> |
| L0043 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_rag_db。 | <code>              doc_id UNINDEXED,</code> |
| L0044 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_rag_db。 | <code>              title,</code> |
| L0045 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_rag_db。 | <code>              tags,</code> |
| L0046 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_rag_db。 | <code>              attack_type,</code> |
| L0047 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_rag_db。 | <code>              content,</code> |
| L0048 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_rag_db。 | <code>              evidence,</code> |
| L0049 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_rag_db。 | <code>              mitigation,</code> |
| L0050 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_rag_db。 | <code>              severity UNINDEXED,</code> |
| L0051 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_rag_db。 | <code>              source UNINDEXED,</code> |
| L0052 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_rag_db。 | <code>              tokenize='unicode61'</code> |
| L0053 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_rag_db。 | <code>            )</code> |
| L0054 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_rag_db。 | <code>            """</code> |
| L0055 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_rag_db。 | <code>        )</code> |
| L0056 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_rag_db。 | <code>        cur.executemany(</code> |
| L0057 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_rag_db。 | <code>            """</code> |
| L0058 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 build_rag_db。 | <code>            INSERT INTO rag_docs(doc_id, title, tags, attack_type, content, evidence, mitigation, severity, source)</code> |
| L0059 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_rag_db。 | <code>            VALUES(:doc_id, :title, :tags, :attack_type, :content, :evidence, :mitigation, :severity, :source)</code> |
| L0060 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 build_rag_db。 | <code>            """,</code> |
| L0061 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_rag_db。 | <code>            seed_rows,</code> |
| L0062 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_rag_db。 | <code>        )</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_rag_db。 | <code>        conn.commit()</code> |
| L0064 | 结束当前函数并把结果返回给调用方，当前位于函数 build_rag_db。 | <code>    return len(seed_rows)</code> |
| L0065 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0066 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0067 | 定义解析args函数 &#96;parse_args&#96;，封装可复用业务逻辑。 | <code>def parse_args() -&gt; argparse.Namespace:</code> |
| L0068 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 parse_args。 | <code>    parser = argparse.ArgumentParser(description="Build SQLite FTS5 RAG knowledge database")</code> |
| L0069 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--seed-file", default="llm/rag/rag_seed.json", help="RAG seed JSON file path")</code> |
| L0070 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--db-path", default="llm/rag/rag_knowledge.db", help="output sqlite db path")</code> |
| L0071 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_args。 | <code>    return parser.parse_args()</code> |
| L0072 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0073 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0074 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; None:</code> |
| L0075 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parse_args()</code> |
| L0076 | 计算并保存 &#96;project_root&#96;（projectroot），供后续逻辑使用，当前位于函数 main。 | <code>    project_root = Path(__file__).resolve().parent.parent</code> |
| L0077 | 计算并保存 &#96;seed_path&#96;（seedpath），供后续逻辑使用，当前位于函数 main。 | <code>    seed_path = (project_root / args.seed_file).resolve()</code> |
| L0078 | 计算并保存 &#96;db_path&#96;（数据库path），供后续逻辑使用，当前位于函数 main。 | <code>    db_path = (project_root / args.db_path).resolve()</code> |
| L0079 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 main。 | <code>    rows = read_seed(seed_path)</code> |
| L0080 | 计算并保存 &#96;count&#96;（count），供后续逻辑使用，当前位于函数 main。 | <code>    count = build_rag_db(db_path, rows)</code> |
| L0081 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"RAG DB built: {db_path} rows={count}", flush=True)</code> |
| L0082 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0083 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0084 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0085 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
