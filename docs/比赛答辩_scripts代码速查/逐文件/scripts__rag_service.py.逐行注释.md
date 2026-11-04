# `scripts/rag_service.py` 逐行注释

**脚本用途：** RAG 知识库核心：文档解析、切片、向量化、召回、重排、阈值判断和回归评估。

**源码行数：** 1068　**函数/类数量：** 38

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>"""Advanced RAG knowledge-base service used by the dashboard and analyzers.</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>MySQL stores auditable metadata and chunk text. LanceDB stores vectors. Cloud</code> |
| L0004 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>calls are limited to embedding and reranking so the existing Ollama report</code> |
| L0005 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>generation path remains unchanged.</code> |
| L0006 | 定义多行文本、提示词、模板或 SQL 片段。 | <code>"""</code> |
| L0007 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0009 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;import hashlib&#96;。 | <code>import hashlib</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0012 | 导入后续逻辑所需的模块、类或函数：&#96;import math&#96;。 | <code>import math</code> |
| L0013 | 导入后续逻辑所需的模块、类或函数：&#96;import os&#96;。 | <code>import os</code> |
| L0014 | 导入后续逻辑所需的模块、类或函数：&#96;import re&#96;。 | <code>import re</code> |
| L0015 | 导入后续逻辑所需的模块、类或函数：&#96;import shutil&#96;。 | <code>import shutil</code> |
| L0016 | 导入后续逻辑所需的模块、类或函数：&#96;import time&#96;。 | <code>import time</code> |
| L0017 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.error&#96;。 | <code>import urllib.error</code> |
| L0018 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.request&#96;。 | <code>import urllib.request</code> |
| L0019 | 导入后续逻辑所需的模块、类或函数：&#96;import uuid&#96;。 | <code>import uuid</code> |
| L0020 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime&#96;。 | <code>from datetime import datetime</code> |
| L0021 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0022 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, List, Optional, Sequence, Tuple&#96;。 | <code>from typing import Any, Dict, List, Optional, Sequence, Tuple</code> |
| L0023 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0024 | 导入后续逻辑所需的模块、类或函数：&#96;import pymysql&#96;。 | <code>import pymysql</code> |
| L0025 | 导入后续逻辑所需的模块、类或函数：&#96;from pymysql.cursors import DictCursor&#96;。 | <code>from pymysql.cursors import DictCursor</code> |
| L0026 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0027 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0028 | 处理向量、相似度或重排结果，属于 RAG 检索链路。 | <code>DEFAULT_EMBEDDING_MODEL = "text-embedding-v4"</code> |
| L0029 | 处理向量、相似度或重排结果，属于 RAG 检索链路。 | <code>DEFAULT_RERANK_MODEL = "qwen3-rerank"</code> |
| L0030 | 计算并保存 &#96;SUPPORTED_EXTENSIONS&#96;（SUPPORTEDEXTENSIONS），供后续逻辑使用。 | <code>SUPPORTED_EXTENSIONS = {"txt", "md", "json", "jsonl", "csv", "pdf", "docx", "pptx", "xlsx"}</code> |
| L0031 | 计算并保存 &#96;MAX_UPLOAD_BYTES&#96;（MAXUPLOADBYTES），供后续逻辑使用。 | <code>MAX_UPLOAD_BYTES = 30 * 1024 * 1024</code> |
| L0032 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0033 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0034 | 定义utctext函数 &#96;utc_text&#96;，封装可复用业务逻辑。 | <code>def utc_text() -&gt; str:</code> |
| L0035 | 结束当前函数并把结果返回给调用方，当前位于函数 utc_text。 | <code>    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")</code> |
| L0036 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0037 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0038 | 定义safefilename函数 &#96;safe_filename&#96;，封装可复用业务逻辑。 | <code>def safe_filename(name: str) -&gt; str:</code> |
| L0039 | 计算并保存 &#96;stem&#96;（stem），供后续逻辑使用，当前位于函数 safe_filename。 | <code>    stem = re.sub(r"[^0-9A-Za-z._\-\u4e00-\u9fff]+", "_", Path(name or "document.txt").name)</code> |
| L0040 | 结束当前函数并把结果返回给调用方，当前位于函数 safe_filename。 | <code>    return stem[:160] or "document.txt"</code> |
| L0041 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0042 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0043 | 定义mysqlconnect函数 &#96;mysql_connect&#96;，封装可复用业务逻辑。 | <code>def mysql_connect(conf: Dict[str, Any], autocommit: bool = False):</code> |
| L0044 | 结束当前函数并把结果返回给调用方，当前位于函数 mysql_connect。 | <code>    return pymysql.connect(</code> |
| L0045 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 mysql_connect。 | <code>        host=conf["host"],</code> |
| L0046 | 计算并保存 &#96;port&#96;（port），供后续逻辑使用，当前位于函数 mysql_connect。 | <code>        port=int(conf["port"]),</code> |
| L0047 | 计算并保存 &#96;user&#96;（user），供后续逻辑使用，当前位于函数 mysql_connect。 | <code>        user=conf["user"],</code> |
| L0048 | 控制当前循环或占位分支的执行流程，当前位于函数 mysql_connect。 | <code>        password=conf["password"],</code> |
| L0049 | 计算并保存 &#96;database&#96;（数据库），供后续逻辑使用，当前位于函数 mysql_connect。 | <code>        database=conf["database"],</code> |
| L0050 | 计算并保存 &#96;charset&#96;（charset），供后续逻辑使用，当前位于函数 mysql_connect。 | <code>        charset="utf8mb4",</code> |
| L0051 | 计算并保存 &#96;cursorclass&#96;（cursorclass），供后续逻辑使用，当前位于函数 mysql_connect。 | <code>        cursorclass=DictCursor,</code> |
| L0052 | 计算并保存 &#96;autocommit&#96;（autocommit），供后续逻辑使用，当前位于函数 mysql_connect。 | <code>        autocommit=autocommit,</code> |
| L0053 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 mysql_connect。 | <code>    )</code> |
| L0054 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0055 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0056 | 定义加载接口配置函数 &#96;load_api_config&#96;，封装可复用业务逻辑。 | <code>def load_api_config(path: Path) -&gt; Dict[str, Any]:</code> |
| L0057 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 load_api_config。 | <code>    payload: Dict[str, Any] = {}</code> |
| L0058 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_api_config。 | <code>    if path.exists():</code> |
| L0059 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 load_api_config。 | <code>        payload = json.loads(path.read_text(encoding="utf-8-sig"))</code> |
| L0060 | 计算并保存 &#96;api_key&#96;（接口key），供后续逻辑使用，当前位于函数 load_api_config。 | <code>    api_key = str(os.environ.get("DASHSCOPE_API_KEY") or payload.get("api_key") or "").strip()</code> |
| L0061 | 计算并保存 &#96;base_url&#96;（baseurl），供后续逻辑使用，当前位于函数 load_api_config。 | <code>    base_url = str(</code> |
| L0062 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_api_config。 | <code>        os.environ.get("DASHSCOPE_BASE_URL")</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_api_config。 | <code>        or payload.get("base_url")</code> |
| L0064 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_api_config。 | <code>        or "https://dashscope.aliyuncs.com/compatible-mode/v1"</code> |
| L0065 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_api_config。 | <code>    ).rstrip("/")</code> |
| L0066 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 load_api_config。 | <code>    rerank_url = str(</code> |
| L0067 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 load_api_config。 | <code>        os.environ.get("DASHSCOPE_RERANK_URL")</code> |
| L0068 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 load_api_config。 | <code>        or payload.get("rerank_url")</code> |
| L0069 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 load_api_config。 | <code>        or base_url.replace("/compatible-mode/v1", "/compatible-api/v1/reranks")</code> |
| L0070 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_api_config。 | <code>    ).rstrip("/")</code> |
| L0071 | 结束当前函数并把结果返回给调用方，当前位于函数 load_api_config。 | <code>    return {</code> |
| L0072 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_api_config。 | <code>        "api_key": api_key,</code> |
| L0073 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_api_config。 | <code>        "base_url": base_url,</code> |
| L0074 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 load_api_config。 | <code>        "rerank_url": rerank_url,</code> |
| L0075 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 load_api_config。 | <code>        "embedding_model": str(payload.get("embedding_model") or DEFAULT_EMBEDDING_MODEL),</code> |
| L0076 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 load_api_config。 | <code>        "rerank_model": str(payload.get("rerank_model") or DEFAULT_RERANK_MODEL),</code> |
| L0077 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 load_api_config。 | <code>        "embedding_dimensions": int(payload.get("embedding_dimensions") or 1024),</code> |
| L0078 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_api_config。 | <code>        "timeout_seconds": int(payload.get("timeout_seconds") or 90),</code> |
| L0079 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_api_config。 | <code>    }</code> |
| L0080 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0081 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0082 | 定义postjson函数 &#96;_post_json&#96;，封装可复用业务逻辑。 | <code>def _post_json(url: str, api_key: str, payload: Dict[str, Any], timeout: int) -&gt; Dict[str, Any]:</code> |
| L0083 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _post_json。 | <code>    if not api_key:</code> |
| L0084 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 _post_json。 | <code>        raise RuntimeError("DashScope API Key 未配置")</code> |
| L0085 | 计算并保存 &#96;req&#96;（req），供后续逻辑使用，当前位于函数 _post_json。 | <code>    req = urllib.request.Request(</code> |
| L0086 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _post_json。 | <code>        url,</code> |
| L0087 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 _post_json。 | <code>        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),</code> |
| L0088 | 计算并保存 &#96;headers&#96;（headers），供后续逻辑使用，当前位于函数 _post_json。 | <code>        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},</code> |
| L0089 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 _post_json。 | <code>        method="POST",</code> |
| L0090 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _post_json。 | <code>    )</code> |
| L0091 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _post_json。 | <code>    try:</code> |
| L0092 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 _post_json。 | <code>        with urllib.request.urlopen(req, timeout=timeout) as resp:</code> |
| L0093 | 结束当前函数并把结果返回给调用方，当前位于函数 _post_json。 | <code>            return json.loads(resp.read().decode("utf-8"))</code> |
| L0094 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _post_json。 | <code>    except urllib.error.HTTPError as exc:</code> |
| L0095 | 计算并保存 &#96;detail&#96;（detail），供后续逻辑使用，当前位于函数 _post_json。 | <code>        detail = exc.read().decode("utf-8", errors="replace")[:500]</code> |
| L0096 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 _post_json。 | <code>        raise RuntimeError(f"DashScope HTTP {exc.code}: {detail}") from exc</code> |
| L0097 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _post_json。 | <code>    except urllib.error.URLError as exc:</code> |
| L0098 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 _post_json。 | <code>        raise RuntimeError(f"DashScope 连接失败: {exc.reason}") from exc</code> |
| L0099 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0100 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0101 | 定义向量化texts函数 &#96;embed_texts&#96;，封装可复用业务逻辑。 | <code>def embed_texts(texts: Sequence[str], config: Dict[str, Any]) -&gt; List[List[float]]:</code> |
| L0102 | 计算并保存 &#96;clean&#96;（clean），供后续逻辑使用，当前位于函数 embed_texts。 | <code>    clean = [str(x or "")[:8192] for x in texts]</code> |
| L0103 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 embed_texts。 | <code>    result: List[List[float]] = []</code> |
| L0104 | 遍历集合中的数据项并逐项处理，当前位于函数 embed_texts。 | <code>    for offset in range(0, len(clean), 10):</code> |
| L0105 | 计算并保存 &#96;batch&#96;（batch），供后续逻辑使用，当前位于函数 embed_texts。 | <code>        batch = clean[offset : offset + 10]</code> |
| L0106 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 embed_texts。 | <code>        data = _post_json(</code> |
| L0107 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 embed_texts。 | <code>            f"{config['base_url']}/embeddings",</code> |
| L0108 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 embed_texts。 | <code>            config["api_key"],</code> |
| L0109 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 embed_texts。 | <code>            {"model": config["embedding_model"], "input": batch, "dimensions": config["embedding_dimensions"]},</code> |
| L0110 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 embed_texts。 | <code>            config["timeout_seconds"],</code> |
| L0111 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 embed_texts。 | <code>        )</code> |
| L0112 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 embed_texts。 | <code>        rows = sorted(data.get("data") or [], key=lambda x: int(x.get("index", 0)))</code> |
| L0113 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 embed_texts。 | <code>        if len(rows) != len(batch):</code> |
| L0114 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 embed_texts。 | <code>            raise RuntimeError("向量接口返回数量与输入不一致")</code> |
| L0115 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 embed_texts。 | <code>        result.extend([[float(v) for v in row["embedding"]] for row in rows])</code> |
| L0116 | 结束当前函数并把结果返回给调用方，当前位于函数 embed_texts。 | <code>    return result</code> |
| L0117 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0118 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0119 | 定义重排函数 &#96;rerank&#96;，封装可复用业务逻辑。 | <code>def rerank(query: str, documents: Sequence[str], config: Dict[str, Any], top_n: int) -&gt; List[Dict[str, Any]]:</code> |
| L0120 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 rerank。 | <code>    if not documents:</code> |
| L0121 | 结束当前函数并把结果返回给调用方，当前位于函数 rerank。 | <code>        return []</code> |
| L0122 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 rerank。 | <code>    payload = {</code> |
| L0123 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 rerank。 | <code>        "model": config["rerank_model"],</code> |
| L0124 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rerank。 | <code>        "query": query[:4096],</code> |
| L0125 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rerank。 | <code>        "documents": [str(x or "")[:8192] for x in documents],</code> |
| L0126 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rerank。 | <code>        "top_n": min(max(1, top_n), len(documents)),</code> |
| L0127 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 rerank。 | <code>        "return_documents": False,</code> |
| L0128 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 rerank。 | <code>    }</code> |
| L0129 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 rerank。 | <code>    data = _post_json(config["rerank_url"], config["api_key"], payload, config["timeout_seconds"])</code> |
| L0130 | 结束当前函数并把结果返回给调用方，当前位于函数 rerank。 | <code>    return list((data.get("output") or {}).get("results") or data.get("results") or [])</code> |
| L0131 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0132 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0133 | 定义ensureschema函数 &#96;ensure_schema&#96;，封装可复用业务逻辑。 | <code>def ensure_schema(conn: Any) -&gt; None:</code> |
| L0134 | 计算并保存 &#96;statements&#96;（statements），供后续逻辑使用，当前位于函数 ensure_schema。 | <code>    statements = [</code> |
| L0135 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """</code> |
| L0136 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>        CREATE TABLE IF NOT EXISTS rag_knowledge_bases (</code> |
| L0137 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          id BIGINT PRIMARY KEY AUTO_INCREMENT,</code> |
| L0138 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          name VARCHAR(160) NOT NULL,</code> |
| L0139 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          description TEXT NULL,</code> |
| L0140 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          embedding_model VARCHAR(80) NOT NULL DEFAULT 'text-embedding-v4',</code> |
| L0141 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          rerank_model VARCHAR(80) NOT NULL DEFAULT 'qwen3-rerank',</code> |
| L0142 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          chunk_method VARCHAR(32) NOT NULL DEFAULT 'semantic',</code> |
| L0143 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          chunk_size INT NOT NULL DEFAULT 900,</code> |
| L0144 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          chunk_overlap INT NOT NULL DEFAULT 120,</code> |
| L0145 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          vector_top_k INT NOT NULL DEFAULT 20,</code> |
| L0146 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          keyword_top_k INT NOT NULL DEFAULT 20,</code> |
| L0147 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          final_top_k INT NOT NULL DEFAULT 5,</code> |
| L0148 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          score_threshold DECIMAL(8,6) NOT NULL DEFAULT 0.100000,</code> |
| L0149 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          enabled TINYINT(1) NOT NULL DEFAULT 1,</code> |
| L0150 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          scope_mode VARCHAR(20) NOT NULL DEFAULT 'all',</code> |
| L0151 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          created_by VARCHAR(80) NOT NULL DEFAULT 'system',</code> |
| L0152 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0153 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,</code> |
| L0154 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          UNIQUE KEY uk_rag_kb_name(name)</code> |
| L0155 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4</code> |
| L0156 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """,</code> |
| L0157 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """</code> |
| L0158 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>        CREATE TABLE IF NOT EXISTS rag_documents (</code> |
| L0159 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          id BIGINT PRIMARY KEY AUTO_INCREMENT,</code> |
| L0160 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          kb_id BIGINT NOT NULL,</code> |
| L0161 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          name VARCHAR(255) NOT NULL,</code> |
| L0162 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          source_type VARCHAR(32) NOT NULL DEFAULT 'upload',</code> |
| L0163 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          source_uri VARCHAR(1000) NULL,</code> |
| L0164 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          file_path VARCHAR(1000) NULL,</code> |
| L0165 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          mime_type VARCHAR(120) NULL,</code> |
| L0166 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          file_size BIGINT NOT NULL DEFAULT 0,</code> |
| L0167 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          checksum CHAR(64) NULL,</code> |
| L0168 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          status VARCHAR(24) NOT NULL DEFAULT 'pending',</code> |
| L0169 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          progress INT NOT NULL DEFAULT 0,</code> |
| L0170 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          chunk_count INT NOT NULL DEFAULT 0,</code> |
| L0171 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          char_count INT NOT NULL DEFAULT 0,</code> |
| L0172 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          error_message TEXT NULL,</code> |
| L0173 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          enabled TINYINT(1) NOT NULL DEFAULT 1,</code> |
| L0174 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          created_by VARCHAR(80) NOT NULL DEFAULT 'system',</code> |
| L0175 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0176 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,</code> |
| L0177 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          KEY idx_rag_document_kb(kb_id),</code> |
| L0178 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          KEY idx_rag_document_status(status)</code> |
| L0179 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4</code> |
| L0180 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """,</code> |
| L0181 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """</code> |
| L0182 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>        CREATE TABLE IF NOT EXISTS rag_chunks (</code> |
| L0183 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          id BIGINT PRIMARY KEY AUTO_INCREMENT,</code> |
| L0184 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          kb_id BIGINT NOT NULL,</code> |
| L0185 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          document_id BIGINT NOT NULL,</code> |
| L0186 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          chunk_index INT NOT NULL,</code> |
| L0187 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          title_path VARCHAR(600) NULL,</code> |
| L0188 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          content MEDIUMTEXT NOT NULL,</code> |
| L0189 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          token_count INT NOT NULL DEFAULT 0,</code> |
| L0190 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          vector_key VARCHAR(80) NOT NULL,</code> |
| L0191 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          enabled TINYINT(1) NOT NULL DEFAULT 1,</code> |
| L0192 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          retrieval_count BIGINT NOT NULL DEFAULT 0,</code> |
| L0193 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          last_retrieved_at DATETIME NULL,</code> |
| L0194 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0195 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,</code> |
| L0196 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          UNIQUE KEY uk_rag_chunk_doc_index(document_id, chunk_index),</code> |
| L0197 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          KEY idx_rag_chunk_kb(kb_id),</code> |
| L0198 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          FULLTEXT KEY ft_rag_chunk_content(title_path, content) WITH PARSER ngram</code> |
| L0199 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4</code> |
| L0200 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """,</code> |
| L0201 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """</code> |
| L0202 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>        CREATE TABLE IF NOT EXISTS rag_retrieval_tests (</code> |
| L0203 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          id BIGINT PRIMARY KEY AUTO_INCREMENT,</code> |
| L0204 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          kb_id BIGINT NOT NULL,</code> |
| L0205 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          query_text TEXT NOT NULL,</code> |
| L0206 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          duration_ms INT NOT NULL DEFAULT 0,</code> |
| L0207 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          result_count INT NOT NULL DEFAULT 0,</code> |
| L0208 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          results_json LONGTEXT NULL,</code> |
| L0209 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          created_by VARCHAR(80) NOT NULL DEFAULT 'system',</code> |
| L0210 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0211 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          KEY idx_rag_test_kb_time(kb_id, created_at)</code> |
| L0212 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4</code> |
| L0213 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """,</code> |
| L0214 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """</code> |
| L0215 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>        CREATE TABLE IF NOT EXISTS rag_eval_cases (</code> |
| L0216 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          id BIGINT PRIMARY KEY AUTO_INCREMENT,</code> |
| L0217 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          kb_id BIGINT NOT NULL,</code> |
| L0218 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          question TEXT NOT NULL,</code> |
| L0219 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          expected_keywords TEXT NULL,</code> |
| L0220 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          expected_document VARCHAR(255) NULL,</code> |
| L0221 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          enabled TINYINT(1) NOT NULL DEFAULT 1,</code> |
| L0222 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0223 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          KEY idx_rag_eval_kb(kb_id)</code> |
| L0224 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4</code> |
| L0225 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """,</code> |
| L0226 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """</code> |
| L0227 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema。 | <code>        CREATE TABLE IF NOT EXISTS rag_eval_runs (</code> |
| L0228 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          id BIGINT PRIMARY KEY AUTO_INCREMENT,</code> |
| L0229 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          kb_id BIGINT NOT NULL,</code> |
| L0230 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          total_cases INT NOT NULL DEFAULT 0,</code> |
| L0231 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          passed_cases INT NOT NULL DEFAULT 0,</code> |
| L0232 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          pass_rate DECIMAL(8,6) NOT NULL DEFAULT 0,</code> |
| L0233 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          average_duration_ms INT NOT NULL DEFAULT 0,</code> |
| L0234 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          results_json LONGTEXT NULL,</code> |
| L0235 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          created_by VARCHAR(80) NOT NULL DEFAULT 'system',</code> |
| L0236 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0237 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>          KEY idx_rag_eval_run_kb_time(kb_id, created_at)</code> |
| L0238 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4</code> |
| L0239 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema。 | <code>        """,</code> |
| L0240 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ensure_schema。 | <code>    ]</code> |
| L0241 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 ensure_schema。 | <code>    with conn.cursor() as cur:</code> |
| L0242 | 遍历集合中的数据项并逐项处理，当前位于函数 ensure_schema。 | <code>        for statement in statements:</code> |
| L0243 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 ensure_schema。 | <code>            try:</code> |
| L0244 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>                cur.execute(statement)</code> |
| L0245 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 ensure_schema。 | <code>            except Exception as exc:</code> |
| L0246 | 源码原注释：Some MySQL builds do not provide the ngram parser. Keep a | <code>                # Some MySQL builds do not provide the ngram parser. Keep a</code> |
| L0247 | 源码原注释：normal FULLTEXT index so the rest of the service still works. | <code>                # normal FULLTEXT index so the rest of the service still works.</code> |
| L0248 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema。 | <code>                if "ngram" in statement.lower():</code> |
| L0249 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema。 | <code>                    cur.execute(statement.replace(" WITH PARSER ngram", ""))</code> |
| L0250 | 处理前述条件均未命中的情况，当前位于函数 ensure_schema。 | <code>                else:</code> |
| L0251 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 ensure_schema。 | <code>                    raise exc</code> |
| L0252 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema。 | <code>    conn.commit()</code> |
| L0253 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0254 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0255 | 定义ensuredefaultkb函数 &#96;ensure_default_kb&#96;，封装可复用业务逻辑。 | <code>def ensure_default_kb(conn: Any) -&gt; int:</code> |
| L0256 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 ensure_default_kb。 | <code>    with conn.cursor() as cur:</code> |
| L0257 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_default_kb。 | <code>        cur.execute("SELECT id FROM rag_knowledge_bases ORDER BY id LIMIT 1")</code> |
| L0258 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 ensure_default_kb。 | <code>        row = cur.fetchone()</code> |
| L0259 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_default_kb。 | <code>        if row:</code> |
| L0260 | 结束当前函数并把结果返回给调用方，当前位于函数 ensure_default_kb。 | <code>            return int(row["id"])</code> |
| L0261 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_default_kb。 | <code>        cur.execute(</code> |
| L0262 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_default_kb。 | <code>            """INSERT INTO rag_knowledge_bases</code> |
| L0263 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_default_kb。 | <code>            (name, description, created_by) VALUES (%s, %s, %s)""",</code> |
| L0264 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_default_kb。 | <code>            ("Web 攻击研判知识库", "用于 Web 攻击证据解释、风险判断与处置建议。", "migration"),</code> |
| L0265 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ensure_default_kb。 | <code>        )</code> |
| L0266 | 计算并保存 &#96;kb_id&#96;（kbid），供后续逻辑使用，当前位于函数 ensure_default_kb。 | <code>        kb_id = int(cur.lastrowid)</code> |
| L0267 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_default_kb。 | <code>    conn.commit()</code> |
| L0268 | 结束当前函数并把结果返回给调用方，当前位于函数 ensure_default_kb。 | <code>    return kb_id</code> |
| L0269 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0270 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0271 | 定义解析document函数 &#96;parse_document&#96;，封装可复用业务逻辑。 | <code>def parse_document(path: Path) -&gt; str:</code> |
| L0272 | 计算并保存 &#96;ext&#96;（ext），供后续逻辑使用，当前位于函数 parse_document。 | <code>    ext = path.suffix.lower().lstrip(".")</code> |
| L0273 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_document。 | <code>    if ext not in SUPPORTED_EXTENSIONS:</code> |
| L0274 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 parse_document。 | <code>        raise ValueError(f"不支持的文件格式: .{ext}")</code> |
| L0275 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_document。 | <code>    if ext in {"txt", "md", "json", "jsonl", "csv"}:</code> |
| L0276 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 parse_document。 | <code>        raw = path.read_bytes()</code> |
| L0277 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 parse_document。 | <code>        text = raw.decode("utf-8-sig", errors="replace")</code> |
| L0278 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_document。 | <code>        if ext == "json":</code> |
| L0279 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 parse_document。 | <code>            try:</code> |
| L0280 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 parse_document。 | <code>                text = json.dumps(json.loads(text), ensure_ascii=False, indent=2)</code> |
| L0281 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 parse_document。 | <code>            except Exception:</code> |
| L0282 | 控制当前循环或占位分支的执行流程，当前位于函数 parse_document。 | <code>                pass</code> |
| L0283 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_document。 | <code>        return text</code> |
| L0284 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_document。 | <code>    if ext == "pdf":</code> |
| L0285 | 导入后续逻辑所需的模块、类或函数：&#96;import fitz&#96;。 | <code>        import fitz</code> |
| L0286 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0287 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 parse_document。 | <code>        with fitz.open(path) as doc:</code> |
| L0288 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_document。 | <code>            return "\n\n".join(page.get_text("text") for page in doc)</code> |
| L0289 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_document。 | <code>    if ext == "docx":</code> |
| L0290 | 导入后续逻辑所需的模块、类或函数：&#96;from docx import Document&#96;。 | <code>        from docx import Document</code> |
| L0291 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0292 | 计算并保存 &#96;doc&#96;（doc），供后续逻辑使用，当前位于函数 parse_document。 | <code>        doc = Document(path)</code> |
| L0293 | 计算并保存 &#96;blocks&#96;（blocks），供后续逻辑使用，当前位于函数 parse_document。 | <code>        blocks = [p.text for p in doc.paragraphs if p.text.strip()]</code> |
| L0294 | 遍历集合中的数据项并逐项处理，当前位于函数 parse_document。 | <code>        for table in doc.tables:</code> |
| L0295 | 遍历集合中的数据项并逐项处理，当前位于函数 parse_document。 | <code>            for row in table.rows:</code> |
| L0296 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 parse_document。 | <code>                blocks.append(" &#124; ".join(cell.text.strip() for cell in row.cells))</code> |
| L0297 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_document。 | <code>        return "\n".join(blocks)</code> |
| L0298 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_document。 | <code>    if ext == "pptx":</code> |
| L0299 | 导入后续逻辑所需的模块、类或函数：&#96;from pptx import Presentation&#96;。 | <code>        from pptx import Presentation</code> |
| L0300 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0301 | 计算并保存 &#96;prs&#96;（prs），供后续逻辑使用，当前位于函数 parse_document。 | <code>        prs = Presentation(path)</code> |
| L0302 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 parse_document。 | <code>        rows: List[str] = []</code> |
| L0303 | 遍历集合中的数据项并逐项处理，当前位于函数 parse_document。 | <code>        for idx, slide in enumerate(prs.slides, 1):</code> |
| L0304 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 parse_document。 | <code>            rows.append(f"# 幻灯片 {idx}")</code> |
| L0305 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 parse_document。 | <code>            rows.extend(shape.text for shape in slide.shapes if hasattr(shape, "text") and shape.text.strip())</code> |
| L0306 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_document。 | <code>        return "\n".join(rows)</code> |
| L0307 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_document。 | <code>    if ext == "xlsx":</code> |
| L0308 | 导入后续逻辑所需的模块、类或函数：&#96;from openpyxl import load_workbook&#96;。 | <code>        from openpyxl import load_workbook</code> |
| L0309 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0310 | 计算并保存 &#96;wb&#96;（wb），供后续逻辑使用，当前位于函数 parse_document。 | <code>        wb = load_workbook(path, read_only=True, data_only=True)</code> |
| L0311 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 parse_document。 | <code>        rows = []</code> |
| L0312 | 遍历集合中的数据项并逐项处理，当前位于函数 parse_document。 | <code>        for ws in wb.worksheets:</code> |
| L0313 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 parse_document。 | <code>            rows.append(f"# 工作表 {ws.title}")</code> |
| L0314 | 遍历集合中的数据项并逐项处理，当前位于函数 parse_document。 | <code>            for row in ws.iter_rows(values_only=True):</code> |
| L0315 | 计算并保存 &#96;values&#96;（values），供后续逻辑使用，当前位于函数 parse_document。 | <code>                values = [str(v).strip() for v in row if v is not None and str(v).strip()]</code> |
| L0316 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_document。 | <code>                if values:</code> |
| L0317 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 parse_document。 | <code>                    rows.append(" &#124; ".join(values))</code> |
| L0318 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_document。 | <code>        return "\n".join(rows)</code> |
| L0319 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_document。 | <code>    return ""</code> |
| L0320 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0321 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0322 | 定义splitlongtext函数 &#96;_split_long_text&#96;，封装可复用业务逻辑。 | <code>def _split_long_text(text: str, size: int, overlap: int) -&gt; List[str]:</code> |
| L0323 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 _split_long_text。 | <code>    text = re.sub(r"[ \t]+", " ", text).strip()</code> |
| L0324 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _split_long_text。 | <code>    if not text:</code> |
| L0325 | 结束当前函数并把结果返回给调用方，当前位于函数 _split_long_text。 | <code>        return []</code> |
| L0326 | 计算并保存 &#96;chunks&#96;（chunks），供后续逻辑使用，当前位于函数 _split_long_text。 | <code>    chunks: List[str] = []</code> |
| L0327 | 计算并保存 &#96;start&#96;（启动），供后续逻辑使用，当前位于函数 _split_long_text。 | <code>    start = 0</code> |
| L0328 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 _split_long_text。 | <code>    while start &lt; len(text):</code> |
| L0329 | 计算并保存 &#96;end&#96;（end），供后续逻辑使用，当前位于函数 _split_long_text。 | <code>        end = min(len(text), start + size)</code> |
| L0330 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _split_long_text。 | <code>        if end &lt; len(text):</code> |
| L0331 | 计算并保存 &#96;candidates&#96;（candidates），供后续逻辑使用，当前位于函数 _split_long_text。 | <code>            candidates = [text.rfind(mark, start + size // 2, end) for mark in ("\n\n", "。", "；", "\n", ". ")]</code> |
| L0332 | 计算并保存 &#96;boundary&#96;（boundary），供后续逻辑使用，当前位于函数 _split_long_text。 | <code>            boundary = max(candidates)</code> |
| L0333 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _split_long_text。 | <code>            if boundary &gt; start:</code> |
| L0334 | 计算并保存 &#96;end&#96;（end），供后续逻辑使用，当前位于函数 _split_long_text。 | <code>                end = boundary + 1</code> |
| L0335 | 计算并保存 &#96;piece&#96;（piece），供后续逻辑使用，当前位于函数 _split_long_text。 | <code>        piece = text[start:end].strip()</code> |
| L0336 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _split_long_text。 | <code>        if piece:</code> |
| L0337 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 _split_long_text。 | <code>            chunks.append(piece)</code> |
| L0338 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _split_long_text。 | <code>        if end &gt;= len(text):</code> |
| L0339 | 控制当前循环或占位分支的执行流程，当前位于函数 _split_long_text。 | <code>            break</code> |
| L0340 | 计算并保存 &#96;start&#96;（启动），供后续逻辑使用，当前位于函数 _split_long_text。 | <code>        start = max(start + 1, end - overlap)</code> |
| L0341 | 结束当前函数并把结果返回给调用方，当前位于函数 _split_long_text。 | <code>    return chunks</code> |
| L0342 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0343 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0344 | 定义chunkdocument函数 &#96;chunk_document&#96;，封装可复用业务逻辑。 | <code>def chunk_document(text: str, method: str = "semantic", size: int = 900, overlap: int = 120) -&gt; List[Dict[str, Any]]:</code> |
| L0345 | 计算并保存 &#96;size&#96;（size），供后续逻辑使用，当前位于函数 chunk_document。 | <code>    size = min(max(int(size), 200), 4000)</code> |
| L0346 | 计算并保存 &#96;overlap&#96;（overlap），供后续逻辑使用，当前位于函数 chunk_document。 | <code>    overlap = min(max(int(overlap), 0), size // 2)</code> |
| L0347 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 chunk_document。 | <code>    text = text.replace("\r\n", "\n").replace("\r", "\n").strip()</code> |
| L0348 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 chunk_document。 | <code>    if not text:</code> |
| L0349 | 结束当前函数并把结果返回给调用方，当前位于函数 chunk_document。 | <code>        return []</code> |
| L0350 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 chunk_document。 | <code>    if method == "fixed":</code> |
| L0351 | 计算并保存 &#96;parts&#96;（parts），供后续逻辑使用，当前位于函数 chunk_document。 | <code>        parts = _split_long_text(text, size, overlap)</code> |
| L0352 | 结束当前函数并把结果返回给调用方，当前位于函数 chunk_document。 | <code>        return [{"title_path": "", "content": part} for part in parts]</code> |
| L0353 | 计算并保存 &#96;heading&#96;（heading），供后续逻辑使用，当前位于函数 chunk_document。 | <code>    heading = "正文"</code> |
| L0354 | 计算并保存 &#96;sections&#96;（sections），供后续逻辑使用，当前位于函数 chunk_document。 | <code>    sections: List[Tuple[str, str]] = []</code> |
| L0355 | 计算并保存 &#96;buffer&#96;（buffer），供后续逻辑使用，当前位于函数 chunk_document。 | <code>    buffer: List[str] = []</code> |
| L0356 | 遍历集合中的数据项并逐项处理，当前位于函数 chunk_document。 | <code>    for line in text.split("\n"):</code> |
| L0357 | 计算并保存 &#96;clean&#96;（clean），供后续逻辑使用，当前位于函数 chunk_document。 | <code>        clean = line.strip()</code> |
| L0358 | 计算并保存 &#96;is_heading&#96;（isheading），供后续逻辑使用，当前位于函数 chunk_document。 | <code>        is_heading = bool(re.match(r"^#{1,6}\s+", clean) or re.match(r"^[一二三四五六七八九十0-9]+[、.．]\s*\S+", clean))</code> |
| L0359 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 chunk_document。 | <code>        if is_heading and buffer:</code> |
| L0360 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 chunk_document。 | <code>            sections.append((heading, "\n".join(buffer).strip()))</code> |
| L0361 | 计算并保存 &#96;buffer&#96;（buffer），供后续逻辑使用，当前位于函数 chunk_document。 | <code>            buffer = []</code> |
| L0362 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 chunk_document。 | <code>        if is_heading:</code> |
| L0363 | 计算并保存 &#96;heading&#96;（heading），供后续逻辑使用，当前位于函数 chunk_document。 | <code>            heading = re.sub(r"^#{1,6}\s+", "", clean)[:300]</code> |
| L0364 | 处理前述条件均未命中的情况，当前位于函数 chunk_document。 | <code>        else:</code> |
| L0365 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 chunk_document。 | <code>            buffer.append(line)</code> |
| L0366 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 chunk_document。 | <code>    if buffer:</code> |
| L0367 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 chunk_document。 | <code>        sections.append((heading, "\n".join(buffer).strip()))</code> |
| L0368 | 计算并保存 &#96;chunks&#96;（chunks），供后续逻辑使用，当前位于函数 chunk_document。 | <code>    chunks: List[Dict[str, Any]] = []</code> |
| L0369 | 遍历集合中的数据项并逐项处理，当前位于函数 chunk_document。 | <code>    for title, body in sections or [("正文", text)]:</code> |
| L0370 | 遍历集合中的数据项并逐项处理，当前位于函数 chunk_document。 | <code>        for piece in _split_long_text(body, size, overlap):</code> |
| L0371 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 chunk_document。 | <code>            chunks.append({"title_path": title, "content": piece})</code> |
| L0372 | 结束当前函数并把结果返回给调用方，当前位于函数 chunk_document。 | <code>    return chunks</code> |
| L0373 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0374 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0375 | 定义lancetable函数 &#96;_lance_table&#96;，封装可复用业务逻辑。 | <code>def _lance_table(data_dir: Path, vector_size: int, create: bool = False):</code> |
| L0376 | 导入后续逻辑所需的模块、类或函数：&#96;import lancedb&#96;。 | <code>    import lancedb</code> |
| L0377 | 导入后续逻辑所需的模块、类或函数：&#96;import pyarrow as pa&#96;。 | <code>    import pyarrow as pa</code> |
| L0378 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0379 | 计算并保存 &#96;db&#96;（数据库），供后续逻辑使用，当前位于函数 _lance_table。 | <code>    db = lancedb.connect(str(data_dir / "lancedb"))</code> |
| L0380 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _lance_table。 | <code>    if "rag_chunks" in db.table_names():</code> |
| L0381 | 结束当前函数并把结果返回给调用方，当前位于函数 _lance_table。 | <code>        return db.open_table("rag_chunks")</code> |
| L0382 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _lance_table。 | <code>    if not create:</code> |
| L0383 | 结束当前函数并把结果返回给调用方，当前位于函数 _lance_table。 | <code>        return None</code> |
| L0384 | 计算并保存 &#96;schema&#96;（schema），供后续逻辑使用，当前位于函数 _lance_table。 | <code>    schema = pa.schema(</code> |
| L0385 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _lance_table。 | <code>        [</code> |
| L0386 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 _lance_table。 | <code>            pa.field("vector_key", pa.string()),</code> |
| L0387 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _lance_table。 | <code>            pa.field("kb_id", pa.int64()),</code> |
| L0388 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _lance_table。 | <code>            pa.field("document_id", pa.int64()),</code> |
| L0389 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _lance_table。 | <code>            pa.field("chunk_id", pa.int64()),</code> |
| L0390 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _lance_table。 | <code>            pa.field("title", pa.string()),</code> |
| L0391 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _lance_table。 | <code>            pa.field("content", pa.string()),</code> |
| L0392 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 _lance_table。 | <code>            pa.field("vector", pa.list_(pa.float32(), vector_size)),</code> |
| L0393 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _lance_table。 | <code>        ]</code> |
| L0394 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _lance_table。 | <code>    )</code> |
| L0395 | 结束当前函数并把结果返回给调用方，当前位于函数 _lance_table。 | <code>    return db.create_table("rag_chunks", schema=schema)</code> |
| L0396 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0397 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0398 | 定义删除vectors函数 &#96;_delete_vectors&#96;，封装可复用业务逻辑。 | <code>def _delete_vectors(data_dir: Path, where: str) -&gt; None:</code> |
| L0399 | 计算并保存 &#96;table&#96;（table），供后续逻辑使用，当前位于函数 _delete_vectors。 | <code>    table = _lance_table(data_dir, 1024, create=False)</code> |
| L0400 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _delete_vectors。 | <code>    if table is not None:</code> |
| L0401 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _delete_vectors。 | <code>        try:</code> |
| L0402 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _delete_vectors。 | <code>            table.delete(where)</code> |
| L0403 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _delete_vectors。 | <code>        except Exception:</code> |
| L0404 | 控制当前循环或占位分支的执行流程，当前位于函数 _delete_vectors。 | <code>            pass</code> |
| L0405 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0406 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0407 | 定义列出kbs函数 &#96;list_kbs&#96;，封装可复用业务逻辑。 | <code>def list_kbs(conn: Any, q: str = "", include_disabled: bool = True) -&gt; List[Dict[str, Any]]:</code> |
| L0408 | 计算并保存 &#96;where&#96;（where），供后续逻辑使用，当前位于函数 list_kbs。 | <code>    where = []</code> |
| L0409 | 计算并保存 &#96;params&#96;（params），供后续逻辑使用，当前位于函数 list_kbs。 | <code>    params: List[Any] = []</code> |
| L0410 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_kbs。 | <code>    if q:</code> |
| L0411 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 list_kbs。 | <code>        where.append("(k.name LIKE %s OR k.description LIKE %s)")</code> |
| L0412 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 list_kbs。 | <code>        params.extend([f"%{q}%", f"%{q}%"])</code> |
| L0413 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_kbs。 | <code>    if not include_disabled:</code> |
| L0414 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 list_kbs。 | <code>        where.append("k.enabled=1")</code> |
| L0415 | 计算并保存 &#96;clause&#96;（clause），供后续逻辑使用，当前位于函数 list_kbs。 | <code>    clause = f"WHERE {' AND '.join(where)}" if where else ""</code> |
| L0416 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 list_kbs。 | <code>    with conn.cursor() as cur:</code> |
| L0417 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 list_kbs。 | <code>        cur.execute(</code> |
| L0418 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_kbs。 | <code>            f"""SELECT k.*,</code> |
| L0419 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_kbs。 | <code>            (SELECT COUNT(*) FROM rag_documents d WHERE d.kb_id=k.id) AS document_count,</code> |
| L0420 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_kbs。 | <code>            (SELECT COUNT(*) FROM rag_chunks c WHERE c.kb_id=k.id AND c.enabled=1) AS chunk_count</code> |
| L0421 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_kbs。 | <code>            FROM rag_knowledge_bases k {clause} ORDER BY k.updated_at DESC, k.id DESC""",</code> |
| L0422 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_kbs。 | <code>            tuple(params),</code> |
| L0423 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 list_kbs。 | <code>        )</code> |
| L0424 | 结束当前函数并把结果返回给调用方，当前位于函数 list_kbs。 | <code>        return list(cur.fetchall())</code> |
| L0425 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0426 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0427 | 定义读取kb函数 &#96;get_kb&#96;，封装可复用业务逻辑。 | <code>def get_kb(conn: Any, kb_id: int) -&gt; Optional[Dict[str, Any]]:</code> |
| L0428 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_kb。 | <code>    rows = [row for row in list_kbs(conn) if int(row["id"]) == int(kb_id)]</code> |
| L0429 | 结束当前函数并把结果返回给调用方，当前位于函数 get_kb。 | <code>    return rows[0] if rows else None</code> |
| L0430 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0431 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0432 | 定义保存kb函数 &#96;save_kb&#96;，封装可复用业务逻辑。 | <code>def save_kb(conn: Any, body: Dict[str, Any], username: str, kb_id: Optional[int] = None) -&gt; int:</code> |
| L0433 | 计算并保存 &#96;name&#96;（name），供后续逻辑使用，当前位于函数 save_kb。 | <code>    name = str(body.get("name") or "").strip()</code> |
| L0434 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 save_kb。 | <code>    if not name:</code> |
| L0435 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 save_kb。 | <code>        raise ValueError("知识库名称不能为空")</code> |
| L0436 | 计算并保存 &#96;values&#96;（values），供后续逻辑使用，当前位于函数 save_kb。 | <code>    values = (</code> |
| L0437 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 save_kb。 | <code>        name,</code> |
| L0438 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 save_kb。 | <code>        str(body.get("description") or "").strip(),</code> |
| L0439 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 save_kb。 | <code>        str(body.get("embedding_model") or DEFAULT_EMBEDDING_MODEL),</code> |
| L0440 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 save_kb。 | <code>        str(body.get("rerank_model") or DEFAULT_RERANK_MODEL),</code> |
| L0441 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 save_kb。 | <code>        "fixed" if body.get("chunk_method") == "fixed" else "semantic",</code> |
| L0442 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 save_kb。 | <code>        min(max(int(body.get("chunk_size") or 900), 200), 4000),</code> |
| L0443 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 save_kb。 | <code>        min(max(int(body.get("chunk_overlap") or 120), 0), 1000),</code> |
| L0444 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 save_kb。 | <code>        min(max(int(body.get("vector_top_k") or 20), 1), 100),</code> |
| L0445 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 save_kb。 | <code>        min(max(int(body.get("keyword_top_k") or 20), 1), 100),</code> |
| L0446 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 save_kb。 | <code>        min(max(int(body.get("final_top_k") or 5), 1), 20),</code> |
| L0447 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 save_kb。 | <code>        max(0.0, min(float(body.get("score_threshold") or 0.1), 1.0)),</code> |
| L0448 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 save_kb。 | <code>        1 if body.get("enabled", True) else 0,</code> |
| L0449 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 save_kb。 | <code>    )</code> |
| L0450 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 save_kb。 | <code>    with conn.cursor() as cur:</code> |
| L0451 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 save_kb。 | <code>        if kb_id:</code> |
| L0452 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 save_kb。 | <code>            cur.execute(</code> |
| L0453 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 save_kb。 | <code>                """UPDATE rag_knowledge_bases SET name=%s,description=%s,embedding_model=%s,rerank_model=%s,</code> |
| L0454 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 save_kb。 | <code>                chunk_method=%s,chunk_size=%s,chunk_overlap=%s,vector_top_k=%s,keyword_top_k=%s,</code> |
| L0455 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 save_kb。 | <code>                final_top_k=%s,score_threshold=%s,enabled=%s WHERE id=%s""",</code> |
| L0456 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 save_kb。 | <code>                values + (int(kb_id),),</code> |
| L0457 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 save_kb。 | <code>            )</code> |
| L0458 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 save_kb。 | <code>            if cur.rowcount == 0:</code> |
| L0459 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 save_kb。 | <code>                raise KeyError("知识库不存在")</code> |
| L0460 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 save_kb。 | <code>            result = int(kb_id)</code> |
| L0461 | 处理前述条件均未命中的情况，当前位于函数 save_kb。 | <code>        else:</code> |
| L0462 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 save_kb。 | <code>            cur.execute(</code> |
| L0463 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 save_kb。 | <code>                """INSERT INTO rag_knowledge_bases</code> |
| L0464 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 save_kb。 | <code>                (name,description,embedding_model,rerank_model,chunk_method,chunk_size,chunk_overlap,</code> |
| L0465 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 save_kb。 | <code>                vector_top_k,keyword_top_k,final_top_k,score_threshold,enabled,created_by)</code> |
| L0466 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 save_kb。 | <code>                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",</code> |
| L0467 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 save_kb。 | <code>                values + (username,),</code> |
| L0468 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 save_kb。 | <code>            )</code> |
| L0469 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 save_kb。 | <code>            result = int(cur.lastrowid)</code> |
| L0470 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 save_kb。 | <code>    conn.commit()</code> |
| L0471 | 结束当前函数并把结果返回给调用方，当前位于函数 save_kb。 | <code>    return result</code> |
| L0472 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0473 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0474 | 定义删除kb函数 &#96;delete_kb&#96;，封装可复用业务逻辑。 | <code>def delete_kb(conn: Any, data_dir: Path, kb_id: int) -&gt; bool:</code> |
| L0475 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 delete_kb。 | <code>    with conn.cursor() as cur:</code> |
| L0476 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 delete_kb。 | <code>        cur.execute("SELECT file_path FROM rag_documents WHERE kb_id=%s", (kb_id,))</code> |
| L0477 | 计算并保存 &#96;files&#96;（files），供后续逻辑使用，当前位于函数 delete_kb。 | <code>        files = [str(row.get("file_path") or "") for row in cur.fetchall()]</code> |
| L0478 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 delete_kb。 | <code>        cur.execute("DELETE FROM rag_retrieval_tests WHERE kb_id=%s", (kb_id,))</code> |
| L0479 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 delete_kb。 | <code>        cur.execute("DELETE FROM rag_eval_cases WHERE kb_id=%s", (kb_id,))</code> |
| L0480 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 delete_kb。 | <code>        cur.execute("DELETE FROM rag_eval_runs WHERE kb_id=%s", (kb_id,))</code> |
| L0481 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 delete_kb。 | <code>        cur.execute("DELETE FROM rag_chunks WHERE kb_id=%s", (kb_id,))</code> |
| L0482 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 delete_kb。 | <code>        cur.execute("DELETE FROM rag_documents WHERE kb_id=%s", (kb_id,))</code> |
| L0483 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 delete_kb。 | <code>        cur.execute("DELETE FROM rag_knowledge_bases WHERE id=%s", (kb_id,))</code> |
| L0484 | 计算并保存 &#96;changed&#96;（changed），供后续逻辑使用，当前位于函数 delete_kb。 | <code>        changed = cur.rowcount &gt; 0</code> |
| L0485 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 delete_kb。 | <code>    conn.commit()</code> |
| L0486 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 delete_kb。 | <code>    _delete_vectors(data_dir, f"kb_id = {int(kb_id)}")</code> |
| L0487 | 遍历集合中的数据项并逐项处理，当前位于函数 delete_kb。 | <code>    for file_path in files:</code> |
| L0488 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 delete_kb。 | <code>        try:</code> |
| L0489 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 delete_kb。 | <code>            Path(file_path).unlink(missing_ok=True)</code> |
| L0490 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 delete_kb。 | <code>        except Exception:</code> |
| L0491 | 控制当前循环或占位分支的执行流程，当前位于函数 delete_kb。 | <code>            pass</code> |
| L0492 | 结束当前函数并把结果返回给调用方，当前位于函数 delete_kb。 | <code>    return changed</code> |
| L0493 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0494 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0495 | 定义列出documents函数 &#96;list_documents&#96;，封装可复用业务逻辑。 | <code>def list_documents(conn: Any, kb_id: int) -&gt; List[Dict[str, Any]]:</code> |
| L0496 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 list_documents。 | <code>    with conn.cursor() as cur:</code> |
| L0497 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 list_documents。 | <code>        cur.execute("SELECT * FROM rag_documents WHERE kb_id=%s ORDER BY updated_at DESC,id DESC", (kb_id,))</code> |
| L0498 | 结束当前函数并把结果返回给调用方，当前位于函数 list_documents。 | <code>        return list(cur.fetchall())</code> |
| L0499 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0500 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0501 | 定义列出chunks函数 &#96;list_chunks&#96;，封装可复用业务逻辑。 | <code>def list_chunks(</code> |
| L0502 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_chunks。 | <code>    conn: Any,</code> |
| L0503 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_chunks。 | <code>    kb_id: int,</code> |
| L0504 | 计算并保存 &#96;document_id&#96;（documentid），供后续逻辑使用，当前位于函数 list_chunks。 | <code>    document_id: Optional[int] = None,</code> |
| L0505 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_chunks。 | <code>    *,</code> |
| L0506 | 计算并保存 &#96;include_content&#96;（includecontent），供后续逻辑使用，当前位于函数 list_chunks。 | <code>    include_content: bool = True,</code> |
| L0507 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 list_chunks。 | <code>) -&gt; List[Dict[str, Any]]:</code> |
| L0508 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_chunks。 | <code>    columns = "c.*" if include_content else """</code> |
| L0509 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_chunks。 | <code>        c.id,c.document_id,c.chunk_index,c.title_path,c.token_count,</code> |
| L0510 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_chunks。 | <code>        c.enabled,c.retrieval_count,c.updated_at,</code> |
| L0511 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_chunks。 | <code>        LEFT(c.content, 160) AS content_preview</code> |
| L0512 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_chunks。 | <code>    """</code> |
| L0513 | 计算并保存 &#96;sql&#96;（sql），供后续逻辑使用，当前位于函数 list_chunks。 | <code>    sql = f"""SELECT {columns},d.name AS document_name FROM rag_chunks c</code> |
| L0514 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_chunks。 | <code>              JOIN rag_documents d ON d.id=c.document_id WHERE c.kb_id=%s"""</code> |
| L0515 | 计算并保存 &#96;params&#96;（params），供后续逻辑使用，当前位于函数 list_chunks。 | <code>    params: List[Any] = [kb_id]</code> |
| L0516 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_chunks。 | <code>    if document_id:</code> |
| L0517 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_chunks。 | <code>        sql += " AND c.document_id=%s"</code> |
| L0518 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 list_chunks。 | <code>        params.append(document_id)</code> |
| L0519 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_chunks。 | <code>    sql += " ORDER BY c.document_id,c.chunk_index"</code> |
| L0520 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 list_chunks。 | <code>    with conn.cursor() as cur:</code> |
| L0521 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 list_chunks。 | <code>        cur.execute(sql, tuple(params))</code> |
| L0522 | 结束当前函数并把结果返回给调用方，当前位于函数 list_chunks。 | <code>        return list(cur.fetchall())</code> |
| L0523 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0524 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0525 | 定义读取chunk函数 &#96;get_chunk&#96;，封装可复用业务逻辑。 | <code>def get_chunk(conn: Any, chunk_id: int) -&gt; Optional[Dict[str, Any]]:</code> |
| L0526 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 get_chunk。 | <code>    with conn.cursor() as cur:</code> |
| L0527 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 get_chunk。 | <code>        cur.execute(</code> |
| L0528 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 get_chunk。 | <code>            """SELECT c.*,d.name AS document_name FROM rag_chunks c</code> |
| L0529 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 get_chunk。 | <code>               JOIN rag_documents d ON d.id=c.document_id WHERE c.id=%s""",</code> |
| L0530 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_chunk。 | <code>            (int(chunk_id),),</code> |
| L0531 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 get_chunk。 | <code>        )</code> |
| L0532 | 结束当前函数并把结果返回给调用方，当前位于函数 get_chunk。 | <code>        return cur.fetchone()</code> |
| L0533 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0534 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0535 | 定义ingestfile函数 &#96;ingest_file&#96;，封装可复用业务逻辑。 | <code>def ingest_file(</code> |
| L0536 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>    conn: Any,</code> |
| L0537 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>    data_dir: Path,</code> |
| L0538 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>    api_config: Dict[str, Any],</code> |
| L0539 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>    kb_id: int,</code> |
| L0540 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>    source_path: Path,</code> |
| L0541 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>    original_name: str,</code> |
| L0542 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>    username: str,</code> |
| L0543 | 计算并保存 &#96;source_type&#96;（来源type），供后续逻辑使用，当前位于函数 ingest_file。 | <code>    source_type: str = "upload",</code> |
| L0544 | 计算并保存 &#96;source_uri&#96;（来源uri），供后续逻辑使用，当前位于函数 ingest_file。 | <code>    source_uri: str = "",</code> |
| L0545 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ingest_file。 | <code>) -&gt; Dict[str, Any]:</code> |
| L0546 | 计算并保存 &#96;kb&#96;（kb），供后续逻辑使用，当前位于函数 ingest_file。 | <code>    kb = get_kb(conn, kb_id)</code> |
| L0547 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ingest_file。 | <code>    if not kb:</code> |
| L0548 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 ingest_file。 | <code>        raise KeyError("知识库不存在")</code> |
| L0549 | 计算并保存 &#96;size&#96;（size），供后续逻辑使用，当前位于函数 ingest_file。 | <code>    size = source_path.stat().st_size</code> |
| L0550 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ingest_file。 | <code>    if size &gt; MAX_UPLOAD_BYTES:</code> |
| L0551 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 ingest_file。 | <code>        raise ValueError("文件不能超过 30MB")</code> |
| L0552 | 计算并保存 &#96;extension&#96;（extension），供后续逻辑使用，当前位于函数 ingest_file。 | <code>    extension = source_path.suffix.lower().lstrip(".")</code> |
| L0553 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ingest_file。 | <code>    if extension not in SUPPORTED_EXTENSIONS:</code> |
| L0554 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 ingest_file。 | <code>        raise ValueError(f"不支持 .{extension} 文件")</code> |
| L0555 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 ingest_file。 | <code>    raw = source_path.read_bytes()</code> |
| L0556 | 计算并保存 &#96;checksum&#96;（checksum），供后续逻辑使用，当前位于函数 ingest_file。 | <code>    checksum = hashlib.sha256(raw).hexdigest()</code> |
| L0557 | 计算并保存 &#96;target_dir&#96;（targetdir），供后续逻辑使用，当前位于函数 ingest_file。 | <code>    target_dir = data_dir / "uploads" / str(kb_id)</code> |
| L0558 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>    target_dir.mkdir(parents=True, exist_ok=True)</code> |
| L0559 | 计算并保存 &#96;target_path&#96;（targetpath），供后续逻辑使用，当前位于函数 ingest_file。 | <code>    target_path = target_dir / f"{uuid.uuid4().hex}_{safe_filename(original_name)}"</code> |
| L0560 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>    shutil.copy2(source_path, target_path)</code> |
| L0561 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 ingest_file。 | <code>    with conn.cursor() as cur:</code> |
| L0562 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ingest_file。 | <code>        cur.execute(</code> |
| L0563 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ingest_file。 | <code>            """INSERT INTO rag_documents</code> |
| L0564 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ingest_file。 | <code>            (kb_id,name,source_type,source_uri,file_path,mime_type,file_size,checksum,status,progress,created_by)</code> |
| L0565 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ingest_file。 | <code>            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'processing',10,%s)""",</code> |
| L0566 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>            (kb_id, original_name[:255], source_type, source_uri[:1000], str(target_path), extension, size, checksum, username),</code> |
| L0567 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ingest_file。 | <code>        )</code> |
| L0568 | 计算并保存 &#96;document_id&#96;（documentid），供后续逻辑使用，当前位于函数 ingest_file。 | <code>        document_id = int(cur.lastrowid)</code> |
| L0569 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>    conn.commit()</code> |
| L0570 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 ingest_file。 | <code>    try:</code> |
| L0571 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 ingest_file。 | <code>        text = parse_document(target_path)</code> |
| L0572 | 计算并保存 &#96;chunks&#96;（chunks），供后续逻辑使用，当前位于函数 ingest_file。 | <code>        chunks = chunk_document(text, str(kb["chunk_method"]), int(kb["chunk_size"]), int(kb["chunk_overlap"]))</code> |
| L0573 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ingest_file。 | <code>        if not chunks:</code> |
| L0574 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 ingest_file。 | <code>            raise ValueError("文档未解析出可用文本")</code> |
| L0575 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 ingest_file。 | <code>        vectors: List[List[float]] = []</code> |
| L0576 | 遍历集合中的数据项并逐项处理，当前位于函数 ingest_file。 | <code>        for offset in range(0, len(chunks), 10):</code> |
| L0577 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 ingest_file。 | <code>            vectors.extend(embed_texts([row["content"] for row in chunks[offset : offset + 10]], api_config))</code> |
| L0578 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 ingest_file。 | <code>            with conn.cursor() as cur:</code> |
| L0579 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ingest_file。 | <code>                cur.execute(</code> |
| L0580 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>                    "UPDATE rag_documents SET progress=%s WHERE id=%s",</code> |
| L0581 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>                    (min(85, 20 + int((offset + 10) / max(1, len(chunks)) * 65)), document_id),</code> |
| L0582 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ingest_file。 | <code>                )</code> |
| L0583 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>            conn.commit()</code> |
| L0584 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 ingest_file。 | <code>        vector_rows = []</code> |
| L0585 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 ingest_file。 | <code>        with conn.cursor() as cur:</code> |
| L0586 | 遍历集合中的数据项并逐项处理，当前位于函数 ingest_file。 | <code>            for index, (chunk, vector) in enumerate(zip(chunks, vectors)):</code> |
| L0587 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 ingest_file。 | <code>                vector_key = uuid.uuid4().hex</code> |
| L0588 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ingest_file。 | <code>                cur.execute(</code> |
| L0589 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ingest_file。 | <code>                    """INSERT INTO rag_chunks</code> |
| L0590 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ingest_file。 | <code>                    (kb_id,document_id,chunk_index,title_path,content,token_count,vector_key)</code> |
| L0591 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ingest_file。 | <code>                    VALUES (%s,%s,%s,%s,%s,%s,%s)""",</code> |
| L0592 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 ingest_file。 | <code>                    (kb_id, document_id, index, chunk["title_path"], chunk["content"], max(1, len(chunk["content"]) // 2), vector_key),</code> |
| L0593 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ingest_file。 | <code>                )</code> |
| L0594 | 计算并保存 &#96;chunk_id&#96;（chunkid），供后续逻辑使用，当前位于函数 ingest_file。 | <code>                chunk_id = int(cur.lastrowid)</code> |
| L0595 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 ingest_file。 | <code>                vector_rows.append(</code> |
| L0596 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>                    {</code> |
| L0597 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 ingest_file。 | <code>                        "vector_key": vector_key,</code> |
| L0598 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>                        "kb_id": int(kb_id),</code> |
| L0599 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>                        "document_id": document_id,</code> |
| L0600 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>                        "chunk_id": chunk_id,</code> |
| L0601 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>                        "title": str(chunk["title_path"] or original_name),</code> |
| L0602 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>                        "content": chunk["content"],</code> |
| L0603 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 ingest_file。 | <code>                        "vector": vector,</code> |
| L0604 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ingest_file。 | <code>                    }</code> |
| L0605 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ingest_file。 | <code>                )</code> |
| L0606 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ingest_file。 | <code>            cur.execute(</code> |
| L0607 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ingest_file。 | <code>                """UPDATE rag_documents SET status='ready',progress=100,chunk_count=%s,char_count=%s,error_message=NULL</code> |
| L0608 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ingest_file。 | <code>                WHERE id=%s""",</code> |
| L0609 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>                (len(chunks), len(text), document_id),</code> |
| L0610 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ingest_file。 | <code>            )</code> |
| L0611 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>        conn.commit()</code> |
| L0612 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 ingest_file。 | <code>        table = _lance_table(data_dir, int(api_config["embedding_dimensions"]), create=True)</code> |
| L0613 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 ingest_file。 | <code>        table.add(vector_rows)</code> |
| L0614 | 结束当前函数并把结果返回给调用方，当前位于函数 ingest_file。 | <code>        return {"id": document_id, "name": original_name, "status": "ready", "chunk_count": len(chunks), "char_count": len(text)}</code> |
| L0615 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 ingest_file。 | <code>    except Exception as exc:</code> |
| L0616 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 ingest_file。 | <code>        with conn.cursor() as cur:</code> |
| L0617 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ingest_file。 | <code>            cur.execute(</code> |
| L0618 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>                "UPDATE rag_documents SET status='failed',progress=100,error_message=%s WHERE id=%s",</code> |
| L0619 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>                (str(exc)[:2000], document_id),</code> |
| L0620 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ingest_file。 | <code>            )</code> |
| L0621 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>        conn.commit()</code> |
| L0622 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ingest_file。 | <code>        raise</code> |
| L0623 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0624 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0625 | 定义删除document函数 &#96;delete_document&#96;，封装可复用业务逻辑。 | <code>def delete_document(conn: Any, data_dir: Path, document_id: int) -&gt; bool:</code> |
| L0626 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 delete_document。 | <code>    with conn.cursor() as cur:</code> |
| L0627 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 delete_document。 | <code>        cur.execute("SELECT file_path FROM rag_documents WHERE id=%s", (document_id,))</code> |
| L0628 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 delete_document。 | <code>        row = cur.fetchone()</code> |
| L0629 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 delete_document。 | <code>        if not row:</code> |
| L0630 | 结束当前函数并把结果返回给调用方，当前位于函数 delete_document。 | <code>            return False</code> |
| L0631 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 delete_document。 | <code>        cur.execute("DELETE FROM rag_chunks WHERE document_id=%s", (document_id,))</code> |
| L0632 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 delete_document。 | <code>        cur.execute("DELETE FROM rag_documents WHERE id=%s", (document_id,))</code> |
| L0633 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 delete_document。 | <code>    conn.commit()</code> |
| L0634 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 delete_document。 | <code>    _delete_vectors(data_dir, f"document_id = {int(document_id)}")</code> |
| L0635 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 delete_document。 | <code>    try:</code> |
| L0636 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 delete_document。 | <code>        Path(str(row.get("file_path") or "")).unlink(missing_ok=True)</code> |
| L0637 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 delete_document。 | <code>    except Exception:</code> |
| L0638 | 控制当前循环或占位分支的执行流程，当前位于函数 delete_document。 | <code>        pass</code> |
| L0639 | 结束当前函数并把结果返回给调用方，当前位于函数 delete_document。 | <code>    return True</code> |
| L0640 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0641 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0642 | 定义更新chunk函数 &#96;update_chunk&#96;，封装可复用业务逻辑。 | <code>def update_chunk(conn: Any, data_dir: Path, api_config: Dict[str, Any], chunk_id: int, content: str, enabled: bool) -&gt; None:</code> |
| L0643 | 计算并保存 &#96;content&#96;（content），供后续逻辑使用，当前位于函数 update_chunk。 | <code>    content = str(content or "").strip()</code> |
| L0644 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 update_chunk。 | <code>    if not content:</code> |
| L0645 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 update_chunk。 | <code>        raise ValueError("切片内容不能为空")</code> |
| L0646 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 update_chunk。 | <code>    with conn.cursor() as cur:</code> |
| L0647 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 update_chunk。 | <code>        cur.execute("SELECT * FROM rag_chunks WHERE id=%s", (chunk_id,))</code> |
| L0648 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 update_chunk。 | <code>        row = cur.fetchone()</code> |
| L0649 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 update_chunk。 | <code>        if not row:</code> |
| L0650 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 update_chunk。 | <code>            raise KeyError("切片不存在")</code> |
| L0651 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 update_chunk。 | <code>        cur.execute(</code> |
| L0652 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_chunk。 | <code>            "UPDATE rag_chunks SET content=%s,enabled=%s,token_count=%s WHERE id=%s",</code> |
| L0653 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_chunk。 | <code>            (content, 1 if enabled else 0, max(1, len(content) // 2), chunk_id),</code> |
| L0654 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 update_chunk。 | <code>        )</code> |
| L0655 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_chunk。 | <code>    conn.commit()</code> |
| L0656 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 update_chunk。 | <code>    vector = embed_texts([content], api_config)[0]</code> |
| L0657 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 update_chunk。 | <code>    table = _lance_table(data_dir, len(vector), create=True)</code> |
| L0658 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_chunk。 | <code>    table.delete(f"chunk_id = {int(chunk_id)}")</code> |
| L0659 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 update_chunk。 | <code>    table.add(</code> |
| L0660 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_chunk。 | <code>        [</code> |
| L0661 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_chunk。 | <code>            {</code> |
| L0662 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 update_chunk。 | <code>                "vector_key": str(row["vector_key"]),</code> |
| L0663 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_chunk。 | <code>                "kb_id": int(row["kb_id"]),</code> |
| L0664 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_chunk。 | <code>                "document_id": int(row["document_id"]),</code> |
| L0665 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_chunk。 | <code>                "chunk_id": int(chunk_id),</code> |
| L0666 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_chunk。 | <code>                "title": str(row.get("title_path") or ""),</code> |
| L0667 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 update_chunk。 | <code>                "content": content,</code> |
| L0668 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 update_chunk。 | <code>                "vector": vector,</code> |
| L0669 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 update_chunk。 | <code>            }</code> |
| L0670 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 update_chunk。 | <code>        ]</code> |
| L0671 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 update_chunk。 | <code>    )</code> |
| L0672 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0673 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0674 | 定义tokens函数 &#96;_tokens&#96;，封装可复用业务逻辑。 | <code>def _tokens(text: str) -&gt; List[str]:</code> |
| L0675 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _tokens。 | <code>    try:</code> |
| L0676 | 导入后续逻辑所需的模块、类或函数：&#96;import jieba&#96;。 | <code>        import jieba</code> |
| L0677 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0678 | 计算并保存 &#96;values&#96;（values），供后续逻辑使用，当前位于函数 _tokens。 | <code>        values = jieba.lcut(str(text or "").lower(), cut_all=False)</code> |
| L0679 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _tokens。 | <code>    except Exception:</code> |
| L0680 | 计算并保存 &#96;values&#96;（values），供后续逻辑使用，当前位于函数 _tokens。 | <code>        values = re.findall(r"[a-z0-9_\-\.]+&#124;[\u4e00-\u9fff]", str(text or "").lower())</code> |
| L0681 | 结束当前函数并把结果返回给调用方，当前位于函数 _tokens。 | <code>    return [x.strip() for x in values if x.strip() and not x.isspace()]</code> |
| L0682 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0683 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0684 | 定义bm25scores函数 &#96;_bm25_scores&#96;，封装可复用业务逻辑。 | <code>def _bm25_scores(query: str, rows: Sequence[Dict[str, Any]]) -&gt; Dict[int, float]:</code> |
| L0685 | 计算并保存 &#96;query_tokens&#96;（querytokens），供后续逻辑使用，当前位于函数 _bm25_scores。 | <code>    query_tokens = _tokens(query)</code> |
| L0686 | 计算并保存 &#96;docs&#96;（docs），供后续逻辑使用，当前位于函数 _bm25_scores。 | <code>    docs = [_tokens(f"{row.get('title_path','')} {row.get('content','')}") for row in rows]</code> |
| L0687 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _bm25_scores。 | <code>    if not query_tokens or not docs:</code> |
| L0688 | 结束当前函数并把结果返回给调用方，当前位于函数 _bm25_scores。 | <code>        return {}</code> |
| L0689 | 计算并保存 &#96;avgdl&#96;（avgdl），供后续逻辑使用，当前位于函数 _bm25_scores。 | <code>    avgdl = sum(len(doc) for doc in docs) / max(1, len(docs))</code> |
| L0690 | 计算并保存 &#96;df&#96;（df），供后续逻辑使用，当前位于函数 _bm25_scores。 | <code>    df: Dict[str, int] = {}</code> |
| L0691 | 遍历集合中的数据项并逐项处理，当前位于函数 _bm25_scores。 | <code>    for doc in docs:</code> |
| L0692 | 遍历集合中的数据项并逐项处理，当前位于函数 _bm25_scores。 | <code>        for token in set(doc):</code> |
| L0693 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _bm25_scores。 | <code>            df[token] = df.get(token, 0) + 1</code> |
| L0694 | 计算并保存 &#96;scores&#96;（scores），供后续逻辑使用，当前位于函数 _bm25_scores。 | <code>    scores: Dict[int, float] = {}</code> |
| L0695 | 遍历集合中的数据项并逐项处理，当前位于函数 _bm25_scores。 | <code>    for row, doc in zip(rows, docs):</code> |
| L0696 | 计算并保存 &#96;freq&#96;（freq），供后续逻辑使用，当前位于函数 _bm25_scores。 | <code>        freq: Dict[str, int] = {}</code> |
| L0697 | 遍历集合中的数据项并逐项处理，当前位于函数 _bm25_scores。 | <code>        for token in doc:</code> |
| L0698 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _bm25_scores。 | <code>            freq[token] = freq.get(token, 0) + 1</code> |
| L0699 | 计算并保存 &#96;score&#96;（score），供后续逻辑使用，当前位于函数 _bm25_scores。 | <code>        score = 0.0</code> |
| L0700 | 遍历集合中的数据项并逐项处理，当前位于函数 _bm25_scores。 | <code>        for token in query_tokens:</code> |
| L0701 | 计算并保存 &#96;tf&#96;（tf），供后续逻辑使用，当前位于函数 _bm25_scores。 | <code>            tf = freq.get(token, 0)</code> |
| L0702 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _bm25_scores。 | <code>            if not tf:</code> |
| L0703 | 控制当前循环或占位分支的执行流程，当前位于函数 _bm25_scores。 | <code>                continue</code> |
| L0704 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 _bm25_scores。 | <code>            idf = math.log(1 + (len(docs) - df.get(token, 0) + 0.5) / (df.get(token, 0) + 0.5))</code> |
| L0705 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _bm25_scores。 | <code>            score += idf * (tf * 2.2) / (tf + 1.2 * (1 - 0.75 + 0.75 * len(doc) / max(1.0, avgdl)))</code> |
| L0706 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _bm25_scores。 | <code>        if score &gt; 0:</code> |
| L0707 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _bm25_scores。 | <code>            scores[int(row["id"])] = score</code> |
| L0708 | 结束当前函数并把结果返回给调用方，当前位于函数 _bm25_scores。 | <code>    return scores</code> |
| L0709 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0710 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0711 | 定义expandsecurityquery函数 &#96;expand_security_query&#96;，封装可复用业务逻辑。 | <code>def expand_security_query(query: str) -&gt; str:</code> |
| L0712 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 expand_security_query。 | <code>    """Add canonical security terms for observable evidence descriptions."""</code> |
| L0713 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 expand_security_query。 | <code>    raw = str(query or "").strip()</code> |
| L0714 | 计算并保存 &#96;lowered&#96;（lowered），供后续逻辑使用，当前位于函数 expand_security_query。 | <code>    lowered = raw.lower()</code> |
| L0715 | 计算并保存 &#96;additions&#96;（additions），供后续逻辑使用，当前位于函数 expand_security_query。 | <code>    additions: List[str] = []</code> |
| L0716 | 计算并保存 &#96;rules&#96;（rules），供后续逻辑使用，当前位于函数 expand_security_query。 | <code>    rules = [</code> |
| L0717 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 expand_security_query。 | <code>        (("nmap" in lowered) or ("syn" in lowered and "端口" in raw), "PortScan port scan 端口扫描 reconnaissance"),</code> |
| L0718 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 expand_security_query。 | <code>        (("404" in lowered and ("路径" in raw or "目录" in raw)) or "目录枚举" in raw, "directory scan path enumeration 目录扫描"),</code> |
| L0719 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 expand_security_query。 | <code>        (("or 1=1" in lowered) or ("单引号" in raw and "注释符" in raw), "SQL Injection SQL 注入 parameterized query"),</code> |
| L0720 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 expand_security_query。 | <code>        (("&lt;script" in lowered) or "onerror" in lowered or ("html" in lowered and "用户输入" in raw), "XSS cross site scripting output encoding CSP"),</code> |
| L0721 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 expand_security_query。 | <code>        (("爆破" in raw) or ("失败登录" in raw and "短时间" in raw), "brute force credential attack 暴力破解"),</code> |
| L0722 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 expand_security_query。 | <code>        (("../" in raw) or "路径穿越" in raw, "path traversal directory traversal 路径遍历"),</code> |
| L0723 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 expand_security_query。 | <code>    ]</code> |
| L0724 | 遍历集合中的数据项并逐项处理，当前位于函数 expand_security_query。 | <code>    for matched, terms in rules:</code> |
| L0725 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 expand_security_query。 | <code>        if matched:</code> |
| L0726 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 expand_security_query。 | <code>            additions.append(terms)</code> |
| L0727 | 结束当前函数并把结果返回给调用方，当前位于函数 expand_security_query。 | <code>    return f"{raw}\n安全领域标准术语：{' '.join(additions)}" if additions else raw</code> |
| L0728 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0729 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0730 | 定义diversifycandidates函数 &#96;diversify_candidates&#96;，封装可复用业务逻辑。 | <code>def diversify_candidates(rows: Sequence[Dict[str, Any]], per_document: int = 12, limit: int = 30) -&gt; List[Dict[str, Any]]:</code> |
| L0731 | 计算并保存 &#96;selected&#96;（selected），供后续逻辑使用，当前位于函数 diversify_candidates。 | <code>    selected: List[Dict[str, Any]] = []</code> |
| L0732 | 计算并保存 &#96;counts&#96;（counts），供后续逻辑使用，当前位于函数 diversify_candidates。 | <code>    counts: Dict[int, int] = {}</code> |
| L0733 | 遍历集合中的数据项并逐项处理，当前位于函数 diversify_candidates。 | <code>    for row in rows:</code> |
| L0734 | 计算并保存 &#96;document_id&#96;（documentid），供后续逻辑使用，当前位于函数 diversify_candidates。 | <code>        document_id = int(row.get("document_id") or 0)</code> |
| L0735 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 diversify_candidates。 | <code>        if counts.get(document_id, 0) &gt;= per_document:</code> |
| L0736 | 控制当前循环或占位分支的执行流程，当前位于函数 diversify_candidates。 | <code>            continue</code> |
| L0737 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 diversify_candidates。 | <code>        selected.append(row)</code> |
| L0738 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 diversify_candidates。 | <code>        counts[document_id] = counts.get(document_id, 0) + 1</code> |
| L0739 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 diversify_candidates。 | <code>        if len(selected) &gt;= limit:</code> |
| L0740 | 控制当前循环或占位分支的执行流程，当前位于函数 diversify_candidates。 | <code>            break</code> |
| L0741 | 结束当前函数并把结果返回给调用方，当前位于函数 diversify_candidates。 | <code>    return selected</code> |
| L0742 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0743 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0744 | 定义hybridsearch函数 &#96;hybrid_search&#96;，封装可复用业务逻辑。 | <code>def hybrid_search(</code> |
| L0745 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>    conn: Any,</code> |
| L0746 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>    data_dir: Path,</code> |
| L0747 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>    api_config: Dict[str, Any],</code> |
| L0748 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>    kb_id: int,</code> |
| L0749 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>    query: str,</code> |
| L0750 | 计算并保存 &#96;username&#96;（username），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>    username: str = "system",</code> |
| L0751 | 计算并保存 &#96;save_test&#96;（保存test），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>    save_test: bool = False,</code> |
| L0752 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 hybrid_search。 | <code>) -&gt; Dict[str, Any]:</code> |
| L0753 | 计算并保存 &#96;started&#96;（started），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>    started = time.perf_counter()</code> |
| L0754 | 计算并保存 &#96;kb&#96;（kb），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>    kb = get_kb(conn, kb_id)</code> |
| L0755 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 hybrid_search。 | <code>    if not kb:</code> |
| L0756 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 hybrid_search。 | <code>        raise KeyError("知识库不存在")</code> |
| L0757 | 计算并保存 &#96;query&#96;（query），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>    query = str(query or "").strip()</code> |
| L0758 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 hybrid_search。 | <code>    if not query:</code> |
| L0759 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 hybrid_search。 | <code>        raise ValueError("测试文本不能为空")</code> |
| L0760 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>    rows = list_chunks(conn, kb_id)</code> |
| L0761 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>    rows = [row for row in rows if int(row.get("enabled") or 0) == 1]</code> |
| L0762 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 hybrid_search。 | <code>    if not rows:</code> |
| L0763 | 结束当前函数并把结果返回给调用方，当前位于函数 hybrid_search。 | <code>        return {"items": [], "duration_ms": 0, "query": query}</code> |
| L0764 | 计算并保存 &#96;search_query&#96;（searchquery），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>    search_query = expand_security_query(query)</code> |
| L0765 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 hybrid_search。 | <code>    vector_scores: Dict[int, float] = {}</code> |
| L0766 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 hybrid_search。 | <code>    table = _lance_table(data_dir, int(api_config["embedding_dimensions"]), create=False)</code> |
| L0767 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 hybrid_search。 | <code>    if table is not None:</code> |
| L0768 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 hybrid_search。 | <code>        vector = embed_texts([search_query], api_config)[0]</code> |
| L0769 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>        result = (</code> |
| L0770 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 hybrid_search。 | <code>            table.search(vector)</code> |
| L0771 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>            .where(f"kb_id = {int(kb_id)}")</code> |
| L0772 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 hybrid_search。 | <code>            .limit(min(int(kb["vector_top_k"]), len(rows)))</code> |
| L0773 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>            .to_list()</code> |
| L0774 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 hybrid_search。 | <code>        )</code> |
| L0775 | 遍历集合中的数据项并逐项处理，当前位于函数 hybrid_search。 | <code>        for rank, item in enumerate(result, 1):</code> |
| L0776 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 hybrid_search。 | <code>            vector_scores[int(item["chunk_id"])] = 1.0 / (60 + rank)</code> |
| L0777 | 计算并保存 &#96;bm25&#96;（bm25），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>    bm25 = _bm25_scores(search_query, rows)</code> |
| L0778 | 计算并保存 &#96;keyword_ranked&#96;（keywordranked），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>    keyword_ranked = sorted(bm25, key=bm25.get, reverse=True)[: int(kb["keyword_top_k"])]</code> |
| L0779 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 hybrid_search。 | <code>    fused: Dict[int, float] = dict(vector_scores)</code> |
| L0780 | 遍历集合中的数据项并逐项处理，当前位于函数 hybrid_search。 | <code>    for rank, chunk_id in enumerate(keyword_ranked, 1):</code> |
| L0781 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>        fused[chunk_id] = fused.get(chunk_id, 0.0) + 1.0 / (60 + rank)</code> |
| L0782 | 计算并保存 &#96;row_map&#96;（rowmap），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>    row_map = {int(row["id"]): row for row in rows}</code> |
| L0783 | 计算并保存 &#96;fused_rows&#96;（fused数据库记录），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>    fused_rows = [row_map[cid] for cid in sorted(fused, key=fused.get, reverse=True) if cid in row_map]</code> |
| L0784 | 计算并保存 &#96;candidates&#96;（candidates），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>    candidates = diversify_candidates(fused_rows, per_document=12, limit=30)</code> |
| L0785 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 hybrid_search。 | <code>    ranked = rerank(search_query, [row["content"] for row in candidates], api_config, min(20, len(candidates)))</code> |
| L0786 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>    items = []</code> |
| L0787 | 计算并保存 &#96;document_counts&#96;（documentcounts），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>    document_counts: Dict[int, int] = {}</code> |
| L0788 | 计算并保存 &#96;threshold&#96;（threshold），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>    threshold = float(kb["score_threshold"])</code> |
| L0789 | 遍历集合中的数据项并逐项处理，当前位于函数 hybrid_search。 | <code>    for item in ranked:</code> |
| L0790 | 计算并保存 &#96;index&#96;（index），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>        index = int(item.get("index", -1))</code> |
| L0791 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 hybrid_search。 | <code>        if index &lt; 0 or index &gt;= len(candidates):</code> |
| L0792 | 控制当前循环或占位分支的执行流程，当前位于函数 hybrid_search。 | <code>            continue</code> |
| L0793 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>        row = dict(candidates[index])</code> |
| L0794 | 计算并保存 &#96;document_id&#96;（documentid），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>        document_id = int(row["document_id"])</code> |
| L0795 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 hybrid_search。 | <code>        if document_counts.get(document_id, 0) &gt;= 3:</code> |
| L0796 | 控制当前循环或占位分支的执行流程，当前位于函数 hybrid_search。 | <code>            continue</code> |
| L0797 | 计算并保存 &#96;score&#96;（score），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>        score = float(item.get("relevance_score") or item.get("score") or 0.0)</code> |
| L0798 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 hybrid_search。 | <code>        if score &lt; threshold:</code> |
| L0799 | 控制当前循环或占位分支的执行流程，当前位于函数 hybrid_search。 | <code>            continue</code> |
| L0800 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 hybrid_search。 | <code>        items.append(</code> |
| L0801 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>            {</code> |
| L0802 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>                "chunk_id": int(row["id"]),</code> |
| L0803 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>                "document_id": int(row["document_id"]),</code> |
| L0804 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>                "document_name": row.get("document_name"),</code> |
| L0805 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>                "chunk_index": int(row["chunk_index"]),</code> |
| L0806 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>                "title_path": row.get("title_path") or "正文",</code> |
| L0807 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>                "content": row.get("content") or "",</code> |
| L0808 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>                "score": round(score, 6),</code> |
| L0809 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>                "rrf_score": round(fused.get(int(row["id"]), 0.0), 6),</code> |
| L0810 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 hybrid_search。 | <code>            }</code> |
| L0811 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 hybrid_search。 | <code>        )</code> |
| L0812 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>        document_counts[document_id] = document_counts.get(document_id, 0) + 1</code> |
| L0813 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 hybrid_search。 | <code>        if len(items) &gt;= int(kb["final_top_k"]):</code> |
| L0814 | 控制当前循环或占位分支的执行流程，当前位于函数 hybrid_search。 | <code>            break</code> |
| L0815 | 计算并保存 &#96;duration_ms&#96;（durationms），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>    duration_ms = int((time.perf_counter() - started) * 1000)</code> |
| L0816 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 hybrid_search。 | <code>    if items:</code> |
| L0817 | 计算并保存 &#96;ids&#96;（ids），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>        ids = [item["chunk_id"] for item in items]</code> |
| L0818 | 计算并保存 &#96;placeholders&#96;（placeholders），供后续逻辑使用，当前位于函数 hybrid_search。 | <code>        placeholders = ",".join(["%s"] * len(ids))</code> |
| L0819 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 hybrid_search。 | <code>        with conn.cursor() as cur:</code> |
| L0820 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 hybrid_search。 | <code>            cur.execute(</code> |
| L0821 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>                f"UPDATE rag_chunks SET retrieval_count=retrieval_count+1,last_retrieved_at=NOW() WHERE id IN ({placeholders})",</code> |
| L0822 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>                tuple(ids),</code> |
| L0823 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 hybrid_search。 | <code>            )</code> |
| L0824 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>        conn.commit()</code> |
| L0825 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 hybrid_search。 | <code>    if save_test:</code> |
| L0826 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 hybrid_search。 | <code>        with conn.cursor() as cur:</code> |
| L0827 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 hybrid_search。 | <code>            cur.execute(</code> |
| L0828 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 hybrid_search。 | <code>                """INSERT INTO rag_retrieval_tests</code> |
| L0829 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 hybrid_search。 | <code>                (kb_id,query_text,duration_ms,result_count,results_json,created_by) VALUES (%s,%s,%s,%s,%s,%s)""",</code> |
| L0830 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>                (kb_id, query, duration_ms, len(items), json.dumps(items, ensure_ascii=False), username),</code> |
| L0831 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 hybrid_search。 | <code>            )</code> |
| L0832 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 hybrid_search。 | <code>        conn.commit()</code> |
| L0833 | 结束当前函数并把结果返回给调用方，当前位于函数 hybrid_search。 | <code>    return {"items": items, "duration_ms": duration_ms, "query": query}</code> |
| L0834 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0835 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0836 | 定义列出testhistory函数 &#96;list_test_history&#96;，封装可复用业务逻辑。 | <code>def list_test_history(conn: Any, kb_id: int, limit: int = 30) -&gt; List[Dict[str, Any]]:</code> |
| L0837 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 list_test_history。 | <code>    with conn.cursor() as cur:</code> |
| L0838 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 list_test_history。 | <code>        cur.execute(</code> |
| L0839 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 list_test_history。 | <code>            """SELECT id,kb_id,query_text,duration_ms,result_count,created_by,created_at</code> |
| L0840 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_test_history。 | <code>            FROM rag_retrieval_tests WHERE kb_id=%s ORDER BY id DESC LIMIT %s""",</code> |
| L0841 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_test_history。 | <code>            (kb_id, min(max(1, limit), 100)),</code> |
| L0842 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 list_test_history。 | <code>        )</code> |
| L0843 | 结束当前函数并把结果返回给调用方，当前位于函数 list_test_history。 | <code>        return list(cur.fetchall())</code> |
| L0844 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0845 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0846 | 定义列出evalcases函数 &#96;list_eval_cases&#96;，封装可复用业务逻辑。 | <code>def list_eval_cases(conn: Any, kb_id: int) -&gt; List[Dict[str, Any]]:</code> |
| L0847 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 list_eval_cases。 | <code>    with conn.cursor() as cur:</code> |
| L0848 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 list_eval_cases。 | <code>        cur.execute(</code> |
| L0849 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 list_eval_cases。 | <code>            """SELECT id,kb_id,question,expected_keywords,expected_document,enabled,created_at</code> |
| L0850 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_eval_cases。 | <code>            FROM rag_eval_cases WHERE kb_id=%s ORDER BY id""",</code> |
| L0851 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_eval_cases。 | <code>            (kb_id,),</code> |
| L0852 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 list_eval_cases。 | <code>        )</code> |
| L0853 | 结束当前函数并把结果返回给调用方，当前位于函数 list_eval_cases。 | <code>        return list(cur.fetchall())</code> |
| L0854 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0855 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0856 | 定义保存evalcase函数 &#96;save_eval_case&#96;，封装可复用业务逻辑。 | <code>def save_eval_case(conn: Any, kb_id: int, payload: Dict[str, Any], case_id: int = 0) -&gt; Dict[str, Any]:</code> |
| L0857 | 计算并保存 &#96;question&#96;（question），供后续逻辑使用，当前位于函数 save_eval_case。 | <code>    question = str(payload.get("question") or "").strip()</code> |
| L0858 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 save_eval_case。 | <code>    if not question:</code> |
| L0859 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 save_eval_case。 | <code>        raise ValueError("测试问题不能为空")</code> |
| L0860 | 计算并保存 &#96;keywords&#96;（keywords），供后续逻辑使用，当前位于函数 save_eval_case。 | <code>    keywords = str(payload.get("expected_keywords") or "").strip()</code> |
| L0861 | 计算并保存 &#96;expected_document&#96;（expecteddocument），供后续逻辑使用，当前位于函数 save_eval_case。 | <code>    expected_document = str(payload.get("expected_document") or "").strip()</code> |
| L0862 | 计算并保存 &#96;enabled&#96;（enabled），供后续逻辑使用，当前位于函数 save_eval_case。 | <code>    enabled = 1 if bool(payload.get("enabled", True)) else 0</code> |
| L0863 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 save_eval_case。 | <code>    with conn.cursor() as cur:</code> |
| L0864 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 save_eval_case。 | <code>        if case_id:</code> |
| L0865 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 save_eval_case。 | <code>            cur.execute(</code> |
| L0866 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 save_eval_case。 | <code>                """UPDATE rag_eval_cases SET question=%s,expected_keywords=%s,</code> |
| L0867 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 save_eval_case。 | <code>                expected_document=%s,enabled=%s WHERE id=%s AND kb_id=%s""",</code> |
| L0868 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 save_eval_case。 | <code>                (question, keywords, expected_document, enabled, case_id, kb_id),</code> |
| L0869 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 save_eval_case。 | <code>            )</code> |
| L0870 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 save_eval_case。 | <code>            if not cur.rowcount:</code> |
| L0871 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 save_eval_case。 | <code>                raise KeyError("回归用例不存在")</code> |
| L0872 | 处理前述条件均未命中的情况，当前位于函数 save_eval_case。 | <code>        else:</code> |
| L0873 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 save_eval_case。 | <code>            cur.execute(</code> |
| L0874 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 save_eval_case。 | <code>                """INSERT INTO rag_eval_cases</code> |
| L0875 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 save_eval_case。 | <code>                (kb_id,question,expected_keywords,expected_document,enabled)</code> |
| L0876 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 save_eval_case。 | <code>                VALUES (%s,%s,%s,%s,%s)""",</code> |
| L0877 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 save_eval_case。 | <code>                (kb_id, question, keywords, expected_document, enabled),</code> |
| L0878 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 save_eval_case。 | <code>            )</code> |
| L0879 | 计算并保存 &#96;case_id&#96;（caseid），供后续逻辑使用，当前位于函数 save_eval_case。 | <code>            case_id = int(cur.lastrowid)</code> |
| L0880 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 save_eval_case。 | <code>    conn.commit()</code> |
| L0881 | 结束当前函数并把结果返回给调用方，当前位于函数 save_eval_case。 | <code>    return next(row for row in list_eval_cases(conn, kb_id) if int(row["id"]) == int(case_id))</code> |
| L0882 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0883 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0884 | 定义删除evalcase函数 &#96;delete_eval_case&#96;，封装可复用业务逻辑。 | <code>def delete_eval_case(conn: Any, kb_id: int, case_id: int) -&gt; bool:</code> |
| L0885 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 delete_eval_case。 | <code>    with conn.cursor() as cur:</code> |
| L0886 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 delete_eval_case。 | <code>        cur.execute("DELETE FROM rag_eval_cases WHERE id=%s AND kb_id=%s", (case_id, kb_id))</code> |
| L0887 | 计算并保存 &#96;changed&#96;（changed），供后续逻辑使用，当前位于函数 delete_eval_case。 | <code>        changed = bool(cur.rowcount)</code> |
| L0888 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 delete_eval_case。 | <code>    conn.commit()</code> |
| L0889 | 结束当前函数并把结果返回给调用方，当前位于函数 delete_eval_case。 | <code>    return changed</code> |
| L0890 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0891 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0892 | 定义评估retrieval数据项函数 &#96;evaluate_retrieval_items&#96;，封装可复用业务逻辑。 | <code>def evaluate_retrieval_items(</code> |
| L0893 | 计算并保存 &#96;items&#96;（数据项），供后续逻辑使用，当前位于函数 evaluate_retrieval_items。 | <code>    items: Sequence[Dict[str, Any]], expected_keywords: str = "", expected_document: str = ""</code> |
| L0894 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 evaluate_retrieval_items。 | <code>) -&gt; Dict[str, Any]:</code> |
| L0895 | 计算并保存 &#96;keywords&#96;（keywords），供后续逻辑使用，当前位于函数 evaluate_retrieval_items。 | <code>    keywords = [part.strip().lower() for part in re.split(r"[,，;；\n]+", expected_keywords or "") if part.strip()]</code> |
| L0896 | 计算并保存 &#96;combined&#96;（combined），供后续逻辑使用，当前位于函数 evaluate_retrieval_items。 | <code>    combined = "\n".join(</code> |
| L0897 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 evaluate_retrieval_items。 | <code>        f"{item.get('document_name') or ''}\n{item.get('title_path') or ''}\n{item.get('content') or ''}" for item in items</code> |
| L0898 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 evaluate_retrieval_items。 | <code>    ).lower()</code> |
| L0899 | 计算并保存 &#96;matched_keywords&#96;（matchedkeywords），供后续逻辑使用，当前位于函数 evaluate_retrieval_items。 | <code>    matched_keywords = [keyword for keyword in keywords if keyword in combined]</code> |
| L0900 | 计算并保存 &#96;document_ok&#96;（documentok），供后续逻辑使用，当前位于函数 evaluate_retrieval_items。 | <code>    document_ok = True</code> |
| L0901 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 evaluate_retrieval_items。 | <code>    if expected_document.strip():</code> |
| L0902 | 计算并保存 &#96;needle&#96;（needle），供后续逻辑使用，当前位于函数 evaluate_retrieval_items。 | <code>        needle = expected_document.strip().lower()</code> |
| L0903 | 计算并保存 &#96;document_ok&#96;（documentok），供后续逻辑使用，当前位于函数 evaluate_retrieval_items。 | <code>        document_ok = any(needle in str(item.get("document_name") or "").lower() for item in items)</code> |
| L0904 | 计算并保存 &#96;keyword_ok&#96;（keywordok），供后续逻辑使用，当前位于函数 evaluate_retrieval_items。 | <code>    keyword_ok = not keywords or bool(matched_keywords)</code> |
| L0905 | 控制当前循环或占位分支的执行流程，当前位于函数 evaluate_retrieval_items。 | <code>    passed = bool(items) and keyword_ok and document_ok</code> |
| L0906 | 计算并保存 &#96;reasons&#96;（reasons），供后续逻辑使用，当前位于函数 evaluate_retrieval_items。 | <code>    reasons = []</code> |
| L0907 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 evaluate_retrieval_items。 | <code>    if not items:</code> |
| L0908 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 evaluate_retrieval_items。 | <code>        reasons.append("未召回任何切片")</code> |
| L0909 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 evaluate_retrieval_items。 | <code>    if keywords and not matched_keywords:</code> |
| L0910 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 evaluate_retrieval_items。 | <code>        reasons.append("未命中任一期望关键词")</code> |
| L0911 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 evaluate_retrieval_items。 | <code>    if not document_ok:</code> |
| L0912 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 evaluate_retrieval_items。 | <code>        reasons.append("未召回期望来源文档")</code> |
| L0913 | 结束当前函数并把结果返回给调用方，当前位于函数 evaluate_retrieval_items。 | <code>    return {</code> |
| L0914 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 evaluate_retrieval_items。 | <code>        "passed": passed,</code> |
| L0915 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 evaluate_retrieval_items。 | <code>        "matched_keywords": matched_keywords,</code> |
| L0916 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 evaluate_retrieval_items。 | <code>        "reason": "；".join(reasons) if reasons else "召回结果满足预期",</code> |
| L0917 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 evaluate_retrieval_items。 | <code>    }</code> |
| L0918 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0919 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0920 | 定义运行evalsuite函数 &#96;run_eval_suite&#96;，封装可复用业务逻辑。 | <code>def run_eval_suite(</code> |
| L0921 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>    conn: Any,</code> |
| L0922 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>    data_dir: Path,</code> |
| L0923 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>    api_config: Dict[str, Any],</code> |
| L0924 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>    kb_id: int,</code> |
| L0925 | 计算并保存 &#96;username&#96;（username），供后续逻辑使用，当前位于函数 run_eval_suite。 | <code>    username: str = "system",</code> |
| L0926 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_eval_suite。 | <code>) -&gt; Dict[str, Any]:</code> |
| L0927 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>    cases = [row for row in list_eval_cases(conn, kb_id) if int(row.get("enabled") or 0) == 1]</code> |
| L0928 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 run_eval_suite。 | <code>    if not cases:</code> |
| L0929 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 run_eval_suite。 | <code>        raise ValueError("请先添加至少一条已启用的回归用例")</code> |
| L0930 | 计算并保存 &#96;results&#96;（results），供后续逻辑使用，当前位于函数 run_eval_suite。 | <code>    results: List[Dict[str, Any]] = []</code> |
| L0931 | 遍历集合中的数据项并逐项处理，当前位于函数 run_eval_suite。 | <code>    for case in cases:</code> |
| L0932 | 计算并保存 &#96;search_result&#96;（search结果），供后续逻辑使用，当前位于函数 run_eval_suite。 | <code>        search_result = hybrid_search(</code> |
| L0933 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>            conn, data_dir, api_config, kb_id, str(case["question"]), username=username, save_test=False</code> |
| L0934 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_eval_suite。 | <code>        )</code> |
| L0935 | 计算并保存 &#96;evaluation&#96;（evaluation），供后续逻辑使用，当前位于函数 run_eval_suite。 | <code>        evaluation = evaluate_retrieval_items(</code> |
| L0936 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>            search_result.get("items") or [],</code> |
| L0937 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>            str(case.get("expected_keywords") or ""),</code> |
| L0938 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>            str(case.get("expected_document") or ""),</code> |
| L0939 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_eval_suite。 | <code>        )</code> |
| L0940 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 run_eval_suite。 | <code>        results.append(</code> |
| L0941 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>            {</code> |
| L0942 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>                "case_id": int(case["id"]),</code> |
| L0943 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>                "question": case["question"],</code> |
| L0944 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>                "expected_keywords": case.get("expected_keywords") or "",</code> |
| L0945 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>                "expected_document": case.get("expected_document") or "",</code> |
| L0946 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>                "duration_ms": int(search_result.get("duration_ms") or 0),</code> |
| L0947 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>                "top_document": (search_result.get("items") or [{}])[0].get("document_name") if search_result.get("items") else "",</code> |
| L0948 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>                "top_score": (search_result.get("items") or [{}])[0].get("score") if search_result.get("items") else 0,</code> |
| L0949 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>                **evaluation,</code> |
| L0950 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_eval_suite。 | <code>            }</code> |
| L0951 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_eval_suite。 | <code>        )</code> |
| L0952 | 控制当前循环或占位分支的执行流程，当前位于函数 run_eval_suite。 | <code>    passed = sum(1 for row in results if row["passed"])</code> |
| L0953 | 计算并保存 &#96;total&#96;（total），供后续逻辑使用，当前位于函数 run_eval_suite。 | <code>    total = len(results)</code> |
| L0954 | 计算并保存 &#96;average_ms&#96;（averagems），供后续逻辑使用，当前位于函数 run_eval_suite。 | <code>    average_ms = int(sum(row["duration_ms"] for row in results) / total) if total else 0</code> |
| L0955 | 控制当前循环或占位分支的执行流程，当前位于函数 run_eval_suite。 | <code>    pass_rate = passed / total if total else 0.0</code> |
| L0956 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 run_eval_suite。 | <code>    with conn.cursor() as cur:</code> |
| L0957 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 run_eval_suite。 | <code>        cur.execute(</code> |
| L0958 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 run_eval_suite。 | <code>            """INSERT INTO rag_eval_runs</code> |
| L0959 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 run_eval_suite。 | <code>            (kb_id,total_cases,passed_cases,pass_rate,average_duration_ms,results_json,created_by)</code> |
| L0960 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 run_eval_suite。 | <code>            VALUES (%s,%s,%s,%s,%s,%s,%s)""",</code> |
| L0961 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>            (kb_id, total, passed, pass_rate, average_ms, json.dumps(results, ensure_ascii=False), username),</code> |
| L0962 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_eval_suite。 | <code>        )</code> |
| L0963 | 计算并保存 &#96;run_id&#96;（运行id），供后续逻辑使用，当前位于函数 run_eval_suite。 | <code>        run_id = int(cur.lastrowid)</code> |
| L0964 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>    conn.commit()</code> |
| L0965 | 结束当前函数并把结果返回给调用方，当前位于函数 run_eval_suite。 | <code>    return {</code> |
| L0966 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>        "run_id": run_id,</code> |
| L0967 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>        "total_cases": total,</code> |
| L0968 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>        "passed_cases": passed,</code> |
| L0969 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>        "pass_rate": round(pass_rate, 6),</code> |
| L0970 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>        "average_duration_ms": average_ms,</code> |
| L0971 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_eval_suite。 | <code>        "items": results,</code> |
| L0972 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_eval_suite。 | <code>    }</code> |
| L0973 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0974 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0975 | 定义列出evalruns函数 &#96;list_eval_runs&#96;，封装可复用业务逻辑。 | <code>def list_eval_runs(conn: Any, kb_id: int, limit: int = 20) -&gt; List[Dict[str, Any]]:</code> |
| L0976 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 list_eval_runs。 | <code>    with conn.cursor() as cur:</code> |
| L0977 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 list_eval_runs。 | <code>        cur.execute(</code> |
| L0978 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 list_eval_runs。 | <code>            """SELECT id,kb_id,total_cases,passed_cases,pass_rate,average_duration_ms,</code> |
| L0979 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 list_eval_runs。 | <code>            results_json,created_by,created_at FROM rag_eval_runs WHERE kb_id=%s ORDER BY id DESC LIMIT %s""",</code> |
| L0980 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_eval_runs。 | <code>            (kb_id, min(max(1, limit), 100)),</code> |
| L0981 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 list_eval_runs。 | <code>        )</code> |
| L0982 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 list_eval_runs。 | <code>        rows = list(cur.fetchall())</code> |
| L0983 | 遍历集合中的数据项并逐项处理，当前位于函数 list_eval_runs。 | <code>    for row in rows:</code> |
| L0984 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 list_eval_runs。 | <code>        try:</code> |
| L0985 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_eval_runs。 | <code>            row["items"] = json.loads(row.pop("results_json") or "[]")</code> |
| L0986 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 list_eval_runs。 | <code>        except (TypeError, ValueError):</code> |
| L0987 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 list_eval_runs。 | <code>            row["items"] = []</code> |
| L0988 | 结束当前函数并把结果返回给调用方，当前位于函数 list_eval_runs。 | <code>    return rows</code> |
| L0989 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0990 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0991 | 定义migratelegacysqlite函数 &#96;migrate_legacy_sqlite&#96;，封装可复用业务逻辑。 | <code>def migrate_legacy_sqlite(conn: Any, sqlite_path: Path) -&gt; Dict[str, int]:</code> |
| L0992 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 migrate_legacy_sqlite。 | <code>    """Import the old FTS rows as one source document without deleting it."""</code> |
| L0993 | 导入后续逻辑所需的模块、类或函数：&#96;import sqlite3&#96;。 | <code>    import sqlite3</code> |
| L0994 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0995 | 计算并保存 &#96;kb_id&#96;（kbid），供后续逻辑使用，当前位于函数 migrate_legacy_sqlite。 | <code>    kb_id = ensure_default_kb(conn)</code> |
| L0996 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 migrate_legacy_sqlite。 | <code>    with conn.cursor() as cur:</code> |
| L0997 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 migrate_legacy_sqlite。 | <code>        cur.execute("SELECT COUNT(*) AS c FROM rag_documents WHERE source_type='legacy'")</code> |
| L0998 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 migrate_legacy_sqlite。 | <code>        if int((cur.fetchone() or {}).get("c") or 0) &gt; 0 or not sqlite_path.exists():</code> |
| L0999 | 结束当前函数并把结果返回给调用方，当前位于函数 migrate_legacy_sqlite。 | <code>            return {"kb_id": kb_id, "documents": 0, "chunks": 0}</code> |
| L1000 | 计算并保存 &#96;legacy&#96;（legacy），供后续逻辑使用，当前位于函数 migrate_legacy_sqlite。 | <code>    legacy = sqlite3.connect(str(sqlite_path))</code> |
| L1001 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 migrate_legacy_sqlite。 | <code>    legacy.row_factory = sqlite3.Row</code> |
| L1002 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 migrate_legacy_sqlite。 | <code>    try:</code> |
| L1003 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 migrate_legacy_sqlite。 | <code>        rows = [dict(row) for row in legacy.execute("SELECT * FROM rag_docs").fetchall()]</code> |
| L1004 | 无论成功或异常都执行资源清理，当前位于函数 migrate_legacy_sqlite。 | <code>    finally:</code> |
| L1005 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 migrate_legacy_sqlite。 | <code>        legacy.close()</code> |
| L1006 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 migrate_legacy_sqlite。 | <code>    if not rows:</code> |
| L1007 | 结束当前函数并把结果返回给调用方，当前位于函数 migrate_legacy_sqlite。 | <code>        return {"kb_id": kb_id, "documents": 0, "chunks": 0}</code> |
| L1008 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 migrate_legacy_sqlite。 | <code>    with conn.cursor() as cur:</code> |
| L1009 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 migrate_legacy_sqlite。 | <code>        cur.execute(</code> |
| L1010 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 migrate_legacy_sqlite。 | <code>            """INSERT INTO rag_documents</code> |
| L1011 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 migrate_legacy_sqlite。 | <code>            (kb_id,name,source_type,source_uri,status,progress,chunk_count,char_count,created_by)</code> |
| L1012 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 migrate_legacy_sqlite。 | <code>            VALUES (%s,%s,'legacy','legacy-sqlite','pending',0,%s,%s,'migration')""",</code> |
| L1013 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 migrate_legacy_sqlite。 | <code>            (kb_id, "原 RAG 种子知识迁移", len(rows), sum(len(str(row.get("content") or "")) for row in rows)),</code> |
| L1014 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 migrate_legacy_sqlite。 | <code>        )</code> |
| L1015 | 计算并保存 &#96;document_id&#96;（documentid），供后续逻辑使用，当前位于函数 migrate_legacy_sqlite。 | <code>        document_id = int(cur.lastrowid)</code> |
| L1016 | 遍历集合中的数据项并逐项处理，当前位于函数 migrate_legacy_sqlite。 | <code>        for index, row in enumerate(rows):</code> |
| L1017 | 计算并保存 &#96;content&#96;（content），供后续逻辑使用，当前位于函数 migrate_legacy_sqlite。 | <code>            content = "\n".join(</code> |
| L1018 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 migrate_legacy_sqlite。 | <code>                part</code> |
| L1019 | 遍历集合中的数据项并逐项处理，当前位于函数 migrate_legacy_sqlite。 | <code>                for part in [</code> |
| L1020 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 migrate_legacy_sqlite。 | <code>                    f"攻击类型：{row.get('attack_type') or '通用'}",</code> |
| L1021 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 migrate_legacy_sqlite。 | <code>                    str(row.get("content") or ""),</code> |
| L1022 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 migrate_legacy_sqlite。 | <code>                    f"判定依据：{row.get('evidence') or ''}",</code> |
| L1023 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 migrate_legacy_sqlite。 | <code>                    f"处置建议：{row.get('mitigation') or ''}",</code> |
| L1024 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 migrate_legacy_sqlite。 | <code>                    f"来源：{row.get('source') or ''}",</code> |
| L1025 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 migrate_legacy_sqlite。 | <code>                ]</code> |
| L1026 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 migrate_legacy_sqlite。 | <code>                if part.strip("：\n ")</code> |
| L1027 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 migrate_legacy_sqlite。 | <code>            )</code> |
| L1028 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 migrate_legacy_sqlite。 | <code>            cur.execute(</code> |
| L1029 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 migrate_legacy_sqlite。 | <code>                """INSERT INTO rag_chunks</code> |
| L1030 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 migrate_legacy_sqlite。 | <code>                (kb_id,document_id,chunk_index,title_path,content,token_count,vector_key)</code> |
| L1031 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 migrate_legacy_sqlite。 | <code>                VALUES (%s,%s,%s,%s,%s,%s,%s)""",</code> |
| L1032 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 migrate_legacy_sqlite。 | <code>                (kb_id, document_id, index, str(row.get("title") or "历史知识")[:600], content, max(1, len(content) // 2), uuid.uuid4().hex),</code> |
| L1033 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 migrate_legacy_sqlite。 | <code>            )</code> |
| L1034 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 migrate_legacy_sqlite。 | <code>    conn.commit()</code> |
| L1035 | 结束当前函数并把结果返回给调用方，当前位于函数 migrate_legacy_sqlite。 | <code>    return {"kb_id": kb_id, "documents": 1, "chunks": len(rows), "document_id": document_id}</code> |
| L1036 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1037 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1038 | 定义indexpendingdocument函数 &#96;index_pending_document&#96;，封装可复用业务逻辑。 | <code>def index_pending_document(conn: Any, data_dir: Path, api_config: Dict[str, Any], document_id: int) -&gt; Dict[str, Any]:</code> |
| L1039 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 index_pending_document。 | <code>    """Vectorize chunks created by the compatibility migration."""</code> |
| L1040 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 index_pending_document。 | <code>    with conn.cursor() as cur:</code> |
| L1041 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 index_pending_document。 | <code>        cur.execute("SELECT * FROM rag_documents WHERE id=%s", (document_id,))</code> |
| L1042 | 计算并保存 &#96;document&#96;（document），供后续逻辑使用，当前位于函数 index_pending_document。 | <code>        document = cur.fetchone()</code> |
| L1043 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 index_pending_document。 | <code>        cur.execute("SELECT * FROM rag_chunks WHERE document_id=%s ORDER BY chunk_index", (document_id,))</code> |
| L1044 | 计算并保存 &#96;chunks&#96;（chunks），供后续逻辑使用，当前位于函数 index_pending_document。 | <code>        chunks = list(cur.fetchall())</code> |
| L1045 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 index_pending_document。 | <code>    if not document or not chunks:</code> |
| L1046 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 index_pending_document。 | <code>        raise KeyError("待索引文档不存在")</code> |
| L1047 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 index_pending_document。 | <code>    vectors = []</code> |
| L1048 | 遍历集合中的数据项并逐项处理，当前位于函数 index_pending_document。 | <code>    for offset in range(0, len(chunks), 10):</code> |
| L1049 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 index_pending_document。 | <code>        vectors.extend(embed_texts([row["content"] for row in chunks[offset : offset + 10]], api_config))</code> |
| L1050 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 index_pending_document。 | <code>    table = _lance_table(data_dir, int(api_config["embedding_dimensions"]), create=True)</code> |
| L1051 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 index_pending_document。 | <code>    table.add(</code> |
| L1052 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 index_pending_document。 | <code>        [</code> |
| L1053 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 index_pending_document。 | <code>            {</code> |
| L1054 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 index_pending_document。 | <code>                "vector_key": str(row["vector_key"]),</code> |
| L1055 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 index_pending_document。 | <code>                "kb_id": int(row["kb_id"]),</code> |
| L1056 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 index_pending_document。 | <code>                "document_id": int(row["document_id"]),</code> |
| L1057 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 index_pending_document。 | <code>                "chunk_id": int(row["id"]),</code> |
| L1058 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 index_pending_document。 | <code>                "title": str(row.get("title_path") or document["name"]),</code> |
| L1059 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 index_pending_document。 | <code>                "content": str(row["content"]),</code> |
| L1060 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 index_pending_document。 | <code>                "vector": vector,</code> |
| L1061 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 index_pending_document。 | <code>            }</code> |
| L1062 | 遍历集合中的数据项并逐项处理，当前位于函数 index_pending_document。 | <code>            for row, vector in zip(chunks, vectors)</code> |
| L1063 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 index_pending_document。 | <code>        ]</code> |
| L1064 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 index_pending_document。 | <code>    )</code> |
| L1065 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 index_pending_document。 | <code>    with conn.cursor() as cur:</code> |
| L1066 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 index_pending_document。 | <code>        cur.execute("UPDATE rag_documents SET status='ready',progress=100,error_message=NULL WHERE id=%s", (document_id,))</code> |
| L1067 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 index_pending_document。 | <code>    conn.commit()</code> |
| L1068 | 结束当前函数并把结果返回给调用方，当前位于函数 index_pending_document。 | <code>    return {"id": document_id, "chunk_count": len(chunks), "status": "ready"}</code> |
