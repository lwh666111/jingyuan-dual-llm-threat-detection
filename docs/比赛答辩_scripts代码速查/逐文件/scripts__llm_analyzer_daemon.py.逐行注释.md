# `scripts/llm_analyzer_daemon.py` 逐行注释

**脚本用途：** 大模型研判守护进程：消费候选事件、检索 RAG、调用本地或外部模型并写回结构化结论。

**源码行数：** 1403　**函数/类数量：** 35

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0002 | 导入后续逻辑所需的模块、类或函数：&#96;import concurrent.futures&#96;。 | <code>import concurrent.futures</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import os&#96;。 | <code>import os</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import re&#96;。 | <code>import re</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;import sqlite3&#96;。 | <code>import sqlite3</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;import threading&#96;。 | <code>import threading</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;import time&#96;。 | <code>import time</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.error&#96;。 | <code>import urllib.error</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.request&#96;。 | <code>import urllib.request</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime, timedelta&#96;。 | <code>from datetime import datetime, timedelta</code> |
| L0012 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0013 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Dict, List, Optional, Tuple&#96;。 | <code>from typing import Dict, List, Optional, Tuple</code> |
| L0014 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0015 | 导入后续逻辑所需的模块、类或函数：&#96;from pipeline_events import LLM_READY_EVENT, wait_event&#96;。 | <code>from pipeline_events import LLM_READY_EVENT, wait_event</code> |
| L0016 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0017 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0018 | 定义nowiso函数 &#96;now_iso&#96;，封装可复用业务逻辑。 | <code>def now_iso() -&gt; str:</code> |
| L0019 | 结束当前函数并把结果返回给调用方，当前位于函数 now_iso。 | <code>    return datetime.now().isoformat(timespec="seconds")</code> |
| L0020 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0021 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0022 | 定义cachedreviewreadyat函数 &#96;_cached_review_ready_at&#96;，封装可复用业务逻辑。 | <code>def _cached_review_ready_at(event_time, now=None) -&gt; Optional[datetime]:</code> |
| L0023 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _cached_review_ready_at。 | <code>    if isinstance(event_time, str):</code> |
| L0024 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _cached_review_ready_at。 | <code>        try:</code> |
| L0025 | 计算并保存 &#96;event_time&#96;（事件time），供后续逻辑使用，当前位于函数 _cached_review_ready_at。 | <code>            event_time = datetime.fromisoformat(event_time)</code> |
| L0026 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _cached_review_ready_at。 | <code>        except (TypeError, ValueError):</code> |
| L0027 | 结束当前函数并把结果返回给调用方，当前位于函数 _cached_review_ready_at。 | <code>            return None</code> |
| L0028 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _cached_review_ready_at。 | <code>    if not isinstance(event_time, datetime):</code> |
| L0029 | 结束当前函数并把结果返回给调用方，当前位于函数 _cached_review_ready_at。 | <code>        return None</code> |
| L0030 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0031 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _cached_review_ready_at。 | <code>    if event_time.tzinfo is not None:</code> |
| L0032 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 _cached_review_ready_at。 | <code>        current = now if isinstance(now, datetime) else datetime.now(tz=event_time.tzinfo)</code> |
| L0033 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _cached_review_ready_at。 | <code>        if current.tzinfo is None:</code> |
| L0034 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 _cached_review_ready_at。 | <code>            current = current.replace(tzinfo=event_time.tzinfo)</code> |
| L0035 | 处理前述条件均未命中的情况，当前位于函数 _cached_review_ready_at。 | <code>        else:</code> |
| L0036 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 _cached_review_ready_at。 | <code>            current = current.astimezone(event_time.tzinfo)</code> |
| L0037 | 处理前述条件均未命中的情况，当前位于函数 _cached_review_ready_at。 | <code>    else:</code> |
| L0038 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 _cached_review_ready_at。 | <code>        current = now if isinstance(now, datetime) else datetime.now()</code> |
| L0039 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _cached_review_ready_at。 | <code>        if current.tzinfo is not None:</code> |
| L0040 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 _cached_review_ready_at。 | <code>            current = current.astimezone().replace(tzinfo=None)</code> |
| L0041 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0042 | 计算并保存 &#96;age&#96;（age），供后续逻辑使用，当前位于函数 _cached_review_ready_at。 | <code>    age = current - event_time</code> |
| L0043 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _cached_review_ready_at。 | <code>    if age &lt; timedelta(seconds=-60) or age &gt; timedelta(minutes=10):</code> |
| L0044 | 结束当前函数并把结果返回给调用方，当前位于函数 _cached_review_ready_at。 | <code>        return current + timedelta(seconds=5)</code> |
| L0045 | 结束当前函数并把结果返回给调用方，当前位于函数 _cached_review_ready_at。 | <code>    return event_time + timedelta(seconds=5)</code> |
| L0046 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0047 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0048 | 定义log函数 &#96;log&#96;，封装可复用业务逻辑。 | <code>def log(msg: str) -&gt; None:</code> |
| L0049 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 log。 | <code>    print(f"[{now_iso()}] {msg}", flush=True)</code> |
| L0050 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0051 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0052 | 定义读取json函数 &#96;read_json&#96;，封装可复用业务逻辑。 | <code>def read_json(path: Path, default=None):</code> |
| L0053 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_json。 | <code>    if default is None:</code> |
| L0054 | 计算并保存 &#96;default&#96;（default），供后续逻辑使用，当前位于函数 read_json。 | <code>        default = {}</code> |
| L0055 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_json。 | <code>    if not path.exists():</code> |
| L0056 | 结束当前函数并把结果返回给调用方，当前位于函数 read_json。 | <code>        return default</code> |
| L0057 | 遍历集合中的数据项并逐项处理，当前位于函数 read_json。 | <code>    for enc in ("utf-8", "utf-8-sig", "gbk", "latin1"):</code> |
| L0058 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 read_json。 | <code>        try:</code> |
| L0059 | 结束当前函数并把结果返回给调用方，当前位于函数 read_json。 | <code>            return json.loads(path.read_text(encoding=enc))</code> |
| L0060 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 read_json。 | <code>        except Exception:</code> |
| L0061 | 控制当前循环或占位分支的执行流程，当前位于函数 read_json。 | <code>            continue</code> |
| L0062 | 结束当前函数并把结果返回给调用方，当前位于函数 read_json。 | <code>    return default</code> |
| L0063 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0064 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0065 | 定义写入json函数 &#96;write_json&#96;，封装可复用业务逻辑。 | <code>def write_json(path: Path, data) -&gt; None:</code> |
| L0066 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_json。 | <code>    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")</code> |
| L0067 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0068 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0069 | 定义读取text函数 &#96;read_text&#96;，封装可复用业务逻辑。 | <code>def read_text(path: Path, default: str = "") -&gt; str:</code> |
| L0070 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_text。 | <code>    if not path.exists():</code> |
| L0071 | 结束当前函数并把结果返回给调用方，当前位于函数 read_text。 | <code>        return default</code> |
| L0072 | 结束当前函数并把结果返回给调用方，当前位于函数 read_text。 | <code>    return path.read_text(encoding="utf-8", errors="replace")</code> |
| L0073 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0074 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0075 | 定义加载systemprompt函数 &#96;load_system_prompt&#96;，封装可复用业务逻辑。 | <code>def load_system_prompt(prompt_path: Path) -&gt; Tuple[str, float]:</code> |
| L0076 | 计算并保存 &#96;system_prompt&#96;（systemprompt），供后续逻辑使用，当前位于函数 load_system_prompt。 | <code>    system_prompt = read_text(prompt_path)</code> |
| L0077 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_system_prompt。 | <code>    if not system_prompt.strip():</code> |
| L0078 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 load_system_prompt。 | <code>        raise RuntimeError(f"prompt 为空: {prompt_path}")</code> |
| L0079 | 计算并保存 &#96;prompt_mtime&#96;（promptmtime），供后续逻辑使用，当前位于函数 load_system_prompt。 | <code>    prompt_mtime = prompt_path.stat().st_mtime if prompt_path.exists() else 0.0</code> |
| L0080 | 结束当前函数并把结果返回给调用方，当前位于函数 load_system_prompt。 | <code>    return system_prompt, prompt_mtime</code> |
| L0081 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0082 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0083 | 定义findcasedirs函数 &#96;find_case_dirs&#96;，封装可复用业务逻辑。 | <code>def find_case_dirs(result_dir: Path) -&gt; List[Path]:</code> |
| L0084 | 计算并保存 &#96;dirs&#96;（dirs），供后续逻辑使用，当前位于函数 find_case_dirs。 | <code>    dirs = []</code> |
| L0085 | 遍历集合中的数据项并逐项处理，当前位于函数 find_case_dirs。 | <code>    for p in result_dir.glob("b.*"):</code> |
| L0086 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 find_case_dirs。 | <code>        if p.is_dir():</code> |
| L0087 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 find_case_dirs。 | <code>            dirs.append(p)</code> |
| L0088 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_case_dirs。 | <code>    dirs.sort(key=lambda x: int(x.name.split(".", 1)[1]) if x.name.split(".", 1)[1].isdigit() else 10**9)</code> |
| L0089 | 结束当前函数并把结果返回给调用方，当前位于函数 find_case_dirs。 | <code>    return dirs</code> |
| L0090 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0091 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0092 | 定义解析ipfromtext函数 &#96;parse_ip_from_text&#96;，封装可复用业务逻辑。 | <code>def parse_ip_from_text(text: str) -&gt; Optional[str]:</code> |
| L0093 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_ip_from_text。 | <code>    if not text:</code> |
| L0094 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_ip_from_text。 | <code>        return None</code> |
| L0095 | 计算并保存 &#96;m&#96;（m），供后续逻辑使用，当前位于函数 parse_ip_from_text。 | <code>    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)</code> |
| L0096 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_ip_from_text。 | <code>    return m.group(0) if m else None</code> |
| L0097 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0098 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0099 | 定义解析caseipsfrominput函数 &#96;parse_case_ips_from_input&#96;，封装可复用业务逻辑。 | <code>def parse_case_ips_from_input(input_file: Path, seq_id: int) -&gt; Tuple[Optional[str], Optional[str]]:</code> |
| L0100 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_case_ips_from_input。 | <code>    if not input_file.exists():</code> |
| L0101 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_case_ips_from_input。 | <code>        return None, None</code> |
| L0102 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0103 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 parse_case_ips_from_input。 | <code>    text = read_text(input_file)</code> |
| L0104 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_case_ips_from_input。 | <code>    if "### CASE_START ###" not in text:</code> |
| L0105 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_case_ips_from_input。 | <code>        return None, None</code> |
| L0106 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0107 | 计算并保存 &#96;blocks&#96;（blocks），供后续逻辑使用，当前位于函数 parse_case_ips_from_input。 | <code>    blocks = re.findall(r"### CASE_START ###(.*?)### CASE_END ###", text, flags=re.DOTALL)</code> |
| L0108 | 遍历集合中的数据项并逐项处理，当前位于函数 parse_case_ips_from_input。 | <code>    for block in blocks:</code> |
| L0109 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 parse_case_ips_from_input。 | <code>        data = {}</code> |
| L0110 | 遍历集合中的数据项并逐项处理，当前位于函数 parse_case_ips_from_input。 | <code>        for line in block.splitlines():</code> |
| L0111 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_case_ips_from_input。 | <code>            if "=" in line:</code> |
| L0112 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_case_ips_from_input。 | <code>                k, v = line.split("=", 1)</code> |
| L0113 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_case_ips_from_input。 | <code>                data[k.strip()] = v.strip()</code> |
| L0114 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 parse_case_ips_from_input。 | <code>        try:</code> |
| L0115 | 计算并保存 &#96;sid&#96;（sid），供后续逻辑使用，当前位于函数 parse_case_ips_from_input。 | <code>            sid = int(data.get("seq_id", "0"))</code> |
| L0116 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 parse_case_ips_from_input。 | <code>        except Exception:</code> |
| L0117 | 计算并保存 &#96;sid&#96;（sid），供后续逻辑使用，当前位于函数 parse_case_ips_from_input。 | <code>            sid = 0</code> |
| L0118 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_case_ips_from_input。 | <code>        if sid == seq_id:</code> |
| L0119 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_case_ips_from_input。 | <code>            return data.get("src_ip"), data.get("dst_ip")</code> |
| L0120 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0121 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_case_ips_from_input。 | <code>    return None, None</code> |
| L0122 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0123 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0124 | 定义构建userpayload函数 &#96;build_user_payload&#96;，封装可复用业务逻辑。 | <code>def build_user_payload(</code> |
| L0125 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_user_payload。 | <code>    case_obj: Dict,</code> |
| L0126 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_user_payload。 | <code>    request_text: str,</code> |
| L0127 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_user_payload。 | <code>    response_text: str,</code> |
| L0128 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_user_payload。 | <code>    src_ip: str,</code> |
| L0129 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_user_payload。 | <code>    dst_ip: str,</code> |
| L0130 | 计算并保存 &#96;rag_context&#96;（ragcontext），供后续逻辑使用，当前位于函数 build_user_payload。 | <code>    rag_context: str = "",</code> |
| L0131 | 计算并保存 &#96;detection_context&#96;（detectioncontext），供后续逻辑使用，当前位于函数 build_user_payload。 | <code>    detection_context: Optional[Dict] = None,</code> |
| L0132 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_user_payload。 | <code>) -&gt; str:</code> |
| L0133 | 计算并保存 &#96;safe_case&#96;（safecase），供后续逻辑使用，当前位于函数 build_user_payload。 | <code>    safe_case = {</code> |
| L0134 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_user_payload。 | <code>        "case_id": case_obj.get("case_id"),</code> |
| L0135 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_user_payload。 | <code>        "file_id": case_obj.get("file_id"),</code> |
| L0136 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_user_payload。 | <code>        "seq_id": case_obj.get("seq_id"),</code> |
| L0137 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_user_payload。 | <code>        "method": case_obj.get("method"),</code> |
| L0138 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_user_payload。 | <code>        "uri": case_obj.get("uri"),</code> |
| L0139 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_user_payload。 | <code>        "host": case_obj.get("host"),</code> |
| L0140 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_user_payload。 | <code>        "status_code": case_obj.get("status_code"),</code> |
| L0141 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_user_payload。 | <code>        "source_ip": src_ip,</code> |
| L0142 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_user_payload。 | <code>        "destination_ip": dst_ip,</code> |
| L0143 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_user_payload。 | <code>    }</code> |
| L0144 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0145 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 build_user_payload。 | <code>    body = {</code> |
| L0146 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_user_payload。 | <code>        "meta": safe_case,</code> |
| L0147 | 源码原注释：The deterministic layers already retain the full packet. Keep the | <code>        # The deterministic layers already retain the full packet. Keep the</code> |
| L0148 | 源码原注释：semantic review payload compact so CPU-only Ollama can answer fast. | <code>        # semantic review payload compact so CPU-only Ollama can answer fast.</code> |
| L0149 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_user_payload。 | <code>        "request_block": request_text[:3000],</code> |
| L0150 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_user_payload。 | <code>        "response_block": response_text[:1200],</code> |
| L0151 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_user_payload。 | <code>        "detection_context": detection_context or {},</code> |
| L0152 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_user_payload。 | <code>        "retrieved_knowledge": rag_context[:6000] if rag_context else "",</code> |
| L0153 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_user_payload。 | <code>    }</code> |
| L0154 | 结束当前函数并把结果返回给调用方，当前位于函数 build_user_payload。 | <code>    return json.dumps(body, ensure_ascii=False)</code> |
| L0155 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0156 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0157 | 定义ensurerag数据库函数 &#96;ensure_rag_db&#96;，封装可复用业务逻辑。 | <code>def ensure_rag_db(db_path: Path, seed_path: Path, auto_build: bool = True) -&gt; None:</code> |
| L0158 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_rag_db。 | <code>    if db_path.exists():</code> |
| L0159 | 结束当前函数并把结果返回给调用方，当前位于函数 ensure_rag_db。 | <code>        return</code> |
| L0160 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_rag_db。 | <code>    if not auto_build:</code> |
| L0161 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 ensure_rag_db。 | <code>        log(f"RAG db not found and auto build disabled: {db_path}")</code> |
| L0162 | 结束当前函数并把结果返回给调用方，当前位于函数 ensure_rag_db。 | <code>        return</code> |
| L0163 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_rag_db。 | <code>    if not seed_path.exists():</code> |
| L0164 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 ensure_rag_db。 | <code>        log(f"RAG seed file not found, skip auto build: {seed_path}")</code> |
| L0165 | 结束当前函数并把结果返回给调用方，当前位于函数 ensure_rag_db。 | <code>        return</code> |
| L0166 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 ensure_rag_db。 | <code>    try:</code> |
| L0167 | 导入后续逻辑所需的模块、类或函数：&#96;from build_rag_db import build_rag_db, read_seed&#96;。 | <code>        from build_rag_db import build_rag_db, read_seed</code> |
| L0168 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0169 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 ensure_rag_db。 | <code>        rows = read_seed(seed_path)</code> |
| L0170 | 计算并保存 &#96;count&#96;（count），供后续逻辑使用，当前位于函数 ensure_rag_db。 | <code>        count = build_rag_db(db_path, rows)</code> |
| L0171 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 ensure_rag_db。 | <code>        log(f"RAG db auto built: {db_path} rows={count}")</code> |
| L0172 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 ensure_rag_db。 | <code>    except Exception as exc:  # noqa: BLE001</code> |
| L0173 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 ensure_rag_db。 | <code>        log(f"RAG db auto build failed: {exc}")</code> |
| L0174 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0175 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0176 | 定义构建ragmatchquery函数 &#96;build_rag_match_query&#96;，封装可复用业务逻辑。 | <code>def build_rag_match_query(text: str, max_terms: int = 12) -&gt; str:</code> |
| L0177 | 计算并保存 &#96;terms&#96;（terms），供后续逻辑使用，当前位于函数 build_rag_match_query。 | <code>    terms = re.findall(r"[a-zA-Z0-9_./:-]{2,}", (text or "").lower())</code> |
| L0178 | 计算并保存 &#96;uniq&#96;（uniq），供后续逻辑使用，当前位于函数 build_rag_match_query。 | <code>    uniq: List[str] = []</code> |
| L0179 | 计算并保存 &#96;seen&#96;（seen），供后续逻辑使用，当前位于函数 build_rag_match_query。 | <code>    seen = set()</code> |
| L0180 | 遍历集合中的数据项并逐项处理，当前位于函数 build_rag_match_query。 | <code>    for t in terms:</code> |
| L0181 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_rag_match_query。 | <code>        if t in seen:</code> |
| L0182 | 控制当前循环或占位分支的执行流程，当前位于函数 build_rag_match_query。 | <code>            continue</code> |
| L0183 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_rag_match_query。 | <code>        seen.add(t)</code> |
| L0184 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_rag_match_query。 | <code>        uniq.append(t)</code> |
| L0185 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_rag_match_query。 | <code>        if len(uniq) &gt;= max_terms:</code> |
| L0186 | 控制当前循环或占位分支的执行流程，当前位于函数 build_rag_match_query。 | <code>            break</code> |
| L0187 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_rag_match_query。 | <code>    if not uniq:</code> |
| L0188 | 结束当前函数并把结果返回给调用方，当前位于函数 build_rag_match_query。 | <code>        return ""</code> |
| L0189 | 计算并保存 &#96;escaped&#96;（escaped），供后续逻辑使用，当前位于函数 build_rag_match_query。 | <code>    escaped = [f'"{t.replace("\"", "")}"' for t in uniq if t.strip()]</code> |
| L0190 | 结束当前函数并把结果返回给调用方，当前位于函数 build_rag_match_query。 | <code>    return " OR ".join(escaped)</code> |
| L0191 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0192 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0193 | 定义召回ragdocs函数 &#96;retrieve_rag_docs&#96;，封装可复用业务逻辑。 | <code>def retrieve_rag_docs(db_path: Path, query_text: str, top_k: int = 3) -&gt; List[Dict]:</code> |
| L0194 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 retrieve_rag_docs。 | <code>    if not db_path.exists():</code> |
| L0195 | 结束当前函数并把结果返回给调用方，当前位于函数 retrieve_rag_docs。 | <code>        return []</code> |
| L0196 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0197 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 retrieve_rag_docs。 | <code>    rows: List[Dict] = []</code> |
| L0198 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 retrieve_rag_docs。 | <code>    with sqlite3.connect(str(db_path)) as conn:</code> |
| L0199 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_rag_docs。 | <code>        conn.row_factory = sqlite3.Row</code> |
| L0200 | 计算并保存 &#96;cur&#96;（cur），供后续逻辑使用，当前位于函数 retrieve_rag_docs。 | <code>        cur = conn.cursor()</code> |
| L0201 | 计算并保存 &#96;match_query&#96;（matchquery），供后续逻辑使用，当前位于函数 retrieve_rag_docs。 | <code>        match_query = build_rag_match_query(query_text, max_terms=14)</code> |
| L0202 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0203 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 retrieve_rag_docs。 | <code>        if match_query:</code> |
| L0204 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 retrieve_rag_docs。 | <code>            try:</code> |
| L0205 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 retrieve_rag_docs。 | <code>                cur.execute(</code> |
| L0206 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 retrieve_rag_docs。 | <code>                    """</code> |
| L0207 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 retrieve_rag_docs。 | <code>                    SELECT</code> |
| L0208 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 retrieve_rag_docs。 | <code>                      doc_id, title, attack_type, evidence, mitigation, severity, source,</code> |
| L0209 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 retrieve_rag_docs。 | <code>                      bm25(rag_docs) AS score</code> |
| L0210 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 retrieve_rag_docs。 | <code>                    FROM rag_docs</code> |
| L0211 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 retrieve_rag_docs。 | <code>                    WHERE rag_docs MATCH ?</code> |
| L0212 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 retrieve_rag_docs。 | <code>                    ORDER BY score ASC</code> |
| L0213 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 retrieve_rag_docs。 | <code>                    LIMIT ?</code> |
| L0214 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 retrieve_rag_docs。 | <code>                    """,</code> |
| L0215 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_rag_docs。 | <code>                    (match_query, max(1, top_k)),</code> |
| L0216 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 retrieve_rag_docs。 | <code>                )</code> |
| L0217 | 遍历集合中的数据项并逐项处理，当前位于函数 retrieve_rag_docs。 | <code>                for row in cur.fetchall():</code> |
| L0218 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 retrieve_rag_docs。 | <code>                    rows.append(dict(row))</code> |
| L0219 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 retrieve_rag_docs。 | <code>            except sqlite3.OperationalError:</code> |
| L0220 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 retrieve_rag_docs。 | <code>                rows = []</code> |
| L0221 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0222 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 retrieve_rag_docs。 | <code>        if rows:</code> |
| L0223 | 结束当前函数并把结果返回给调用方，当前位于函数 retrieve_rag_docs。 | <code>            return rows</code> |
| L0224 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0225 | 计算并保存 &#96;fallback_tokens&#96;（fallbacktokens），供后续逻辑使用，当前位于函数 retrieve_rag_docs。 | <code>        fallback_tokens = re.findall(r"[a-zA-Z0-9_./:-]{2,}", (query_text or "").lower())</code> |
| L0226 | 计算并保存 &#96;keyword&#96;（keyword），供后续逻辑使用，当前位于函数 retrieve_rag_docs。 | <code>        keyword = fallback_tokens[0] if fallback_tokens else "login"</code> |
| L0227 | 计算并保存 &#96;pattern&#96;（pattern），供后续逻辑使用，当前位于函数 retrieve_rag_docs。 | <code>        pattern = f"%{keyword}%"</code> |
| L0228 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 retrieve_rag_docs。 | <code>        cur.execute(</code> |
| L0229 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 retrieve_rag_docs。 | <code>            """</code> |
| L0230 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 retrieve_rag_docs。 | <code>            SELECT</code> |
| L0231 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 retrieve_rag_docs。 | <code>              doc_id, title, attack_type, evidence, mitigation, severity, source,</code> |
| L0232 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 retrieve_rag_docs。 | <code>              0.0 AS score</code> |
| L0233 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 retrieve_rag_docs。 | <code>            FROM rag_docs</code> |
| L0234 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 retrieve_rag_docs。 | <code>            WHERE tags LIKE ? OR content LIKE ? OR title LIKE ?</code> |
| L0235 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 retrieve_rag_docs。 | <code>            LIMIT ?</code> |
| L0236 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 retrieve_rag_docs。 | <code>            """,</code> |
| L0237 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_rag_docs。 | <code>            (pattern, pattern, pattern, max(1, top_k)),</code> |
| L0238 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 retrieve_rag_docs。 | <code>        )</code> |
| L0239 | 结束当前函数并把结果返回给调用方，当前位于函数 retrieve_rag_docs。 | <code>        return [dict(r) for r in cur.fetchall()]</code> |
| L0240 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0241 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0242 | 定义召回advancedrag函数 &#96;retrieve_advanced_rag&#96;，封装可复用业务逻辑。 | <code>def retrieve_advanced_rag(args, query_text: str) -&gt; List[Dict]:</code> |
| L0243 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 retrieve_advanced_rag。 | <code>    """Run the cloud-embedding hybrid retriever and map results to legacy fields."""</code> |
| L0244 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 retrieve_advanced_rag。 | <code>    try:</code> |
| L0245 | 导入后续逻辑所需的模块、类或函数：&#96;from rag_service import hybrid_search, list_kbs, load_api_config, mysql_connect&#96;。 | <code>        from rag_service import hybrid_search, list_kbs, load_api_config, mysql_connect</code> |
| L0246 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0247 | 计算并保存 &#96;mysql_conf&#96;（mysqlconf），供后续逻辑使用，当前位于函数 retrieve_advanced_rag。 | <code>        mysql_conf = {</code> |
| L0248 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_advanced_rag。 | <code>            "host": args.rag_mysql_host,</code> |
| L0249 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_advanced_rag。 | <code>            "port": args.rag_mysql_port,</code> |
| L0250 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_advanced_rag。 | <code>            "user": args.rag_mysql_user,</code> |
| L0251 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_advanced_rag。 | <code>            "password": args.rag_mysql_password,</code> |
| L0252 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_advanced_rag。 | <code>            "database": args.rag_mysql_database,</code> |
| L0253 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 retrieve_advanced_rag。 | <code>        }</code> |
| L0254 | 计算并保存 &#96;api_config&#96;（接口配置），供后续逻辑使用，当前位于函数 retrieve_advanced_rag。 | <code>        api_config = load_api_config(args.rag_api_config)</code> |
| L0255 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 retrieve_advanced_rag。 | <code>        if not api_config.get("api_key"):</code> |
| L0256 | 结束当前函数并把结果返回给调用方，当前位于函数 retrieve_advanced_rag。 | <code>            return []</code> |
| L0257 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 retrieve_advanced_rag。 | <code>        with mysql_connect(mysql_conf, autocommit=False) as conn:</code> |
| L0258 | 计算并保存 &#96;kbs&#96;（kbs），供后续逻辑使用，当前位于函数 retrieve_advanced_rag。 | <code>            kbs = list_kbs(conn, include_disabled=False)</code> |
| L0259 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 retrieve_advanced_rag。 | <code>            if not kbs:</code> |
| L0260 | 结束当前函数并把结果返回给调用方，当前位于函数 retrieve_advanced_rag。 | <code>                return []</code> |
| L0261 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 retrieve_advanced_rag。 | <code>            result = hybrid_search(</code> |
| L0262 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_advanced_rag。 | <code>                conn,</code> |
| L0263 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_advanced_rag。 | <code>                args.rag_data_dir,</code> |
| L0264 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_advanced_rag。 | <code>                api_config,</code> |
| L0265 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_advanced_rag。 | <code>                int(kbs[0]["id"]),</code> |
| L0266 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_advanced_rag。 | <code>                query_text,</code> |
| L0267 | 计算并保存 &#96;username&#96;（username），供后续逻辑使用，当前位于函数 retrieve_advanced_rag。 | <code>                username="llm-daemon",</code> |
| L0268 | 计算并保存 &#96;save_test&#96;（保存test），供后续逻辑使用，当前位于函数 retrieve_advanced_rag。 | <code>                save_test=False,</code> |
| L0269 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 retrieve_advanced_rag。 | <code>            )</code> |
| L0270 | 结束当前函数并把结果返回给调用方，当前位于函数 retrieve_advanced_rag。 | <code>        return [</code> |
| L0271 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_advanced_rag。 | <code>            {</code> |
| L0272 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_advanced_rag。 | <code>                "doc_id": f"DOC-{item.get('document_id')}-CHUNK-{item.get('chunk_id')}",</code> |
| L0273 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_advanced_rag。 | <code>                "title": item.get("title_path") or item.get("document_name") or "知识片段",</code> |
| L0274 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_advanced_rag。 | <code>                "attack_type": "",</code> |
| L0275 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_advanced_rag。 | <code>                "evidence": item.get("content") or "",</code> |
| L0276 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_advanced_rag。 | <code>                "mitigation": "",</code> |
| L0277 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_advanced_rag。 | <code>                "severity": "",</code> |
| L0278 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_advanced_rag。 | <code>                "source": item.get("document_name") or "advanced-rag",</code> |
| L0279 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 retrieve_advanced_rag。 | <code>                "score": item.get("score") or 0,</code> |
| L0280 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 retrieve_advanced_rag。 | <code>            }</code> |
| L0281 | 遍历集合中的数据项并逐项处理，当前位于函数 retrieve_advanced_rag。 | <code>            for item in (result.get("items") or [])[: max(1, int(args.rag_top_k))]</code> |
| L0282 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 retrieve_advanced_rag。 | <code>        ]</code> |
| L0283 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 retrieve_advanced_rag。 | <code>    except Exception as exc:</code> |
| L0284 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 retrieve_advanced_rag。 | <code>        log(f"advanced RAG fallback to legacy: {exc}")</code> |
| L0285 | 结束当前函数并把结果返回给调用方，当前位于函数 retrieve_advanced_rag。 | <code>        return []</code> |
| L0286 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0287 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0288 | 定义格式化ragcontext函数 &#96;format_rag_context&#96;，封装可复用业务逻辑。 | <code>def format_rag_context(rows: List[Dict], max_chars: int = 3200) -&gt; str:</code> |
| L0289 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 format_rag_context。 | <code>    if not rows:</code> |
| L0290 | 结束当前函数并把结果返回给调用方，当前位于函数 format_rag_context。 | <code>        return ""</code> |
| L0291 | 计算并保存 &#96;lines&#96;（lines），供后续逻辑使用，当前位于函数 format_rag_context。 | <code>    lines: List[str] = []</code> |
| L0292 | 遍历集合中的数据项并逐项处理，当前位于函数 format_rag_context。 | <code>    for idx, row in enumerate(rows, start=1):</code> |
| L0293 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 format_rag_context。 | <code>        lines.append(</code> |
| L0294 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 format_rag_context。 | <code>            (</code> |
| L0295 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 format_rag_context。 | <code>                f"[RAG#{idx}] title={row.get('title','')} attack_type={row.get('attack_type','')} "</code> |
| L0296 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 format_rag_context。 | <code>                f"severity={row.get('severity','')} evidence={row.get('evidence','')} "</code> |
| L0297 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 format_rag_context。 | <code>                f"mitigation={row.get('mitigation','')}"</code> |
| L0298 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 format_rag_context。 | <code>            )</code> |
| L0299 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 format_rag_context。 | <code>        )</code> |
| L0300 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 format_rag_context。 | <code>    text = "\n".join(lines)</code> |
| L0301 | 结束当前函数并把结果返回给调用方，当前位于函数 format_rag_context。 | <code>    return text[:max_chars]</code> |
| L0302 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0303 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0304 | 定义构建ragreferences函数 &#96;build_rag_references&#96;，封装可复用业务逻辑。 | <code>def build_rag_references(rows: List[Dict]) -&gt; List[str]:</code> |
| L0305 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_rag_references。 | <code>    """Build citations only from chunks actually retrieved for this request."""</code> |
| L0306 | 计算并保存 &#96;references&#96;（references），供后续逻辑使用，当前位于函数 build_rag_references。 | <code>    references: List[str] = []</code> |
| L0307 | 遍历集合中的数据项并逐项处理，当前位于函数 build_rag_references。 | <code>    for idx, row in enumerate(rows[:4], start=1):</code> |
| L0308 | 计算并保存 &#96;title&#96;（title），供后续逻辑使用，当前位于函数 build_rag_references。 | <code>        title = str(row.get("title") or row.get("source") or "知识片段").strip()</code> |
| L0309 | 计算并保存 &#96;doc_id&#96;（docid），供后续逻辑使用，当前位于函数 build_rag_references。 | <code>        doc_id = str(row.get("doc_id") or "").strip()</code> |
| L0310 | 计算并保存 &#96;label&#96;（label），供后续逻辑使用，当前位于函数 build_rag_references。 | <code>        label = f"RAG#{idx} {title}"</code> |
| L0311 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_rag_references。 | <code>        if doc_id:</code> |
| L0312 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_rag_references。 | <code>            label += f"（{doc_id}）"</code> |
| L0313 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_rag_references。 | <code>        if label not in references:</code> |
| L0314 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_rag_references。 | <code>            references.append(label)</code> |
| L0315 | 结束当前函数并把结果返回给调用方，当前位于函数 build_rag_references。 | <code>    return references</code> |
| L0316 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0317 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0318 | 定义callollamachat函数 &#96;call_ollama_chat&#96;，封装可复用业务逻辑。 | <code>def call_ollama_chat(</code> |
| L0319 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>    base_url: str,</code> |
| L0320 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>    model: str,</code> |
| L0321 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>    system_prompt: str,</code> |
| L0322 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>    user_payload: str,</code> |
| L0323 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>    schema_obj: Dict,</code> |
| L0324 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>    timeout_sec: int,</code> |
| L0325 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>    num_ctx: int,</code> |
| L0326 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>    num_gpu: int,</code> |
| L0327 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>    temperature: float,</code> |
| L0328 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_ollama_chat。 | <code>) -&gt; Tuple[Dict, str]:</code> |
| L0329 | 计算并保存 &#96;url&#96;（url），供后续逻辑使用，当前位于函数 call_ollama_chat。 | <code>    url = base_url.rstrip("/") + "/api/chat"</code> |
| L0330 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0331 | 计算并保存 &#96;req_obj&#96;（reqobj），供后续逻辑使用，当前位于函数 call_ollama_chat。 | <code>    req_obj = {</code> |
| L0332 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>        "model": model,</code> |
| L0333 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>        "stream": False,</code> |
| L0334 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>        "keep_alive": os.environ.get("OLLAMA_KEEP_ALIVE", "5m"),</code> |
| L0335 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>        "format": schema_obj,</code> |
| L0336 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>        "messages": [</code> |
| L0337 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>            {"role": "system", "content": system_prompt},</code> |
| L0338 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>            {"role": "user", "content": user_payload},</code> |
| L0339 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_ollama_chat。 | <code>        ],</code> |
| L0340 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>        "options": {</code> |
| L0341 | 源码原注释：Prompt, packet facts, detector evidence and RAG excerpts share one | <code>            # Prompt, packet facts, detector evidence and RAG excerpts share one</code> |
| L0342 | 源码原注释：window. 2048 tokens truncated otherwise valid JSON on the 1.5B model. | <code>            # window. 2048 tokens truncated otherwise valid JSON on the 1.5B model.</code> |
| L0343 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>            "num_ctx": max(6144, num_ctx),</code> |
| L0344 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>            "num_gpu": num_gpu,</code> |
| L0345 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>            "temperature": temperature,</code> |
| L0346 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama_chat。 | <code>            "num_predict": 768,</code> |
| L0347 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_ollama_chat。 | <code>        },</code> |
| L0348 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_ollama_chat。 | <code>    }</code> |
| L0349 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0350 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 call_ollama_chat。 | <code>    data = json.dumps(req_obj, ensure_ascii=False).encode("utf-8")</code> |
| L0351 | 计算并保存 &#96;request&#96;（request），供后续逻辑使用，当前位于函数 call_ollama_chat。 | <code>    request = urllib.request.Request(</code> |
| L0352 | 计算并保存 &#96;url&#96;（url），供后续逻辑使用，当前位于函数 call_ollama_chat。 | <code>        url=url,</code> |
| L0353 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 call_ollama_chat。 | <code>        data=data,</code> |
| L0354 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 call_ollama_chat。 | <code>        method="POST",</code> |
| L0355 | 计算并保存 &#96;headers&#96;（headers），供后续逻辑使用，当前位于函数 call_ollama_chat。 | <code>        headers={"Content-Type": "application/json"},</code> |
| L0356 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_ollama_chat。 | <code>    )</code> |
| L0357 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0358 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 call_ollama_chat。 | <code>    try:</code> |
| L0359 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 call_ollama_chat。 | <code>        with urllib.request.urlopen(request, timeout=timeout_sec) as resp:</code> |
| L0360 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 call_ollama_chat。 | <code>            raw = resp.read().decode("utf-8", errors="replace")</code> |
| L0361 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 call_ollama_chat。 | <code>    except urllib.error.HTTPError as exc:</code> |
| L0362 | 计算并保存 &#96;detail&#96;（detail），供后续逻辑使用，当前位于函数 call_ollama_chat。 | <code>        detail = exc.read().decode("utf-8", errors="replace") if exc.fp else ""</code> |
| L0363 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 call_ollama_chat。 | <code>        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc</code> |
| L0364 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 call_ollama_chat。 | <code>    except Exception as exc:</code> |
| L0365 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 call_ollama_chat。 | <code>        raise RuntimeError(str(exc)) from exc</code> |
| L0366 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0367 | 计算并保存 &#96;outer&#96;（outer），供后续逻辑使用，当前位于函数 call_ollama_chat。 | <code>    outer = json.loads(raw)</code> |
| L0368 | 计算并保存 &#96;content&#96;（content），供后续逻辑使用，当前位于函数 call_ollama_chat。 | <code>    content = outer.get("message", {}).get("content", "")</code> |
| L0369 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0370 | 计算并保存 &#96;parsed&#96;（parsed），供后续逻辑使用，当前位于函数 call_ollama_chat。 | <code>    parsed = parse_model_content(content)</code> |
| L0371 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0372 | 结束当前函数并把结果返回给调用方，当前位于函数 call_ollama_chat。 | <code>    return parsed, content</code> |
| L0373 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0374 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0375 | 定义加载review接口配置函数 &#96;load_review_api_config&#96;，封装可复用业务逻辑。 | <code>def load_review_api_config(path: Path) -&gt; Dict:</code> |
| L0376 | 调用外部 HTTP/大模型 API，并等待远端返回结果，当前位于函数 load_review_api_config。 | <code>    """Load the private OpenAI-compatible final-review configuration."""</code> |
| L0377 | 计算并保存 &#96;config&#96;（配置），供后续逻辑使用，当前位于函数 load_review_api_config。 | <code>    config = read_json(path, default={})</code> |
| L0378 | 结束当前函数并把结果返回给调用方，当前位于函数 load_review_api_config。 | <code>    return config if isinstance(config, dict) else {}</code> |
| L0379 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0380 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0381 | 定义callopenaicompatiblechat函数 &#96;call_openai_compatible_chat&#96;，封装可复用业务逻辑。 | <code>def call_openai_compatible_chat(</code> |
| L0382 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>    *,</code> |
| L0383 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>    config: Dict,</code> |
| L0384 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>    system_prompt: str,</code> |
| L0385 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>    user_payload: str,</code> |
| L0386 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>    schema_obj: Dict,</code> |
| L0387 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>    temperature: float,</code> |
| L0388 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>    timeout_sec: int,</code> |
| L0389 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_openai_compatible_chat。 | <code>) -&gt; Tuple[Dict, str]:</code> |
| L0390 | 计算并保存 &#96;api_key&#96;（接口key），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>    api_key = str(config.get("api_key") or os.environ.get("LLM_REVIEW_API_KEY") or "").strip()</code> |
| L0391 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 call_openai_compatible_chat。 | <code>    if not api_key:</code> |
| L0392 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 call_openai_compatible_chat。 | <code>        raise RuntimeError("external_review_api_key_missing")</code> |
| L0393 | 计算并保存 &#96;base_url&#96;（baseurl），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>    base_url = str(config.get("base_url") or "https://api.deepseek.com").strip().rstrip("/")</code> |
| L0394 | 计算并保存 &#96;model&#96;（模型），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>    model = str(config.get("model") or "deepseek-v4-flash").strip()</code> |
| L0395 | 计算并保存 &#96;schema_text&#96;（schematext），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>    schema_text = json.dumps(schema_obj, ensure_ascii=False, separators=(",", ":"))</code> |
| L0396 | 计算并保存 &#96;request_obj&#96;（requestobj），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>    request_obj = {</code> |
| L0397 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>        "model": model,</code> |
| L0398 | 源码原注释：DeepSeek V4 defaults to thinking mode. Event review needs the final | <code>        # DeepSeek V4 defaults to thinking mode. Event review needs the final</code> |
| L0399 | 源码原注释：structured verdict quickly instead of spending its budget on CoT. | <code>        # structured verdict quickly instead of spending its budget on CoT.</code> |
| L0400 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>        "thinking": {"type": "disabled"},</code> |
| L0401 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>        "messages": [</code> |
| L0402 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>            {</code> |
| L0403 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>                "role": "system",</code> |
| L0404 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>                "content": (</code> |
| L0405 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>                    system_prompt</code> |
| L0406 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>                    + "\n\n必须只返回一个合法 JSON 对象，不得输出 Markdown。"</code> |
| L0407 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>                    + "返回字段必须符合以下 JSON Schema："</code> |
| L0408 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>                    + schema_text</code> |
| L0409 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_openai_compatible_chat。 | <code>                ),</code> |
| L0410 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_openai_compatible_chat。 | <code>            },</code> |
| L0411 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>            {"role": "user", "content": user_payload},</code> |
| L0412 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_openai_compatible_chat。 | <code>        ],</code> |
| L0413 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>        "temperature": float(temperature),</code> |
| L0414 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>        "max_tokens": int(config.get("max_tokens") or 1200),</code> |
| L0415 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>        "response_format": {"type": "json_object"},</code> |
| L0416 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>        "stream": False,</code> |
| L0417 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_openai_compatible_chat。 | <code>    }</code> |
| L0418 | 计算并保存 &#96;retries&#96;（retries），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>    retries = max(1, min(3, int(config.get("max_retries") or 2)))</code> |
| L0419 | 计算并保存 &#96;effective_timeout&#96;（effectivetimeout），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>    effective_timeout = max(10, int(config.get("timeout_seconds") or timeout_sec or 45))</code> |
| L0420 | 计算并保存 &#96;last_error&#96;（lasterror），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>    last_error: Optional[Exception] = None</code> |
| L0421 | 遍历集合中的数据项并逐项处理，当前位于函数 call_openai_compatible_chat。 | <code>    for attempt in range(retries):</code> |
| L0422 | 计算并保存 &#96;request&#96;（request），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>        request = urllib.request.Request(</code> |
| L0423 | 调用外部 HTTP/大模型 API，并等待远端返回结果，当前位于函数 call_openai_compatible_chat。 | <code>            url=base_url + "/chat/completions",</code> |
| L0424 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>            data=json.dumps(request_obj, ensure_ascii=False).encode("utf-8"),</code> |
| L0425 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>            method="POST",</code> |
| L0426 | 计算并保存 &#96;headers&#96;（headers），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>            headers={</code> |
| L0427 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>                "Authorization": f"Bearer {api_key}",</code> |
| L0428 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>                "Content-Type": "application/json",</code> |
| L0429 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>                "Accept": "application/json",</code> |
| L0430 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_openai_compatible_chat。 | <code>            },</code> |
| L0431 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_openai_compatible_chat。 | <code>        )</code> |
| L0432 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 call_openai_compatible_chat。 | <code>        try:</code> |
| L0433 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 call_openai_compatible_chat。 | <code>            with urllib.request.urlopen(request, timeout=effective_timeout) as response:</code> |
| L0434 | 计算并保存 &#96;outer&#96;（outer），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>                outer = json.loads(response.read().decode("utf-8", errors="replace"))</code> |
| L0435 | 计算并保存 &#96;choices&#96;（choices），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>            choices = outer.get("choices") if isinstance(outer, dict) else None</code> |
| L0436 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 call_openai_compatible_chat。 | <code>            if not isinstance(choices, list) or not choices:</code> |
| L0437 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 call_openai_compatible_chat。 | <code>                raise RuntimeError("external_review_empty_choices")</code> |
| L0438 | 计算并保存 &#96;choice&#96;（choice），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>            choice = choices[0] if isinstance(choices[0], dict) else {}</code> |
| L0439 | 计算并保存 &#96;message&#96;（message），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>            message = choice.get("message") if isinstance(choice.get("message"), dict) else {}</code> |
| L0440 | 计算并保存 &#96;content&#96;（content），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>            content = str(message.get("content") or "")</code> |
| L0441 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 call_openai_compatible_chat。 | <code>            if not content.strip():</code> |
| L0442 | 计算并保存 &#96;finish_reason&#96;（finishreason），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>                finish_reason = str(choice.get("finish_reason") or "unknown")[:40]</code> |
| L0443 | 计算并保存 &#96;reasoning_length&#96;（reasoninglength），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>                reasoning_length = len(str(message.get("reasoning_content") or ""))</code> |
| L0444 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 call_openai_compatible_chat。 | <code>                raise RuntimeError(</code> |
| L0445 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>                    "external_review_empty_content"</code> |
| L0446 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>                    f"(finish_reason={finish_reason},reasoning_chars={reasoning_length})"</code> |
| L0447 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_openai_compatible_chat。 | <code>                )</code> |
| L0448 | 结束当前函数并把结果返回给调用方，当前位于函数 call_openai_compatible_chat。 | <code>            return parse_model_content(content), content</code> |
| L0449 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 call_openai_compatible_chat。 | <code>        except urllib.error.HTTPError as exc:</code> |
| L0450 | 计算并保存 &#96;detail&#96;（detail），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>            detail = exc.read().decode("utf-8", errors="replace") if exc.fp else ""</code> |
| L0451 | 计算并保存 &#96;last_error&#96;（lasterror），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>            last_error = RuntimeError(f"HTTP {exc.code}: {detail[:800]}")</code> |
| L0452 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 call_openai_compatible_chat。 | <code>            if exc.code not in {408, 409, 429, 500, 502, 503, 504}:</code> |
| L0453 | 控制当前循环或占位分支的执行流程，当前位于函数 call_openai_compatible_chat。 | <code>                break</code> |
| L0454 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 call_openai_compatible_chat。 | <code>        except Exception as exc:  # noqa: BLE001</code> |
| L0455 | 计算并保存 &#96;last_error&#96;（lasterror），供后续逻辑使用，当前位于函数 call_openai_compatible_chat。 | <code>            last_error = exc</code> |
| L0456 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 call_openai_compatible_chat。 | <code>        if attempt &lt; retries - 1:</code> |
| L0457 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_openai_compatible_chat。 | <code>            time.sleep(0.75 * (2**attempt))</code> |
| L0458 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 call_openai_compatible_chat。 | <code>    raise RuntimeError(str(last_error or "external_review_failed"))</code> |
| L0459 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0460 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0461 | 定义解析模型content函数 &#96;parse_model_content&#96;，封装可复用业务逻辑。 | <code>def parse_model_content(content: str) -&gt; Dict:</code> |
| L0462 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>    """Parse structured output and safely recover a truncated core verdict."""</code> |
| L0463 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 parse_model_content。 | <code>    try:</code> |
| L0464 | 计算并保存 &#96;parsed&#96;（parsed），供后续逻辑使用，当前位于函数 parse_model_content。 | <code>        parsed = json.loads(content)</code> |
| L0465 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_model_content。 | <code>        return parsed if isinstance(parsed, dict) else {}</code> |
| L0466 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 parse_model_content。 | <code>    except Exception:</code> |
| L0467 | 控制当前循环或占位分支的执行流程，当前位于函数 parse_model_content。 | <code>        pass</code> |
| L0468 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0469 | 计算并保存 &#96;verdict_match&#96;（verdictmatch），供后续逻辑使用，当前位于函数 parse_model_content。 | <code>    verdict_match = re.search(r'"verdict"\s*:\s*"(attack&#124;benign&#124;unknown)"', content, re.I)</code> |
| L0470 | 计算并保存 &#96;severity_match&#96;（severitymatch），供后续逻辑使用，当前位于函数 parse_model_content。 | <code>    severity_match = re.search(r'"severity"\s*:\s*"(low&#124;medium&#124;high&#124;critical&#124;unknown)"', content, re.I)</code> |
| L0471 | 计算并保存 &#96;confidence_match&#96;（confidencematch），供后续逻辑使用，当前位于函数 parse_model_content。 | <code>    confidence_match = re.search(r'"confidence"\s*:\s*([0-9]+(?:\.[0-9]+)?)', content, re.I)</code> |
| L0472 | 计算并保存 &#96;verdict&#96;（verdict），供后续逻辑使用，当前位于函数 parse_model_content。 | <code>    verdict = verdict_match.group(1).lower() if verdict_match else "unknown"</code> |
| L0473 | 计算并保存 &#96;severity&#96;（severity），供后续逻辑使用，当前位于函数 parse_model_content。 | <code>    severity = severity_match.group(1).lower() if severity_match else "unknown"</code> |
| L0474 | 计算并保存 &#96;confidence&#96;（confidence），供后续逻辑使用，当前位于函数 parse_model_content。 | <code>    confidence = float(confidence_match.group(1)) if confidence_match else 0.0</code> |
| L0475 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_model_content。 | <code>    if verdict in {"attack", "benign"} and severity_match and confidence_match:</code> |
| L0476 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>        is_attack = verdict == "attack"</code> |
| L0477 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_model_content。 | <code>        return {</code> |
| L0478 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>            "_partial_recovered": True,</code> |
| L0479 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>            "verdict": verdict,</code> |
| L0480 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>            "source_ip": "unknown",</code> |
| L0481 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>            "destination_ip": "unknown",</code> |
| L0482 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>            "attack_interface": "unknown",</code> |
| L0483 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>            "attack_method": "unknown",</code> |
| L0484 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>            "attack_path": "unknown",</code> |
| L0485 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>            "attack_time": now_iso(),</code> |
| L0486 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>            "severity": severity,</code> |
| L0487 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>            "confidence": confidence,</code> |
| L0488 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>            "evidence": [],</code> |
| L0489 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>            "analysis_reasoning": "大模型已形成核心结论，系统结合抓包事实和多源检测证据完成一致性校验。",</code> |
| L0490 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>            "potential_impact": ["若该载荷成功利用，可能影响目标接口的数据、权限或服务完整性。"] if is_attack else ["当前请求未显示明确安全影响。"],</code> |
| L0491 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>            "immediate_actions": ["保留原始请求并核查同时间窗口日志。"] if is_attack else ["按正常业务流量留存审计记录。"],</code> |
| L0492 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>            "hardening_actions": ["持续更新规则、依赖组件和输入校验策略。"],</code> |
| L0493 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>            "false_positive_notes": "核心结论已恢复，最终字段仍须服从抓包事实与上游证据校验。",</code> |
| L0494 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>            "knowledge_references": [],</code> |
| L0495 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>            "summary": (</code> |
| L0496 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>                "大模型结合当前载荷与检测证据判定该请求为攻击尝试；尚无成功利用回显，建议立即核查来源与目标接口。"</code> |
| L0497 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_model_content。 | <code>                if is_attack</code> |
| L0498 | 处理前述条件均未命中的情况，当前位于函数 parse_model_content。 | <code>                else "大模型结合当前请求和检测证据未发现明确攻击语义，按正常流量留存。"</code> |
| L0499 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 parse_model_content。 | <code>            ),</code> |
| L0500 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 parse_model_content。 | <code>        }</code> |
| L0501 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0502 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_model_content。 | <code>    return {</code> |
| L0503 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>        "_partial_recovered": False,</code> |
| L0504 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>        "verdict": "unknown",</code> |
| L0505 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>        "source_ip": "unknown",</code> |
| L0506 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>        "destination_ip": "unknown",</code> |
| L0507 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>        "attack_interface": "unknown",</code> |
| L0508 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>        "attack_method": "unknown",</code> |
| L0509 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>        "attack_path": "unknown",</code> |
| L0510 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>        "attack_time": now_iso(),</code> |
| L0511 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>        "severity": "unknown",</code> |
| L0512 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>        "confidence": 0.0,</code> |
| L0513 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>        "evidence": [],</code> |
| L0514 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>        "analysis_reasoning": content[:500],</code> |
| L0515 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>        "potential_impact": ["模型未返回可恢复的结构化结论，暂无法确认具体影响"],</code> |
| L0516 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>        "immediate_actions": ["保留原始请求并转人工复核"],</code> |
| L0517 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>        "hardening_actions": ["核验接口输入校验与安全日志配置"],</code> |
| L0518 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>        "false_positive_notes": "模型输出格式异常且核心结论不完整，不能据此确认攻击。",</code> |
| L0519 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>        "knowledge_references": [],</code> |
| L0520 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_model_content。 | <code>        "summary": content[:500],</code> |
| L0521 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 parse_model_content。 | <code>    }</code> |
| L0522 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0523 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0524 | 定义warmollama模型函数 &#96;warm_ollama_model&#96;，封装可复用业务逻辑。 | <code>def warm_ollama_model(base_url: str, model: str, timeout_sec: int = 60) -&gt; None:</code> |
| L0525 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 warm_ollama_model。 | <code>    """Load model weights before traffic arrives and retain them for the demo window."""</code> |
| L0526 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 warm_ollama_model。 | <code>    data = json.dumps(</code> |
| L0527 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 warm_ollama_model。 | <code>        {</code> |
| L0528 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 warm_ollama_model。 | <code>            "model": model, "prompt": "ready", "stream": False,</code> |
| L0529 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 warm_ollama_model。 | <code>            "keep_alive": os.environ.get("OLLAMA_KEEP_ALIVE", "15m"),</code> |
| L0530 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 warm_ollama_model。 | <code>            "options": {"num_predict": 1},</code> |
| L0531 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 warm_ollama_model。 | <code>        }</code> |
| L0532 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 warm_ollama_model。 | <code>    ).encode("utf-8")</code> |
| L0533 | 计算并保存 &#96;request&#96;（request），供后续逻辑使用，当前位于函数 warm_ollama_model。 | <code>    request = urllib.request.Request(</code> |
| L0534 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 warm_ollama_model。 | <code>        base_url.rstrip("/") + "/api/generate", data=data,</code> |
| L0535 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 warm_ollama_model。 | <code>        method="POST", headers={"Content-Type": "application/json"},</code> |
| L0536 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 warm_ollama_model。 | <code>    )</code> |
| L0537 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 warm_ollama_model。 | <code>    with urllib.request.urlopen(request, timeout=max(5, int(timeout_sec))) as response:</code> |
| L0538 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 warm_ollama_model。 | <code>        response.read()</code> |
| L0539 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0540 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0541 | 定义获取availablemodels函数 &#96;fetch_available_models&#96;，封装可复用业务逻辑。 | <code>def fetch_available_models(base_url: str, timeout_sec: int = 10) -&gt; List[str]:</code> |
| L0542 | 计算并保存 &#96;url&#96;（url），供后续逻辑使用，当前位于函数 fetch_available_models。 | <code>    url = base_url.rstrip("/") + "/api/tags"</code> |
| L0543 | 计算并保存 &#96;req&#96;（req），供后续逻辑使用，当前位于函数 fetch_available_models。 | <code>    req = urllib.request.Request(url=url, method="GET")</code> |
| L0544 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 fetch_available_models。 | <code>    try:</code> |
| L0545 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 fetch_available_models。 | <code>        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:</code> |
| L0546 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 fetch_available_models。 | <code>            raw = resp.read().decode("utf-8", errors="replace")</code> |
| L0547 | 计算并保存 &#96;obj&#96;（obj），供后续逻辑使用，当前位于函数 fetch_available_models。 | <code>        obj = json.loads(raw)</code> |
| L0548 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 fetch_available_models。 | <code>    except Exception:</code> |
| L0549 | 结束当前函数并把结果返回给调用方，当前位于函数 fetch_available_models。 | <code>        return []</code> |
| L0550 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0551 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 fetch_available_models。 | <code>    rows = obj.get("models")</code> |
| L0552 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 fetch_available_models。 | <code>    if not isinstance(rows, list):</code> |
| L0553 | 结束当前函数并把结果返回给调用方，当前位于函数 fetch_available_models。 | <code>        return []</code> |
| L0554 | 计算并保存 &#96;names&#96;（names），供后续逻辑使用，当前位于函数 fetch_available_models。 | <code>    names: List[str] = []</code> |
| L0555 | 遍历集合中的数据项并逐项处理，当前位于函数 fetch_available_models。 | <code>    for row in rows:</code> |
| L0556 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 fetch_available_models。 | <code>        if not isinstance(row, dict):</code> |
| L0557 | 控制当前循环或占位分支的执行流程，当前位于函数 fetch_available_models。 | <code>            continue</code> |
| L0558 | 计算并保存 &#96;name&#96;（name），供后续逻辑使用，当前位于函数 fetch_available_models。 | <code>        name = str(row.get("name") or "").strip()</code> |
| L0559 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 fetch_available_models。 | <code>        if name:</code> |
| L0560 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 fetch_available_models。 | <code>            names.append(name)</code> |
| L0561 | 结束当前函数并把结果返回给调用方，当前位于函数 fetch_available_models。 | <code>    return names</code> |
| L0562 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0563 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0564 | 定义解析并确定模型name函数 &#96;resolve_model_name&#96;，封装可复用业务逻辑。 | <code>def resolve_model_name(base_url: str, preferred_model: str, timeout_sec: int = 10) -&gt; str:</code> |
| L0565 | 计算并保存 &#96;preferred&#96;（preferred），供后续逻辑使用，当前位于函数 resolve_model_name。 | <code>    preferred = str(preferred_model or "").strip()</code> |
| L0566 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_model_name。 | <code>    if not preferred:</code> |
| L0567 | 计算并保存 &#96;preferred&#96;（preferred），供后续逻辑使用，当前位于函数 resolve_model_name。 | <code>        preferred = "qwen3:8b"</code> |
| L0568 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0569 | 计算并保存 &#96;models&#96;（models），供后续逻辑使用，当前位于函数 resolve_model_name。 | <code>    models = fetch_available_models(base_url=base_url, timeout_sec=timeout_sec)</code> |
| L0570 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_model_name。 | <code>    if not models:</code> |
| L0571 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 resolve_model_name。 | <code>        log(f"cannot read Ollama model list, keep configured model: {preferred}")</code> |
| L0572 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_model_name。 | <code>        return preferred</code> |
| L0573 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0574 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_model_name。 | <code>    if preferred in models:</code> |
| L0575 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_model_name。 | <code>        return preferred</code> |
| L0576 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0577 | 计算并保存 &#96;fallback&#96;（fallback），供后续逻辑使用，当前位于函数 resolve_model_name。 | <code>    fallback = models[0]</code> |
| L0578 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 resolve_model_name。 | <code>    log(f"configured model '{preferred}' not found, fallback to installed model: {fallback}")</code> |
| L0579 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_model_name。 | <code>    return fallback</code> |
| L0580 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0581 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0582 | 定义infertrusted攻击type函数 &#96;infer_trusted_attack_type&#96;，封装可复用业务逻辑。 | <code>def infer_trusted_attack_type(case_obj: Dict, parsed: Dict) -&gt; str:</code> |
| L0583 | 遍历集合中的数据项并逐项处理，当前位于函数 infer_trusted_attack_type。 | <code>    for key in ("attack_type", "v2_payload_label"):</code> |
| L0584 | 计算并保存 &#96;label&#96;（label），供后续逻辑使用，当前位于函数 infer_trusted_attack_type。 | <code>        label = str(case_obj.get(key) or "").strip()</code> |
| L0585 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 infer_trusted_attack_type。 | <code>        if label and "\ufffd" not in label:</code> |
| L0586 | 结束当前函数并把结果返回给调用方，当前位于函数 infer_trusted_attack_type。 | <code>            return label</code> |
| L0587 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0588 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 infer_trusted_attack_type。 | <code>    text = "\n".join(</code> |
| L0589 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_trusted_attack_type。 | <code>        str(case_obj.get(key) or "") for key in ("uri", "request_text", "rule_reason")</code> |
| L0590 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 infer_trusted_attack_type。 | <code>    ).lower()</code> |
| L0591 | 计算并保存 &#96;rules&#96;（rules），供后续逻辑使用，当前位于函数 infer_trusted_attack_type。 | <code>    rules = [</code> |
| L0592 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_trusted_attack_type。 | <code>        (r"(?:union\s+select&#124;information_schema&#124;sleep\s*\(&#124;\bor\s+1\s*=\s*1)", "SQL注入"),</code> |
| L0593 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_trusted_attack_type。 | <code>        (r"(?:&lt;script&#124;javascript:&#124;onerror\s*=&#124;onload\s*=)", "XSS"),</code> |
| L0594 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_trusted_attack_type。 | <code>        (r"(?:\.\./&#124;%2e%2e&#124;/etc/passwd&#124;windows[\\/]system32)", "路径遍历"),</code> |
| L0595 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_trusted_attack_type。 | <code>        (r"(?:cmd\.exe&#124;/bin/sh&#124;powershell&#124;runtime\.getruntime&#124;processbuilder)", "命令注入"),</code> |
| L0596 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_trusted_attack_type。 | <code>        (r"(?:multipart/form-data&#124;\.php\b&#124;\.jsp\b&#124;\.aspx\b)", "文件上传"),</code> |
| L0597 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 infer_trusted_attack_type。 | <code>    ]</code> |
| L0598 | 遍历集合中的数据项并逐项处理，当前位于函数 infer_trusted_attack_type。 | <code>    for pattern, label in rules:</code> |
| L0599 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 infer_trusted_attack_type。 | <code>        if re.search(pattern, text, re.I):</code> |
| L0600 | 结束当前函数并把结果返回给调用方，当前位于函数 infer_trusted_attack_type。 | <code>            return label</code> |
| L0601 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0602 | 计算并保存 &#96;parsed_label&#96;（parsedlabel），供后续逻辑使用，当前位于函数 infer_trusted_attack_type。 | <code>    parsed_label = str(parsed.get("attack_method") or "").strip()</code> |
| L0603 | 结束当前函数并把结果返回给调用方，当前位于函数 infer_trusted_attack_type。 | <code>    return parsed_label if parsed_label and "\ufffd" not in parsed_label else "可疑流量"</code> |
| L0604 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0605 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0606 | 定义标准化analysis函数 &#96;normalize_analysis&#96;，封装可复用业务逻辑。 | <code>def normalize_analysis(parsed: Dict, case_obj: Dict, src_ip: str, dst_ip: str, model_name: str) -&gt; Dict:</code> |
| L0607 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    uri = str(case_obj.get("uri") or "unknown")</code> |
| L0608 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    method = str(case_obj.get("method") or "")</code> |
| L0609 | 计算并保存 &#96;trusted_source_ip&#96;（trusted来源ip），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    trusted_source_ip = str(case_obj.get("source_ip") or src_ip or "unknown")</code> |
| L0610 | 计算并保存 &#96;trusted_destination_ip&#96;（trusteddestinationip），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    trusted_destination_ip = str(case_obj.get("destination_ip") or dst_ip or "unknown")</code> |
| L0611 | 计算并保存 &#96;trusted_attack_type&#96;（trusted攻击type），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    trusted_attack_type = infer_trusted_attack_type(case_obj, parsed)</code> |
| L0612 | 计算并保存 &#96;trusted_attack_path&#96;（trusted攻击path），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    trusted_attack_path = f"{method} {uri}".strip() or uri</code> |
| L0613 | 计算并保存 &#96;trusted_attack_time&#96;（trusted攻击time），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    trusted_attack_time = str(case_obj.get("export_time") or now_iso())</code> |
| L0614 | 计算并保存 &#96;verdict_raw&#96;（verdictraw），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    verdict_raw = str(parsed.get("verdict") or "unknown").strip().lower()</code> |
| L0615 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_analysis。 | <code>    if any(token in verdict_raw for token in ("attack", "malicious", "攻击", "恶意")):</code> |
| L0616 | 计算并保存 &#96;verdict&#96;（verdict），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        verdict = "attack"</code> |
| L0617 | 当前一条件未命中时继续判断另一条件，当前位于函数 normalize_analysis。 | <code>    elif any(token in verdict_raw for token in ("benign", "normal", "safe", "正常", "安全")):</code> |
| L0618 | 计算并保存 &#96;verdict&#96;（verdict），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        verdict = "benign"</code> |
| L0619 | 处理前述条件均未命中的情况，当前位于函数 normalize_analysis。 | <code>    else:</code> |
| L0620 | 计算并保存 &#96;verdict&#96;（verdict），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        verdict = "unknown"</code> |
| L0621 | 计算并保存 &#96;severity&#96;（severity），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    severity = str(parsed.get("severity") or case_obj.get("v2_risk_level") or "unknown")</code> |
| L0622 | 计算并保存 &#96;confidence&#96;（confidence），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    confidence = float(parsed.get("confidence", 0.0) or 0.0)</code> |
| L0623 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_analysis。 | <code>    if 1 &lt; confidence &lt;= 100:</code> |
| L0624 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        confidence /= 100.0</code> |
| L0625 | 计算并保存 &#96;confidence&#96;（confidence），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    confidence = max(0.0, min(1.0, confidence))</code> |
| L0626 | 计算并保存 &#96;confidence_percent&#96;（confidencepercent），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    confidence_percent = confidence * 100</code> |
| L0627 | 计算并保存 &#96;source_material&#96;（来源material），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    source_material = "\n".join(</code> |
| L0628 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        str(case_obj.get(key) or "")</code> |
| L0629 | 遍历集合中的数据项并逐项处理，当前位于函数 normalize_analysis。 | <code>        for key in ("uri", "request_text", "response_text", "detection_context")</code> |
| L0630 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_analysis。 | <code>    ).lower()</code> |
| L0631 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0632 | 计算并保存 &#96;signature_terms&#96;（signatureterms），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    signature_terms = {</code> |
| L0633 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "xss": ("script", "onerror", "onload", "javascript:", "xss"),</code> |
| L0634 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "sql": ("union", "select", "information_schema", "sleep(", "sql", "or 1=1"),</code> |
| L0635 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "命令": ("cmd.exe", "/bin/sh", "powershell", "whoami", "命令注入", "$(&#96;", "&amp;&amp;"),</code> |
| L0636 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "路径": ("../", "..\\", "%2e%2e", "/etc/passwd", "win.ini", "路径遍历"),</code> |
| L0637 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_analysis。 | <code>    }</code> |
| L0638 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0639 | 定义evidenceisgrounded函数 &#96;evidence_is_grounded&#96;，封装可复用业务逻辑。 | <code>    def evidence_is_grounded(item: str) -&gt; bool:</code> |
| L0640 | 计算并保存 &#96;lowered&#96;（lowered），供后续逻辑使用，当前位于函数 evidence_is_grounded。 | <code>        lowered = item.lower()</code> |
| L0641 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 evidence_is_grounded。 | <code>        if any(token in lowered for token in ("rce_ok", "shell_ok", "exploit succeeded", "利用成功")):</code> |
| L0642 | 结束当前函数并把结果返回给调用方，当前位于函数 evidence_is_grounded。 | <code>            return any(token in source_material for token in ("rce_ok", "shell_ok", "exploit succeeded", "利用成功"))</code> |
| L0643 | 遍历集合中的数据项并逐项处理，当前位于函数 evidence_is_grounded。 | <code>        for label, terms in signature_terms.items():</code> |
| L0644 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 evidence_is_grounded。 | <code>            if label in lowered and not any(term in source_material for term in terms):</code> |
| L0645 | 结束当前函数并把结果返回给调用方，当前位于函数 evidence_is_grounded。 | <code>                return False</code> |
| L0646 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 evidence_is_grounded。 | <code>        if "script" in lowered and "script" not in source_material:</code> |
| L0647 | 结束当前函数并把结果返回给调用方，当前位于函数 evidence_is_grounded。 | <code>            return False</code> |
| L0648 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 evidence_is_grounded。 | <code>        if re.search(r"(?:参数&#124;parameter)\s*[qQ](?:\s&#124;：&#124;:)", item) and not re.search(r"[?&amp;]q=&#124;\"q\"", source_material):</code> |
| L0649 | 结束当前函数并把结果返回给调用方，当前位于函数 evidence_is_grounded。 | <code>            return False</code> |
| L0650 | 结束当前函数并把结果返回给调用方，当前位于函数 evidence_is_grounded。 | <code>        return True</code> |
| L0651 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0652 | 计算并保存 &#96;parsed_evidence&#96;（parsedevidence），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    parsed_evidence = parsed.get("evidence") if isinstance(parsed.get("evidence"), list) else []</code> |
| L0653 | 计算并保存 &#96;grounded_evidence&#96;（groundedevidence），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    grounded_evidence = [</code> |
| L0654 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        str(item).strip() for item in parsed_evidence</code> |
| L0655 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_analysis。 | <code>        if str(item).strip() and evidence_is_grounded(str(item))</code> |
| L0656 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_analysis。 | <code>    ][:6]</code> |
| L0657 | 计算并保存 &#96;context&#96;（context），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    context = case_obj.get("detection_context") if isinstance(case_obj.get("detection_context"), dict) else {}</code> |
| L0658 | 计算并保存 &#96;fusion_score&#96;（fusionscore），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    fusion_score = float(context.get("fusion_score") or 0.0)</code> |
| L0659 | 计算并保存 &#96;poc_rows&#96;（poc数据库记录），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    poc_rows = context.get("poc_matches") if isinstance(context.get("poc_matches"), list) else []</code> |
| L0660 | 计算并保存 &#96;payload_rows&#96;（payload数据库记录），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    payload_rows = context.get("payload_models") if isinstance(context.get("payload_models"), list) else []</code> |
| L0661 | 计算并保存 &#96;strong_payload&#96;（strongpayload），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    strong_payload = any(float(item.get("score") or 0.0) &gt;= 0.85 for item in payload_rows if isinstance(item, dict))</code> |
| L0662 | 计算并保存 &#96;strong_poc&#96;（strongpoc），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    strong_poc = any(</code> |
| L0663 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        str(item.get("severity") or "").lower() in {"high", "critical"}</code> |
| L0664 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        and float(item.get("score") or 0.0) &gt;= 0.8</code> |
| L0665 | 遍历集合中的数据项并逐项处理，当前位于函数 normalize_analysis。 | <code>        for item in poc_rows</code> |
| L0666 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_analysis。 | <code>        if isinstance(item, dict)</code> |
| L0667 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_analysis。 | <code>    )</code> |
| L0668 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_analysis。 | <code>    if parsed.get("_partial_recovered") and not (strong_poc or strong_payload or fusion_score &gt;= 0.8):</code> |
| L0669 | 计算并保存 &#96;verdict&#96;（verdict），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        verdict = "unknown"</code> |
| L0670 | 计算并保存 &#96;severity&#96;（severity），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        severity = "unknown"</code> |
| L0671 | 计算并保存 &#96;confidence&#96;（confidence），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        confidence = min(confidence, 0.49)</code> |
| L0672 | 计算并保存 &#96;model_summary&#96;（模型summary），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    model_summary = str(parsed.get("summary") or "").strip()</code> |
| L0673 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_analysis。 | <code>    if verdict == "benign" and fusion_score &gt;= 0.8 and poc_rows and strong_payload:</code> |
| L0674 | 计算并保存 &#96;verdict&#96;（verdict），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        verdict = "unknown"</code> |
| L0675 | 计算并保存 &#96;severity&#96;（severity），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        severity = "unknown"</code> |
| L0676 | 计算并保存 &#96;confidence&#96;（confidence），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        confidence = min(confidence, 0.49)</code> |
| L0677 | 计算并保存 &#96;model_summary&#96;（模型summary），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        model_summary = "大模型结论与多源强证据发生冲突，系统已阻止其发布为正常流量并转入人工复核。"</code> |
| L0678 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_analysis。 | <code>    if not grounded_evidence:</code> |
| L0679 | 计算并保存 &#96;pocs&#96;（pocs），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        pocs = poc_rows</code> |
| L0680 | 计算并保存 &#96;predictions&#96;（predictions），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        predictions = payload_rows</code> |
| L0681 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_analysis。 | <code>        if pocs:</code> |
| L0682 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 normalize_analysis。 | <code>            grounded_evidence.append(f"POC 规则：{pocs[0].get('rule_name') or pocs[0].get('rule_id') or '明确规则命中'}")</code> |
| L0683 | 当前一条件未命中时继续判断另一条件，当前位于函数 normalize_analysis。 | <code>        elif predictions:</code> |
| L0684 | 计算并保存 &#96;pred&#96;（pred），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>            pred = predictions[0]</code> |
| L0685 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 normalize_analysis。 | <code>            grounded_evidence.append(</code> |
| L0686 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>                f"Payload 模型：{pred.get('label') or 'unknown'}，评分 {float(pred.get('score') or 0):.2f}"</code> |
| L0687 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_analysis。 | <code>            )</code> |
| L0688 | 处理前述条件均未命中的情况，当前位于函数 normalize_analysis。 | <code>        else:</code> |
| L0689 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 normalize_analysis。 | <code>            grounded_evidence.append("大模型复核：输入中未发现可独立验证的明确攻击特征")</code> |
| L0690 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_analysis。 | <code>    if verdict == "attack" and confidence &gt;= 0.8:</code> |
| L0691 | 计算并保存 &#96;model_summary&#96;（模型summary），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        model_summary = model_summary.replace("证据不足", "尚无成功利用证据")</code> |
| L0692 | 计算并保存 &#96;trusted_summary&#96;（trustedsummary），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    trusted_summary = model_summary or (</code> |
| L0693 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        f"来源 {trusted_source_ip} 对 {uri} 的请求经大模型复核为 {verdict}，"</code> |
| L0694 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        f"攻击类型为 {trusted_attack_type}，风险等级 {severity}，"</code> |
| L0695 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        f"置信度约 {confidence_percent:.1f}%。"</code> |
| L0696 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_analysis。 | <code>    )</code> |
| L0697 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0698 | 定义clean列出函数 &#96;clean_list&#96;，封装可复用业务逻辑。 | <code>    def clean_list(name: str, limit: int = 4) -&gt; List[str]:</code> |
| L0699 | 计算并保存 &#96;value&#96;（value），供后续逻辑使用，当前位于函数 clean_list。 | <code>        value = parsed.get(name)</code> |
| L0700 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 clean_list。 | <code>        if not isinstance(value, list):</code> |
| L0701 | 结束当前函数并把结果返回给调用方，当前位于函数 clean_list。 | <code>            return []</code> |
| L0702 | 结束当前函数并把结果返回给调用方，当前位于函数 clean_list。 | <code>        return [str(item).strip() for item in value if str(item).strip()][:limit]</code> |
| L0703 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0704 | 计算并保存 &#96;immediate_actions&#96;（immediateactions），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    immediate_actions = clean_list("immediate_actions")</code> |
| L0705 | 计算并保存 &#96;hardening_actions&#96;（hardeningactions），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    hardening_actions = clean_list("hardening_actions")</code> |
| L0706 | 计算并保存 &#96;attack_type_lower&#96;（攻击typelower），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    attack_type_lower = trusted_attack_type.lower()</code> |
| L0707 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_analysis。 | <code>    if "xss" in attack_type_lower:</code> |
| L0708 | 计算并保存 &#96;hardening_actions&#96;（hardeningactions），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        hardening_actions = [item for item in hardening_actions if "参数化查询" not in item and "sql" not in item.lower()]</code> |
| L0709 | 计算并保存 &#96;defaults&#96;（defaults），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        defaults = ["按 HTML/属性/JavaScript 上下文执行输出编码", "部署 CSP 并使用可信 HTML Sanitizer 处理富文本"]</code> |
| L0710 | 计算并保存 &#96;hardening_actions&#96;（hardeningactions），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        hardening_actions = (hardening_actions + [item for item in defaults if item not in hardening_actions])[:4]</code> |
| L0711 | 当前一条件未命中时继续判断另一条件，当前位于函数 normalize_analysis。 | <code>    elif "sql" in attack_type_lower:</code> |
| L0712 | 计算并保存 &#96;defaults&#96;（defaults），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        defaults = ["数据库访问统一使用参数化查询或预编译语句", "限制数据库账户权限并隐藏详细数据库错误"]</code> |
| L0713 | 计算并保存 &#96;hardening_actions&#96;（hardeningactions），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        hardening_actions = (hardening_actions + [item for item in defaults if item not in hardening_actions])[:4]</code> |
| L0714 | 当前一条件未命中时继续判断另一条件，当前位于函数 normalize_analysis。 | <code>    elif "fastjson" in attack_type_lower or "反序列化" in attack_type_lower:</code> |
| L0715 | 计算并保存 &#96;hardening_actions&#96;（hardeningactions），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        hardening_actions = [</code> |
| L0716 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>            item for item in hardening_actions</code> |
| L0717 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_analysis。 | <code>            if not any(token in item.lower() for token in ("sql", "参数化查询", "html sanitizer", "csp", "输出编码"))</code> |
| L0718 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_analysis。 | <code>        ]</code> |
| L0719 | 计算并保存 &#96;defaults&#96;（defaults），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        defaults = [</code> |
| L0720 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>            "升级并固定使用受支持的 Fastjson2 安全版本，保持 AutoType 默认关闭",</code> |
| L0721 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>            "确需多态反序列化时使用最小类白名单 AutoTypeFilter，并评估启用 SafeMode",</code> |
| L0722 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>            "拒绝包含外部协议、任意类名和危险 gadget 的 @type 输入",</code> |
| L0723 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_analysis。 | <code>        ]</code> |
| L0724 | 计算并保存 &#96;hardening_actions&#96;（hardeningactions），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        hardening_actions = (hardening_actions + [item for item in defaults if item not in hardening_actions])[:4]</code> |
| L0725 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0726 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_analysis。 | <code>    if verdict == "benign":</code> |
| L0727 | 计算并保存 &#96;immediate_actions&#96;（immediateactions），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        immediate_actions = [item for item in immediate_actions if "封禁" not in item and "拦截" not in item]</code> |
| L0728 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0729 | 计算并保存 &#96;analysis_reasoning&#96;（analysisreasoning），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>    analysis_reasoning = str(parsed.get("analysis_reasoning") or "").strip()</code> |
| L0730 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_analysis。 | <code>    if analysis_reasoning and not evidence_is_grounded(analysis_reasoning):</code> |
| L0731 | 计算并保存 &#96;analysis_reasoning&#96;（analysisreasoning），供后续逻辑使用，当前位于函数 normalize_analysis。 | <code>        analysis_reasoning = (</code> |
| L0732 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>            f"大模型结合抓包事实、融合评分及可复核证据，将该请求判定为 {verdict}；"</code> |
| L0733 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>            "原模型推理包含无法在输入中定位的特征，已由一致性校验移除。"</code> |
| L0734 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_analysis。 | <code>        )</code> |
| L0735 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0736 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_analysis。 | <code>    return {</code> |
| L0737 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "case_id": str(case_obj.get("case_id") or ""),</code> |
| L0738 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "file_id": str(case_obj.get("file_id") or ""),</code> |
| L0739 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "seq_id": int(case_obj.get("seq_id") or 0),</code> |
| L0740 | 源码原注释：Network facts come from packet capture and the deterministic detector. | <code>        # Network facts come from packet capture and the deterministic detector.</code> |
| L0741 | 源码原注释：A small LLM may hallucinate these fields, so it must not overwrite them. | <code>        # A small LLM may hallucinate these fields, so it must not overwrite them.</code> |
| L0742 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "source_ip": trusted_source_ip,</code> |
| L0743 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "destination_ip": trusted_destination_ip,</code> |
| L0744 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "attack_interface": uri,</code> |
| L0745 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "attack_method": trusted_attack_type,</code> |
| L0746 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "attack_path": trusted_attack_path,</code> |
| L0747 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "attack_time": trusted_attack_time,</code> |
| L0748 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "severity": severity,</code> |
| L0749 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "confidence": confidence,</code> |
| L0750 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "verdict": verdict,</code> |
| L0751 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "evidence": grounded_evidence,</code> |
| L0752 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "summary": trusted_summary,</code> |
| L0753 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "llm_explanation": analysis_reasoning or model_summary,</code> |
| L0754 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "analysis_reasoning": analysis_reasoning,</code> |
| L0755 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "potential_impact": clean_list("potential_impact"),</code> |
| L0756 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "immediate_actions": immediate_actions,</code> |
| L0757 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "hardening_actions": hardening_actions,</code> |
| L0758 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "false_positive_notes": str(parsed.get("false_positive_notes") or "").strip(),</code> |
| L0759 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "knowledge_references": clean_list("knowledge_references"),</code> |
| L0760 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "model_name": model_name,</code> |
| L0761 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_analysis。 | <code>        "analyzed_at": now_iso(),</code> |
| L0762 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_analysis。 | <code>    }</code> |
| L0763 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0764 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0765 | 定义shouldretryllmerror函数 &#96;should_retry_llm_error&#96;，封装可复用业务逻辑。 | <code>def should_retry_llm_error(err_text: str) -&gt; bool:</code> |
| L0766 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 should_retry_llm_error。 | <code>    text = (err_text or "").lower()</code> |
| L0767 | 计算并保存 &#96;retry_tokens&#96;（retrytokens），供后续逻辑使用，当前位于函数 should_retry_llm_error。 | <code>    retry_tokens = [</code> |
| L0768 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 should_retry_llm_error。 | <code>        "timed out",</code> |
| L0769 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 should_retry_llm_error。 | <code>        "connection refused",</code> |
| L0770 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 should_retry_llm_error。 | <code>        "winerror 10061",</code> |
| L0771 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 should_retry_llm_error。 | <code>        "llama runner process has terminated",</code> |
| L0772 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 should_retry_llm_error。 | <code>        "http 500",</code> |
| L0773 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 should_retry_llm_error。 | <code>        "internal server error",</code> |
| L0774 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 should_retry_llm_error。 | <code>    ]</code> |
| L0775 | 结束当前函数并把结果返回给调用方，当前位于函数 should_retry_llm_error。 | <code>    return any(tok in text for tok in retry_tokens)</code> |
| L0776 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0777 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0778 | 定义processcase函数 &#96;process_case&#96;，封装可复用业务逻辑。 | <code>def process_case(</code> |
| L0779 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>    case_dir: Path,</code> |
| L0780 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>    input_dir: Path,</code> |
| L0781 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>    system_prompt: str,</code> |
| L0782 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>    schema_obj: Dict,</code> |
| L0783 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>    args,</code> |
| L0784 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_case。 | <code>) -&gt; str:</code> |
| L0785 | 计算并保存 &#96;case_json_path&#96;（casejsonpath），供后续逻辑使用，当前位于函数 process_case。 | <code>    case_json_path = case_dir / "case.json"</code> |
| L0786 | 计算并保存 &#96;request_path&#96;（requestpath），供后续逻辑使用，当前位于函数 process_case。 | <code>    request_path = case_dir / "request.txt"</code> |
| L0787 | 计算并保存 &#96;response_path&#96;（responsepath），供后续逻辑使用，当前位于函数 process_case。 | <code>    response_path = case_dir / "response.txt"</code> |
| L0788 | 计算并保存 &#96;analysis_path&#96;（analysispath），供后续逻辑使用，当前位于函数 process_case。 | <code>    analysis_path = case_dir / "analysis.json"</code> |
| L0789 | 计算并保存 &#96;analysis_raw_path&#96;（analysisrawpath），供后续逻辑使用，当前位于函数 process_case。 | <code>    analysis_raw_path = case_dir / "analysis_raw.txt"</code> |
| L0790 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0791 | 计算并保存 &#96;case_obj&#96;（caseobj），供后续逻辑使用，当前位于函数 process_case。 | <code>    case_obj = read_json(case_json_path, default={})</code> |
| L0792 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_case。 | <code>    if not case_obj:</code> |
| L0793 | 结束当前函数并把结果返回给调用方，当前位于函数 process_case。 | <code>        return "skip(no_case_json)"</code> |
| L0794 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0795 | 计算并保存 &#96;llm_status&#96;（llm状态），供后续逻辑使用，当前位于函数 process_case。 | <code>    llm_status = str(case_obj.get("llm_status") or "pending").lower()</code> |
| L0796 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_case。 | <code>    if llm_status == "done" and analysis_path.exists():</code> |
| L0797 | 结束当前函数并把结果返回给调用方，当前位于函数 process_case。 | <code>        return "skip(done)"</code> |
| L0798 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0799 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_case。 | <code>    if llm_status == "processing":</code> |
| L0800 | 结束当前函数并把结果返回给调用方，当前位于函数 process_case。 | <code>        return "skip(processing)"</code> |
| L0801 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0802 | 源码原注释：mark processing | <code>    # mark processing</code> |
| L0803 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>    case_obj["llm_status"] = "processing"</code> |
| L0804 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>    case_obj["llm_started_at"] = now_iso()</code> |
| L0805 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>    write_json(case_json_path, case_obj)</code> |
| L0806 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0807 | 计算并保存 &#96;request_text&#96;（requesttext），供后续逻辑使用，当前位于函数 process_case。 | <code>    request_text = read_text(request_path)</code> |
| L0808 | 计算并保存 &#96;response_text&#96;（responsetext），供后续逻辑使用，当前位于函数 process_case。 | <code>    response_text = read_text(response_path)</code> |
| L0809 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0810 | 计算并保存 &#96;file_id&#96;（fileid），供后续逻辑使用，当前位于函数 process_case。 | <code>    file_id = str(case_obj.get("file_id") or "")</code> |
| L0811 | 计算并保存 &#96;seq_id&#96;（seqid），供后续逻辑使用，当前位于函数 process_case。 | <code>    seq_id = int(case_obj.get("seq_id") or 0)</code> |
| L0812 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>    src_ip, dst_ip = parse_case_ips_from_input(input_dir / f"{file_id}.txt", seq_id)</code> |
| L0813 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0814 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_case。 | <code>    if not src_ip:</code> |
| L0815 | 计算并保存 &#96;src_ip&#96;（srcip），供后续逻辑使用，当前位于函数 process_case。 | <code>        src_ip = parse_ip_from_text(request_text) or "unknown"</code> |
| L0816 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_case。 | <code>    if not dst_ip:</code> |
| L0817 | 计算并保存 &#96;dst_ip&#96;（dstip），供后续逻辑使用，当前位于函数 process_case。 | <code>        dst_ip = parse_ip_from_text(response_text) or "unknown"</code> |
| L0818 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0819 | 计算并保存 &#96;rag_rows&#96;（rag数据库记录），供后续逻辑使用，当前位于函数 process_case。 | <code>    rag_rows: List[Dict] = []</code> |
| L0820 | 计算并保存 &#96;rag_context&#96;（ragcontext），供后续逻辑使用，当前位于函数 process_case。 | <code>    rag_context = ""</code> |
| L0821 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_case。 | <code>    if args.rag_enable:</code> |
| L0822 | 计算并保存 &#96;query_text&#96;（querytext），供后续逻辑使用，当前位于函数 process_case。 | <code>        query_text = "\n".join(</code> |
| L0823 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>            [</code> |
| L0824 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>                str(case_obj.get("attack_type") or ""),</code> |
| L0825 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>                str(case_obj.get("method") or ""),</code> |
| L0826 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>                str(case_obj.get("uri") or ""),</code> |
| L0827 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>                str(case_obj.get("host") or ""),</code> |
| L0828 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>                request_text[:2500],</code> |
| L0829 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>                response_text[:1200],</code> |
| L0830 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_case。 | <code>            ]</code> |
| L0831 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_case。 | <code>        )</code> |
| L0832 | 计算并保存 &#96;rag_rows&#96;（rag数据库记录），供后续逻辑使用，当前位于函数 process_case。 | <code>        rag_rows = retrieve_advanced_rag(args, query_text=query_text)</code> |
| L0833 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_case。 | <code>        if not rag_rows:</code> |
| L0834 | 计算并保存 &#96;rag_rows&#96;（rag数据库记录），供后续逻辑使用，当前位于函数 process_case。 | <code>            rag_rows = retrieve_rag_docs(args.rag_db_path, query_text=query_text, top_k=args.rag_top_k)</code> |
| L0835 | 计算并保存 &#96;rag_context&#96;（ragcontext），供后续逻辑使用，当前位于函数 process_case。 | <code>        rag_context = format_rag_context(rag_rows, max_chars=args.rag_max_chars)</code> |
| L0836 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0837 | 计算并保存 &#96;user_payload&#96;（userpayload），供后续逻辑使用，当前位于函数 process_case。 | <code>    user_payload = build_user_payload(case_obj, request_text, response_text, src_ip, dst_ip, rag_context=rag_context)</code> |
| L0838 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0839 | 计算并保存 &#96;models_to_try&#96;（modelstotry），供后续逻辑使用，当前位于函数 process_case。 | <code>    models_to_try: List[str] = [args.model]</code> |
| L0840 | 计算并保存 &#96;fallback_model&#96;（fallback模型），供后续逻辑使用，当前位于函数 process_case。 | <code>    fallback_model = str(getattr(args, "fallback_model_resolved", "") or "").strip()</code> |
| L0841 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_case。 | <code>    if fallback_model and fallback_model not in models_to_try:</code> |
| L0842 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 process_case。 | <code>        models_to_try.append(fallback_model)</code> |
| L0843 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0844 | 计算并保存 &#96;last_exc&#96;（lastexc），供后续逻辑使用，当前位于函数 process_case。 | <code>    last_exc: Optional[Exception] = None</code> |
| L0845 | 遍历集合中的数据项并逐项处理，当前位于函数 process_case。 | <code>    for idx, model_name in enumerate(models_to_try):</code> |
| L0846 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 process_case。 | <code>        try:</code> |
| L0847 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>            parsed, raw_content = call_ollama_chat(</code> |
| L0848 | 计算并保存 &#96;base_url&#96;（baseurl），供后续逻辑使用，当前位于函数 process_case。 | <code>                base_url=args.ollama_url,</code> |
| L0849 | 计算并保存 &#96;model&#96;（模型），供后续逻辑使用，当前位于函数 process_case。 | <code>                model=model_name,</code> |
| L0850 | 计算并保存 &#96;system_prompt&#96;（systemprompt），供后续逻辑使用，当前位于函数 process_case。 | <code>                system_prompt=system_prompt,</code> |
| L0851 | 计算并保存 &#96;user_payload&#96;（userpayload），供后续逻辑使用，当前位于函数 process_case。 | <code>                user_payload=user_payload,</code> |
| L0852 | 计算并保存 &#96;schema_obj&#96;（schemaobj），供后续逻辑使用，当前位于函数 process_case。 | <code>                schema_obj=schema_obj,</code> |
| L0853 | 计算并保存 &#96;timeout_sec&#96;（timeoutsec），供后续逻辑使用，当前位于函数 process_case。 | <code>                timeout_sec=args.timeout_sec,</code> |
| L0854 | 计算并保存 &#96;num_ctx&#96;（numctx），供后续逻辑使用，当前位于函数 process_case。 | <code>                num_ctx=args.num_ctx,</code> |
| L0855 | 计算并保存 &#96;num_gpu&#96;（numgpu），供后续逻辑使用，当前位于函数 process_case。 | <code>                num_gpu=args.num_gpu,</code> |
| L0856 | 计算并保存 &#96;temperature&#96;（temperature），供后续逻辑使用，当前位于函数 process_case。 | <code>                temperature=args.temperature,</code> |
| L0857 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_case。 | <code>            )</code> |
| L0858 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0859 | 计算并保存 &#96;analysis&#96;（analysis），供后续逻辑使用，当前位于函数 process_case。 | <code>            analysis = normalize_analysis(parsed, case_obj, src_ip, dst_ip, model_name)</code> |
| L0860 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>            analysis["rag_hits"] = len(rag_rows)</code> |
| L0861 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>            analysis["rag_enabled"] = bool(args.rag_enable)</code> |
| L0862 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>            analysis["knowledge_references"] = build_rag_references(rag_rows) if args.rag_enable else []</code> |
| L0863 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>            write_json(analysis_path, analysis)</code> |
| L0864 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>            analysis_raw_path.write_text(raw_content or "", encoding="utf-8")</code> |
| L0865 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0866 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>            case_obj["llm_status"] = "done"</code> |
| L0867 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>            case_obj.pop("llm_error", None)</code> |
| L0868 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>            case_obj.pop("llm_failed_at", None)</code> |
| L0869 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>            case_obj["analysis_file"] = str(analysis_path.resolve())</code> |
| L0870 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>            case_obj["analysis_raw_file"] = str(analysis_raw_path.resolve())</code> |
| L0871 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>            case_obj["rag_hits"] = len(rag_rows)</code> |
| L0872 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>            case_obj["analyzed_at"] = now_iso()</code> |
| L0873 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>            case_obj["status"] = case_obj.get("status") or "pending"</code> |
| L0874 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>            write_json(case_json_path, case_obj)</code> |
| L0875 | 结束当前函数并把结果返回给调用方，当前位于函数 process_case。 | <code>            return "done"</code> |
| L0876 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 process_case。 | <code>        except Exception as exc:  # noqa: BLE001</code> |
| L0877 | 计算并保存 &#96;last_exc&#96;（lastexc），供后续逻辑使用，当前位于函数 process_case。 | <code>            last_exc = exc</code> |
| L0878 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_case。 | <code>            if idx &lt; len(models_to_try) - 1 and should_retry_llm_error(str(exc)):</code> |
| L0879 | 计算并保存 &#96;next_model&#96;（next模型），供后续逻辑使用，当前位于函数 process_case。 | <code>                next_model = models_to_try[idx + 1]</code> |
| L0880 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 process_case。 | <code>                log(f"{case_dir.name}: model={model_name} failed ({exc}), retry with {next_model}")</code> |
| L0881 | 控制当前循环或占位分支的执行流程，当前位于函数 process_case。 | <code>                continue</code> |
| L0882 | 控制当前循环或占位分支的执行流程，当前位于函数 process_case。 | <code>            break</code> |
| L0883 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0884 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>    case_obj["llm_status"] = "failed"</code> |
| L0885 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>    case_obj["llm_error"] = str(last_exc) if last_exc else "unknown_error"</code> |
| L0886 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>    case_obj["llm_failed_at"] = now_iso()</code> |
| L0887 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_case。 | <code>    write_json(case_json_path, case_obj)</code> |
| L0888 | 结束当前函数并把结果返回给调用方，当前位于函数 process_case。 | <code>    return f"failed({last_exc})"</code> |
| L0889 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0890 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0891 | 定义openreviewconn函数 &#96;open_review_conn&#96;，封装可复用业务逻辑。 | <code>def open_review_conn(args):</code> |
| L0892 | 导入后续逻辑所需的模块、类或函数：&#96;from build_result_db import MySQLConfig&#96;。 | <code>    from build_result_db import MySQLConfig</code> |
| L0893 | 导入后续逻辑所需的模块、类或函数：&#96;from sync_detection_v2_db import mysql_connect&#96;。 | <code>    from sync_detection_v2_db import mysql_connect</code> |
| L0894 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0895 | 结束当前函数并把结果返回给调用方，当前位于函数 open_review_conn。 | <code>    return mysql_connect(</code> |
| L0896 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 open_review_conn。 | <code>        MySQLConfig(</code> |
| L0897 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 open_review_conn。 | <code>            args.rag_mysql_host,</code> |
| L0898 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 open_review_conn。 | <code>            args.rag_mysql_port,</code> |
| L0899 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 open_review_conn。 | <code>            args.rag_mysql_user,</code> |
| L0900 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 open_review_conn。 | <code>            args.rag_mysql_password,</code> |
| L0901 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 open_review_conn。 | <code>            args.rag_mysql_database,</code> |
| L0902 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 open_review_conn。 | <code>        )</code> |
| L0903 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 open_review_conn。 | <code>    )</code> |
| L0904 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0905 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0906 | 定义构建fusiononlyanalysis函数 &#96;build_fusion_only_analysis&#96;，封装可复用业务逻辑。 | <code>def build_fusion_only_analysis(row: Dict, case_obj: Dict, context: Dict) -&gt; Dict:</code> |
| L0907 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 build_fusion_only_analysis。 | <code>    attack_type = str(row.get("attack_type") or "可疑流量")</code> |
| L0908 | 计算并保存 &#96;risk&#96;（risk），供后续逻辑使用，当前位于函数 build_fusion_only_analysis。 | <code>    risk = str(row.get("risk_level") or "medium").lower()</code> |
| L0909 | 计算并保存 &#96;score&#96;（score），供后续逻辑使用，当前位于函数 build_fusion_only_analysis。 | <code>    score = max(0.0, min(1.0, float(row.get("final_score") or 0.0)))</code> |
| L0910 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 build_fusion_only_analysis。 | <code>    evidence: List[str] = []</code> |
| L0911 | 遍历集合中的数据项并逐项处理，当前位于函数 build_fusion_only_analysis。 | <code>    for value in context.get("fusion_evidence") or []:</code> |
| L0912 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 build_fusion_only_analysis。 | <code>        text = str(value).strip()</code> |
| L0913 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_fusion_only_analysis。 | <code>        if text and text not in evidence:</code> |
| L0914 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_fusion_only_analysis。 | <code>            evidence.append(text)</code> |
| L0915 | 遍历集合中的数据项并逐项处理，当前位于函数 build_fusion_only_analysis。 | <code>    for item in context.get("poc_matches") or []:</code> |
| L0916 | 计算并保存 &#96;name&#96;（name），供后续逻辑使用，当前位于函数 build_fusion_only_analysis。 | <code>        name = str(item.get("rule_name") or item.get("rule_id") or "POC规则").strip()</code> |
| L0917 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 build_fusion_only_analysis。 | <code>        text = f"POC规则命中：{name}"</code> |
| L0918 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_fusion_only_analysis。 | <code>        if text not in evidence:</code> |
| L0919 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_fusion_only_analysis。 | <code>            evidence.append(text)</code> |
| L0920 | 遍历集合中的数据项并逐项处理，当前位于函数 build_fusion_only_analysis。 | <code>    for item in context.get("payload_models") or []:</code> |
| L0921 | 计算并保存 &#96;label&#96;（label），供后续逻辑使用，当前位于函数 build_fusion_only_analysis。 | <code>        label = str(item.get("label") or "").strip()</code> |
| L0922 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_fusion_only_analysis。 | <code>        if label:</code> |
| L0923 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_fusion_only_analysis。 | <code>            evidence.append(f"Payload模型判定为{label}，评分{float(item.get('score') or 0):.3f}")</code> |
| L0924 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 build_fusion_only_analysis。 | <code>    evidence = evidence[:6] or [f"多模型融合评分为{score:.3f}，建议人工复核原始请求与响应"]</code> |
| L0925 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fusion_only_analysis。 | <code>    verdict = "attack" if str(row.get("preliminary_decision")) == "attack_event" else "unknown"</code> |
| L0926 | 结束当前函数并把结果返回给调用方，当前位于函数 build_fusion_only_analysis。 | <code>    return {</code> |
| L0927 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fusion_only_analysis。 | <code>        "verdict": verdict,</code> |
| L0928 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fusion_only_analysis。 | <code>        "source_ip": str(row.get("source_ip") or "unknown"),</code> |
| L0929 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fusion_only_analysis。 | <code>        "destination_ip": str(row.get("destination_ip") or "unknown"),</code> |
| L0930 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fusion_only_analysis。 | <code>        "attack_interface": str(row.get("uri") or ""),</code> |
| L0931 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fusion_only_analysis。 | <code>        "attack_method": attack_type,</code> |
| L0932 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fusion_only_analysis。 | <code>        "attack_path": f"{row.get('method') or ''} {row.get('uri') or ''}".strip(),</code> |
| L0933 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fusion_only_analysis。 | <code>        "attack_time": str(row.get("event_time") or ""),</code> |
| L0934 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fusion_only_analysis。 | <code>        "severity": risk if risk in {"low", "medium", "high", "critical"} else "unknown",</code> |
| L0935 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fusion_only_analysis。 | <code>        "confidence": score,</code> |
| L0936 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fusion_only_analysis。 | <code>        "evidence": evidence,</code> |
| L0937 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fusion_only_analysis。 | <code>        "analysis_reasoning": "Payload模型、POC规则与行为窗口完成交叉验证；当前未调用实时生成模型。",</code> |
| L0938 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fusion_only_analysis。 | <code>        "potential_impact": [f"若该{attack_type}请求成功，可能影响目标接口的数据或服务完整性。"],</code> |
| L0939 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fusion_only_analysis。 | <code>        "immediate_actions": ["核验来源IP与同时间窗口请求，必要时限流或封禁。", "检查目标接口日志与异常响应。"],</code> |
| L0940 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fusion_only_analysis。 | <code>        "hardening_actions": ["针对目标接口实施参数校验、最小权限和安全审计。", "持续更新POC规则与行为基线。"],</code> |
| L0941 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fusion_only_analysis。 | <code>        "false_positive_notes": "如请求来自授权测试或内部扫描，应结合资产台账降级处置。",</code> |
| L0942 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fusion_only_analysis。 | <code>        "knowledge_references": [],</code> |
| L0943 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_fusion_only_analysis。 | <code>        "summary": f"多模型融合发现{attack_type}特征，风险等级为{risk}，融合置信度{score:.1%}。",</code> |
| L0944 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_fusion_only_analysis。 | <code>    }</code> |
| L0945 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0946 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0947 | 定义processnextrawreview函数 &#96;process_next_raw_review&#96;，封装可复用业务逻辑。 | <code>def process_next_raw_review(system_prompt: str, schema_obj: Dict, args) -&gt; Optional[str]:</code> |
| L0948 | 导入后续逻辑所需的模块、类或函数：&#96;from raw_llm_review import (&#96;。 | <code>    from raw_llm_review import (</code> |
| L0949 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>        claim_next_review,</code> |
| L0950 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>        complete_review,</code> |
| L0951 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>        defer_review,</code> |
| L0952 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>        detection_context,</code> |
| L0953 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>        fail_review,</code> |
| L0954 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>        find_cached_review,</code> |
| L0955 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>        mark_cache_hit,</code> |
| L0956 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>        realtime_llm_enabled,</code> |
| L0957 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_next_raw_review。 | <code>    )</code> |
| L0958 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0959 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>    conn = open_review_conn(args)</code> |
| L0960 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 process_next_raw_review。 | <code>    try:</code> |
| L0961 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        row = claim_next_review(conn, max_attempts=args.raw_review_max_attempts)</code> |
| L0962 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_next_raw_review。 | <code>        if not row:</code> |
| L0963 | 结束当前函数并把结果返回给调用方，当前位于函数 process_next_raw_review。 | <code>            return None</code> |
| L0964 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0965 | 计算并保存 &#96;event_id&#96;（事件id），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        event_id = str(row.get("event_id") or "")</code> |
| L0966 | 计算并保存 &#96;case_id&#96;（caseid），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        case_id = str(row.get("case_id") or "")</code> |
| L0967 | 计算并保存 &#96;started&#96;（started），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        started = time.perf_counter()</code> |
| L0968 | 计算并保存 &#96;request_text&#96;（requesttext），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        request_text = str(row.get("request_text") or "")</code> |
| L0969 | 计算并保存 &#96;response_text&#96;（responsetext），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        response_text = str(row.get("response_text") or "")</code> |
| L0970 | 计算并保存 &#96;context&#96;（context），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        context = detection_context(row)</code> |
| L0971 | 计算并保存 &#96;case_obj&#96;（caseobj），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        case_obj = {</code> |
| L0972 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            "case_id": case_id,</code> |
| L0973 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            "file_id": row.get("file_id"),</code> |
| L0974 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            "seq_id": row.get("seq_id"),</code> |
| L0975 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            "method": row.get("method"),</code> |
| L0976 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            "uri": row.get("uri"),</code> |
| L0977 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            "host": row.get("host"),</code> |
| L0978 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            "status_code": row.get("status_code"),</code> |
| L0979 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            "source_ip": row.get("source_ip"),</code> |
| L0980 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            "destination_ip": row.get("destination_ip"),</code> |
| L0981 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            "attack_type": row.get("attack_type"),</code> |
| L0982 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            "v2_risk_level": row.get("risk_level"),</code> |
| L0983 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            "export_time": row.get("event_time"),</code> |
| L0984 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            "request_text": request_text,</code> |
| L0985 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            "response_text": response_text,</code> |
| L0986 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            "detection_context": context,</code> |
| L0987 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_next_raw_review。 | <code>        }</code> |
| L0988 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0989 | 计算并保存 &#96;realtime_enabled&#96;（realtimeenabled），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        realtime_enabled = realtime_llm_enabled(conn)</code> |
| L0990 | 源码原注释：Exact port-4000 fingerprints are the deterministic five-second demo | <code>        # Exact port-4000 fingerprints are the deterministic five-second demo</code> |
| L0991 | 源码原注释：path. They never consume an external or local LLM request. | <code>        # path. They never consume an external or local LLM request.</code> |
| L0992 | 计算并保存 &#96;cached&#96;（cached），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        cached = find_cached_review(conn, row)</code> |
| L0993 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_next_raw_review。 | <code>        if cached:</code> |
| L0994 | 源码原注释：Queue creation uses the database server's local clock and is | <code>            # Queue creation uses the database server's local clock and is</code> |
| L0995 | 源码原注释：therefore stable even when packet timestamps arrive as UTC. | <code>            # therefore stable even when packet timestamps arrive as UTC.</code> |
| L0996 | 计算并保存 &#96;ready_at&#96;（readyat），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>            ready_at = _cached_review_ready_at(</code> |
| L0997 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                row.get("review_created_at") or row.get("event_time")</code> |
| L0998 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_next_raw_review。 | <code>            )</code> |
| L0999 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_next_raw_review。 | <code>            if ready_at is not None:</code> |
| L1000 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                current = datetime.now(tz=ready_at.tzinfo) if ready_at.tzinfo is not None else datetime.now()</code> |
| L1001 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_next_raw_review。 | <code>                if current &lt; ready_at:</code> |
| L1002 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                    defer_review(conn, event_id, ready_at)</code> |
| L1003 | 结束当前函数并把结果返回给调用方，当前位于函数 process_next_raw_review。 | <code>                    return f"{event_id}: cached review deferred until {ready_at.isoformat(timespec='milliseconds')}"</code> |
| L1004 | 计算并保存 &#96;analysis&#96;（analysis），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>            analysis = normalize_analysis(</code> |
| L1005 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                dict(cached["analysis"]), case_obj,</code> |
| L1006 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                str(row.get("source_ip") or "unknown"),</code> |
| L1007 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                str(row.get("destination_ip") or "unknown"),</code> |
| L1008 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                str(cached.get("model_name") or args.model),</code> |
| L1009 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_next_raw_review。 | <code>            )</code> |
| L1010 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            analysis["knowledge_references"] = list(analysis.get("knowledge_references") or [])</code> |
| L1011 | 计算并保存 &#96;latency_ms&#96;（latencyms），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>            latency_ms = max(0, int(round((time.perf_counter() - started) * 1000)))</code> |
| L1012 | 计算并保存 &#96;confirmed&#96;（confirmed），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>            confirmed = complete_review(</code> |
| L1013 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                conn, row=row, analysis=analysis,</code> |
| L1014 | 计算并保存 &#96;raw_content&#96;（rawcontent），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                raw_content=json.dumps(analysis, ensure_ascii=False),</code> |
| L1015 | 计算并保存 &#96;model_name&#96;（模型name），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                model_name=str(cached.get("model_name") or args.model),</code> |
| L1016 | 计算并保存 &#96;rag_enabled&#96;（ragenabled），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                rag_enabled=bool(analysis.get("knowledge_references")),</code> |
| L1017 | 计算并保存 &#96;rag_hits&#96;（raghits），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                rag_hits=len(analysis.get("knowledge_references") or []),</code> |
| L1018 | 计算并保存 &#96;latency_ms&#96;（latencyms），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                latency_ms=latency_ms, review_source="verified_cache",</code> |
| L1019 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_next_raw_review。 | <code>            )</code> |
| L1020 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            mark_cache_hit(conn, str(cached["fingerprint"]))</code> |
| L1021 | 结束当前函数并把结果返回给调用方，当前位于函数 process_next_raw_review。 | <code>            return f"{event_id}: done cached=1 published={int(confirmed)} latency_ms={latency_ms}"</code> |
| L1022 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1023 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_next_raw_review。 | <code>        if not realtime_enabled:</code> |
| L1024 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1025 | 计算并保存 &#96;analysis&#96;（analysis），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>            analysis = build_fusion_only_analysis(row, case_obj, context)</code> |
| L1026 | 计算并保存 &#96;latency_ms&#96;（latencyms），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>            latency_ms = max(0, int(round((time.perf_counter() - started) * 1000)))</code> |
| L1027 | 计算并保存 &#96;confirmed&#96;（confirmed），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>            confirmed = complete_review(</code> |
| L1028 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                conn, row=row, analysis=analysis,</code> |
| L1029 | 计算并保存 &#96;raw_content&#96;（rawcontent），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                raw_content=json.dumps(analysis, ensure_ascii=False),</code> |
| L1030 | 计算并保存 &#96;model_name&#96;（模型name），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                model_name="AI多模型融合", rag_enabled=False, rag_hits=0,</code> |
| L1031 | 计算并保存 &#96;latency_ms&#96;（latencyms），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                latency_ms=latency_ms, review_source="fusion_only",</code> |
| L1032 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_next_raw_review。 | <code>            )</code> |
| L1033 | 结束当前函数并把结果返回给调用方，当前位于函数 process_next_raw_review。 | <code>            return f"{event_id}: done fusion_only=1 published={int(confirmed)} latency_ms={latency_ms}"</code> |
| L1034 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1035 | 计算并保存 &#96;rag_rows&#96;（rag数据库记录），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        rag_rows: List[Dict] = []</code> |
| L1036 | 计算并保存 &#96;rag_context&#96;（ragcontext），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        rag_context = ""</code> |
| L1037 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_next_raw_review。 | <code>        if args.rag_enable:</code> |
| L1038 | 计算并保存 &#96;query_text&#96;（querytext），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>            query_text = "\n".join(</code> |
| L1039 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                [</code> |
| L1040 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                    str(row.get("attack_type") or ""),</code> |
| L1041 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                    str(row.get("method") or ""),</code> |
| L1042 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                    str(row.get("uri") or ""),</code> |
| L1043 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                    request_text[:2500],</code> |
| L1044 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                    response_text[:1200],</code> |
| L1045 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                    json.dumps(context, ensure_ascii=False)[:2500],</code> |
| L1046 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_next_raw_review。 | <code>                ]</code> |
| L1047 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_next_raw_review。 | <code>            )</code> |
| L1048 | 计算并保存 &#96;rag_rows&#96;（rag数据库记录），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>            rag_rows = retrieve_advanced_rag(args, query_text=query_text)</code> |
| L1049 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_next_raw_review。 | <code>            if not rag_rows:</code> |
| L1050 | 计算并保存 &#96;rag_rows&#96;（rag数据库记录），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                rag_rows = retrieve_rag_docs(args.rag_db_path, query_text=query_text, top_k=args.rag_top_k)</code> |
| L1051 | 计算并保存 &#96;rag_context&#96;（ragcontext），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>            rag_context = format_rag_context(rag_rows, max_chars=args.rag_max_chars)</code> |
| L1052 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1053 | 计算并保存 &#96;user_payload&#96;（userpayload），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        user_payload = build_user_payload(</code> |
| L1054 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            case_obj,</code> |
| L1055 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            request_text,</code> |
| L1056 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            response_text,</code> |
| L1057 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            str(row.get("source_ip") or "unknown"),</code> |
| L1058 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            str(row.get("destination_ip") or "unknown"),</code> |
| L1059 | 计算并保存 &#96;rag_context&#96;（ragcontext），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>            rag_context=rag_context,</code> |
| L1060 | 计算并保存 &#96;detection_context&#96;（detectioncontext），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>            detection_context=context,</code> |
| L1061 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_next_raw_review。 | <code>        )</code> |
| L1062 | 计算并保存 &#96;review_api_config&#96;（review接口配置），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        review_api_config = getattr(args, "review_api_config_obj", {}) or {}</code> |
| L1063 | 计算并保存 &#96;cloud_enabled&#96;（cloudenabled），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        cloud_enabled = bool(review_api_config.get("api_key") or os.environ.get("LLM_REVIEW_API_KEY"))</code> |
| L1064 | 计算并保存 &#96;models_to_try&#96;（modelstotry），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        models_to_try = [args.model]</code> |
| L1065 | 计算并保存 &#96;fallback_model&#96;（fallback模型），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        fallback_model = str(getattr(args, "fallback_model_resolved", "") or "").strip()</code> |
| L1066 | 计算并保存 &#96;allow_ollama_fallback&#96;（allowollamafallback），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        allow_ollama_fallback = bool(review_api_config.get("fallback_to_ollama", False))</code> |
| L1067 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_next_raw_review。 | <code>        if allow_ollama_fallback and fallback_model and fallback_model not in models_to_try:</code> |
| L1068 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 process_next_raw_review。 | <code>            models_to_try.append(fallback_model)</code> |
| L1069 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1070 | 计算并保存 &#96;last_exc&#96;（lastexc），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        last_exc: Optional[Exception] = None</code> |
| L1071 | 计算并保存 &#96;attempts&#96;（attempts），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>        attempts = ["external"] if cloud_enabled else list(models_to_try)</code> |
| L1072 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_next_raw_review。 | <code>        if cloud_enabled and allow_ollama_fallback:</code> |
| L1073 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 process_next_raw_review。 | <code>            attempts.extend(models_to_try)</code> |
| L1074 | 遍历集合中的数据项并逐项处理，当前位于函数 process_next_raw_review。 | <code>        for idx, attempt_name in enumerate(attempts):</code> |
| L1075 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 process_next_raw_review。 | <code>            try:</code> |
| L1076 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_next_raw_review。 | <code>                if attempt_name == "external":</code> |
| L1077 | 调用外部 HTTP/大模型 API，并等待远端返回结果，当前位于函数 process_next_raw_review。 | <code>                    parsed, raw_content = call_openai_compatible_chat(</code> |
| L1078 | 计算并保存 &#96;config&#96;（配置），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                        config=review_api_config,</code> |
| L1079 | 计算并保存 &#96;system_prompt&#96;（systemprompt），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                        system_prompt=system_prompt,</code> |
| L1080 | 计算并保存 &#96;user_payload&#96;（userpayload），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                        user_payload=user_payload,</code> |
| L1081 | 计算并保存 &#96;schema_obj&#96;（schemaobj），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                        schema_obj=schema_obj,</code> |
| L1082 | 计算并保存 &#96;temperature&#96;（temperature），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                        temperature=args.temperature,</code> |
| L1083 | 计算并保存 &#96;timeout_sec&#96;（timeoutsec），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                        timeout_sec=args.timeout_sec,</code> |
| L1084 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_next_raw_review。 | <code>                    )</code> |
| L1085 | 源码原注释：Public UI keeps the existing product wording and model label. | <code>                    # Public UI keeps the existing product wording and model label.</code> |
| L1086 | 计算并保存 &#96;model_name&#96;（模型name），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                    model_name = str(review_api_config.get("display_model_name") or args.model)</code> |
| L1087 | 处理前述条件均未命中的情况，当前位于函数 process_next_raw_review。 | <code>                else:</code> |
| L1088 | 计算并保存 &#96;model_name&#96;（模型name），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                    model_name = attempt_name</code> |
| L1089 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                    parsed, raw_content = call_ollama_chat(</code> |
| L1090 | 计算并保存 &#96;base_url&#96;（baseurl），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                        base_url=args.ollama_url,</code> |
| L1091 | 计算并保存 &#96;model&#96;（模型），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                        model=model_name,</code> |
| L1092 | 计算并保存 &#96;system_prompt&#96;（systemprompt），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                        system_prompt=system_prompt,</code> |
| L1093 | 计算并保存 &#96;user_payload&#96;（userpayload），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                        user_payload=user_payload,</code> |
| L1094 | 计算并保存 &#96;schema_obj&#96;（schemaobj），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                        schema_obj=schema_obj,</code> |
| L1095 | 计算并保存 &#96;timeout_sec&#96;（timeoutsec），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                        timeout_sec=args.timeout_sec,</code> |
| L1096 | 计算并保存 &#96;num_ctx&#96;（numctx），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                        num_ctx=args.num_ctx,</code> |
| L1097 | 计算并保存 &#96;num_gpu&#96;（numgpu），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                        num_gpu=args.num_gpu,</code> |
| L1098 | 计算并保存 &#96;temperature&#96;（temperature），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                        temperature=args.temperature,</code> |
| L1099 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_next_raw_review。 | <code>                    )</code> |
| L1100 | 计算并保存 &#96;analysis&#96;（analysis），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                analysis = normalize_analysis(</code> |
| L1101 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                    parsed,</code> |
| L1102 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                    case_obj,</code> |
| L1103 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                    str(row.get("source_ip") or "unknown"),</code> |
| L1104 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                    str(row.get("destination_ip") or "unknown"),</code> |
| L1105 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                    model_name,</code> |
| L1106 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_next_raw_review。 | <code>                )</code> |
| L1107 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                analysis["knowledge_references"] = build_rag_references(rag_rows) if args.rag_enable else []</code> |
| L1108 | 计算并保存 &#96;latency_ms&#96;（latencyms），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                latency_ms = max(0, int(round((time.perf_counter() - started) * 1000)))</code> |
| L1109 | 计算并保存 &#96;confirmed&#96;（confirmed），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                confirmed = complete_review(</code> |
| L1110 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                    conn,</code> |
| L1111 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                    row=row,</code> |
| L1112 | 计算并保存 &#96;analysis&#96;（analysis），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                    analysis=analysis,</code> |
| L1113 | 计算并保存 &#96;raw_content&#96;（rawcontent），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                    raw_content=raw_content,</code> |
| L1114 | 计算并保存 &#96;model_name&#96;（模型name），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                    model_name=model_name,</code> |
| L1115 | 计算并保存 &#96;rag_enabled&#96;（ragenabled），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                    rag_enabled=bool(args.rag_enable),</code> |
| L1116 | 计算并保存 &#96;rag_hits&#96;（raghits），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                    rag_hits=len(rag_rows),</code> |
| L1117 | 计算并保存 &#96;latency_ms&#96;（latencyms），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                    latency_ms=latency_ms,</code> |
| L1118 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_next_raw_review。 | <code>                )</code> |
| L1119 | 结束当前函数并把结果返回给调用方，当前位于函数 process_next_raw_review。 | <code>                return (</code> |
| L1120 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                    f"{event_id}: done verdict={analysis.get('verdict')} "</code> |
| L1121 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>                    f"published={int(confirmed)} latency_ms={latency_ms}"</code> |
| L1122 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_next_raw_review。 | <code>                )</code> |
| L1123 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 process_next_raw_review。 | <code>            except Exception as exc:  # noqa: BLE001</code> |
| L1124 | 计算并保存 &#96;last_exc&#96;（lastexc），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>                last_exc = exc</code> |
| L1125 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 process_next_raw_review。 | <code>                if idx &lt; len(attempts) - 1 and should_retry_llm_error(str(exc)):</code> |
| L1126 | 控制当前循环或占位分支的执行流程，当前位于函数 process_next_raw_review。 | <code>                    continue</code> |
| L1127 | 控制当前循环或占位分支的执行流程，当前位于函数 process_next_raw_review。 | <code>                break</code> |
| L1128 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1129 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>        fail_review(</code> |
| L1130 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>            conn,</code> |
| L1131 | 计算并保存 &#96;event_id&#96;（事件id），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>            event_id=event_id,</code> |
| L1132 | 计算并保存 &#96;case_id&#96;（caseid），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>            case_id=case_id,</code> |
| L1133 | 计算并保存 &#96;error&#96;（error），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>            error=str(last_exc or "unknown_error"),</code> |
| L1134 | 计算并保存 &#96;max_attempts&#96;（maxattempts），供后续逻辑使用，当前位于函数 process_next_raw_review。 | <code>            max_attempts=args.raw_review_max_attempts,</code> |
| L1135 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 process_next_raw_review。 | <code>        )</code> |
| L1136 | 结束当前函数并把结果返回给调用方，当前位于函数 process_next_raw_review。 | <code>        return f"{event_id}: failed({last_exc})"</code> |
| L1137 | 无论成功或异常都执行资源清理，当前位于函数 process_next_raw_review。 | <code>    finally:</code> |
| L1138 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 process_next_raw_review。 | <code>        conn.close()</code> |
| L1139 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1140 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1141 | 定义运行rawreviewworker函数 &#96;run_raw_review_worker&#96;，封装可复用业务逻辑。 | <code>def run_raw_review_worker(</code> |
| L1142 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_raw_review_worker。 | <code>    worker_id: int,</code> |
| L1143 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_raw_review_worker。 | <code>    prompt_path: Path,</code> |
| L1144 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_raw_review_worker。 | <code>    fallback_prompt: str,</code> |
| L1145 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_raw_review_worker。 | <code>    schema_obj: Dict,</code> |
| L1146 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_raw_review_worker。 | <code>    args,</code> |
| L1147 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_raw_review_worker。 | <code>    stop_event: threading.Event,</code> |
| L1148 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_raw_review_worker。 | <code>) -&gt; None:</code> |
| L1149 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_raw_review_worker。 | <code>    """Continuously claim RAW jobs; each job owns its own database connection."""</code> |
| L1150 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 run_raw_review_worker。 | <code>    while not stop_event.is_set():</code> |
| L1151 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 run_raw_review_worker。 | <code>        try:</code> |
| L1152 | 计算并保存 &#96;prompt&#96;（prompt），供后续逻辑使用，当前位于函数 run_raw_review_worker。 | <code>            prompt = read_text(prompt_path, fallback_prompt)</code> |
| L1153 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 run_raw_review_worker。 | <code>            if not prompt.strip():</code> |
| L1154 | 计算并保存 &#96;prompt&#96;（prompt），供后续逻辑使用，当前位于函数 run_raw_review_worker。 | <code>                prompt = fallback_prompt</code> |
| L1155 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 run_raw_review_worker。 | <code>            result = process_next_raw_review(prompt, schema_obj, args)</code> |
| L1156 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 run_raw_review_worker。 | <code>            if result:</code> |
| L1157 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 run_raw_review_worker。 | <code>                log(f"review-worker-{worker_id}: {result}")</code> |
| L1158 | 控制当前循环或占位分支的执行流程，当前位于函数 run_raw_review_worker。 | <code>                continue</code> |
| L1159 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 run_raw_review_worker。 | <code>        except Exception as exc:  # noqa: BLE001</code> |
| L1160 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 run_raw_review_worker。 | <code>            log(f"review-worker-{worker_id}: cycle failed: {exc}")</code> |
| L1161 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_raw_review_worker。 | <code>        wait_event(LLM_READY_EVENT, max(1, min(2, int(args.poll_seconds))))</code> |
| L1162 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1163 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1164 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; None:</code> |
| L1165 | 计算并保存 &#96;project_root&#96;（projectroot），供后续逻辑使用，当前位于函数 main。 | <code>    project_root = Path(__file__).resolve().parent.parent</code> |
| L1166 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1167 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="监听 result/b.n 并自动调用本地大模型分析（不重复处理）")</code> |
| L1168 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--result-dir", default="result", help="result 根目录")</code> |
| L1169 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--input-dir", default="input", help="input 根目录，用于回查 source_ip/destination_ip")</code> |
| L1170 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--model", default="qwen3:8b", help="Ollama 模型名")</code> |
| L1171 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434", help="Ollama 服务地址")</code> |
| L1172 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--prompt", default="llm/prompts/system_prompt.txt", help="系统提示词文件")</code> |
| L1173 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--schema", default="llm/schemas/analysis.schema.json", help="输出 JSON schema 文件")</code> |
| L1174 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--poll-seconds", type=int, default=5)</code> |
| L1175 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--timeout-sec", type=int, default=300)</code> |
| L1176 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--num-ctx", type=int, default=6144)</code> |
| L1177 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--num-gpu", type=int, default=0, help="0=CPU 更稳；设大于0可尝试GPU")</code> |
| L1178 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--temperature", type=float, default=0.2)</code> |
| L1179 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--once", action="store_true", help="仅扫描一次并处理后退出")</code> |
| L1180 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--max-cases", type=int, default=0, help="每轮最多处理多少条，0=不限制")</code> |
| L1181 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument(</code> |
| L1182 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--legacy-result-review",</code> |
| L1183 | 计算并保存 &#96;action&#96;（action），供后续逻辑使用，当前位于函数 main。 | <code>        action="store_true",</code> |
| L1184 | 计算并保存 &#96;help&#96;（help），供后续逻辑使用，当前位于函数 main。 | <code>        help="兼容处理历史 result/b.* 队列；默认关闭以保证 RAW 实时候选优先",</code> |
| L1185 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L1186 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--fallback-model", default="", help="主模型失败时的回退模型，留空则自动选择已安装的其他模型")</code> |
| L1187 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument(</code> |
| L1188 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--processing-timeout-sec",</code> |
| L1189 | 计算并保存 &#96;type&#96;（type），供后续逻辑使用，当前位于函数 main。 | <code>        type=int,</code> |
| L1190 | 计算并保存 &#96;default&#96;（default），供后续逻辑使用，当前位于函数 main。 | <code>        default=180,</code> |
| L1191 | 计算并保存 &#96;help&#96;（help），供后续逻辑使用，当前位于函数 main。 | <code>        help="case 长时间停留 processing 的超时秒数，超时后自动重置为 pending",</code> |
| L1192 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L1193 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-enable", dest="rag_enable", action="store_true", help="启用 RAG 检索增强")</code> |
| L1194 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--no-rag", dest="rag_enable", action="store_false", help="关闭 RAG 检索增强")</code> |
| L1195 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    parser.set_defaults(rag_enable=True)</code> |
| L1196 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-db-path", default="llm/rag/rag_knowledge.db", help="RAG sqlite db 文件路径")</code> |
| L1197 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-seed-file", default="llm/rag/rag_seed.json", help="RAG seed JSON 文件路径")</code> |
| L1198 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-data-dir", default="D:/JingyuanTrafficPipelineData/rag", help="高级 RAG 向量与上传目录")</code> |
| L1199 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-api-config", default="config/ai_api.local.json", help="百炼 API 本地配置")</code> |
| L1200 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument(</code> |
| L1201 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--review-api-config",</code> |
| L1202 | 计算并保存 &#96;default&#96;（default），供后续逻辑使用，当前位于函数 main。 | <code>        default="config/llm_review_api.local.json",</code> |
| L1203 | 调用外部 HTTP/大模型 API，并等待远端返回结果，当前位于函数 main。 | <code>        help="OpenAI 兼容的最终研判 API 私密配置",</code> |
| L1204 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L1205 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--review-workers", type=int, default=8, help="RAW 最终研判并发工作线程数")</code> |
| L1206 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-mysql-host", default="127.0.0.1")</code> |
| L1207 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-mysql-port", type=int, default=3306)</code> |
| L1208 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-mysql-user", default="root")</code> |
| L1209 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-mysql-password", default="123456")</code> |
| L1210 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-mysql-database", default="traffic_pipeline")</code> |
| L1211 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--raw-review-max-attempts", type=int, default=3)</code> |
| L1212 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-top-k", type=int, default=3, help="RAG 每次检索条数")</code> |
| L1213 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-max-chars", type=int, default=3200, help="注入 LLM 的 RAG 上下文最大字符数")</code> |
| L1214 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-auto-build", dest="rag_auto_build", action="store_true", help="若 RAG db 不存在则自动构建")</code> |
| L1215 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--no-rag-auto-build", dest="rag_auto_build", action="store_false", help="不自动构建 RAG db")</code> |
| L1216 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    parser.set_defaults(rag_auto_build=True)</code> |
| L1217 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L1218 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1219 | 计算并保存 &#96;result_dir&#96;（结果dir），供后续逻辑使用，当前位于函数 main。 | <code>    result_dir = (project_root / args.result_dir).resolve()</code> |
| L1220 | 计算并保存 &#96;input_dir&#96;（inputdir），供后续逻辑使用，当前位于函数 main。 | <code>    input_dir = (project_root / args.input_dir).resolve()</code> |
| L1221 | 计算并保存 &#96;prompt_path&#96;（promptpath），供后续逻辑使用，当前位于函数 main。 | <code>    prompt_path = (project_root / args.prompt).resolve()</code> |
| L1222 | 计算并保存 &#96;schema_path&#96;（schemapath），供后续逻辑使用，当前位于函数 main。 | <code>    schema_path = (project_root / args.schema).resolve()</code> |
| L1223 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    args.rag_db_path = (project_root / args.rag_db_path).resolve()</code> |
| L1224 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    args.rag_seed_file = (project_root / args.rag_seed_file).resolve()</code> |
| L1225 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    args.rag_data_dir = Path(args.rag_data_dir).resolve()</code> |
| L1226 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    args.rag_api_config = (project_root / args.rag_api_config).resolve()</code> |
| L1227 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    args.review_api_config = (project_root / args.review_api_config).resolve()</code> |
| L1228 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    args.review_api_config_obj = load_review_api_config(args.review_api_config)</code> |
| L1229 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    args.review_workers = max(1, min(16, int(args.review_workers)))</code> |
| L1230 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1231 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    result_dir.mkdir(parents=True, exist_ok=True)</code> |
| L1232 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    input_dir.mkdir(parents=True, exist_ok=True)</code> |
| L1233 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1234 | 计算并保存 &#96;system_prompt&#96;（systemprompt），供后续逻辑使用，当前位于函数 main。 | <code>    system_prompt = read_text(prompt_path)</code> |
| L1235 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if not system_prompt.strip():</code> |
| L1236 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 main。 | <code>        raise RuntimeError(f"prompt 为空: {prompt_path}")</code> |
| L1237 | 计算并保存 &#96;prompt_mtime&#96;（promptmtime），供后续逻辑使用，当前位于函数 main。 | <code>    prompt_mtime = prompt_path.stat().st_mtime if prompt_path.exists() else 0.0</code> |
| L1238 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1239 | 计算并保存 &#96;schema_obj&#96;（schemaobj），供后续逻辑使用，当前位于函数 main。 | <code>    schema_obj = read_json(schema_path, default={})</code> |
| L1240 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if not schema_obj:</code> |
| L1241 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 main。 | <code>        raise RuntimeError(f"schema 无效: {schema_path}")</code> |
| L1242 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1243 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if args.rag_enable:</code> |
| L1244 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        ensure_rag_db(args.rag_db_path, args.rag_seed_file, auto_build=args.rag_auto_build)</code> |
| L1245 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        log(f"RAG enabled db={args.rag_db_path} top_k={args.rag_top_k}")</code> |
| L1246 | 处理前述条件均未命中的情况，当前位于函数 main。 | <code>    else:</code> |
| L1247 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        log("RAG disabled")</code> |
| L1248 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1249 | 计算并保存 &#96;cloud_review_enabled&#96;（cloudreviewenabled），供后续逻辑使用，当前位于函数 main。 | <code>    cloud_review_enabled = bool(</code> |
| L1250 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        args.review_api_config_obj.get("api_key") or os.environ.get("LLM_REVIEW_API_KEY")</code> |
| L1251 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L1252 | 计算并保存 &#96;installed_models&#96;（installedmodels），供后续逻辑使用，当前位于函数 main。 | <code>    installed_models: List[str] = []</code> |
| L1253 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if cloud_review_enabled:</code> |
| L1254 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        log(</code> |
| L1255 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "external final review enabled "</code> |
| L1256 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            f"model={args.review_api_config_obj.get('model') or 'configured'} workers={args.review_workers}"</code> |
| L1257 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        )</code> |
| L1258 | 处理前述条件均未命中的情况，当前位于函数 main。 | <code>    else:</code> |
| L1259 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        args.model = resolve_model_name(args.ollama_url, args.model, timeout_sec=10)</code> |
| L1260 | 计算并保存 &#96;installed_models&#96;（installedmodels），供后续逻辑使用，当前位于函数 main。 | <code>        installed_models = fetch_available_models(base_url=args.ollama_url, timeout_sec=10)</code> |
| L1261 | 计算并保存 &#96;fallback_model&#96;（fallback模型），供后续逻辑使用，当前位于函数 main。 | <code>    fallback_model = str(args.fallback_model or "").strip()</code> |
| L1262 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if fallback_model and fallback_model not in installed_models:</code> |
| L1263 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        log(f"configured fallback model '{fallback_model}' not found, ignore fallback")</code> |
| L1264 | 计算并保存 &#96;fallback_model&#96;（fallback模型），供后续逻辑使用，当前位于函数 main。 | <code>        fallback_model = ""</code> |
| L1265 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if not fallback_model:</code> |
| L1266 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>        for m in installed_models:</code> |
| L1267 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if m != args.model:</code> |
| L1268 | 计算并保存 &#96;fallback_model&#96;（fallback模型），供后续逻辑使用，当前位于函数 main。 | <code>                fallback_model = m</code> |
| L1269 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                break</code> |
| L1270 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    args.fallback_model_resolved = fallback_model</code> |
| L1271 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if args.fallback_model_resolved:</code> |
| L1272 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        log(f"fallback model enabled: {args.fallback_model_resolved}")</code> |
| L1273 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    log(f"LLM daemon started model={args.model} url={args.ollama_url}")</code> |
| L1274 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    log(f"result_dir={result_dir}")</code> |
| L1275 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if not cloud_review_enabled or bool(args.review_api_config_obj.get("fallback_to_ollama", False)):</code> |
| L1276 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>        try:</code> |
| L1277 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            warm_ollama_model(args.ollama_url, args.model, timeout_sec=min(90, args.timeout_sec))</code> |
| L1278 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>            log(f"LLM model warmed and kept alive: {args.model}")</code> |
| L1279 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>        except Exception as exc:</code> |
| L1280 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>            log(f"LLM warmup skipped: {exc}")</code> |
| L1281 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1282 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>    try:</code> |
| L1283 | 计算并保存 &#96;review_conn&#96;（reviewconn），供后续逻辑使用，当前位于函数 main。 | <code>        review_conn = open_review_conn(args)</code> |
| L1284 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>        try:</code> |
| L1285 | 导入后续逻辑所需的模块、类或函数：&#96;from raw_llm_review import ensure_review_schema&#96;。 | <code>            from raw_llm_review import ensure_review_schema</code> |
| L1286 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1287 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            ensure_review_schema(review_conn)</code> |
| L1288 | 无论成功或异常都执行资源清理，当前位于函数 main。 | <code>        finally:</code> |
| L1289 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            review_conn.close()</code> |
| L1290 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        log("RAW LLM review queue enabled")</code> |
| L1291 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>    except Exception as exc:</code> |
| L1292 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        log(f"RAW LLM review queue unavailable: {exc}")</code> |
| L1293 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1294 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if not args.once and not args.legacy_result_review and args.review_workers &gt; 1:</code> |
| L1295 | 计算并保存 &#96;stop_event&#96;（停止事件），供后续逻辑使用，当前位于函数 main。 | <code>        stop_event = threading.Event()</code> |
| L1296 | 计算并保存 &#96;executor&#96;（executor），供后续逻辑使用，当前位于函数 main。 | <code>        executor = concurrent.futures.ThreadPoolExecutor(</code> |
| L1297 | 计算并保存 &#96;max_workers&#96;（maxworkers），供后续逻辑使用，当前位于函数 main。 | <code>            max_workers=args.review_workers,</code> |
| L1298 | 计算并保存 &#96;thread_name_prefix&#96;（threadnameprefix），供后续逻辑使用，当前位于函数 main。 | <code>            thread_name_prefix="raw-review",</code> |
| L1299 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        )</code> |
| L1300 | 计算并保存 &#96;futures&#96;（futures），供后续逻辑使用，当前位于函数 main。 | <code>        futures = [</code> |
| L1301 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            executor.submit(</code> |
| L1302 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                run_raw_review_worker,</code> |
| L1303 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                worker_id,</code> |
| L1304 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                prompt_path,</code> |
| L1305 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                system_prompt,</code> |
| L1306 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                schema_obj,</code> |
| L1307 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                args,</code> |
| L1308 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                stop_event,</code> |
| L1309 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>            )</code> |
| L1310 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>            for worker_id in range(1, args.review_workers + 1)</code> |
| L1311 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        ]</code> |
| L1312 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        log(f"RAW review worker pool started workers={args.review_workers}")</code> |
| L1313 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>        try:</code> |
| L1314 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 main。 | <code>            while True:</code> |
| L1315 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>                for future in futures:</code> |
| L1316 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                    if future.done():</code> |
| L1317 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                        future.result()</code> |
| L1318 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                time.sleep(1)</code> |
| L1319 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>        except KeyboardInterrupt:</code> |
| L1320 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            stop_event.set()</code> |
| L1321 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            executor.shutdown(wait=True, cancel_futures=True)</code> |
| L1322 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>            log("RAW review worker pool stopped")</code> |
| L1323 | 结束当前函数并把结果返回给调用方，当前位于函数 main。 | <code>        return</code> |
| L1324 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1325 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 main。 | <code>    while True:</code> |
| L1326 | 计算并保存 &#96;processed&#96;（processed），供后续逻辑使用，当前位于函数 main。 | <code>        processed = 0</code> |
| L1327 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>        try:</code> |
| L1328 | 计算并保存 &#96;current_prompt_mtime&#96;（currentpromptmtime），供后续逻辑使用，当前位于函数 main。 | <code>            current_prompt_mtime = prompt_path.stat().st_mtime if prompt_path.exists() else 0.0</code> |
| L1329 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if current_prompt_mtime != prompt_mtime:</code> |
| L1330 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                system_prompt, prompt_mtime = load_system_prompt(prompt_path)</code> |
| L1331 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                log(f"prompt reloaded: {prompt_path}")</code> |
| L1332 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>        except Exception as exc:</code> |
| L1333 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>            log(f"prompt reload skipped: {exc}")</code> |
| L1334 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1335 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>        try:</code> |
| L1336 | 计算并保存 &#96;raw_result&#96;（raw结果），供后续逻辑使用，当前位于函数 main。 | <code>            raw_result = process_next_raw_review(system_prompt, schema_obj, args)</code> |
| L1337 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>        except Exception as exc:</code> |
| L1338 | 计算并保存 &#96;raw_result&#96;（raw结果），供后续逻辑使用，当前位于函数 main。 | <code>            raw_result = None</code> |
| L1339 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>            log(f"RAW LLM review cycle failed: {exc}")</code> |
| L1340 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if raw_result:</code> |
| L1341 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            processed += 1</code> |
| L1342 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>            log(raw_result)</code> |
| L1343 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if args.once:</code> |
| L1344 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                log(f"once done processed={processed}")</code> |
| L1345 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                break</code> |
| L1346 | 源码原注释：Prioritize new suspicious traffic instead of waiting behind the | <code>            # Prioritize new suspicious traffic instead of waiting behind the</code> |
| L1347 | 源码原注释：historical result/b.* retry backlog. | <code>            # historical result/b.* retry backlog.</code> |
| L1348 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>            continue</code> |
| L1349 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1350 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if not args.legacy_result_review:</code> |
| L1351 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if args.once:</code> |
| L1352 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                log(f"once done processed={processed}")</code> |
| L1353 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                break</code> |
| L1354 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            wait_event(LLM_READY_EVENT, max(1, args.poll_seconds))</code> |
| L1355 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>            continue</code> |
| L1356 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1357 | 计算并保存 &#96;case_dirs&#96;（casedirs），供后续逻辑使用，当前位于函数 main。 | <code>        case_dirs = find_case_dirs(result_dir)</code> |
| L1358 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1359 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>        for case_dir in case_dirs:</code> |
| L1360 | 计算并保存 &#96;case_obj&#96;（caseobj），供后续逻辑使用，当前位于函数 main。 | <code>            case_obj = read_json(case_dir / "case.json", default={})</code> |
| L1361 | 计算并保存 &#96;llm_status&#96;（llm状态），供后续逻辑使用，当前位于函数 main。 | <code>            llm_status = str(case_obj.get("llm_status") or "pending").lower()</code> |
| L1362 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1363 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if llm_status == "processing":</code> |
| L1364 | 计算并保存 &#96;started_at&#96;（startedat），供后续逻辑使用，当前位于函数 main。 | <code>                started_at = str(case_obj.get("llm_started_at") or "").strip()</code> |
| L1365 | 计算并保存 &#96;stale&#96;（stale），供后续逻辑使用，当前位于函数 main。 | <code>                stale = False</code> |
| L1366 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if started_at:</code> |
| L1367 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>                    try:</code> |
| L1368 | 计算并保存 &#96;elapsed&#96;（elapsed），供后续逻辑使用，当前位于函数 main。 | <code>                        elapsed = time.time() - datetime.fromisoformat(started_at).timestamp()</code> |
| L1369 | 计算并保存 &#96;stale&#96;（stale），供后续逻辑使用，当前位于函数 main。 | <code>                        stale = elapsed &gt;= max(30, int(args.processing_timeout_sec))</code> |
| L1370 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>                    except Exception:</code> |
| L1371 | 计算并保存 &#96;stale&#96;（stale），供后续逻辑使用，当前位于函数 main。 | <code>                        stale = True</code> |
| L1372 | 处理前述条件均未命中的情况，当前位于函数 main。 | <code>                else:</code> |
| L1373 | 计算并保存 &#96;stale&#96;（stale），供后续逻辑使用，当前位于函数 main。 | <code>                    stale = True</code> |
| L1374 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1375 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if stale:</code> |
| L1376 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    case_obj["llm_status"] = "pending"</code> |
| L1377 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    case_obj["llm_recovered_at"] = now_iso()</code> |
| L1378 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    write_json(case_dir / "case.json", case_obj)</code> |
| L1379 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                    log(f"{case_dir.name}: stale processing recovered -&gt; pending")</code> |
| L1380 | 计算并保存 &#96;llm_status&#96;（llm状态），供后续逻辑使用，当前位于函数 main。 | <code>                    llm_status = "pending"</code> |
| L1381 | 处理前述条件均未命中的情况，当前位于函数 main。 | <code>                else:</code> |
| L1382 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                    continue</code> |
| L1383 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1384 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if llm_status not in ("pending", "failed"):</code> |
| L1385 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                continue</code> |
| L1386 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1387 | 计算并保存 &#96;ret&#96;（ret），供后续逻辑使用，当前位于函数 main。 | <code>            ret = process_case(case_dir, input_dir, system_prompt, schema_obj, args)</code> |
| L1388 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if not ret.startswith("skip"):</code> |
| L1389 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                processed += 1</code> |
| L1390 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                log(f"{case_dir.name}: {ret}")</code> |
| L1391 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1392 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if args.max_cases &gt; 0 and processed &gt;= args.max_cases:</code> |
| L1393 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                break</code> |
| L1394 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1395 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if args.once:</code> |
| L1396 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>            log(f"once done processed={processed}")</code> |
| L1397 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>            break</code> |
| L1398 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1399 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        wait_event(LLM_READY_EVENT, max(args.poll_seconds, 1))</code> |
| L1400 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1401 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1402 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L1403 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
