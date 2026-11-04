# `scripts/real_capture_threshold_compare.py` 逐行注释

**脚本用途：** 使用真实抓包数据比较阈值效果。

**源码行数：** 387　**函数/类数量：** 11

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0002 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import random&#96;。 | <code>import random</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import re&#96;。 | <code>import re</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import subprocess&#96;。 | <code>import subprocess</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;import sys&#96;。 | <code>import sys</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;import time&#96;。 | <code>import time</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;from dataclasses import dataclass&#96;。 | <code>from dataclasses import dataclass</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime&#96;。 | <code>from datetime import datetime</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;from http.client import HTTPConnection&#96;。 | <code>from http.client import HTTPConnection</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0012 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, List, Tuple&#96;。 | <code>from typing import Any, Dict, List, Tuple</code> |
| L0013 | 导入后续逻辑所需的模块、类或函数：&#96;from urllib.parse import quote_plus&#96;。 | <code>from urllib.parse import quote_plus</code> |
| L0014 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0015 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0016 | 应用装饰器 &#96;@dataclass&#96;，为下一定义附加权限、缓存或注册行为。 | <code>@dataclass</code> |
| L0017 | 定义类 &#96;CaseTemplate&#96;，集中保存相关状态与操作。 | <code>class CaseTemplate:</code> |
| L0018 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 CaseTemplate。 | <code>    name: str</code> |
| L0019 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 CaseTemplate。 | <code>    method: str</code> |
| L0020 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 CaseTemplate。 | <code>    uri: str</code> |
| L0021 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于类 CaseTemplate。 | <code>    body: str = ""</code> |
| L0022 | 计算并保存 &#96;content_type&#96;（contenttype），供后续逻辑使用，当前位于类 CaseTemplate。 | <code>    content_type: str = ""</code> |
| L0023 | 计算并保存 &#96;is_attack&#96;（is攻击），供后续逻辑使用，当前位于类 CaseTemplate。 | <code>    is_attack: int = 0</code> |
| L0024 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0025 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0026 | 定义appendtrace函数 &#96;append_trace&#96;，封装可复用业务逻辑。 | <code>def append_trace(uri: str, trace_value: str) -&gt; str:</code> |
| L0027 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 append_trace。 | <code>    if "?" in uri:</code> |
| L0028 | 结束当前函数并把结果返回给调用方，当前位于函数 append_trace。 | <code>        return f"{uri}&amp;trace={trace_value}"</code> |
| L0029 | 结束当前函数并把结果返回给调用方，当前位于函数 append_trace。 | <code>    return f"{uri}?trace={trace_value}"</code> |
| L0030 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0031 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0032 | 定义default攻击templates函数 &#96;default_attack_templates&#96;，封装可复用业务逻辑。 | <code>def default_attack_templates() -&gt; List[CaseTemplate]:</code> |
| L0033 | 结束当前函数并把结果返回给调用方，当前位于函数 default_attack_templates。 | <code>    return [</code> |
| L0034 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("sqli_or", "POST", "/api/auth/login", '{"username":"admin","password":"\' OR 1=1 -- "}', "application/json", 1),</code> |
| L0035 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("sqli_union", "POST", "/api/auth/login", '{"username":"admin\' UNION SELECT 1,2,3 -- ","password":"x"}', "application/json", 1),</code> |
| L0036 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("xss_script", "GET", "/api/search?q=" + quote_plus("&lt;script&gt;alert(1)&lt;/script&gt;"), "", "", 1),</code> |
| L0037 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("xss_onerror", "POST", "/api/comment", '{"author":"a","content":"&lt;img src=x onerror=alert(1)&gt;"}', "application/json", 1),</code> |
| L0038 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("traversal_linux", "GET", "/api/file/read?path=" + quote_plus("../../../../etc/passwd"), "", "", 1),</code> |
| L0039 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("traversal_win", "GET", "/api/file/read?path=" + quote_plus("..\\..\\..\\Windows\\win.ini"), "", "", 1),</code> |
| L0040 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("cmdi", "POST", "/api/system/ping", '{"host":"8.8.8.8 &amp;&amp; whoami"}', "application/json", 1),</code> |
| L0041 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("ssrf", "GET", "/api/fetch?url=" + quote_plus("http://169.254.169.254/latest/meta-data"), "", "", 1),</code> |
| L0042 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("ssti", "POST", "/api/template/render", '{"template":"{{7*7}}"}', "application/json", 1),</code> |
| L0043 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("xxe", "POST", "/api/xml/import", '&lt;?xml version="1.0"?&gt;&lt;!DOCTYPE x [&lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;]&gt;&lt;x&gt;&amp;xxe;&lt;/x&gt;', "application/xml", 1),</code> |
| L0044 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("graphql_inj", "POST", "/api/graphql", '{"query":"{user(id:\\"1 OR 1=1\\"){id}}"}', "application/json", 1),</code> |
| L0045 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("rce_eval", "POST", "/api/eval", '{"code":"__import__(\\"os\\").system(\\"id\\")"}', "application/json", 1),</code> |
| L0046 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 default_attack_templates。 | <code>    ]</code> |
| L0047 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0048 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0049 | 定义defaultbenigntemplates函数 &#96;default_benign_templates&#96;，封装可复用业务逻辑。 | <code>def default_benign_templates() -&gt; List[CaseTemplate]:</code> |
| L0050 | 结束当前函数并把结果返回给调用方，当前位于函数 default_benign_templates。 | <code>    return [</code> |
| L0051 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("home", "GET", "/", "", "", 0),</code> |
| L0052 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("health", "GET", "/health", "", "", 0),</code> |
| L0053 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("products", "GET", "/api/products", "", "", 0),</code> |
| L0054 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("news", "GET", "/api/news", "", "", 0),</code> |
| L0055 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("search_normal", "GET", "/api/search?q=" + quote_plus("security monitor"), "", "", 0),</code> |
| L0056 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("login_ok", "POST", "/api/auth/login", '{"username":"admin","password":"admin"}', "application/json", 0),</code> |
| L0057 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("comment", "POST", "/api/comment", '{"author":"alice","content":"hello"}', "application/json", 0),</code> |
| L0058 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("file_safe", "GET", "/api/file/read?path=" + quote_plus("notes/todo.txt"), "", "", 0),</code> |
| L0059 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("ping_safe", "POST", "/api/system/ping", '{"host":"8.8.8.8"}', "application/json", 0),</code> |
| L0060 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("fetch_safe", "GET", "/api/fetch?url=" + quote_plus("https://example.com"), "", "", 0),</code> |
| L0061 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("xml_safe", "POST", "/api/xml/import", '&lt;?xml version="1.0"?&gt;&lt;root&gt;&lt;x&gt;ok&lt;/x&gt;&lt;/root&gt;', "application/xml", 0),</code> |
| L0062 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("graphql_safe", "POST", "/api/graphql", '{"query":"{viewer{id name}}"}', "application/json", 0),</code> |
| L0063 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 default_benign_templates。 | <code>    ]</code> |
| L0064 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0065 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0066 | 定义sendhttp函数 &#96;send_http&#96;，封装可复用业务逻辑。 | <code>def send_http(host: str, port: int, method: str, uri: str, body: str, content_type: str) -&gt; Tuple[int, str]:</code> |
| L0067 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 send_http。 | <code>    conn = HTTPConnection(host, port, timeout=8)</code> |
| L0068 | 计算并保存 &#96;status&#96;（状态），供后续逻辑使用，当前位于函数 send_http。 | <code>    status = 599</code> |
| L0069 | 计算并保存 &#96;reason&#96;（reason），供后续逻辑使用，当前位于函数 send_http。 | <code>    reason = "client_error"</code> |
| L0070 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 send_http。 | <code>    try:</code> |
| L0071 | 计算并保存 &#96;headers&#96;（headers），供后续逻辑使用，当前位于函数 send_http。 | <code>        headers = {"Host": "ctf.ski:3000", "User-Agent": "real-capture-threshold-compare/1.0"}</code> |
| L0072 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 send_http。 | <code>        if content_type:</code> |
| L0073 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 send_http。 | <code>            headers["Content-Type"] = content_type</code> |
| L0074 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 send_http。 | <code>        payload = body.encode("utf-8") if body else None</code> |
| L0075 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 send_http。 | <code>        conn.request(method=method, url=uri, body=payload, headers=headers)</code> |
| L0076 | 计算并保存 &#96;resp&#96;（resp），供后续逻辑使用，当前位于函数 send_http。 | <code>        resp = conn.getresponse()</code> |
| L0077 | 计算并保存 &#96;status&#96;（状态），供后续逻辑使用，当前位于函数 send_http。 | <code>        status = int(resp.status)</code> |
| L0078 | 计算并保存 &#96;reason&#96;（reason），供后续逻辑使用，当前位于函数 send_http。 | <code>        reason = str(resp.reason or "")</code> |
| L0079 | 计算并保存 &#96;_&#96;（_），供后续逻辑使用，当前位于函数 send_http。 | <code>        _ = resp.read(256)</code> |
| L0080 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 send_http。 | <code>    except Exception as exc:  # noqa: BLE001</code> |
| L0081 | 计算并保存 &#96;reason&#96;（reason），供后续逻辑使用，当前位于函数 send_http。 | <code>        reason = str(exc)</code> |
| L0082 | 无论成功或异常都执行资源清理，当前位于函数 send_http。 | <code>    finally:</code> |
| L0083 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 send_http。 | <code>        try:</code> |
| L0084 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 send_http。 | <code>            conn.close()</code> |
| L0085 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 send_http。 | <code>        except Exception:</code> |
| L0086 | 控制当前循环或占位分支的执行流程，当前位于函数 send_http。 | <code>            pass</code> |
| L0087 | 结束当前函数并把结果返回给调用方，当前位于函数 send_http。 | <code>    return status, reason</code> |
| L0088 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0089 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0090 | 定义calcmetrics函数 &#96;calc_metrics&#96;，封装可复用业务逻辑。 | <code>def calc_metrics(rows: List[Dict[str, Any]], threshold: float) -&gt; Dict[str, Any]:</code> |
| L0091 | 计算并保存 &#96;tp&#96;（tp），供后续逻辑使用，当前位于函数 calc_metrics。 | <code>    tp = fp = tn = fn = 0</code> |
| L0092 | 遍历集合中的数据项并逐项处理，当前位于函数 calc_metrics。 | <code>    for row in rows:</code> |
| L0093 | 计算并保存 &#96;pred&#96;（pred），供后续逻辑使用，当前位于函数 calc_metrics。 | <code>        pred = 1 if float(row["score"]) &gt;= threshold else 0</code> |
| L0094 | 计算并保存 &#96;y&#96;（y），供后续逻辑使用，当前位于函数 calc_metrics。 | <code>        y = int(row["is_attack"])</code> |
| L0095 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 calc_metrics。 | <code>        if pred == 1 and y == 1:</code> |
| L0096 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>            tp += 1</code> |
| L0097 | 当前一条件未命中时继续判断另一条件，当前位于函数 calc_metrics。 | <code>        elif pred == 1 and y == 0:</code> |
| L0098 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>            fp += 1</code> |
| L0099 | 当前一条件未命中时继续判断另一条件，当前位于函数 calc_metrics。 | <code>        elif pred == 0 and y == 0:</code> |
| L0100 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>            tn += 1</code> |
| L0101 | 处理前述条件均未命中的情况，当前位于函数 calc_metrics。 | <code>        else:</code> |
| L0102 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>            fn += 1</code> |
| L0103 | 计算并保存 &#96;total&#96;（total），供后续逻辑使用，当前位于函数 calc_metrics。 | <code>    total = tp + fp + tn + fn</code> |
| L0104 | 计算并保存 &#96;precision&#96;（precision），供后续逻辑使用，当前位于函数 calc_metrics。 | <code>    precision = tp / (tp + fp) if (tp + fp) else 0.0</code> |
| L0105 | 计算并保存 &#96;recall&#96;（recall），供后续逻辑使用，当前位于函数 calc_metrics。 | <code>    recall = tp / (tp + fn) if (tp + fn) else 0.0</code> |
| L0106 | 计算并保存 &#96;f1&#96;（f1），供后续逻辑使用，当前位于函数 calc_metrics。 | <code>    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0</code> |
| L0107 | 计算并保存 &#96;accuracy&#96;（accuracy），供后续逻辑使用，当前位于函数 calc_metrics。 | <code>    accuracy = (tp + tn) / total if total else 0.0</code> |
| L0108 | 计算并保存 &#96;fpr&#96;（fpr），供后续逻辑使用，当前位于函数 calc_metrics。 | <code>    fpr = fp / (fp + tn) if (fp + tn) else 0.0</code> |
| L0109 | 结束当前函数并把结果返回给调用方，当前位于函数 calc_metrics。 | <code>    return {</code> |
| L0110 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "threshold": round(float(threshold), 4),</code> |
| L0111 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "tp": tp,</code> |
| L0112 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "fp": fp,</code> |
| L0113 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "tn": tn,</code> |
| L0114 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "fn": fn,</code> |
| L0115 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "precision": round(precision, 6),</code> |
| L0116 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "recall": round(recall, 6),</code> |
| L0117 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "f1": round(f1, 6),</code> |
| L0118 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "accuracy": round(accuracy, 6),</code> |
| L0119 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "fpr": round(fpr, 6),</code> |
| L0120 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "sample_count": total,</code> |
| L0121 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 calc_metrics。 | <code>    }</code> |
| L0122 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0123 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0124 | 定义解析thresholds函数 &#96;parse_thresholds&#96;，封装可复用业务逻辑。 | <code>def parse_thresholds(text: str) -&gt; List[float]:</code> |
| L0125 | 计算并保存 &#96;out&#96;（out），供后续逻辑使用，当前位于函数 parse_thresholds。 | <code>    out: List[float] = []</code> |
| L0126 | 遍历集合中的数据项并逐项处理，当前位于函数 parse_thresholds。 | <code>    for token in re.split(r"[\s,]+", (text or "").strip()):</code> |
| L0127 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_thresholds。 | <code>        if not token:</code> |
| L0128 | 控制当前循环或占位分支的执行流程，当前位于函数 parse_thresholds。 | <code>            continue</code> |
| L0129 | 计算并保存 &#96;v&#96;（v），供后续逻辑使用，当前位于函数 parse_thresholds。 | <code>        v = float(token)</code> |
| L0130 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_thresholds。 | <code>        if v &lt; 0 or v &gt; 1:</code> |
| L0131 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 parse_thresholds。 | <code>            raise ValueError(f"invalid threshold: {v}")</code> |
| L0132 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 parse_thresholds。 | <code>        out.append(v)</code> |
| L0133 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_thresholds。 | <code>    if not out:</code> |
| L0134 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 parse_thresholds。 | <code>        raise ValueError("empty thresholds")</code> |
| L0135 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_thresholds。 | <code>    return out</code> |
| L0136 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0137 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0138 | 定义解析并确定default模型paths函数 &#96;resolve_default_model_paths&#96;，封装可复用业务逻辑。 | <code>def resolve_default_model_paths(project_root: Path) -&gt; Tuple[Path, Path]:</code> |
| L0139 | 计算并保存 &#96;local_models&#96;（localmodels），供后续逻辑使用，当前位于函数 resolve_default_model_paths。 | <code>    local_models = project_root / "models"</code> |
| L0140 | 计算并保存 &#96;local_pre&#96;（localpre），供后续逻辑使用，当前位于函数 resolve_default_model_paths。 | <code>    local_pre = local_models / "preprocessor.joblib"</code> |
| L0141 | 计算并保存 &#96;local_mdl&#96;（localmdl），供后续逻辑使用，当前位于函数 resolve_default_model_paths。 | <code>    local_mdl = local_models / "best_mlp.pth"</code> |
| L0142 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_default_model_paths。 | <code>    if local_pre.exists() and local_mdl.exists():</code> |
| L0143 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_default_model_paths。 | <code>        return local_pre, local_mdl</code> |
| L0144 | 计算并保存 &#96;fallback_models&#96;（fallbackmodels），供后续逻辑使用，当前位于函数 resolve_default_model_paths。 | <code>    fallback_models = project_root.parent / "traffic_mlp" / "models"</code> |
| L0145 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_default_model_paths。 | <code>    return fallback_models / "preprocessor.joblib", fallback_models / "best_mlp.pth"</code> |
| L0146 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0147 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0148 | 定义waithttpready函数 &#96;wait_http_ready&#96;，封装可复用业务逻辑。 | <code>def wait_http_ready(url: str, timeout_sec: float = 20.0) -&gt; None:</code> |
| L0149 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.request&#96;。 | <code>    import urllib.request</code> |
| L0150 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0151 | 计算并保存 &#96;end&#96;（end），供后续逻辑使用，当前位于函数 wait_http_ready。 | <code>    end = time.time() + timeout_sec</code> |
| L0152 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 wait_http_ready。 | <code>    while time.time() &lt; end:</code> |
| L0153 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 wait_http_ready。 | <code>        try:</code> |
| L0154 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 wait_http_ready。 | <code>            with urllib.request.urlopen(url, timeout=1.5) as resp:</code> |
| L0155 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 wait_http_ready。 | <code>                if int(resp.status) &lt; 500:</code> |
| L0156 | 结束当前函数并把结果返回给调用方，当前位于函数 wait_http_ready。 | <code>                    return</code> |
| L0157 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 wait_http_ready。 | <code>        except Exception:</code> |
| L0158 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 wait_http_ready。 | <code>            time.sleep(0.25)</code> |
| L0159 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 wait_http_ready。 | <code>    raise RuntimeError(f"service not ready: {url}")</code> |
| L0160 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0161 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0162 | 定义newestcapturefile函数 &#96;newest_capture_file&#96;，封装可复用业务逻辑。 | <code>def newest_capture_file(input_dir: Path) -&gt; Path:</code> |
| L0163 | 计算并保存 &#96;files&#96;（files），供后续逻辑使用，当前位于函数 newest_capture_file。 | <code>    files = sorted(input_dir.glob("1.1.*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)</code> |
| L0164 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 newest_capture_file。 | <code>    if not files:</code> |
| L0165 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 newest_capture_file。 | <code>        raise FileNotFoundError(f"no capture file under: {input_dir}")</code> |
| L0166 | 结束当前函数并把结果返回给调用方，当前位于函数 newest_capture_file。 | <code>    return files[0]</code> |
| L0167 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0168 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0169 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; None:</code> |
| L0170 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="Compare thresholds on real packet-capture pipeline.")</code> |
| L0171 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--host", default="127.0.0.1")</code> |
| L0172 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--port", type=int, default=3000)</code> |
| L0173 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--interface", default="1", help="capture interface keyword or index")</code> |
| L0174 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--attacks", type=int, default=250)</code> |
| L0175 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--benign", type=int, default=250)</code> |
| L0176 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--capture-batch-size", type=int, default=0, help="0 means attacks+benign")</code> |
| L0177 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--capture-timeout-seconds", type=int, default=420)</code> |
| L0178 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--capture-ready-timeout-seconds", type=int, default=45)</code> |
| L0179 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--request-interval-ms", type=int, default=20)</code> |
| L0180 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--thresholds", default="0.79,0.46")</code> |
| L0181 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--seed", type=int, default=20260426)</code> |
| L0182 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--project-root", default=".")</code> |
| L0183 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--output-root", default="output/real_capture_threshold_compare")</code> |
| L0184 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--preprocessor", default="")</code> |
| L0185 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--model", default="")</code> |
| L0186 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0187 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0188 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    random.seed(int(args.seed))</code> |
| L0189 | 计算并保存 &#96;thresholds&#96;（thresholds），供后续逻辑使用，当前位于函数 main。 | <code>    thresholds = parse_thresholds(args.thresholds)</code> |
| L0190 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0191 | 计算并保存 &#96;project_root&#96;（projectroot），供后续逻辑使用，当前位于函数 main。 | <code>    project_root = Path(args.project_root).resolve()</code> |
| L0192 | 计算并保存 &#96;output_root&#96;（outputroot），供后续逻辑使用，当前位于函数 main。 | <code>    output_root = (project_root / args.output_root).resolve()</code> |
| L0193 | 计算并保存 &#96;ts&#96;（ts），供后续逻辑使用，当前位于函数 main。 | <code>    ts = datetime.now().strftime("%Y%m%d_%H%M%S")</code> |
| L0194 | 计算并保存 &#96;run_dir&#96;（运行dir），供后续逻辑使用，当前位于函数 main。 | <code>    run_dir = output_root / ts</code> |
| L0195 | 计算并保存 &#96;input_dir&#96;（inputdir），供后续逻辑使用，当前位于函数 main。 | <code>    input_dir = run_dir / "input"</code> |
| L0196 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    run_dir.mkdir(parents=True, exist_ok=True)</code> |
| L0197 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    input_dir.mkdir(parents=True, exist_ok=True)</code> |
| L0198 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0199 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    pre_default, model_default = resolve_default_model_paths(project_root)</code> |
| L0200 | 计算并保存 &#96;pre_path&#96;（prepath），供后续逻辑使用，当前位于函数 main。 | <code>    pre_path = Path(args.preprocessor).resolve() if args.preprocessor else pre_default</code> |
| L0201 | 计算并保存 &#96;model_path&#96;（模型path），供后续逻辑使用，当前位于函数 main。 | <code>    model_path = Path(args.model).resolve() if args.model else model_default</code> |
| L0202 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if not pre_path.exists():</code> |
| L0203 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 main。 | <code>        raise FileNotFoundError(f"preprocessor not found: {pre_path}")</code> |
| L0204 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if not model_path.exists():</code> |
| L0205 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 main。 | <code>        raise FileNotFoundError(f"model not found: {model_path}")</code> |
| L0206 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0207 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    wait_http_ready(f"http://{args.host}:{args.port}/health", timeout_sec=25.0)</code> |
| L0208 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0209 | 计算并保存 &#96;attacks&#96;（attacks），供后续逻辑使用，当前位于函数 main。 | <code>    attacks = [random.choice(default_attack_templates()) for _ in range(int(args.attacks))]</code> |
| L0210 | 计算并保存 &#96;benigns&#96;（benigns），供后续逻辑使用，当前位于函数 main。 | <code>    benigns = [random.choice(default_benign_templates()) for _ in range(int(args.benign))]</code> |
| L0211 | 计算并保存 &#96;mixed&#96;（mixed），供后续逻辑使用，当前位于函数 main。 | <code>    mixed = attacks + benigns</code> |
| L0212 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    random.shuffle(mixed)</code> |
| L0213 | 计算并保存 &#96;total&#96;（total），供后续逻辑使用，当前位于函数 main。 | <code>    total = len(mixed)</code> |
| L0214 | 计算并保存 &#96;bench_id&#96;（benchid），供后续逻辑使用，当前位于函数 main。 | <code>    bench_id = f"bench{datetime.now().strftime('%H%M%S')}"</code> |
| L0215 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0216 | 计算并保存 &#96;capture_batch_size&#96;（capturebatchsize），供后续逻辑使用，当前位于函数 main。 | <code>    capture_batch_size = int(args.capture_batch_size) if int(args.capture_batch_size) &gt; 0 else total</code> |
| L0217 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0218 | 计算并保存 &#96;capture_cmd&#96;（capturecmd），供后续逻辑使用，当前位于函数 main。 | <code>    capture_cmd = [</code> |
| L0219 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        sys.executable,</code> |
| L0220 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "-u",</code> |
| L0221 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        str(project_root / "scripts" / "capture_http_request_batches.py"),</code> |
| L0222 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--port",</code> |
| L0223 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        str(args.port),</code> |
| L0224 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--ports",</code> |
| L0225 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        str(args.port),</code> |
| L0226 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--batch-size",</code> |
| L0227 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        str(capture_batch_size),</code> |
| L0228 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--input-dir",</code> |
| L0229 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        str(input_dir),</code> |
| L0230 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--once",</code> |
| L0231 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--interface",</code> |
| L0232 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        str(args.interface),</code> |
| L0233 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    ]</code> |
| L0234 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0235 | 计算并保存 &#96;capture_proc&#96;（captureproc），供后续逻辑使用，当前位于函数 main。 | <code>    capture_proc = subprocess.Popen(</code> |
| L0236 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        capture_cmd,</code> |
| L0237 | 计算并保存 &#96;cwd&#96;（cwd），供后续逻辑使用，当前位于函数 main。 | <code>        cwd=str(project_root),</code> |
| L0238 | 计算并保存 &#96;stdout&#96;（stdout），供后续逻辑使用，当前位于函数 main。 | <code>        stdout=subprocess.PIPE,</code> |
| L0239 | 计算并保存 &#96;stderr&#96;（stderr），供后续逻辑使用，当前位于函数 main。 | <code>        stderr=subprocess.PIPE,</code> |
| L0240 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 main。 | <code>        text=True,</code> |
| L0241 | 计算并保存 &#96;encoding&#96;（encoding），供后续逻辑使用，当前位于函数 main。 | <code>        encoding="utf-8",</code> |
| L0242 | 计算并保存 &#96;errors&#96;（errors），供后续逻辑使用，当前位于函数 main。 | <code>        errors="replace",</code> |
| L0243 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0244 | 源码原注释：Avoid blocking reads on pipes: give capture process a configurable warm-up window. | <code>    # Avoid blocking reads on pipes: give capture process a configurable warm-up window.</code> |
| L0245 | 计算并保存 &#96;warmup&#96;（warmup），供后续逻辑使用，当前位于函数 main。 | <code>    warmup = max(1, int(args.capture_ready_timeout_seconds))</code> |
| L0246 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    time.sleep(warmup)</code> |
| L0247 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0248 | 计算并保存 &#96;truth_by_trace&#96;（truthbytrace），供后续逻辑使用，当前位于函数 main。 | <code>    truth_by_trace: Dict[str, Dict[str, Any]] = {}</code> |
| L0249 | 计算并保存 &#96;interval&#96;（interval），供后续逻辑使用，当前位于函数 main。 | <code>    interval = max(0, int(args.request_interval_ms)) / 1000.0</code> |
| L0250 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>    for idx, tmpl in enumerate(mixed, start=1):</code> |
| L0251 | 计算并保存 &#96;trace&#96;（trace），供后续逻辑使用，当前位于函数 main。 | <code>        trace = f"{bench_id}_{idx:04d}"</code> |
| L0252 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 main。 | <code>        uri = append_trace(tmpl.uri, trace)</code> |
| L0253 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        status, reason = send_http(args.host, int(args.port), tmpl.method, uri, tmpl.body, tmpl.content_type)</code> |
| L0254 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        truth_by_trace[trace] = {</code> |
| L0255 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "trace": trace,</code> |
| L0256 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "is_attack": int(tmpl.is_attack),</code> |
| L0257 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "template": tmpl.name,</code> |
| L0258 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "method": tmpl.method,</code> |
| L0259 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "uri": uri,</code> |
| L0260 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "response_status": int(status),</code> |
| L0261 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "response_reason": reason,</code> |
| L0262 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        }</code> |
| L0263 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if interval &gt; 0:</code> |
| L0264 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            time.sleep(interval)</code> |
| L0265 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0266 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>    try:</code> |
| L0267 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        capture_proc.wait(timeout=max(30, int(args.capture_timeout_seconds)))</code> |
| L0268 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>    except subprocess.TimeoutExpired as exc:</code> |
| L0269 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        capture_proc.kill()</code> |
| L0270 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 main。 | <code>        raise RuntimeError(</code> |
| L0271 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            f"capture process timed out before producing one batch: batch_size={capture_batch_size}"</code> |
| L0272 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        ) from exc</code> |
| L0273 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0274 | 计算并保存 &#96;cap_stdout&#96;（capstdout），供后续逻辑使用，当前位于函数 main。 | <code>    cap_stdout = capture_proc.stdout.read() if capture_proc.stdout else ""</code> |
| L0275 | 计算并保存 &#96;cap_stderr&#96;（capstderr），供后续逻辑使用，当前位于函数 main。 | <code>    cap_stderr = capture_proc.stderr.read() if capture_proc.stderr else ""</code> |
| L0276 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if capture_proc.returncode != 0:</code> |
| L0277 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 main。 | <code>        raise RuntimeError(f"capture failed rc={capture_proc.returncode}\nstdout={cap_stdout}\nstderr={cap_stderr}")</code> |
| L0278 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0279 | 计算并保存 &#96;capture_txt&#96;（capturetxt），供后续逻辑使用，当前位于函数 main。 | <code>    capture_txt = newest_capture_file(input_dir)</code> |
| L0280 | 计算并保存 &#96;file_id&#96;（fileid），供后续逻辑使用，当前位于函数 main。 | <code>    file_id = capture_txt.stem</code> |
| L0281 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0282 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    subprocess.run(</code> |
| L0283 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        [</code> |
| L0284 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            sys.executable,</code> |
| L0285 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(project_root / "scripts" / "extract_old_model_features_from_txt.py"),</code> |
| L0286 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--input",</code> |
| L0287 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(capture_txt),</code> |
| L0288 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--preprocessor",</code> |
| L0289 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(pre_path),</code> |
| L0290 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--output-dir",</code> |
| L0291 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(run_dir),</code> |
| L0292 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--keep-static",</code> |
| L0293 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        ],</code> |
| L0294 | 计算并保存 &#96;cwd&#96;（cwd），供后续逻辑使用，当前位于函数 main。 | <code>        cwd=str(project_root),</code> |
| L0295 | 计算并保存 &#96;check&#96;（检查），供后续逻辑使用，当前位于函数 main。 | <code>        check=True,</code> |
| L0296 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0297 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0298 | 计算并保存 &#96;old_input&#96;（oldinput），供后续逻辑使用，当前位于函数 main。 | <code>    old_input = run_dir / f"{file_id}.old_model_input.csv"</code> |
| L0299 | 计算并保存 &#96;model_jsonl&#96;（模型jsonl），供后续逻辑使用，当前位于函数 main。 | <code>    model_jsonl = run_dir / f"{file_id}.model_result.jsonl"</code> |
| L0300 | 计算并保存 &#96;model_csv&#96;（模型csv），供后续逻辑使用，当前位于函数 main。 | <code>    model_csv = run_dir / f"{file_id}.model_result.csv"</code> |
| L0301 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    subprocess.run(</code> |
| L0302 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        [</code> |
| L0303 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            sys.executable,</code> |
| L0304 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(project_root / "scripts" / "run_old_model_direct.py"),</code> |
| L0305 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--input",</code> |
| L0306 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(old_input),</code> |
| L0307 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--preprocessor",</code> |
| L0308 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(pre_path),</code> |
| L0309 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--model",</code> |
| L0310 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(model_path),</code> |
| L0311 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--output-jsonl",</code> |
| L0312 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(model_jsonl),</code> |
| L0313 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--output-csv",</code> |
| L0314 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            str(model_csv),</code> |
| L0315 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "--label-threshold",</code> |
| L0316 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "0.5",</code> |
| L0317 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        ],</code> |
| L0318 | 计算并保存 &#96;cwd&#96;（cwd），供后续逻辑使用，当前位于函数 main。 | <code>        cwd=str(project_root),</code> |
| L0319 | 计算并保存 &#96;check&#96;（检查），供后续逻辑使用，当前位于函数 main。 | <code>        check=True,</code> |
| L0320 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0321 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0322 | 计算并保存 &#96;raw_index&#96;（rawindex），供后续逻辑使用，当前位于函数 main。 | <code>    raw_index = run_dir / f"{file_id}.raw_index.jsonl"</code> |
| L0323 | 计算并保存 &#96;seq_to_uri&#96;（seqtouri），供后续逻辑使用，当前位于函数 main。 | <code>    seq_to_uri: Dict[int, str] = {}</code> |
| L0324 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 main。 | <code>    with raw_index.open("r", encoding="utf-8") as f:</code> |
| L0325 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>        for line in f:</code> |
| L0326 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if not line.strip():</code> |
| L0327 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                continue</code> |
| L0328 | 计算并保存 &#96;obj&#96;（obj），供后续逻辑使用，当前位于函数 main。 | <code>            obj = json.loads(line)</code> |
| L0329 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            seq_to_uri[int(obj.get("seq_id") or 0)] = str(obj.get("uri") or "")</code> |
| L0330 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0331 | 计算并保存 &#96;seq_to_score&#96;（seqtoscore），供后续逻辑使用，当前位于函数 main。 | <code>    seq_to_score: Dict[int, float] = {}</code> |
| L0332 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 main。 | <code>    with model_jsonl.open("r", encoding="utf-8") as f:</code> |
| L0333 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>        for line in f:</code> |
| L0334 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if not line.strip():</code> |
| L0335 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                continue</code> |
| L0336 | 计算并保存 &#96;obj&#96;（obj），供后续逻辑使用，当前位于函数 main。 | <code>            obj = json.loads(line)</code> |
| L0337 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            seq_to_score[int(obj.get("seq_id") or 0)] = float(obj.get("score") or 0.0)</code> |
| L0338 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0339 | 计算并保存 &#96;eval_rows&#96;（eval数据库记录），供后续逻辑使用，当前位于函数 main。 | <code>    eval_rows: List[Dict[str, Any]] = []</code> |
| L0340 | 计算并保存 &#96;trace_pattern&#96;（tracepattern），供后续逻辑使用，当前位于函数 main。 | <code>    trace_pattern = re.compile(rf"trace=({bench_id}_[0-9]{{4}})")</code> |
| L0341 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>    for seq_id, uri in seq_to_uri.items():</code> |
| L0342 | 计算并保存 &#96;m&#96;（m），供后续逻辑使用，当前位于函数 main。 | <code>        m = trace_pattern.search(uri)</code> |
| L0343 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if not m:</code> |
| L0344 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>            continue</code> |
| L0345 | 计算并保存 &#96;trace&#96;（trace），供后续逻辑使用，当前位于函数 main。 | <code>        trace = m.group(1)</code> |
| L0346 | 计算并保存 &#96;truth&#96;（truth），供后续逻辑使用，当前位于函数 main。 | <code>        truth = truth_by_trace.get(trace)</code> |
| L0347 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if not truth or seq_id not in seq_to_score:</code> |
| L0348 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>            continue</code> |
| L0349 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>        eval_rows.append(</code> |
| L0350 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            {</code> |
| L0351 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "trace": trace,</code> |
| L0352 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "seq_id": seq_id,</code> |
| L0353 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "uri": uri,</code> |
| L0354 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "is_attack": int(truth["is_attack"]),</code> |
| L0355 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "score": float(seq_to_score[seq_id]),</code> |
| L0356 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>            }</code> |
| L0357 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        )</code> |
| L0358 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0359 | 计算并保存 &#96;threshold_results&#96;（thresholdresults），供后续逻辑使用，当前位于函数 main。 | <code>    threshold_results = [calc_metrics(eval_rows, t) for t in thresholds]</code> |
| L0360 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    threshold_results.sort(key=lambda x: x["threshold"], reverse=True)</code> |
| L0361 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0362 | 计算并保存 &#96;summary&#96;（summary），供后续逻辑使用，当前位于函数 main。 | <code>    summary = {</code> |
| L0363 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "run_at": datetime.now().isoformat(timespec="seconds"),</code> |
| L0364 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "host": args.host,</code> |
| L0365 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "port": int(args.port),</code> |
| L0366 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "interface": str(args.interface),</code> |
| L0367 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "attacks_sent": int(args.attacks),</code> |
| L0368 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "benign_sent": int(args.benign),</code> |
| L0369 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "sent_total": total,</code> |
| L0370 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "capture_batch_size": capture_batch_size,</code> |
| L0371 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "captured_file": str(capture_txt),</code> |
| L0372 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "capture_return_code": int(capture_proc.returncode),</code> |
| L0373 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "capture_stdout_tail": cap_stdout[-1200:],</code> |
| L0374 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "capture_stderr_tail": cap_stderr[-1200:],</code> |
| L0375 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "scored_total": len(seq_to_score),</code> |
| L0376 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "trace_matched_total": len(eval_rows),</code> |
| L0377 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "coverage_ratio": round((len(eval_rows) / total) if total else 0.0, 6),</code> |
| L0378 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "threshold_results": threshold_results,</code> |
| L0379 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    }</code> |
| L0380 | 计算并保存 &#96;summary_path&#96;（summarypath），供后续逻辑使用，当前位于函数 main。 | <code>    summary_path = run_dir / "summary.json"</code> |
| L0381 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")</code> |
| L0382 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(json.dumps(summary, ensure_ascii=False, indent=2))</code> |
| L0383 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"\n[real-capture-threshold-compare] summary: {summary_path}")</code> |
| L0384 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0385 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0386 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0387 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
