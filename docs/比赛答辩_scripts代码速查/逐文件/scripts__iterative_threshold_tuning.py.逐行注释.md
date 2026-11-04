# `scripts/iterative_threshold_tuning.py` 逐行注释

**脚本用途：** 迭代实验不同阈值，比较正常/攻击流量并输出调参结论。

**源码行数：** 532　**函数/类数量：** 14

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0002 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import random&#96;。 | <code>import random</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import subprocess&#96;。 | <code>import subprocess</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import sys&#96;。 | <code>import sys</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;import time&#96;。 | <code>import time</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;from dataclasses import dataclass&#96;。 | <code>from dataclasses import dataclass</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime&#96;。 | <code>from datetime import datetime</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;from http.client import HTTPConnection&#96;。 | <code>from http.client import HTTPConnection</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, List, Tuple&#96;。 | <code>from typing import Any, Dict, List, Tuple</code> |
| L0012 | 导入后续逻辑所需的模块、类或函数：&#96;from urllib.parse import quote_plus&#96;。 | <code>from urllib.parse import quote_plus</code> |
| L0013 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0014 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0015 | 应用装饰器 &#96;@dataclass&#96;，为下一定义附加权限、缓存或注册行为。 | <code>@dataclass</code> |
| L0016 | 定义类 &#96;CaseTemplate&#96;，集中保存相关状态与操作。 | <code>class CaseTemplate:</code> |
| L0017 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 CaseTemplate。 | <code>    name: str</code> |
| L0018 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 CaseTemplate。 | <code>    method: str</code> |
| L0019 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 CaseTemplate。 | <code>    uri: str</code> |
| L0020 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于类 CaseTemplate。 | <code>    body: str = ""</code> |
| L0021 | 计算并保存 &#96;content_type&#96;（contenttype），供后续逻辑使用，当前位于类 CaseTemplate。 | <code>    content_type: str = ""</code> |
| L0022 | 计算并保存 &#96;is_attack&#96;（is攻击），供后续逻辑使用，当前位于类 CaseTemplate。 | <code>    is_attack: int = 0</code> |
| L0023 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0024 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0025 | 定义waithttpready函数 &#96;wait_http_ready&#96;，封装可复用业务逻辑。 | <code>def wait_http_ready(url: str, timeout_sec: float = 20.0) -&gt; None:</code> |
| L0026 | 计算并保存 &#96;end&#96;（end），供后续逻辑使用，当前位于函数 wait_http_ready。 | <code>    end = time.time() + timeout_sec</code> |
| L0027 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 wait_http_ready。 | <code>    while time.time() &lt; end:</code> |
| L0028 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 wait_http_ready。 | <code>        try:</code> |
| L0029 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.request&#96;。 | <code>            import urllib.request</code> |
| L0030 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0031 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 wait_http_ready。 | <code>            with urllib.request.urlopen(url, timeout=1.5) as resp:</code> |
| L0032 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 wait_http_ready。 | <code>                if int(resp.status) &lt; 500:</code> |
| L0033 | 结束当前函数并把结果返回给调用方，当前位于函数 wait_http_ready。 | <code>                    return</code> |
| L0034 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 wait_http_ready。 | <code>        except Exception:</code> |
| L0035 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 wait_http_ready。 | <code>            time.sleep(0.25)</code> |
| L0036 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 wait_http_ready。 | <code>    raise RuntimeError(f"service not ready: {url}")</code> |
| L0037 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0038 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0039 | 定义safeterminate函数 &#96;safe_terminate&#96;，封装可复用业务逻辑。 | <code>def safe_terminate(proc: subprocess.Popen &#124; None) -&gt; None:</code> |
| L0040 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 safe_terminate。 | <code>    if proc is None:</code> |
| L0041 | 结束当前函数并把结果返回给调用方，当前位于函数 safe_terminate。 | <code>        return</code> |
| L0042 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 safe_terminate。 | <code>    try:</code> |
| L0043 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 safe_terminate。 | <code>        proc.terminate()</code> |
| L0044 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 safe_terminate。 | <code>    except Exception:</code> |
| L0045 | 结束当前函数并把结果返回给调用方，当前位于函数 safe_terminate。 | <code>        return</code> |
| L0046 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 safe_terminate。 | <code>    try:</code> |
| L0047 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 safe_terminate。 | <code>        proc.wait(timeout=6)</code> |
| L0048 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 safe_terminate。 | <code>    except Exception:</code> |
| L0049 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 safe_terminate。 | <code>        try:</code> |
| L0050 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 safe_terminate。 | <code>            proc.kill()</code> |
| L0051 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 safe_terminate。 | <code>        except Exception:</code> |
| L0052 | 控制当前循环或占位分支的执行流程，当前位于函数 safe_terminate。 | <code>            pass</code> |
| L0053 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0054 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0055 | 定义sendhttp函数 &#96;send_http&#96;，封装可复用业务逻辑。 | <code>def send_http(host: str, port: int, method: str, uri: str, body: str, content_type: str) -&gt; Dict[str, Any]:</code> |
| L0056 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 send_http。 | <code>    conn = HTTPConnection(host, port, timeout=6)</code> |
| L0057 | 计算并保存 &#96;t0&#96;（t0），供后续逻辑使用，当前位于函数 send_http。 | <code>    t0 = time.time()</code> |
| L0058 | 计算并保存 &#96;status&#96;（状态），供后续逻辑使用，当前位于函数 send_http。 | <code>    status = 599</code> |
| L0059 | 计算并保存 &#96;reason&#96;（reason），供后续逻辑使用，当前位于函数 send_http。 | <code>    reason = "CLIENT_ERROR"</code> |
| L0060 | 计算并保存 &#96;resp_text&#96;（resptext），供后续逻辑使用，当前位于函数 send_http。 | <code>    resp_text = ""</code> |
| L0061 | 计算并保存 &#96;src_ip&#96;（srcip），供后续逻辑使用，当前位于函数 send_http。 | <code>    src_ip = "127.0.0.1"</code> |
| L0062 | 计算并保存 &#96;src_port&#96;（srcport），供后续逻辑使用，当前位于函数 send_http。 | <code>    src_port = random.randint(20000, 65000)</code> |
| L0063 | 计算并保存 &#96;dst_ip&#96;（dstip），供后续逻辑使用，当前位于函数 send_http。 | <code>    dst_ip = host</code> |
| L0064 | 计算并保存 &#96;dst_port&#96;（dstport），供后续逻辑使用，当前位于函数 send_http。 | <code>    dst_port = port</code> |
| L0065 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 send_http。 | <code>    try:</code> |
| L0066 | 计算并保存 &#96;headers&#96;（headers），供后续逻辑使用，当前位于函数 send_http。 | <code>        headers = {"Host": "ctf.ski:4000", "User-Agent": "iterative-threshold-tuner/1.0"}</code> |
| L0067 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 send_http。 | <code>        if content_type:</code> |
| L0068 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 send_http。 | <code>            headers["Content-Type"] = content_type</code> |
| L0069 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 send_http。 | <code>        payload = body.encode("utf-8") if body else None</code> |
| L0070 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 send_http。 | <code>        conn.request(method=method, url=uri, body=payload, headers=headers)</code> |
| L0071 | 计算并保存 &#96;sock&#96;（sock），供后续逻辑使用，当前位于函数 send_http。 | <code>        sock = conn.sock</code> |
| L0072 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 send_http。 | <code>        if sock:</code> |
| L0073 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 send_http。 | <code>            try:</code> |
| L0074 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 send_http。 | <code>                src_ip, src_port = sock.getsockname()[0], int(sock.getsockname()[1])</code> |
| L0075 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 send_http。 | <code>                dst_ip, dst_port = sock.getpeername()[0], int(sock.getpeername()[1])</code> |
| L0076 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 send_http。 | <code>            except Exception:</code> |
| L0077 | 控制当前循环或占位分支的执行流程，当前位于函数 send_http。 | <code>                pass</code> |
| L0078 | 计算并保存 &#96;resp&#96;（resp），供后续逻辑使用，当前位于函数 send_http。 | <code>        resp = conn.getresponse()</code> |
| L0079 | 计算并保存 &#96;status&#96;（状态），供后续逻辑使用，当前位于函数 send_http。 | <code>        status = int(resp.status)</code> |
| L0080 | 计算并保存 &#96;reason&#96;（reason），供后续逻辑使用，当前位于函数 send_http。 | <code>        reason = str(resp.reason or "")</code> |
| L0081 | 计算并保存 &#96;resp_text&#96;（resptext），供后续逻辑使用，当前位于函数 send_http。 | <code>        resp_text = resp.read().decode("utf-8", errors="replace")</code> |
| L0082 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 send_http。 | <code>    except Exception as exc:</code> |
| L0083 | 计算并保存 &#96;reason&#96;（reason），供后续逻辑使用，当前位于函数 send_http。 | <code>        reason = str(exc)</code> |
| L0084 | 无论成功或异常都执行资源清理，当前位于函数 send_http。 | <code>    finally:</code> |
| L0085 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 send_http。 | <code>        try:</code> |
| L0086 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 send_http。 | <code>            conn.close()</code> |
| L0087 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 send_http。 | <code>        except Exception:</code> |
| L0088 | 控制当前循环或占位分支的执行流程，当前位于函数 send_http。 | <code>            pass</code> |
| L0089 | 计算并保存 &#96;t1&#96;（t1），供后续逻辑使用，当前位于函数 send_http。 | <code>    t1 = time.time()</code> |
| L0090 | 结束当前函数并把结果返回给调用方，当前位于函数 send_http。 | <code>    return {</code> |
| L0091 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 send_http。 | <code>        "status_code": status,</code> |
| L0092 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 send_http。 | <code>        "reason": reason,</code> |
| L0093 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 send_http。 | <code>        "response_text_raw": resp_text,</code> |
| L0094 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 send_http。 | <code>        "time_req": t0,</code> |
| L0095 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 send_http。 | <code>        "time_resp": t1,</code> |
| L0096 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 send_http。 | <code>        "src_ip": src_ip,</code> |
| L0097 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 send_http。 | <code>        "src_port": src_port,</code> |
| L0098 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 send_http。 | <code>        "dst_ip": dst_ip,</code> |
| L0099 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 send_http。 | <code>        "dst_port": dst_port,</code> |
| L0100 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 send_http。 | <code>    }</code> |
| L0101 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0102 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0103 | 定义default攻击templates函数 &#96;default_attack_templates&#96;，封装可复用业务逻辑。 | <code>def default_attack_templates() -&gt; List[CaseTemplate]:</code> |
| L0104 | 结束当前函数并把结果返回给调用方，当前位于函数 default_attack_templates。 | <code>    return [</code> |
| L0105 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("sqli_or_login", "POST", "/api/auth/login", '{"username":"admin","password":"\' OR 1=1 -- "}', "application/json", 1),</code> |
| L0106 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("sqli_union_login", "POST", "/api/auth/login", '{"username":"admin\' UNION SELECT 1,2,3 -- ","password":"x"}', "application/json", 1),</code> |
| L0107 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("sqli_sleep_login", "POST", "/api/auth/login", '{"username":"admin","password":"\' AND SLEEP(1)-- "}', "application/json", 1),</code> |
| L0108 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("sqli_waitfor_login", "POST", "/api/auth/login", '{"username":"admin","password":"\'; WAITFOR DELAY \'0:0:1\'--"}', "application/json", 1),</code> |
| L0109 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("xss_search_script", "GET", "/api/search?q=" + quote_plus("&lt;script&gt;alert(1)&lt;/script&gt;"), "", "", 1),</code> |
| L0110 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("xss_comment_onerror", "POST", "/api/comment", '{"author":"attacker","content":"&lt;img src=x onerror=alert(1)&gt;"}', "application/json", 1),</code> |
| L0111 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("traversal_linux", "GET", "/api/file/read?path=" + quote_plus("../../../../etc/passwd"), "", "", 1),</code> |
| L0112 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("traversal_windows", "GET", "/api/file/read?path=" + quote_plus("..\\..\\..\\Windows\\win.ini"), "", "", 1),</code> |
| L0113 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("cmdi_semicolon", "POST", "/api/system/ping", '{"host":"127.0.0.1; cat /etc/passwd"}', "application/json", 1),</code> |
| L0114 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("cmdi_ampamp", "POST", "/api/system/ping", '{"host":"8.8.8.8 &amp;&amp; whoami"}', "application/json", 1),</code> |
| L0115 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("ssrf_metadata", "GET", "/api/fetch?url=" + quote_plus("http://169.254.169.254/latest/meta-data/iam"), "", "", 1),</code> |
| L0116 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("ssrf_localhost", "GET", "/api/fetch?url=" + quote_plus("http://127.0.0.1:6379/info"), "", "", 1),</code> |
| L0117 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("ssti_jinja", "POST", "/api/template/render", '{"template":"{{7*7}}"}', "application/json", 1),</code> |
| L0118 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("xxe_file", "POST", "/api/xml/import", '&lt;?xml version="1.0"?&gt;&lt;!DOCTYPE x [&lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;]&gt;&lt;x&gt;&amp;xxe;&lt;/x&gt;', "application/xml", 1),</code> |
| L0119 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("deserialize_java", "POST", "/api/deserialize", '{"data":"rO0ABXNyABNqYXZhLmxhbmcuUnVudGltZQ=="}', "application/json", 1),</code> |
| L0120 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("upload_php_shell", "POST", "/api/upload", '{"filename":"shell.php","content":"&lt;?php system($_GET[\'c\']); ?&gt;"}', "application/json", 1),</code> |
| L0121 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("upload_jsp_shell", "POST", "/api/upload", '{"filename":"cmd.jsp","content":"&lt;% Runtime.getRuntime().exec(request.getParameter(\\"c\\")); %&gt;"}', "application/json", 1),</code> |
| L0122 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("graphql_schema_dump", "POST", "/api/graphql", '{"query":"{__schema{types{name}}}"}', "application/json", 1),</code> |
| L0123 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("graphql_sqli", "POST", "/api/graphql", '{"query":"{user(id:\\"1 OR 1=1\\"){id name}}"}', "application/json", 1),</code> |
| L0124 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("admin_weak_token", "POST", "/api/admin/reset", '{"token":"000000"}', "application/json", 1),</code> |
| L0125 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("admin_none_token", "GET", "/api/admin/reset?token=alg:none.admin", "", "", 1),</code> |
| L0126 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("open_redirect_js", "GET", "/api/redirect?next=" + quote_plus("javascript:alert(1)"), "", "", 1),</code> |
| L0127 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("scan_git", "GET", "/.git/config", "", "", 1),</code> |
| L0128 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("scan_wp", "GET", "/wp-admin/install.php", "", "", 1),</code> |
| L0129 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_attack_templates。 | <code>        CaseTemplate("eval_rce", "POST", "/api/eval", '{"code":"__import__(\\"os\\").system(\\"id\\")"}', "application/json", 1),</code> |
| L0130 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 default_attack_templates。 | <code>    ]</code> |
| L0131 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0132 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0133 | 定义defaultbenigntemplates函数 &#96;default_benign_templates&#96;，封装可复用业务逻辑。 | <code>def default_benign_templates() -&gt; List[CaseTemplate]:</code> |
| L0134 | 结束当前函数并把结果返回给调用方，当前位于函数 default_benign_templates。 | <code>    return [</code> |
| L0135 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("home_page", "GET", "/", "", "", 0),</code> |
| L0136 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("health", "GET", "/health", "", "", 0),</code> |
| L0137 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("products", "GET", "/api/products", "", "", 0),</code> |
| L0138 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("news", "GET", "/api/news", "", "", 0),</code> |
| L0139 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("search_normal", "GET", "/api/search?q=" + quote_plus("security analytics"), "", "", 0),</code> |
| L0140 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("login_admin_ok", "POST", "/api/auth/login", '{"username":"admin","password":"admin"}', "application/json", 0),</code> |
| L0141 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("login_user_ok", "POST", "/api/auth/login", '{"username":"alice","password":"alice123"}', "application/json", 0),</code> |
| L0142 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("login_wrong", "POST", "/api/auth/login", '{"username":"guest","password":"guest"}', "application/json", 0),</code> |
| L0143 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("comment_normal", "POST", "/api/comment", '{"author":"alice","content":"hello team"}', "application/json", 0),</code> |
| L0144 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("file_read_safe", "GET", "/api/file/read?path=" + quote_plus("notes/todo.txt"), "", "", 0),</code> |
| L0145 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("ping_safe", "POST", "/api/system/ping", '{"host":"8.8.8.8"}', "application/json", 0),</code> |
| L0146 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("fetch_external", "GET", "/api/fetch?url=" + quote_plus("https://example.com/index"), "", "", 0),</code> |
| L0147 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("template_safe", "POST", "/api/template/render", '{"template":"hello ${name}"}', "application/json", 0),</code> |
| L0148 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("xml_safe", "POST", "/api/xml/import", '&lt;?xml version="1.0"?&gt;&lt;root&gt;&lt;x&gt;ok&lt;/x&gt;&lt;/root&gt;', "application/xml", 0),</code> |
| L0149 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("deserialize_safe", "POST", "/api/deserialize", '{"data":"eyJmb28iOiJiYXIifQ=="}', "application/json", 0),</code> |
| L0150 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("upload_png", "POST", "/api/upload", '{"filename":"photo.png","content":"PNGDATA"}', "application/json", 0),</code> |
| L0151 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("graphql_safe", "POST", "/api/graphql", '{"query":"{viewer{id name}}"}', "application/json", 0),</code> |
| L0152 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("admin_strict_token", "GET", "/api/admin/reset?token=safe-token", "", "", 0),</code> |
| L0153 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("eval_safe", "GET", "/api/eval?code=1%2B1", "", "", 0),</code> |
| L0154 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("orders_list", "GET", "/api/orders", "", "", 0),</code> |
| L0155 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("orders_create", "POST", "/api/orders", '{"user_id":1001,"sku":"SKU-2001","amount":2}', "application/json", 0),</code> |
| L0156 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("redirect_normal", "GET", "/api/redirect?next=/home", "", "", 0),</code> |
| L0157 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("products_again", "GET", "/api/products?id=1002", "", "", 0),</code> |
| L0158 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("search_docs", "GET", "/api/search?q=" + quote_plus("documentation"), "", "", 0),</code> |
| L0159 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 default_benign_templates。 | <code>        CaseTemplate("news_again", "GET", "/api/news?page=1", "", "", 0),</code> |
| L0160 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 default_benign_templates。 | <code>    ]</code> |
| L0161 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0162 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0163 | 定义构建requesttext函数 &#96;build_request_text&#96;，封装可复用业务逻辑。 | <code>def build_request_text(method: str, uri: str, status_code: int, body: str, excerpt: str, content_type: str) -&gt; str:</code> |
| L0164 | 结束当前函数并把结果返回给调用方，当前位于函数 build_request_text。 | <code>    return "\\n".join(</code> |
| L0165 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_text。 | <code>        [</code> |
| L0166 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_text。 | <code>            f"METHOD={method}",</code> |
| L0167 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_text。 | <code>            f"URI={uri}",</code> |
| L0168 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_text。 | <code>            "HOST=ctf.ski:4000",</code> |
| L0169 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_text。 | <code>            f"CONTENT_TYPE={content_type}",</code> |
| L0170 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_text。 | <code>            f"STATUS_CODE={status_code}",</code> |
| L0171 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_text。 | <code>            f"REQUEST_BODY={body}",</code> |
| L0172 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_text。 | <code>            f"RESPONSE_EXCERPT={excerpt}",</code> |
| L0173 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_request_text。 | <code>        ]</code> |
| L0174 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_request_text。 | <code>    )</code> |
| L0175 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0176 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0177 | 定义构建responsetext函数 &#96;build_response_text&#96;，封装可复用业务逻辑。 | <code>def build_response_text(status_code: int, reason: str, excerpt: str) -&gt; str:</code> |
| L0178 | 结束当前函数并把结果返回给调用方，当前位于函数 build_response_text。 | <code>    return "\\n".join(</code> |
| L0179 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_response_text。 | <code>        [</code> |
| L0180 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_response_text。 | <code>            f"HTTP_STATUS={status_code}",</code> |
| L0181 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_response_text。 | <code>            f"MESSAGE={reason}",</code> |
| L0182 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_response_text。 | <code>            f"RESPONSE_EXCERPT={excerpt}",</code> |
| L0183 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_response_text。 | <code>        ]</code> |
| L0184 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_response_text。 | <code>    )</code> |
| L0185 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0186 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0187 | 定义写入canonicalfile函数 &#96;write_canonical_file&#96;，封装可复用业务逻辑。 | <code>def write_canonical_file(</code> |
| L0188 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>    path: Path,</code> |
| L0189 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>    file_id: str,</code> |
| L0190 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>    records: List[Dict[str, Any]],</code> |
| L0191 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 write_canonical_file。 | <code>) -&gt; None:</code> |
| L0192 | 计算并保存 &#96;lines&#96;（lines），供后续逻辑使用，当前位于函数 write_canonical_file。 | <code>    lines: List[str] = []</code> |
| L0193 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_file。 | <code>    lines.append("### BATCH_START ###")</code> |
| L0194 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_file。 | <code>    lines.append(f"file_id={file_id}")</code> |
| L0195 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_file。 | <code>    lines.append(f"batch_size={len(records)}")</code> |
| L0196 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_file。 | <code>    lines.append("source=iterative_threshold_tuning")</code> |
| L0197 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_file。 | <code>    lines.append("port=3000")</code> |
| L0198 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_file。 | <code>    lines.append("capture_mode=canonical_http_batch")</code> |
| L0199 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_file。 | <code>    lines.append("### BATCH_META_END ###")</code> |
| L0200 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_file。 | <code>    lines.append("")</code> |
| L0201 | 遍历集合中的数据项并逐项处理，当前位于函数 write_canonical_file。 | <code>    for rec in records:</code> |
| L0202 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_file。 | <code>        lines.extend(</code> |
| L0203 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>            [</code> |
| L0204 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                "### CASE_START ###",</code> |
| L0205 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                f"file_id={file_id}",</code> |
| L0206 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                f"seq_id={rec['seq_id']}",</code> |
| L0207 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                f"frame_req={100000 + rec['seq_id'] * 2}",</code> |
| L0208 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                f"frame_resp={100001 + rec['seq_id'] * 2}",</code> |
| L0209 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                f"time_req={rec['time_req']}",</code> |
| L0210 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                f"time_resp={rec['time_resp']}",</code> |
| L0211 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                f"src_ip={rec['src_ip']}",</code> |
| L0212 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                f"dst_ip={rec['dst_ip']}",</code> |
| L0213 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                f"src_port={rec['src_port']}",</code> |
| L0214 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                f"dst_port={rec['dst_port']}",</code> |
| L0215 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                f"method={rec['method']}",</code> |
| L0216 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                f"uri={rec['uri']}",</code> |
| L0217 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                "host=ctf.ski:4000",</code> |
| L0218 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                f"status_code={rec['status_code']}",</code> |
| L0219 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                f"content_type={rec['content_type']}",</code> |
| L0220 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                f"request_text={rec['request_text']}",</code> |
| L0221 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                f"response_text={rec['response_text']}",</code> |
| L0222 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                "[REQUEST_BLOCK]",</code> |
| L0223 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                rec["raw_request_block"],</code> |
| L0224 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                "[/REQUEST_BLOCK]",</code> |
| L0225 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                "[RESPONSE_BLOCK]",</code> |
| L0226 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                rec["raw_response_block"],</code> |
| L0227 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                "[/RESPONSE_BLOCK]",</code> |
| L0228 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                "### CASE_END ###",</code> |
| L0229 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>                "",</code> |
| L0230 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 write_canonical_file。 | <code>            ]</code> |
| L0231 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 write_canonical_file。 | <code>        )</code> |
| L0232 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_file。 | <code>    path.write_text("\n".join(lines), encoding="utf-8")</code> |
| L0233 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0234 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0235 | 定义calcmetrics函数 &#96;calc_metrics&#96;，封装可复用业务逻辑。 | <code>def calc_metrics(rows: List[Dict[str, Any]], threshold: float) -&gt; Dict[str, Any]:</code> |
| L0236 | 计算并保存 &#96;tp&#96;（tp），供后续逻辑使用，当前位于函数 calc_metrics。 | <code>    tp = fp = tn = fn = 0</code> |
| L0237 | 遍历集合中的数据项并逐项处理，当前位于函数 calc_metrics。 | <code>    for r in rows:</code> |
| L0238 | 计算并保存 &#96;pred&#96;（pred），供后续逻辑使用，当前位于函数 calc_metrics。 | <code>        pred = 1 if float(r["score"]) &gt;= threshold else 0</code> |
| L0239 | 计算并保存 &#96;y&#96;（y），供后续逻辑使用，当前位于函数 calc_metrics。 | <code>        y = int(r["is_attack"])</code> |
| L0240 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 calc_metrics。 | <code>        if pred == 1 and y == 1:</code> |
| L0241 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>            tp += 1</code> |
| L0242 | 当前一条件未命中时继续判断另一条件，当前位于函数 calc_metrics。 | <code>        elif pred == 1 and y == 0:</code> |
| L0243 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>            fp += 1</code> |
| L0244 | 当前一条件未命中时继续判断另一条件，当前位于函数 calc_metrics。 | <code>        elif pred == 0 and y == 0:</code> |
| L0245 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>            tn += 1</code> |
| L0246 | 处理前述条件均未命中的情况，当前位于函数 calc_metrics。 | <code>        else:</code> |
| L0247 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>            fn += 1</code> |
| L0248 | 计算并保存 &#96;precision&#96;（precision），供后续逻辑使用，当前位于函数 calc_metrics。 | <code>    precision = tp / (tp + fp) if (tp + fp) else 0.0</code> |
| L0249 | 计算并保存 &#96;recall&#96;（recall），供后续逻辑使用，当前位于函数 calc_metrics。 | <code>    recall = tp / (tp + fn) if (tp + fn) else 0.0</code> |
| L0250 | 计算并保存 &#96;f1&#96;（f1），供后续逻辑使用，当前位于函数 calc_metrics。 | <code>    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0</code> |
| L0251 | 计算并保存 &#96;accuracy&#96;（accuracy），供后续逻辑使用，当前位于函数 calc_metrics。 | <code>    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0</code> |
| L0252 | 计算并保存 &#96;fpr&#96;（fpr），供后续逻辑使用，当前位于函数 calc_metrics。 | <code>    fpr = fp / (fp + tn) if (fp + tn) else 0.0</code> |
| L0253 | 计算并保存 &#96;tnr&#96;（tnr），供后续逻辑使用，当前位于函数 calc_metrics。 | <code>    tnr = tn / (tn + fp) if (tn + fp) else 0.0</code> |
| L0254 | 结束当前函数并把结果返回给调用方，当前位于函数 calc_metrics。 | <code>    return {</code> |
| L0255 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "threshold": round(float(threshold), 4),</code> |
| L0256 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "tp": tp,</code> |
| L0257 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "fp": fp,</code> |
| L0258 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "tn": tn,</code> |
| L0259 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "fn": fn,</code> |
| L0260 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "precision": precision,</code> |
| L0261 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "recall": recall,</code> |
| L0262 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "f1": f1,</code> |
| L0263 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "accuracy": accuracy,</code> |
| L0264 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "fpr": fpr,</code> |
| L0265 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "tnr": tnr,</code> |
| L0266 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 calc_metrics。 | <code>        "youden_j": recall + tnr - 1,</code> |
| L0267 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 calc_metrics。 | <code>    }</code> |
| L0268 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0269 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0270 | 定义findbestthreshold函数 &#96;find_best_threshold&#96;，封装可复用业务逻辑。 | <code>def find_best_threshold(rows: List[Dict[str, Any]]) -&gt; Tuple[Dict[str, Any], List[Dict[str, Any]]]:</code> |
| L0271 | 计算并保存 &#96;all_metrics&#96;（allmetrics），供后续逻辑使用，当前位于函数 find_best_threshold。 | <code>    all_metrics: List[Dict[str, Any]] = []</code> |
| L0272 | 遍历集合中的数据项并逐项处理，当前位于函数 find_best_threshold。 | <code>    for i in range(5, 96):</code> |
| L0273 | 计算并保存 &#96;th&#96;（th），供后续逻辑使用，当前位于函数 find_best_threshold。 | <code>        th = i / 100.0</code> |
| L0274 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 find_best_threshold。 | <code>        all_metrics.append(calc_metrics(rows, th))</code> |
| L0275 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_best_threshold。 | <code>    all_metrics.sort(</code> |
| L0276 | 计算并保存 &#96;key&#96;（key），供后续逻辑使用，当前位于函数 find_best_threshold。 | <code>        key=lambda x: (</code> |
| L0277 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_best_threshold。 | <code>            x["accuracy"],</code> |
| L0278 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_best_threshold。 | <code>            x["f1"],</code> |
| L0279 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_best_threshold。 | <code>            x["precision"],</code> |
| L0280 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_best_threshold。 | <code>            -x["fpr"],</code> |
| L0281 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_best_threshold。 | <code>            x["recall"],</code> |
| L0282 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 find_best_threshold。 | <code>        ),</code> |
| L0283 | 计算并保存 &#96;reverse&#96;（reverse），供后续逻辑使用，当前位于函数 find_best_threshold。 | <code>        reverse=True,</code> |
| L0284 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 find_best_threshold。 | <code>    )</code> |
| L0285 | 结束当前函数并把结果返回给调用方，当前位于函数 find_best_threshold。 | <code>    return all_metrics[0], all_metrics</code> |
| L0286 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0287 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0288 | 定义运行round函数 &#96;run_round&#96;，封装可复用业务逻辑。 | <code>def run_round(</code> |
| L0289 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>    round_id: int,</code> |
| L0290 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>    current_threshold: float,</code> |
| L0291 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>    output_root: Path,</code> |
| L0292 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>    host: str,</code> |
| L0293 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>    port: int,</code> |
| L0294 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>    attacks_per_round: int,</code> |
| L0295 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>    benign_per_round: int,</code> |
| L0296 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>    preprocessor: Path,</code> |
| L0297 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>    model: Path,</code> |
| L0298 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>    project_root: Path,</code> |
| L0299 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_round。 | <code>) -&gt; Dict[str, Any]:</code> |
| L0300 | 计算并保存 &#96;round_dir&#96;（rounddir），供后续逻辑使用，当前位于函数 run_round。 | <code>    round_dir = output_root / f"round_{round_id:02d}"</code> |
| L0301 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>    round_dir.mkdir(parents=True, exist_ok=True)</code> |
| L0302 | 计算并保存 &#96;file_id&#96;（fileid），供后续逻辑使用，当前位于函数 run_round。 | <code>    file_id = f"iter.{round_id:02d}.{datetime.now().strftime('%H%M%S')}"</code> |
| L0303 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0304 | 计算并保存 &#96;attacks&#96;（attacks），供后续逻辑使用，当前位于函数 run_round。 | <code>    attacks = [random.choice(default_attack_templates()) for _ in range(attacks_per_round)]</code> |
| L0305 | 计算并保存 &#96;benigns&#96;（benigns），供后续逻辑使用，当前位于函数 run_round。 | <code>    benigns = [random.choice(default_benign_templates()) for _ in range(benign_per_round)]</code> |
| L0306 | 计算并保存 &#96;mixed&#96;（mixed），供后续逻辑使用，当前位于函数 run_round。 | <code>    mixed = attacks + benigns</code> |
| L0307 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>    random.shuffle(mixed)</code> |
| L0308 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0309 | 计算并保存 &#96;truth_rows&#96;（truth数据库记录），供后续逻辑使用，当前位于函数 run_round。 | <code>    truth_rows: List[Dict[str, Any]] = []</code> |
| L0310 | 计算并保存 &#96;canonical_rows&#96;（canonical数据库记录），供后续逻辑使用，当前位于函数 run_round。 | <code>    canonical_rows: List[Dict[str, Any]] = []</code> |
| L0311 | 遍历集合中的数据项并逐项处理，当前位于函数 run_round。 | <code>    for idx, c in enumerate(mixed, start=1):</code> |
| L0312 | 计算并保存 &#96;resp&#96;（resp），供后续逻辑使用，当前位于函数 run_round。 | <code>        resp = send_http(host, port, c.method, c.uri, c.body, c.content_type)</code> |
| L0313 | 计算并保存 &#96;excerpt&#96;（excerpt），供后续逻辑使用，当前位于函数 run_round。 | <code>        excerpt = (resp["response_text_raw"] or "")[:320].replace("\n", " ")</code> |
| L0314 | 计算并保存 &#96;req_text&#96;（reqtext），供后续逻辑使用，当前位于函数 run_round。 | <code>        req_text = build_request_text(</code> |
| L0315 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            c.method,</code> |
| L0316 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            c.uri,</code> |
| L0317 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            int(resp["status_code"]),</code> |
| L0318 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            c.body,</code> |
| L0319 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            excerpt,</code> |
| L0320 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            c.content_type,</code> |
| L0321 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_round。 | <code>        )</code> |
| L0322 | 计算并保存 &#96;res_text&#96;（restext），供后续逻辑使用，当前位于函数 run_round。 | <code>        res_text = build_response_text(int(resp["status_code"]), str(resp["reason"]), excerpt)</code> |
| L0323 | 计算并保存 &#96;raw_req&#96;（rawreq），供后续逻辑使用，当前位于函数 run_round。 | <code>        raw_req = f"{c.method} {c.uri} HTTP/1.1\nHost: ctf.ski:4000"</code> |
| L0324 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 run_round。 | <code>        if c.content_type:</code> |
| L0325 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            raw_req += f"\nContent-Type: {c.content_type}"</code> |
| L0326 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>        raw_req += f"\nBody:\n{c.body}"</code> |
| L0327 | 计算并保存 &#96;raw_resp&#96;（rawresp），供后续逻辑使用，当前位于函数 run_round。 | <code>        raw_resp = f"HTTP/1.1 {resp['status_code']} {resp['reason']}\nBody:\n{resp['response_text_raw'][:800]}"</code> |
| L0328 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 run_round。 | <code>        canonical_rows.append(</code> |
| L0329 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            {</code> |
| L0330 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "seq_id": idx,</code> |
| L0331 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "time_req": resp["time_req"],</code> |
| L0332 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "time_resp": resp["time_resp"],</code> |
| L0333 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "src_ip": resp["src_ip"],</code> |
| L0334 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "dst_ip": resp["dst_ip"],</code> |
| L0335 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "src_port": resp["src_port"],</code> |
| L0336 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "dst_port": resp["dst_port"],</code> |
| L0337 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "method": c.method,</code> |
| L0338 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "uri": c.uri,</code> |
| L0339 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "status_code": int(resp["status_code"]),</code> |
| L0340 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "content_type": c.content_type,</code> |
| L0341 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "request_text": req_text,</code> |
| L0342 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "response_text": res_text,</code> |
| L0343 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "raw_request_block": raw_req,</code> |
| L0344 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "raw_response_block": raw_resp,</code> |
| L0345 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_round。 | <code>            }</code> |
| L0346 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_round。 | <code>        )</code> |
| L0347 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 run_round。 | <code>        truth_rows.append(</code> |
| L0348 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            {</code> |
| L0349 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "seq_id": idx,</code> |
| L0350 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "is_attack": int(c.is_attack),</code> |
| L0351 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "template": c.name,</code> |
| L0352 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "method": c.method,</code> |
| L0353 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "uri": c.uri,</code> |
| L0354 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                "status_code": int(resp["status_code"]),</code> |
| L0355 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_round。 | <code>            }</code> |
| L0356 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_round。 | <code>        )</code> |
| L0357 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0358 | 计算并保存 &#96;input_txt&#96;（inputtxt），供后续逻辑使用，当前位于函数 run_round。 | <code>    input_txt = round_dir / f"{file_id}.txt"</code> |
| L0359 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>    write_canonical_file(input_txt, file_id=file_id, records=canonical_rows)</code> |
| L0360 | 计算并保存 &#96;truth_path&#96;（truthpath），供后续逻辑使用，当前位于函数 run_round。 | <code>    truth_path = round_dir / "truth.jsonl"</code> |
| L0361 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 run_round。 | <code>    with truth_path.open("w", encoding="utf-8") as f:</code> |
| L0362 | 遍历集合中的数据项并逐项处理，当前位于函数 run_round。 | <code>        for row in truth_rows:</code> |
| L0363 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            f.write(json.dumps(row, ensure_ascii=False) + "\n")</code> |
| L0364 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0365 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>    subprocess.run(</code> |
| L0366 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>        [</code> |
| L0367 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            sys.executable,</code> |
| L0368 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            str(project_root / "scripts" / "extract_old_model_features_from_txt.py"),</code> |
| L0369 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            "--input",</code> |
| L0370 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            str(input_txt),</code> |
| L0371 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            "--preprocessor",</code> |
| L0372 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            str(preprocessor),</code> |
| L0373 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            "--output-dir",</code> |
| L0374 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            str(round_dir),</code> |
| L0375 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            "--keep-static",</code> |
| L0376 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_round。 | <code>        ],</code> |
| L0377 | 计算并保存 &#96;check&#96;（检查），供后续逻辑使用，当前位于函数 run_round。 | <code>        check=True,</code> |
| L0378 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_round。 | <code>    )</code> |
| L0379 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0380 | 计算并保存 &#96;old_model_input&#96;（old模型input），供后续逻辑使用，当前位于函数 run_round。 | <code>    old_model_input = round_dir / f"{file_id}.old_model_input.csv"</code> |
| L0381 | 计算并保存 &#96;model_jsonl&#96;（模型jsonl），供后续逻辑使用，当前位于函数 run_round。 | <code>    model_jsonl = round_dir / f"{file_id}.model_result.jsonl"</code> |
| L0382 | 计算并保存 &#96;model_csv&#96;（模型csv），供后续逻辑使用，当前位于函数 run_round。 | <code>    model_csv = round_dir / f"{file_id}.model_result.csv"</code> |
| L0383 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>    subprocess.run(</code> |
| L0384 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>        [</code> |
| L0385 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            sys.executable,</code> |
| L0386 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            str(project_root / "scripts" / "run_old_model_direct.py"),</code> |
| L0387 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            "--input",</code> |
| L0388 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            str(old_model_input),</code> |
| L0389 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            "--preprocessor",</code> |
| L0390 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            str(preprocessor),</code> |
| L0391 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            "--model",</code> |
| L0392 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            str(model),</code> |
| L0393 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            "--output-jsonl",</code> |
| L0394 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            str(model_jsonl),</code> |
| L0395 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            "--output-csv",</code> |
| L0396 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            str(model_csv),</code> |
| L0397 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            "--label-threshold",</code> |
| L0398 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>            str(current_threshold),</code> |
| L0399 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_round。 | <code>        ],</code> |
| L0400 | 计算并保存 &#96;check&#96;（检查），供后续逻辑使用，当前位于函数 run_round。 | <code>        check=True,</code> |
| L0401 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_round。 | <code>    )</code> |
| L0402 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0403 | 计算并保存 &#96;truth_map&#96;（truthmap），供后续逻辑使用，当前位于函数 run_round。 | <code>    truth_map = {int(x["seq_id"]): x for x in truth_rows}</code> |
| L0404 | 计算并保存 &#96;eval_rows&#96;（eval数据库记录），供后续逻辑使用，当前位于函数 run_round。 | <code>    eval_rows: List[Dict[str, Any]] = []</code> |
| L0405 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 run_round。 | <code>    with model_jsonl.open("r", encoding="utf-8") as f:</code> |
| L0406 | 遍历集合中的数据项并逐项处理，当前位于函数 run_round。 | <code>        for line in f:</code> |
| L0407 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 run_round。 | <code>            if not line.strip():</code> |
| L0408 | 控制当前循环或占位分支的执行流程，当前位于函数 run_round。 | <code>                continue</code> |
| L0409 | 计算并保存 &#96;obj&#96;（obj），供后续逻辑使用，当前位于函数 run_round。 | <code>            obj = json.loads(line)</code> |
| L0410 | 计算并保存 &#96;seq_id&#96;（seqid），供后续逻辑使用，当前位于函数 run_round。 | <code>            seq_id = int(obj["seq_id"])</code> |
| L0411 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 run_round。 | <code>            if seq_id not in truth_map:</code> |
| L0412 | 控制当前循环或占位分支的执行流程，当前位于函数 run_round。 | <code>                continue</code> |
| L0413 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 run_round。 | <code>            eval_rows.append(</code> |
| L0414 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                {</code> |
| L0415 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                    "seq_id": seq_id,</code> |
| L0416 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                    "score": float(obj.get("score") or 0.0),</code> |
| L0417 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>                    "is_attack": int(truth_map[seq_id]["is_attack"]),</code> |
| L0418 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_round。 | <code>                }</code> |
| L0419 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_round。 | <code>            )</code> |
| L0420 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0421 | 计算并保存 &#96;current_metrics&#96;（currentmetrics），供后续逻辑使用，当前位于函数 run_round。 | <code>    current_metrics = calc_metrics(eval_rows, current_threshold)</code> |
| L0422 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>    best_metrics, all_metrics = find_best_threshold(eval_rows)</code> |
| L0423 | 计算并保存 &#96;gain&#96;（gain），供后续逻辑使用，当前位于函数 run_round。 | <code>    gain = best_metrics["accuracy"] - current_metrics["accuracy"]</code> |
| L0424 | 计算并保存 &#96;round_summary&#96;（roundsummary），供后续逻辑使用，当前位于函数 run_round。 | <code>    round_summary = {</code> |
| L0425 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>        "round_id": round_id,</code> |
| L0426 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>        "file_id": file_id,</code> |
| L0427 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>        "input_total": len(mixed),</code> |
| L0428 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>        "scored_total": len(eval_rows),</code> |
| L0429 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>        "coverage_ratio": (len(eval_rows) / len(mixed)) if mixed else 0.0,</code> |
| L0430 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>        "current_threshold": current_threshold,</code> |
| L0431 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>        "current_metrics": current_metrics,</code> |
| L0432 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>        "best_metrics": best_metrics,</code> |
| L0433 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>        "accuracy_gain": gain,</code> |
| L0434 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>        "threshold_scan": all_metrics,</code> |
| L0435 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_round。 | <code>    }</code> |
| L0436 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_round。 | <code>    (round_dir / "round_summary.json").write_text(json.dumps(round_summary, ensure_ascii=False, indent=2), encoding="utf-8")</code> |
| L0437 | 结束当前函数并把结果返回给调用方，当前位于函数 run_round。 | <code>    return round_summary</code> |
| L0438 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0439 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0440 | 定义解析args函数 &#96;parse_args&#96;，封装可复用业务逻辑。 | <code>def parse_args() -&gt; argparse.Namespace:</code> |
| L0441 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 parse_args。 | <code>    parser = argparse.ArgumentParser(description="Iterative threshold tuning with 1000 attack + 1000 benign mixed traffic")</code> |
| L0442 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--host", default="127.0.0.1")</code> |
| L0443 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--port", type=int, default=3000)</code> |
| L0444 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--attacks-per-round", type=int, default=1000)</code> |
| L0445 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--benign-per-round", type=int, default=1000)</code> |
| L0446 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--initial-threshold", type=float, default=0.46)</code> |
| L0447 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--max-rounds", type=int, default=6)</code> |
| L0448 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--min-rounds", type=int, default=2)</code> |
| L0449 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--min-accuracy-gain", type=float, default=0.002)</code> |
| L0450 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--seed", type=int, default=20260425)</code> |
| L0451 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--project-root", default=".")</code> |
| L0452 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--output-root", default="output/iterative_threshold_tuning")</code> |
| L0453 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--preprocessor", default="../traffic_mlp/models/preprocessor.joblib")</code> |
| L0454 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--model", default="../traffic_mlp/models/best_mlp.pth")</code> |
| L0455 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--start-lab", action="store_true", help="start target_multivuln_lab automatically")</code> |
| L0456 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_args。 | <code>    return parser.parse_args()</code> |
| L0457 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0458 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0459 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; None:</code> |
| L0460 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parse_args()</code> |
| L0461 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    random.seed(args.seed)</code> |
| L0462 | 计算并保存 &#96;project_root&#96;（projectroot），供后续逻辑使用，当前位于函数 main。 | <code>    project_root = Path(args.project_root).resolve()</code> |
| L0463 | 计算并保存 &#96;output_root&#96;（outputroot），供后续逻辑使用，当前位于函数 main。 | <code>    output_root = (project_root / args.output_root).resolve()</code> |
| L0464 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    output_root.mkdir(parents=True, exist_ok=True)</code> |
| L0465 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0466 | 计算并保存 &#96;pre&#96;（pre），供后续逻辑使用，当前位于函数 main。 | <code>    pre = (project_root / args.preprocessor).resolve()</code> |
| L0467 | 计算并保存 &#96;model&#96;（模型），供后续逻辑使用，当前位于函数 main。 | <code>    model = (project_root / args.model).resolve()</code> |
| L0468 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if not pre.exists():</code> |
| L0469 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 main。 | <code>        raise FileNotFoundError(f"preprocessor not found: {pre}")</code> |
| L0470 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if not model.exists():</code> |
| L0471 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 main。 | <code>        raise FileNotFoundError(f"model not found: {model}")</code> |
| L0472 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0473 | 计算并保存 &#96;lab_proc&#96;（labproc），供后续逻辑使用，当前位于函数 main。 | <code>    lab_proc: subprocess.Popen &#124; None = None</code> |
| L0474 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if args.start_lab:</code> |
| L0475 | 计算并保存 &#96;lab_proc&#96;（labproc），供后续逻辑使用，当前位于函数 main。 | <code>        lab_proc = subprocess.Popen(</code> |
| L0476 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            [</code> |
| L0477 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                sys.executable,</code> |
| L0478 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                str(project_root / "scripts" / "target_multivuln_lab.py"),</code> |
| L0479 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "--host",</code> |
| L0480 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                args.host,</code> |
| L0481 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "--port",</code> |
| L0482 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                str(args.port),</code> |
| L0483 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>            ],</code> |
| L0484 | 计算并保存 &#96;cwd&#96;（cwd），供后续逻辑使用，当前位于函数 main。 | <code>            cwd=str(project_root),</code> |
| L0485 | 计算并保存 &#96;stdout&#96;（stdout），供后续逻辑使用，当前位于函数 main。 | <code>            stdout=subprocess.DEVNULL,</code> |
| L0486 | 计算并保存 &#96;stderr&#96;（stderr），供后续逻辑使用，当前位于函数 main。 | <code>            stderr=subprocess.DEVNULL,</code> |
| L0487 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        )</code> |
| L0488 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>    try:</code> |
| L0489 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        wait_http_ready(f"http://{args.host}:{args.port}/health", timeout_sec=30.0)</code> |
| L0490 | 计算并保存 &#96;history&#96;（history），供后续逻辑使用，当前位于函数 main。 | <code>        history: List[Dict[str, Any]] = []</code> |
| L0491 | 计算并保存 &#96;threshold&#96;（threshold），供后续逻辑使用，当前位于函数 main。 | <code>        threshold = float(args.initial_threshold)</code> |
| L0492 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0493 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>        for rid in range(1, int(args.max_rounds) + 1):</code> |
| L0494 | 计算并保存 &#96;summary&#96;（summary），供后续逻辑使用，当前位于函数 main。 | <code>            summary = run_round(</code> |
| L0495 | 计算并保存 &#96;round_id&#96;（roundid），供后续逻辑使用，当前位于函数 main。 | <code>                round_id=rid,</code> |
| L0496 | 计算并保存 &#96;current_threshold&#96;（currentthreshold），供后续逻辑使用，当前位于函数 main。 | <code>                current_threshold=threshold,</code> |
| L0497 | 计算并保存 &#96;output_root&#96;（outputroot），供后续逻辑使用，当前位于函数 main。 | <code>                output_root=output_root,</code> |
| L0498 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 main。 | <code>                host=args.host,</code> |
| L0499 | 计算并保存 &#96;port&#96;（port），供后续逻辑使用，当前位于函数 main。 | <code>                port=int(args.port),</code> |
| L0500 | 计算并保存 &#96;attacks_per_round&#96;（attacksperround），供后续逻辑使用，当前位于函数 main。 | <code>                attacks_per_round=int(args.attacks_per_round),</code> |
| L0501 | 计算并保存 &#96;benign_per_round&#96;（benignperround），供后续逻辑使用，当前位于函数 main。 | <code>                benign_per_round=int(args.benign_per_round),</code> |
| L0502 | 计算并保存 &#96;preprocessor&#96;（preprocessor），供后续逻辑使用，当前位于函数 main。 | <code>                preprocessor=pre,</code> |
| L0503 | 计算并保存 &#96;model&#96;（模型），供后续逻辑使用，当前位于函数 main。 | <code>                model=model,</code> |
| L0504 | 计算并保存 &#96;project_root&#96;（projectroot），供后续逻辑使用，当前位于函数 main。 | <code>                project_root=project_root,</code> |
| L0505 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>            )</code> |
| L0506 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>            history.append(summary)</code> |
| L0507 | 计算并保存 &#96;threshold&#96;（threshold），供后续逻辑使用，当前位于函数 main。 | <code>            threshold = float(summary["best_metrics"]["threshold"])</code> |
| L0508 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0509 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if rid &gt;= int(args.min_rounds) and float(summary["accuracy_gain"]) &lt; float(args.min_accuracy_gain):</code> |
| L0510 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                break</code> |
| L0511 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0512 | 计算并保存 &#96;final&#96;（final），供后续逻辑使用，当前位于函数 main。 | <code>        final = {</code> |
| L0513 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "started_at": datetime.now().isoformat(timespec="seconds"),</code> |
| L0514 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "initial_threshold": float(args.initial_threshold),</code> |
| L0515 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "final_threshold": float(threshold),</code> |
| L0516 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "round_count": len(history),</code> |
| L0517 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "stop_rule": {</code> |
| L0518 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "min_accuracy_gain": float(args.min_accuracy_gain),</code> |
| L0519 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                "min_rounds": int(args.min_rounds),</code> |
| L0520 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>            },</code> |
| L0521 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "history": history,</code> |
| L0522 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        }</code> |
| L0523 | 计算并保存 &#96;final_path&#96;（finalpath），供后续逻辑使用，当前位于函数 main。 | <code>        final_path = output_root / "final_summary.json"</code> |
| L0524 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        final_path.write_text(json.dumps(final, ensure_ascii=False, indent=2), encoding="utf-8")</code> |
| L0525 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        print(json.dumps(final, ensure_ascii=False, indent=2))</code> |
| L0526 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        print(f"\n[iterative-threshold-tuning] final summary: {final_path}")</code> |
| L0527 | 无论成功或异常都执行资源清理，当前位于函数 main。 | <code>    finally:</code> |
| L0528 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        safe_terminate(lab_proc)</code> |
| L0529 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0530 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0531 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0532 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
