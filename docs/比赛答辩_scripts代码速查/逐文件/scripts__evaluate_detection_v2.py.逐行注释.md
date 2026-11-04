# `scripts/evaluate_detection_v2.py` 逐行注释

**脚本用途：** 评估新检测架构的准确率、精确率、召回率和 F1。

**源码行数：** 130　**函数/类数量：** 4

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;from collections import Counter&#96;。 | <code>from collections import Counter</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, List, Tuple&#96;。 | <code>from typing import Any, Dict, List, Tuple</code> |
| L0008 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score&#96;。 | <code>from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score</code> |
| L0010 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;from security_detection_v2 import DetectionEngineV2, extract_request_from_record, is_simple_page_view&#96;。 | <code>from security_detection_v2 import DetectionEngineV2, extract_request_from_record, is_simple_page_view</code> |
| L0012 | 导入后续逻辑所需的模块、类或函数：&#96;from train_payload_model_v2 import make_record&#96;。 | <code>from train_payload_model_v2 import make_record</code> |
| L0013 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0014 | 计算并保存 &#96;PROJECT_ROOT&#96;（PROJECTROOT），供后续逻辑使用。 | <code>PROJECT_ROOT = Path(__file__).resolve().parent.parent</code> |
| L0015 | 计算并保存 &#96;SERVER_ROWS&#96;（SERVER数据库记录），供后续逻辑使用。 | <code>SERVER_ROWS = PROJECT_ROOT / "output" / "server_all_joined_rows.json"</code> |
| L0016 | 计算并保存 &#96;DEFAULT_OUT&#96;（DEFAULTOUT），供后续逻辑使用。 | <code>DEFAULT_OUT = PROJECT_ROOT / "output" / "detection_v2"</code> |
| L0017 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0018 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0019 | 定义makeadversarialcases函数 &#96;make_adversarial_cases&#96;，封装可复用业务逻辑。 | <code>def make_adversarial_cases() -&gt; List[Tuple[str, Dict[str, Any], str]]:</code> |
| L0020 | 计算并保存 &#96;cases&#96;（cases），供后续逻辑使用，当前位于函数 make_adversarial_cases。 | <code>    cases: List[Tuple[str, Dict[str, Any], str]] = []</code> |
| L0021 | 计算并保存 &#96;normal_texts&#96;（normaltexts），供后续逻辑使用，当前位于函数 make_adversarial_cases。 | <code>    normal_texts = [</code> |
| L0022 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_adversarial_cases。 | <code>        ("/api/search?q=union+station", "normal search phrase containing union"),</code> |
| L0023 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_adversarial_cases。 | <code>        ("/api/search?q=script+writing+tutorial", "normal search phrase containing script"),</code> |
| L0024 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_adversarial_cases。 | <code>        ("/api/search?q=select+a+city", "normal search phrase containing select"),</code> |
| L0025 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_adversarial_cases。 | <code>        ("/api/comment", "json normal comment with &lt;b&gt;safe html&lt;/b&gt;"),</code> |
| L0026 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_adversarial_cases。 | <code>        ("/sql", "open SQL test page"),</code> |
| L0027 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_adversarial_cases。 | <code>        ("/xss", "open XSS test page"),</code> |
| L0028 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_adversarial_cases。 | <code>        ("/upload", "open upload page"),</code> |
| L0029 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_adversarial_cases。 | <code>        ("/api/auth/login", "normal failed login"),</code> |
| L0030 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 make_adversarial_cases。 | <code>    ]</code> |
| L0031 | 遍历集合中的数据项并逐项处理，当前位于函数 make_adversarial_cases。 | <code>    for uri, note in normal_texts:</code> |
| L0032 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 make_adversarial_cases。 | <code>        if uri == "/api/comment":</code> |
| L0033 | 计算并保存 &#96;rec&#96;（rec），供后续逻辑使用，当前位于函数 make_adversarial_cases。 | <code>            rec = make_record("POST", uri, '{"content":"I like script writing and union station"}', "application/json", 200)</code> |
| L0034 | 当前一条件未命中时继续判断另一条件，当前位于函数 make_adversarial_cases。 | <code>        elif uri == "/api/auth/login":</code> |
| L0035 | 计算并保存 &#96;rec&#96;（rec），供后续逻辑使用，当前位于函数 make_adversarial_cases。 | <code>            rec = make_record("POST", uri, '{"username":"admin","password":"wrongpass"}', "application/json", 401)</code> |
| L0036 | 处理前述条件均未命中的情况，当前位于函数 make_adversarial_cases。 | <code>        else:</code> |
| L0037 | 计算并保存 &#96;rec&#96;（rec），供后续逻辑使用，当前位于函数 make_adversarial_cases。 | <code>            rec = make_record("GET", uri, "", "", 200)</code> |
| L0038 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 make_adversarial_cases。 | <code>        cases.append(("normal", rec, note))</code> |
| L0039 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0040 | 计算并保存 &#96;attacks&#96;（attacks），供后续逻辑使用，当前位于函数 make_adversarial_cases。 | <code>    attacks = [</code> |
| L0041 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_adversarial_cases。 | <code>        ("SQL注入", make_record("GET", "/api/item?id=1%27%20OR%20%271%27%3D%271", "", "", 500), "encoded sqli"),</code> |
| L0042 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_adversarial_cases。 | <code>        ("SQL注入", make_record("POST", "/api/auth/login", '{"username":"a","password":"x\" OR \"1\"=\"1"}', "application/json", 200), "double quote sqli"),</code> |
| L0043 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_adversarial_cases。 | <code>        ("XSS", make_record("GET", "/api/search?q=%3Csvg%2Fonload%3Dalert%281%29%3E", "", "", 200), "encoded svg xss"),</code> |
| L0044 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_adversarial_cases。 | <code>        ("命令注入", make_record("POST", "/api/system/ping", '{"host":"127.0.0.1%3Bwhoami"}', "application/json", 200), "encoded command"),</code> |
| L0045 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_adversarial_cases。 | <code>        ("路径遍历", make_record("GET", "/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd", "", "", 200), "double encoded traversal"),</code> |
| L0046 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_adversarial_cases。 | <code>        ("SSRF", make_record("GET", "/api/proxy?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F", "", "", 200), "metadata ssrf"),</code> |
| L0047 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_adversarial_cases。 | <code>        ("SSTI", make_record("GET", "/api/render?name=%7B%7B7*7%7D%7D", "", "", 200), "encoded ssti"),</code> |
| L0048 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_adversarial_cases。 | <code>        ("XXE", make_record("POST", "/api/xml/import", "&lt;!DOCTYPE a [&lt;!ENTITY b SYSTEM 'file:///etc/passwd'&gt;]&gt;&lt;a&gt;&amp;b;&lt;/a&gt;", "application/xml", 500), "xxe"),</code> |
| L0049 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_adversarial_cases。 | <code>        ("危险文件上传", make_record("POST", "/api/upload", "filename=shell.phtml\r\n&lt;?php phpinfo();?&gt;", "multipart/form-data", 200), "phtml upload"),</code> |
| L0050 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_adversarial_cases。 | <code>        ("反序列化", make_record("POST", "/api/object/load", '{"payload":"aced000573720011"}', "application/json", 500), "java serialized"),</code> |
| L0051 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_adversarial_cases。 | <code>        ("GraphQL探测", make_record("POST", "/graphql", '{"query":"{__schema{types{name}}}"}', "application/json", 200), "graphql introspection"),</code> |
| L0052 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 make_adversarial_cases。 | <code>    ]</code> |
| L0053 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 make_adversarial_cases。 | <code>    cases.extend(attacks)</code> |
| L0054 | 结束当前函数并把结果返回给调用方，当前位于函数 make_adversarial_cases。 | <code>    return cases</code> |
| L0055 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0056 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0057 | 定义expectedlabelforserver函数 &#96;expected_label_for_server&#96;，封装可复用业务逻辑。 | <code>def expected_label_for_server(row: Dict[str, Any]) -&gt; str &#124; None:</code> |
| L0058 | 计算并保存 &#96;ev&#96;（ev），供后续逻辑使用，当前位于函数 expected_label_for_server。 | <code>    ev = extract_request_from_record(row)</code> |
| L0059 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 expected_label_for_server。 | <code>    uri = str(ev.get("uri") or "")</code> |
| L0060 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 expected_label_for_server。 | <code>    body = str(ev.get("body") or "")</code> |
| L0061 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 expected_label_for_server。 | <code>    text = (uri + "\n" + body).lower()</code> |
| L0062 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 expected_label_for_server。 | <code>    if "&lt;!doctype" in text or "&lt;!entity" in text:</code> |
| L0063 | 结束当前函数并把结果返回给调用方，当前位于函数 expected_label_for_server。 | <code>        return "XXE"</code> |
| L0064 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 expected_label_for_server。 | <code>    if any(x in text for x in ["whoami", "cat /etc/passwd", "powershell", ";whoami", "&amp;&amp; cat"]):</code> |
| L0065 | 结束当前函数并把结果返回给调用方，当前位于函数 expected_label_for_server。 | <code>        return "命令注入"</code> |
| L0066 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 expected_label_for_server。 | <code>    if is_simple_page_view(ev):</code> |
| L0067 | 结束当前函数并把结果返回给调用方，当前位于函数 expected_label_for_server。 | <code>        return "normal"</code> |
| L0068 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 expected_label_for_server。 | <code>    if "&lt;script" in text or "onerror" in text or "onload" in text or "javascript:" in text:</code> |
| L0069 | 结束当前函数并把结果返回给调用方，当前位于函数 expected_label_for_server。 | <code>        return "XSS"</code> |
| L0070 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 expected_label_for_server。 | <code>    if "union select" in text or " or 1=1" in text or "' or" in text or "\" or" in text or "information_schema" in text or "sleep(" in text:</code> |
| L0071 | 结束当前函数并把结果返回给调用方，当前位于函数 expected_label_for_server。 | <code>        return "SQL注入"</code> |
| L0072 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 expected_label_for_server。 | <code>    if "../" in text or "%2e%2e" in text or "etc/passwd" in text or "win.ini" in text:</code> |
| L0073 | 结束当前函数并把结果返回给调用方，当前位于函数 expected_label_for_server。 | <code>        return "路径遍历"</code> |
| L0074 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 expected_label_for_server。 | <code>    if "{{7*7" in text or "__class__" in text:</code> |
| L0075 | 结束当前函数并把结果返回给调用方，当前位于函数 expected_label_for_server。 | <code>        return "SSTI"</code> |
| L0076 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 expected_label_for_server。 | <code>    if "filename=" in text and any(ext in text for ext in [".php", ".jsp", ".aspx", ".ps1", ".sh"]):</code> |
| L0077 | 结束当前函数并把结果返回给调用方，当前位于函数 expected_label_for_server。 | <code>        return "危险文件上传"</code> |
| L0078 | 结束当前函数并把结果返回给调用方，当前位于函数 expected_label_for_server。 | <code>    return None</code> |
| L0079 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0080 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0081 | 定义评估records函数 &#96;evaluate_records&#96;，封装可复用业务逻辑。 | <code>def evaluate_records(engine: DetectionEngineV2, labeled: List[Tuple[str, Dict[str, Any], str]]) -&gt; Dict[str, Any]:</code> |
| L0082 | 计算并保存 &#96;y_true&#96;（ytrue），供后续逻辑使用，当前位于函数 evaluate_records。 | <code>    y_true=[]; y_pred=[]; decisions=[]; rows=[]</code> |
| L0083 | 遍历集合中的数据项并逐项处理，当前位于函数 evaluate_records。 | <code>    for label, rec, note in labeled:</code> |
| L0084 | 计算并保存 &#96;out&#96;（out），供后续逻辑使用，当前位于函数 evaluate_records。 | <code>        out = engine.detect(rec)</code> |
| L0085 | 计算并保存 &#96;pred&#96;（pred），供后续逻辑使用，当前位于函数 evaluate_records。 | <code>        pred = out["fusion"].get("attack_type") or out["payload"].get("label") or "unknown"</code> |
| L0086 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 evaluate_records。 | <code>        if out["fusion"].get("decision") == "raw_only":</code> |
| L0087 | 计算并保存 &#96;pred&#96;（pred），供后续逻辑使用，当前位于函数 evaluate_records。 | <code>            pred = "normal"</code> |
| L0088 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 evaluate_records。 | <code>        y_true.append(label); y_pred.append(pred); decisions.append(out["fusion"].get("decision"))</code> |
| L0089 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 evaluate_records。 | <code>        rows.append({"expected":label,"pred":pred,"decision":out["fusion"].get("decision"),"note":note,"uri":extract_request_from_record(rec).get("uri"),"score":out["fusion"].get("final_score"),"payload":out["payload"],"poc":out["poc_matches"],"fusion":out["fusion"],"evidence":out["fusion"].get("evidence")})</code> |
| L0090 | 计算并保存 &#96;labels&#96;（labels），供后续逻辑使用，当前位于函数 evaluate_records。 | <code>    labels=sorted(set(y_true)&#124;set(y_pred))</code> |
| L0091 | 结束当前函数并把结果返回给调用方，当前位于函数 evaluate_records。 | <code>    return {"accuracy":accuracy_score(y_true,y_pred),"macro_f1":f1_score(y_true,y_pred,average="macro"),"report":classification_report(y_true,y_pred,digits=4,zero_division=0),"confusion":confusion_matrix(y_true,y_pred,labels=labels).tolist(),"labels":labels,"decision_counts":dict(Counter(decisions)),"rows":rows}</code> |
| L0092 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0093 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0094 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; None:</code> |
| L0095 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser=argparse.ArgumentParser(description="Evaluate detection v2")</code> |
| L0096 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))</code> |
| L0097 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args=parser.parse_args()</code> |
| L0098 | 计算并保存 &#96;out_dir&#96;（outdir），供后续逻辑使用，当前位于函数 main。 | <code>    out_dir=Path(args.out_dir); out_dir.mkdir(parents=True,exist_ok=True)</code> |
| L0099 | 计算并保存 &#96;engine&#96;（engine），供后续逻辑使用，当前位于函数 main。 | <code>    engine=DetectionEngineV2()</code> |
| L0100 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0101 | 计算并保存 &#96;adversarial&#96;（adversarial），供后续逻辑使用，当前位于函数 main。 | <code>    adversarial=make_adversarial_cases()</code> |
| L0102 | 计算并保存 &#96;adv_eval&#96;（adveval），供后续逻辑使用，当前位于函数 main。 | <code>    adv_eval=evaluate_records(engine, adversarial)</code> |
| L0103 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0104 | 计算并保存 &#96;server_labeled&#96;（serverlabeled），供后续逻辑使用，当前位于函数 main。 | <code>    server_labeled=[]</code> |
| L0105 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if SERVER_ROWS.exists():</code> |
| L0106 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 main。 | <code>        rows=json.loads(SERVER_ROWS.read_text(encoding="utf-8-sig"))</code> |
| L0107 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>        for r in rows:</code> |
| L0108 | 计算并保存 &#96;lab&#96;（lab），供后续逻辑使用，当前位于函数 main。 | <code>            lab=expected_label_for_server(r)</code> |
| L0109 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if lab:</code> |
| L0110 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>                server_labeled.append((lab,r,str(r.get("case_id"))))</code> |
| L0111 | 计算并保存 &#96;server_eval&#96;（servereval），供后续逻辑使用，当前位于函数 main。 | <code>    server_eval=evaluate_records(engine, server_labeled)</code> |
| L0112 | 源码原注释：Full server suppression summary, without requiring labels for every row. | <code>    # Full server suppression summary, without requiring labels for every row.</code> |
| L0113 | 计算并保存 &#96;full&#96;（full），供后续逻辑使用，当前位于函数 main。 | <code>    full=[]</code> |
| L0114 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if SERVER_ROWS.exists():</code> |
| L0115 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>        for r in json.loads(SERVER_ROWS.read_text(encoding="utf-8-sig")):</code> |
| L0116 | 计算并保存 &#96;out&#96;（out），供后续逻辑使用，当前位于函数 main。 | <code>            out=engine.detect(r)</code> |
| L0117 | 计算并保存 &#96;ev&#96;（ev），供后续逻辑使用，当前位于函数 main。 | <code>            ev=extract_request_from_record(r)</code> |
| L0118 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>            full.append({"case_id":r.get("case_id"),"uri":ev.get("uri"),"old_type":r.get("attack_type"),"decision":out["fusion"].get("decision"),"attack_type":out["fusion"].get("attack_type"),"score":out["fusion"].get("final_score"),"evidence":out["fusion"].get("evidence")})</code> |
| L0119 | 计算并保存 &#96;summary&#96;（summary），供后续逻辑使用，当前位于函数 main。 | <code>    summary={"adversarial":{k:v for k,v in adv_eval.items() if k!="rows"},"server_labeled":{k:v for k,v in server_eval.items() if k!="rows"},"server_labeled_count":len(server_labeled),"full_server_decisions":dict(Counter(x["decision"] for x in full)),"full_server_total":len(full)}</code> |
| L0120 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    (out_dir/"evaluation_summary.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding="utf-8")</code> |
| L0121 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    (out_dir/"adversarial_rows.json").write_text(json.dumps(adv_eval["rows"],ensure_ascii=False,indent=2),encoding="utf-8")</code> |
| L0122 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    (out_dir/"server_labeled_rows.json").write_text(json.dumps(server_eval["rows"],ensure_ascii=False,indent=2),encoding="utf-8")</code> |
| L0123 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    (out_dir/"server_full_decisions.json").write_text(json.dumps(full,ensure_ascii=False,indent=2),encoding="utf-8")</code> |
| L0124 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(json.dumps(summary,ensure_ascii=False,indent=2))</code> |
| L0125 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("\nAdversarial report:\n", adv_eval["report"])</code> |
| L0126 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("\nServer labeled report:\n", server_eval["report"])</code> |
| L0127 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0128 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0129 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
| L0130 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
