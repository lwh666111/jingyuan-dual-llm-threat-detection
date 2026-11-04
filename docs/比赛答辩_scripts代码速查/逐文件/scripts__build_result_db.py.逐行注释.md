# `scripts/build_result_db.py` 逐行注释

**脚本用途：** 创建结果数据库表结构并导入历史 result 文件。

**源码行数：** 1287　**函数/类数量：** 44

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0002 | 导入后续逻辑所需的模块、类或函数：&#96;import ipaddress&#96;。 | <code>import ipaddress</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import re&#96;。 | <code>import re</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import sqlite3&#96;。 | <code>import sqlite3</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.error&#96;。 | <code>import urllib.error</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.request&#96;。 | <code>import urllib.request</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;from dataclasses import dataclass&#96;。 | <code>from dataclasses import dataclass</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime&#96;。 | <code>from datetime import datetime</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, List, Literal&#96;。 | <code>from typing import Any, Dict, List, Literal</code> |
| L0012 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0013 | 开始受保护操作，异常会交给后续分支处理。 | <code>try:</code> |
| L0014 | 导入后续逻辑所需的模块、类或函数：&#96;import pymysql&#96;。 | <code>    import pymysql</code> |
| L0015 | 导入后续逻辑所需的模块、类或函数：&#96;from pymysql.cursors import DictCursor&#96;。 | <code>    from pymysql.cursors import DictCursor</code> |
| L0016 | 捕获异常，避免单次错误导致整个服务退出。 | <code>except Exception:  # noqa: BLE001</code> |
| L0017 | 计算并保存 &#96;pymysql&#96;（pymysql），供后续逻辑使用。 | <code>    pymysql = None</code> |
| L0018 | 计算并保存 &#96;DictCursor&#96;（DictCursor），供后续逻辑使用。 | <code>    DictCursor = None</code> |
| L0019 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0020 | 计算并保存 &#96;Backend&#96;（Backend），供后续逻辑使用。 | <code>Backend = Literal["sqlite", "mysql"]</code> |
| L0021 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0022 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0023 | 应用装饰器 &#96;@dataclass&#96;，为下一定义附加权限、缓存或注册行为。 | <code>@dataclass</code> |
| L0024 | 定义类 &#96;MySQLConfig&#96;，集中保存相关状态与操作。 | <code>class MySQLConfig:</code> |
| L0025 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于类 MySQLConfig。 | <code>    host: str = "127.0.0.1"</code> |
| L0026 | 计算并保存 &#96;port&#96;（port），供后续逻辑使用，当前位于类 MySQLConfig。 | <code>    port: int = 3306</code> |
| L0027 | 计算并保存 &#96;user&#96;（user），供后续逻辑使用，当前位于类 MySQLConfig。 | <code>    user: str = "root"</code> |
| L0028 | 控制当前循环或占位分支的执行流程，当前位于类 MySQLConfig。 | <code>    password: str = "123456"</code> |
| L0029 | 计算并保存 &#96;database&#96;（数据库），供后续逻辑使用，当前位于类 MySQLConfig。 | <code>    database: str = "traffic_pipeline"</code> |
| L0030 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0031 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0032 | 定义读取text函数 &#96;read_text&#96;，封装可复用业务逻辑。 | <code>def read_text(path: Path, default: str = "") -&gt; str:</code> |
| L0033 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_text。 | <code>    if not path.exists():</code> |
| L0034 | 结束当前函数并把结果返回给调用方，当前位于函数 read_text。 | <code>        return default</code> |
| L0035 | 遍历集合中的数据项并逐项处理，当前位于函数 read_text。 | <code>    for enc in ("utf-8", "utf-8-sig", "gbk", "latin1"):</code> |
| L0036 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 read_text。 | <code>        try:</code> |
| L0037 | 结束当前函数并把结果返回给调用方，当前位于函数 read_text。 | <code>            return path.read_text(encoding=enc)</code> |
| L0038 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 read_text。 | <code>        except Exception:</code> |
| L0039 | 控制当前循环或占位分支的执行流程，当前位于函数 read_text。 | <code>            continue</code> |
| L0040 | 结束当前函数并把结果返回给调用方，当前位于函数 read_text。 | <code>    return path.read_text(encoding="utf-8", errors="replace")</code> |
| L0041 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0042 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0043 | 定义读取json函数 &#96;read_json&#96;，封装可复用业务逻辑。 | <code>def read_json(path: Path, default: Dict[str, Any] &#124; None = None) -&gt; Dict[str, Any]:</code> |
| L0044 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_json。 | <code>    if default is None:</code> |
| L0045 | 计算并保存 &#96;default&#96;（default），供后续逻辑使用，当前位于函数 read_json。 | <code>        default = {}</code> |
| L0046 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 read_json。 | <code>    text = read_text(path, default="")</code> |
| L0047 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_json。 | <code>    if not text.strip():</code> |
| L0048 | 结束当前函数并把结果返回给调用方，当前位于函数 read_json。 | <code>        return default</code> |
| L0049 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 read_json。 | <code>    try:</code> |
| L0050 | 计算并保存 &#96;obj&#96;（obj），供后续逻辑使用，当前位于函数 read_json。 | <code>        obj = json.loads(text)</code> |
| L0051 | 结束当前函数并把结果返回给调用方，当前位于函数 read_json。 | <code>        return obj if isinstance(obj, dict) else default</code> |
| L0052 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 read_json。 | <code>    except Exception:</code> |
| L0053 | 结束当前函数并把结果返回给调用方，当前位于函数 read_json。 | <code>        return default</code> |
| L0054 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0055 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0056 | 定义加载manifest函数 &#96;load_manifest&#96;，封装可复用业务逻辑。 | <code>def load_manifest(path: Path) -&gt; Dict[str, Dict[str, Any]]:</code> |
| L0057 | 计算并保存 &#96;mapping&#96;（mapping），供后续逻辑使用，当前位于函数 load_manifest。 | <code>    mapping: Dict[str, Dict[str, Any]] = {}</code> |
| L0058 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 load_manifest。 | <code>    text = read_text(path, default="")</code> |
| L0059 | 遍历集合中的数据项并逐项处理，当前位于函数 load_manifest。 | <code>    for line in text.splitlines():</code> |
| L0060 | 计算并保存 &#96;line&#96;（line），供后续逻辑使用，当前位于函数 load_manifest。 | <code>        line = line.strip()</code> |
| L0061 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_manifest。 | <code>        if not line:</code> |
| L0062 | 控制当前循环或占位分支的执行流程，当前位于函数 load_manifest。 | <code>            continue</code> |
| L0063 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 load_manifest。 | <code>        try:</code> |
| L0064 | 计算并保存 &#96;obj&#96;（obj），供后续逻辑使用，当前位于函数 load_manifest。 | <code>            obj = json.loads(line)</code> |
| L0065 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 load_manifest。 | <code>        except Exception:</code> |
| L0066 | 控制当前循环或占位分支的执行流程，当前位于函数 load_manifest。 | <code>            continue</code> |
| L0067 | 计算并保存 &#96;case_id&#96;（caseid），供后续逻辑使用，当前位于函数 load_manifest。 | <code>        case_id = obj.get("case_id")</code> |
| L0068 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 load_manifest。 | <code>        if isinstance(case_id, str) and case_id:</code> |
| L0069 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_manifest。 | <code>            mapping[case_id] = obj</code> |
| L0070 | 结束当前函数并把结果返回给调用方，当前位于函数 load_manifest。 | <code>    return mapping</code> |
| L0071 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0072 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0073 | 定义firstnonnone函数 &#96;first_non_none&#96;，封装可复用业务逻辑。 | <code>def first_non_none(*vals: Any) -&gt; Any:</code> |
| L0074 | 遍历集合中的数据项并逐项处理，当前位于函数 first_non_none。 | <code>    for v in vals:</code> |
| L0075 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 first_non_none。 | <code>        if v is not None:</code> |
| L0076 | 结束当前函数并把结果返回给调用方，当前位于函数 first_non_none。 | <code>            return v</code> |
| L0077 | 结束当前函数并把结果返回给调用方，当前位于函数 first_non_none。 | <code>    return None</code> |
| L0078 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0079 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0080 | 定义toint函数 &#96;to_int&#96;，封装可复用业务逻辑。 | <code>def to_int(v: Any) -&gt; int &#124; None:</code> |
| L0081 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 to_int。 | <code>    if v is None:</code> |
| L0082 | 结束当前函数并把结果返回给调用方，当前位于函数 to_int。 | <code>        return None</code> |
| L0083 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 to_int。 | <code>    try:</code> |
| L0084 | 结束当前函数并把结果返回给调用方，当前位于函数 to_int。 | <code>        return int(v)</code> |
| L0085 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 to_int。 | <code>    except Exception:</code> |
| L0086 | 结束当前函数并把结果返回给调用方，当前位于函数 to_int。 | <code>        return None</code> |
| L0087 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0088 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0089 | 定义tofloat函数 &#96;to_float&#96;，封装可复用业务逻辑。 | <code>def to_float(v: Any) -&gt; float &#124; None:</code> |
| L0090 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 to_float。 | <code>    if v is None:</code> |
| L0091 | 结束当前函数并把结果返回给调用方，当前位于函数 to_float。 | <code>        return None</code> |
| L0092 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 to_float。 | <code>    try:</code> |
| L0093 | 结束当前函数并把结果返回给调用方，当前位于函数 to_float。 | <code>        return float(v)</code> |
| L0094 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 to_float。 | <code>    except Exception:</code> |
| L0095 | 结束当前函数并把结果返回给调用方，当前位于函数 to_float。 | <code>        return None</code> |
| L0096 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0097 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0098 | 定义标准化ipliteral函数 &#96;normalize_ip_literal&#96;，封装可复用业务逻辑。 | <code>def normalize_ip_literal(value: Any) -&gt; str:</code> |
| L0099 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 normalize_ip_literal。 | <code>    text = str(value or "").strip()</code> |
| L0100 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_ip_literal。 | <code>    if not text:</code> |
| L0101 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_ip_literal。 | <code>        return ""</code> |
| L0102 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 normalize_ip_literal。 | <code>    try:</code> |
| L0103 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_ip_literal。 | <code>        return str(ipaddress.ip_address(text))</code> |
| L0104 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 normalize_ip_literal。 | <code>    except Exception:</code> |
| L0105 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_ip_literal。 | <code>        return ""</code> |
| L0106 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0107 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0108 | 定义ispublicip函数 &#96;is_public_ip&#96;，封装可复用业务逻辑。 | <code>def is_public_ip(ip_text: str) -&gt; bool:</code> |
| L0109 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 is_public_ip。 | <code>    try:</code> |
| L0110 | 计算并保存 &#96;ip_obj&#96;（ipobj），供后续逻辑使用，当前位于函数 is_public_ip。 | <code>        ip_obj = ipaddress.ip_address(ip_text)</code> |
| L0111 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 is_public_ip。 | <code>    except Exception:</code> |
| L0112 | 结束当前函数并把结果返回给调用方，当前位于函数 is_public_ip。 | <code>        return False</code> |
| L0113 | 结束当前函数并把结果返回给调用方，当前位于函数 is_public_ip。 | <code>    return bool(ip_obj.is_global)</code> |
| L0114 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0115 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0116 | 定义标准化攻击typelabel函数 &#96;normalize_attack_type_label&#96;，封装可复用业务逻辑。 | <code>def normalize_attack_type_label(value: Any) -&gt; str:</code> |
| L0117 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 normalize_attack_type_label。 | <code>    raw = str(value or "").strip()</code> |
| L0118 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if not raw:</code> |
| L0119 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "可疑流量"</code> |
| L0120 | 计算并保存 &#96;t&#96;（t），供后续逻辑使用，当前位于函数 normalize_attack_type_label。 | <code>    t = raw.lower().replace(" ", "").replace("_", "").replace("-", "")</code> |
| L0121 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0122 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if any(x in t for x in ["sql", "sqli", "unionselect", "or1=1", "informationschema", "sleep("]):</code> |
| L0123 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "SQL注入"</code> |
| L0124 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if "sql娉" in t or "sql??" in t:</code> |
| L0125 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "SQL注入"</code> |
| L0126 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if "xss" in t or "&lt;script" in t:</code> |
| L0127 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "XSS"</code> |
| L0128 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if "ddos" in t:</code> |
| L0129 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "DDoS"</code> |
| L0130 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if "ssrf" in t:</code> |
| L0131 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "SSRF"</code> |
| L0132 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if "rce" in t or "remotecode" in t or "远程代码" in raw:</code> |
| L0133 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "RCE"</code> |
| L0134 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if any(x in raw for x in ["暴力破解", "爆破", "鏆村姏鐮磋В"]) or "bruteforce" in t:</code> |
| L0135 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "暴力破解"</code> |
| L0136 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if any(x in raw for x in ["端口扫描", "绔彛鎵弿"]) or "portscan" in t or "nmap" in t:</code> |
| L0137 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "端口扫描"</code> |
| L0138 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if any(x in raw for x in ["路径遍历", "璺緞閬嶅巻"]) or "traversal" in t:</code> |
| L0139 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "路径遍历"</code> |
| L0140 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if any(x in raw for x in ["文件上传", "鏂囦欢涓婁紶"]) or "upload" in t:</code> |
| L0141 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "文件上传"</code> |
| L0142 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type_label。 | <code>    if any(x in raw for x in ["命令注入", "鍛戒护娉ㄥ叆"]) or "cmd" in t or "commandinject" in t:</code> |
| L0143 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>        return "命令注入"</code> |
| L0144 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type_label。 | <code>    return "可疑流量"</code> |
| L0145 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0146 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0147 | 定义标准化regionlabel函数 &#96;normalize_region_label&#96;，封装可复用业务逻辑。 | <code>def normalize_region_label(value: Any) -&gt; str:</code> |
| L0148 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 normalize_region_label。 | <code>    raw = str(value or "").strip()</code> |
| L0149 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_region_label。 | <code>    if not raw:</code> |
| L0150 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_region_label。 | <code>        return "未知"</code> |
| L0151 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0152 | 计算并保存 &#96;mapping&#96;（mapping），供后续逻辑使用，当前位于函数 normalize_region_label。 | <code>    mapping = {</code> |
| L0153 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_region_label。 | <code>        "鍖椾含": "北京",</code> |
| L0154 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_region_label。 | <code>        "涓婃捣": "上海",</code> |
| L0155 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_region_label。 | <code>        "骞夸笢": "广东",</code> |
| L0156 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_region_label。 | <code>        "娴欐睙": "浙江",</code> |
| L0157 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_region_label。 | <code>        "姹熻嫃": "江苏",</code> |
| L0158 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_region_label。 | <code>        "灞变笢": "山东",</code> |
| L0159 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_region_label。 | <code>        "娌冲崡": "河南",</code> |
| L0160 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_region_label。 | <code>        "鍥涘窛": "四川",</code> |
| L0161 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_region_label。 | <code>        "棣欐腐": "香港",</code> |
| L0162 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_region_label。 | <code>        "缇庡浗": "美国",</code> |
| L0163 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_region_label。 | <code>        "寰峰浗": "德国",</code> |
| L0164 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_region_label。 | <code>        "鍙枒娴侀噺": "未知",</code> |
| L0165 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_region_label。 | <code>    }</code> |
| L0166 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_region_label。 | <code>    if raw in mapping:</code> |
| L0167 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_region_label。 | <code>        return mapping[raw]</code> |
| L0168 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0169 | 计算并保存 &#96;low&#96;（low），供后续逻辑使用，当前位于函数 normalize_region_label。 | <code>    low = raw.lower()</code> |
| L0170 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_region_label。 | <code>    if low in {"unknown", "n/a", "none", "null", "-", "--"} or "未知" in raw:</code> |
| L0171 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_region_label。 | <code>        return "未知"</code> |
| L0172 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_region_label。 | <code>    if any(x in low for x in ["private", "localhost", "loopback"]) or "内网" in raw:</code> |
| L0173 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_region_label。 | <code>        return "内网"</code> |
| L0174 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_region_label。 | <code>    return raw</code> |
| L0175 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0176 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0177 | 定义http读取json函数 &#96;_http_get_json&#96;，封装可复用业务逻辑。 | <code>def _http_get_json(url: str, timeout_sec: float = 2.5) -&gt; Dict[str, Any]:</code> |
| L0178 | 计算并保存 &#96;req&#96;（req），供后续逻辑使用，当前位于函数 _http_get_json。 | <code>    req = urllib.request.Request(url, headers={"User-Agent": "traffic-pipeline/1.0"})</code> |
| L0179 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 _http_get_json。 | <code>    with urllib.request.urlopen(req, timeout=timeout_sec) as resp:</code> |
| L0180 | 计算并保存 &#96;charset&#96;（charset），供后续逻辑使用，当前位于函数 _http_get_json。 | <code>        charset = "utf-8"</code> |
| L0181 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _http_get_json。 | <code>        try:</code> |
| L0182 | 计算并保存 &#96;charset&#96;（charset），供后续逻辑使用，当前位于函数 _http_get_json。 | <code>            charset = resp.headers.get_content_charset() or "utf-8"</code> |
| L0183 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _http_get_json。 | <code>        except Exception:</code> |
| L0184 | 计算并保存 &#96;charset&#96;（charset），供后续逻辑使用，当前位于函数 _http_get_json。 | <code>            charset = "utf-8"</code> |
| L0185 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 _http_get_json。 | <code>        text = resp.read().decode(charset, errors="replace")</code> |
| L0186 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _http_get_json。 | <code>    try:</code> |
| L0187 | 计算并保存 &#96;obj&#96;（obj），供后续逻辑使用，当前位于函数 _http_get_json。 | <code>        obj = json.loads(text)</code> |
| L0188 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _http_get_json。 | <code>    except Exception:</code> |
| L0189 | 结束当前函数并把结果返回给调用方，当前位于函数 _http_get_json。 | <code>        return {}</code> |
| L0190 | 结束当前函数并把结果返回给调用方，当前位于函数 _http_get_json。 | <code>    return obj if isinstance(obj, dict) else {}</code> |
| L0191 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0192 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0193 | 定义joinregion函数 &#96;_join_region&#96;，封装可复用业务逻辑。 | <code>def _join_region(country: str, region: str, city: str) -&gt; str:</code> |
| L0194 | 计算并保存 &#96;c&#96;（c），供后续逻辑使用，当前位于函数 _join_region。 | <code>    c = str(country or "").strip()</code> |
| L0195 | 计算并保存 &#96;r&#96;（r），供后续逻辑使用，当前位于函数 _join_region。 | <code>    r = str(region or "").strip()</code> |
| L0196 | 计算并保存 &#96;ct&#96;（ct），供后续逻辑使用，当前位于函数 _join_region。 | <code>    ct = str(city or "").strip()</code> |
| L0197 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _join_region。 | <code>    if not c and not r and not ct:</code> |
| L0198 | 结束当前函数并把结果返回给调用方，当前位于函数 _join_region。 | <code>        return "未知"</code> |
| L0199 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _join_region。 | <code>    if c.lower() in {"cn", "china"} or c == "中国":</code> |
| L0200 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _join_region。 | <code>        if r and ct:</code> |
| L0201 | 结束当前函数并把结果返回给调用方，当前位于函数 _join_region。 | <code>            return f"{r}/{ct}"</code> |
| L0202 | 结束当前函数并把结果返回给调用方，当前位于函数 _join_region。 | <code>        return r or ct or "中国"</code> |
| L0203 | 计算并保存 &#96;parts&#96;（parts），供后续逻辑使用，当前位于函数 _join_region。 | <code>    parts = [x for x in [c, r, ct] if x]</code> |
| L0204 | 结束当前函数并把结果返回给调用方，当前位于函数 _join_region。 | <code>    return "/".join(parts) if parts else "未知"</code> |
| L0205 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0206 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0207 | 定义获取regionbyipremote函数 &#96;fetch_region_by_ip_remote&#96;，封装可复用业务逻辑。 | <code>def fetch_region_by_ip_remote(ip_text: str) -&gt; str:</code> |
| L0208 | 计算并保存 &#96;ip_norm&#96;（ipnorm），供后续逻辑使用，当前位于函数 fetch_region_by_ip_remote。 | <code>    ip_norm = normalize_ip_literal(ip_text)</code> |
| L0209 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 fetch_region_by_ip_remote。 | <code>    if not ip_norm:</code> |
| L0210 | 结束当前函数并把结果返回给调用方，当前位于函数 fetch_region_by_ip_remote。 | <code>        return "未知"</code> |
| L0211 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 fetch_region_by_ip_remote。 | <code>    if not is_public_ip(ip_norm):</code> |
| L0212 | 结束当前函数并把结果返回给调用方，当前位于函数 fetch_region_by_ip_remote。 | <code>        return "内网"</code> |
| L0213 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0214 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 fetch_region_by_ip_remote。 | <code>    try:</code> |
| L0215 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 fetch_region_by_ip_remote。 | <code>        data = _http_get_json(f"https://ipwho.is/{ip_norm}")</code> |
| L0216 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 fetch_region_by_ip_remote。 | <code>        if data.get("success") is True:</code> |
| L0217 | 结束当前函数并把结果返回给调用方，当前位于函数 fetch_region_by_ip_remote。 | <code>            return normalize_region_label(</code> |
| L0218 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fetch_region_by_ip_remote。 | <code>                _join_region(data.get("country"), data.get("region"), data.get("city"))</code> |
| L0219 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fetch_region_by_ip_remote。 | <code>            )</code> |
| L0220 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 fetch_region_by_ip_remote。 | <code>    except urllib.error.URLError:</code> |
| L0221 | 控制当前循环或占位分支的执行流程，当前位于函数 fetch_region_by_ip_remote。 | <code>        pass</code> |
| L0222 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 fetch_region_by_ip_remote。 | <code>    except Exception:</code> |
| L0223 | 控制当前循环或占位分支的执行流程，当前位于函数 fetch_region_by_ip_remote。 | <code>        pass</code> |
| L0224 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0225 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 fetch_region_by_ip_remote。 | <code>    try:</code> |
| L0226 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 fetch_region_by_ip_remote。 | <code>        data = _http_get_json(f"http://ip-api.com/json/{ip_norm}?lang=zh-CN")</code> |
| L0227 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 fetch_region_by_ip_remote。 | <code>        if str(data.get("status", "")).lower() == "success":</code> |
| L0228 | 结束当前函数并把结果返回给调用方，当前位于函数 fetch_region_by_ip_remote。 | <code>            return normalize_region_label(</code> |
| L0229 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fetch_region_by_ip_remote。 | <code>                _join_region(data.get("country"), data.get("regionName"), data.get("city"))</code> |
| L0230 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fetch_region_by_ip_remote。 | <code>            )</code> |
| L0231 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 fetch_region_by_ip_remote。 | <code>    except urllib.error.URLError:</code> |
| L0232 | 控制当前循环或占位分支的执行流程，当前位于函数 fetch_region_by_ip_remote。 | <code>        pass</code> |
| L0233 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 fetch_region_by_ip_remote。 | <code>    except Exception:</code> |
| L0234 | 控制当前循环或占位分支的执行流程，当前位于函数 fetch_region_by_ip_remote。 | <code>        pass</code> |
| L0235 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0236 | 结束当前函数并把结果返回给调用方，当前位于函数 fetch_region_by_ip_remote。 | <code>    return "未知"</code> |
| L0237 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0238 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0239 | 定义解析并确定来源regionmysql函数 &#96;resolve_source_region_mysql&#96;，封装可复用业务逻辑。 | <code>def resolve_source_region_mysql(conn: Any, source_ip: str) -&gt; str:</code> |
| L0240 | 计算并保存 &#96;ip_norm&#96;（ipnorm），供后续逻辑使用，当前位于函数 resolve_source_region_mysql。 | <code>    ip_norm = normalize_ip_literal(source_ip)</code> |
| L0241 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_source_region_mysql。 | <code>    if not ip_norm:</code> |
| L0242 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_source_region_mysql。 | <code>        return "未知"</code> |
| L0243 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_source_region_mysql。 | <code>    if not is_public_ip(ip_norm):</code> |
| L0244 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_source_region_mysql。 | <code>        return "内网"</code> |
| L0245 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0246 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 resolve_source_region_mysql。 | <code>    with conn.cursor() as cur:</code> |
| L0247 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 resolve_source_region_mysql。 | <code>        cur.execute("SELECT region FROM ip_geo_cache WHERE ip=%s LIMIT 1", (ip_norm,))</code> |
| L0248 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 resolve_source_region_mysql。 | <code>        row = cur.fetchone() or {}</code> |
| L0249 | 计算并保存 &#96;cached_raw&#96;（cachedraw），供后续逻辑使用，当前位于函数 resolve_source_region_mysql。 | <code>    cached_raw = row.get("region")</code> |
| L0250 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_source_region_mysql。 | <code>    if cached_raw is not None and str(cached_raw).strip():</code> |
| L0251 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_source_region_mysql。 | <code>        return normalize_region_label(cached_raw)</code> |
| L0252 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0253 | 计算并保存 &#96;region&#96;（region），供后续逻辑使用，当前位于函数 resolve_source_region_mysql。 | <code>    region = normalize_region_label(fetch_region_by_ip_remote(ip_norm))</code> |
| L0254 | 计算并保存 &#96;source&#96;（来源），供后续逻辑使用，当前位于函数 resolve_source_region_mysql。 | <code>    source = "remote" if region not in {"未知", "内网"} else "fallback"</code> |
| L0255 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 resolve_source_region_mysql。 | <code>    with conn.cursor() as cur:</code> |
| L0256 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 resolve_source_region_mysql。 | <code>        cur.execute(</code> |
| L0257 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 resolve_source_region_mysql。 | <code>            """</code> |
| L0258 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 resolve_source_region_mysql。 | <code>            INSERT INTO ip_geo_cache(ip, region, source)</code> |
| L0259 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 resolve_source_region_mysql。 | <code>            VALUES (%s, %s, %s)</code> |
| L0260 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 resolve_source_region_mysql。 | <code>            ON DUPLICATE KEY UPDATE</code> |
| L0261 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 resolve_source_region_mysql。 | <code>              region=VALUES(region),</code> |
| L0262 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 resolve_source_region_mysql。 | <code>              source=VALUES(source),</code> |
| L0263 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 resolve_source_region_mysql。 | <code>              updated_at=CURRENT_TIMESTAMP</code> |
| L0264 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 resolve_source_region_mysql。 | <code>            """,</code> |
| L0265 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 resolve_source_region_mysql。 | <code>            (ip_norm, region, source),</code> |
| L0266 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 resolve_source_region_mysql。 | <code>        )</code> |
| L0267 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_source_region_mysql。 | <code>    return region</code> |
| L0268 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0269 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0270 | 定义标准化攻击事件time函数 &#96;normalize_attack_event_time&#96;，封装可复用业务逻辑。 | <code>def normalize_attack_event_time(case_obj: Dict[str, Any], analysis_obj: Dict[str, Any]) -&gt; str &#124; None:</code> |
| L0271 | 计算并保存 &#96;val&#96;（val），供后续逻辑使用，当前位于函数 normalize_attack_event_time。 | <code>    val = first_non_none(</code> |
| L0272 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_attack_event_time。 | <code>        case_obj.get("export_time"),</code> |
| L0273 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_attack_event_time。 | <code>        analysis_obj.get("attack_time"),</code> |
| L0274 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_attack_event_time。 | <code>        analysis_obj.get("analyzed_at"),</code> |
| L0275 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_attack_event_time。 | <code>        case_obj.get("analyzed_at"),</code> |
| L0276 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_attack_event_time。 | <code>    )</code> |
| L0277 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_event_time。 | <code>    if val is None:</code> |
| L0278 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_event_time。 | <code>        return None</code> |
| L0279 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 normalize_attack_event_time。 | <code>    text = str(val).strip()</code> |
| L0280 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_event_time。 | <code>    return text or None</code> |
| L0281 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0282 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0283 | 定义标准化攻击ip函数 &#96;normalize_attack_ip&#96;，封装可复用业务逻辑。 | <code>def normalize_attack_ip(case_obj: Dict[str, Any], analysis_obj: Dict[str, Any]) -&gt; str &#124; None:</code> |
| L0284 | 计算并保存 &#96;val&#96;（val），供后续逻辑使用，当前位于函数 normalize_attack_ip。 | <code>    val = first_non_none(</code> |
| L0285 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_attack_ip。 | <code>        case_obj.get("source_ip"),</code> |
| L0286 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_attack_ip。 | <code>        analysis_obj.get("source_ip"),</code> |
| L0287 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_attack_ip。 | <code>    )</code> |
| L0288 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_ip。 | <code>    if val is None:</code> |
| L0289 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_ip。 | <code>        return None</code> |
| L0290 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 normalize_attack_ip。 | <code>    text = str(val).strip()</code> |
| L0291 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_ip。 | <code>    return text or None</code> |
| L0292 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0293 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0294 | 定义标准化targetinterface函数 &#96;normalize_target_interface&#96;，封装可复用业务逻辑。 | <code>def normalize_target_interface(case_obj: Dict[str, Any], analysis_obj: Dict[str, Any]) -&gt; str &#124; None:</code> |
| L0295 | 计算并保存 &#96;val&#96;（val），供后续逻辑使用，当前位于函数 normalize_target_interface。 | <code>    val = first_non_none(</code> |
| L0296 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_target_interface。 | <code>        case_obj.get("uri"),</code> |
| L0297 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_target_interface。 | <code>        analysis_obj.get("attack_interface"),</code> |
| L0298 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_target_interface。 | <code>    )</code> |
| L0299 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_target_interface。 | <code>    if val is None:</code> |
| L0300 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_target_interface。 | <code>        return None</code> |
| L0301 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 normalize_target_interface。 | <code>    text = str(val).strip()</code> |
| L0302 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_target_interface。 | <code>    return text or None</code> |
| L0303 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0304 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0305 | 定义标准化攻击type函数 &#96;normalize_attack_type&#96;，封装可复用业务逻辑。 | <code>def normalize_attack_type(analysis_obj: Dict[str, Any], case_obj: Dict[str, Any] &#124; None = None) -&gt; str &#124; None:</code> |
| L0306 | 计算并保存 &#96;case_obj&#96;（caseobj），供后续逻辑使用，当前位于函数 normalize_attack_type。 | <code>    case_obj = case_obj or {}</code> |
| L0307 | 计算并保存 &#96;val&#96;（val），供后续逻辑使用，当前位于函数 normalize_attack_type。 | <code>    val = first_non_none(</code> |
| L0308 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_attack_type。 | <code>        case_obj.get("attack_type"),</code> |
| L0309 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_attack_type。 | <code>        case_obj.get("v2_payload_label"),</code> |
| L0310 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_attack_type。 | <code>        analysis_obj.get("attack_method"),</code> |
| L0311 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 normalize_attack_type。 | <code>        analysis_obj.get("verdict"),</code> |
| L0312 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 normalize_attack_type。 | <code>    )</code> |
| L0313 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type。 | <code>    if val is None:</code> |
| L0314 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type。 | <code>        return None</code> |
| L0315 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 normalize_attack_type。 | <code>    text = str(val).strip()</code> |
| L0316 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_attack_type。 | <code>    if "\ufffd" in text:</code> |
| L0317 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type。 | <code>        return None</code> |
| L0318 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_attack_type。 | <code>    return text or None</code> |
| L0319 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0320 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0321 | 定义解析inputsrcipmap函数 &#96;_parse_input_src_ip_map&#96;，封装可复用业务逻辑。 | <code>def _parse_input_src_ip_map(input_file: Path) -&gt; Dict[int, str]:</code> |
| L0322 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 _parse_input_src_ip_map。 | <code>    text = read_text(input_file, default="")</code> |
| L0323 | 计算并保存 &#96;out&#96;（out），供后续逻辑使用，当前位于函数 _parse_input_src_ip_map。 | <code>    out: Dict[int, str] = {}</code> |
| L0324 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _parse_input_src_ip_map。 | <code>    if not text.strip():</code> |
| L0325 | 结束当前函数并把结果返回给调用方，当前位于函数 _parse_input_src_ip_map。 | <code>        return out</code> |
| L0326 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0327 | 计算并保存 &#96;case_blocks&#96;（caseblocks），供后续逻辑使用，当前位于函数 _parse_input_src_ip_map。 | <code>    case_blocks = re.findall(r"### CASE_START ###(.*?)### CASE_END ###", text, flags=re.DOTALL)</code> |
| L0328 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _parse_input_src_ip_map。 | <code>    if case_blocks:</code> |
| L0329 | 遍历集合中的数据项并逐项处理，当前位于函数 _parse_input_src_ip_map。 | <code>        for block in case_blocks:</code> |
| L0330 | 计算并保存 &#96;seq_m&#96;（seqm），供后续逻辑使用，当前位于函数 _parse_input_src_ip_map。 | <code>            seq_m = re.search(r"(?mi)^seq_id=(\d+)\s*$", block)</code> |
| L0331 | 计算并保存 &#96;src_m&#96;（srcm），供后续逻辑使用，当前位于函数 _parse_input_src_ip_map。 | <code>            src_m = re.search(r"(?mi)^src_ip=([^\r\n]+)\s*$", block)</code> |
| L0332 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _parse_input_src_ip_map。 | <code>            if not src_m:</code> |
| L0333 | 控制当前循环或占位分支的执行流程，当前位于函数 _parse_input_src_ip_map。 | <code>                continue</code> |
| L0334 | 计算并保存 &#96;src_ip&#96;（srcip），供后续逻辑使用，当前位于函数 _parse_input_src_ip_map。 | <code>            src_ip = normalize_ip_literal(src_m.group(1))</code> |
| L0335 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _parse_input_src_ip_map。 | <code>            if not src_ip:</code> |
| L0336 | 控制当前循环或占位分支的执行流程，当前位于函数 _parse_input_src_ip_map。 | <code>                continue</code> |
| L0337 | 计算并保存 &#96;seq_id&#96;（seqid），供后续逻辑使用，当前位于函数 _parse_input_src_ip_map。 | <code>            seq_id = int(seq_m.group(1)) if seq_m else (len(out) + 1)</code> |
| L0338 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _parse_input_src_ip_map。 | <code>            out[seq_id] = src_ip</code> |
| L0339 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _parse_input_src_ip_map。 | <code>        if out:</code> |
| L0340 | 结束当前函数并把结果返回给调用方，当前位于函数 _parse_input_src_ip_map。 | <code>            return out</code> |
| L0341 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0342 | 计算并保存 &#96;src_m&#96;（srcm），供后续逻辑使用，当前位于函数 _parse_input_src_ip_map。 | <code>    src_m = re.search(r"(?mi)^src_ip=([^\r\n]+)\s*$", text)</code> |
| L0343 | 计算并保存 &#96;src_ip&#96;（srcip），供后续逻辑使用，当前位于函数 _parse_input_src_ip_map。 | <code>    src_ip = normalize_ip_literal(src_m.group(1)) if src_m else ""</code> |
| L0344 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _parse_input_src_ip_map。 | <code>    if src_ip:</code> |
| L0345 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _parse_input_src_ip_map。 | <code>        out[1] = src_ip</code> |
| L0346 | 结束当前函数并把结果返回给调用方，当前位于函数 _parse_input_src_ip_map。 | <code>    return out</code> |
| L0347 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0348 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0349 | 定义来源ipfrominputfile函数 &#96;_source_ip_from_input_file&#96;，封装可复用业务逻辑。 | <code>def _source_ip_from_input_file(</code> |
| L0350 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _source_ip_from_input_file。 | <code>    input_dir: Path,</code> |
| L0351 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _source_ip_from_input_file。 | <code>    file_id: str,</code> |
| L0352 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _source_ip_from_input_file。 | <code>    seq_id: int &#124; None,</code> |
| L0353 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _source_ip_from_input_file。 | <code>    cache: Dict[str, Dict[int, str]],</code> |
| L0354 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _source_ip_from_input_file。 | <code>) -&gt; str:</code> |
| L0355 | 计算并保存 &#96;fid&#96;（fid），供后续逻辑使用，当前位于函数 _source_ip_from_input_file。 | <code>    fid = str(file_id or "").strip()</code> |
| L0356 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _source_ip_from_input_file。 | <code>    if not fid:</code> |
| L0357 | 结束当前函数并把结果返回给调用方，当前位于函数 _source_ip_from_input_file。 | <code>        return ""</code> |
| L0358 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _source_ip_from_input_file。 | <code>    if fid not in cache:</code> |
| L0359 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _source_ip_from_input_file。 | <code>        cache[fid] = _parse_input_src_ip_map(input_dir / f"{fid}.txt")</code> |
| L0360 | 计算并保存 &#96;seq_map&#96;（seqmap），供后续逻辑使用，当前位于函数 _source_ip_from_input_file。 | <code>    seq_map = cache.get(fid) or {}</code> |
| L0361 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _source_ip_from_input_file。 | <code>    if not seq_map:</code> |
| L0362 | 结束当前函数并把结果返回给调用方，当前位于函数 _source_ip_from_input_file。 | <code>        return ""</code> |
| L0363 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _source_ip_from_input_file。 | <code>    if seq_id is not None and seq_id in seq_map:</code> |
| L0364 | 结束当前函数并把结果返回给调用方，当前位于函数 _source_ip_from_input_file。 | <code>        return seq_map[seq_id]</code> |
| L0365 | 结束当前函数并把结果返回给调用方，当前位于函数 _source_ip_from_input_file。 | <code>    return seq_map.get(1, "")</code> |
| L0366 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0367 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0368 | 定义解析并确定来源ipforcase函数 &#96;resolve_source_ip_for_case&#96;，封装可复用业务逻辑。 | <code>def resolve_source_ip_for_case(</code> |
| L0369 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 resolve_source_ip_for_case。 | <code>    case_obj: Dict[str, Any],</code> |
| L0370 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 resolve_source_ip_for_case。 | <code>    analysis_obj: Dict[str, Any],</code> |
| L0371 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 resolve_source_ip_for_case。 | <code>    request_content: str,</code> |
| L0372 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 resolve_source_ip_for_case。 | <code>    request_summary: str,</code> |
| L0373 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 resolve_source_ip_for_case。 | <code>    input_dir: Path,</code> |
| L0374 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 resolve_source_ip_for_case。 | <code>    file_id: str,</code> |
| L0375 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 resolve_source_ip_for_case。 | <code>    seq_id: int &#124; None,</code> |
| L0376 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 resolve_source_ip_for_case。 | <code>    input_ip_cache: Dict[str, Dict[int, str]],</code> |
| L0377 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 resolve_source_ip_for_case。 | <code>) -&gt; str:</code> |
| L0378 | 计算并保存 &#96;src&#96;（src），供后续逻辑使用，当前位于函数 resolve_source_ip_for_case。 | <code>    src = normalize_ip_literal(normalize_attack_ip(case_obj, analysis_obj))</code> |
| L0379 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_source_ip_for_case。 | <code>    if src:</code> |
| L0380 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_source_ip_for_case。 | <code>        return src</code> |
| L0381 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0382 | 计算并保存 &#96;merged&#96;（merged），供后续逻辑使用，当前位于函数 resolve_source_ip_for_case。 | <code>    merged = "\n".join([request_content or "", request_summary or ""])</code> |
| L0383 | 计算并保存 &#96;patterns&#96;（patterns），供后续逻辑使用，当前位于函数 resolve_source_ip_for_case。 | <code>    patterns = [</code> |
| L0384 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 resolve_source_ip_for_case。 | <code>        r"(?mi)^src_ip=([^\r\n]+)",</code> |
| L0385 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 resolve_source_ip_for_case。 | <code>        r"(?mi)\bsrc(?:_&#124; )?ip[:=]\s*([0-9a-fA-F:.]+)",</code> |
| L0386 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 resolve_source_ip_for_case。 | <code>    ]</code> |
| L0387 | 遍历集合中的数据项并逐项处理，当前位于函数 resolve_source_ip_for_case。 | <code>    for pat in patterns:</code> |
| L0388 | 遍历集合中的数据项并逐项处理，当前位于函数 resolve_source_ip_for_case。 | <code>        for m in re.finditer(pat, merged):</code> |
| L0389 | 计算并保存 &#96;ip_text&#96;（iptext），供后续逻辑使用，当前位于函数 resolve_source_ip_for_case。 | <code>            ip_text = normalize_ip_literal(m.group(1))</code> |
| L0390 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_source_ip_for_case。 | <code>            if ip_text:</code> |
| L0391 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_source_ip_for_case。 | <code>                return ip_text</code> |
| L0392 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0393 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_source_ip_for_case。 | <code>    return _source_ip_from_input_file(input_dir, file_id, seq_id, input_ip_cache)</code> |
| L0394 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0395 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0396 | 定义解析mysqldatetime函数 &#96;parse_mysql_datetime&#96;，封装可复用业务逻辑。 | <code>def parse_mysql_datetime(v: Any) -&gt; datetime:</code> |
| L0397 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_mysql_datetime。 | <code>    if v is None:</code> |
| L0398 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_mysql_datetime。 | <code>        return datetime.now()</code> |
| L0399 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 parse_mysql_datetime。 | <code>    text = str(v).strip()</code> |
| L0400 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_mysql_datetime。 | <code>    if not text:</code> |
| L0401 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_mysql_datetime。 | <code>        return datetime.now()</code> |
| L0402 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0403 | 计算并保存 &#96;normalized&#96;（normalized），供后续逻辑使用，当前位于函数 parse_mysql_datetime。 | <code>    normalized = text.replace("T", " ").replace("Z", "")</code> |
| L0404 | 计算并保存 &#96;normalized&#96;（normalized），供后续逻辑使用，当前位于函数 parse_mysql_datetime。 | <code>    normalized = re.sub(r"[+-]\d{2}:\d{2}$", "", normalized).strip()</code> |
| L0405 | 遍历集合中的数据项并逐项处理，当前位于函数 parse_mysql_datetime。 | <code>    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):</code> |
| L0406 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 parse_mysql_datetime。 | <code>        try:</code> |
| L0407 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_mysql_datetime。 | <code>            return datetime.strptime(normalized, fmt)</code> |
| L0408 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 parse_mysql_datetime。 | <code>        except Exception:</code> |
| L0409 | 控制当前循环或占位分支的执行流程，当前位于函数 parse_mysql_datetime。 | <code>            continue</code> |
| L0410 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_mysql_datetime。 | <code>    return datetime.now()</code> |
| L0411 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0412 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0413 | 定义infer攻击typetext函数 &#96;infer_attack_type_text&#96;，封装可复用业务逻辑。 | <code>def infer_attack_type_text(analysis_obj: Dict[str, Any], request_row: Dict[str, Any], request_content: str) -&gt; str:</code> |
| L0414 | 遍历集合中的数据项并逐项处理，当前位于函数 infer_attack_type_text。 | <code>    for key in ("attack_type", "attack_method", "verdict"):</code> |
| L0415 | 计算并保存 &#96;val&#96;（val），供后续逻辑使用，当前位于函数 infer_attack_type_text。 | <code>        val = str(analysis_obj.get(key) or "").strip()</code> |
| L0416 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 infer_attack_type_text。 | <code>        if val:</code> |
| L0417 | 结束当前函数并把结果返回给调用方，当前位于函数 infer_attack_type_text。 | <code>            return normalize_attack_type_label(val)</code> |
| L0418 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0419 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 infer_attack_type_text。 | <code>    text = "\n".join(</code> |
| L0420 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type_text。 | <code>        [</code> |
| L0421 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type_text。 | <code>            str(request_row.get("uri") or ""),</code> |
| L0422 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type_text。 | <code>            str(request_row.get("request_text_summary") or ""),</code> |
| L0423 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type_text。 | <code>            str(request_content or ""),</code> |
| L0424 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 infer_attack_type_text。 | <code>        ]</code> |
| L0425 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 infer_attack_type_text。 | <code>    ).lower()</code> |
| L0426 | 计算并保存 &#96;rules&#96;（rules），供后续逻辑使用，当前位于函数 infer_attack_type_text。 | <code>    rules = [</code> |
| L0427 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type_text。 | <code>        (</code> |
| L0428 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type_text。 | <code>            r"(?:\bor\b\s+1=1&#124;union\s+select&#124;information_schema&#124;sleep\(&#124;benchmark\(&#124;ascii\s*\(&#124;substr\s*\(&#124;database\s*\(&#124;\band\b.+--&#124;'\s*or\s*'?\d)",</code> |
| L0429 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type_text。 | <code>            "\u0053\u0051\u004c\u6ce8\u5165",</code> |
| L0430 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 infer_attack_type_text。 | <code>        ),</code> |
| L0431 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type_text。 | <code>        (r"(&lt;script&#124;javascript:&#124;onerror=&#124;onload=)", "XSS"),</code> |
| L0432 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type_text。 | <code>        (r"(\.\./&#124;\.\.\\&#124;/etc/passwd&#124;\\windows\\system32)", "\u8def\u5f84\u904d\u5386"),</code> |
| L0433 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type_text。 | <code>        (r"(cmd\.exe&#124;/bin/sh&#124;powershell&#124;;\s*cat\s+)", "\u547d\u4ee4\u6ce8\u5165"),</code> |
| L0434 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type_text。 | <code>        (r"(multipart/form-data&#124;\.php&#124;\.jsp&#124;\.aspx)", "\u6587\u4ef6\u4e0a\u4f20"),</code> |
| L0435 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 infer_attack_type_text。 | <code>        (r"(scan&#124;masscan&#124;nmap)", "\u7aef\u53e3\u626b\u63cf"),</code> |
| L0436 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 infer_attack_type_text。 | <code>    ]</code> |
| L0437 | 遍历集合中的数据项并逐项处理，当前位于函数 infer_attack_type_text。 | <code>    for pattern, label in rules:</code> |
| L0438 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 infer_attack_type_text。 | <code>        if re.search(pattern, text, re.I):</code> |
| L0439 | 结束当前函数并把结果返回给调用方，当前位于函数 infer_attack_type_text。 | <code>            return normalize_attack_type_label(label)</code> |
| L0440 | 结束当前函数并把结果返回给调用方，当前位于函数 infer_attack_type_text。 | <code>    return "\u53ef\u7591\u6d41\u91cf"</code> |
| L0441 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0442 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0443 | 定义inferrisklevel函数 &#96;infer_risk_level&#96;，封装可复用业务逻辑。 | <code>def infer_risk_level(analysis_obj: Dict[str, Any], request_row: Dict[str, Any]) -&gt; str:</code> |
| L0444 | 计算并保存 &#96;sev&#96;（sev），供后续逻辑使用，当前位于函数 infer_risk_level。 | <code>    sev = str(analysis_obj.get("severity") or "").strip().lower()</code> |
| L0445 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 infer_risk_level。 | <code>    if sev in {"critical", "high", "medium", "low"}:</code> |
| L0446 | 结束当前函数并把结果返回给调用方，当前位于函数 infer_risk_level。 | <code>        return "high" if sev == "critical" else sev</code> |
| L0447 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0448 | 计算并保存 &#96;conf&#96;（conf），供后续逻辑使用，当前位于函数 infer_risk_level。 | <code>    conf = to_float(analysis_obj.get("confidence"))</code> |
| L0449 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 infer_risk_level。 | <code>    if conf is None:</code> |
| L0450 | 计算并保存 &#96;conf&#96;（conf），供后续逻辑使用，当前位于函数 infer_risk_level。 | <code>        conf = to_float(request_row.get("raw_score"))</code> |
| L0451 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 infer_risk_level。 | <code>    if conf is None:</code> |
| L0452 | 计算并保存 &#96;conf&#96;（conf），供后续逻辑使用，当前位于函数 infer_risk_level。 | <code>        conf = 0.0</code> |
| L0453 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0454 | 计算并保存 &#96;label&#96;（label），供后续逻辑使用，当前位于函数 infer_risk_level。 | <code>    label = str(request_row.get("label") or "").strip().lower()</code> |
| L0455 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 infer_risk_level。 | <code>    if conf &gt;= 0.8:</code> |
| L0456 | 结束当前函数并把结果返回给调用方，当前位于函数 infer_risk_level。 | <code>        return "high"</code> |
| L0457 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 infer_risk_level。 | <code>    if conf &gt;= 0.45 or label == "suspicious":</code> |
| L0458 | 结束当前函数并把结果返回给调用方，当前位于函数 infer_risk_level。 | <code>        return "medium"</code> |
| L0459 | 结束当前函数并把结果返回给调用方，当前位于函数 infer_risk_level。 | <code>    return "low"</code> |
| L0460 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0461 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0462 | 定义infer攻击结果函数 &#96;infer_attack_result&#96;，封装可复用业务逻辑。 | <code>def infer_attack_result(status_code: int &#124; None) -&gt; str:</code> |
| L0463 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 infer_attack_result。 | <code>    if status_code is None:</code> |
| L0464 | 结束当前函数并把结果返回给调用方，当前位于函数 infer_attack_result。 | <code>        return "success"</code> |
| L0465 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 infer_attack_result。 | <code>    if status_code in {401, 403, 404, 406, 409, 429}:</code> |
| L0466 | 结束当前函数并把结果返回给调用方，当前位于函数 infer_attack_result。 | <code>        return "blocked"</code> |
| L0467 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 infer_attack_result。 | <code>    if status_code &gt;= 500:</code> |
| L0468 | 结束当前函数并把结果返回给调用方，当前位于函数 infer_attack_result。 | <code>        return "blocked"</code> |
| L0469 | 结束当前函数并把结果返回给调用方，当前位于函数 infer_attack_result。 | <code>    return "success"</code> |
| L0470 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0471 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0472 | 定义校验mysqlidentifier函数 &#96;validate_mysql_identifier&#96;，封装可复用业务逻辑。 | <code>def validate_mysql_identifier(name: str) -&gt; str:</code> |
| L0473 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 validate_mysql_identifier。 | <code>    if not re.fullmatch(r"[A-Za-z0-9_]+", name):</code> |
| L0474 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 validate_mysql_identifier。 | <code>        raise ValueError(f"invalid mysql database name: {name}")</code> |
| L0475 | 结束当前函数并把结果返回给调用方，当前位于函数 validate_mysql_identifier。 | <code>    return name</code> |
| L0476 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0477 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0478 | 定义ensurepymysqlavailable函数 &#96;ensure_pymysql_available&#96;，封装可复用业务逻辑。 | <code>def ensure_pymysql_available() -&gt; None:</code> |
| L0479 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_pymysql_available。 | <code>    if pymysql is None:</code> |
| L0480 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 ensure_pymysql_available。 | <code>        raise RuntimeError("PyMySQL is required for MySQL backend. Run: python -m pip install PyMySQL")</code> |
| L0481 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0482 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0483 | 定义connectsqlite函数 &#96;connect_sqlite&#96;，封装可复用业务逻辑。 | <code>def connect_sqlite(db_path: Path) -&gt; sqlite3.Connection:</code> |
| L0484 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 connect_sqlite。 | <code>    db_path.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0485 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 connect_sqlite。 | <code>    conn = sqlite3.connect(str(db_path))</code> |
| L0486 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 connect_sqlite。 | <code>    conn.row_factory = sqlite3.Row</code> |
| L0487 | 结束当前函数并把结果返回给调用方，当前位于函数 connect_sqlite。 | <code>    return conn</code> |
| L0488 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0489 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0490 | 定义connectmysql函数 &#96;connect_mysql&#96;，封装可复用业务逻辑。 | <code>def connect_mysql(cfg: MySQLConfig):</code> |
| L0491 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 connect_mysql。 | <code>    ensure_pymysql_available()</code> |
| L0492 | 计算并保存 &#96;db_name&#96;（数据库name），供后续逻辑使用，当前位于函数 connect_mysql。 | <code>    db_name = validate_mysql_identifier(cfg.database)</code> |
| L0493 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0494 | 计算并保存 &#96;bootstrap_conn&#96;（bootstrapconn），供后续逻辑使用，当前位于函数 connect_mysql。 | <code>    bootstrap_conn = pymysql.connect(</code> |
| L0495 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 connect_mysql。 | <code>        host=cfg.host,</code> |
| L0496 | 计算并保存 &#96;port&#96;（port），供后续逻辑使用，当前位于函数 connect_mysql。 | <code>        port=cfg.port,</code> |
| L0497 | 计算并保存 &#96;user&#96;（user），供后续逻辑使用，当前位于函数 connect_mysql。 | <code>        user=cfg.user,</code> |
| L0498 | 控制当前循环或占位分支的执行流程，当前位于函数 connect_mysql。 | <code>        password=cfg.password,</code> |
| L0499 | 计算并保存 &#96;charset&#96;（charset），供后续逻辑使用，当前位于函数 connect_mysql。 | <code>        charset="utf8mb4",</code> |
| L0500 | 计算并保存 &#96;autocommit&#96;（autocommit），供后续逻辑使用，当前位于函数 connect_mysql。 | <code>        autocommit=False,</code> |
| L0501 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 connect_mysql。 | <code>    )</code> |
| L0502 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 connect_mysql。 | <code>    try:</code> |
| L0503 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 connect_mysql。 | <code>        with bootstrap_conn.cursor() as cur:</code> |
| L0504 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 connect_mysql。 | <code>            cur.execute(</code> |
| L0505 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 connect_mysql。 | <code>                f"CREATE DATABASE IF NOT EXISTS &#96;{db_name}&#96; "</code> |
| L0506 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 connect_mysql。 | <code>                "DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"</code> |
| L0507 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 connect_mysql。 | <code>            )</code> |
| L0508 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 connect_mysql。 | <code>        bootstrap_conn.commit()</code> |
| L0509 | 无论成功或异常都执行资源清理，当前位于函数 connect_mysql。 | <code>    finally:</code> |
| L0510 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 connect_mysql。 | <code>        bootstrap_conn.close()</code> |
| L0511 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0512 | 结束当前函数并把结果返回给调用方，当前位于函数 connect_mysql。 | <code>    return pymysql.connect(</code> |
| L0513 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 connect_mysql。 | <code>        host=cfg.host,</code> |
| L0514 | 计算并保存 &#96;port&#96;（port），供后续逻辑使用，当前位于函数 connect_mysql。 | <code>        port=cfg.port,</code> |
| L0515 | 计算并保存 &#96;user&#96;（user），供后续逻辑使用，当前位于函数 connect_mysql。 | <code>        user=cfg.user,</code> |
| L0516 | 控制当前循环或占位分支的执行流程，当前位于函数 connect_mysql。 | <code>        password=cfg.password,</code> |
| L0517 | 计算并保存 &#96;database&#96;（数据库），供后续逻辑使用，当前位于函数 connect_mysql。 | <code>        database=db_name,</code> |
| L0518 | 计算并保存 &#96;charset&#96;（charset），供后续逻辑使用，当前位于函数 connect_mysql。 | <code>        charset="utf8mb4",</code> |
| L0519 | 计算并保存 &#96;cursorclass&#96;（cursorclass），供后续逻辑使用，当前位于函数 connect_mysql。 | <code>        cursorclass=DictCursor,</code> |
| L0520 | 计算并保存 &#96;autocommit&#96;（autocommit），供后续逻辑使用，当前位于函数 connect_mysql。 | <code>        autocommit=False,</code> |
| L0521 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 connect_mysql。 | <code>    )</code> |
| L0522 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0523 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0524 | 定义ensureschemasqlite函数 &#96;ensure_schema_sqlite&#96;，封装可复用业务逻辑。 | <code>def ensure_schema_sqlite(conn: sqlite3.Connection) -&gt; None:</code> |
| L0525 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema_sqlite。 | <code>    conn.executescript(</code> |
| L0526 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>        """</code> |
| L0527 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>        PRAGMA journal_mode = WAL;</code> |
| L0528 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0529 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema_sqlite。 | <code>        CREATE TABLE IF NOT EXISTS requests (</code> |
| L0530 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          case_id TEXT PRIMARY KEY,</code> |
| L0531 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          file_id TEXT,</code> |
| L0532 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          seq_id INTEGER,</code> |
| L0533 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          rank_no INTEGER,</code> |
| L0534 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          raw_score REAL,</code> |
| L0535 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          norm_score REAL,</code> |
| L0536 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          label TEXT,</code> |
| L0537 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          method TEXT,</code> |
| L0538 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          uri TEXT,</code> |
| L0539 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          host TEXT,</code> |
| L0540 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          status_code INTEGER,</code> |
| L0541 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          request_text_summary TEXT,</code> |
| L0542 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          request_content TEXT,</code> |
| L0543 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          export_time TEXT,</code> |
| L0544 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),</code> |
| L0545 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))</code> |
| L0546 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>        );</code> |
| L0547 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0548 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema_sqlite。 | <code>        CREATE TABLE IF NOT EXISTS responses (</code> |
| L0549 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          case_id TEXT PRIMARY KEY,</code> |
| L0550 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          file_id TEXT,</code> |
| L0551 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          seq_id INTEGER,</code> |
| L0552 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          status_code INTEGER,</code> |
| L0553 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          response_content TEXT,</code> |
| L0554 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          export_time TEXT,</code> |
| L0555 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),</code> |
| L0556 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))</code> |
| L0557 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>        );</code> |
| L0558 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0559 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema_sqlite。 | <code>        CREATE TABLE IF NOT EXISTS analyses (</code> |
| L0560 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          case_id TEXT PRIMARY KEY,</code> |
| L0561 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          file_id TEXT,</code> |
| L0562 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          seq_id INTEGER,</code> |
| L0563 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          llm_status TEXT,</code> |
| L0564 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          llm_error TEXT,</code> |
| L0565 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          llm_started_at TEXT,</code> |
| L0566 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          llm_failed_at TEXT,</code> |
| L0567 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          analyzed_at TEXT,</code> |
| L0568 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          model_name TEXT,</code> |
| L0569 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          verdict TEXT,</code> |
| L0570 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          source_ip TEXT,</code> |
| L0571 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          destination_ip TEXT,</code> |
| L0572 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          attack_interface TEXT,</code> |
| L0573 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          attack_method TEXT,</code> |
| L0574 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          attack_path TEXT,</code> |
| L0575 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          attack_time TEXT,</code> |
| L0576 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          severity TEXT,</code> |
| L0577 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          confidence REAL,</code> |
| L0578 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          summary TEXT,</code> |
| L0579 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          evidence_json TEXT,</code> |
| L0580 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          analysis_raw TEXT,</code> |
| L0581 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          attack_event_time TEXT,</code> |
| L0582 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          attack_ip TEXT,</code> |
| L0583 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          target_interface TEXT,</code> |
| L0584 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          attack_type TEXT,</code> |
| L0585 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          attack_confidence REAL,</code> |
| L0586 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),</code> |
| L0587 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>          updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))</code> |
| L0588 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>        );</code> |
| L0589 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0590 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>        CREATE INDEX IF NOT EXISTS idx_requests_file_seq ON requests(file_id, seq_id);</code> |
| L0591 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>        CREATE INDEX IF NOT EXISTS idx_responses_file_seq ON responses(file_id, seq_id);</code> |
| L0592 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>        CREATE INDEX IF NOT EXISTS idx_analyses_file_seq ON analyses(file_id, seq_id);</code> |
| L0593 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>        CREATE INDEX IF NOT EXISTS idx_analyses_llm_status ON analyses(llm_status);</code> |
| L0594 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_sqlite。 | <code>        """</code> |
| L0595 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ensure_schema_sqlite。 | <code>    )</code> |
| L0596 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema_sqlite。 | <code>    _ensure_sqlite_columns(</code> |
| L0597 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema_sqlite。 | <code>        conn,</code> |
| L0598 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema_sqlite。 | <code>        "analyses",</code> |
| L0599 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema_sqlite。 | <code>        [</code> |
| L0600 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema_sqlite。 | <code>            ("attack_event_time", "TEXT"),</code> |
| L0601 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema_sqlite。 | <code>            ("attack_ip", "TEXT"),</code> |
| L0602 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema_sqlite。 | <code>            ("target_interface", "TEXT"),</code> |
| L0603 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema_sqlite。 | <code>            ("attack_type", "TEXT"),</code> |
| L0604 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ensure_schema_sqlite。 | <code>            ("attack_confidence", "REAL"),</code> |
| L0605 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ensure_schema_sqlite。 | <code>        ],</code> |
| L0606 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ensure_schema_sqlite。 | <code>    )</code> |
| L0607 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0608 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0609 | 定义ensuresqlitecolumns函数 &#96;_ensure_sqlite_columns&#96;，封装可复用业务逻辑。 | <code>def _ensure_sqlite_columns(conn: sqlite3.Connection, table: str, column_defs: List[tuple[str, str]]) -&gt; None:</code> |
| L0610 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 _ensure_sqlite_columns。 | <code>    existing = {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}</code> |
| L0611 | 遍历集合中的数据项并逐项处理，当前位于函数 _ensure_sqlite_columns。 | <code>    for col_name, col_type in column_defs:</code> |
| L0612 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _ensure_sqlite_columns。 | <code>        if col_name in existing:</code> |
| L0613 | 控制当前循环或占位分支的执行流程，当前位于函数 _ensure_sqlite_columns。 | <code>            continue</code> |
| L0614 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 _ensure_sqlite_columns。 | <code>        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}")</code> |
| L0615 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0616 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0617 | 定义ensureschemamysql函数 &#96;ensure_schema_mysql&#96;，封装可复用业务逻辑。 | <code>def ensure_schema_mysql(conn: Any) -&gt; None:</code> |
| L0618 | 计算并保存 &#96;ddl_list&#96;（ddl列出），供后续逻辑使用，当前位于函数 ensure_schema_mysql。 | <code>    ddl_list = [</code> |
| L0619 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>        """</code> |
| L0620 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema_mysql。 | <code>        CREATE TABLE IF NOT EXISTS requests (</code> |
| L0621 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          case_id VARCHAR(64) PRIMARY KEY,</code> |
| L0622 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          file_id VARCHAR(128) NULL,</code> |
| L0623 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          seq_id INT NULL,</code> |
| L0624 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          rank_no INT NULL,</code> |
| L0625 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          raw_score DOUBLE NULL,</code> |
| L0626 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          norm_score DOUBLE NULL,</code> |
| L0627 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          label VARCHAR(64) NULL,</code> |
| L0628 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          method VARCHAR(16) NULL,</code> |
| L0629 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          uri TEXT NULL,</code> |
| L0630 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          host VARCHAR(255) NULL,</code> |
| L0631 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          status_code INT NULL,</code> |
| L0632 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          request_text_summary LONGTEXT NULL,</code> |
| L0633 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          request_content LONGTEXT NULL,</code> |
| L0634 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          export_time VARCHAR(64) NULL,</code> |
| L0635 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0636 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema_mysql。 | <code>          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,</code> |
| L0637 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          KEY idx_requests_file_seq (file_id, seq_id)</code> |
| L0638 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L0639 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>        """,</code> |
| L0640 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>        """</code> |
| L0641 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema_mysql。 | <code>        CREATE TABLE IF NOT EXISTS responses (</code> |
| L0642 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          case_id VARCHAR(64) PRIMARY KEY,</code> |
| L0643 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          file_id VARCHAR(128) NULL,</code> |
| L0644 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          seq_id INT NULL,</code> |
| L0645 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          status_code INT NULL,</code> |
| L0646 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          response_content LONGTEXT NULL,</code> |
| L0647 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          export_time VARCHAR(64) NULL,</code> |
| L0648 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0649 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema_mysql。 | <code>          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,</code> |
| L0650 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          KEY idx_responses_file_seq (file_id, seq_id)</code> |
| L0651 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L0652 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>        """,</code> |
| L0653 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>        """</code> |
| L0654 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema_mysql。 | <code>        CREATE TABLE IF NOT EXISTS analyses (</code> |
| L0655 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          case_id VARCHAR(64) PRIMARY KEY,</code> |
| L0656 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          file_id VARCHAR(128) NULL,</code> |
| L0657 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          seq_id INT NULL,</code> |
| L0658 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          llm_status VARCHAR(32) NULL,</code> |
| L0659 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          llm_error TEXT NULL,</code> |
| L0660 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          llm_started_at VARCHAR(64) NULL,</code> |
| L0661 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          llm_failed_at VARCHAR(64) NULL,</code> |
| L0662 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          analyzed_at VARCHAR(64) NULL,</code> |
| L0663 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          model_name VARCHAR(255) NULL,</code> |
| L0664 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          verdict VARCHAR(64) NULL,</code> |
| L0665 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          source_ip VARCHAR(64) NULL,</code> |
| L0666 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          destination_ip VARCHAR(64) NULL,</code> |
| L0667 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          attack_interface TEXT NULL,</code> |
| L0668 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          attack_method LONGTEXT NULL,</code> |
| L0669 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          attack_path TEXT NULL,</code> |
| L0670 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          attack_time VARCHAR(64) NULL,</code> |
| L0671 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          severity VARCHAR(64) NULL,</code> |
| L0672 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          confidence DOUBLE NULL,</code> |
| L0673 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          summary LONGTEXT NULL,</code> |
| L0674 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          evidence_json LONGTEXT NULL,</code> |
| L0675 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          analysis_raw LONGTEXT NULL,</code> |
| L0676 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          attack_event_time VARCHAR(64) NULL,</code> |
| L0677 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          attack_ip VARCHAR(64) NULL,</code> |
| L0678 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          target_interface TEXT NULL,</code> |
| L0679 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          attack_type VARCHAR(255) NULL,</code> |
| L0680 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          attack_confidence DOUBLE NULL,</code> |
| L0681 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0682 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema_mysql。 | <code>          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,</code> |
| L0683 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          KEY idx_analyses_file_seq (file_id, seq_id),</code> |
| L0684 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          KEY idx_analyses_llm_status (llm_status)</code> |
| L0685 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L0686 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>        """,</code> |
| L0687 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>        """</code> |
| L0688 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema_mysql。 | <code>        CREATE TABLE IF NOT EXISTS demo_attack_events (</code> |
| L0689 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          event_id VARCHAR(40) PRIMARY KEY,</code> |
| L0690 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          occurred_at DATETIME(3) NOT NULL,</code> |
| L0691 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          risk_level VARCHAR(16) NOT NULL,</code> |
| L0692 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          attack_type VARCHAR(64) NOT NULL,</code> |
| L0693 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          source_ip VARCHAR(64) NOT NULL,</code> |
| L0694 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          source_region VARCHAR(64) NOT NULL,</code> |
| L0695 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          target_node VARCHAR(64) NOT NULL,</code> |
| L0696 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          target_port INT NULL,</code> |
| L0697 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          target_interface TEXT NOT NULL,</code> |
| L0698 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          attack_result VARCHAR(16) NOT NULL,</code> |
| L0699 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          process_status VARCHAR(16) NOT NULL DEFAULT 'unprocessed',</code> |
| L0700 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          acked TINYINT(1) NOT NULL DEFAULT 0,</code> |
| L0701 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          attack_payload LONGTEXT NULL,</code> |
| L0702 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          request_log LONGTEXT NULL,</code> |
| L0703 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          protection_action TEXT NULL,</code> |
| L0704 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          handling_suggestion TEXT NULL,</code> |
| L0705 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          note TEXT NULL,</code> |
| L0706 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          response_ms INT NOT NULL DEFAULT 0,</code> |
| L0707 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          anomaly_detected TINYINT(1) NOT NULL DEFAULT 0,</code> |
| L0708 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          machine_id INT NULL,</code> |
| L0709 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,</code> |
| L0710 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema_mysql。 | <code>          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,</code> |
| L0711 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          KEY idx_event_time (occurred_at),</code> |
| L0712 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          KEY idx_event_risk (risk_level),</code> |
| L0713 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          KEY idx_event_type (attack_type),</code> |
| L0714 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          KEY idx_event_node (target_node)</code> |
| L0715 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L0716 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>        """,</code> |
| L0717 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>        """</code> |
| L0718 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema_mysql。 | <code>        CREATE TABLE IF NOT EXISTS ip_geo_cache (</code> |
| L0719 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          ip VARCHAR(64) PRIMARY KEY,</code> |
| L0720 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          region VARCHAR(128) NOT NULL,</code> |
| L0721 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>          source VARCHAR(32) NOT NULL DEFAULT 'fallback',</code> |
| L0722 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 ensure_schema_mysql。 | <code>          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP</code> |
| L0723 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci</code> |
| L0724 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 ensure_schema_mysql。 | <code>        """,</code> |
| L0725 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ensure_schema_mysql。 | <code>    ]</code> |
| L0726 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 ensure_schema_mysql。 | <code>    with conn.cursor() as cur:</code> |
| L0727 | 遍历集合中的数据项并逐项处理，当前位于函数 ensure_schema_mysql。 | <code>        for ddl in ddl_list:</code> |
| L0728 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema_mysql。 | <code>            cur.execute(ddl)</code> |
| L0729 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema_mysql。 | <code>        cur.execute("SHOW COLUMNS FROM analyses")</code> |
| L0730 | 计算并保存 &#96;columns&#96;（columns），供后续逻辑使用，当前位于函数 ensure_schema_mysql。 | <code>        columns = {str(row["Field"]): row for row in cur.fetchall()}</code> |
| L0731 | 计算并保存 &#96;existing&#96;（existing），供后续逻辑使用，当前位于函数 ensure_schema_mysql。 | <code>        existing = set(columns)</code> |
| L0732 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema_mysql。 | <code>        if "attack_event_time" not in existing:</code> |
| L0733 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema_mysql。 | <code>            cur.execute("ALTER TABLE analyses ADD COLUMN attack_event_time VARCHAR(64) NULL")</code> |
| L0734 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema_mysql。 | <code>        if "attack_ip" not in existing:</code> |
| L0735 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema_mysql。 | <code>            cur.execute("ALTER TABLE analyses ADD COLUMN attack_ip VARCHAR(64) NULL")</code> |
| L0736 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema_mysql。 | <code>        if "target_interface" not in existing:</code> |
| L0737 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema_mysql。 | <code>            cur.execute("ALTER TABLE analyses ADD COLUMN target_interface VARCHAR(255) NULL")</code> |
| L0738 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema_mysql。 | <code>        if "attack_type" not in existing:</code> |
| L0739 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema_mysql。 | <code>            cur.execute("ALTER TABLE analyses ADD COLUMN attack_type VARCHAR(255) NULL")</code> |
| L0740 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema_mysql。 | <code>        if "attack_confidence" not in existing:</code> |
| L0741 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema_mysql。 | <code>            cur.execute("ALTER TABLE analyses ADD COLUMN attack_confidence DOUBLE NULL")</code> |
| L0742 | 源码原注释：LLM output may describe an attack method in more than 255 characters. | <code>        # LLM output may describe an attack method in more than 255 characters.</code> |
| L0743 | 源码原注释：Preserve the evidence instead of aborting the entire result import batch. | <code>        # Preserve the evidence instead of aborting the entire result import batch.</code> |
| L0744 | 计算并保存 &#96;attack_method_type&#96;（攻击methodtype），供后续逻辑使用，当前位于函数 ensure_schema_mysql。 | <code>        attack_method_type = str(columns.get("attack_method", {}).get("Type") or "").lower()</code> |
| L0745 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema_mysql。 | <code>        if attack_method_type.startswith("varchar"):</code> |
| L0746 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema_mysql。 | <code>            cur.execute("ALTER TABLE analyses MODIFY COLUMN attack_method LONGTEXT NULL")</code> |
| L0747 | 源码原注释：LLMs may return a descriptive interface value rather than only a short URI. | <code>        # LLMs may return a descriptive interface value rather than only a short URI.</code> |
| L0748 | 源码原注释：Keep the complete evidence and prevent one long row from rolling back a batch. | <code>        # Keep the complete evidence and prevent one long row from rolling back a batch.</code> |
| L0749 | 计算并保存 &#96;attack_interface_type&#96;（攻击interfacetype），供后续逻辑使用，当前位于函数 ensure_schema_mysql。 | <code>        attack_interface_type = str(columns.get("attack_interface", {}).get("Type") or "").lower()</code> |
| L0750 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema_mysql。 | <code>        if attack_interface_type.startswith("varchar"):</code> |
| L0751 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema_mysql。 | <code>            cur.execute("ALTER TABLE analyses MODIFY COLUMN attack_interface TEXT NULL")</code> |
| L0752 | 计算并保存 &#96;target_interface_type&#96;（targetinterfacetype），供后续逻辑使用，当前位于函数 ensure_schema_mysql。 | <code>        target_interface_type = str(columns.get("target_interface", {}).get("Type") or "").lower()</code> |
| L0753 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema_mysql。 | <code>        if target_interface_type.startswith("varchar"):</code> |
| L0754 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema_mysql。 | <code>            cur.execute("ALTER TABLE analyses MODIFY COLUMN target_interface TEXT NULL")</code> |
| L0755 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema_mysql。 | <code>        cur.execute("SHOW COLUMNS FROM demo_attack_events")</code> |
| L0756 | 计算并保存 &#96;event_columns&#96;（事件columns），供后续逻辑使用，当前位于函数 ensure_schema_mysql。 | <code>        event_columns = {str(row["Field"]): row for row in cur.fetchall()}</code> |
| L0757 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema_mysql。 | <code>        if "target_port" not in event_columns:</code> |
| L0758 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema_mysql。 | <code>            cur.execute("ALTER TABLE demo_attack_events ADD COLUMN target_port INT NULL AFTER target_node")</code> |
| L0759 | 计算并保存 &#96;event_target_type&#96;（事件targettype），供后续逻辑使用，当前位于函数 ensure_schema_mysql。 | <code>        event_target_type = str(event_columns.get("target_interface", {}).get("Type") or "").lower()</code> |
| L0760 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 ensure_schema_mysql。 | <code>        if event_target_type.startswith("varchar"):</code> |
| L0761 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 ensure_schema_mysql。 | <code>            cur.execute("ALTER TABLE demo_attack_events MODIFY COLUMN target_interface TEXT NOT NULL")</code> |
| L0762 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0763 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0764 | 定义upsertrequestssqlite函数 &#96;upsert_requests_sqlite&#96;，封装可复用业务逻辑。 | <code>def upsert_requests_sqlite(conn: sqlite3.Connection, row: Dict[str, Any]) -&gt; None:</code> |
| L0765 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 upsert_requests_sqlite。 | <code>    conn.execute(</code> |
| L0766 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>        """</code> |
| L0767 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 upsert_requests_sqlite。 | <code>        INSERT INTO requests(</code> |
| L0768 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>          case_id,file_id,seq_id,rank_no,raw_score,norm_score,label,method,uri,host,status_code,</code> |
| L0769 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>          request_text_summary,request_content,export_time,updated_at</code> |
| L0770 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>        ) VALUES(</code> |
| L0771 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>          :case_id,:file_id,:seq_id,:rank_no,:raw_score,:norm_score,:label,:method,:uri,:host,:status_code,</code> |
| L0772 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>          :request_text_summary,:request_content,:export_time,datetime('now','localtime')</code> |
| L0773 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>        )</code> |
| L0774 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 upsert_requests_sqlite。 | <code>        ON CONFLICT(case_id) DO UPDATE SET</code> |
| L0775 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>          file_id=excluded.file_id,</code> |
| L0776 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>          seq_id=excluded.seq_id,</code> |
| L0777 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>          rank_no=excluded.rank_no,</code> |
| L0778 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>          raw_score=excluded.raw_score,</code> |
| L0779 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>          norm_score=excluded.norm_score,</code> |
| L0780 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>          label=excluded.label,</code> |
| L0781 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>          method=excluded.method,</code> |
| L0782 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>          uri=excluded.uri,</code> |
| L0783 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>          host=excluded.host,</code> |
| L0784 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>          status_code=excluded.status_code,</code> |
| L0785 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>          request_text_summary=excluded.request_text_summary,</code> |
| L0786 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>          request_content=excluded.request_content,</code> |
| L0787 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>          export_time=excluded.export_time,</code> |
| L0788 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>          updated_at=datetime('now','localtime');</code> |
| L0789 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_sqlite。 | <code>        """,</code> |
| L0790 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_requests_sqlite。 | <code>        row,</code> |
| L0791 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 upsert_requests_sqlite。 | <code>    )</code> |
| L0792 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0793 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0794 | 定义upsertrequestsmysql函数 &#96;upsert_requests_mysql&#96;，封装可复用业务逻辑。 | <code>def upsert_requests_mysql(conn: Any, row: Dict[str, Any]) -&gt; None:</code> |
| L0795 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 upsert_requests_mysql。 | <code>    with conn.cursor() as cur:</code> |
| L0796 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 upsert_requests_mysql。 | <code>        cur.execute(</code> |
| L0797 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>            """</code> |
| L0798 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 upsert_requests_mysql。 | <code>            INSERT INTO requests(</code> |
| L0799 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>              case_id,file_id,seq_id,rank_no,raw_score,norm_score,label,method,uri,host,status_code,</code> |
| L0800 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>              request_text_summary,request_content,export_time</code> |
| L0801 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>            ) VALUES(</code> |
| L0802 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>              %(case_id)s,%(file_id)s,%(seq_id)s,%(rank_no)s,%(raw_score)s,%(norm_score)s,%(label)s,%(method)s,%(uri)s,%(host)s,%(status_code)s,</code> |
| L0803 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>              %(request_text_summary)s,%(request_content)s,%(export_time)s</code> |
| L0804 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>            )</code> |
| L0805 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>            ON DUPLICATE KEY UPDATE</code> |
| L0806 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>              file_id=VALUES(file_id),</code> |
| L0807 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>              seq_id=VALUES(seq_id),</code> |
| L0808 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>              rank_no=VALUES(rank_no),</code> |
| L0809 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>              raw_score=VALUES(raw_score),</code> |
| L0810 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>              norm_score=VALUES(norm_score),</code> |
| L0811 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>              label=VALUES(label),</code> |
| L0812 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>              method=VALUES(method),</code> |
| L0813 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>              uri=VALUES(uri),</code> |
| L0814 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>              host=VALUES(host),</code> |
| L0815 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>              status_code=VALUES(status_code),</code> |
| L0816 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>              request_text_summary=VALUES(request_text_summary),</code> |
| L0817 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>              request_content=VALUES(request_content),</code> |
| L0818 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>              export_time=VALUES(export_time)</code> |
| L0819 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_requests_mysql。 | <code>            """,</code> |
| L0820 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_requests_mysql。 | <code>            row,</code> |
| L0821 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 upsert_requests_mysql。 | <code>        )</code> |
| L0822 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0823 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0824 | 定义upsertresponsessqlite函数 &#96;upsert_responses_sqlite&#96;，封装可复用业务逻辑。 | <code>def upsert_responses_sqlite(conn: sqlite3.Connection, row: Dict[str, Any]) -&gt; None:</code> |
| L0825 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 upsert_responses_sqlite。 | <code>    conn.execute(</code> |
| L0826 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_sqlite。 | <code>        """</code> |
| L0827 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 upsert_responses_sqlite。 | <code>        INSERT INTO responses(</code> |
| L0828 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_sqlite。 | <code>          case_id,file_id,seq_id,status_code,response_content,export_time,updated_at</code> |
| L0829 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_sqlite。 | <code>        ) VALUES(</code> |
| L0830 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_sqlite。 | <code>          :case_id,:file_id,:seq_id,:status_code,:response_content,:export_time,datetime('now','localtime')</code> |
| L0831 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_sqlite。 | <code>        )</code> |
| L0832 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 upsert_responses_sqlite。 | <code>        ON CONFLICT(case_id) DO UPDATE SET</code> |
| L0833 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_sqlite。 | <code>          file_id=excluded.file_id,</code> |
| L0834 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_sqlite。 | <code>          seq_id=excluded.seq_id,</code> |
| L0835 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_sqlite。 | <code>          status_code=excluded.status_code,</code> |
| L0836 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_sqlite。 | <code>          response_content=excluded.response_content,</code> |
| L0837 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_sqlite。 | <code>          export_time=excluded.export_time,</code> |
| L0838 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_sqlite。 | <code>          updated_at=datetime('now','localtime');</code> |
| L0839 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_sqlite。 | <code>        """,</code> |
| L0840 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_responses_sqlite。 | <code>        row,</code> |
| L0841 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 upsert_responses_sqlite。 | <code>    )</code> |
| L0842 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0843 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0844 | 定义upsertresponsesmysql函数 &#96;upsert_responses_mysql&#96;，封装可复用业务逻辑。 | <code>def upsert_responses_mysql(conn: Any, row: Dict[str, Any]) -&gt; None:</code> |
| L0845 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 upsert_responses_mysql。 | <code>    with conn.cursor() as cur:</code> |
| L0846 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 upsert_responses_mysql。 | <code>        cur.execute(</code> |
| L0847 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_mysql。 | <code>            """</code> |
| L0848 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 upsert_responses_mysql。 | <code>            INSERT INTO responses(</code> |
| L0849 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_mysql。 | <code>              case_id,file_id,seq_id,status_code,response_content,export_time</code> |
| L0850 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_mysql。 | <code>            ) VALUES(</code> |
| L0851 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_mysql。 | <code>              %(case_id)s,%(file_id)s,%(seq_id)s,%(status_code)s,%(response_content)s,%(export_time)s</code> |
| L0852 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_mysql。 | <code>            )</code> |
| L0853 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_mysql。 | <code>            ON DUPLICATE KEY UPDATE</code> |
| L0854 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_mysql。 | <code>              file_id=VALUES(file_id),</code> |
| L0855 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_mysql。 | <code>              seq_id=VALUES(seq_id),</code> |
| L0856 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_mysql。 | <code>              status_code=VALUES(status_code),</code> |
| L0857 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_mysql。 | <code>              response_content=VALUES(response_content),</code> |
| L0858 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_mysql。 | <code>              export_time=VALUES(export_time)</code> |
| L0859 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_responses_mysql。 | <code>            """,</code> |
| L0860 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_responses_mysql。 | <code>            row,</code> |
| L0861 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 upsert_responses_mysql。 | <code>        )</code> |
| L0862 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0863 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0864 | 定义upsertanalysessqlite函数 &#96;upsert_analyses_sqlite&#96;，封装可复用业务逻辑。 | <code>def upsert_analyses_sqlite(conn: sqlite3.Connection, row: Dict[str, Any]) -&gt; None:</code> |
| L0865 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 upsert_analyses_sqlite。 | <code>    conn.execute(</code> |
| L0866 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>        """</code> |
| L0867 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 upsert_analyses_sqlite。 | <code>        INSERT INTO analyses(</code> |
| L0868 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          case_id,file_id,seq_id,llm_status,llm_error,llm_started_at,llm_failed_at,analyzed_at,model_name,</code> |
| L0869 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          verdict,source_ip,destination_ip,attack_interface,attack_method,attack_path,attack_time,severity,</code> |
| L0870 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          confidence,summary,evidence_json,analysis_raw,attack_event_time,attack_ip,target_interface,attack_type,attack_confidence,updated_at</code> |
| L0871 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>        ) VALUES(</code> |
| L0872 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          :case_id,:file_id,:seq_id,:llm_status,:llm_error,:llm_started_at,:llm_failed_at,:analyzed_at,:model_name,</code> |
| L0873 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          :verdict,:source_ip,:destination_ip,:attack_interface,:attack_method,:attack_path,:attack_time,:severity,</code> |
| L0874 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          :confidence,:summary,:evidence_json,:analysis_raw,:attack_event_time,:attack_ip,:target_interface,:attack_type,:attack_confidence,datetime('now','localtime')</code> |
| L0875 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>        )</code> |
| L0876 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 upsert_analyses_sqlite。 | <code>        ON CONFLICT(case_id) DO UPDATE SET</code> |
| L0877 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          file_id=excluded.file_id,</code> |
| L0878 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          seq_id=excluded.seq_id,</code> |
| L0879 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          llm_status=excluded.llm_status,</code> |
| L0880 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          llm_error=excluded.llm_error,</code> |
| L0881 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          llm_started_at=excluded.llm_started_at,</code> |
| L0882 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          llm_failed_at=excluded.llm_failed_at,</code> |
| L0883 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          analyzed_at=excluded.analyzed_at,</code> |
| L0884 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          model_name=excluded.model_name,</code> |
| L0885 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          verdict=excluded.verdict,</code> |
| L0886 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          source_ip=excluded.source_ip,</code> |
| L0887 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          destination_ip=excluded.destination_ip,</code> |
| L0888 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          attack_interface=excluded.attack_interface,</code> |
| L0889 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          attack_method=excluded.attack_method,</code> |
| L0890 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          attack_path=excluded.attack_path,</code> |
| L0891 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          attack_time=excluded.attack_time,</code> |
| L0892 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          severity=excluded.severity,</code> |
| L0893 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          confidence=excluded.confidence,</code> |
| L0894 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          summary=excluded.summary,</code> |
| L0895 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          evidence_json=excluded.evidence_json,</code> |
| L0896 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          analysis_raw=excluded.analysis_raw,</code> |
| L0897 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          attack_event_time=excluded.attack_event_time,</code> |
| L0898 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          attack_ip=excluded.attack_ip,</code> |
| L0899 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          target_interface=excluded.target_interface,</code> |
| L0900 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          attack_type=excluded.attack_type,</code> |
| L0901 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          attack_confidence=excluded.attack_confidence,</code> |
| L0902 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>          updated_at=datetime('now','localtime');</code> |
| L0903 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_sqlite。 | <code>        """,</code> |
| L0904 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_analyses_sqlite。 | <code>        row,</code> |
| L0905 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 upsert_analyses_sqlite。 | <code>    )</code> |
| L0906 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0907 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0908 | 定义upsertanalysesmysql函数 &#96;upsert_analyses_mysql&#96;，封装可复用业务逻辑。 | <code>def upsert_analyses_mysql(conn: Any, row: Dict[str, Any]) -&gt; None:</code> |
| L0909 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 upsert_analyses_mysql。 | <code>    with conn.cursor() as cur:</code> |
| L0910 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 upsert_analyses_mysql。 | <code>        cur.execute(</code> |
| L0911 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>            """</code> |
| L0912 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 upsert_analyses_mysql。 | <code>            INSERT INTO analyses(</code> |
| L0913 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              case_id,file_id,seq_id,llm_status,llm_error,llm_started_at,llm_failed_at,analyzed_at,model_name,</code> |
| L0914 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              verdict,source_ip,destination_ip,attack_interface,attack_method,attack_path,attack_time,severity,</code> |
| L0915 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              confidence,summary,evidence_json,analysis_raw,attack_event_time,attack_ip,target_interface,attack_type,attack_confidence</code> |
| L0916 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>            ) VALUES(</code> |
| L0917 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              %(case_id)s,%(file_id)s,%(seq_id)s,%(llm_status)s,%(llm_error)s,%(llm_started_at)s,%(llm_failed_at)s,%(analyzed_at)s,%(model_name)s,</code> |
| L0918 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              %(verdict)s,%(source_ip)s,%(destination_ip)s,%(attack_interface)s,%(attack_method)s,%(attack_path)s,%(attack_time)s,%(severity)s,</code> |
| L0919 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              %(confidence)s,%(summary)s,%(evidence_json)s,%(analysis_raw)s,%(attack_event_time)s,%(attack_ip)s,%(target_interface)s,%(attack_type)s,%(attack_confidence)s</code> |
| L0920 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>            )</code> |
| L0921 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>            ON DUPLICATE KEY UPDATE</code> |
| L0922 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              file_id=VALUES(file_id),</code> |
| L0923 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              seq_id=VALUES(seq_id),</code> |
| L0924 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              llm_status=VALUES(llm_status),</code> |
| L0925 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              llm_error=VALUES(llm_error),</code> |
| L0926 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              llm_started_at=VALUES(llm_started_at),</code> |
| L0927 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              llm_failed_at=VALUES(llm_failed_at),</code> |
| L0928 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              analyzed_at=VALUES(analyzed_at),</code> |
| L0929 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              model_name=VALUES(model_name),</code> |
| L0930 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              verdict=VALUES(verdict),</code> |
| L0931 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              source_ip=VALUES(source_ip),</code> |
| L0932 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              destination_ip=VALUES(destination_ip),</code> |
| L0933 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              attack_interface=VALUES(attack_interface),</code> |
| L0934 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              attack_method=VALUES(attack_method),</code> |
| L0935 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              attack_path=VALUES(attack_path),</code> |
| L0936 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              attack_time=VALUES(attack_time),</code> |
| L0937 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              severity=VALUES(severity),</code> |
| L0938 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              confidence=VALUES(confidence),</code> |
| L0939 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              summary=VALUES(summary),</code> |
| L0940 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              evidence_json=VALUES(evidence_json),</code> |
| L0941 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              analysis_raw=VALUES(analysis_raw),</code> |
| L0942 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              attack_event_time=VALUES(attack_event_time),</code> |
| L0943 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              attack_ip=VALUES(attack_ip),</code> |
| L0944 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              target_interface=VALUES(target_interface),</code> |
| L0945 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              attack_type=VALUES(attack_type),</code> |
| L0946 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>              attack_confidence=VALUES(attack_confidence)</code> |
| L0947 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_analyses_mysql。 | <code>            """,</code> |
| L0948 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_analyses_mysql。 | <code>            row,</code> |
| L0949 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 upsert_analyses_mysql。 | <code>        )</code> |
| L0950 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0951 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0952 | 定义upsertdemo攻击事件mysql函数 &#96;upsert_demo_attack_event_mysql&#96;，封装可复用业务逻辑。 | <code>def upsert_demo_attack_event_mysql(conn: Any, row: Dict[str, Any]) -&gt; None:</code> |
| L0953 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 upsert_demo_attack_event_mysql。 | <code>    with conn.cursor() as cur:</code> |
| L0954 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 upsert_demo_attack_event_mysql。 | <code>        cur.execute(</code> |
| L0955 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>            """</code> |
| L0956 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 upsert_demo_attack_event_mysql。 | <code>            INSERT INTO demo_attack_events(</code> |
| L0957 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              event_id, occurred_at, risk_level, attack_type, source_ip, source_region,</code> |
| L0958 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              target_node, target_port, target_interface, attack_result, process_status, acked,</code> |
| L0959 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              attack_payload, request_log, protection_action, handling_suggestion, note,</code> |
| L0960 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              response_ms, anomaly_detected, machine_id</code> |
| L0961 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>            ) VALUES (</code> |
| L0962 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              %(event_id)s, %(occurred_at)s, %(risk_level)s, %(attack_type)s, %(source_ip)s, %(source_region)s,</code> |
| L0963 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              %(target_node)s, %(target_port)s, %(target_interface)s, %(attack_result)s, %(process_status)s, %(acked)s,</code> |
| L0964 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              %(attack_payload)s, %(request_log)s, %(protection_action)s, %(handling_suggestion)s, %(note)s,</code> |
| L0965 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              %(response_ms)s, %(anomaly_detected)s, %(machine_id)s</code> |
| L0966 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>            )</code> |
| L0967 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>            ON DUPLICATE KEY UPDATE</code> |
| L0968 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              occurred_at=VALUES(occurred_at),</code> |
| L0969 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              risk_level=VALUES(risk_level),</code> |
| L0970 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              attack_type=VALUES(attack_type),</code> |
| L0971 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              source_ip=VALUES(source_ip),</code> |
| L0972 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              source_region=VALUES(source_region),</code> |
| L0973 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              target_node=VALUES(target_node),</code> |
| L0974 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              target_port=VALUES(target_port),</code> |
| L0975 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              target_interface=VALUES(target_interface),</code> |
| L0976 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              attack_result=VALUES(attack_result),</code> |
| L0977 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              attack_payload=VALUES(attack_payload),</code> |
| L0978 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              request_log=VALUES(request_log),</code> |
| L0979 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              protection_action=VALUES(protection_action),</code> |
| L0980 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              handling_suggestion=VALUES(handling_suggestion),</code> |
| L0981 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              response_ms=VALUES(response_ms),</code> |
| L0982 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              anomaly_detected=VALUES(anomaly_detected),</code> |
| L0983 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>              machine_id=VALUES(machine_id)</code> |
| L0984 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 upsert_demo_attack_event_mysql。 | <code>            """,</code> |
| L0985 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 upsert_demo_attack_event_mysql。 | <code>            row,</code> |
| L0986 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 upsert_demo_attack_event_mysql。 | <code>        )</code> |
| L0987 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0988 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0989 | 定义llmverdictis攻击函数 &#96;llm_verdict_is_attack&#96;，封装可复用业务逻辑。 | <code>def llm_verdict_is_attack(case_obj: Dict[str, Any], analysis_obj: Dict[str, Any]) -&gt; bool:</code> |
| L0990 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 llm_verdict_is_attack。 | <code>    if str(case_obj.get("llm_status") or "").strip().lower() != "done":</code> |
| L0991 | 结束当前函数并把结果返回给调用方，当前位于函数 llm_verdict_is_attack。 | <code>        return False</code> |
| L0992 | 计算并保存 &#96;verdict&#96;（verdict），供后续逻辑使用，当前位于函数 llm_verdict_is_attack。 | <code>    verdict = str(analysis_obj.get("verdict") or "").strip().lower()</code> |
| L0993 | 结束当前函数并把结果返回给调用方，当前位于函数 llm_verdict_is_attack。 | <code>    return verdict in {"attack", "malicious", "攻击", "恶意"}</code> |
| L0994 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0995 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0996 | 定义count数据库记录函数 &#96;count_rows&#96;，封装可复用业务逻辑。 | <code>def count_rows(conn: Any, backend: Backend, table: str) -&gt; int:</code> |
| L0997 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 count_rows。 | <code>    if table not in {"requests", "responses", "analyses", "demo_attack_events"}:</code> |
| L0998 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 count_rows。 | <code>        raise ValueError(f"unsupported table: {table}")</code> |
| L0999 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1000 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 count_rows。 | <code>    if backend == "sqlite":</code> |
| L1001 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 count_rows。 | <code>        row = conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()</code> |
| L1002 | 结束当前函数并把结果返回给调用方，当前位于函数 count_rows。 | <code>        return int(row["c"])</code> |
| L1003 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1004 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 count_rows。 | <code>    with conn.cursor() as cur:</code> |
| L1005 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 count_rows。 | <code>        cur.execute(f"SELECT COUNT(*) AS c FROM &#96;{table}&#96;")</code> |
| L1006 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 count_rows。 | <code>        row = cur.fetchone() or {}</code> |
| L1007 | 结束当前函数并把结果返回给调用方，当前位于函数 count_rows。 | <code>    return int(row.get("c", 0))</code> |
| L1008 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1009 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1010 | 定义同步结果to数据库函数 &#96;sync_result_to_db&#96;，封装可复用业务逻辑。 | <code>def sync_result_to_db(</code> |
| L1011 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>    result_dir: Path,</code> |
| L1012 | 计算并保存 &#96;backend&#96;（backend），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>    backend: Backend = "mysql",</code> |
| L1013 | 计算并保存 &#96;db_path&#96;（数据库path），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>    db_path: Path &#124; None = None,</code> |
| L1014 | 计算并保存 &#96;mysql_config&#96;（mysql配置），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>    mysql_config: MySQLConfig &#124; None = None,</code> |
| L1015 | 计算并保存 &#96;case_names&#96;（casenames），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>    case_names: set[str] &#124; None = None,</code> |
| L1016 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_result_to_db。 | <code>) -&gt; Dict[str, Any]:</code> |
| L1017 | 计算并保存 &#96;manifest_map&#96;（manifestmap），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>    manifest_map = load_manifest(result_dir / "manifest.jsonl")</code> |
| L1018 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1019 | 计算并保存 &#96;case_dirs&#96;（casedirs），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>    case_dirs: List[Path] = sorted(</code> |
| L1020 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>        [</code> |
| L1021 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            p</code> |
| L1022 | 遍历集合中的数据项并逐项处理，当前位于函数 sync_result_to_db。 | <code>            for p in result_dir.glob("b.*")</code> |
| L1023 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_result_to_db。 | <code>            if p.is_dir() and (case_names is None or p.name in case_names)</code> |
| L1024 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_result_to_db。 | <code>        ],</code> |
| L1025 | 计算并保存 &#96;key&#96;（key），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        key=lambda p: int(p.name.split(".", 1)[1]) if p.name.split(".", 1)[1].isdigit() else 10**9,</code> |
| L1026 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_result_to_db。 | <code>    )</code> |
| L1027 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1028 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_result_to_db。 | <code>    if backend == "sqlite":</code> |
| L1029 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_result_to_db。 | <code>        if db_path is None:</code> |
| L1030 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 sync_result_to_db。 | <code>            raise ValueError("db_path is required when backend=sqlite")</code> |
| L1031 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        conn = connect_sqlite(db_path)</code> |
| L1032 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>        ensure_schema_sqlite(conn)</code> |
| L1033 | 计算并保存 &#96;target&#96;（target），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        target = str(db_path)</code> |
| L1034 | 处理前述条件均未命中的情况，当前位于函数 sync_result_to_db。 | <code>    else:</code> |
| L1035 | 计算并保存 &#96;cfg&#96;（cfg），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        cfg = mysql_config or MySQLConfig()</code> |
| L1036 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        conn = connect_mysql(cfg)</code> |
| L1037 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>        ensure_schema_mysql(conn)</code> |
| L1038 | 计算并保存 &#96;target&#96;（target），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        target = f"mysql://{cfg.user}@{cfg.host}:{cfg.port}/{cfg.database}"</code> |
| L1039 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1040 | 计算并保存 &#96;machine_targets&#96;（machinetargets），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>    machine_targets: List[Dict[str, Any]] = []</code> |
| L1041 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_result_to_db。 | <code>    if backend == "mysql":</code> |
| L1042 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 sync_result_to_db。 | <code>        with conn.cursor() as cur:</code> |
| L1043 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 sync_result_to_db。 | <code>            try:</code> |
| L1044 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 sync_result_to_db。 | <code>                cur.execute("SELECT id, machine_name FROM demo_machines ORDER BY id")</code> |
| L1045 | 计算并保存 &#96;machine_targets&#96;（machinetargets），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>                machine_targets = [x for x in cur.fetchall() if x.get("machine_name")]</code> |
| L1046 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 sync_result_to_db。 | <code>            except Exception:</code> |
| L1047 | 计算并保存 &#96;machine_targets&#96;（machinetargets），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>                machine_targets = []</code> |
| L1048 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_result_to_db。 | <code>    if not machine_targets:</code> |
| L1049 | 计算并保存 &#96;machine_targets&#96;（machinetargets），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        machine_targets = [{"id": None, "machine_name": "node-local-01"}]</code> |
| L1050 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1051 | 计算并保存 &#96;input_dir&#96;（inputdir），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>    input_dir = result_dir.parent / "input"</code> |
| L1052 | 计算并保存 &#96;input_ip_cache&#96;（inputipcache），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>    input_ip_cache: Dict[str, Dict[int, str]] = {}</code> |
| L1053 | 计算并保存 &#96;region_cache&#96;（regioncache），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>    region_cache: Dict[str, str] = {}</code> |
| L1054 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1055 | 计算并保存 &#96;total&#96;（total），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>    total = 0</code> |
| L1056 | 计算并保存 &#96;with_analysis&#96;（withanalysis），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>    with_analysis = 0</code> |
| L1057 | 遍历集合中的数据项并逐项处理，当前位于函数 sync_result_to_db。 | <code>    for case_dir in case_dirs:</code> |
| L1058 | 计算并保存 &#96;case_id&#96;（caseid），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        case_id = case_dir.name</code> |
| L1059 | 计算并保存 &#96;case_obj&#96;（caseobj），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        case_obj = read_json(case_dir / "case.json", default={})</code> |
| L1060 | 计算并保存 &#96;manifest_obj&#96;（manifestobj），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        manifest_obj = manifest_map.get(case_id, {})</code> |
| L1061 | 计算并保存 &#96;analysis_obj&#96;（analysisobj），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        analysis_obj = read_json(case_dir / "analysis.json", default={})</code> |
| L1062 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1063 | 计算并保存 &#96;file_id&#96;（fileid），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        file_id = first_non_none(case_obj.get("file_id"), manifest_obj.get("file_id"))</code> |
| L1064 | 计算并保存 &#96;seq_id&#96;（seqid），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        seq_id = to_int(first_non_none(case_obj.get("seq_id"), manifest_obj.get("seq_id")))</code> |
| L1065 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1066 | 计算并保存 &#96;request_content&#96;（requestcontent），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        request_content = read_text(case_dir / "request.txt", default="")</code> |
| L1067 | 计算并保存 &#96;response_content&#96;（responsecontent），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        response_content = read_text(case_dir / "response.txt", default="")</code> |
| L1068 | 计算并保存 &#96;analysis_raw&#96;（analysisraw），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        analysis_raw = read_text(case_dir / "analysis_raw.txt", default="")</code> |
| L1069 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1070 | 计算并保存 &#96;request_row&#96;（requestrow），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        request_row = {</code> |
| L1071 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "case_id": case_id,</code> |
| L1072 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "file_id": file_id,</code> |
| L1073 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "seq_id": seq_id,</code> |
| L1074 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "rank_no": to_int(case_obj.get("rank")),</code> |
| L1075 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "raw_score": to_float(first_non_none(case_obj.get("raw_score"), manifest_obj.get("raw_score"))),</code> |
| L1076 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "norm_score": to_float(first_non_none(case_obj.get("norm_score"), manifest_obj.get("norm_score"))),</code> |
| L1077 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "label": first_non_none(case_obj.get("label"), manifest_obj.get("label")),</code> |
| L1078 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "method": case_obj.get("method"),</code> |
| L1079 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "uri": first_non_none(case_obj.get("uri"), manifest_obj.get("uri")),</code> |
| L1080 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "host": case_obj.get("host"),</code> |
| L1081 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "status_code": to_int(case_obj.get("status_code")),</code> |
| L1082 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "request_text_summary": case_obj.get("request_text"),</code> |
| L1083 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "request_content": request_content,</code> |
| L1084 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "export_time": case_obj.get("export_time"),</code> |
| L1085 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_result_to_db。 | <code>        }</code> |
| L1086 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_result_to_db。 | <code>        if backend == "sqlite":</code> |
| L1087 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            upsert_requests_sqlite(conn, request_row)</code> |
| L1088 | 处理前述条件均未命中的情况，当前位于函数 sync_result_to_db。 | <code>        else:</code> |
| L1089 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            upsert_requests_mysql(conn, request_row)</code> |
| L1090 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1091 | 计算并保存 &#96;response_row&#96;（responserow），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        response_row = {</code> |
| L1092 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "case_id": case_id,</code> |
| L1093 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "file_id": file_id,</code> |
| L1094 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "seq_id": seq_id,</code> |
| L1095 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "status_code": to_int(case_obj.get("status_code")),</code> |
| L1096 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "response_content": response_content,</code> |
| L1097 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "export_time": case_obj.get("export_time"),</code> |
| L1098 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_result_to_db。 | <code>        }</code> |
| L1099 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_result_to_db。 | <code>        if backend == "sqlite":</code> |
| L1100 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            upsert_responses_sqlite(conn, response_row)</code> |
| L1101 | 处理前述条件均未命中的情况，当前位于函数 sync_result_to_db。 | <code>        else:</code> |
| L1102 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            upsert_responses_mysql(conn, response_row)</code> |
| L1103 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1104 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        evidence = analysis_obj.get("evidence")</code> |
| L1105 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_result_to_db。 | <code>        if isinstance(evidence, list):</code> |
| L1106 | 计算并保存 &#96;evidence_json&#96;（evidencejson），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>            evidence_json = json.dumps(evidence, ensure_ascii=False)</code> |
| L1107 | 处理前述条件均未命中的情况，当前位于函数 sync_result_to_db。 | <code>        else:</code> |
| L1108 | 计算并保存 &#96;evidence_json&#96;（evidencejson），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>            evidence_json = "[]"</code> |
| L1109 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1110 | 计算并保存 &#96;inferred_attack_type&#96;（inferred攻击type），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        inferred_attack_type = infer_attack_type_text(analysis_obj, request_row, request_content)</code> |
| L1111 | 计算并保存 &#96;resolved_attack_type&#96;（resolved攻击type），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        resolved_attack_type = normalize_attack_type_label(</code> |
| L1112 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            (</code> |
| L1113 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                normalize_attack_type(analysis_obj, case_obj)</code> |
| L1114 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                or str(case_obj.get("attack_type") or "").strip()</code> |
| L1115 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                or inferred_attack_type</code> |
| L1116 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_result_to_db。 | <code>            )</code> |
| L1117 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_result_to_db。 | <code>        )</code> |
| L1118 | 计算并保存 &#96;resolved_source_ip&#96;（resolved来源ip），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        resolved_source_ip = resolve_source_ip_for_case(</code> |
| L1119 | 计算并保存 &#96;case_obj&#96;（caseobj），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>            case_obj=case_obj,</code> |
| L1120 | 计算并保存 &#96;analysis_obj&#96;（analysisobj），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>            analysis_obj=analysis_obj,</code> |
| L1121 | 计算并保存 &#96;request_content&#96;（requestcontent），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>            request_content=request_content,</code> |
| L1122 | 计算并保存 &#96;request_summary&#96;（requestsummary），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>            request_summary=str(request_row.get("request_text_summary") or ""),</code> |
| L1123 | 计算并保存 &#96;input_dir&#96;（inputdir），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>            input_dir=input_dir,</code> |
| L1124 | 计算并保存 &#96;file_id&#96;（fileid），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>            file_id=str(file_id or ""),</code> |
| L1125 | 计算并保存 &#96;seq_id&#96;（seqid），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>            seq_id=seq_id,</code> |
| L1126 | 计算并保存 &#96;input_ip_cache&#96;（inputipcache），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>            input_ip_cache=input_ip_cache,</code> |
| L1127 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_result_to_db。 | <code>        )</code> |
| L1128 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1129 | 计算并保存 &#96;analysis_row&#96;（analysisrow），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>        analysis_row = {</code> |
| L1130 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "case_id": case_id,</code> |
| L1131 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "file_id": file_id,</code> |
| L1132 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "seq_id": seq_id,</code> |
| L1133 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "llm_status": case_obj.get("llm_status"),</code> |
| L1134 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "llm_error": case_obj.get("llm_error"),</code> |
| L1135 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "llm_started_at": case_obj.get("llm_started_at"),</code> |
| L1136 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "llm_failed_at": case_obj.get("llm_failed_at"),</code> |
| L1137 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "analyzed_at": first_non_none(case_obj.get("analyzed_at"), analysis_obj.get("analyzed_at")),</code> |
| L1138 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "model_name": first_non_none(analysis_obj.get("model_name"), case_obj.get("model_name")),</code> |
| L1139 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "verdict": analysis_obj.get("verdict"),</code> |
| L1140 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "source_ip": first_non_none(analysis_obj.get("source_ip"), case_obj.get("source_ip"), resolved_source_ip),</code> |
| L1141 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "destination_ip": first_non_none(analysis_obj.get("destination_ip"), case_obj.get("destination_ip")),</code> |
| L1142 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "attack_interface": first_non_none(analysis_obj.get("attack_interface"), case_obj.get("uri")),</code> |
| L1143 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "attack_method": analysis_obj.get("attack_method"),</code> |
| L1144 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "attack_path": analysis_obj.get("attack_path"),</code> |
| L1145 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "attack_time": analysis_obj.get("attack_time"),</code> |
| L1146 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "severity": analysis_obj.get("severity"),</code> |
| L1147 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "confidence": to_float(first_non_none(analysis_obj.get("confidence"), request_row.get("raw_score"))),</code> |
| L1148 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "summary": analysis_obj.get("summary"),</code> |
| L1149 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "evidence_json": evidence_json,</code> |
| L1150 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "analysis_raw": analysis_raw,</code> |
| L1151 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "attack_event_time": normalize_attack_event_time(case_obj, analysis_obj),</code> |
| L1152 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "attack_ip": normalize_attack_ip(case_obj, analysis_obj),</code> |
| L1153 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "target_interface": normalize_target_interface(case_obj, analysis_obj),</code> |
| L1154 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "attack_type": resolved_attack_type,</code> |
| L1155 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            "attack_confidence": to_float(first_non_none(analysis_obj.get("confidence"), request_row.get("raw_score"))),</code> |
| L1156 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_result_to_db。 | <code>        }</code> |
| L1157 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_result_to_db。 | <code>        if backend == "sqlite":</code> |
| L1158 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            upsert_analyses_sqlite(conn, analysis_row)</code> |
| L1159 | 处理前述条件均未命中的情况，当前位于函数 sync_result_to_db。 | <code>        else:</code> |
| L1160 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            upsert_analyses_mysql(conn, analysis_row)</code> |
| L1161 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>            source_ip = resolved_source_ip or "unknown"</code> |
| L1162 | 计算并保存 &#96;target_interface&#96;（targetinterface），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>            target_interface = normalize_target_interface(case_obj, analysis_obj) or str(request_row.get("uri") or "-")</code> |
| L1163 | 计算并保存 &#96;attack_type&#96;（攻击type），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>            attack_type = resolved_attack_type</code> |
| L1164 | 计算并保存 &#96;risk_level&#96;（risklevel），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>            risk_level = infer_risk_level(analysis_obj, request_row)</code> |
| L1165 | 计算并保存 &#96;status_code&#96;（状态code），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>            status_code = to_int(request_row.get("status_code"))</code> |
| L1166 | 计算并保存 &#96;machine&#96;（machine），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>            machine = machine_targets[hash(case_id) % len(machine_targets)]</code> |
| L1167 | 计算并保存 &#96;source_ip_norm&#96;（来源ipnorm），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>            source_ip_norm = normalize_ip_literal(source_ip)</code> |
| L1168 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_result_to_db。 | <code>            if source_ip_norm in region_cache:</code> |
| L1169 | 计算并保存 &#96;source_region&#96;（来源region），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>                source_region = region_cache[source_ip_norm]</code> |
| L1170 | 处理前述条件均未命中的情况，当前位于函数 sync_result_to_db。 | <code>            else:</code> |
| L1171 | 计算并保存 &#96;source_region&#96;（来源region），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>                source_region = resolve_source_region_mysql(conn, source_ip)</code> |
| L1172 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_result_to_db。 | <code>                if source_ip_norm:</code> |
| L1173 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                    region_cache[source_ip_norm] = source_region</code> |
| L1174 | 计算并保存 &#96;event_row&#96;（事件row），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>            event_row = {</code> |
| L1175 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "event_id": str(case_id)[:40],</code> |
| L1176 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "occurred_at": parse_mysql_datetime(analysis_row.get("attack_event_time") or case_obj.get("export_time")),</code> |
| L1177 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "risk_level": risk_level,</code> |
| L1178 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "attack_type": str(attack_type)[:64] if attack_type else "\u53ef\u7591\u6d41\u91cf",</code> |
| L1179 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "source_ip": str(source_ip)[:64],</code> |
| L1180 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "source_region": str(source_region)[:64],</code> |
| L1181 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "target_node": str(machine.get("machine_name") or "node-local-01")[:64],</code> |
| L1182 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "target_port": to_int(case_obj.get("destination_port")),</code> |
| L1183 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "target_interface": str(target_interface)[:255],</code> |
| L1184 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "attack_result": infer_attack_result(status_code),</code> |
| L1185 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "process_status": "unprocessed",</code> |
| L1186 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "acked": 0,</code> |
| L1187 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "attack_payload": str(request_row.get("request_text_summary") or "")[:20000],</code> |
| L1188 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "request_log": request_content,</code> |
| L1189 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "protection_action": str(analysis_obj.get("summary") or "\u81ea\u52a8\u8bc6\u522b\u5230\u53ef\u7591\u6d41\u91cf\uff0c\u5df2\u8fdb\u5165\u4eba\u5de5\u590d\u6838\u6d41\u7a0b\u3002")[:4000],</code> |
| L1190 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "handling_suggestion": "\u6838\u67e5\u767b\u5f55\u63a5\u53e3\u53c2\u6570\u5316\u4e0eWAF\u89c4\u5219\uff0c\u9650\u5236\u5f02\u5e38\u91cd\u8bd5\u5e76\u8bb0\u5f55\u5ba1\u8ba1\u65e5\u5fd7\u3002",</code> |
| L1191 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "note": "",</code> |
| L1192 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "response_ms": 0,</code> |
| L1193 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "anomaly_detected": 1 if risk_level == "high" else 0,</code> |
| L1194 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                "machine_id": machine.get("id"),</code> |
| L1195 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_result_to_db。 | <code>            }</code> |
| L1196 | 计算并保存 &#96;raw_canonical_exists&#96;（rawcanonicalexists），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>            raw_canonical_exists = False</code> |
| L1197 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 sync_result_to_db。 | <code>            try:</code> |
| L1198 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 sync_result_to_db。 | <code>                with conn.cursor() as cur:</code> |
| L1199 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 sync_result_to_db。 | <code>                    cur.execute(</code> |
| L1200 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 sync_result_to_db。 | <code>                        """</code> |
| L1201 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 sync_result_to_db。 | <code>                        SELECT 1 FROM detection_candidates</code> |
| L1202 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 sync_result_to_db。 | <code>                        WHERE case_id LIKE 'raw:%' AND file_id=%s AND seq_id=%s</code> |
| L1203 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 sync_result_to_db。 | <code>                        LIMIT 1</code> |
| L1204 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 sync_result_to_db。 | <code>                        """,</code> |
| L1205 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                        (file_id, seq_id),</code> |
| L1206 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_result_to_db。 | <code>                    )</code> |
| L1207 | 计算并保存 &#96;raw_canonical_exists&#96;（rawcanonicalexists），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>                    raw_canonical_exists = bool(cur.fetchone())</code> |
| L1208 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 sync_result_to_db。 | <code>            except Exception:</code> |
| L1209 | 源码原注释：A fresh database creates the v2 tables immediately after the legacy import. | <code>                # A fresh database creates the v2 tables immediately after the legacy import.</code> |
| L1210 | 计算并保存 &#96;raw_canonical_exists&#96;（rawcanonicalexists），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>                raw_canonical_exists = False</code> |
| L1211 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_result_to_db。 | <code>            if llm_verdict_is_attack(case_obj, analysis_obj) and not raw_canonical_exists:</code> |
| L1212 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>                upsert_demo_attack_event_mysql(conn, event_row)</code> |
| L1213 | 处理前述条件均未命中的情况，当前位于函数 sync_result_to_db。 | <code>            else:</code> |
| L1214 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 sync_result_to_db。 | <code>                with conn.cursor() as cur:</code> |
| L1215 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 sync_result_to_db。 | <code>                    cur.execute("DELETE FROM demo_attack_events WHERE event_id=%s", (str(case_id)[:40],))</code> |
| L1216 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1217 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>        total += 1</code> |
| L1218 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_result_to_db。 | <code>        if analysis_obj:</code> |
| L1219 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>            with_analysis += 1</code> |
| L1220 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1221 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>    conn.commit()</code> |
| L1222 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1223 | 计算并保存 &#96;req_count&#96;（reqcount），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>    req_count = count_rows(conn, backend, "requests")</code> |
| L1224 | 计算并保存 &#96;rsp_count&#96;（rspcount），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>    rsp_count = count_rows(conn, backend, "responses")</code> |
| L1225 | 计算并保存 &#96;an_count&#96;（ancount），供后续逻辑使用，当前位于函数 sync_result_to_db。 | <code>    an_count = count_rows(conn, backend, "analyses")</code> |
| L1226 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>    demo_count = count_rows(conn, backend, "demo_attack_events") if backend == "mysql" else 0</code> |
| L1227 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>    conn.close()</code> |
| L1228 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1229 | 结束当前函数并把结果返回给调用方，当前位于函数 sync_result_to_db。 | <code>    return {</code> |
| L1230 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>        "backend": backend,</code> |
| L1231 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>        "target": target,</code> |
| L1232 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>        "cases_scanned": total,</code> |
| L1233 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>        "cases_with_analysis_json": with_analysis,</code> |
| L1234 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>        "requests_rows": req_count,</code> |
| L1235 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>        "responses_rows": rsp_count,</code> |
| L1236 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>        "analyses_rows": an_count,</code> |
| L1237 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_result_to_db。 | <code>        "demo_event_rows": demo_count,</code> |
| L1238 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_result_to_db。 | <code>    }</code> |
| L1239 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1240 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1241 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; None:</code> |
| L1242 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="Build DB from result/b.* directories")</code> |
| L1243 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--result-dir", default="result", help="Directory containing b.* case folders")</code> |
| L1244 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--backend", choices=["sqlite", "mysql"], default="mysql", help="Database backend")</code> |
| L1245 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1246 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--db-path", default="result/result_cases.db", help="SQLite db path")</code> |
| L1247 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1248 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-host", default="127.0.0.1", help="MySQL host")</code> |
| L1249 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-port", type=int, default=3306, help="MySQL port")</code> |
| L1250 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-user", default="root", help="MySQL user")</code> |
| L1251 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-password", default="123456", help="MySQL password")</code> |
| L1252 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-database", default="traffic_pipeline", help="MySQL database name")</code> |
| L1253 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1254 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L1255 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1256 | 计算并保存 &#96;project_root&#96;（projectroot），供后续逻辑使用，当前位于函数 main。 | <code>    project_root = Path(__file__).resolve().parent.parent</code> |
| L1257 | 计算并保存 &#96;result_dir&#96;（结果dir），供后续逻辑使用，当前位于函数 main。 | <code>    result_dir = (project_root / args.result_dir).resolve()</code> |
| L1258 | 计算并保存 &#96;db_path&#96;（数据库path），供后续逻辑使用，当前位于函数 main。 | <code>    db_path = (project_root / args.db_path).resolve()</code> |
| L1259 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1260 | 计算并保存 &#96;mysql_cfg&#96;（mysqlcfg），供后续逻辑使用，当前位于函数 main。 | <code>    mysql_cfg = MySQLConfig(</code> |
| L1261 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 main。 | <code>        host=args.mysql_host,</code> |
| L1262 | 计算并保存 &#96;port&#96;（port），供后续逻辑使用，当前位于函数 main。 | <code>        port=args.mysql_port,</code> |
| L1263 | 计算并保存 &#96;user&#96;（user），供后续逻辑使用，当前位于函数 main。 | <code>        user=args.mysql_user,</code> |
| L1264 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>        password=args.mysql_password,</code> |
| L1265 | 计算并保存 &#96;database&#96;（数据库），供后续逻辑使用，当前位于函数 main。 | <code>        database=args.mysql_database,</code> |
| L1266 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L1267 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1268 | 计算并保存 &#96;stats&#96;（stats），供后续逻辑使用，当前位于函数 main。 | <code>    stats = sync_result_to_db(</code> |
| L1269 | 计算并保存 &#96;result_dir&#96;（结果dir），供后续逻辑使用，当前位于函数 main。 | <code>        result_dir=result_dir,</code> |
| L1270 | 计算并保存 &#96;backend&#96;（backend），供后续逻辑使用，当前位于函数 main。 | <code>        backend=args.backend,</code> |
| L1271 | 计算并保存 &#96;db_path&#96;（数据库path），供后续逻辑使用，当前位于函数 main。 | <code>        db_path=db_path,</code> |
| L1272 | 计算并保存 &#96;mysql_config&#96;（mysql配置），供后续逻辑使用，当前位于函数 main。 | <code>        mysql_config=mysql_cfg,</code> |
| L1273 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L1274 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1275 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"backend: {stats['backend']}")</code> |
| L1276 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"target: {stats['target']}")</code> |
| L1277 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"cases scanned: {stats['cases_scanned']}")</code> |
| L1278 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"cases with analysis.json: {stats['cases_with_analysis_json']}")</code> |
| L1279 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"requests rows: {stats['requests_rows']}")</code> |
| L1280 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"responses rows: {stats['responses_rows']}")</code> |
| L1281 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"analyses rows: {stats['analyses_rows']}")</code> |
| L1282 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if "demo_event_rows" in stats:</code> |
| L1283 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        print(f"demo_attack_events rows: {stats['demo_event_rows']}")</code> |
| L1284 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1285 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L1286 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L1287 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
