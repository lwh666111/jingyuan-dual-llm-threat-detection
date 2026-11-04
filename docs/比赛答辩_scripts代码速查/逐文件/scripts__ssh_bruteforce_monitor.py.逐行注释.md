# `scripts/ssh_bruteforce_monitor.py` 逐行注释

**脚本用途：** 读取 Windows SSH 登录失败日志，按时间窗聚合 SSH 暴力破解。

**源码行数：** 410　**函数/类数量：** 15

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import hashlib&#96;。 | <code>import hashlib</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import ipaddress&#96;。 | <code>import ipaddress</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;import re&#96;。 | <code>import re</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;import socket&#96;。 | <code>import socket</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;import subprocess&#96;。 | <code>import subprocess</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;import sys&#96;。 | <code>import sys</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;import time&#96;。 | <code>import time</code> |
| L0012 | 导入后续逻辑所需的模块、类或函数：&#96;from collections import Counter, defaultdict&#96;。 | <code>from collections import Counter, defaultdict</code> |
| L0013 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime, timedelta&#96;。 | <code>from datetime import datetime, timedelta</code> |
| L0014 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0015 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, Iterable, List, Tuple&#96;。 | <code>from typing import Any, Dict, Iterable, List, Tuple</code> |
| L0016 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0017 | 导入后续逻辑所需的模块、类或函数：&#96;from build_result_db import MySQLConfig&#96;。 | <code>from build_result_db import MySQLConfig</code> |
| L0018 | 导入后续逻辑所需的模块、类或函数：&#96;from sync_detection_v2_db import ensure_mysql, mysql_connect, upsert_mysql&#96;。 | <code>from sync_detection_v2_db import ensure_mysql, mysql_connect, upsert_mysql</code> |
| L0019 | 导入后续逻辑所需的模块、类或函数：&#96;from sync_raw_http_logs import ensure_demo_attack_events&#96;。 | <code>from sync_raw_http_logs import ensure_demo_attack_events</code> |
| L0020 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0021 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0022 | 计算并保存 &#96;IP_RE&#96;（IPRE），供后续逻辑使用。 | <code>IP_RE = re.compile(r"(?&lt;![\w.])((?:\d{1,3}\.){3}\d{1,3}&#124;[a-fA-F0-9:]{3,})(?![\w.])")</code> |
| L0023 | 计算并保存 &#96;SOURCE_PATTERNS&#96;（来源PATTERNS），供后续逻辑使用。 | <code>SOURCE_PATTERNS = [</code> |
| L0024 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    re.compile(r"(?i)Source\s+Network\s+Address\s*:\s*([^\r\n]+)"),</code> |
| L0025 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    re.compile(r"源网络地址\s*[:：]\s*([^\r\n]+)"),</code> |
| L0026 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    re.compile(r"来源网络地址\s*[:：]\s*([^\r\n]+)"),</code> |
| L0027 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    re.compile(r"(?i)\bfrom\s+((?:\d{1,3}\.){3}\d{1,3}&#124;[a-fA-F0-9:]{3,})\s+port\b"),</code> |
| L0028 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    re.compile(r"(?i)remote\s+host\s*[:=]\s*((?:\d{1,3}\.){3}\d{1,3}&#124;[a-fA-F0-9:]{3,})"),</code> |
| L0029 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>]</code> |
| L0030 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0031 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0032 | 定义nowiso函数 &#96;now_iso&#96;，封装可复用业务逻辑。 | <code>def now_iso() -&gt; str:</code> |
| L0033 | 结束当前函数并把结果返回给调用方，当前位于函数 now_iso。 | <code>    return datetime.now().isoformat(timespec="seconds")</code> |
| L0034 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0035 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0036 | 定义log函数 &#96;log&#96;，封装可复用业务逻辑。 | <code>def log(message: str, log_file: Path) -&gt; None:</code> |
| L0037 | 计算并保存 &#96;line&#96;（line），供后续逻辑使用，当前位于函数 log。 | <code>    line = f"[{now_iso()}] {message}"</code> |
| L0038 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 log。 | <code>    print(line, flush=True)</code> |
| L0039 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 log。 | <code>    log_file.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0040 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 log。 | <code>    with log_file.open("a", encoding="utf-8") as f:</code> |
| L0041 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 log。 | <code>        f.write(line + "\n")</code> |
| L0042 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0043 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0044 | 定义运行powershelljson函数 &#96;run_powershell_json&#96;，封装可复用业务逻辑。 | <code>def run_powershell_json(script: str, timeout: int = 30) -&gt; List[Dict[str, Any]]:</code> |
| L0045 | 计算并保存 &#96;proc&#96;（proc），供后续逻辑使用，当前位于函数 run_powershell_json。 | <code>    proc = subprocess.run(</code> |
| L0046 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_powershell_json。 | <code>        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],</code> |
| L0047 | 计算并保存 &#96;capture_output&#96;（captureoutput），供后续逻辑使用，当前位于函数 run_powershell_json。 | <code>        capture_output=True,</code> |
| L0048 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 run_powershell_json。 | <code>        text=True,</code> |
| L0049 | 计算并保存 &#96;encoding&#96;（encoding），供后续逻辑使用，当前位于函数 run_powershell_json。 | <code>        encoding="utf-8",</code> |
| L0050 | 计算并保存 &#96;errors&#96;（errors），供后续逻辑使用，当前位于函数 run_powershell_json。 | <code>        errors="replace",</code> |
| L0051 | 计算并保存 &#96;timeout&#96;（timeout），供后续逻辑使用，当前位于函数 run_powershell_json。 | <code>        timeout=timeout,</code> |
| L0052 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_powershell_json。 | <code>    )</code> |
| L0053 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 run_powershell_json。 | <code>    if proc.returncode != 0 or not proc.stdout.strip():</code> |
| L0054 | 结束当前函数并把结果返回给调用方，当前位于函数 run_powershell_json。 | <code>        return []</code> |
| L0055 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 run_powershell_json。 | <code>    try:</code> |
| L0056 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 run_powershell_json。 | <code>        data = json.loads(proc.stdout)</code> |
| L0057 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 run_powershell_json。 | <code>    except Exception:</code> |
| L0058 | 结束当前函数并把结果返回给调用方，当前位于函数 run_powershell_json。 | <code>        return []</code> |
| L0059 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 run_powershell_json。 | <code>    if isinstance(data, dict):</code> |
| L0060 | 结束当前函数并把结果返回给调用方，当前位于函数 run_powershell_json。 | <code>        return [data]</code> |
| L0061 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 run_powershell_json。 | <code>    if isinstance(data, list):</code> |
| L0062 | 结束当前函数并把结果返回给调用方，当前位于函数 run_powershell_json。 | <code>        return [x for x in data if isinstance(x, dict)]</code> |
| L0063 | 结束当前函数并把结果返回给调用方，当前位于函数 run_powershell_json。 | <code>    return []</code> |
| L0064 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0065 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0066 | 定义读取windowssecurityfailures函数 &#96;get_windows_security_failures&#96;，封装可复用业务逻辑。 | <code>def get_windows_security_failures(window_minutes: int) -&gt; List[Dict[str, Any]]:</code> |
| L0067 | 计算并保存 &#96;script&#96;（script），供后续逻辑使用，当前位于函数 get_windows_security_failures。 | <code>    script = rf"""</code> |
| L0068 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_windows_security_failures。 | <code>$utf8 = New-Object System.Text.UTF8Encoding($false)</code> |
| L0069 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_windows_security_failures。 | <code>[Console]::OutputEncoding = $utf8</code> |
| L0070 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_windows_security_failures。 | <code>$OutputEncoding = $utf8</code> |
| L0071 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_windows_security_failures。 | <code>$start=(Get-Date).AddMinutes(-{int(window_minutes)})</code> |
| L0072 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_windows_security_failures。 | <code>Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4625; StartTime=$start}} -ErrorAction SilentlyContinue &#124;</code> |
| L0073 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_windows_security_failures。 | <code>  Select-Object TimeCreated, Id, ProviderName, Message &#124;</code> |
| L0074 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_windows_security_failures。 | <code>  ConvertTo-Json -Compress -Depth 3</code> |
| L0075 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_windows_security_failures。 | <code>"""</code> |
| L0076 | 结束当前函数并把结果返回给调用方，当前位于函数 get_windows_security_failures。 | <code>    return run_powershell_json(script)</code> |
| L0077 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0078 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0079 | 定义读取opensshfailures函数 &#96;get_openssh_failures&#96;，封装可复用业务逻辑。 | <code>def get_openssh_failures(window_minutes: int) -&gt; List[Dict[str, Any]]:</code> |
| L0080 | 计算并保存 &#96;script&#96;（script），供后续逻辑使用，当前位于函数 get_openssh_failures。 | <code>    script = rf"""</code> |
| L0081 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_openssh_failures。 | <code>$utf8 = New-Object System.Text.UTF8Encoding($false)</code> |
| L0082 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_openssh_failures。 | <code>[Console]::OutputEncoding = $utf8</code> |
| L0083 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_openssh_failures。 | <code>$OutputEncoding = $utf8</code> |
| L0084 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_openssh_failures。 | <code>$start=(Get-Date).AddMinutes(-{int(window_minutes)})</code> |
| L0085 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_openssh_failures。 | <code>Get-WinEvent -FilterHashtable @{{LogName='OpenSSH/Operational'; StartTime=$start}} -ErrorAction SilentlyContinue &#124;</code> |
| L0086 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_openssh_failures。 | <code>  Where-Object {{ $_.Message -match 'fail&#124;invalid&#124;Unable to negotiate&#124;authentication&#124;password' }} &#124;</code> |
| L0087 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_openssh_failures。 | <code>  Select-Object TimeCreated, Id, ProviderName, Message &#124;</code> |
| L0088 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_openssh_failures。 | <code>  ConvertTo-Json -Compress -Depth 3</code> |
| L0089 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 get_openssh_failures。 | <code>"""</code> |
| L0090 | 结束当前函数并把结果返回给调用方，当前位于函数 get_openssh_failures。 | <code>    return run_powershell_json(script)</code> |
| L0091 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0092 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0093 | 定义标准化事件time函数 &#96;normalize_event_time&#96;，封装可复用业务逻辑。 | <code>def normalize_event_time(value: Any) -&gt; datetime:</code> |
| L0094 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 normalize_event_time。 | <code>    text = str(value or "").strip()</code> |
| L0095 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_event_time。 | <code>    if not text:</code> |
| L0096 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_event_time。 | <code>        return datetime.now()</code> |
| L0097 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 normalize_event_time。 | <code>    text = text.replace("Z", "")</code> |
| L0098 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_event_time。 | <code>    if text.startswith("/Date("):</code> |
| L0099 | 计算并保存 &#96;m&#96;（m），供后续逻辑使用，当前位于函数 normalize_event_time。 | <code>        m = re.search(r"/Date\((\d+)", text)</code> |
| L0100 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_event_time。 | <code>        if m:</code> |
| L0101 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_event_time。 | <code>            return datetime.fromtimestamp(int(m.group(1)) / 1000)</code> |
| L0102 | 遍历集合中的数据项并逐项处理，当前位于函数 normalize_event_time。 | <code>    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):</code> |
| L0103 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 normalize_event_time。 | <code>        try:</code> |
| L0104 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_event_time。 | <code>            return datetime.strptime(text[:26], fmt)</code> |
| L0105 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 normalize_event_time。 | <code>        except Exception:</code> |
| L0106 | 控制当前循环或占位分支的执行流程，当前位于函数 normalize_event_time。 | <code>            continue</code> |
| L0107 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 normalize_event_time。 | <code>    try:</code> |
| L0108 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_event_time。 | <code>        return datetime.fromisoformat(text)</code> |
| L0109 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 normalize_event_time。 | <code>    except Exception:</code> |
| L0110 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_event_time。 | <code>        return datetime.now()</code> |
| L0111 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0112 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0113 | 定义ispublicorlanip函数 &#96;is_public_or_lan_ip&#96;，封装可复用业务逻辑。 | <code>def is_public_or_lan_ip(ip: str) -&gt; bool:</code> |
| L0114 | 计算并保存 &#96;ip&#96;（ip），供后续逻辑使用，当前位于函数 is_public_or_lan_ip。 | <code>    ip = str(ip or "").strip()</code> |
| L0115 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_public_or_lan_ip。 | <code>    if not ip or ip == "-":</code> |
| L0116 | 结束当前函数并把结果返回给调用方，当前位于函数 is_public_or_lan_ip。 | <code>        return False</code> |
| L0117 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 is_public_or_lan_ip。 | <code>    try:</code> |
| L0118 | 计算并保存 &#96;address&#96;（address），供后续逻辑使用，当前位于函数 is_public_or_lan_ip。 | <code>        address = ipaddress.ip_address(ip)</code> |
| L0119 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 is_public_or_lan_ip。 | <code>    except ValueError:</code> |
| L0120 | 结束当前函数并把结果返回给调用方，当前位于函数 is_public_or_lan_ip。 | <code>        return False</code> |
| L0121 | 结束当前函数并把结果返回给调用方，当前位于函数 is_public_or_lan_ip。 | <code>    return not (address.is_unspecified or address.is_loopback or address.is_link_local)</code> |
| L0122 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0123 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0124 | 定义extract来源ip函数 &#96;extract_source_ip&#96;，封装可复用业务逻辑。 | <code>def extract_source_ip(message: str) -&gt; str:</code> |
| L0125 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 extract_source_ip。 | <code>    text = str(message or "")</code> |
| L0126 | 遍历集合中的数据项并逐项处理，当前位于函数 extract_source_ip。 | <code>    for pattern in SOURCE_PATTERNS:</code> |
| L0127 | 计算并保存 &#96;m&#96;（m），供后续逻辑使用，当前位于函数 extract_source_ip。 | <code>        m = pattern.search(text)</code> |
| L0128 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 extract_source_ip。 | <code>        if m:</code> |
| L0129 | 计算并保存 &#96;ip&#96;（ip），供后续逻辑使用，当前位于函数 extract_source_ip。 | <code>            ip = m.group(1).strip()</code> |
| L0130 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 extract_source_ip。 | <code>            if is_public_or_lan_ip(ip):</code> |
| L0131 | 结束当前函数并把结果返回给调用方，当前位于函数 extract_source_ip。 | <code>                return ip</code> |
| L0132 | 遍历集合中的数据项并逐项处理，当前位于函数 extract_source_ip。 | <code>    for ip in IP_RE.findall(text):</code> |
| L0133 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 extract_source_ip。 | <code>        if is_public_or_lan_ip(ip):</code> |
| L0134 | 结束当前函数并把结果返回给调用方，当前位于函数 extract_source_ip。 | <code>            return ip</code> |
| L0135 | 结束当前函数并把结果返回给调用方，当前位于函数 extract_source_ip。 | <code>    return ""</code> |
| L0136 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0137 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0138 | 定义summarizefailure事件函数 &#96;summarize_failure_event&#96;，封装可复用业务逻辑。 | <code>def summarize_failure_event(item: Dict[str, Any], message: str, source_ip: str) -&gt; str:</code> |
| L0139 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 summarize_failure_event。 | <code>    """Return stable evidence without persisting localized Windows message blobs."""</code> |
| L0140 | 计算并保存 &#96;provider&#96;（provider），供后续逻辑使用，当前位于函数 summarize_failure_event。 | <code>    provider = str(item.get("ProviderName") or "").strip()</code> |
| L0141 | 计算并保存 &#96;event_id&#96;（事件id），供后续逻辑使用，当前位于函数 summarize_failure_event。 | <code>    event_id = str(item.get("Id") or "").strip()</code> |
| L0142 | 计算并保存 &#96;account_patterns&#96;（accountpatterns），供后续逻辑使用，当前位于函数 summarize_failure_event。 | <code>    account_patterns = [</code> |
| L0143 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 summarize_failure_event。 | <code>        re.compile(r"(?im)^\s*(?:Account Name&#124;Target User Name)\s*:\s*([^\r\n]+)"),</code> |
| L0144 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 summarize_failure_event。 | <code>        re.compile(r"(?im)^\s*(?:帐户名&#124;账户名&#124;目标帐户名&#124;目标账户名)\s*[:：]\s*([^\r\n]+)"),</code> |
| L0145 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 summarize_failure_event。 | <code>    ]</code> |
| L0146 | 计算并保存 &#96;accounts&#96;（accounts），供后续逻辑使用，当前位于函数 summarize_failure_event。 | <code>    accounts: List[str] = []</code> |
| L0147 | 遍历集合中的数据项并逐项处理，当前位于函数 summarize_failure_event。 | <code>    for pattern in account_patterns:</code> |
| L0148 | 遍历集合中的数据项并逐项处理，当前位于函数 summarize_failure_event。 | <code>        for value in pattern.findall(str(message or "")):</code> |
| L0149 | 计算并保存 &#96;clean&#96;（clean），供后续逻辑使用，当前位于函数 summarize_failure_event。 | <code>            clean = re.sub(r"[\x00-\x1f\x7f]", "", str(value)).strip()</code> |
| L0150 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 summarize_failure_event。 | <code>            if clean and clean not in {"-", "N/A"} and "�" not in clean:</code> |
| L0151 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 summarize_failure_event。 | <code>                accounts.append(clean[:80])</code> |
| L0152 | 计算并保存 &#96;account&#96;（account），供后续逻辑使用，当前位于函数 summarize_failure_event。 | <code>    account = accounts[-1] if accounts else "未知"</code> |
| L0153 | 计算并保存 &#96;source&#96;（来源），供后续逻辑使用，当前位于函数 summarize_failure_event。 | <code>    source = "OpenSSH 日志" if "openssh" in provider.lower() else "Windows 安全日志"</code> |
| L0154 | 计算并保存 &#96;parts&#96;（parts），供后续逻辑使用，当前位于函数 summarize_failure_event。 | <code>    parts = [f"{source}登录失败", f"来源IP={source_ip}", f"目标账户={account}"]</code> |
| L0155 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 summarize_failure_event。 | <code>    if event_id:</code> |
| L0156 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 summarize_failure_event。 | <code>        parts.append(f"事件ID={event_id}")</code> |
| L0157 | 结束当前函数并把结果返回给调用方，当前位于函数 summarize_failure_event。 | <code>    return "；".join(parts)</code> |
| L0158 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0159 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0160 | 定义collectsshfailures函数 &#96;collect_ssh_failures&#96;，封装可复用业务逻辑。 | <code>def collect_ssh_failures(window_minutes: int) -&gt; List[Tuple[datetime, str, str]]:</code> |
| L0161 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 collect_ssh_failures。 | <code>    rows: List[Tuple[datetime, str, str]] = []</code> |
| L0162 | 遍历集合中的数据项并逐项处理，当前位于函数 collect_ssh_failures。 | <code>    for item in get_windows_security_failures(window_minutes) + get_openssh_failures(window_minutes):</code> |
| L0163 | 计算并保存 &#96;message&#96;（message），供后续逻辑使用，当前位于函数 collect_ssh_failures。 | <code>        message = str(item.get("Message") or "")</code> |
| L0164 | 计算并保存 &#96;ip&#96;（ip），供后续逻辑使用，当前位于函数 collect_ssh_failures。 | <code>        ip = extract_source_ip(message)</code> |
| L0165 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 collect_ssh_failures。 | <code>        if not ip:</code> |
| L0166 | 控制当前循环或占位分支的执行流程，当前位于函数 collect_ssh_failures。 | <code>            continue</code> |
| L0167 | 计算并保存 &#96;t&#96;（t），供后续逻辑使用，当前位于函数 collect_ssh_failures。 | <code>        t = normalize_event_time(item.get("TimeCreated"))</code> |
| L0168 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 collect_ssh_failures。 | <code>        rows.append((t, ip, summarize_failure_event(item, message, ip)))</code> |
| L0169 | 结束当前函数并把结果返回给调用方，当前位于函数 collect_ssh_failures。 | <code>    return rows</code> |
| L0170 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0171 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0172 | 定义bucket启动函数 &#96;bucket_start&#96;，封装可复用业务逻辑。 | <code>def bucket_start(dt: datetime, minutes: int) -&gt; datetime:</code> |
| L0173 | 计算并保存 &#96;minute&#96;（minute），供后续逻辑使用，当前位于函数 bucket_start。 | <code>    minute = (dt.minute // minutes) * minutes</code> |
| L0174 | 结束当前函数并把结果返回给调用方，当前位于函数 bucket_start。 | <code>    return dt.replace(minute=minute, second=0, microsecond=0)</code> |
| L0175 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0176 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0177 | 定义事件idfor函数 &#96;event_id_for&#96;，封装可复用业务逻辑。 | <code>def event_id_for(group_key: str, bucket: datetime, aggregate: bool = False) -&gt; str:</code> |
| L0178 | 计算并保存 &#96;prefix&#96;（prefix），供后续逻辑使用，当前位于函数 event_id_for。 | <code>    prefix = "SSHAGG" if aggregate else "SSH"</code> |
| L0179 | 计算并保存 &#96;digest&#96;（digest），供后续逻辑使用，当前位于函数 event_id_for。 | <code>    digest = hashlib.sha1(f"ssh&#124;{group_key}&#124;{bucket.isoformat()}".encode("utf-8")).hexdigest()[:18].upper()</code> |
| L0180 | 结束当前函数并把结果返回给调用方，当前位于函数 event_id_for。 | <code>    return f"{prefix}{digest}"</code> |
| L0181 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0182 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0183 | 定义写入ssh事件函数 &#96;write_ssh_event&#96;，封装可复用业务逻辑。 | <code>def write_ssh_event(</code> |
| L0184 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>    conn: Any,</code> |
| L0185 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>    ip: str,</code> |
| L0186 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>    bucket: datetime,</code> |
| L0187 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>    count: int,</code> |
| L0188 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>    samples: Iterable[str],</code> |
| L0189 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>    *,</code> |
| L0190 | 计算并保存 &#96;aggregate&#96;（聚合），供后续逻辑使用，当前位于函数 write_ssh_event。 | <code>    aggregate: bool = False,</code> |
| L0191 | 计算并保存 &#96;unique_ips&#96;（uniqueips），供后续逻辑使用，当前位于函数 write_ssh_event。 | <code>    unique_ips: int = 1,</code> |
| L0192 | 计算并保存 &#96;top_sources&#96;（topsources），供后续逻辑使用，当前位于函数 write_ssh_event。 | <code>    top_sources: List[Tuple[str, int]] &#124; None = None,</code> |
| L0193 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 write_ssh_event。 | <code>) -&gt; None:</code> |
| L0194 | 计算并保存 &#96;group_key&#96;（groupkey），供后续逻辑使用，当前位于函数 write_ssh_event。 | <code>    group_key = "all" if aggregate else ip</code> |
| L0195 | 计算并保存 &#96;event_id&#96;（事件id），供后续逻辑使用，当前位于函数 write_ssh_event。 | <code>    event_id = event_id_for(group_key, bucket, aggregate=aggregate)</code> |
| L0196 | 计算并保存 &#96;case_id&#96;（caseid），供后续逻辑使用，当前位于函数 write_ssh_event。 | <code>    case_id = f"ssh:{group_key}:{bucket.strftime('%Y%m%d%H%M')}"</code> |
| L0197 | 计算并保存 &#96;top_sources&#96;（topsources），供后续逻辑使用，当前位于函数 write_ssh_event。 | <code>    top_sources = top_sources or [(ip, count)]</code> |
| L0198 | 计算并保存 &#96;top_source_text&#96;（top来源text），供后续逻辑使用，当前位于函数 write_ssh_event。 | <code>    top_source_text = "，".join([f"{src_ip}({src_count}次)" for src_ip, src_count in top_sources[:5]])</code> |
| L0199 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 write_ssh_event。 | <code>    evidence = [</code> |
| L0200 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>        f"聚合窗口：{bucket.strftime('%Y-%m-%d %H:%M:%S')} ~ {(bucket + timedelta(minutes=10)).strftime('%H:%M:%S')}",</code> |
| L0201 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>        f"来源IP数量：{unique_ips}",</code> |
| L0202 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>        f"主要来源：{top_source_text}",</code> |
| L0203 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>        f"SSH登录失败次数：{count}",</code> |
| L0204 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 write_ssh_event。 | <code>    ]</code> |
| L0205 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_ssh_event。 | <code>    evidence.extend([x for x in samples if x][:3])</code> |
| L0206 | 计算并保存 &#96;evidence_json&#96;（evidencejson），供后续逻辑使用，当前位于函数 write_ssh_event。 | <code>    evidence_json = json.dumps(evidence, ensure_ascii=False)</code> |
| L0207 | 计算并保存 &#96;occurred_at&#96;（occurredat），供后续逻辑使用，当前位于函数 write_ssh_event。 | <code>    occurred_at = bucket.isoformat(timespec="seconds")</code> |
| L0208 | 计算并保存 &#96;confidence&#96;（confidence），供后续逻辑使用，当前位于函数 write_ssh_event。 | <code>    confidence = min(0.99, 0.72 + count * 0.025)</code> |
| L0209 | 计算并保存 &#96;risk_level&#96;（risklevel），供后续逻辑使用，当前位于函数 write_ssh_event。 | <code>    risk_level = "critical" if count &gt;= 20 else "high"</code> |
| L0210 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0211 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>    upsert_mysql(</code> |
| L0212 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>        conn,</code> |
| L0213 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>        "detection_candidates",</code> |
| L0214 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>        {</code> |
| L0215 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "event_id": event_id,</code> |
| L0216 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "case_id": case_id,</code> |
| L0217 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "file_id": "ssh-auth-log",</code> |
| L0218 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "seq_id": count,</code> |
| L0219 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "decision": "attack_event",</code> |
| L0220 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "final_score": confidence,</code> |
| L0221 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "risk_level": risk_level,</code> |
| L0222 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "attack_type": "SSH爆破",</code> |
| L0223 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "source_ip": ip,</code> |
| L0224 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "target_interface": "ssh:22",</code> |
| L0225 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "evidence_json": evidence_json,</code> |
| L0226 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 write_ssh_event。 | <code>        },</code> |
| L0227 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 write_ssh_event。 | <code>    )</code> |
| L0228 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>    upsert_mysql(</code> |
| L0229 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>        conn,</code> |
| L0230 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>        "attack_events",</code> |
| L0231 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>        {</code> |
| L0232 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "event_id": event_id,</code> |
| L0233 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "case_id": case_id,</code> |
| L0234 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "occurred_at": occurred_at,</code> |
| L0235 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "source_ip": ip,</code> |
| L0236 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "target_interface": "ssh:22",</code> |
| L0237 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "attack_type": "SSH爆破",</code> |
| L0238 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "risk_level": risk_level,</code> |
| L0239 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "confidence": confidence,</code> |
| L0240 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "status": "unprocessed",</code> |
| L0241 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            "evidence_json": evidence_json,</code> |
| L0242 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 write_ssh_event。 | <code>        },</code> |
| L0243 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 write_ssh_event。 | <code>    )</code> |
| L0244 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 write_ssh_event。 | <code>    with conn.cursor() as cur:</code> |
| L0245 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 write_ssh_event。 | <code>        cur.execute("DELETE FROM behavior_windows WHERE case_id=%s", (case_id,))</code> |
| L0246 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 write_ssh_event。 | <code>        cur.execute(</code> |
| L0247 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 write_ssh_event。 | <code>            """INSERT INTO behavior_windows(case_id,source_ip,behavior_type,score,features_json,evidence_json)</code> |
| L0248 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 write_ssh_event。 | <code>               VALUES(%s,%s,%s,%s,%s,%s)""",</code> |
| L0249 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            (</code> |
| L0250 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                case_id,</code> |
| L0251 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                ip,</code> |
| L0252 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                "SSH爆破",</code> |
| L0253 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                confidence,</code> |
| L0254 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                json.dumps(</code> |
| L0255 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                    {</code> |
| L0256 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                        "ssh_fail_count": count,</code> |
| L0257 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                        "unique_source_ips": unique_ips,</code> |
| L0258 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                        "top_sources": top_sources[:10],</code> |
| L0259 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                        "window_minutes": 10,</code> |
| L0260 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                        "aggregate": aggregate,</code> |
| L0261 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 write_ssh_event。 | <code>                    },</code> |
| L0262 | 计算并保存 &#96;ensure_ascii&#96;（ensureascii），供后续逻辑使用，当前位于函数 write_ssh_event。 | <code>                    ensure_ascii=False,</code> |
| L0263 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 write_ssh_event。 | <code>                ),</code> |
| L0264 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                evidence_json,</code> |
| L0265 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 write_ssh_event。 | <code>            ),</code> |
| L0266 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 write_ssh_event。 | <code>        )</code> |
| L0267 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 write_ssh_event。 | <code>        cur.execute(</code> |
| L0268 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 write_ssh_event。 | <code>            """</code> |
| L0269 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 write_ssh_event。 | <code>            INSERT INTO demo_attack_events(</code> |
| L0270 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 write_ssh_event。 | <code>              event_id, occurred_at, risk_level, attack_type, source_ip, source_region,</code> |
| L0271 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 write_ssh_event。 | <code>              target_node, target_port, target_interface, attack_result, process_status,</code> |
| L0272 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 write_ssh_event。 | <code>              attack_payload, request_log, protection_action, handling_suggestion,</code> |
| L0273 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 write_ssh_event。 | <code>              response_ms, anomaly_detected</code> |
| L0274 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 write_ssh_event。 | <code>            )</code> |
| L0275 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 write_ssh_event。 | <code>            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)</code> |
| L0276 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 write_ssh_event。 | <code>            ON DUPLICATE KEY UPDATE</code> |
| L0277 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 write_ssh_event。 | <code>              occurred_at=VALUES(occurred_at),</code> |
| L0278 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 write_ssh_event。 | <code>              risk_level=VALUES(risk_level),</code> |
| L0279 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 write_ssh_event。 | <code>              source_ip=VALUES(source_ip),</code> |
| L0280 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 write_ssh_event。 | <code>              target_port=VALUES(target_port),</code> |
| L0281 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 write_ssh_event。 | <code>              attack_payload=VALUES(attack_payload),</code> |
| L0282 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 write_ssh_event。 | <code>              request_log=VALUES(request_log),</code> |
| L0283 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 write_ssh_event。 | <code>              handling_suggestion=VALUES(handling_suggestion),</code> |
| L0284 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 write_ssh_event。 | <code>              updated_at=CURRENT_TIMESTAMP</code> |
| L0285 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 write_ssh_event。 | <code>            """,</code> |
| L0286 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>            (</code> |
| L0287 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                event_id[:40],</code> |
| L0288 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                occurred_at.replace("T", " "),</code> |
| L0289 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                risk_level,</code> |
| L0290 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                "SSH爆破",</code> |
| L0291 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                ip,</code> |
| L0292 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                "未知地区",</code> |
| L0293 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                socket.gethostname(),</code> |
| L0294 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                22,</code> |
| L0295 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                "ssh:22",</code> |
| L0296 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                "已拦截",</code> |
| L0297 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                "unprocessed",</code> |
| L0298 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                f"SSH failed login x{count}; unique_ips={unique_ips}; top_sources={top_source_text}",</code> |
| L0299 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                "\n".join(evidence),</code> |
| L0300 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                "SSH行为窗口检测",</code> |
| L0301 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                "检测到短时间内SSH登录失败次数异常，建议限制SSH暴露面、启用密钥登录并封禁高频来源IP。",</code> |
| L0302 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                0,</code> |
| L0303 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_ssh_event。 | <code>                1,</code> |
| L0304 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 write_ssh_event。 | <code>            ),</code> |
| L0305 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 write_ssh_event。 | <code>        )</code> |
| L0306 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0307 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0308 | 定义同步once函数 &#96;sync_once&#96;，封装可复用业务逻辑。 | <code>def sync_once(conn: Any, window_minutes: int, threshold: int, bucket_minutes: int, group_mode: str = "global") -&gt; Dict[str, int]:</code> |
| L0309 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 sync_once。 | <code>    rows = collect_ssh_failures(window_minutes)</code> |
| L0310 | 计算并保存 &#96;grouped&#96;（grouped），供后续逻辑使用，当前位于函数 sync_once。 | <code>    grouped: Dict[Tuple[str, datetime], List[str]] = defaultdict(list)</code> |
| L0311 | 计算并保存 &#96;counter&#96;（counter），供后续逻辑使用，当前位于函数 sync_once。 | <code>    counter: Counter[Tuple[str, datetime]] = Counter()</code> |
| L0312 | 计算并保存 &#96;bucket_ip_counter&#96;（bucketipcounter），供后续逻辑使用，当前位于函数 sync_once。 | <code>    bucket_ip_counter: Dict[datetime, Counter[str]] = defaultdict(Counter)</code> |
| L0313 | 计算并保存 &#96;bucket_samples&#96;（bucketsamples），供后续逻辑使用，当前位于函数 sync_once。 | <code>    bucket_samples: Dict[datetime, List[str]] = defaultdict(list)</code> |
| L0314 | 遍历集合中的数据项并逐项处理，当前位于函数 sync_once。 | <code>    for t, ip, message in rows:</code> |
| L0315 | 计算并保存 &#96;bucket&#96;（bucket），供后续逻辑使用，当前位于函数 sync_once。 | <code>        bucket = bucket_start(t, bucket_minutes)</code> |
| L0316 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_once。 | <code>        if group_mode == "source_ip":</code> |
| L0317 | 计算并保存 &#96;key&#96;（key），供后续逻辑使用，当前位于函数 sync_once。 | <code>            key = (ip, bucket)</code> |
| L0318 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_once。 | <code>            counter[key] += 1</code> |
| L0319 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_once。 | <code>            if len(grouped[key]) &lt; 3:</code> |
| L0320 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 sync_once。 | <code>                grouped[key].append(message)</code> |
| L0321 | 处理前述条件均未命中的情况，当前位于函数 sync_once。 | <code>        else:</code> |
| L0322 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_once。 | <code>            bucket_ip_counter[bucket][ip] += 1</code> |
| L0323 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_once。 | <code>            if len(bucket_samples[bucket]) &lt; 3:</code> |
| L0324 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 sync_once。 | <code>                bucket_samples[bucket].append(message)</code> |
| L0325 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0326 | 计算并保存 &#96;written&#96;（written），供后续逻辑使用，当前位于函数 sync_once。 | <code>    written = 0</code> |
| L0327 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_once。 | <code>    if group_mode == "source_ip":</code> |
| L0328 | 遍历集合中的数据项并逐项处理，当前位于函数 sync_once。 | <code>        for (ip, bucket), count in counter.items():</code> |
| L0329 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_once。 | <code>            if count &lt; threshold:</code> |
| L0330 | 控制当前循环或占位分支的执行流程，当前位于函数 sync_once。 | <code>                continue</code> |
| L0331 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_once。 | <code>            write_ssh_event(conn, ip, bucket, count, grouped[(ip, bucket)])</code> |
| L0332 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_once。 | <code>            written += 1</code> |
| L0333 | 处理前述条件均未命中的情况，当前位于函数 sync_once。 | <code>    else:</code> |
| L0334 | 遍历集合中的数据项并逐项处理，当前位于函数 sync_once。 | <code>        for bucket, ip_counts in bucket_ip_counter.items():</code> |
| L0335 | 计算并保存 &#96;count&#96;（count），供后续逻辑使用，当前位于函数 sync_once。 | <code>            count = sum(ip_counts.values())</code> |
| L0336 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 sync_once。 | <code>            if count &lt; threshold:</code> |
| L0337 | 控制当前循环或占位分支的执行流程，当前位于函数 sync_once。 | <code>                continue</code> |
| L0338 | 计算并保存 &#96;top_sources&#96;（topsources），供后续逻辑使用，当前位于函数 sync_once。 | <code>            top_sources = ip_counts.most_common(10)</code> |
| L0339 | 计算并保存 &#96;top_ip&#96;（topip），供后续逻辑使用，当前位于函数 sync_once。 | <code>            top_ip = top_sources[0][0] if top_sources else ""</code> |
| L0340 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_once。 | <code>            write_ssh_event(</code> |
| L0341 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_once。 | <code>                conn,</code> |
| L0342 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_once。 | <code>                top_ip,</code> |
| L0343 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_once。 | <code>                bucket,</code> |
| L0344 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_once。 | <code>                count,</code> |
| L0345 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_once。 | <code>                bucket_samples[bucket],</code> |
| L0346 | 计算并保存 &#96;aggregate&#96;（聚合），供后续逻辑使用，当前位于函数 sync_once。 | <code>                aggregate=True,</code> |
| L0347 | 计算并保存 &#96;unique_ips&#96;（uniqueips），供后续逻辑使用，当前位于函数 sync_once。 | <code>                unique_ips=len(ip_counts),</code> |
| L0348 | 计算并保存 &#96;top_sources&#96;（topsources），供后续逻辑使用，当前位于函数 sync_once。 | <code>                top_sources=top_sources,</code> |
| L0349 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sync_once。 | <code>            )</code> |
| L0350 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sync_once。 | <code>            written += 1</code> |
| L0351 | 结束当前函数并把结果返回给调用方，当前位于函数 sync_once。 | <code>    return {"observed": len(rows), "written": written, "unique_ips": len({ip for _, ip, _ in rows})}</code> |
| L0352 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0353 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0354 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; None:</code> |
| L0355 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="Monitor Windows SSH/login failures and aggregate SSH brute-force events into MySQL")</code> |
| L0356 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-host", default="127.0.0.1")</code> |
| L0357 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-port", type=int, default=3306)</code> |
| L0358 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-user", default="root")</code> |
| L0359 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-password", default="123456")</code> |
| L0360 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-database", default="traffic_pipeline")</code> |
| L0361 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--window-minutes", type=int, default=10)</code> |
| L0362 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--bucket-minutes", type=int, default=10)</code> |
| L0363 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--threshold", type=int, default=5)</code> |
| L0364 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--poll-seconds", type=int, default=20)</code> |
| L0365 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--log-file", default="output/ssh_bruteforce_monitor.log")</code> |
| L0366 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument(</code> |
| L0367 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--group-mode",</code> |
| L0368 | 计算并保存 &#96;choices&#96;（choices），供后续逻辑使用，当前位于函数 main。 | <code>        choices=["global", "source_ip"],</code> |
| L0369 | 计算并保存 &#96;default&#96;（default），供后续逻辑使用，当前位于函数 main。 | <code>        default="global",</code> |
| L0370 | 计算并保存 &#96;help&#96;（help），供后续逻辑使用，当前位于函数 main。 | <code>        help="Aggregate SSH brute-force alerts globally per time bucket or per source IP",</code> |
| L0371 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0372 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--once", action="store_true")</code> |
| L0373 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0374 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0375 | 计算并保存 &#96;project_root&#96;（projectroot），供后续逻辑使用，当前位于函数 main。 | <code>    project_root = Path(__file__).resolve().parent.parent</code> |
| L0376 | 计算并保存 &#96;log_file&#96;（logfile），供后续逻辑使用，当前位于函数 main。 | <code>    log_file = (project_root / args.log_file).resolve()</code> |
| L0377 | 计算并保存 &#96;cfg&#96;（cfg），供后续逻辑使用，当前位于函数 main。 | <code>    cfg = MySQLConfig(</code> |
| L0378 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 main。 | <code>        host=args.mysql_host,</code> |
| L0379 | 计算并保存 &#96;port&#96;（port），供后续逻辑使用，当前位于函数 main。 | <code>        port=args.mysql_port,</code> |
| L0380 | 计算并保存 &#96;user&#96;（user），供后续逻辑使用，当前位于函数 main。 | <code>        user=args.mysql_user,</code> |
| L0381 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>        password=args.mysql_password,</code> |
| L0382 | 计算并保存 &#96;database&#96;（数据库），供后续逻辑使用，当前位于函数 main。 | <code>        database=args.mysql_database,</code> |
| L0383 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0384 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0385 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 main。 | <code>    while True:</code> |
| L0386 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>        try:</code> |
| L0387 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 main。 | <code>            conn = mysql_connect(cfg)</code> |
| L0388 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            ensure_mysql(conn)</code> |
| L0389 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            ensure_demo_attack_events(conn)</code> |
| L0390 | 计算并保存 &#96;stats&#96;（stats），供后续逻辑使用，当前位于函数 main。 | <code>            stats = sync_once(conn, args.window_minutes, args.threshold, args.bucket_minutes, args.group_mode)</code> |
| L0391 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            conn.close()</code> |
| L0392 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>            log(</code> |
| L0393 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                f"ssh monitor sync observed={stats['observed']} unique_ips={stats.get('unique_ips', 0)} "</code> |
| L0394 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                f"written={stats['written']} group_mode={args.group_mode}",</code> |
| L0395 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                log_file,</code> |
| L0396 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>            )</code> |
| L0397 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>        except Exception as exc:  # noqa: BLE001</code> |
| L0398 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>            log(f"ssh monitor failed: {exc}", log_file)</code> |
| L0399 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if args.once:</code> |
| L0400 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                raise</code> |
| L0401 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if args.once:</code> |
| L0402 | 结束当前函数并把结果返回给调用方，当前位于函数 main。 | <code>            return</code> |
| L0403 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        time.sleep(max(5, int(args.poll_seconds)))</code> |
| L0404 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0405 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0406 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0407 | 开始受保护操作，异常会交给后续分支处理。 | <code>    try:</code> |
| L0408 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        main()</code> |
| L0409 | 捕获异常，避免单次错误导致整个服务退出。 | <code>    except KeyboardInterrupt:</code> |
| L0410 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>        sys.exit(0)</code> |
