# `scripts/situation_supervisor.py` 逐行注释

**脚本用途：** 态势子服务监护器，启动并检查端口扫描、态势聚合和 AI 报告进程。

**源码行数：** 317　**函数/类数量：** 13

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import socket&#96;。 | <code>import socket</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import subprocess&#96;。 | <code>import subprocess</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;import sys&#96;。 | <code>import sys</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;import time&#96;。 | <code>import time</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;import re&#96;。 | <code>import re</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime&#96;。 | <code>from datetime import datetime</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0012 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Dict, List, Optional&#96;。 | <code>from typing import Dict, List, Optional</code> |
| L0013 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0014 | 导入后续逻辑所需的模块、类或函数：&#96;import pymysql&#96;。 | <code>import pymysql</code> |
| L0015 | 导入后续逻辑所需的模块、类或函数：&#96;from pymysql.cursors import DictCursor&#96;。 | <code>from pymysql.cursors import DictCursor</code> |
| L0016 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0017 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0018 | 定义log函数 &#96;log&#96;，封装可复用业务逻辑。 | <code>def log(message: str) -&gt; None:</code> |
| L0019 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 log。 | <code>    print(f"[{datetime.now().isoformat(timespec='seconds')}] {message}", flush=True)</code> |
| L0020 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0021 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0022 | 定义validatedinttext函数 &#96;validated_int_text&#96;，封装可复用业务逻辑。 | <code>def validated_int_text(value: object, fallback: int, minimum: int, maximum: int) -&gt; str:</code> |
| L0023 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 validated_int_text。 | <code>    try:</code> |
| L0024 | 计算并保存 &#96;parsed&#96;（parsed），供后续逻辑使用，当前位于函数 validated_int_text。 | <code>        parsed = int(str(value).strip())</code> |
| L0025 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 validated_int_text。 | <code>    except (TypeError, ValueError):</code> |
| L0026 | 计算并保存 &#96;parsed&#96;（parsed），供后续逻辑使用，当前位于函数 validated_int_text。 | <code>        parsed = int(fallback)</code> |
| L0027 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 validated_int_text。 | <code>    if parsed &lt; minimum or parsed &gt; maximum:</code> |
| L0028 | 计算并保存 &#96;parsed&#96;（parsed），供后续逻辑使用，当前位于函数 validated_int_text。 | <code>        parsed = int(fallback)</code> |
| L0029 | 结束当前函数并把结果返回给调用方，当前位于函数 validated_int_text。 | <code>    return str(parsed)</code> |
| L0030 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0031 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0032 | 定义解析并确定tsharkinterfaceindex函数 &#96;resolve_tshark_interface_index&#96;，封装可复用业务逻辑。 | <code>def resolve_tshark_interface_index(configured: str) -&gt; str:</code> |
| L0033 | 计算并保存 &#96;value&#96;（value），供后续逻辑使用，当前位于函数 resolve_tshark_interface_index。 | <code>    value = str(configured or "").strip()</code> |
| L0034 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_tshark_interface_index。 | <code>    if not value or value.isdigit() or value.lower() in {"auto", "none", "off"}:</code> |
| L0035 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_tshark_interface_index。 | <code>        return value</code> |
| L0036 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 resolve_tshark_interface_index。 | <code>    try:</code> |
| L0037 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 resolve_tshark_interface_index。 | <code>        result = subprocess.run(</code> |
| L0038 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 resolve_tshark_interface_index。 | <code>            ["tshark", "-D"], capture_output=True, text=True,</code> |
| L0039 | 计算并保存 &#96;encoding&#96;（encoding），供后续逻辑使用，当前位于函数 resolve_tshark_interface_index。 | <code>            encoding="utf-8", errors="replace", timeout=12,</code> |
| L0040 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 resolve_tshark_interface_index。 | <code>        )</code> |
| L0041 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_tshark_interface_index。 | <code>        if result.returncode == 0:</code> |
| L0042 | 计算并保存 &#96;needle&#96;（needle），供后续逻辑使用，当前位于函数 resolve_tshark_interface_index。 | <code>            needle = value.lower()</code> |
| L0043 | 遍历集合中的数据项并逐项处理，当前位于函数 resolve_tshark_interface_index。 | <code>            for line in result.stdout.splitlines():</code> |
| L0044 | 计算并保存 &#96;match&#96;（match），供后续逻辑使用，当前位于函数 resolve_tshark_interface_index。 | <code>                match = re.match(r"^\s*(\d+)\.\s+(.+)$", line)</code> |
| L0045 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 resolve_tshark_interface_index。 | <code>                if match and needle in match.group(2).lower():</code> |
| L0046 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_tshark_interface_index。 | <code>                    return match.group(1)</code> |
| L0047 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 resolve_tshark_interface_index。 | <code>    except Exception:</code> |
| L0048 | 控制当前循环或占位分支的执行流程，当前位于函数 resolve_tshark_interface_index。 | <code>        pass</code> |
| L0049 | 结束当前函数并把结果返回给调用方，当前位于函数 resolve_tshark_interface_index。 | <code>    return value</code> |
| L0050 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0051 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0052 | 定义停止函数 &#96;stop&#96;，封装可复用业务逻辑。 | <code>def stop(proc: Optional[subprocess.Popen], name: str) -&gt; None:</code> |
| L0053 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 stop。 | <code>    if not proc or proc.poll() is not None:</code> |
| L0054 | 结束当前函数并把结果返回给调用方，当前位于函数 stop。 | <code>        return</code> |
| L0055 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 stop。 | <code>    log(f"stopping {name} pid={proc.pid}")</code> |
| L0056 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 stop。 | <code>    proc.terminate()</code> |
| L0057 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 stop。 | <code>    try:</code> |
| L0058 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 stop。 | <code>        proc.wait(timeout=8)</code> |
| L0059 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 stop。 | <code>    except subprocess.TimeoutExpired:</code> |
| L0060 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 stop。 | <code>        proc.kill()</code> |
| L0061 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0062 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0063 | 定义加载runtime配置函数 &#96;load_runtime_config&#96;，封装可复用业务逻辑。 | <code>def load_runtime_config(args: argparse.Namespace) -&gt; Dict[str, str]:</code> |
| L0064 | 计算并保存 &#96;fallback&#96;（fallback），供后续逻辑使用，当前位于函数 load_runtime_config。 | <code>    fallback = {</code> |
| L0065 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>        "capture_interface": args.interface,</code> |
| L0066 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>        "llm_model": args.model,</code> |
| L0067 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>        "situation_minimum_actions": str(args.minimum_actions),</code> |
| L0068 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>        "situation_window_minutes": str(args.window_minutes),</code> |
| L0069 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>        "situation_inactivity_minutes": str(args.inactivity_minutes),</code> |
| L0070 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>        "scan_port_threshold": str(args.scan_port_threshold),</code> |
| L0071 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>        "scan_window_seconds": str(args.scan_window_seconds),</code> |
| L0072 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_runtime_config。 | <code>    }</code> |
| L0073 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 load_runtime_config。 | <code>    try:</code> |
| L0074 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 load_runtime_config。 | <code>        conn = pymysql.connect(</code> |
| L0075 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 load_runtime_config。 | <code>            host=args.mysql_host,</code> |
| L0076 | 计算并保存 &#96;port&#96;（port），供后续逻辑使用，当前位于函数 load_runtime_config。 | <code>            port=args.mysql_port,</code> |
| L0077 | 计算并保存 &#96;user&#96;（user），供后续逻辑使用，当前位于函数 load_runtime_config。 | <code>            user=args.mysql_user,</code> |
| L0078 | 控制当前循环或占位分支的执行流程，当前位于函数 load_runtime_config。 | <code>            password=args.mysql_password,</code> |
| L0079 | 计算并保存 &#96;database&#96;（数据库），供后续逻辑使用，当前位于函数 load_runtime_config。 | <code>            database=args.mysql_database,</code> |
| L0080 | 计算并保存 &#96;charset&#96;（charset），供后续逻辑使用，当前位于函数 load_runtime_config。 | <code>            charset="utf8mb4",</code> |
| L0081 | 计算并保存 &#96;cursorclass&#96;（cursorclass），供后续逻辑使用，当前位于函数 load_runtime_config。 | <code>            cursorclass=DictCursor,</code> |
| L0082 | 计算并保存 &#96;connect_timeout&#96;（connecttimeout），供后续逻辑使用，当前位于函数 load_runtime_config。 | <code>            connect_timeout=3,</code> |
| L0083 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_runtime_config。 | <code>        )</code> |
| L0084 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 load_runtime_config。 | <code>        with conn.cursor() as cur:</code> |
| L0085 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 load_runtime_config。 | <code>            cur.execute(</code> |
| L0086 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 load_runtime_config。 | <code>                """SELECT config_key,config_value FROM demo_system_config</code> |
| L0087 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_runtime_config。 | <code>                   WHERE config_key IN (</code> |
| L0088 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_runtime_config。 | <code>                     'capture_interface','capture_interface_identity','llm_model','situation_minimum_actions',</code> |
| L0089 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_runtime_config。 | <code>                     'situation_window_minutes','situation_inactivity_minutes',</code> |
| L0090 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_runtime_config。 | <code>                     'scan_port_threshold','scan_window_seconds'</code> |
| L0091 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 load_runtime_config。 | <code>                   )"""</code> |
| L0092 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_runtime_config。 | <code>            )</code> |
| L0093 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 load_runtime_config。 | <code>            rows = cur.fetchall()</code> |
| L0094 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>        conn.close()</code> |
| L0095 | 遍历集合中的数据项并逐项处理，当前位于函数 load_runtime_config。 | <code>        for row in rows:</code> |
| L0096 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>            fallback[str(row["config_key"])] = str(row["config_value"] or "").strip()</code> |
| L0097 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 load_runtime_config。 | <code>    except Exception as exc:</code> |
| L0098 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 load_runtime_config。 | <code>        log(f"runtime config fallback: {exc}")</code> |
| L0099 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>    fallback["situation_minimum_actions"] = validated_int_text(</code> |
| L0100 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>        fallback.get("situation_minimum_actions"), args.minimum_actions, 3, 12</code> |
| L0101 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_runtime_config。 | <code>    )</code> |
| L0102 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>    fallback["situation_window_minutes"] = validated_int_text(</code> |
| L0103 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>        fallback.get("situation_window_minutes"), args.window_minutes, 1, 1440</code> |
| L0104 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_runtime_config。 | <code>    )</code> |
| L0105 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>    fallback["situation_inactivity_minutes"] = validated_int_text(</code> |
| L0106 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>        fallback.get("situation_inactivity_minutes"), args.inactivity_minutes, 1, 1440</code> |
| L0107 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_runtime_config。 | <code>    )</code> |
| L0108 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>    fallback["scan_port_threshold"] = validated_int_text(</code> |
| L0109 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>        fallback.get("scan_port_threshold"), args.scan_port_threshold, 3, 65535</code> |
| L0110 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_runtime_config。 | <code>    )</code> |
| L0111 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>    fallback["scan_window_seconds"] = validated_int_text(</code> |
| L0112 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>        fallback.get("scan_window_seconds"), args.scan_window_seconds, 10, 3600</code> |
| L0113 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_runtime_config。 | <code>    )</code> |
| L0114 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>    fallback["capture_interface"] = (</code> |
| L0115 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>        fallback.get("capture_interface_identity") or fallback.get("capture_interface") or args.interface</code> |
| L0116 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 load_runtime_config。 | <code>    )</code> |
| L0117 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 load_runtime_config。 | <code>    fallback["capture_interface"] = resolve_tshark_interface_index(fallback["capture_interface"])</code> |
| L0118 | 结束当前函数并把结果返回给调用方，当前位于函数 load_runtime_config。 | <code>    return fallback</code> |
| L0119 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0120 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0121 | 定义commonmysqlargs函数 &#96;common_mysql_args&#96;，封装可复用业务逻辑。 | <code>def common_mysql_args(args: argparse.Namespace) -&gt; List[str]:</code> |
| L0122 | 结束当前函数并把结果返回给调用方，当前位于函数 common_mysql_args。 | <code>    return [</code> |
| L0123 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 common_mysql_args。 | <code>        "--mysql-host", args.mysql_host,</code> |
| L0124 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 common_mysql_args。 | <code>        "--mysql-port", str(args.mysql_port),</code> |
| L0125 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 common_mysql_args。 | <code>        "--mysql-user", args.mysql_user,</code> |
| L0126 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 common_mysql_args。 | <code>        "--mysql-password", args.mysql_password,</code> |
| L0127 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 common_mysql_args。 | <code>        "--mysql-database", args.mysql_database,</code> |
| L0128 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 common_mysql_args。 | <code>    ]</code> |
| L0129 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0130 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0131 | 定义态势command函数 &#96;situation_command&#96;，封装可复用业务逻辑。 | <code>def situation_command(args: argparse.Namespace, runtime: Optional[Dict[str, str]] = None) -&gt; List[str]:</code> |
| L0132 | 计算并保存 &#96;runtime&#96;（runtime），供后续逻辑使用，当前位于函数 situation_command。 | <code>    runtime = runtime or {}</code> |
| L0133 | 结束当前函数并把结果返回给调用方，当前位于函数 situation_command。 | <code>    return [</code> |
| L0134 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_command。 | <code>        args.python_exe,</code> |
| L0135 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_command。 | <code>        str(args.scripts_dir / "situation_daemon.py"),</code> |
| L0136 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_command。 | <code>        *common_mysql_args(args),</code> |
| L0137 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_command。 | <code>        "--target-asset", args.target_asset,</code> |
| L0138 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_command。 | <code>        "--minimum-actions", runtime.get("situation_minimum_actions", str(args.minimum_actions)),</code> |
| L0139 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_command。 | <code>        "--window-minutes", runtime.get("situation_window_minutes", str(args.window_minutes)),</code> |
| L0140 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_command。 | <code>        "--inactivity-minutes", runtime.get("situation_inactivity_minutes", str(args.inactivity_minutes)),</code> |
| L0141 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_command。 | <code>        "--lookback-days", str(args.lookback_days),</code> |
| L0142 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 situation_command。 | <code>        "--poll-seconds", str(args.poll_seconds),</code> |
| L0143 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 situation_command。 | <code>    ]</code> |
| L0144 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0145 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0146 | 定义aicommand函数 &#96;ai_command&#96;，封装可复用业务逻辑。 | <code>def ai_command(args: argparse.Namespace, model: str) -&gt; List[str]:</code> |
| L0147 | 结束当前函数并把结果返回给调用方，当前位于函数 ai_command。 | <code>    return [</code> |
| L0148 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ai_command。 | <code>        args.python_exe,</code> |
| L0149 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ai_command。 | <code>        str(args.scripts_dir / "situation_ai_daemon.py"),</code> |
| L0150 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ai_command。 | <code>        *common_mysql_args(args),</code> |
| L0151 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ai_command。 | <code>        "--ollama-url", args.ollama_url,</code> |
| L0152 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ai_command。 | <code>        "--model", model,</code> |
| L0153 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ai_command。 | <code>        "--rag-db-path", args.rag_db_path,</code> |
| L0154 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ai_command。 | <code>        "--rag-data-dir", args.rag_data_dir,</code> |
| L0155 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ai_command。 | <code>        "--rag-api-config", args.rag_api_config,</code> |
| L0156 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ai_command。 | <code>        "--poll-seconds", str(args.poll_seconds),</code> |
| L0157 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 ai_command。 | <code>        "--heartbeat-file", str(getattr(args, "ai_heartbeat_file", Path("output/situation_ai_heartbeat.json"))),</code> |
| L0158 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 ai_command。 | <code>    ]</code> |
| L0159 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0160 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0161 | 定义sensorcommand函数 &#96;sensor_command&#96;，封装可复用业务逻辑。 | <code>def sensor_command(args: argparse.Namespace, interface: str, runtime: Optional[Dict[str, str]] = None) -&gt; List[str]:</code> |
| L0162 | 计算并保存 &#96;runtime&#96;（runtime），供后续逻辑使用，当前位于函数 sensor_command。 | <code>    runtime = runtime or {}</code> |
| L0163 | 结束当前函数并把结果返回给调用方，当前位于函数 sensor_command。 | <code>    return [</code> |
| L0164 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sensor_command。 | <code>        args.python_exe,</code> |
| L0165 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sensor_command。 | <code>        str(args.scripts_dir / "port_scan_sensor.py"),</code> |
| L0166 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sensor_command。 | <code>        *common_mysql_args(args),</code> |
| L0167 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sensor_command。 | <code>        "--interface", interface,</code> |
| L0168 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sensor_command。 | <code>        "--target-asset", args.target_asset,</code> |
| L0169 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sensor_command。 | <code>        "--unique-port-threshold", runtime.get("scan_port_threshold", str(args.scan_port_threshold)),</code> |
| L0170 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 sensor_command。 | <code>        "--window-seconds", runtime.get("scan_window_seconds", str(args.scan_window_seconds)),</code> |
| L0171 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 sensor_command。 | <code>    ]</code> |
| L0172 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0173 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0174 | 定义neo4jcommand函数 &#96;neo4j_command&#96;，封装可复用业务逻辑。 | <code>def neo4j_command(args: argparse.Namespace) -&gt; List[str]:</code> |
| L0175 | 结束当前函数并把结果返回给调用方，当前位于函数 neo4j_command。 | <code>    return [</code> |
| L0176 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 neo4j_command。 | <code>        args.python_exe,</code> |
| L0177 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 neo4j_command。 | <code>        str(args.scripts_dir / "situation_neo4j_sync.py"),</code> |
| L0178 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 neo4j_command。 | <code>        *common_mysql_args(args),</code> |
| L0179 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 neo4j_command。 | <code>        "--neo4j-url", args.neo4j_url,</code> |
| L0180 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 neo4j_command。 | <code>        "--neo4j-user", args.neo4j_user,</code> |
| L0181 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 neo4j_command。 | <code>        "--neo4j-password", args.neo4j_password,</code> |
| L0182 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 neo4j_command。 | <code>        "--neo4j-database", args.neo4j_database,</code> |
| L0183 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 neo4j_command。 | <code>        "--poll-seconds", str(args.poll_seconds),</code> |
| L0184 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 neo4j_command。 | <code>    ]</code> |
| L0185 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0186 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0187 | 定义autodefensecommand函数 &#96;auto_defense_command&#96;，封装可复用业务逻辑。 | <code>def auto_defense_command(args: argparse.Namespace) -&gt; List[str]:</code> |
| L0188 | 结束当前函数并把结果返回给调用方，当前位于函数 auto_defense_command。 | <code>    return [</code> |
| L0189 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 auto_defense_command。 | <code>        args.python_exe,</code> |
| L0190 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 auto_defense_command。 | <code>        str(args.scripts_dir / "auto_defense_daemon.py"),</code> |
| L0191 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 auto_defense_command。 | <code>        *common_mysql_args(args),</code> |
| L0192 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 auto_defense_command。 | <code>        "--poll-seconds", "2",</code> |
| L0193 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 auto_defense_command。 | <code>        "--log-file", "output/auto_defense_daemon.log",</code> |
| L0194 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 auto_defense_command。 | <code>    ]</code> |
| L0195 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0196 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0197 | 定义启动函数 &#96;start&#96;，封装可复用业务逻辑。 | <code>def start(command: List[str], name: str, cwd: Path) -&gt; subprocess.Popen:</code> |
| L0198 | 计算并保存 &#96;proc&#96;（proc），供后续逻辑使用，当前位于函数 start。 | <code>    proc = subprocess.Popen(command, cwd=str(cwd), text=True, encoding="utf-8", errors="replace")</code> |
| L0199 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 start。 | <code>    log(f"started {name} pid={proc.pid}")</code> |
| L0200 | 结束当前函数并把结果返回给调用方，当前位于函数 start。 | <code>    return proc</code> |
| L0201 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0202 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0203 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; None:</code> |
| L0204 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="Self-healing situation correlation, AI and scan supervisor")</code> |
| L0205 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--python-exe", default=sys.executable)</code> |
| L0206 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--scripts-dir", type=Path, default=Path(__file__).resolve().parent)</code> |
| L0207 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-host", default="127.0.0.1")</code> |
| L0208 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-port", type=int, default=3306)</code> |
| L0209 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-user", default="root")</code> |
| L0210 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-password", default="123456")</code> |
| L0211 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-database", default="traffic_pipeline")</code> |
| L0212 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--interface", default="")</code> |
| L0213 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--model", default="qwen2.5:3b")</code> |
| L0214 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")</code> |
| L0215 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-db-path", default="llm/rag/rag_knowledge.db")</code> |
| L0216 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-data-dir", default="D:/JingyuanTrafficPipelineData/rag")</code> |
| L0217 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--rag-api-config", default="config/ai_api.local.json")</code> |
| L0218 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--target-asset", default=socket.gethostname())</code> |
| L0219 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--minimum-actions", type=int, default=3)</code> |
| L0220 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--window-minutes", type=int, default=30)</code> |
| L0221 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--inactivity-minutes", type=int, default=15)</code> |
| L0222 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--lookback-days", type=int, default=30)</code> |
| L0223 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--poll-seconds", type=int, default=10)</code> |
| L0224 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--ai-heartbeat-file", type=Path, default=Path("output/situation_ai_heartbeat.json"))</code> |
| L0225 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--ai-heartbeat-timeout", type=int, default=210)</code> |
| L0226 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--scan-port-threshold", type=int, default=10)</code> |
| L0227 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--scan-window-seconds", type=int, default=60)</code> |
| L0228 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--neo4j-url", default="")</code> |
| L0229 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--neo4j-user", default="neo4j")</code> |
| L0230 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--neo4j-password", default="")</code> |
| L0231 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--neo4j-database", default="neo4j")</code> |
| L0232 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0233 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    args.scripts_dir = args.scripts_dir.resolve()</code> |
| L0234 | 计算并保存 &#96;project_root&#96;（projectroot），供后续逻辑使用，当前位于函数 main。 | <code>    project_root = args.scripts_dir.parent</code> |
| L0235 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if not args.ai_heartbeat_file.is_absolute():</code> |
| L0236 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        args.ai_heartbeat_file = project_root / args.ai_heartbeat_file</code> |
| L0237 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0238 | 计算并保存 &#96;processes&#96;（processes），供后续逻辑使用，当前位于函数 main。 | <code>    processes: Dict[str, Optional[subprocess.Popen]] = {</code> |
| L0239 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "correlator": None,</code> |
| L0240 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "ai": None,</code> |
| L0241 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "sensor": None,</code> |
| L0242 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "neo4j": None,</code> |
| L0243 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "auto-defense": None,</code> |
| L0244 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    }</code> |
| L0245 | 计算并保存 &#96;active_model&#96;（active模型），供后续逻辑使用，当前位于函数 main。 | <code>    active_model = ""</code> |
| L0246 | 计算并保存 &#96;active_interface&#96;（activeinterface），供后续逻辑使用，当前位于函数 main。 | <code>    active_interface = ""</code> |
| L0247 | 计算并保存 &#96;active_correlation_config&#96;（activecorrelation配置），供后续逻辑使用，当前位于函数 main。 | <code>    active_correlation_config: tuple[str, str, str] = ("", "", "")</code> |
| L0248 | 计算并保存 &#96;active_scan_config&#96;（activescan配置），供后续逻辑使用，当前位于函数 main。 | <code>    active_scan_config: tuple[str, str] = ("", "")</code> |
| L0249 | 计算并保存 &#96;runtime_config&#96;（runtime配置），供后续逻辑使用，当前位于函数 main。 | <code>    runtime_config: Dict[str, str] = {}</code> |
| L0250 | 计算并保存 &#96;next_config_check&#96;（next配置检查），供后续逻辑使用，当前位于函数 main。 | <code>    next_config_check = 0.0</code> |
| L0251 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>    try:</code> |
| L0252 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 main。 | <code>        while True:</code> |
| L0253 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if time.monotonic() &gt;= next_config_check:</code> |
| L0254 | 计算并保存 &#96;config&#96;（配置），供后续逻辑使用，当前位于函数 main。 | <code>                config = load_runtime_config(args)</code> |
| L0255 | 计算并保存 &#96;model&#96;（模型），供后续逻辑使用，当前位于函数 main。 | <code>                model = config.get("llm_model") or args.model</code> |
| L0256 | 计算并保存 &#96;interface&#96;（interface），供后续逻辑使用，当前位于函数 main。 | <code>                interface = config.get("capture_interface") or args.interface</code> |
| L0257 | 计算并保存 &#96;correlation_config&#96;（correlation配置），供后续逻辑使用，当前位于函数 main。 | <code>                correlation_config = (</code> |
| L0258 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    config.get("situation_minimum_actions", str(args.minimum_actions)),</code> |
| L0259 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    config.get("situation_window_minutes", str(args.window_minutes)),</code> |
| L0260 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    config.get("situation_inactivity_minutes", str(args.inactivity_minutes)),</code> |
| L0261 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>                )</code> |
| L0262 | 计算并保存 &#96;scan_config&#96;（scan配置），供后续逻辑使用，当前位于函数 main。 | <code>                scan_config = (</code> |
| L0263 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    config.get("scan_port_threshold", str(args.scan_port_threshold)),</code> |
| L0264 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    config.get("scan_window_seconds", str(args.scan_window_seconds)),</code> |
| L0265 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>                )</code> |
| L0266 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if model != active_model:</code> |
| L0267 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    stop(processes["ai"], "ai")</code> |
| L0268 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    processes["ai"] = None</code> |
| L0269 | 计算并保存 &#96;active_model&#96;（active模型），供后续逻辑使用，当前位于函数 main。 | <code>                    active_model = model</code> |
| L0270 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if interface != active_interface:</code> |
| L0271 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    stop(processes["sensor"], "sensor")</code> |
| L0272 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    processes["sensor"] = None</code> |
| L0273 | 计算并保存 &#96;active_interface&#96;（activeinterface），供后续逻辑使用，当前位于函数 main。 | <code>                    active_interface = interface</code> |
| L0274 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if correlation_config != active_correlation_config:</code> |
| L0275 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    stop(processes["correlator"], "correlator")</code> |
| L0276 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    processes["correlator"] = None</code> |
| L0277 | 计算并保存 &#96;active_correlation_config&#96;（activecorrelation配置），供后续逻辑使用，当前位于函数 main。 | <code>                    active_correlation_config = correlation_config</code> |
| L0278 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if scan_config != active_scan_config:</code> |
| L0279 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    stop(processes["sensor"], "sensor")</code> |
| L0280 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    processes["sensor"] = None</code> |
| L0281 | 计算并保存 &#96;active_scan_config&#96;（activescan配置），供后续逻辑使用，当前位于函数 main。 | <code>                    active_scan_config = scan_config</code> |
| L0282 | 计算并保存 &#96;runtime_config&#96;（runtime配置），供后续逻辑使用，当前位于函数 main。 | <code>                runtime_config = config</code> |
| L0283 | 计算并保存 &#96;next_config_check&#96;（next配置检查），供后续逻辑使用，当前位于函数 main。 | <code>                next_config_check = time.monotonic() + 10</code> |
| L0284 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0285 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if processes["correlator"] is None or processes["correlator"].poll() is not None:</code> |
| L0286 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                processes["correlator"] = start(situation_command(args, runtime_config), "correlator", project_root)</code> |
| L0287 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if processes["ai"] is None or processes["ai"].poll() is not None:</code> |
| L0288 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                processes["ai"] = start(ai_command(args, active_model or args.model), "ai", project_root)</code> |
| L0289 | 当前一条件未命中时继续判断另一条件，当前位于函数 main。 | <code>            elif args.ai_heartbeat_file.exists():</code> |
| L0290 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>                try:</code> |
| L0291 | 计算并保存 &#96;heartbeat&#96;（heartbeat），供后续逻辑使用，当前位于函数 main。 | <code>                    heartbeat = json.loads(args.ai_heartbeat_file.read_text(encoding="utf-8-sig"))</code> |
| L0292 | 计算并保存 &#96;updated&#96;（updated），供后续逻辑使用，当前位于函数 main。 | <code>                    updated = datetime.fromisoformat(str(heartbeat.get("updated_at") or ""))</code> |
| L0293 | 计算并保存 &#96;age&#96;（age），供后续逻辑使用，当前位于函数 main。 | <code>                    age = (datetime.now() - updated).total_seconds()</code> |
| L0294 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                    if age &gt; max(60, args.ai_heartbeat_timeout):</code> |
| L0295 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                        log(f"ai business heartbeat stale ({age:.0f}s), restarting")</code> |
| L0296 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                        stop(processes["ai"], "ai")</code> |
| L0297 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                        processes["ai"] = None</code> |
| L0298 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>                except Exception as exc:</code> |
| L0299 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                    log(f"ai heartbeat check skipped: {exc}")</code> |
| L0300 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if active_interface and active_interface.lower() not in {"auto", "none", "off"}:</code> |
| L0301 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if processes["sensor"] is None or processes["sensor"].poll() is not None:</code> |
| L0302 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    processes["sensor"] = start(sensor_command(args, active_interface, runtime_config), "sensor", project_root)</code> |
| L0303 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if args.neo4j_url and args.neo4j_password:</code> |
| L0304 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if processes["neo4j"] is None or processes["neo4j"].poll() is not None:</code> |
| L0305 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    processes["neo4j"] = start(neo4j_command(args), "neo4j", project_root)</code> |
| L0306 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if processes["auto-defense"] is None or processes["auto-defense"].poll() is not None:</code> |
| L0307 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                processes["auto-defense"] = start(auto_defense_command(args), "auto-defense", project_root)</code> |
| L0308 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            time.sleep(3)</code> |
| L0309 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>    except KeyboardInterrupt:</code> |
| L0310 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        log("shutdown requested")</code> |
| L0311 | 无论成功或异常都执行资源清理，当前位于函数 main。 | <code>    finally:</code> |
| L0312 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>        for name, proc in processes.items():</code> |
| L0313 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            stop(proc, name)</code> |
| L0314 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0315 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0316 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0317 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
