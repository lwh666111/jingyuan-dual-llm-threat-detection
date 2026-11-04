# `scripts/capture_http_request_batches.py` 逐行注释

**脚本用途：** 调用 TShark 实时抓取 HTTP 流量，解析请求/响应并触发快速防御与检测流水线。

**源码行数：** 848　**函数/类数量：** 29

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0002 | 导入后续逻辑所需的模块、类或函数：&#96;import csv&#96;。 | <code>import csv</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import ctypes&#96;。 | <code>import ctypes</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import os&#96;。 | <code>import os</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;import re&#96;。 | <code>import re</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;import shutil&#96;。 | <code>import shutil</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;import subprocess&#96;。 | <code>import subprocess</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;import sys&#96;。 | <code>import sys</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;import time&#96;。 | <code>import time</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.parse&#96;。 | <code>import urllib.parse</code> |
| L0012 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0013 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Dict, List, Optional, Tuple&#96;。 | <code>from typing import Dict, List, Optional, Tuple</code> |
| L0014 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0015 | 开始受保护操作，异常会交给后续分支处理。 | <code>try:</code> |
| L0016 | 导入后续逻辑所需的模块、类或函数：&#96;from fast_defense import FastDefenseGuard&#96;。 | <code>    from fast_defense import FastDefenseGuard</code> |
| L0017 | 捕获异常，避免单次错误导致整个服务退出。 | <code>except ImportError:  # package import during tests</code> |
| L0018 | 导入后续逻辑所需的模块、类或函数：&#96;from scripts.fast_defense import FastDefenseGuard&#96;。 | <code>    from scripts.fast_defense import FastDefenseGuard</code> |
| L0019 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0020 | 开始受保护操作，异常会交给后续分支处理。 | <code>try:</code> |
| L0021 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    csv.field_size_limit(16 * 1024 * 1024)</code> |
| L0022 | 捕获异常，避免单次错误导致整个服务退出。 | <code>except Exception:</code> |
| L0023 | 控制当前循环或占位分支的执行流程。 | <code>    pass</code> |
| L0024 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0025 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0026 | 计算并保存 &#96;MAX_CAPTURE_PAYLOAD_CHARS&#96;（MAXCAPTUREPAYLOADCHARS），供后续逻辑使用。 | <code>MAX_CAPTURE_PAYLOAD_CHARS = 16 * 1024</code> |
| L0027 | 计算并保存 &#96;MAX_TSHARK_FIELD_CHARS&#96;（MAXTSHARKFIELDCHARS），供后续逻辑使用。 | <code>MAX_TSHARK_FIELD_CHARS = MAX_CAPTURE_PAYLOAD_CHARS * 4</code> |
| L0028 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0029 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0030 | 定义findexecutable函数 &#96;find_executable&#96;，封装可复用业务逻辑。 | <code>def find_executable(name: str) -&gt; str:</code> |
| L0031 | 计算并保存 &#96;candidates&#96;（candidates），供后续逻辑使用，当前位于函数 find_executable。 | <code>    candidates = []</code> |
| L0032 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 find_executable。 | <code>    if not name.lower().endswith(".exe"):</code> |
| L0033 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 find_executable。 | <code>        candidates.append(f"{name}.exe")</code> |
| L0034 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 find_executable。 | <code>    candidates.append(name)</code> |
| L0035 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0036 | 遍历集合中的数据项并逐项处理，当前位于函数 find_executable。 | <code>    for candidate in candidates:</code> |
| L0037 | 计算并保存 &#96;exe&#96;（exe），供后续逻辑使用，当前位于函数 find_executable。 | <code>        exe = shutil.which(candidate)</code> |
| L0038 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 find_executable。 | <code>        if exe:</code> |
| L0039 | 结束当前函数并把结果返回给调用方，当前位于函数 find_executable。 | <code>            return exe</code> |
| L0040 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0041 | 计算并保存 &#96;local_appdata&#96;（localappdata），供后续逻辑使用，当前位于函数 find_executable。 | <code>    local_appdata = os.environ.get("LOCALAPPDATA", "")</code> |
| L0042 | 计算并保存 &#96;user_profile&#96;（userprofile），供后续逻辑使用，当前位于函数 find_executable。 | <code>    user_profile = os.environ.get("USERPROFILE", "")</code> |
| L0043 | 计算并保存 &#96;program_files&#96;（programfiles），供后续逻辑使用，当前位于函数 find_executable。 | <code>    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")</code> |
| L0044 | 计算并保存 &#96;program_files_x86&#96;（programfilesx86），供后续逻辑使用，当前位于函数 find_executable。 | <code>    program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")</code> |
| L0045 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0046 | 计算并保存 &#96;fallback_dirs&#96;（fallbackdirs），供后续逻辑使用，当前位于函数 find_executable。 | <code>    fallback_dirs = [</code> |
| L0047 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_executable。 | <code>        Path(user_profile) / "Wireshark" if user_profile else None,</code> |
| L0048 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_executable。 | <code>        Path(local_appdata) / "Programs" / "Wireshark" if local_appdata else None,</code> |
| L0049 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_executable。 | <code>        Path(program_files) / "Wireshark",</code> |
| L0050 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_executable。 | <code>        Path(program_files_x86) / "Wireshark",</code> |
| L0051 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 find_executable。 | <code>    ]</code> |
| L0052 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0053 | 遍历集合中的数据项并逐项处理，当前位于函数 find_executable。 | <code>    for d in fallback_dirs:</code> |
| L0054 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 find_executable。 | <code>        if not d:</code> |
| L0055 | 控制当前循环或占位分支的执行流程，当前位于函数 find_executable。 | <code>            continue</code> |
| L0056 | 遍历集合中的数据项并逐项处理，当前位于函数 find_executable。 | <code>        for candidate in candidates:</code> |
| L0057 | 计算并保存 &#96;full&#96;（full），供后续逻辑使用，当前位于函数 find_executable。 | <code>            full = d / candidate</code> |
| L0058 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 find_executable。 | <code>            if full.exists():</code> |
| L0059 | 结束当前函数并把结果返回给调用方，当前位于函数 find_executable。 | <code>                return str(full)</code> |
| L0060 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0061 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 find_executable。 | <code>    raise FileNotFoundError(</code> |
| L0062 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_executable。 | <code>        f"未找到可执行文件: {name}，请确认 Wireshark/TShark 已安装并加入 PATH，"</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 find_executable。 | <code>        "或位于常见目录（如 C:\\Users\\&lt;你&gt;\\Wireshark / C:\\Program Files\\Wireshark）"</code> |
| L0064 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 find_executable。 | <code>    )</code> |
| L0065 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0066 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0067 | 定义运行textcommand函数 &#96;run_text_command&#96;，封装可复用业务逻辑。 | <code>def run_text_command(cmd: List[str], timeout: Optional[int] = None) -&gt; str:</code> |
| L0068 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 run_text_command。 | <code>    result = subprocess.run(</code> |
| L0069 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_text_command。 | <code>        cmd,</code> |
| L0070 | 计算并保存 &#96;capture_output&#96;（captureoutput），供后续逻辑使用，当前位于函数 run_text_command。 | <code>        capture_output=True,</code> |
| L0071 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 run_text_command。 | <code>        text=True,</code> |
| L0072 | 计算并保存 &#96;encoding&#96;（encoding），供后续逻辑使用，当前位于函数 run_text_command。 | <code>        encoding="utf-8",</code> |
| L0073 | 计算并保存 &#96;errors&#96;（errors），供后续逻辑使用，当前位于函数 run_text_command。 | <code>        errors="replace",</code> |
| L0074 | 计算并保存 &#96;timeout&#96;（timeout），供后续逻辑使用，当前位于函数 run_text_command。 | <code>        timeout=timeout,</code> |
| L0075 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_text_command。 | <code>    )</code> |
| L0076 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 run_text_command。 | <code>    if result.returncode != 0:</code> |
| L0077 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 run_text_command。 | <code>        raise RuntimeError(</code> |
| L0078 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 run_text_command。 | <code>            f"命令执行失败: {' '.join(cmd)}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"</code> |
| L0079 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 run_text_command。 | <code>        )</code> |
| L0080 | 结束当前函数并把结果返回给调用方，当前位于函数 run_text_command。 | <code>    return result.stdout</code> |
| L0081 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0082 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0083 | 定义iswindowsadmin函数 &#96;is_windows_admin&#96;，封装可复用业务逻辑。 | <code>def is_windows_admin() -&gt; bool:</code> |
| L0084 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_windows_admin。 | <code>    if os.name != "nt":</code> |
| L0085 | 结束当前函数并把结果返回给调用方，当前位于函数 is_windows_admin。 | <code>        return True</code> |
| L0086 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 is_windows_admin。 | <code>    try:</code> |
| L0087 | 结束当前函数并把结果返回给调用方，当前位于函数 is_windows_admin。 | <code>        return bool(ctypes.windll.shell32.IsUserAnAdmin())</code> |
| L0088 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 is_windows_admin。 | <code>    except Exception:</code> |
| L0089 | 结束当前函数并把结果返回给调用方，当前位于函数 is_windows_admin。 | <code>        return False</code> |
| L0090 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0091 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0092 | 定义读取npcapadminonlyflag函数 &#96;read_npcap_admin_only_flag&#96;，封装可复用业务逻辑。 | <code>def read_npcap_admin_only_flag() -&gt; Optional[bool]:</code> |
| L0093 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 read_npcap_admin_only_flag。 | <code>    if os.name != "nt":</code> |
| L0094 | 结束当前函数并把结果返回给调用方，当前位于函数 read_npcap_admin_only_flag。 | <code>        return None</code> |
| L0095 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 read_npcap_admin_only_flag。 | <code>    try:</code> |
| L0096 | 导入后续逻辑所需的模块、类或函数：&#96;import winreg&#96;。 | <code>        import winreg</code> |
| L0097 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0098 | 计算并保存 &#96;key_path&#96;（keypath），供后续逻辑使用，当前位于函数 read_npcap_admin_only_flag。 | <code>        key_path = r"SYSTEM\CurrentControlSet\Services\npcap\Parameters"</code> |
| L0099 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 read_npcap_admin_only_flag。 | <code>        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:</code> |
| L0100 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_npcap_admin_only_flag。 | <code>            value, _ = winreg.QueryValueEx(key, "AdminOnly")</code> |
| L0101 | 结束当前函数并把结果返回给调用方，当前位于函数 read_npcap_admin_only_flag。 | <code>        return bool(int(value))</code> |
| L0102 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 read_npcap_admin_only_flag。 | <code>    except Exception:</code> |
| L0103 | 结束当前函数并把结果返回给调用方，当前位于函数 read_npcap_admin_only_flag。 | <code>        return None</code> |
| L0104 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0105 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0106 | 定义列出interfaces函数 &#96;list_interfaces&#96;，封装可复用业务逻辑。 | <code>def list_interfaces(tshark_exe: str, timeout: Optional[int] = None):</code> |
| L0107 | 计算并保存 &#96;output&#96;（output），供后续逻辑使用，当前位于函数 list_interfaces。 | <code>    output = run_text_command([tshark_exe, "-D"], timeout=timeout)</code> |
| L0108 | 计算并保存 &#96;interfaces&#96;（interfaces），供后续逻辑使用，当前位于函数 list_interfaces。 | <code>    interfaces = []</code> |
| L0109 | 遍历集合中的数据项并逐项处理，当前位于函数 list_interfaces。 | <code>    for line in output.splitlines():</code> |
| L0110 | 计算并保存 &#96;line&#96;（line），供后续逻辑使用，当前位于函数 list_interfaces。 | <code>        line = line.strip()</code> |
| L0111 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_interfaces。 | <code>        if not line:</code> |
| L0112 | 控制当前循环或占位分支的执行流程，当前位于函数 list_interfaces。 | <code>            continue</code> |
| L0113 | 计算并保存 &#96;m&#96;（m），供后续逻辑使用，当前位于函数 list_interfaces。 | <code>        m = re.match(r"^(\d+)\.\s+(.+)$", line)</code> |
| L0114 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 list_interfaces。 | <code>        if not m:</code> |
| L0115 | 控制当前循环或占位分支的执行流程，当前位于函数 list_interfaces。 | <code>            continue</code> |
| L0116 | 计算并保存 &#96;idx&#96;（idx），供后续逻辑使用，当前位于函数 list_interfaces。 | <code>        idx = m.group(1)</code> |
| L0117 | 计算并保存 &#96;rest&#96;（rest），供后续逻辑使用，当前位于函数 list_interfaces。 | <code>        rest = m.group(2)</code> |
| L0118 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 list_interfaces。 | <code>        interfaces.append({"index": idx, "raw": rest})</code> |
| L0119 | 结束当前函数并把结果返回给调用方，当前位于函数 list_interfaces。 | <code>    return interfaces</code> |
| L0120 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0121 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0122 | 定义chooseinterface函数 &#96;choose_interface&#96;，封装可复用业务逻辑。 | <code>def choose_interface(interfaces, preferred_name: str = "") -&gt; str:</code> |
| L0123 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 choose_interface。 | <code>    if preferred_name:</code> |
| L0124 | 遍历集合中的数据项并逐项处理，当前位于函数 choose_interface。 | <code>        for iface in interfaces:</code> |
| L0125 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 choose_interface。 | <code>            if preferred_name.lower() in iface["raw"].lower():</code> |
| L0126 | 结束当前函数并把结果返回给调用方，当前位于函数 choose_interface。 | <code>                return iface["index"]</code> |
| L0127 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0128 | 源码原注释：优先真实业务网卡，避免误选 Microsoft Wi-Fi Direct/本地连接* 等虚拟适配器。 | <code>    # 优先真实业务网卡，避免误选 Microsoft Wi-Fi Direct/本地连接* 等虚拟适配器。</code> |
| L0129 | 计算并保存 &#96;preferred_groups&#96;（preferredgroups），供后续逻辑使用，当前位于函数 choose_interface。 | <code>    preferred_groups = [</code> |
| L0130 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 choose_interface。 | <code>        ["以太网", "ethernet"],</code> |
| L0131 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 choose_interface。 | <code>        ["wi-fi", "wlan", "wireless", "wifi"],</code> |
| L0132 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 choose_interface。 | <code>    ]</code> |
| L0133 | 遍历集合中的数据项并逐项处理，当前位于函数 choose_interface。 | <code>    for group in preferred_groups:</code> |
| L0134 | 遍历集合中的数据项并逐项处理，当前位于函数 choose_interface。 | <code>        for iface in interfaces:</code> |
| L0135 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 choose_interface。 | <code>            raw = iface["raw"].lower()</code> |
| L0136 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 choose_interface。 | <code>            if any(kw in raw for kw in group):</code> |
| L0137 | 结束当前函数并把结果返回给调用方，当前位于函数 choose_interface。 | <code>                return iface["index"]</code> |
| L0138 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0139 | 计算并保存 &#96;deprioritized_tokens&#96;（deprioritizedtokens），供后续逻辑使用，当前位于函数 choose_interface。 | <code>    deprioritized_tokens = [</code> |
| L0140 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 choose_interface。 | <code>        "loopback",</code> |
| L0141 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 choose_interface。 | <code>        "npcap loopback",</code> |
| L0142 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 choose_interface。 | <code>        "local area connection*",</code> |
| L0143 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 choose_interface。 | <code>        "本地连接*",</code> |
| L0144 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 choose_interface。 | <code>        "wi-fi direct",</code> |
| L0145 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 choose_interface。 | <code>        "virtual",</code> |
| L0146 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 choose_interface。 | <code>        "vmware",</code> |
| L0147 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 choose_interface。 | <code>        "hyper-v",</code> |
| L0148 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 choose_interface。 | <code>        "vethernet",</code> |
| L0149 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 choose_interface。 | <code>        "bluetooth",</code> |
| L0150 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 choose_interface。 | <code>    ]</code> |
| L0151 | 遍历集合中的数据项并逐项处理，当前位于函数 choose_interface。 | <code>    for iface in interfaces:</code> |
| L0152 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 choose_interface。 | <code>        raw = iface["raw"].lower()</code> |
| L0153 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 choose_interface。 | <code>        if not any(tok in raw for tok in deprioritized_tokens):</code> |
| L0154 | 结束当前函数并把结果返回给调用方，当前位于函数 choose_interface。 | <code>            return iface["index"]</code> |
| L0155 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0156 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 choose_interface。 | <code>    if interfaces:</code> |
| L0157 | 结束当前函数并把结果返回给调用方，当前位于函数 choose_interface。 | <code>        return interfaces[0]["index"]</code> |
| L0158 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0159 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 choose_interface。 | <code>    raise RuntimeError("没有找到可用抓包网卡")</code> |
| L0160 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0161 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0162 | 定义检测httplinkfields函数 &#96;detect_http_link_fields&#96;，封装可复用业务逻辑。 | <code>def detect_http_link_fields(tshark_exe: str) -&gt; Tuple[str, str]:</code> |
| L0163 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 detect_http_link_fields。 | <code>    """</code> |
| L0164 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 detect_http_link_fields。 | <code>    返回 (request_in_field, response_in_field)：</code> |
| L0165 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 detect_http_link_fields。 | <code>    - request_in_field: 响应中指向请求帧</code> |
| L0166 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 detect_http_link_fields。 | <code>    - response_in_field: 请求中指向响应帧</code> |
| L0167 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 detect_http_link_fields。 | <code>    """</code> |
| L0168 | 计算并保存 &#96;fields_text&#96;（fieldstext），供后续逻辑使用，当前位于函数 detect_http_link_fields。 | <code>    fields_text = run_text_command([tshark_exe, "-G", "fields"])</code> |
| L0169 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0170 | 计算并保存 &#96;has_request_in&#96;（hasrequestin），供后续逻辑使用，当前位于函数 detect_http_link_fields。 | <code>    has_request_in = "http.request_in" in fields_text</code> |
| L0171 | 计算并保存 &#96;has_prev_request_in&#96;（hasprevrequestin），供后续逻辑使用，当前位于函数 detect_http_link_fields。 | <code>    has_prev_request_in = "http.prev_request_in" in fields_text</code> |
| L0172 | 计算并保存 &#96;has_response_in&#96;（hasresponsein），供后续逻辑使用，当前位于函数 detect_http_link_fields。 | <code>    has_response_in = "http.response_in" in fields_text</code> |
| L0173 | 计算并保存 &#96;has_next_response_in&#96;（hasnextresponsein），供后续逻辑使用，当前位于函数 detect_http_link_fields。 | <code>    has_next_response_in = "http.next_response_in" in fields_text</code> |
| L0174 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0175 | 计算并保存 &#96;request_in_field&#96;（requestinfield），供后续逻辑使用，当前位于函数 detect_http_link_fields。 | <code>    request_in_field = "http.request_in" if has_request_in else "http.prev_request_in" if has_prev_request_in else ""</code> |
| L0176 | 计算并保存 &#96;response_in_field&#96;（responseinfield），供后续逻辑使用，当前位于函数 detect_http_link_fields。 | <code>    response_in_field = "http.response_in" if has_response_in else "http.next_response_in" if has_next_response_in else ""</code> |
| L0177 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0178 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 detect_http_link_fields。 | <code>    if not request_in_field or not response_in_field:</code> |
| L0179 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 detect_http_link_fields。 | <code>        raise RuntimeError(</code> |
| L0180 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detect_http_link_fields。 | <code>            "当前 tshark 缺少 HTTP 请求/响应关联字段，无法稳定配对。"</code> |
| L0181 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detect_http_link_fields。 | <code>            f"request_in 可用={has_request_in or has_prev_request_in}, "</code> |
| L0182 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 detect_http_link_fields。 | <code>            f"response_in 可用={has_response_in or has_next_response_in}"</code> |
| L0183 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 detect_http_link_fields。 | <code>        )</code> |
| L0184 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0185 | 结束当前函数并把结果返回给调用方，当前位于函数 detect_http_link_fields。 | <code>    return request_in_field, response_in_field</code> |
| L0186 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0187 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0188 | 定义读取capturesequence函数 &#96;read_capture_sequence&#96;，封装可复用业务逻辑。 | <code>def read_capture_sequence(state_path: Path) -&gt; int:</code> |
| L0189 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 read_capture_sequence。 | <code>    try:</code> |
| L0190 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 read_capture_sequence。 | <code>        data = json.loads(state_path.read_text(encoding="utf-8-sig"))</code> |
| L0191 | 结束当前函数并把结果返回给调用方，当前位于函数 read_capture_sequence。 | <code>        return max(0, int(data.get("last_index") or 0))</code> |
| L0192 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 read_capture_sequence。 | <code>    except (FileNotFoundError, OSError, ValueError, TypeError, json.JSONDecodeError):</code> |
| L0193 | 结束当前函数并把结果返回给调用方，当前位于函数 read_capture_sequence。 | <code>        return 0</code> |
| L0194 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0195 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0196 | 定义写入capturesequence函数 &#96;write_capture_sequence&#96;，封装可复用业务逻辑。 | <code>def write_capture_sequence(state_path: Path, last_index: int) -&gt; None:</code> |
| L0197 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_capture_sequence。 | <code>    state_path.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0198 | 计算并保存 &#96;temp_path&#96;（temppath），供后续逻辑使用，当前位于函数 write_capture_sequence。 | <code>    temp_path = state_path.with_suffix(f"{state_path.suffix}.tmp")</code> |
| L0199 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_capture_sequence。 | <code>    temp_path.write_text(</code> |
| L0200 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_capture_sequence。 | <code>        json.dumps({"last_index": int(last_index)}, ensure_ascii=False, indent=2),</code> |
| L0201 | 计算并保存 &#96;encoding&#96;（encoding），供后续逻辑使用，当前位于函数 write_capture_sequence。 | <code>        encoding="utf-8",</code> |
| L0202 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 write_capture_sequence。 | <code>    )</code> |
| L0203 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_capture_sequence。 | <code>    os.replace(temp_path, state_path)</code> |
| L0204 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0205 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0206 | 定义nextfileindex函数 &#96;next_file_index&#96;，封装可复用业务逻辑。 | <code>def next_file_index(</code> |
| L0207 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 next_file_index。 | <code>    input_dir: Path,</code> |
| L0208 | 计算并保存 &#96;prefix&#96;（prefix），供后续逻辑使用，当前位于函数 next_file_index。 | <code>    prefix: str = "1.1.",</code> |
| L0209 | 计算并保存 &#96;state_path&#96;（statepath），供后续逻辑使用，当前位于函数 next_file_index。 | <code>    state_path: Optional[Path] = None,</code> |
| L0210 | 计算并保存 &#96;minimum_last_index&#96;（minimumlastindex），供后续逻辑使用，当前位于函数 next_file_index。 | <code>    minimum_last_index: int = 0,</code> |
| L0211 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 next_file_index。 | <code>) -&gt; int:</code> |
| L0212 | 计算并保存 &#96;max_n&#96;（maxn），供后续逻辑使用，当前位于函数 next_file_index。 | <code>    max_n = 0</code> |
| L0213 | 遍历集合中的数据项并逐项处理，当前位于函数 next_file_index。 | <code>    for p in input_dir.glob(f"{prefix}*.txt"):</code> |
| L0214 | 计算并保存 &#96;m&#96;（m），供后续逻辑使用，当前位于函数 next_file_index。 | <code>        m = re.match(rf"{re.escape(prefix)}(\d+)\.txt$", p.name)</code> |
| L0215 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 next_file_index。 | <code>        if m:</code> |
| L0216 | 计算并保存 &#96;max_n&#96;（maxn），供后续逻辑使用，当前位于函数 next_file_index。 | <code>            max_n = max(max_n, int(m.group(1)))</code> |
| L0217 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 next_file_index。 | <code>    if state_path is not None:</code> |
| L0218 | 计算并保存 &#96;max_n&#96;（maxn），供后续逻辑使用，当前位于函数 next_file_index。 | <code>        max_n = max(max_n, read_capture_sequence(state_path))</code> |
| L0219 | 计算并保存 &#96;max_n&#96;（maxn），供后续逻辑使用，当前位于函数 next_file_index。 | <code>    max_n = max(max_n, int(minimum_last_index or 0))</code> |
| L0220 | 结束当前函数并把结果返回给调用方，当前位于函数 next_file_index。 | <code>    return max_n + 1</code> |
| L0221 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0222 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0223 | 定义读取mysqlcapturesequence函数 &#96;read_mysql_capture_sequence&#96;，封装可复用业务逻辑。 | <code>def read_mysql_capture_sequence(config: Dict[str, object]) -&gt; int:</code> |
| L0224 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 read_mysql_capture_sequence。 | <code>    try:</code> |
| L0225 | 导入后续逻辑所需的模块、类或函数：&#96;import pymysql&#96;。 | <code>        import pymysql</code> |
| L0226 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0227 | 计算并保存 &#96;conn&#96;（conn），供后续逻辑使用，当前位于函数 read_mysql_capture_sequence。 | <code>        conn = pymysql.connect(</code> |
| L0228 | 计算并保存 &#96;host&#96;（host），供后续逻辑使用，当前位于函数 read_mysql_capture_sequence。 | <code>            host=str(config["host"]),</code> |
| L0229 | 计算并保存 &#96;port&#96;（port），供后续逻辑使用，当前位于函数 read_mysql_capture_sequence。 | <code>            port=int(config["port"]),</code> |
| L0230 | 计算并保存 &#96;user&#96;（user），供后续逻辑使用，当前位于函数 read_mysql_capture_sequence。 | <code>            user=str(config["user"]),</code> |
| L0231 | 控制当前循环或占位分支的执行流程，当前位于函数 read_mysql_capture_sequence。 | <code>            password=str(config["password"]),</code> |
| L0232 | 计算并保存 &#96;database&#96;（数据库），供后续逻辑使用，当前位于函数 read_mysql_capture_sequence。 | <code>            database=str(config["database"]),</code> |
| L0233 | 计算并保存 &#96;connect_timeout&#96;（connecttimeout），供后续逻辑使用，当前位于函数 read_mysql_capture_sequence。 | <code>            connect_timeout=3,</code> |
| L0234 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 read_mysql_capture_sequence。 | <code>        )</code> |
| L0235 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 read_mysql_capture_sequence。 | <code>        try:</code> |
| L0236 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 read_mysql_capture_sequence。 | <code>            with conn.cursor() as cur:</code> |
| L0237 | 向 MySQL 执行参数化查询或结构维护语句，当前位于函数 read_mysql_capture_sequence。 | <code>                cur.execute(</code> |
| L0238 | 定义或拼接 MySQL 语句，用于读取或写入业务数据，当前位于函数 read_mysql_capture_sequence。 | <code>                    """SELECT MAX(CAST(SUBSTRING_INDEX(file_id,'.',-1) AS UNSIGNED))</code> |
| L0239 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 read_mysql_capture_sequence。 | <code>                       FROM raw_http_logs</code> |
| L0240 | 定义多行文本、提示词、模板或 SQL 片段，当前位于函数 read_mysql_capture_sequence。 | <code>                       WHERE file_id REGEXP '^1[.]1[.][0-9]+$'"""</code> |
| L0241 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 read_mysql_capture_sequence。 | <code>                )</code> |
| L0242 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 read_mysql_capture_sequence。 | <code>                row = cur.fetchone()</code> |
| L0243 | 结束当前函数并把结果返回给调用方，当前位于函数 read_mysql_capture_sequence。 | <code>                return max(0, int((row or [0])[0] or 0))</code> |
| L0244 | 无论成功或异常都执行资源清理，当前位于函数 read_mysql_capture_sequence。 | <code>        finally:</code> |
| L0245 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 read_mysql_capture_sequence。 | <code>            conn.close()</code> |
| L0246 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 read_mysql_capture_sequence。 | <code>    except Exception as exc:</code> |
| L0247 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 read_mysql_capture_sequence。 | <code>        print(f"[WARN] 无法从 MySQL 恢复抓包编号，使用本地状态: {type(exc).__name__}: {exc}", file=sys.stderr)</code> |
| L0248 | 结束当前函数并把结果返回给调用方，当前位于函数 read_mysql_capture_sequence。 | <code>        return 0</code> |
| L0249 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0250 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0251 | 定义解析tsharkline函数 &#96;parse_tshark_line&#96;，封装可复用业务逻辑。 | <code>def parse_tshark_line(line: str, headers: List[str]) -&gt; Dict[str, str]:</code> |
| L0252 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_tshark_line。 | <code>    row: List[str]</code> |
| L0253 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 parse_tshark_line。 | <code>    try:</code> |
| L0254 | 计算并保存 &#96;reader&#96;（reader），供后续逻辑使用，当前位于函数 parse_tshark_line。 | <code>        reader = csv.reader([line], delimiter="\t", quotechar='"')</code> |
| L0255 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 parse_tshark_line。 | <code>        row = next(reader, [])</code> |
| L0256 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 parse_tshark_line。 | <code>    except csv.Error:</code> |
| L0257 | 源码原注释：大字段或异常转义时降级解析，避免抓包进程直接崩溃。 | <code>        # 大字段或异常转义时降级解析，避免抓包进程直接崩溃。</code> |
| L0258 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 parse_tshark_line。 | <code>        row = line.rstrip("\r\n").split("\t")</code> |
| L0259 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_tshark_line。 | <code>    if len(row) &lt; len(headers):</code> |
| L0260 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 parse_tshark_line。 | <code>        row += [""] * (len(headers) - len(row))</code> |
| L0261 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_tshark_line。 | <code>    if len(row) &gt; len(headers):</code> |
| L0262 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 parse_tshark_line。 | <code>        row = row[: len(headers)]</code> |
| L0263 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_tshark_line。 | <code>    return dict(zip(headers, row))</code> |
| L0264 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0265 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0266 | 定义clean函数 &#96;clean&#96;，封装可复用业务逻辑。 | <code>def clean(v: str) -&gt; str:</code> |
| L0267 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 clean。 | <code>    if v is None:</code> |
| L0268 | 结束当前函数并把结果返回给调用方，当前位于函数 clean。 | <code>        return ""</code> |
| L0269 | 结束当前函数并把结果返回给调用方，当前位于函数 clean。 | <code>    return str(v).strip()</code> |
| L0270 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0271 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0272 | 定义truncatecapturetext函数 &#96;truncate_capture_text&#96;，封装可复用业务逻辑。 | <code>def truncate_capture_text(value: str, limit: int = MAX_CAPTURE_PAYLOAD_CHARS) -&gt; str:</code> |
| L0273 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 truncate_capture_text。 | <code>    text = clean(value)</code> |
| L0274 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 truncate_capture_text。 | <code>    if len(text) &lt;= limit:</code> |
| L0275 | 结束当前函数并把结果返回给调用方，当前位于函数 truncate_capture_text。 | <code>        return text</code> |
| L0276 | 计算并保存 &#96;omitted&#96;（omitted），供后续逻辑使用，当前位于函数 truncate_capture_text。 | <code>    omitted = len(text) - limit</code> |
| L0277 | 结束当前函数并把结果返回给调用方，当前位于函数 truncate_capture_text。 | <code>    return f"{text[:limit]}\n...[截断 {omitted} 个字符]"</code> |
| L0278 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0279 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0280 | 定义toint函数 &#96;to_int&#96;，封装可复用业务逻辑。 | <code>def to_int(v: str) -&gt; Optional[int]:</code> |
| L0281 | 计算并保存 &#96;v&#96;（v），供后续逻辑使用，当前位于函数 to_int。 | <code>    v = clean(v)</code> |
| L0282 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 to_int。 | <code>    if not v:</code> |
| L0283 | 结束当前函数并把结果返回给调用方，当前位于函数 to_int。 | <code>        return None</code> |
| L0284 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 to_int。 | <code>    try:</code> |
| L0285 | 结束当前函数并把结果返回给调用方，当前位于函数 to_int。 | <code>        return int(float(v))</code> |
| L0286 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 to_int。 | <code>    except Exception:</code> |
| L0287 | 结束当前函数并把结果返回给调用方，当前位于函数 to_int。 | <code>        return None</code> |
| L0288 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0289 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0290 | 定义tofloat函数 &#96;to_float&#96;，封装可复用业务逻辑。 | <code>def to_float(v: str) -&gt; Optional[float]:</code> |
| L0291 | 计算并保存 &#96;v&#96;（v），供后续逻辑使用，当前位于函数 to_float。 | <code>    v = clean(v)</code> |
| L0292 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 to_float。 | <code>    if not v:</code> |
| L0293 | 结束当前函数并把结果返回给调用方，当前位于函数 to_float。 | <code>        return None</code> |
| L0294 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 to_float。 | <code>    try:</code> |
| L0295 | 结束当前函数并把结果返回给调用方，当前位于函数 to_float。 | <code>        return float(v)</code> |
| L0296 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 to_float。 | <code>    except Exception:</code> |
| L0297 | 结束当前函数并把结果返回给调用方，当前位于函数 to_float。 | <code>        return None</code> |
| L0298 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0299 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0300 | 定义解析ports函数 &#96;parse_ports&#96;，封装可复用业务逻辑。 | <code>def parse_ports(port_default: int, ports_text: str) -&gt; List[int]:</code> |
| L0301 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 parse_ports。 | <code>    raw = (ports_text or "").strip()</code> |
| L0302 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_ports。 | <code>    if not raw:</code> |
| L0303 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_ports。 | <code>        return [int(port_default)]</code> |
| L0304 | 计算并保存 &#96;parts&#96;（parts），供后续逻辑使用，当前位于函数 parse_ports。 | <code>    parts = [x for x in re.split(r"[\s,]+", raw) if x]</code> |
| L0305 | 计算并保存 &#96;ports&#96;（ports），供后续逻辑使用，当前位于函数 parse_ports。 | <code>    ports: List[int] = []</code> |
| L0306 | 计算并保存 &#96;seen&#96;（seen），供后续逻辑使用，当前位于函数 parse_ports。 | <code>    seen = set()</code> |
| L0307 | 遍历集合中的数据项并逐项处理，当前位于函数 parse_ports。 | <code>    for item in parts:</code> |
| L0308 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_ports。 | <code>        if not item.isdigit():</code> |
| L0309 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 parse_ports。 | <code>            raise ValueError(f"非法端口: {item}")</code> |
| L0310 | 计算并保存 &#96;port&#96;（port），供后续逻辑使用，当前位于函数 parse_ports。 | <code>        port = int(item)</code> |
| L0311 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_ports。 | <code>        if port &lt; 1 or port &gt; 65535:</code> |
| L0312 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 parse_ports。 | <code>            raise ValueError(f"端口越界: {port}")</code> |
| L0313 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_ports。 | <code>        if port in seen:</code> |
| L0314 | 控制当前循环或占位分支的执行流程，当前位于函数 parse_ports。 | <code>            continue</code> |
| L0315 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 parse_ports。 | <code>        seen.add(port)</code> |
| L0316 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 parse_ports。 | <code>        ports.append(port)</code> |
| L0317 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_ports。 | <code>    if not ports:</code> |
| L0318 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 parse_ports。 | <code>        raise ValueError("ports 为空")</code> |
| L0319 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_ports。 | <code>    return ports</code> |
| L0320 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0321 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0322 | 定义ismostlyreadable函数 &#96;is_mostly_readable&#96;，封装可复用业务逻辑。 | <code>def is_mostly_readable(text: str) -&gt; bool:</code> |
| L0323 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_mostly_readable。 | <code>    if not text:</code> |
| L0324 | 结束当前函数并把结果返回给调用方，当前位于函数 is_mostly_readable。 | <code>        return False</code> |
| L0325 | 计算并保存 &#96;bad&#96;（bad），供后续逻辑使用，当前位于函数 is_mostly_readable。 | <code>    bad = 0</code> |
| L0326 | 计算并保存 &#96;total&#96;（total），供后续逻辑使用，当前位于函数 is_mostly_readable。 | <code>    total = 0</code> |
| L0327 | 遍历集合中的数据项并逐项处理，当前位于函数 is_mostly_readable。 | <code>    for ch in text:</code> |
| L0328 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 is_mostly_readable。 | <code>        total += 1</code> |
| L0329 | 计算并保存 &#96;code&#96;（code），供后续逻辑使用，当前位于函数 is_mostly_readable。 | <code>        code = ord(ch)</code> |
| L0330 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_mostly_readable。 | <code>        if code in (9, 10, 13):  # \t \n \r</code> |
| L0331 | 控制当前循环或占位分支的执行流程，当前位于函数 is_mostly_readable。 | <code>            continue</code> |
| L0332 | 源码原注释：控制字符与明显乱码字符 | <code>        # 控制字符与明显乱码字符</code> |
| L0333 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_mostly_readable。 | <code>        if code &lt; 32 or code == 127:</code> |
| L0334 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 is_mostly_readable。 | <code>            bad += 1</code> |
| L0335 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_mostly_readable。 | <code>    if total == 0:</code> |
| L0336 | 结束当前函数并把结果返回给调用方，当前位于函数 is_mostly_readable。 | <code>        return False</code> |
| L0337 | 结束当前函数并把结果返回给调用方，当前位于函数 is_mostly_readable。 | <code>    return (bad / total) &lt;= 0.1</code> |
| L0338 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0339 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0340 | 定义looksliketextpayload函数 &#96;looks_like_text_payload&#96;，封装可复用业务逻辑。 | <code>def looks_like_text_payload(text: str) -&gt; bool:</code> |
| L0341 | 计算并保存 &#96;s&#96;（s），供后续逻辑使用，当前位于函数 looks_like_text_payload。 | <code>    s = clean(text)</code> |
| L0342 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 looks_like_text_payload。 | <code>    if not s:</code> |
| L0343 | 结束当前函数并把结果返回给调用方，当前位于函数 looks_like_text_payload。 | <code>        return False</code> |
| L0344 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 looks_like_text_payload。 | <code>    if not is_mostly_readable(s):</code> |
| L0345 | 结束当前函数并把结果返回给调用方，当前位于函数 looks_like_text_payload。 | <code>        return False</code> |
| L0346 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0347 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 looks_like_text_payload。 | <code>    if re.search(r"(?:\{&#124;\}&#124;\[&#124;\]&#124;=&#124;&amp;&#124;:&#124;\"&#124;&lt;&#124;&gt;&#124;/&#124;\\n)", s):</code> |
| L0348 | 结束当前函数并把结果返回给调用方，当前位于函数 looks_like_text_payload。 | <code>        return True</code> |
| L0349 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 looks_like_text_payload。 | <code>    if re.search(r"\b(select&#124;union&#124;drop&#124;insert&#124;update&#124;delete&#124;or\s+1=1&#124;username&#124;password&#124;token)\b", s, re.I):</code> |
| L0350 | 结束当前函数并把结果返回给调用方，当前位于函数 looks_like_text_payload。 | <code>        return True</code> |
| L0351 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 looks_like_text_payload。 | <code>    if re.fullmatch(r"[A-Za-z0-9._~=&amp;%+\-/:;,@\s]{6,}", s):</code> |
| L0352 | 结束当前函数并把结果返回给调用方，当前位于函数 looks_like_text_payload。 | <code>        return True</code> |
| L0353 | 结束当前函数并把结果返回给调用方，当前位于函数 looks_like_text_payload。 | <code>    return False</code> |
| L0354 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0355 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0356 | 定义maybeunquotepayload函数 &#96;maybe_unquote_payload&#96;，封装可复用业务逻辑。 | <code>def maybe_unquote_payload(text: str) -&gt; str:</code> |
| L0357 | 计算并保存 &#96;s&#96;（s），供后续逻辑使用，当前位于函数 maybe_unquote_payload。 | <code>    s = clean(text)</code> |
| L0358 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 maybe_unquote_payload。 | <code>    if not s:</code> |
| L0359 | 结束当前函数并把结果返回给调用方，当前位于函数 maybe_unquote_payload。 | <code>        return s</code> |
| L0360 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 maybe_unquote_payload。 | <code>    if "%" not in s and "+" not in s:</code> |
| L0361 | 结束当前函数并把结果返回给调用方，当前位于函数 maybe_unquote_payload。 | <code>        return s</code> |
| L0362 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 maybe_unquote_payload。 | <code>    try:</code> |
| L0363 | 计算并保存 &#96;decoded&#96;（decoded），供后续逻辑使用，当前位于函数 maybe_unquote_payload。 | <code>        decoded = urllib.parse.unquote_plus(s)</code> |
| L0364 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 maybe_unquote_payload。 | <code>    except Exception:</code> |
| L0365 | 结束当前函数并把结果返回给调用方，当前位于函数 maybe_unquote_payload。 | <code>        return s</code> |
| L0366 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 maybe_unquote_payload。 | <code>    if looks_like_text_payload(decoded):</code> |
| L0367 | 结束当前函数并把结果返回给调用方，当前位于函数 maybe_unquote_payload。 | <code>        return decoded</code> |
| L0368 | 结束当前函数并把结果返回给调用方，当前位于函数 maybe_unquote_payload。 | <code>    return s</code> |
| L0369 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0370 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0371 | 定义decodehttpfiledata函数 &#96;decode_http_file_data&#96;，封装可复用业务逻辑。 | <code>def decode_http_file_data(value: str) -&gt; str:</code> |
| L0372 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 decode_http_file_data。 | <code>    raw = clean(value)</code> |
| L0373 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_http_file_data。 | <code>    if not raw:</code> |
| L0374 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_http_file_data。 | <code>        return ""</code> |
| L0375 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0376 | 计算并保存 &#96;original_length&#96;（originallength），供后续逻辑使用，当前位于函数 decode_http_file_data。 | <code>    original_length = len(raw)</code> |
| L0377 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_http_file_data。 | <code>    if original_length &gt; MAX_TSHARK_FIELD_CHARS:</code> |
| L0378 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 decode_http_file_data。 | <code>        raw = raw[:MAX_TSHARK_FIELD_CHARS]</code> |
| L0379 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0380 | 源码原注释：tshark 的 http.file_data 常见是连续 hex（或带分隔符） | <code>    # tshark 的 http.file_data 常见是连续 hex（或带分隔符）</code> |
| L0381 | 计算并保存 &#96;compact&#96;（compact），供后续逻辑使用，当前位于函数 decode_http_file_data。 | <code>    compact = raw</code> |
| L0382 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_http_file_data。 | <code>    if re.fullmatch(r"(?:[0-9A-Fa-f]{2}:)+[0-9A-Fa-f]{2}", compact):</code> |
| L0383 | 计算并保存 &#96;compact&#96;（compact），供后续逻辑使用，当前位于函数 decode_http_file_data。 | <code>        compact = compact.replace(":", "")</code> |
| L0384 | 当前一条件未命中时继续判断另一条件，当前位于函数 decode_http_file_data。 | <code>    elif re.fullmatch(r"(?:[0-9A-Fa-f]{2}\s+)+[0-9A-Fa-f]{2}", compact):</code> |
| L0385 | 计算并保存 &#96;compact&#96;（compact），供后续逻辑使用，当前位于函数 decode_http_file_data。 | <code>        compact = re.sub(r"\s+", "", compact)</code> |
| L0386 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0387 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_http_file_data。 | <code>    if not re.fullmatch(r"[0-9A-Fa-f]+", compact):</code> |
| L0388 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_http_file_data。 | <code>        return truncate_capture_text(raw)</code> |
| L0389 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_http_file_data。 | <code>    if len(compact) &lt; 8 or len(compact) % 2 != 0:</code> |
| L0390 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_http_file_data。 | <code>        return truncate_capture_text(raw)</code> |
| L0391 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0392 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 decode_http_file_data。 | <code>    try:</code> |
| L0393 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 decode_http_file_data。 | <code>        data = bytes.fromhex(compact)</code> |
| L0394 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 decode_http_file_data。 | <code>    except Exception:</code> |
| L0395 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_http_file_data。 | <code>        return truncate_capture_text(raw)</code> |
| L0396 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0397 | 遍历集合中的数据项并逐项处理，当前位于函数 decode_http_file_data。 | <code>    for enc in ("utf-8", "latin1"):</code> |
| L0398 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 decode_http_file_data。 | <code>        try:</code> |
| L0399 | 计算并保存 &#96;decoded&#96;（decoded），供后续逻辑使用，当前位于函数 decode_http_file_data。 | <code>            decoded = data.decode(enc)</code> |
| L0400 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 decode_http_file_data。 | <code>        except Exception:</code> |
| L0401 | 控制当前循环或占位分支的执行流程，当前位于函数 decode_http_file_data。 | <code>            continue</code> |
| L0402 | 计算并保存 &#96;decoded&#96;（decoded），供后续逻辑使用，当前位于函数 decode_http_file_data。 | <code>        decoded = maybe_unquote_payload(decoded)</code> |
| L0403 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_http_file_data。 | <code>        if looks_like_text_payload(decoded):</code> |
| L0404 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 decode_http_file_data。 | <code>            result = truncate_capture_text(decoded)</code> |
| L0405 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_http_file_data。 | <code>            if original_length &gt; MAX_TSHARK_FIELD_CHARS:</code> |
| L0406 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decode_http_file_data。 | <code>                result += f"\n...[原始字段共 {original_length} 个字符]"</code> |
| L0407 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_http_file_data。 | <code>            return result</code> |
| L0408 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0409 | 源码原注释：对不可读负载保留原始 hex，避免输出乱码误导检测。 | <code>    # 对不可读负载保留原始 hex，避免输出乱码误导检测。</code> |
| L0410 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 decode_http_file_data。 | <code>    result = truncate_capture_text(raw)</code> |
| L0411 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 decode_http_file_data。 | <code>    if original_length &gt; MAX_TSHARK_FIELD_CHARS:</code> |
| L0412 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 decode_http_file_data。 | <code>        result += f"\n...[原始字段共 {original_length} 个字符]"</code> |
| L0413 | 结束当前函数并把结果返回给调用方，当前位于函数 decode_http_file_data。 | <code>    return result</code> |
| L0414 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0415 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0416 | 定义requesttext函数 &#96;request_text&#96;，封装可复用业务逻辑。 | <code>def request_text(req: Dict, resp: Optional[Dict]) -&gt; str:</code> |
| L0417 | 结束当前函数并把结果返回给调用方，当前位于函数 request_text。 | <code>    return "\n".join(</code> |
| L0418 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_text。 | <code>        [</code> |
| L0419 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_text。 | <code>            f"METHOD={req.get('method','')}",</code> |
| L0420 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_text。 | <code>            f"URI={req.get('uri','')}",</code> |
| L0421 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_text。 | <code>            f"HOST={req.get('host','')}",</code> |
| L0422 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_text。 | <code>            f"CONTENT_TYPE={req.get('content_type','')}",</code> |
| L0423 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_text。 | <code>            f"STATUS_CODE={resp.get('status_code','') if resp else ''}",</code> |
| L0424 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_text。 | <code>            f"REQUEST_BODY={req.get('request_body','')}",</code> |
| L0425 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 request_text。 | <code>            f"RESPONSE_EXCERPT={resp.get('response_body_excerpt','') if resp else ''}",</code> |
| L0426 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 request_text。 | <code>        ]</code> |
| L0427 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 request_text。 | <code>    )</code> |
| L0428 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0429 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0430 | 定义responsetext函数 &#96;response_text&#96;，封装可复用业务逻辑。 | <code>def response_text(resp: Optional[Dict]) -&gt; str:</code> |
| L0431 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 response_text。 | <code>    if not resp:</code> |
| L0432 | 结束当前函数并把结果返回给调用方，当前位于函数 response_text。 | <code>        return ""</code> |
| L0433 | 结束当前函数并把结果返回给调用方，当前位于函数 response_text。 | <code>    return "\n".join(</code> |
| L0434 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 response_text。 | <code>        [</code> |
| L0435 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 response_text。 | <code>            f"HTTP_STATUS={resp.get('status_code','')}",</code> |
| L0436 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 response_text。 | <code>            f"MESSAGE={resp.get('response_phrase','')}",</code> |
| L0437 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 response_text。 | <code>            f"RESPONSE_EXCERPT={resp.get('response_body_excerpt','')}",</code> |
| L0438 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 response_text。 | <code>        ]</code> |
| L0439 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 response_text。 | <code>    )</code> |
| L0440 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0441 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0442 | 定义request封禁函数 &#96;request_block&#96;，封装可复用业务逻辑。 | <code>def request_block(req: Dict) -&gt; str:</code> |
| L0443 | 计算并保存 &#96;lines&#96;（lines），供后续逻辑使用，当前位于函数 request_block。 | <code>    lines = [f"{req.get('method','')} {req.get('uri','')} HTTP/1.1"]</code> |
| L0444 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 request_block。 | <code>    if req.get("host"):</code> |
| L0445 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 request_block。 | <code>        lines.append(f"Host: {req.get('host')}")</code> |
| L0446 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 request_block。 | <code>    if req.get("content_type"):</code> |
| L0447 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 request_block。 | <code>        lines.append(f"Content-Type: {req.get('content_type')}")</code> |
| L0448 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 request_block。 | <code>    lines.append("Body:")</code> |
| L0449 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 request_block。 | <code>    lines.append(req.get("request_body") or "")</code> |
| L0450 | 结束当前函数并把结果返回给调用方，当前位于函数 request_block。 | <code>    return "\n".join(lines)</code> |
| L0451 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0452 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0453 | 定义response封禁函数 &#96;response_block&#96;，封装可复用业务逻辑。 | <code>def response_block(resp: Optional[Dict]) -&gt; str:</code> |
| L0454 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 response_block。 | <code>    if not resp:</code> |
| L0455 | 结束当前函数并把结果返回给调用方，当前位于函数 response_block。 | <code>        return ""</code> |
| L0456 | 计算并保存 &#96;lines&#96;（lines），供后续逻辑使用，当前位于函数 response_block。 | <code>    lines = [f"HTTP/1.1 {resp.get('status_code','')} {resp.get('response_phrase','')}"]</code> |
| L0457 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 response_block。 | <code>    lines.append("Body:")</code> |
| L0458 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 response_block。 | <code>    lines.append(resp.get("response_body_excerpt") or "")</code> |
| L0459 | 结束当前函数并把结果返回给调用方，当前位于函数 response_block。 | <code>    return "\n".join(lines)</code> |
| L0460 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0461 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0462 | 定义写入canonicalbatch函数 &#96;write_canonical_batch&#96;，封装可复用业务逻辑。 | <code>def write_canonical_batch(path: Path, file_id: str, batch_size: int, port_desc: str, cases: List[Dict]):</code> |
| L0463 | 计算并保存 &#96;lines&#96;（lines），供后续逻辑使用，当前位于函数 write_canonical_batch。 | <code>    lines: List[str] = []</code> |
| L0464 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>    lines.append("### BATCH_START ###")</code> |
| L0465 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>    lines.append(f"file_id={file_id}")</code> |
| L0466 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>    lines.append(f"batch_size={batch_size}")</code> |
| L0467 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>    lines.append("source=live_capture")</code> |
| L0468 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>    lines.append(f"port={port_desc}")</code> |
| L0469 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>    lines.append("capture_mode=canonical_http_batch")</code> |
| L0470 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>    lines.append("### BATCH_META_END ###")</code> |
| L0471 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>    lines.append("")</code> |
| L0472 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0473 | 遍历集合中的数据项并逐项处理，当前位于函数 write_canonical_batch。 | <code>    for idx, case in enumerate(cases, start=1):</code> |
| L0474 | 计算并保存 &#96;req&#96;（req），供后续逻辑使用，当前位于函数 write_canonical_batch。 | <code>        req = case["request"]</code> |
| L0475 | 计算并保存 &#96;resp&#96;（resp），供后续逻辑使用，当前位于函数 write_canonical_batch。 | <code>        resp = case.get("response")</code> |
| L0476 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0477 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append("### CASE_START ###")</code> |
| L0478 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append(f"file_id={file_id}")</code> |
| L0479 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append(f"seq_id={idx}")</code> |
| L0480 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append(f"frame_req={req.get('frame_no','')}")</code> |
| L0481 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append(f"frame_resp={resp.get('frame_no','') if resp else ''}")</code> |
| L0482 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append(f"time_req={req.get('time','')}")</code> |
| L0483 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append(f"time_resp={resp.get('time','') if resp else ''}")</code> |
| L0484 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append(f"src_ip={req.get('src_ip','')}")</code> |
| L0485 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append(f"dst_ip={req.get('dst_ip','')}")</code> |
| L0486 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append(f"src_port={req.get('src_port','')}")</code> |
| L0487 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append(f"dst_port={req.get('dst_port','')}")</code> |
| L0488 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append(f"method={req.get('method','')}")</code> |
| L0489 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append(f"uri={req.get('uri','')}")</code> |
| L0490 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append(f"host={req.get('host','')}")</code> |
| L0491 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append(f"status_code={resp.get('status_code','') if resp else ''}")</code> |
| L0492 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append(f"content_type={req.get('content_type','')}")</code> |
| L0493 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append(f"request_text={request_text(req, resp).replace(chr(10), r'\n')}")</code> |
| L0494 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append(f"response_text={response_text(resp).replace(chr(10), r'\n')}")</code> |
| L0495 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append("[REQUEST_BLOCK]")</code> |
| L0496 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append(request_block(req))</code> |
| L0497 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append("[/REQUEST_BLOCK]")</code> |
| L0498 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append("[RESPONSE_BLOCK]")</code> |
| L0499 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append(response_block(resp))</code> |
| L0500 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append("[/RESPONSE_BLOCK]")</code> |
| L0501 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append("### CASE_END ###")</code> |
| L0502 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 write_canonical_batch。 | <code>        lines.append("")</code> |
| L0503 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0504 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_batch。 | <code>    path.parent.mkdir(parents=True, exist_ok=True)</code> |
| L0505 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 write_canonical_batch。 | <code>    path.write_text("\n".join(lines), encoding="utf-8")</code> |
| L0506 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0507 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0508 | 定义构建requestfromfields函数 &#96;build_request_from_fields&#96;，封装可复用业务逻辑。 | <code>def build_request_from_fields(fields: Dict[str, str], response_in_field: str) -&gt; Dict:</code> |
| L0509 | 结束当前函数并把结果返回给调用方，当前位于函数 build_request_from_fields。 | <code>    return {</code> |
| L0510 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_from_fields。 | <code>        "frame_no": to_int(fields.get("frame.number")) or 0,</code> |
| L0511 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_from_fields。 | <code>        "time": to_float(fields.get("frame.time_epoch")) or 0.0,</code> |
| L0512 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_from_fields。 | <code>        "src_ip": clean(fields.get("ip.src")),</code> |
| L0513 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_from_fields。 | <code>        "dst_ip": clean(fields.get("ip.dst")),</code> |
| L0514 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_from_fields。 | <code>        "src_port": to_int(fields.get("tcp.srcport")) or 0,</code> |
| L0515 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_from_fields。 | <code>        "dst_port": to_int(fields.get("tcp.dstport")) or 0,</code> |
| L0516 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_from_fields。 | <code>        "stream": to_int(fields.get("tcp.stream")) or -1,</code> |
| L0517 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_from_fields。 | <code>        "method": clean(fields.get("http.request.method")),</code> |
| L0518 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_from_fields。 | <code>        "uri": truncate_capture_text(fields.get("http.request.uri"), 8 * 1024),</code> |
| L0519 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_from_fields。 | <code>        "host": truncate_capture_text(fields.get("http.host"), 512),</code> |
| L0520 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_from_fields。 | <code>        "content_type": truncate_capture_text(fields.get("http.content_type"), 512),</code> |
| L0521 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_from_fields。 | <code>        "request_body": decode_http_file_data(fields.get("http.file_data")),</code> |
| L0522 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_request_from_fields。 | <code>        "response_in_frame": to_int(fields.get(response_in_field)),</code> |
| L0523 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_request_from_fields。 | <code>    }</code> |
| L0524 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0525 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0526 | 定义构建responsefromfields函数 &#96;build_response_from_fields&#96;，封装可复用业务逻辑。 | <code>def build_response_from_fields(fields: Dict[str, str], request_in_field: str) -&gt; Dict:</code> |
| L0527 | 结束当前函数并把结果返回给调用方，当前位于函数 build_response_from_fields。 | <code>    return {</code> |
| L0528 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_response_from_fields。 | <code>        "frame_no": to_int(fields.get("frame.number")) or 0,</code> |
| L0529 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_response_from_fields。 | <code>        "time": to_float(fields.get("frame.time_epoch")) or 0.0,</code> |
| L0530 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_response_from_fields。 | <code>        "src_ip": clean(fields.get("ip.src")),</code> |
| L0531 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_response_from_fields。 | <code>        "dst_ip": clean(fields.get("ip.dst")),</code> |
| L0532 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_response_from_fields。 | <code>        "src_port": to_int(fields.get("tcp.srcport")) or 0,</code> |
| L0533 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_response_from_fields。 | <code>        "dst_port": to_int(fields.get("tcp.dstport")) or 0,</code> |
| L0534 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_response_from_fields。 | <code>        "stream": to_int(fields.get("tcp.stream")) or -1,</code> |
| L0535 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_response_from_fields。 | <code>        "status_code": to_int(fields.get("http.response.code")) or 0,</code> |
| L0536 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_response_from_fields。 | <code>        "response_phrase": clean(fields.get("http.response.phrase")),</code> |
| L0537 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_response_from_fields。 | <code>        "response_body_excerpt": decode_http_file_data(fields.get("http.file_data")),</code> |
| L0538 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_response_from_fields。 | <code>        "request_in_frame": to_int(fields.get(request_in_field)),</code> |
| L0539 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_response_from_fields。 | <code>    }</code> |
| L0540 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0541 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0542 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main():</code> |
| L0543 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="持续抓包并按完整 HTTP 请求/响应记录生成 1.1.n.txt")</code> |
| L0544 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--port", type=int, default=10086, help="抓包端口，默认 10086")</code> |
| L0545 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--ports", default="", help="多端口监听，逗号分隔，如 80,443,8080；为空则用 --port")</code> |
| L0546 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--batch-size", type=int, default=20, help="每个 batch 的完整请求/响应数量")</code> |
| L0547 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--input-dir", default="input", help="输出 txt 目录")</code> |
| L0548 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument(</code> |
| L0549 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--sequence-state",</code> |
| L0550 | 计算并保存 &#96;default&#96;（default），供后续逻辑使用，当前位于函数 main。 | <code>        default="output/capture_sequence.json",</code> |
| L0551 | 计算并保存 &#96;help&#96;（help），供后续逻辑使用，当前位于函数 main。 | <code>        help="抓包文件全局递增编号状态；即使 input 被清理，重启后也不会复用旧编号",</code> |
| L0552 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0553 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument(</code> |
| L0554 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--interface",</code> |
| L0555 | 计算并保存 &#96;default&#96;（default），供后续逻辑使用，当前位于函数 main。 | <code>        default="",</code> |
| L0556 | 计算并保存 &#96;help&#96;（help），供后续逻辑使用，当前位于函数 main。 | <code>        help="手动指定网卡关键字，或直接传接口索引（如 1）跳过网卡枚举",</code> |
| L0557 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0558 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument(</code> |
| L0559 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "--interface-list-timeout",</code> |
| L0560 | 计算并保存 &#96;type&#96;（type），供后续逻辑使用，当前位于函数 main。 | <code>        type=int,</code> |
| L0561 | 计算并保存 &#96;default&#96;（default），供后续逻辑使用，当前位于函数 main。 | <code>        default=180,</code> |
| L0562 | 计算并保存 &#96;help&#96;（help），供后续逻辑使用，当前位于函数 main。 | <code>        help="tshark -D 网卡枚举超时时间（秒），默认 180",</code> |
| L0563 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0564 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--decode-http-port", type=int, default=None, help="强制 HTTP 解码端口，默认等于 --port")</code> |
| L0565 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--keep-running", action="store_true", default=True, help="持续运行直到 Ctrl+C")</code> |
| L0566 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--once", action="store_true", help="仅生成一个 batch 后退出")</code> |
| L0567 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--fast-defense", action="store_true", help="启用后端静默高置信快速封禁")</code> |
| L0568 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--fast-rules", default="rules/fast_defense_rules.json")</code> |
| L0569 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--fast-audit-log", default="output/fast_defense_audit.log")</code> |
| L0570 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-host", default="127.0.0.1")</code> |
| L0571 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-port", type=int, default=3306)</code> |
| L0572 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-user", default="root")</code> |
| L0573 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-password", default="123456")</code> |
| L0574 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-database", default="traffic_pipeline")</code> |
| L0575 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0576 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0577 | 计算并保存 &#96;monitor_ports&#96;（monitorports），供后续逻辑使用，当前位于函数 main。 | <code>    monitor_ports = parse_ports(args.port, args.ports)</code> |
| L0578 | 计算并保存 &#96;decode_ports&#96;（decodeports），供后续逻辑使用，当前位于函数 main。 | <code>    decode_ports = [args.decode_http_port] if args.decode_http_port is not None else list(monitor_ports)</code> |
| L0579 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0580 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0581 | 计算并保存 &#96;admin_only&#96;（adminonly），供后续逻辑使用，当前位于函数 main。 | <code>    admin_only = read_npcap_admin_only_flag()</code> |
| L0582 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if admin_only and not is_windows_admin():</code> |
| L0583 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        print(</code> |
| L0584 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "[ERROR] Npcap AdminOnly=1 and current session is not elevated; packet capture is unavailable.",</code> |
| L0585 | 计算并保存 &#96;file&#96;（file），供后续逻辑使用，当前位于函数 main。 | <code>            file=sys.stderr,</code> |
| L0586 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        )</code> |
| L0587 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        print(</code> |
| L0588 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "[ERROR] Run app.py/script as Administrator, or reinstall Npcap with AdminOnly disabled.",</code> |
| L0589 | 计算并保存 &#96;file&#96;（file），供后续逻辑使用，当前位于函数 main。 | <code>            file=sys.stderr,</code> |
| L0590 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        )</code> |
| L0591 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        sys.exit(2)</code> |
| L0592 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0593 | 计算并保存 &#96;tshark_exe&#96;（tsharkexe），供后续逻辑使用，当前位于函数 main。 | <code>    tshark_exe = find_executable("tshark")</code> |
| L0594 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    request_in_field, response_in_field = detect_http_link_fields(tshark_exe)</code> |
| L0595 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0596 | 计算并保存 &#96;input_dir&#96;（inputdir），供后续逻辑使用，当前位于函数 main。 | <code>    input_dir = Path(args.input_dir)</code> |
| L0597 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    input_dir.mkdir(parents=True, exist_ok=True)</code> |
| L0598 | 计算并保存 &#96;sequence_state&#96;（sequencestate），供后续逻辑使用，当前位于函数 main。 | <code>    sequence_state = Path(args.sequence_state)</code> |
| L0599 | 计算并保存 &#96;fast_guard&#96;（fastguard），供后续逻辑使用，当前位于函数 main。 | <code>    fast_guard = None</code> |
| L0600 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if args.fast_defense:</code> |
| L0601 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>        try:</code> |
| L0602 | 计算并保存 &#96;fast_guard&#96;（fastguard），供后续逻辑使用，当前位于函数 main。 | <code>            fast_guard = FastDefenseGuard(</code> |
| L0603 | 计算并保存 &#96;rules_path&#96;（rulespath），供后续逻辑使用，当前位于函数 main。 | <code>                rules_path=Path(args.fast_rules),</code> |
| L0604 | 计算并保存 &#96;mysql_config&#96;（mysql配置），供后续逻辑使用，当前位于函数 main。 | <code>                mysql_config={</code> |
| L0605 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    "host": args.mysql_host,</code> |
| L0606 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    "port": args.mysql_port,</code> |
| L0607 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    "user": args.mysql_user,</code> |
| L0608 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    "password": args.mysql_password,</code> |
| L0609 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    "database": args.mysql_database,</code> |
| L0610 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>                },</code> |
| L0611 | 计算并保存 &#96;log_path&#96;（logpath），供后续逻辑使用，当前位于函数 main。 | <code>                log_path=Path(args.fast_audit_log),</code> |
| L0612 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>            )</code> |
| L0613 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>            print(f"静默快速防御: enabled rules={len(fast_guard.engine.rules)}")</code> |
| L0614 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>        except Exception as exc:</code> |
| L0615 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>            print(f"[WARN] fast defense unavailable; capture continues: {type(exc).__name__}: {exc}", file=sys.stderr)</code> |
| L0616 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0617 | 计算并保存 &#96;iface_arg&#96;（ifacearg），供后续逻辑使用，当前位于函数 main。 | <code>    iface_arg = (args.interface or "").strip()</code> |
| L0618 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if iface_arg.isdigit():</code> |
| L0619 | 计算并保存 &#96;iface&#96;（iface），供后续逻辑使用，当前位于函数 main。 | <code>        iface = iface_arg</code> |
| L0620 | 计算并保存 &#96;interfaces&#96;（interfaces），供后续逻辑使用，当前位于函数 main。 | <code>        interfaces = []</code> |
| L0621 | 处理前述条件均未命中的情况，当前位于函数 main。 | <code>    else:</code> |
| L0622 | 计算并保存 &#96;interfaces&#96;（interfaces），供后续逻辑使用，当前位于函数 main。 | <code>        interfaces = list_interfaces(</code> |
| L0623 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            tshark_exe,</code> |
| L0624 | 计算并保存 &#96;timeout&#96;（timeout），供后续逻辑使用，当前位于函数 main。 | <code>            timeout=max(1, int(args.interface_list_timeout)),</code> |
| L0625 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        )</code> |
| L0626 | 计算并保存 &#96;iface&#96;（iface），供后续逻辑使用，当前位于函数 main。 | <code>        iface = choose_interface(interfaces, preferred_name=iface_arg)</code> |
| L0627 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0628 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("=" * 80)</code> |
| L0629 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("自动抓包启动（完整 HTTP 请求/响应配对模式）")</code> |
| L0630 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("tshark:", tshark_exe)</code> |
| L0631 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("网卡:", iface)</code> |
| L0632 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("监听端口:", ",".join(str(p) for p in monitor_ports))</code> |
| L0633 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("HTTP decode 端口:", ",".join(str(p) for p in decode_ports))</code> |
| L0634 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("batch 大小:", args.batch_size)</code> |
| L0635 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("input 目录:", input_dir.resolve())</code> |
| L0636 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("request_in 字段:", request_in_field)</code> |
| L0637 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("response_in 字段:", response_in_field)</code> |
| L0638 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("=" * 80)</code> |
| L0639 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0640 | 计算并保存 &#96;headers&#96;（headers），供后续逻辑使用，当前位于函数 main。 | <code>    headers = [</code> |
| L0641 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "frame.number",</code> |
| L0642 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "frame.time_epoch",</code> |
| L0643 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "ip.src",</code> |
| L0644 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "ip.dst",</code> |
| L0645 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "tcp.srcport",</code> |
| L0646 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "tcp.dstport",</code> |
| L0647 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "tcp.stream",</code> |
| L0648 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "http.request.method",</code> |
| L0649 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "http.request.uri",</code> |
| L0650 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "http.host",</code> |
| L0651 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "http.content_type",</code> |
| L0652 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "http.file_data",</code> |
| L0653 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "http.response.code",</code> |
| L0654 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "http.response.phrase",</code> |
| L0655 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        request_in_field,</code> |
| L0656 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        response_in_field,</code> |
| L0657 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    ]</code> |
| L0658 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0659 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>    if len(monitor_ports) == 1:</code> |
| L0660 | 计算并保存 &#96;bpf_filter&#96;（bpffilter），供后续逻辑使用，当前位于函数 main。 | <code>        bpf_filter = f"tcp port {monitor_ports[0]}"</code> |
| L0661 | 处理前述条件均未命中的情况，当前位于函数 main。 | <code>    else:</code> |
| L0662 | 计算并保存 &#96;bpf_filter&#96;（bpffilter），供后续逻辑使用，当前位于函数 main。 | <code>        bpf_filter = " or ".join(f"tcp port {p}" for p in monitor_ports)</code> |
| L0663 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0664 | 计算并保存 &#96;cmd&#96;（cmd），供后续逻辑使用，当前位于函数 main。 | <code>    cmd = [</code> |
| L0665 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        tshark_exe,</code> |
| L0666 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "-l",</code> |
| L0667 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "-n",</code> |
| L0668 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "-i",</code> |
| L0669 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        str(iface),</code> |
| L0670 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "-f",</code> |
| L0671 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        bpf_filter,</code> |
| L0672 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "-Y",</code> |
| L0673 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "http.request or http.response",</code> |
| L0674 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "-T",</code> |
| L0675 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "fields",</code> |
| L0676 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "-E",</code> |
| L0677 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "separator=\t",</code> |
| L0678 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "-E",</code> |
| L0679 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "quote=d",</code> |
| L0680 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "-E",</code> |
| L0681 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        "occurrence=f",</code> |
| L0682 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    ]</code> |
| L0683 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0684 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>    for dp in decode_ports:</code> |
| L0685 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>        cmd.extend(["-d", f"tcp.port=={dp},http"])</code> |
| L0686 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0687 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>    for h in headers:</code> |
| L0688 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>        cmd.extend(["-e", h])</code> |
| L0689 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0690 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print("执行命令:")</code> |
| L0691 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(" ".join(cmd))</code> |
| L0692 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0693 | 计算并保存 &#96;proc&#96;（proc），供后续逻辑使用，当前位于函数 main。 | <code>    proc = subprocess.Popen(</code> |
| L0694 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        cmd,</code> |
| L0695 | 计算并保存 &#96;stdout&#96;（stdout），供后续逻辑使用，当前位于函数 main。 | <code>        stdout=subprocess.PIPE,</code> |
| L0696 | 计算并保存 &#96;stderr&#96;（stderr），供后续逻辑使用，当前位于函数 main。 | <code>        stderr=subprocess.PIPE,</code> |
| L0697 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 main。 | <code>        text=True,</code> |
| L0698 | 计算并保存 &#96;encoding&#96;（encoding），供后续逻辑使用，当前位于函数 main。 | <code>        encoding="utf-8",</code> |
| L0699 | 计算并保存 &#96;errors&#96;（errors），供后续逻辑使用，当前位于函数 main。 | <code>        errors="replace",</code> |
| L0700 | 计算并保存 &#96;bufsize&#96;（bufsize），供后续逻辑使用，当前位于函数 main。 | <code>        bufsize=1,</code> |
| L0701 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0702 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0703 | 计算并保存 &#96;pending_by_frame&#96;（pendingbyframe），供后续逻辑使用，当前位于函数 main。 | <code>    pending_by_frame: Dict[int, Dict] = {}</code> |
| L0704 | 计算并保存 &#96;pending_stream_queue&#96;（pendingstreamqueue），供后续逻辑使用，当前位于函数 main。 | <code>    pending_stream_queue: Dict[int, List[int]] = {}</code> |
| L0705 | 计算并保存 &#96;completed_cases&#96;（completedcases），供后续逻辑使用，当前位于函数 main。 | <code>    completed_cases: List[Dict] = []</code> |
| L0706 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0707 | 计算并保存 &#96;db_last_index&#96;（数据库lastindex），供后续逻辑使用，当前位于函数 main。 | <code>    db_last_index = read_mysql_capture_sequence(</code> |
| L0708 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        {</code> |
| L0709 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "host": args.mysql_host,</code> |
| L0710 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "port": args.mysql_port,</code> |
| L0711 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "user": args.mysql_user,</code> |
| L0712 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "password": args.mysql_password,</code> |
| L0713 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            "database": args.mysql_database,</code> |
| L0714 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>        }</code> |
| L0715 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0716 | 计算并保存 &#96;next_idx&#96;（nextidx），供后续逻辑使用，当前位于函数 main。 | <code>    next_idx = next_file_index(</code> |
| L0717 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        input_dir,</code> |
| L0718 | 计算并保存 &#96;prefix&#96;（prefix），供后续逻辑使用，当前位于函数 main。 | <code>        prefix="1.1.",</code> |
| L0719 | 计算并保存 &#96;state_path&#96;（statepath），供后续逻辑使用，当前位于函数 main。 | <code>        state_path=sequence_state,</code> |
| L0720 | 计算并保存 &#96;minimum_last_index&#96;（minimumlastindex），供后续逻辑使用，当前位于函数 main。 | <code>        minimum_last_index=db_last_index,</code> |
| L0721 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0722 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    write_capture_sequence(sequence_state, next_idx - 1)</code> |
| L0723 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"下一个输出编号从 1.1.{next_idx}.txt 开始")</code> |
| L0724 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0725 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>    try:</code> |
| L0726 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 main。 | <code>        while True:</code> |
| L0727 | 计算并保存 &#96;line&#96;（line），供后续逻辑使用，当前位于函数 main。 | <code>            line = proc.stdout.readline()</code> |
| L0728 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if not line:</code> |
| L0729 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if proc.poll() is not None:</code> |
| L0730 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                    break</code> |
| L0731 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                time.sleep(0.05)</code> |
| L0732 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                continue</code> |
| L0733 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0734 | 计算并保存 &#96;line&#96;（line），供后续逻辑使用，当前位于函数 main。 | <code>            line = line.rstrip("\r\n")</code> |
| L0735 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if not line:</code> |
| L0736 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                continue</code> |
| L0737 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0738 | 计算并保存 &#96;fields&#96;（fields），供后续逻辑使用，当前位于函数 main。 | <code>            fields = parse_tshark_line(line, headers)</code> |
| L0739 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0740 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 main。 | <code>            method = clean(fields.get("http.request.method"))</code> |
| L0741 | 计算并保存 &#96;code&#96;（code），供后续逻辑使用，当前位于函数 main。 | <code>            code = clean(fields.get("http.response.code"))</code> |
| L0742 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0743 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if method:</code> |
| L0744 | 计算并保存 &#96;req&#96;（req），供后续逻辑使用，当前位于函数 main。 | <code>                req = build_request_from_fields(fields, response_in_field=response_in_field)</code> |
| L0745 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if fast_guard is not None:</code> |
| L0746 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>                    try:</code> |
| L0747 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                        fast_guard.inspect(req)</code> |
| L0748 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>                    except Exception as exc:</code> |
| L0749 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                        print(f"[WARN] fast defense inspect failed: {type(exc).__name__}: {exc}", file=sys.stderr)</code> |
| L0750 | 计算并保存 &#96;frame_no&#96;（frameno），供后续逻辑使用，当前位于函数 main。 | <code>                frame_no = req["frame_no"]</code> |
| L0751 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                pending_by_frame[frame_no] = req</code> |
| L0752 | 计算并保存 &#96;stream&#96;（stream），供后续逻辑使用，当前位于函数 main。 | <code>                stream = req.get("stream", -1)</code> |
| L0753 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if stream not in pending_stream_queue:</code> |
| L0754 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    pending_stream_queue[stream] = []</code> |
| L0755 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>                pending_stream_queue[stream].append(frame_no)</code> |
| L0756 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0757 | 当前一条件未命中时继续判断另一条件，当前位于函数 main。 | <code>            elif code:</code> |
| L0758 | 计算并保存 &#96;resp&#96;（resp），供后续逻辑使用，当前位于函数 main。 | <code>                resp = build_response_from_fields(fields, request_in_field=request_in_field)</code> |
| L0759 | 计算并保存 &#96;req&#96;（req），供后续逻辑使用，当前位于函数 main。 | <code>                req = None</code> |
| L0760 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0761 | 计算并保存 &#96;request_frame&#96;（requestframe），供后续逻辑使用，当前位于函数 main。 | <code>                request_frame = resp.get("request_in_frame")</code> |
| L0762 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if request_frame and request_frame in pending_by_frame:</code> |
| L0763 | 计算并保存 &#96;req&#96;（req），供后续逻辑使用，当前位于函数 main。 | <code>                    req = pending_by_frame.pop(request_frame)</code> |
| L0764 | 计算并保存 &#96;q&#96;（q），供后续逻辑使用，当前位于函数 main。 | <code>                    q = pending_stream_queue.get(req.get("stream", -1), [])</code> |
| L0765 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                    if request_frame in q:</code> |
| L0766 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                        q.remove(request_frame)</code> |
| L0767 | 处理前述条件均未命中的情况，当前位于函数 main。 | <code>                else:</code> |
| L0768 | 计算并保存 &#96;stream&#96;（stream），供后续逻辑使用，当前位于函数 main。 | <code>                    stream = resp.get("stream", -1)</code> |
| L0769 | 计算并保存 &#96;q&#96;（q），供后续逻辑使用，当前位于函数 main。 | <code>                    q = pending_stream_queue.get(stream, [])</code> |
| L0770 | 在条件成立期间循环执行，常用于守护进程轮询，当前位于函数 main。 | <code>                    while q:</code> |
| L0771 | 计算并保存 &#96;candidate_frame&#96;（candidateframe），供后续逻辑使用，当前位于函数 main。 | <code>                        candidate_frame = q.pop(0)</code> |
| L0772 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                        if candidate_frame in pending_by_frame:</code> |
| L0773 | 计算并保存 &#96;req&#96;（req），供后续逻辑使用，当前位于函数 main。 | <code>                            req = pending_by_frame.pop(candidate_frame)</code> |
| L0774 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                            break</code> |
| L0775 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0776 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if req:</code> |
| L0777 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 main。 | <code>                    completed_cases.append({"request": req, "response": resp})</code> |
| L0778 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0779 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                    if len(completed_cases) &gt;= args.batch_size:</code> |
| L0780 | 计算并保存 &#96;file_id&#96;（fileid），供后续逻辑使用，当前位于函数 main。 | <code>                        file_id = f"1.1.{next_idx}"</code> |
| L0781 | 计算并保存 &#96;output_txt&#96;（outputtxt），供后续逻辑使用，当前位于函数 main。 | <code>                        output_txt = input_dir / f"{file_id}.txt"</code> |
| L0782 | 计算并保存 &#96;to_write&#96;（to写入），供后续逻辑使用，当前位于函数 main。 | <code>                        to_write = completed_cases[: args.batch_size]</code> |
| L0783 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                        write_canonical_batch(</code> |
| L0784 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                            output_txt,</code> |
| L0785 | 计算并保存 &#96;file_id&#96;（fileid），供后续逻辑使用，当前位于函数 main。 | <code>                            file_id=file_id,</code> |
| L0786 | 计算并保存 &#96;batch_size&#96;（batchsize），供后续逻辑使用，当前位于函数 main。 | <code>                            batch_size=args.batch_size,</code> |
| L0787 | 计算并保存 &#96;port_desc&#96;（portdesc），供后续逻辑使用，当前位于函数 main。 | <code>                            port_desc=",".join(str(p) for p in decode_ports),</code> |
| L0788 | 计算并保存 &#96;cases&#96;（cases），供后续逻辑使用，当前位于函数 main。 | <code>                            cases=to_write,</code> |
| L0789 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>                        )</code> |
| L0790 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>                        try:</code> |
| L0791 | 导入后续逻辑所需的模块、类或函数：&#96;from pipeline_events import DB_READY_EVENT, DETECTION_READY_EVENT, INPUT_QUEUE_NAME, append_input_ready, notify_event&#96;。 | <code>                            from pipeline_events import DB_READY_EVENT, DETECTION_READY_EVENT, INPUT_QUEUE_NAME, append_input_ready, notify_event</code> |
| L0792 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0793 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                            append_input_ready(output_txt.parent.parent / "output" / INPUT_QUEUE_NAME, output_txt)</code> |
| L0794 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                            notify_event(DETECTION_READY_EVENT)</code> |
| L0795 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                            notify_event(DB_READY_EVENT)</code> |
| L0796 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>                        except Exception as exc:</code> |
| L0797 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                            print(f"[WARN] input event notification failed: {exc}", file=sys.stderr)</code> |
| L0798 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0799 | 计算并保存 &#96;seq_from&#96;（seqfrom），供后续逻辑使用，当前位于函数 main。 | <code>                        seq_from = 1</code> |
| L0800 | 计算并保存 &#96;seq_to&#96;（seqto），供后续逻辑使用，当前位于函数 main。 | <code>                        seq_to = len(to_write)</code> |
| L0801 | 计算并保存 &#96;preview_uris&#96;（previewuris），供后续逻辑使用，当前位于函数 main。 | <code>                        preview_uris = [c["request"].get("uri", "") for c in to_write[:3]]</code> |
| L0802 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0803 | 源码原注释：Untrusted HTTP text must never terminate packet capture | <code>                        # Untrusted HTTP text must never terminate packet capture</code> |
| L0804 | 源码原注释：because the Windows console cannot encode a payload. | <code>                        # because the Windows console cannot encode a payload.</code> |
| L0805 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>                        try:</code> |
| L0806 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                            print(f"[OK] generated {output_txt}")</code> |
| L0807 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                            print(f"cases={len(to_write)}")</code> |
| L0808 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                            print(f"seq_range={seq_from}-{seq_to}")</code> |
| L0809 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                            print(f"uri_preview={preview_uris!r}")</code> |
| L0810 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>                        except UnicodeEncodeError:</code> |
| L0811 | 计算并保存 &#96;safe_preview&#96;（safepreview），供后续逻辑使用，当前位于函数 main。 | <code>                            safe_preview = repr(preview_uris).encode("ascii", "backslashreplace").decode("ascii")</code> |
| L0812 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                            print(f"uri_preview={safe_preview}")</code> |
| L0813 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0814 | 计算并保存 &#96;completed_cases&#96;（completedcases），供后续逻辑使用，当前位于函数 main。 | <code>                        completed_cases = completed_cases[args.batch_size :]</code> |
| L0815 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                        write_capture_sequence(sequence_state, next_idx)</code> |
| L0816 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                        next_idx += 1</code> |
| L0817 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0818 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                        if args.once:</code> |
| L0819 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                            break</code> |
| L0820 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0821 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if args.once and proc.poll() is not None:</code> |
| L0822 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                break</code> |
| L0823 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0824 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>    except KeyboardInterrupt:</code> |
| L0825 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        print("\n收到 Ctrl+C，正在停止抓包...")</code> |
| L0826 | 无论成功或异常都执行资源清理，当前位于函数 main。 | <code>    finally:</code> |
| L0827 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if fast_guard is not None:</code> |
| L0828 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            fast_guard.close()</code> |
| L0829 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>        try:</code> |
| L0830 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            proc.terminate()</code> |
| L0831 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            proc.wait(timeout=5)</code> |
| L0832 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>        except Exception:</code> |
| L0833 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>            try:</code> |
| L0834 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                proc.kill()</code> |
| L0835 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 main。 | <code>            except Exception:</code> |
| L0836 | 控制当前循环或占位分支的执行流程，当前位于函数 main。 | <code>                pass</code> |
| L0837 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0838 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if proc.stderr:</code> |
| L0839 | 计算并保存 &#96;err&#96;（err），供后续逻辑使用，当前位于函数 main。 | <code>            err = proc.stderr.read().strip()</code> |
| L0840 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if err:</code> |
| L0841 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                print("\n[tshark STDERR]")</code> |
| L0842 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>                print(err)</code> |
| L0843 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0844 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>        print("抓包已停止。")</code> |
| L0845 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0846 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0847 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0848 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
