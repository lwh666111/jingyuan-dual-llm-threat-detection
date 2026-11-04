# `scripts/firewall_control.py` 逐行注释

**脚本用途：** Windows 防火墙双向封禁与解封实现，维护安全操作记录。

**源码行数：** 173　**函数/类数量：** 9

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import ipaddress&#96;。 | <code>import ipaddress</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import os&#96;。 | <code>import os</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;import re&#96;。 | <code>import re</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;import subprocess&#96;。 | <code>import subprocess</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, List, Tuple&#96;。 | <code>from typing import Any, Dict, List, Tuple</code> |
| L0009 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0010 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0011 | 计算并保存 &#96;RULE_PREFIX&#96;（RULEPREFIX），供后续逻辑使用。 | <code>RULE_PREFIX = "TP_BLOCK_IP"</code> |
| L0012 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0013 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0014 | 定义标准化ipliteral函数 &#96;normalize_ip_literal&#96;，封装可复用业务逻辑。 | <code>def normalize_ip_literal(value: Any) -&gt; str:</code> |
| L0015 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 normalize_ip_literal。 | <code>    text = str(value or "").strip()</code> |
| L0016 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_ip_literal。 | <code>    if not text:</code> |
| L0017 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_ip_literal。 | <code>        return ""</code> |
| L0018 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 normalize_ip_literal。 | <code>    if text.startswith("[") and text.endswith("]"):</code> |
| L0019 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 normalize_ip_literal。 | <code>        text = text[1:-1]</code> |
| L0020 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 normalize_ip_literal。 | <code>    try:</code> |
| L0021 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_ip_literal。 | <code>        return str(ipaddress.ip_address(text))</code> |
| L0022 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 normalize_ip_literal。 | <code>    except ValueError:</code> |
| L0023 | 结束当前函数并把结果返回给调用方，当前位于函数 normalize_ip_literal。 | <code>        return ""</code> |
| L0024 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0025 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0026 | 定义firewallrulenames函数 &#96;firewall_rule_names&#96;，封装可复用业务逻辑。 | <code>def firewall_rule_names(ip_text: str) -&gt; Tuple[str, str]:</code> |
| L0027 | 计算并保存 &#96;suffix&#96;（suffix），供后续逻辑使用，当前位于函数 firewall_rule_names。 | <code>    suffix = re.sub(r"[^A-Za-z0-9_.:-]", "_", str(ip_text or "").strip())</code> |
| L0028 | 结束当前函数并把结果返回给调用方，当前位于函数 firewall_rule_names。 | <code>    return f"{RULE_PREFIX}_IN_{suffix}", f"{RULE_PREFIX}_OUT_{suffix}"</code> |
| L0029 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0030 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0031 | 定义psquote函数 &#96;_ps_quote&#96;，封装可复用业务逻辑。 | <code>def _ps_quote(value: str) -&gt; str:</code> |
| L0032 | 结束当前函数并把结果返回给调用方，当前位于函数 _ps_quote。 | <code>    return "'" + str(value).replace("'", "''") + "'"</code> |
| L0033 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0034 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0035 | 定义运行powershell函数 &#96;_run_powershell&#96;，封装可复用业务逻辑。 | <code>def _run_powershell(command: str, timeout: int = 20) -&gt; Tuple[bool, str]:</code> |
| L0036 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _run_powershell。 | <code>    if os.name != "nt":</code> |
| L0037 | 结束当前函数并把结果返回给调用方，当前位于函数 _run_powershell。 | <code>        return False, "firewall_supported_only_on_windows"</code> |
| L0038 | 计算并保存 &#96;prefix&#96;（prefix），供后续逻辑使用，当前位于函数 _run_powershell。 | <code>    prefix = "$ErrorActionPreference='Stop'; $OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); "</code> |
| L0039 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 _run_powershell。 | <code>    try:</code> |
| L0040 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 _run_powershell。 | <code>        result = subprocess.run(</code> |
| L0041 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _run_powershell。 | <code>            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", prefix + command],</code> |
| L0042 | 计算并保存 &#96;capture_output&#96;（captureoutput），供后续逻辑使用，当前位于函数 _run_powershell。 | <code>            capture_output=True,</code> |
| L0043 | 计算并保存 &#96;text&#96;（text），供后续逻辑使用，当前位于函数 _run_powershell。 | <code>            text=True,</code> |
| L0044 | 计算并保存 &#96;encoding&#96;（encoding），供后续逻辑使用，当前位于函数 _run_powershell。 | <code>            encoding="utf-8",</code> |
| L0045 | 计算并保存 &#96;errors&#96;（errors），供后续逻辑使用，当前位于函数 _run_powershell。 | <code>            errors="replace",</code> |
| L0046 | 计算并保存 &#96;timeout&#96;（timeout），供后续逻辑使用，当前位于函数 _run_powershell。 | <code>            timeout=timeout,</code> |
| L0047 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _run_powershell。 | <code>        )</code> |
| L0048 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 _run_powershell。 | <code>    except Exception as exc:</code> |
| L0049 | 结束当前函数并把结果返回给调用方，当前位于函数 _run_powershell。 | <code>        return False, str(exc)</code> |
| L0050 | 计算并保存 &#96;detail&#96;（detail），供后续逻辑使用，当前位于函数 _run_powershell。 | <code>    detail = "\n".join(part for part in [result.stdout.strip(), result.stderr.strip()] if part)</code> |
| L0051 | 结束当前函数并把结果返回给调用方，当前位于函数 _run_powershell。 | <code>    return result.returncode == 0, detail</code> |
| L0052 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0053 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0054 | 定义firewall状态函数 &#96;firewall_status&#96;，封装可复用业务逻辑。 | <code>def firewall_status(ip_text: str) -&gt; Dict[str, Any]:</code> |
| L0055 | 计算并保存 &#96;ip_value&#96;（ipvalue），供后续逻辑使用，当前位于函数 firewall_status。 | <code>    ip_value = normalize_ip_literal(ip_text)</code> |
| L0056 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 firewall_status。 | <code>    if not ip_value:</code> |
| L0057 | 结束当前函数并把结果返回给调用方，当前位于函数 firewall_status。 | <code>        return {"ip_address": "", "active": False, "inbound": False, "outbound": False, "error": "invalid_ip"}</code> |
| L0058 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status。 | <code>    inbound, outbound = firewall_rule_names(ip_value)</code> |
| L0059 | 计算并保存 &#96;script&#96;（script），供后续逻辑使用，当前位于函数 firewall_status。 | <code>    script = (</code> |
| L0060 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status。 | <code>        f"$names=@({_ps_quote(inbound)},{_ps_quote(outbound)}); "</code> |
| L0061 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status。 | <code>        "$rows=@(); foreach($name in $names){ "</code> |
| L0062 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status。 | <code>        "$rule=Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue; "</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status。 | <code>        "if($rule){$addr=$rule &#124; Get-NetFirewallAddressFilter; "</code> |
| L0064 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status。 | <code>        "$rows += [pscustomobject]@{Name=$rule.Name;Enabled=[string]$rule.Enabled;Direction=[string]$rule.Direction;Action=[string]$rule.Action;RemoteAddress=($addr.RemoteAddress -join ',')}}}; "</code> |
| L0065 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status。 | <code>        "$rows &#124; ConvertTo-Json -Compress"</code> |
| L0066 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 firewall_status。 | <code>    )</code> |
| L0067 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status。 | <code>    ok, output = _run_powershell(script)</code> |
| L0068 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 firewall_status。 | <code>    if not ok:</code> |
| L0069 | 结束当前函数并把结果返回给调用方，当前位于函数 firewall_status。 | <code>        return {"ip_address": ip_value, "active": False, "inbound": False, "outbound": False, "error": output}</code> |
| L0070 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 firewall_status。 | <code>    try:</code> |
| L0071 | 计算并保存 &#96;parsed&#96;（parsed），供后续逻辑使用，当前位于函数 firewall_status。 | <code>        parsed = json.loads(output) if output else []</code> |
| L0072 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 firewall_status。 | <code>    except json.JSONDecodeError:</code> |
| L0073 | 计算并保存 &#96;parsed&#96;（parsed），供后续逻辑使用，当前位于函数 firewall_status。 | <code>        parsed = []</code> |
| L0074 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 firewall_status。 | <code>    rows: List[Dict[str, Any]] = parsed if isinstance(parsed, list) else ([parsed] if isinstance(parsed, dict) else [])</code> |
| L0075 | 计算并保存 &#96;active_names&#96;（activenames），供后续逻辑使用，当前位于函数 firewall_status。 | <code>    active_names = {</code> |
| L0076 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status。 | <code>        str(row.get("Name") or "")</code> |
| L0077 | 遍历集合中的数据项并逐项处理，当前位于函数 firewall_status。 | <code>        for row in rows</code> |
| L0078 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 firewall_status。 | <code>        if str(row.get("Enabled") or "").lower() == "true" and str(row.get("Action") or "").lower() == "block"</code> |
| L0079 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 firewall_status。 | <code>    }</code> |
| L0080 | 计算并保存 &#96;has_inbound&#96;（hasinbound），供后续逻辑使用，当前位于函数 firewall_status。 | <code>    has_inbound = inbound in active_names</code> |
| L0081 | 计算并保存 &#96;has_outbound&#96;（hasoutbound），供后续逻辑使用，当前位于函数 firewall_status。 | <code>    has_outbound = outbound in active_names</code> |
| L0082 | 结束当前函数并把结果返回给调用方，当前位于函数 firewall_status。 | <code>    return {</code> |
| L0083 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status。 | <code>        "ip_address": ip_value,</code> |
| L0084 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status。 | <code>        "active": has_inbound and has_outbound,</code> |
| L0085 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status。 | <code>        "inbound": has_inbound,</code> |
| L0086 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status。 | <code>        "outbound": has_outbound,</code> |
| L0087 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status。 | <code>        "rules": rows,</code> |
| L0088 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status。 | <code>        "error": "",</code> |
| L0089 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 firewall_status。 | <code>    }</code> |
| L0090 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0091 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0092 | 定义firewall状态many函数 &#96;firewall_status_many&#96;，封装可复用业务逻辑。 | <code>def firewall_status_many(ip_values: List[str]) -&gt; Dict[str, Dict[str, Any]]:</code> |
| L0093 | 计算并保存 &#96;normalized&#96;（normalized），供后续逻辑使用，当前位于函数 firewall_status_many。 | <code>    normalized = list(dict.fromkeys(normalize_ip_literal(value) for value in ip_values))</code> |
| L0094 | 计算并保存 &#96;normalized&#96;（normalized），供后续逻辑使用，当前位于函数 firewall_status_many。 | <code>    normalized = [value for value in normalized if value]</code> |
| L0095 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 firewall_status_many。 | <code>    if not normalized:</code> |
| L0096 | 结束当前函数并把结果返回给调用方，当前位于函数 firewall_status_many。 | <code>        return {}</code> |
| L0097 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 firewall_status_many。 | <code>    if os.name != "nt":</code> |
| L0098 | 结束当前函数并把结果返回给调用方，当前位于函数 firewall_status_many。 | <code>        return {value: {"ip_address": value, "active": False, "inbound": False, "outbound": False, "error": "unsupported_platform"} for value in normalized}</code> |
| L0099 | 计算并保存 &#96;script&#96;（script），供后续逻辑使用，当前位于函数 firewall_status_many。 | <code>    script = (</code> |
| L0100 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status_many。 | <code>        f"$rules=Get-NetFirewallRule -Name {_ps_quote(RULE_PREFIX + '_*')} -ErrorAction SilentlyContinue; "</code> |
| L0101 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status_many。 | <code>        "$rows=@(); foreach($rule in $rules){$rows += [pscustomobject]@{Name=$rule.Name;Enabled=[string]$rule.Enabled;Direction=[string]$rule.Direction;Action=[string]$rule.Action}}; "</code> |
| L0102 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status_many。 | <code>        "$rows &#124; ConvertTo-Json -Compress"</code> |
| L0103 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 firewall_status_many。 | <code>    )</code> |
| L0104 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status_many。 | <code>    ok, output = _run_powershell(script)</code> |
| L0105 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 firewall_status_many。 | <code>    if not ok:</code> |
| L0106 | 结束当前函数并把结果返回给调用方，当前位于函数 firewall_status_many。 | <code>        return {value: {"ip_address": value, "active": False, "inbound": False, "outbound": False, "error": output} for value in normalized}</code> |
| L0107 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 firewall_status_many。 | <code>    try:</code> |
| L0108 | 计算并保存 &#96;parsed&#96;（parsed），供后续逻辑使用，当前位于函数 firewall_status_many。 | <code>        parsed = json.loads(output) if output else []</code> |
| L0109 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 firewall_status_many。 | <code>    except json.JSONDecodeError:</code> |
| L0110 | 计算并保存 &#96;parsed&#96;（parsed），供后续逻辑使用，当前位于函数 firewall_status_many。 | <code>        parsed = []</code> |
| L0111 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 firewall_status_many。 | <code>    rows: List[Dict[str, Any]] = parsed if isinstance(parsed, list) else ([parsed] if isinstance(parsed, dict) else [])</code> |
| L0112 | 计算并保存 &#96;active_names&#96;（activenames），供后续逻辑使用，当前位于函数 firewall_status_many。 | <code>    active_names = {</code> |
| L0113 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status_many。 | <code>        str(row.get("Name") or "")</code> |
| L0114 | 遍历集合中的数据项并逐项处理，当前位于函数 firewall_status_many。 | <code>        for row in rows</code> |
| L0115 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 firewall_status_many。 | <code>        if str(row.get("Enabled") or "").lower() == "true" and str(row.get("Action") or "").lower() == "block"</code> |
| L0116 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 firewall_status_many。 | <code>    }</code> |
| L0117 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 firewall_status_many。 | <code>    result: Dict[str, Dict[str, Any]] = {}</code> |
| L0118 | 遍历集合中的数据项并逐项处理，当前位于函数 firewall_status_many。 | <code>    for value in normalized:</code> |
| L0119 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status_many。 | <code>        inbound, outbound = firewall_rule_names(value)</code> |
| L0120 | 计算并保存 &#96;has_inbound&#96;（hasinbound），供后续逻辑使用，当前位于函数 firewall_status_many。 | <code>        has_inbound = inbound in active_names</code> |
| L0121 | 计算并保存 &#96;has_outbound&#96;（hasoutbound），供后续逻辑使用，当前位于函数 firewall_status_many。 | <code>        has_outbound = outbound in active_names</code> |
| L0122 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status_many。 | <code>        result[value] = {</code> |
| L0123 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status_many。 | <code>            "ip_address": value,</code> |
| L0124 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status_many。 | <code>            "active": has_inbound and has_outbound,</code> |
| L0125 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status_many。 | <code>            "inbound": has_inbound,</code> |
| L0126 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status_many。 | <code>            "outbound": has_outbound,</code> |
| L0127 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_status_many。 | <code>            "error": "",</code> |
| L0128 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 firewall_status_many。 | <code>        }</code> |
| L0129 | 结束当前函数并把结果返回给调用方，当前位于函数 firewall_status_many。 | <code>    return result</code> |
| L0130 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0131 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0132 | 定义firewall封禁ip函数 &#96;firewall_block_ip&#96;，封装可复用业务逻辑。 | <code>def firewall_block_ip(ip_text: str) -&gt; Tuple[bool, str]:</code> |
| L0133 | 计算并保存 &#96;ip_value&#96;（ipvalue），供后续逻辑使用，当前位于函数 firewall_block_ip。 | <code>    ip_value = normalize_ip_literal(ip_text)</code> |
| L0134 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 firewall_block_ip。 | <code>    if not ip_value:</code> |
| L0135 | 结束当前函数并把结果返回给调用方，当前位于函数 firewall_block_ip。 | <code>        return False, "invalid_or_empty_ip"</code> |
| L0136 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_block_ip。 | <code>    inbound, outbound = firewall_rule_names(ip_value)</code> |
| L0137 | 计算并保存 &#96;script&#96;（script），供后续逻辑使用，当前位于函数 firewall_block_ip。 | <code>    script = (</code> |
| L0138 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_block_ip。 | <code>        f"$names=@({_ps_quote(inbound)},{_ps_quote(outbound)}); "</code> |
| L0139 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_block_ip。 | <code>        "foreach($name in $names){Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue &#124; Remove-NetFirewallRule -ErrorAction Stop}; "</code> |
| L0140 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_block_ip。 | <code>        f"New-NetFirewallRule -Name {_ps_quote(inbound)} -DisplayName {_ps_quote(inbound)} -Direction Inbound -Action Block -RemoteAddress {_ps_quote(ip_value)} -Profile Any -Enabled True &#124; Out-Null; "</code> |
| L0141 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_block_ip。 | <code>        f"New-NetFirewallRule -Name {_ps_quote(outbound)} -DisplayName {_ps_quote(outbound)} -Direction Outbound -Action Block -RemoteAddress {_ps_quote(ip_value)} -Profile Any -Enabled True &#124; Out-Null; "</code> |
| L0142 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_block_ip。 | <code>        "$verified=@($names &#124; ForEach-Object {Get-NetFirewallRule -Name $_ -ErrorAction Stop &#124; Where-Object {$_.Enabled -eq 'True' -and $_.Action -eq 'Block'}}); "</code> |
| L0143 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_block_ip。 | <code>        "if($verified.Count -ne 2){throw 'firewall_rule_verification_failed'}"</code> |
| L0144 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 firewall_block_ip。 | <code>    )</code> |
| L0145 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_block_ip。 | <code>    ok, detail = _run_powershell(script)</code> |
| L0146 | 结束当前函数并把结果返回给调用方，当前位于函数 firewall_block_ip。 | <code>    return (True, "") if ok else (False, detail)</code> |
| L0147 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0148 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0149 | 定义firewall解封ip函数 &#96;firewall_unblock_ip&#96;，封装可复用业务逻辑。 | <code>def firewall_unblock_ip(ip_text: str) -&gt; Tuple[bool, str]:</code> |
| L0150 | 计算并保存 &#96;ip_value&#96;（ipvalue），供后续逻辑使用，当前位于函数 firewall_unblock_ip。 | <code>    ip_value = normalize_ip_literal(ip_text)</code> |
| L0151 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 firewall_unblock_ip。 | <code>    if not ip_value:</code> |
| L0152 | 结束当前函数并把结果返回给调用方，当前位于函数 firewall_unblock_ip。 | <code>        return False, "invalid_or_empty_ip"</code> |
| L0153 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_unblock_ip。 | <code>    inbound, outbound = firewall_rule_names(ip_value)</code> |
| L0154 | 计算并保存 &#96;script&#96;（script），供后续逻辑使用，当前位于函数 firewall_unblock_ip。 | <code>    script = (</code> |
| L0155 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_unblock_ip。 | <code>        f"$names=@({_ps_quote(inbound)},{_ps_quote(outbound)}); "</code> |
| L0156 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_unblock_ip。 | <code>        "foreach($name in $names){Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue &#124; Remove-NetFirewallRule -ErrorAction Stop}; "</code> |
| L0157 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_unblock_ip。 | <code>        "$remaining=@($names &#124; ForEach-Object {Get-NetFirewallRule -Name $_ -ErrorAction SilentlyContinue}); "</code> |
| L0158 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_unblock_ip。 | <code>        "if($remaining.Count -gt 0){throw ('firewall_rule_removal_verification_failed: ' + (($remaining &#124; Select-Object -ExpandProperty Name) -join ','))}"</code> |
| L0159 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 firewall_unblock_ip。 | <code>    )</code> |
| L0160 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 firewall_unblock_ip。 | <code>    ok, detail = _run_powershell(script)</code> |
| L0161 | 结束当前函数并把结果返回给调用方，当前位于函数 firewall_unblock_ip。 | <code>    return (True, "") if ok else (False, detail)</code> |
| L0162 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0163 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0164 | 定义issafeautomatictarget函数 &#96;is_safe_automatic_target&#96;，封装可复用业务逻辑。 | <code>def is_safe_automatic_target(ip_text: str, allow_private: bool = False) -&gt; bool:</code> |
| L0165 | 计算并保存 &#96;value&#96;（value），供后续逻辑使用，当前位于函数 is_safe_automatic_target。 | <code>    value = normalize_ip_literal(ip_text)</code> |
| L0166 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_safe_automatic_target。 | <code>    if not value:</code> |
| L0167 | 结束当前函数并把结果返回给调用方，当前位于函数 is_safe_automatic_target。 | <code>        return False</code> |
| L0168 | 计算并保存 &#96;ip_value&#96;（ipvalue），供后续逻辑使用，当前位于函数 is_safe_automatic_target。 | <code>    ip_value = ipaddress.ip_address(value)</code> |
| L0169 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_safe_automatic_target。 | <code>    if ip_value.is_loopback or ip_value.is_unspecified or ip_value.is_multicast or ip_value.is_link_local:</code> |
| L0170 | 结束当前函数并把结果返回给调用方，当前位于函数 is_safe_automatic_target。 | <code>        return False</code> |
| L0171 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 is_safe_automatic_target。 | <code>    if not allow_private and (ip_value.is_private or ip_value.is_reserved):</code> |
| L0172 | 结束当前函数并把结果返回给调用方，当前位于函数 is_safe_automatic_target。 | <code>        return False</code> |
| L0173 | 结束当前函数并把结果返回给调用方，当前位于函数 is_safe_automatic_target。 | <code>    return True</code> |
