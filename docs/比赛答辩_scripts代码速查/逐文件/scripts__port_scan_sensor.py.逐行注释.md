# `scripts/port_scan_sensor.py` 逐行注释

**脚本用途：** 从 TCP SYN/连接行为中识别端口扫描并写入行为证据。

**源码行数：** 205　**函数/类数量：** 10

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import argparse&#96;。 | <code>import argparse</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import hashlib&#96;。 | <code>import hashlib</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import shutil&#96;。 | <code>import shutil</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;import socket&#96;。 | <code>import socket</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;import subprocess&#96;。 | <code>import subprocess</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;import time&#96;。 | <code>import time</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;from dataclasses import dataclass, field&#96;。 | <code>from dataclasses import dataclass, field</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime, timedelta, timezone&#96;。 | <code>from datetime import datetime, timedelta, timezone</code> |
| L0011 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0012 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Dict, List, Optional, Set, Tuple&#96;。 | <code>from typing import Dict, List, Optional, Set, Tuple</code> |
| L0013 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0014 | 导入后续逻辑所需的模块、类或函数：&#96;from situation_core import SecurityAction, parse_timestamp&#96;。 | <code>from situation_core import SecurityAction, parse_timestamp</code> |
| L0015 | 导入后续逻辑所需的模块、类或函数：&#96;from situation_store import MySQLSettings, MySQLSituationStore&#96;。 | <code>from situation_store import MySQLSettings, MySQLSituationStore</code> |
| L0016 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0017 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0018 | 应用装饰器 &#96;@dataclass&#96;，为下一定义附加权限、缓存或注册行为。 | <code>@dataclass</code> |
| L0019 | 定义类 &#96;ScanWindow&#96;，集中保存相关状态与操作。 | <code>class ScanWindow:</code> |
| L0020 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 ScanWindow。 | <code>    source_ip: str</code> |
| L0021 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 ScanWindow。 | <code>    destination_ip: str</code> |
| L0022 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 ScanWindow。 | <code>    started_at: datetime</code> |
| L0023 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于类 ScanWindow。 | <code>    last_seen_at: datetime</code> |
| L0024 | 计算并保存 &#96;ports&#96;（ports），供后续逻辑使用，当前位于类 ScanWindow。 | <code>    ports: Set[int] = field(default_factory=set)</code> |
| L0025 | 计算并保存 &#96;packet_count&#96;（packetcount），供后续逻辑使用，当前位于类 ScanWindow。 | <code>    packet_count: int = 0</code> |
| L0026 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0027 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0028 | 定义类 &#96;PortScanDetector&#96;，集中保存相关状态与操作。 | <code>class PortScanDetector:</code> |
| L0029 | 定义init函数 &#96;__init__&#96;，封装可复用业务逻辑。 | <code>    def __init__(</code> |
| L0030 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 __init__。 | <code>        self,</code> |
| L0031 | 计算并保存 &#96;unique_port_threshold&#96;（uniqueportthreshold），供后续逻辑使用，当前位于函数 __init__。 | <code>        unique_port_threshold: int = 10,</code> |
| L0032 | 计算并保存 &#96;window_seconds&#96;（windowseconds），供后续逻辑使用，当前位于函数 __init__。 | <code>        window_seconds: int = 60,</code> |
| L0033 | 计算并保存 &#96;target_asset&#96;（targetasset），供后续逻辑使用，当前位于函数 __init__。 | <code>        target_asset: str = "local-server",</code> |
| L0034 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 __init__。 | <code>    ) -&gt; None:</code> |
| L0035 | 计算并保存 &#96;unique_port_threshold&#96;（uniqueportthreshold），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.unique_port_threshold = max(3, int(unique_port_threshold))</code> |
| L0036 | 计算并保存 &#96;window&#96;（window），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.window = timedelta(seconds=max(10, int(window_seconds)))</code> |
| L0037 | 计算并保存 &#96;target_asset&#96;（targetasset），供后续逻辑使用，当前位于函数 __init__。 | <code>        self.target_asset = str(target_asset or "local-server")</code> |
| L0038 | 计算并保存 &#96;_windows&#96;（windows），供后续逻辑使用，当前位于函数 __init__。 | <code>        self._windows: Dict[Tuple[str, str, int], ScanWindow] = {}</code> |
| L0039 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0040 | 定义observe函数 &#96;observe&#96;，封装可复用业务逻辑。 | <code>    def observe(self, occurred_at: datetime, source_ip: str, destination_ip: str, destination_port: int) -&gt; None:</code> |
| L0041 | 计算并保存 &#96;timestamp&#96;（timestamp），供后续逻辑使用，当前位于函数 observe。 | <code>        timestamp = parse_timestamp(occurred_at)</code> |
| L0042 | 计算并保存 &#96;source&#96;（来源），供后续逻辑使用，当前位于函数 observe。 | <code>        source = str(source_ip)</code> |
| L0043 | 计算并保存 &#96;destination&#96;（destination），供后续逻辑使用，当前位于函数 observe。 | <code>        destination = str(destination_ip)</code> |
| L0044 | 计算并保存 &#96;key&#96;（key），供后续逻辑使用，当前位于函数 observe。 | <code>        key = None</code> |
| L0045 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 observe。 | <code>        row = None</code> |
| L0046 | 源码原注释：Fixed epoch buckets split scans that cross a minute boundary. Keep a | <code>        # Fixed epoch buckets split scans that cross a minute boundary. Keep a</code> |
| L0047 | 源码原注释：rolling source/target window so contiguous SYNs remain one action. | <code>        # rolling source/target window so contiguous SYNs remain one action.</code> |
| L0048 | 计算并保存 &#96;candidates&#96;（candidates），供后续逻辑使用，当前位于函数 observe。 | <code>        candidates = sorted(</code> |
| L0049 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 observe。 | <code>            (</code> |
| L0050 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 observe。 | <code>                (window_key, window)</code> |
| L0051 | 遍历集合中的数据项并逐项处理，当前位于函数 observe。 | <code>                for window_key, window in self._windows.items()</code> |
| L0052 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 observe。 | <code>                if window.source_ip == source and window.destination_ip == destination</code> |
| L0053 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 observe。 | <code>            ),</code> |
| L0054 | 计算并保存 &#96;key&#96;（key），供后续逻辑使用，当前位于函数 observe。 | <code>            key=lambda item: item[1].last_seen_at,</code> |
| L0055 | 计算并保存 &#96;reverse&#96;（reverse），供后续逻辑使用，当前位于函数 observe。 | <code>            reverse=True,</code> |
| L0056 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 observe。 | <code>        )</code> |
| L0057 | 遍历集合中的数据项并逐项处理，当前位于函数 observe。 | <code>        for window_key, window in candidates:</code> |
| L0058 | 计算并保存 &#96;earliest&#96;（earliest），供后续逻辑使用，当前位于函数 observe。 | <code>            earliest = min(window.started_at, timestamp)</code> |
| L0059 | 计算并保存 &#96;latest&#96;（latest），供后续逻辑使用，当前位于函数 observe。 | <code>            latest = max(window.last_seen_at, timestamp)</code> |
| L0060 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 observe。 | <code>            if latest - earliest &lt;= self.window:</code> |
| L0061 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 observe。 | <code>                key, row = window_key, window</code> |
| L0062 | 控制当前循环或占位分支的执行流程，当前位于函数 observe。 | <code>                break</code> |
| L0063 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 observe。 | <code>        if row is None:</code> |
| L0064 | 计算并保存 &#96;bucket&#96;（bucket），供后续逻辑使用，当前位于函数 observe。 | <code>            bucket = int(timestamp.timestamp() * 1000)</code> |
| L0065 | 计算并保存 &#96;key&#96;（key），供后续逻辑使用，当前位于函数 observe。 | <code>            key = (source, destination, bucket)</code> |
| L0066 | 计算并保存 &#96;row&#96;（row），供后续逻辑使用，当前位于函数 observe。 | <code>            row = ScanWindow(source, destination, timestamp, timestamp)</code> |
| L0067 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 observe。 | <code>            self._windows[key] = row</code> |
| L0068 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 observe。 | <code>        row.started_at = min(row.started_at, timestamp)</code> |
| L0069 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 observe。 | <code>        row.last_seen_at = max(row.last_seen_at, timestamp)</code> |
| L0070 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 observe。 | <code>        row.ports.add(int(destination_port))</code> |
| L0071 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 observe。 | <code>        row.packet_count += 1</code> |
| L0072 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0073 | 定义actions函数 &#96;actions&#96;，封装可复用业务逻辑。 | <code>    def actions(self, now: Optional[datetime] = None, include_active: bool = True) -&gt; List[SecurityAction]:</code> |
| L0074 | 计算并保存 &#96;now_utc&#96;（nowutc），供后续逻辑使用，当前位于函数 actions。 | <code>        now_utc = parse_timestamp(now or datetime.now(timezone.utc))</code> |
| L0075 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 actions。 | <code>        result: List[SecurityAction] = []</code> |
| L0076 | 遍历集合中的数据项并逐项处理，当前位于函数 actions。 | <code>        for (source_ip, destination_ip, bucket), row in sorted(self._windows.items()):</code> |
| L0077 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 actions。 | <code>            if len(row.ports) &lt; self.unique_port_threshold:</code> |
| L0078 | 控制当前循环或占位分支的执行流程，当前位于函数 actions。 | <code>                continue</code> |
| L0079 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 actions。 | <code>            if not include_active and now_utc - row.last_seen_at &lt;= self.window:</code> |
| L0080 | 控制当前循环或占位分支的执行流程，当前位于函数 actions。 | <code>                continue</code> |
| L0081 | 计算并保存 &#96;digest&#96;（digest），供后续逻辑使用，当前位于函数 actions。 | <code>            digest = hashlib.sha1(f"scan&#124;{source_ip}&#124;{destination_ip}&#124;{bucket}".encode("utf-8")).hexdigest()[:20].upper()</code> |
| L0082 | 计算并保存 &#96;confidence&#96;（confidence），供后续逻辑使用，当前位于函数 actions。 | <code>            confidence = min(0.99, 0.58 + len(row.ports) / max(self.unique_port_threshold * 5.0, 50.0))</code> |
| L0083 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 actions。 | <code>            result.append(</code> |
| L0084 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 actions。 | <code>                SecurityAction(</code> |
| L0085 | 计算并保存 &#96;action_id&#96;（actionid），供后续逻辑使用，当前位于函数 actions。 | <code>                    action_id=f"ACT-SCAN-{digest}",</code> |
| L0086 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 actions。 | <code>                    source_ip=source_ip,</code> |
| L0087 | 计算并保存 &#96;target_asset&#96;（targetasset），供后续逻辑使用，当前位于函数 actions。 | <code>                    target_asset=self.target_asset,</code> |
| L0088 | 计算并保存 &#96;action_type&#96;（actiontype），供后续逻辑使用，当前位于函数 actions。 | <code>                    action_type="PORT_SCAN",</code> |
| L0089 | 计算并保存 &#96;occurred_at&#96;（occurredat），供后续逻辑使用，当前位于函数 actions。 | <code>                    occurred_at=row.started_at,</code> |
| L0090 | 计算并保存 &#96;last_seen_at&#96;（lastseenat），供后续逻辑使用，当前位于函数 actions。 | <code>                    last_seen_at=row.last_seen_at,</code> |
| L0091 | 计算并保存 &#96;protocol&#96;（protocol），供后续逻辑使用，当前位于函数 actions。 | <code>                    protocol="TCP",</code> |
| L0092 | 计算并保存 &#96;sensor&#96;（sensor），供后续逻辑使用，当前位于函数 actions。 | <code>                    sensor="tshark_syn_scan",</code> |
| L0093 | 计算并保存 &#96;count&#96;（count），供后续逻辑使用，当前位于函数 actions。 | <code>                    count=row.packet_count,</code> |
| L0094 | 计算并保存 &#96;confidence&#96;（confidence），供后续逻辑使用，当前位于函数 actions。 | <code>                    confidence=confidence,</code> |
| L0095 | 计算并保存 &#96;severity&#96;（severity），供后续逻辑使用，当前位于函数 actions。 | <code>                    severity="high" if len(row.ports) &gt;= self.unique_port_threshold * 3 else "medium",</code> |
| L0096 | 计算并保存 &#96;evidence_refs&#96;（evidencerefs），供后续逻辑使用，当前位于函数 actions。 | <code>                    evidence_refs=[f"syn-window:{bucket}"],</code> |
| L0097 | 计算并保存 &#96;metadata&#96;（metadata），供后续逻辑使用，当前位于函数 actions。 | <code>                    metadata={</code> |
| L0098 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 actions。 | <code>                        "destination_ip": destination_ip,</code> |
| L0099 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 actions。 | <code>                        "unique_port_count": len(row.ports),</code> |
| L0100 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 actions。 | <code>                        "ports": sorted(row.ports)[:256],</code> |
| L0101 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 actions。 | <code>                    },</code> |
| L0102 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 actions。 | <code>                )</code> |
| L0103 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 actions。 | <code>            )</code> |
| L0104 | 结束当前函数并把结果返回给调用方，当前位于函数 actions。 | <code>        return result</code> |
| L0105 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0106 | 定义prune函数 &#96;prune&#96;，封装可复用业务逻辑。 | <code>    def prune(self, now: Optional[datetime] = None, retention_windows: int = 3) -&gt; None:</code> |
| L0107 | 计算并保存 &#96;now_utc&#96;（nowutc），供后续逻辑使用，当前位于函数 prune。 | <code>        now_utc = parse_timestamp(now or datetime.now(timezone.utc))</code> |
| L0108 | 计算并保存 &#96;cutoff&#96;（cutoff），供后续逻辑使用，当前位于函数 prune。 | <code>        cutoff = now_utc - self.window * max(2, int(retention_windows))</code> |
| L0109 | 计算并保存 &#96;_windows&#96;（windows），供后续逻辑使用，当前位于函数 prune。 | <code>        self._windows = {key: row for key, row in self._windows.items() if row.last_seen_at &gt;= cutoff}</code> |
| L0110 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0111 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0112 | 定义findtshark函数 &#96;find_tshark&#96;，封装可复用业务逻辑。 | <code>def find_tshark(explicit: str = "") -&gt; str:</code> |
| L0113 | 计算并保存 &#96;candidates&#96;（candidates），供后续逻辑使用，当前位于函数 find_tshark。 | <code>    candidates = [explicit, shutil.which("tshark") or "", r"C:\Program Files\Wireshark\tshark.exe"]</code> |
| L0114 | 遍历集合中的数据项并逐项处理，当前位于函数 find_tshark。 | <code>    for candidate in candidates:</code> |
| L0115 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 find_tshark。 | <code>        if candidate and Path(candidate).exists():</code> |
| L0116 | 结束当前函数并把结果返回给调用方，当前位于函数 find_tshark。 | <code>            return str(Path(candidate))</code> |
| L0117 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 find_tshark。 | <code>    raise FileNotFoundError("未找到 tshark，请先安装 Wireshark 并启用 Npcap")</code> |
| L0118 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0119 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0120 | 定义tsharkcommand函数 &#96;tshark_command&#96;，封装可复用业务逻辑。 | <code>def tshark_command(tshark: str, interface: str) -&gt; List[str]:</code> |
| L0121 | 结束当前函数并把结果返回给调用方，当前位于函数 tshark_command。 | <code>    return [</code> |
| L0122 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        tshark,</code> |
| L0123 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        "-l",</code> |
| L0124 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        "-n",</code> |
| L0125 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        "-i",</code> |
| L0126 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        str(interface),</code> |
| L0127 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        "-f",</code> |
| L0128 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        "tcp[tcpflags] &amp; (tcp-syn&#124;tcp-ack) == tcp-syn",</code> |
| L0129 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        "-Y",</code> |
| L0130 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        "tcp.flags.syn == 1 &amp;&amp; tcp.flags.ack == 0 &amp;&amp; ip.src &amp;&amp; ip.dst",</code> |
| L0131 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        "-T",</code> |
| L0132 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        "fields",</code> |
| L0133 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        "-E",</code> |
| L0134 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        "separator=\\t",</code> |
| L0135 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        "-e",</code> |
| L0136 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        "frame.time_epoch",</code> |
| L0137 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        "-e",</code> |
| L0138 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        "ip.src",</code> |
| L0139 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        "-e",</code> |
| L0140 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        "ip.dst",</code> |
| L0141 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        "-e",</code> |
| L0142 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 tshark_command。 | <code>        "tcp.dstport",</code> |
| L0143 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 tshark_command。 | <code>    ]</code> |
| L0144 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0145 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0146 | 定义解析packetline函数 &#96;parse_packet_line&#96;，封装可复用业务逻辑。 | <code>def parse_packet_line(line: str) -&gt; Optional[Tuple[datetime, str, str, int]]:</code> |
| L0147 | 计算并保存 &#96;parts&#96;（parts），供后续逻辑使用，当前位于函数 parse_packet_line。 | <code>    parts = line.strip().split("\t")</code> |
| L0148 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 parse_packet_line。 | <code>    if len(parts) != 4:</code> |
| L0149 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_packet_line。 | <code>        return None</code> |
| L0150 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 parse_packet_line。 | <code>    try:</code> |
| L0151 | 计算并保存 &#96;timestamp&#96;（timestamp），供后续逻辑使用，当前位于函数 parse_packet_line。 | <code>        timestamp = datetime.fromtimestamp(float(parts[0]), tz=timezone.utc)</code> |
| L0152 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_packet_line。 | <code>        return timestamp, parts[1].strip(), parts[2].strip(), int(parts[3])</code> |
| L0153 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 parse_packet_line。 | <code>    except (TypeError, ValueError):</code> |
| L0154 | 结束当前函数并把结果返回给调用方，当前位于函数 parse_packet_line。 | <code>        return None</code> |
| L0155 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0156 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0157 | 定义main函数 &#96;main&#96;，封装可复用业务逻辑。 | <code>def main() -&gt; None:</code> |
| L0158 | 计算并保存 &#96;parser&#96;（parser），供后续逻辑使用，当前位于函数 main。 | <code>    parser = argparse.ArgumentParser(description="Detect TCP SYN port scans and write normalized security actions")</code> |
| L0159 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--interface", required=True)</code> |
| L0160 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--tshark", default="")</code> |
| L0161 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--unique-port-threshold", type=int, default=10)</code> |
| L0162 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--window-seconds", type=int, default=60)</code> |
| L0163 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--flush-seconds", type=int, default=5)</code> |
| L0164 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--target-asset", default=socket.gethostname())</code> |
| L0165 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-host", default="127.0.0.1")</code> |
| L0166 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-port", type=int, default=3306)</code> |
| L0167 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-user", default="root")</code> |
| L0168 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-password", default="123456")</code> |
| L0169 | 声明一个命令行启动参数，允许部署时覆盖默认配置。 | <code>    parser.add_argument("--mysql-database", default="traffic_pipeline")</code> |
| L0170 | 计算并保存 &#96;args&#96;（args），供后续逻辑使用，当前位于函数 main。 | <code>    args = parser.parse_args()</code> |
| L0171 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0172 | 计算并保存 &#96;tshark&#96;（tshark），供后续逻辑使用，当前位于函数 main。 | <code>    tshark = find_tshark(args.tshark)</code> |
| L0173 | 计算并保存 &#96;command&#96;（command），供后续逻辑使用，当前位于函数 main。 | <code>    command = tshark_command(tshark, args.interface)</code> |
| L0174 | 计算并保存 &#96;detector&#96;（detector），供后续逻辑使用，当前位于函数 main。 | <code>    detector = PortScanDetector(args.unique_port_threshold, args.window_seconds, args.target_asset)</code> |
| L0175 | 计算并保存 &#96;store&#96;（store），供后续逻辑使用，当前位于函数 main。 | <code>    store = MySQLSituationStore(</code> |
| L0176 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        MySQLSettings(args.mysql_host, args.mysql_port, args.mysql_user, args.mysql_password, args.mysql_database)</code> |
| L0177 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 main。 | <code>    )</code> |
| L0178 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>    store.ensure_schema()</code> |
| L0179 | 记录运行状态或诊断信息，便于日志排障，当前位于函数 main。 | <code>    print(f"[{datetime.now().isoformat(timespec='seconds')}] port scan sensor: {' '.join(command)}", flush=True)</code> |
| L0180 | 计算并保存 &#96;process&#96;（process），供后续逻辑使用，当前位于函数 main。 | <code>    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")</code> |
| L0181 | 计算并保存 &#96;last_flush&#96;（lastflush），供后续逻辑使用，当前位于函数 main。 | <code>    last_flush = time.monotonic()</code> |
| L0182 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 main。 | <code>    try:</code> |
| L0183 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if process.stdout is None:</code> |
| L0184 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 main。 | <code>            raise RuntimeError("tshark stdout unavailable")</code> |
| L0185 | 遍历集合中的数据项并逐项处理，当前位于函数 main。 | <code>        for line in process.stdout:</code> |
| L0186 | 计算并保存 &#96;packet&#96;（packet），供后续逻辑使用，当前位于函数 main。 | <code>            packet = parse_packet_line(line)</code> |
| L0187 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if packet:</code> |
| L0188 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                detector.observe(*packet)</code> |
| L0189 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>            if time.monotonic() - last_flush &gt;= max(1, args.flush_seconds):</code> |
| L0190 | 计算并保存 &#96;actions&#96;（actions），供后续逻辑使用，当前位于函数 main。 | <code>                actions = detector.actions()</code> |
| L0191 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>                if actions:</code> |
| L0192 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                    store.upsert_actions(actions)</code> |
| L0193 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>                detector.prune()</code> |
| L0194 | 计算并保存 &#96;last_flush&#96;（lastflush），供后续逻辑使用，当前位于函数 main。 | <code>                last_flush = time.monotonic()</code> |
| L0195 | 计算并保存 &#96;rc&#96;（rc），供后续逻辑使用，当前位于函数 main。 | <code>        rc = process.wait(timeout=5)</code> |
| L0196 | 计算并保存 &#96;stderr&#96;（stderr），供后续逻辑使用，当前位于函数 main。 | <code>        stderr = process.stderr.read() if process.stderr else ""</code> |
| L0197 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 main。 | <code>        raise RuntimeError(f"tshark exited rc={rc}: {stderr[-1000:]}")</code> |
| L0198 | 无论成功或异常都执行资源清理，当前位于函数 main。 | <code>    finally:</code> |
| L0199 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 main。 | <code>        if process.poll() is None:</code> |
| L0200 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>            process.terminate()</code> |
| L0201 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 main。 | <code>        store.close()</code> |
| L0202 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0203 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0204 | 判断条件是否成立，成立时进入对应处理分支。 | <code>if __name__ == "__main__":</code> |
| L0205 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    main()</code> |
