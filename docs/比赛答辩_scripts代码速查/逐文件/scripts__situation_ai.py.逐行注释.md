# `scripts/situation_ai.py` 逐行注释

**脚本用途：** 调用外部 API 生成普通 AI 态势报告并校验结构化结果。

**源码行数：** 380　**函数/类数量：** 8

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import json&#96;。 | <code>import json</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;import os&#96;。 | <code>import os</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;import re&#96;。 | <code>import re</code> |
| L0006 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.request&#96;。 | <code>import urllib.request</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;import urllib.error&#96;。 | <code>import urllib.error</code> |
| L0008 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime&#96;。 | <code>from datetime import datetime</code> |
| L0009 | 导入后续逻辑所需的模块、类或函数：&#96;from pathlib import Path&#96;。 | <code>from pathlib import Path</code> |
| L0010 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, List, Optional, Tuple&#96;。 | <code>from typing import Any, Dict, List, Optional, Tuple</code> |
| L0011 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0012 | 导入后续逻辑所需的模块、类或函数：&#96;from llm_analyzer_daemon import format_rag_context, retrieve_rag_docs&#96;。 | <code>from llm_analyzer_daemon import format_rag_context, retrieve_rag_docs</code> |
| L0013 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0014 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0015 | 计算并保存 &#96;REPORT_FIELDS&#96;（报告FIELDS），供后续逻辑使用。 | <code>REPORT_FIELDS = {</code> |
| L0016 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "narrative",</code> |
| L0017 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "analysis",</code> |
| L0018 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "conclusion",</code> |
| L0019 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "likely_intent",</code> |
| L0020 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "protection_measures",</code> |
| L0021 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "improvement_suggestions",</code> |
| L0022 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>}</code> |
| L0023 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0024 | 计算并保存 &#96;DETAIL_TEXT_FIELDS&#96;（DETAILTEXTFIELDS），供后续逻辑使用。 | <code>DETAIL_TEXT_FIELDS = (</code> |
| L0025 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "executive_summary",</code> |
| L0026 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "timeline_analysis",</code> |
| L0027 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "technique_analysis",</code> |
| L0028 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "evidence_assessment",</code> |
| L0029 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "impact_assessment",</code> |
| L0030 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "compromise_assessment",</code> |
| L0031 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>)</code> |
| L0032 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0033 | 计算并保存 &#96;DETAIL_LIST_FIELDS&#96;（DETAIL列出FIELDS），供后续逻辑使用。 | <code>DETAIL_LIST_FIELDS = (</code> |
| L0034 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "investigation_steps",</code> |
| L0035 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "protection_measures",</code> |
| L0036 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "detection_improvements",</code> |
| L0037 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "improvement_suggestions",</code> |
| L0038 | 执行当前业务语句，完成数据构造、函数调用或状态更新。 | <code>    "evidence_limitations",</code> |
| L0039 | 结束前面开始的字典、列表、参数或表达式结构。 | <code>)</code> |
| L0040 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0041 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0042 | 定义actionlabel函数 &#96;action_label&#96;，封装可复用业务逻辑。 | <code>def action_label(action: Dict[str, Any]) -&gt; str:</code> |
| L0043 | 结束当前函数并把结果返回给调用方，当前位于函数 action_label。 | <code>    return str(action.get("action_label") or action.get("action_type") or "异常行为")</code> |
| L0044 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0045 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0046 | 定义fallback报告函数 &#96;fallback_report&#96;，封装可复用业务逻辑。 | <code>def fallback_report(situation: Dict[str, Any], reason: str = "") -&gt; Dict[str, Any]:</code> |
| L0047 | 计算并保存 &#96;actions&#96;（actions），供后续逻辑使用，当前位于函数 fallback_report。 | <code>    actions = list(situation.get("actions") or [])</code> |
| L0048 | 计算并保存 &#96;labels&#96;（labels），供后续逻辑使用，当前位于函数 fallback_report。 | <code>    labels = [action_label(row) for row in actions]</code> |
| L0049 | 计算并保存 &#96;source_ip&#96;（来源ip），供后续逻辑使用，当前位于函数 fallback_report。 | <code>    source_ip = str(situation.get("source_ip") or "未知来源")</code> |
| L0050 | 计算并保存 &#96;chain&#96;（chain），供后续逻辑使用，当前位于函数 fallback_report。 | <code>    chain = " → ".join(labels) if labels else "尚无完整动作证据"</code> |
| L0051 | 计算并保存 &#96;total&#96;（total），供后续逻辑使用，当前位于函数 fallback_report。 | <code>    total = int(situation.get("total_action_count") or sum(int(row.get("action_count") or row.get("count") or 1) for row in actions))</code> |
| L0052 | 计算并保存 &#96;risk_level&#96;（risklevel），供后续逻辑使用，当前位于函数 fallback_report。 | <code>    risk_level = str(situation.get("risk_level") or "medium")</code> |
| L0053 | 计算并保存 &#96;unique_labels&#96;（uniquelabels），供后续逻辑使用，当前位于函数 fallback_report。 | <code>    unique_labels = list(dict.fromkeys(labels))</code> |
| L0054 | 计算并保存 &#96;started_at&#96;（startedat），供后续逻辑使用，当前位于函数 fallback_report。 | <code>    started_at = str(situation.get("started_at") or "未知时间")</code> |
| L0055 | 计算并保存 &#96;last_action_at&#96;（lastactionat），供后续逻辑使用，当前位于函数 fallback_report。 | <code>    last_action_at = str(situation.get("last_action_at") or "未知时间")</code> |
| L0056 | 计算并保存 &#96;target_asset&#96;（targetasset），供后续逻辑使用，当前位于函数 fallback_report。 | <code>    target_asset = str(situation.get("target_asset") or "本机受监测资产")</code> |
| L0057 | 计算并保存 &#96;stage_summary&#96;（stagesummary），供后续逻辑使用，当前位于函数 fallback_report。 | <code>    stage_summary = "、".join(unique_labels) if unique_labels else "尚未形成可确认的多阶段动作"</code> |
| L0058 | 计算并保存 &#96;report&#96;（报告），供后续逻辑使用，当前位于函数 fallback_report。 | <code>    report = {</code> |
| L0059 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        "executive_summary": (</code> |
| L0060 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            f"来源 {source_ip} 在 {started_at} 至 {last_action_at} 的关联窗口内，围绕 {target_asset} "</code> |
| L0061 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            f"连续出现 {stage_summary} 等 {len(unique_labels)} 类安全动作，累计 {total} 次。"</code> |
| L0062 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            f"系统将其关联为风险等级 {risk_level} 的攻击者态势；现有证据能够证明攻击尝试持续发生，"</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "但不能单独证明目标已经被成功控制。"</code> |
| L0064 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fallback_report。 | <code>        ),</code> |
| L0065 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        "narrative": (</code> |
| L0066 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            f"来源 {source_ip} 在同一关联窗口内依次出现 {chain}，累计观测 {total} 次相关请求或连接。"</code> |
| L0067 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "动作从前期探测逐步过渡到凭据或应用层利用尝试，显示其行为并非孤立误触，而是具有连续性和目标导向。"</code> |
| L0068 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fallback_report。 | <code>        ),</code> |
| L0069 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        "timeline_analysis": (</code> |
| L0070 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            f"关联窗口起始于 {started_at}，最近动作发生于 {last_action_at}。系统按照事件时间、来源 IP、目标资产和动作类型"</code> |
| L0071 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "进行排序，并将同源同类的高频请求压缩为聚合动作，因此时间线展示的是阶段推进，而不是重复列出每一个数据包。"</code> |
| L0072 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fallback_report。 | <code>        ),</code> |
| L0073 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        "technique_analysis": (</code> |
| L0074 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            f"已识别的主要技术手法包括 {stage_summary}。这些动作覆盖 {len(unique_labels)} 种类型；"</code> |
| L0075 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "若其中同时包含侦察、认证攻击与漏洞利用，则说明攻击者可能正在执行由发现入口到验证可利用性的完整流程。"</code> |
| L0076 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fallback_report。 | <code>        ),</code> |
| L0077 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        "evidence_assessment": (</code> |
| L0078 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "该结论由来源一致性、时间接近性、目标相关性、动作类型多样性、POC 规则命中、Payload 模型评分及行为窗口统计共同支持。"</code> |
| L0079 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "原始请求、响应摘要、传感器来源和证据引用均已保留，可从证据序列逐项回溯。"</code> |
| L0080 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fallback_report。 | <code>        ),</code> |
| L0081 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        "impact_assessment": (</code> |
| L0082 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            f"当前主要影响是 {target_asset} 面临持续探测和漏洞验证压力，可能造成认证接口、应用接口或暴露服务被反复访问。"</code> |
| L0083 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "在没有登录成功、敏感数据返回、文件写入或命令执行等后续证据前，不扩大推断为数据泄露或主机失陷。"</code> |
| L0084 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fallback_report。 | <code>        ),</code> |
| L0085 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        "compromise_assessment": (</code> |
| L0086 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "暂无足以确认成功入侵的直接证据。当前结论应表述为连续攻击尝试或高风险疑似利用；"</code> |
| L0087 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "需要结合应用日志、认证日志、数据库审计、文件完整性和主机进程记录进一步确认是否存在成功利用。"</code> |
| L0088 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fallback_report。 | <code>        ),</code> |
| L0089 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        "analysis": (</code> |
| L0090 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "该结论由时间相关性、来源一致性、动作类型多样性和攻击阶段推进共同支持；重复请求已聚合，不按单包重复告警。"</code> |
| L0091 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "风险评分反映行为组合的危险程度，不等同于攻击成功率。"</code> |
| L0092 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fallback_report。 | <code>        ),</code> |
| L0093 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        "conclusion": (</code> |
| L0094 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            f"已形成包含 {len(unique_labels)} 类动作的连续攻击态势，当前风险等级为 {risk_level}。"</code> |
| L0095 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "建议立即复核关键日志并采取限流或临时阻断措施，同时保留证据以便后续溯源。"</code> |
| L0096 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fallback_report。 | <code>        ),</code> |
| L0097 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        "likely_intent": "探测可利用入口并尝试获得未授权访问权限",</code> |
| L0098 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        "investigation_steps": [</code> |
| L0099 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "按证据序列核对每个动作对应的原始请求、响应状态码、目标接口和传感器时间，排除测试流量或代理转发造成的误关联。",</code> |
| L0100 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "检索同一来源 IP、相邻网段及相同 User-Agent 在关联窗口前后至少一小时的访问记录，确认是否存在更早的侦察或后续横向动作。",</code> |
| L0101 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "核查认证日志中的成功登录、异常会话、密码重置和权限变更记录，并与攻击时间线进行交叉比对。",</code> |
| L0102 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "核查应用、数据库和操作系统日志中是否出现异常查询、敏感数据读取、文件写入、子进程启动或计划任务变更。",</code> |
| L0103 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fallback_report。 | <code>        ],</code> |
| L0104 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        "protection_measures": [</code> |
| L0105 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            f"临时限制或封禁来源 IP {source_ip}，并核查是否存在代理或误封风险。",</code> |
| L0106 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "检查被访问服务的认证日志、应用日志和数据库审计日志，确认是否已成功利用。",</code> |
| L0107 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "对暴露端口实施最小化开放、访问频率限制和多因素认证。",</code> |
| L0108 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "对命中的目标接口启用参数化查询、输入校验、输出编码和最小权限访问，并优先修复已确认的高危组件版本。",</code> |
| L0109 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "在处置期间持续监测相同来源、同网段和相似载荷，防止攻击者更换端口或路径后继续尝试。",</code> |
| L0110 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fallback_report。 | <code>        ],</code> |
| L0111 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        "detection_improvements": [</code> |
| L0112 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "将本次动作链中的稳定特征沉淀为回归样本，分别验证 Payload 模型、POC 规则和行为窗口是否给出一致结论。",</code> |
| L0113 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "为高频扫描、爆破和重复漏洞测试配置同源同类时间桶，减少重复告警，同时保留总次数、首末时间与代表性证据。",</code> |
| L0114 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "补充成功利用侧的响应证据，例如登录成功、敏感字段返回、文件落地或异常进程，以便区分尝试与失陷。",</code> |
| L0115 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fallback_report。 | <code>        ],</code> |
| L0116 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        "improvement_suggestions": [</code> |
| L0117 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "建立面向扫描、凭据攻击、漏洞利用和执行控制的分阶段处置剧本，并明确每个阶段的升级条件和责任人。",</code> |
| L0118 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "定期梳理互联网暴露面、停用无业务必要的端口与调试接口，对管理入口实施来源白名单或零信任访问控制。",</code> |
| L0119 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "持续观察该来源及关联网段后续活动，必要时扩大溯源范围，并将最终复核结果回写知识库和样本池。",</code> |
| L0120 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fallback_report。 | <code>        ],</code> |
| L0121 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        "evidence_limitations": [</code> |
| L0122 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "网络侧证据能够证明请求或连接行为发生，但不能仅凭攻击特征证明命令已经执行、数据已经泄露或权限已经提升。",</code> |
| L0123 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "来源 IP 可能对应代理、NAT、云主机或被控节点，封禁和归因前需要结合业务访问情况复核。",</code> |
| L0124 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>            "若抓包缺少加密流量明文、响应体或主机日志，部分攻击阶段只能判定为疑似，不能作成功利用结论。",</code> |
| L0125 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fallback_report。 | <code>        ],</code> |
| L0126 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        "confidence": round(float(situation.get("risk_score") or 0.0), 4),</code> |
| L0127 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        "generated_by": "deterministic_fallback",</code> |
| L0128 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        "generated_at": datetime.now().isoformat(timespec="seconds"),</code> |
| L0129 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        "rag_hits": 0,</code> |
| L0130 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 fallback_report。 | <code>    }</code> |
| L0131 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 fallback_report。 | <code>    if reason:</code> |
| L0132 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 fallback_report。 | <code>        report["fallback_reason"] = reason[:500]</code> |
| L0133 | 结束当前函数并把结果返回给调用方，当前位于函数 fallback_report。 | <code>    return report</code> |
| L0134 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0135 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0136 | 定义extractjson函数 &#96;extract_json&#96;，封装可复用业务逻辑。 | <code>def extract_json(text: str) -&gt; Dict[str, Any]:</code> |
| L0137 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 extract_json。 | <code>    raw = str(text or "").strip()</code> |
| L0138 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 extract_json。 | <code>    if raw.startswith("&#96;&#96;&#96;"):</code> |
| L0139 | 计算并保存 &#96;raw&#96;（raw），供后续逻辑使用，当前位于函数 extract_json。 | <code>        raw = re.sub(r"^&#96;&#96;&#96;(?:json)?\s*&#124;\s*&#96;&#96;&#96;$", "", raw, flags=re.I &#124; re.S)</code> |
| L0140 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 extract_json。 | <code>    try:</code> |
| L0141 | 计算并保存 &#96;value&#96;（value），供后续逻辑使用，当前位于函数 extract_json。 | <code>        value = json.loads(raw)</code> |
| L0142 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 extract_json。 | <code>    except json.JSONDecodeError:</code> |
| L0143 | 计算并保存 &#96;match&#96;（match），供后续逻辑使用，当前位于函数 extract_json。 | <code>        match = re.search(r"\{.*\}", raw, flags=re.S)</code> |
| L0144 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 extract_json。 | <code>        if not match:</code> |
| L0145 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 extract_json。 | <code>            raise ValueError("大模型未返回 JSON 对象")</code> |
| L0146 | 计算并保存 &#96;value&#96;（value），供后续逻辑使用，当前位于函数 extract_json。 | <code>        value = json.loads(match.group(0))</code> |
| L0147 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 extract_json。 | <code>    if not isinstance(value, dict):</code> |
| L0148 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 extract_json。 | <code>        raise ValueError("大模型返回值不是 JSON 对象")</code> |
| L0149 | 结束当前函数并把结果返回给调用方，当前位于函数 extract_json。 | <code>    return value</code> |
| L0150 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0151 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0152 | 定义校验报告函数 &#96;validate_report&#96;，封装可复用业务逻辑。 | <code>def validate_report(report: Dict[str, Any], *, allow_success_claims: bool = False) -&gt; Dict[str, Any]:</code> |
| L0153 | 计算并保存 &#96;missing&#96;（missing），供后续逻辑使用，当前位于函数 validate_report。 | <code>    missing = [field for field in REPORT_FIELDS if not report.get(field)]</code> |
| L0154 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 validate_report。 | <code>    if missing:</code> |
| L0155 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 validate_report。 | <code>        raise ValueError("大模型报告缺少字段: " + ", ".join(sorted(missing)))</code> |
| L0156 | 源码原注释：Older reports remain readable while newly generated reports provide a | <code>    # Older reports remain readable while newly generated reports provide a</code> |
| L0157 | 源码原注释：deeper, evidence-led structure for the situation workspace. | <code>    # deeper, evidence-led structure for the situation workspace.</code> |
| L0158 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 validate_report。 | <code>    report.setdefault("executive_summary", str(report.get("narrative") or ""))</code> |
| L0159 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 validate_report。 | <code>    report.setdefault("timeline_analysis", str(report.get("narrative") or ""))</code> |
| L0160 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 validate_report。 | <code>    report.setdefault("technique_analysis", str(report.get("analysis") or ""))</code> |
| L0161 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 validate_report。 | <code>    report.setdefault("evidence_assessment", str(report.get("analysis") or ""))</code> |
| L0162 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 validate_report。 | <code>    report.setdefault("impact_assessment", str(report.get("conclusion") or ""))</code> |
| L0163 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 validate_report。 | <code>    report.setdefault("compromise_assessment", str(report.get("conclusion") or ""))</code> |
| L0164 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 validate_report。 | <code>    report.setdefault("investigation_steps", [])</code> |
| L0165 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 validate_report。 | <code>    report.setdefault("detection_improvements", [])</code> |
| L0166 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 validate_report。 | <code>    report.setdefault("evidence_limitations", [])</code> |
| L0167 | 遍历集合中的数据项并逐项处理，当前位于函数 validate_report。 | <code>    for key in DETAIL_LIST_FIELDS:</code> |
| L0168 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 validate_report。 | <code>        if not isinstance(report[key], list):</code> |
| L0169 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 validate_report。 | <code>            report[key] = [str(report[key])]</code> |
| L0170 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 validate_report。 | <code>        report[key] = [str(item).strip() for item in report[key] if str(item).strip()]</code> |
| L0171 | 遍历集合中的数据项并逐项处理，当前位于函数 validate_report。 | <code>    for key in DETAIL_TEXT_FIELDS:</code> |
| L0172 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 validate_report。 | <code>        if isinstance(report[key], list):</code> |
| L0173 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 validate_report。 | <code>            report[key] = "；".join(str(item).strip(" ；") for item in report[key] if str(item).strip())</code> |
| L0174 | 处理前述条件均未命中的情况，当前位于函数 validate_report。 | <code>        else:</code> |
| L0175 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 validate_report。 | <code>            report[key] = str(report[key]).strip()</code> |
| L0176 | 遍历集合中的数据项并逐项处理，当前位于函数 validate_report。 | <code>    for key in ("narrative", "analysis", "conclusion", "likely_intent", *DETAIL_TEXT_FIELDS):</code> |
| L0177 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 validate_report。 | <code>        if not re.search(r"[\u4e00-\u9fff]", str(report[key])):</code> |
| L0178 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 validate_report。 | <code>            raise ValueError(f"大模型报告字段未使用中文: {key}")</code> |
| L0179 | 遍历集合中的数据项并逐项处理，当前位于函数 validate_report。 | <code>    for key in ("protection_measures", "improvement_suggestions"):</code> |
| L0180 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 validate_report。 | <code>        if not re.search(r"[\u4e00-\u9fff]", " ".join(report[key])):</code> |
| L0181 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 validate_report。 | <code>            raise ValueError(f"大模型报告字段未使用中文: {key}")</code> |
| L0182 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 validate_report。 | <code>    if not allow_success_claims:</code> |
| L0183 | 计算并保存 &#96;narrative_text&#96;（narrativetext），供后续逻辑使用，当前位于函数 validate_report。 | <code>        narrative_text = " ".join(</code> |
| L0184 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 validate_report。 | <code>            str(report[key])</code> |
| L0185 | 遍历集合中的数据项并逐项处理，当前位于函数 validate_report。 | <code>            for key in ("narrative", "analysis", "conclusion", "likely_intent", *DETAIL_TEXT_FIELDS)</code> |
| L0186 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 validate_report。 | <code>        )</code> |
| L0187 | 源码原注释：Keep legitimate negative wording such as “暂无成功入侵证据”, while | <code>        # Keep legitimate negative wording such as “暂无成功入侵证据”, while</code> |
| L0188 | 源码原注释：rejecting unsupported affirmative compromise claims. | <code>        # rejecting unsupported affirmative compromise claims.</code> |
| L0189 | 计算并保存 &#96;narrative_text&#96;（narrativetext），供后续逻辑使用，当前位于函数 validate_report。 | <code>        narrative_text = re.sub(</code> |
| L0190 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 validate_report。 | <code>            r"(?:未发现&#124;未观察到&#124;未能&#124;不能&#124;无法&#124;不足以&#124;不代表&#124;不等于&#124;没有&#124;尚未&#124;暂无&#124;无&#124;缺乏)"</code> |
| L0191 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 validate_report。 | <code>            r"[^。；，]{0,32}(?:成功&#124;失陷)",</code> |
| L0192 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 validate_report。 | <code>            "",</code> |
| L0193 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 validate_report。 | <code>            narrative_text,</code> |
| L0194 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 validate_report。 | <code>        )</code> |
| L0195 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 validate_report。 | <code>        if re.search(r"成功(?:地&#124;的)?(?:执行&#124;利用&#124;入侵&#124;获取&#124;写入&#124;绕过)&#124;攻击成功", narrative_text):</code> |
| L0196 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 validate_report。 | <code>            raise ValueError("大模型报告包含未经证据确认的攻击成功表述")</code> |
| L0197 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 validate_report。 | <code>    report["confidence"] = max(0.0, min(1.0, float(report.get("confidence") or 0.0)))</code> |
| L0198 | 结束当前函数并把结果返回给调用方，当前位于函数 validate_report。 | <code>    return report</code> |
| L0199 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0200 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0201 | 定义构建prompt函数 &#96;build_prompt&#96;，封装可复用业务逻辑。 | <code>def build_prompt(situation: Dict[str, Any], rag_context: str) -&gt; str:</code> |
| L0202 | 计算并保存 &#96;evidence&#96;（evidence），供后续逻辑使用，当前位于函数 build_prompt。 | <code>    evidence = {</code> |
| L0203 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>        "situation_id": situation.get("situation_id"),</code> |
| L0204 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>        "source_ip": situation.get("source_ip"),</code> |
| L0205 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>        "target_asset": situation.get("target_asset"),</code> |
| L0206 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>        "started_at": str(situation.get("started_at")),</code> |
| L0207 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>        "last_action_at": str(situation.get("last_action_at")),</code> |
| L0208 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>        "risk_score": situation.get("risk_score"),</code> |
| L0209 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>        "risk_level": situation.get("risk_level"),</code> |
| L0210 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>        "actions": [</code> |
| L0211 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>            {</code> |
| L0212 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>                "sequence": row.get("sequence_no") or row.get("sequence"),</code> |
| L0213 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>                "action_type": row.get("action_type"),</code> |
| L0214 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>                "stage": row.get("stage"),</code> |
| L0215 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>                "occurred_at": str(row.get("occurred_at")),</code> |
| L0216 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>                "last_seen_at": str(row.get("last_seen_at")),</code> |
| L0217 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>                "count": row.get("action_count") or row.get("count"),</code> |
| L0218 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>                "confidence": row.get("confidence"),</code> |
| L0219 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>                "target_interface": row.get("target_interface"),</code> |
| L0220 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>                "metadata": row.get("metadata") or {},</code> |
| L0221 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_prompt。 | <code>            }</code> |
| L0222 | 遍历集合中的数据项并逐项处理，当前位于函数 build_prompt。 | <code>            for row in situation.get("actions") or []</code> |
| L0223 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_prompt。 | <code>        ],</code> |
| L0224 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_prompt。 | <code>    }</code> |
| L0225 | 结束当前函数并把结果返回给调用方，当前位于函数 build_prompt。 | <code>    return f"""你是网络安全态势研判专家。仅依据给定证据分析同一来源 IP 的连续动作，不得补造不存在的攻击结果。</code> |
| L0226 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>区分“尝试攻击”和“已成功入侵”；没有成功证据时必须写成尝试或疑似。</code> |
| L0227 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>知识库内容只用于解释和处置参考，不能覆盖事件证据。</code> |
| L0228 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>所有自然语言内容必须使用简体中文，不得输出英文完整句子；SQL、XSS、IP、CSP 等必要技术缩写可以保留。</code> |
| L0229 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0230 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>事件证据：</code> |
| L0231 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>{json.dumps(evidence, ensure_ascii=False, default=str)}</code> |
| L0232 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0233 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>检索知识：</code> |
| L0234 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>{rag_context or '无匹配知识'}</code> |
| L0235 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0236 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>请生成一份可以直接交给安全运营人员处置的详细报告。避免空泛套话，每个判断都应指出对应的证据或明确说明证据不足。</code> |
| L0237 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>正文建议 1200 至 2200 个汉字，数组字段每项应为完整、可执行的句子。</code> |
| L0238 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0239 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>只返回 JSON，字段必须为：</code> |
| L0240 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>executive_summary（执行摘要，至少120字）、narrative（按时间顺序完整叙述）、timeline_analysis（时间线与阶段推进分析）、</code> |
| L0241 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>technique_analysis（攻击技术与可能链路分析）、evidence_assessment（证据来源、强度与相互印证）、</code> |
| L0242 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>impact_assessment（可能影响，区分已知事实与风险推测）、compromise_assessment（是否失陷及判断依据）、</code> |
| L0243 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>analysis（综合分析）、conclusion（明确结论）、likely_intent（可能意图）、</code> |
| L0244 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>investigation_steps（4至8项调查步骤）、protection_measures（5至8项即时防护措施）、</code> |
| L0245 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>detection_improvements（3至6项检测优化）、improvement_suggestions（3至6项长期改进）、</code> |
| L0246 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>evidence_limitations（2至5项证据边界）、confidence（0到1）。</code> |
| L0247 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>再次强调：所有自然语言字段必须用简体中文填写；没有直接证据时必须明确写“暂无成功入侵证据”。</code> |
| L0248 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_prompt。 | <code>"""</code> |
| L0249 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0250 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0251 | 定义callollama函数 &#96;call_ollama&#96;，封装可复用业务逻辑。 | <code>def call_ollama(ollama_url: str, model: str, prompt: str, timeout_sec: int = 120) -&gt; Dict[str, Any]:</code> |
| L0252 | 计算并保存 &#96;endpoint&#96;（endpoint），供后续逻辑使用，当前位于函数 call_ollama。 | <code>    endpoint = str(ollama_url or "http://127.0.0.1:11434").rstrip("/") + "/api/generate"</code> |
| L0253 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 call_ollama。 | <code>    payload = {</code> |
| L0254 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama。 | <code>        "model": model,</code> |
| L0255 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama。 | <code>        "prompt": prompt,</code> |
| L0256 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama。 | <code>        "stream": False,</code> |
| L0257 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama。 | <code>        "keep_alive": os.environ.get("OLLAMA_KEEP_ALIVE", "5m"),</code> |
| L0258 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama。 | <code>        "format": "json",</code> |
| L0259 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama。 | <code>        "options": {"temperature": 0.15, "num_ctx": 6144, "num_predict": 2000},</code> |
| L0260 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_ollama。 | <code>    }</code> |
| L0261 | 计算并保存 &#96;request&#96;（request），供后续逻辑使用，当前位于函数 call_ollama。 | <code>    request = urllib.request.Request(</code> |
| L0262 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_ollama。 | <code>        endpoint,</code> |
| L0263 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 call_ollama。 | <code>        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),</code> |
| L0264 | 计算并保存 &#96;headers&#96;（headers），供后续逻辑使用，当前位于函数 call_ollama。 | <code>        headers={"Content-Type": "application/json"},</code> |
| L0265 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 call_ollama。 | <code>        method="POST",</code> |
| L0266 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_ollama。 | <code>    )</code> |
| L0267 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 call_ollama。 | <code>    with urllib.request.urlopen(request, timeout=max(10, int(timeout_sec))) as response:</code> |
| L0268 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 call_ollama。 | <code>        result = json.loads(response.read().decode("utf-8"))</code> |
| L0269 | 结束当前函数并把结果返回给调用方，当前位于函数 call_ollama。 | <code>    return extract_json(str(result.get("response") or ""))</code> |
| L0270 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0271 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0272 | 定义callbailian函数 &#96;call_bailian&#96;，封装可复用业务逻辑。 | <code>def call_bailian(api_config: Dict[str, Any], model: str, prompt: str, timeout_sec: int = 120) -&gt; Dict[str, Any]:</code> |
| L0273 | 调用外部 HTTP/大模型 API，并等待远端返回结果，当前位于函数 call_bailian。 | <code>    """Generate a structured situation report through Bailian's OpenAI-compatible API."""</code> |
| L0274 | 计算并保存 &#96;api_key&#96;（接口key），供后续逻辑使用，当前位于函数 call_bailian。 | <code>    api_key = str(api_config.get("api_key") or "").strip()</code> |
| L0275 | 计算并保存 &#96;base_url&#96;（baseurl），供后续逻辑使用，当前位于函数 call_bailian。 | <code>    base_url = str(api_config.get("base_url") or "").strip().rstrip("/")</code> |
| L0276 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 call_bailian。 | <code>    if not api_key or not base_url:</code> |
| L0277 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 call_bailian。 | <code>        raise RuntimeError("百炼 API 配置不完整")</code> |
| L0278 | 计算并保存 &#96;payload&#96;（payload），供后续逻辑使用，当前位于函数 call_bailian。 | <code>    payload = {</code> |
| L0279 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_bailian。 | <code>        "model": model,</code> |
| L0280 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_bailian。 | <code>        "messages": [</code> |
| L0281 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_bailian。 | <code>            {"role": "system", "content": "你是严谨的网络安全态势研判专家，只输出合法 JSON。"},</code> |
| L0282 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_bailian。 | <code>            {"role": "user", "content": prompt},</code> |
| L0283 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_bailian。 | <code>        ],</code> |
| L0284 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_bailian。 | <code>        "temperature": 0.15,</code> |
| L0285 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_bailian。 | <code>        "response_format": {"type": "json_object"},</code> |
| L0286 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 call_bailian。 | <code>        "stream": False,</code> |
| L0287 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_bailian。 | <code>    }</code> |
| L0288 | 计算并保存 &#96;request&#96;（request），供后续逻辑使用，当前位于函数 call_bailian。 | <code>    request = urllib.request.Request(</code> |
| L0289 | 调用外部 HTTP/大模型 API，并等待远端返回结果，当前位于函数 call_bailian。 | <code>        f"{base_url}/chat/completions",</code> |
| L0290 | 计算并保存 &#96;data&#96;（data），供后续逻辑使用，当前位于函数 call_bailian。 | <code>        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),</code> |
| L0291 | 计算并保存 &#96;headers&#96;（headers），供后续逻辑使用，当前位于函数 call_bailian。 | <code>        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},</code> |
| L0292 | 计算并保存 &#96;method&#96;（method），供后续逻辑使用，当前位于函数 call_bailian。 | <code>        method="POST",</code> |
| L0293 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 call_bailian。 | <code>    )</code> |
| L0294 | 计算并保存 &#96;request_timeout&#96;（requesttimeout），供后续逻辑使用，当前位于函数 call_bailian。 | <code>    request_timeout = max(10, int(api_config.get("timeout_seconds") or timeout_sec))</code> |
| L0295 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 call_bailian。 | <code>    try:</code> |
| L0296 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 call_bailian。 | <code>        with urllib.request.urlopen(request, timeout=request_timeout) as response:</code> |
| L0297 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 call_bailian。 | <code>            result = json.loads(response.read().decode("utf-8"))</code> |
| L0298 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 call_bailian。 | <code>    except urllib.error.HTTPError as exc:</code> |
| L0299 | 计算并保存 &#96;detail&#96;（detail），供后续逻辑使用，当前位于函数 call_bailian。 | <code>        detail = exc.read().decode("utf-8", "replace")[:500]</code> |
| L0300 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 call_bailian。 | <code>        raise RuntimeError(f"百炼 HTTP {exc.code}: {detail}") from exc</code> |
| L0301 | 计算并保存 &#96;content&#96;（content），供后续逻辑使用，当前位于函数 call_bailian。 | <code>    content = str((((result.get("choices") or [{}])[0].get("message") or {}).get("content") or ""))</code> |
| L0302 | 结束当前函数并把结果返回给调用方，当前位于函数 call_bailian。 | <code>    return extract_json(content)</code> |
| L0303 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0304 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0305 | 定义analyze态势函数 &#96;analyze_situation&#96;，封装可复用业务逻辑。 | <code>def analyze_situation(</code> |
| L0306 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>    situation: Dict[str, Any],</code> |
| L0307 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>    *,</code> |
| L0308 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>    ollama_url: str,</code> |
| L0309 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>    model: str,</code> |
| L0310 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>    rag_db_path: Path,</code> |
| L0311 | 计算并保存 &#96;rag_mysql_conf&#96;（ragmysqlconf），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>    rag_mysql_conf: Optional[Dict[str, Any]] = None,</code> |
| L0312 | 计算并保存 &#96;rag_data_dir&#96;（ragdatadir），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>    rag_data_dir: Optional[Path] = None,</code> |
| L0313 | 计算并保存 &#96;rag_api_config&#96;（rag接口配置），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>    rag_api_config: Optional[Path] = None,</code> |
| L0314 | 计算并保存 &#96;rag_enabled&#96;（ragenabled），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>    rag_enabled: bool = True,</code> |
| L0315 | 计算并保存 &#96;rag_top_k&#96;（ragtopk），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>    rag_top_k: int = 4,</code> |
| L0316 | 计算并保存 &#96;timeout_sec&#96;（timeoutsec），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>    timeout_sec: int = 120,</code> |
| L0317 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 analyze_situation。 | <code>) -&gt; Tuple[Dict[str, Any], str]:</code> |
| L0318 | 计算并保存 &#96;query&#96;（query），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>    query = " ".join(</code> |
| L0319 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>        [str(situation.get("source_ip") or "")]</code> |
| L0320 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>        + [action_label(row) + " " + str(row.get("action_type") or "") for row in situation.get("actions") or []]</code> |
| L0321 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 analyze_situation。 | <code>    )</code> |
| L0322 | 计算并保存 &#96;rag_rows&#96;（rag数据库记录），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>    rag_rows: List[Dict[str, Any]] = []</code> |
| L0323 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 analyze_situation。 | <code>    try:</code> |
| L0324 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 analyze_situation。 | <code>        if rag_enabled and rag_mysql_conf and rag_data_dir and rag_api_config:</code> |
| L0325 | 导入后续逻辑所需的模块、类或函数：&#96;from rag_service import hybrid_search, list_kbs, load_api_config, mysql_connect&#96;。 | <code>            from rag_service import hybrid_search, list_kbs, load_api_config, mysql_connect</code> |
| L0326 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0327 | 通过上下文管理器安全打开资源，并在结束后自动释放，当前位于函数 analyze_situation。 | <code>            with mysql_connect(rag_mysql_conf, autocommit=False) as conn:</code> |
| L0328 | 计算并保存 &#96;kbs&#96;（kbs），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>                kbs = list_kbs(conn, include_disabled=False)</code> |
| L0329 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 analyze_situation。 | <code>                if kbs:</code> |
| L0330 | 计算并保存 &#96;result&#96;（结果），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>                    result = hybrid_search(</code> |
| L0331 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>                        conn,</code> |
| L0332 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>                        rag_data_dir,</code> |
| L0333 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>                        load_api_config(rag_api_config),</code> |
| L0334 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>                        int(kbs[0]["id"]),</code> |
| L0335 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>                        query,</code> |
| L0336 | 计算并保存 &#96;username&#96;（username），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>                        username="situation-ai",</code> |
| L0337 | 计算并保存 &#96;save_test&#96;（保存test），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>                        save_test=False,</code> |
| L0338 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 analyze_situation。 | <code>                    )</code> |
| L0339 | 计算并保存 &#96;rag_rows&#96;（rag数据库记录），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>                    rag_rows = [</code> |
| L0340 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>                        {</code> |
| L0341 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>                            "doc_id": f"DOC-{item.get('document_id')}-CHUNK-{item.get('chunk_id')}",</code> |
| L0342 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>                            "title": item.get("title_path") or item.get("document_name") or "知识片段",</code> |
| L0343 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>                            "evidence": item.get("content") or "",</code> |
| L0344 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>                            "source": item.get("document_name") or "advanced-rag",</code> |
| L0345 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 analyze_situation。 | <code>                        }</code> |
| L0346 | 遍历集合中的数据项并逐项处理，当前位于函数 analyze_situation。 | <code>                        for item in (result.get("items") or [])[: max(1, rag_top_k)]</code> |
| L0347 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 analyze_situation。 | <code>                    ]</code> |
| L0348 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 analyze_situation。 | <code>        if rag_enabled and not rag_rows and rag_db_path.exists():</code> |
| L0349 | 计算并保存 &#96;rag_rows&#96;（rag数据库记录），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>            rag_rows = retrieve_rag_docs(rag_db_path, query_text=query, top_k=max(1, rag_top_k))</code> |
| L0350 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 analyze_situation。 | <code>    except Exception:</code> |
| L0351 | 计算并保存 &#96;rag_rows&#96;（rag数据库记录），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>        rag_rows = []</code> |
| L0352 | 计算并保存 &#96;rag_context&#96;（ragcontext），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>    rag_context = format_rag_context(rag_rows, max_chars=5000) if rag_rows else ""</code> |
| L0353 | 开始受保护操作，异常会交给后续分支处理，当前位于函数 analyze_situation。 | <code>    try:</code> |
| L0354 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 analyze_situation。 | <code>        if not rag_api_config:</code> |
| L0355 | 主动抛出异常，阻止无效或危险状态继续执行，当前位于函数 analyze_situation。 | <code>            raise RuntimeError("未配置态势报告外部 API")</code> |
| L0356 | 导入后续逻辑所需的模块、类或函数：&#96;from rag_service import load_api_config&#96;。 | <code>        from rag_service import load_api_config</code> |
| L0357 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0358 | 计算并保存 &#96;api_config&#96;（接口配置），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>        api_config = load_api_config(rag_api_config)</code> |
| L0359 | 计算并保存 &#96;config_payload&#96;（配置payload），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>        config_payload = json.loads(rag_api_config.read_text(encoding="utf-8-sig")) if rag_api_config.exists() else {}</code> |
| L0360 | 计算并保存 &#96;cloud_model&#96;（cloud模型），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>        cloud_model = str(</code> |
| L0361 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>            config_payload.get("situation_report_model")</code> |
| L0362 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>            or config_payload.get("report_model")</code> |
| L0363 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>            or "qwen-plus"</code> |
| L0364 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 analyze_situation。 | <code>        ).strip()</code> |
| L0365 | 计算并保存 &#96;report&#96;（报告），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>        report = validate_report(</code> |
| L0366 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>            call_bailian(api_config, cloud_model, build_prompt(situation, rag_context), timeout_sec),</code> |
| L0367 | 计算并保存 &#96;allow_success_claims&#96;（allowsuccessclaims），供后续逻辑使用，当前位于函数 analyze_situation。 | <code>            allow_success_claims=False,</code> |
| L0368 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 analyze_situation。 | <code>        )</code> |
| L0369 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>        report.update(</code> |
| L0370 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>            {</code> |
| L0371 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>                "generated_by": "bailian_rag" if rag_enabled and rag_rows else "bailian",</code> |
| L0372 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>                "model_name": cloud_model,</code> |
| L0373 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>                "generated_at": datetime.now().isoformat(timespec="seconds"),</code> |
| L0374 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>                "rag_hits": len(rag_rows),</code> |
| L0375 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 analyze_situation。 | <code>                "rag_refs": [str(row.get("title") or row.get("doc_id") or "") for row in rag_rows],</code> |
| L0376 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 analyze_situation。 | <code>            }</code> |
| L0377 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 analyze_situation。 | <code>        )</code> |
| L0378 | 结束当前函数并把结果返回给调用方，当前位于函数 analyze_situation。 | <code>        return report, "complete"</code> |
| L0379 | 捕获异常，避免单次错误导致整个服务退出，当前位于函数 analyze_situation。 | <code>    except Exception as exc:</code> |
| L0380 | 结束当前函数并把结果返回给调用方，当前位于函数 analyze_situation。 | <code>        return fallback_report(situation, f"{type(exc).__name__}: {exc}"), "fallback"</code> |
