# `scripts/situation_cluster.py` 逐行注释

**脚本用途：** 跨 IP 聚类与多代理协同态势识别。

**源码行数：** 199　**函数/类数量：** 6

| 行号 | 中文说明 | 原始源码 |
|---:|---|---|
| L0001 | 导入后续逻辑所需的模块、类或函数：&#96;from __future__ import annotations&#96;。 | <code>from __future__ import annotations</code> |
| L0002 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0003 | 导入后续逻辑所需的模块、类或函数：&#96;import hashlib&#96;。 | <code>import hashlib</code> |
| L0004 | 导入后续逻辑所需的模块、类或函数：&#96;from datetime import datetime, timedelta, timezone&#96;。 | <code>from datetime import datetime, timedelta, timezone</code> |
| L0005 | 导入后续逻辑所需的模块、类或函数：&#96;from typing import Any, Dict, Iterable, List&#96;。 | <code>from typing import Any, Dict, Iterable, List</code> |
| L0006 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0007 | 导入后续逻辑所需的模块、类或函数：&#96;from situation_core import ACTION_CATALOG, STAGE_LABELS, STAGE_ORDER, parse_timestamp, risk_level&#96;。 | <code>from situation_core import ACTION_CATALOG, STAGE_LABELS, STAGE_ORDER, parse_timestamp, risk_level</code> |
| L0008 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0009 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0010 | 定义time函数 &#96;_time&#96;，封装可复用业务逻辑。 | <code>def _time(value: Any) -&gt; datetime:</code> |
| L0011 | 计算并保存 &#96;parsed&#96;（parsed），供后续逻辑使用，当前位于函数 _time。 | <code>    parsed = parse_timestamp(value)</code> |
| L0012 | 结束当前函数并把结果返回给调用方，当前位于函数 _time。 | <code>    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)</code> |
| L0013 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0014 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0015 | 定义actiontype函数 &#96;_action_type&#96;，封装可复用业务逻辑。 | <code>def _action_type(action: Dict[str, Any]) -&gt; str:</code> |
| L0016 | 计算并保存 &#96;value&#96;（value），供后续逻辑使用，当前位于函数 _action_type。 | <code>    value = str(action.get("action_type") or "UNKNOWN").strip().upper()</code> |
| L0017 | 结束当前函数并把结果返回给调用方，当前位于函数 _action_type。 | <code>    return value if value in ACTION_CATALOG else "UNKNOWN"</code> |
| L0018 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0019 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0020 | 定义构建报告函数 &#96;_build_report&#96;，封装可复用业务逻辑。 | <code>def _build_report(cluster: Dict[str, Any]) -&gt; Dict[str, Any]:</code> |
| L0021 | 计算并保存 &#96;ips&#96;（ips），供后续逻辑使用，当前位于函数 _build_report。 | <code>    ips = cluster["source_ips"]</code> |
| L0022 | 计算并保存 &#96;labels&#96;（labels），供后续逻辑使用，当前位于函数 _build_report。 | <code>    labels = cluster["action_labels"]</code> |
| L0023 | 计算并保存 &#96;duration&#96;（duration），供后续逻辑使用，当前位于函数 _build_report。 | <code>    duration = max(1, int(cluster["duration_seconds"] / 60))</code> |
| L0024 | 计算并保存 &#96;ip_sample&#96;（ipsample），供后续逻辑使用，当前位于函数 _build_report。 | <code>    ip_sample = "、".join(ips[:5]) + (f" 等 {len(ips)} 个地址" if len(ips) &gt; 5 else "")</code> |
| L0025 | 计算并保存 &#96;action_chain&#96;（actionchain），供后续逻辑使用，当前位于函数 _build_report。 | <code>    action_chain = " → ".join(labels)</code> |
| L0026 | 计算并保存 &#96;proxy_note&#96;（proxynote），供后续逻辑使用，当前位于函数 _build_report。 | <code>    proxy_note = "来源地址高频切换，具有代理池或分布式协同行为特征" if cluster["proxy_rotation_suspected"] else "多个来源在相近时间针对同一资产执行相似动作"</code> |
| L0027 | 结束当前函数并把结果返回给调用方，当前位于函数 _build_report。 | <code>    return {</code> |
| L0028 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>        "executive_summary": (</code> |
| L0029 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>            f"系统在 {duration} 分钟内关联到 {len(ips)} 个来源 IP，针对 {cluster['target_asset']} "</code> |
| L0030 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>            f"累计实施 {cluster['total_action_count']} 次、{cluster['distinct_action_types']} 类安全动作。{proxy_note}。"</code> |
| L0031 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _build_report。 | <code>        ),</code> |
| L0032 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>        "likely_intent": "通过轮换代理隐藏真实来源并推进侦察、凭据攻击或漏洞利用",</code> |
| L0033 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>        "narrative": f"主要来源为 {ip_sample}。融合后的动作链为：{action_chain}。所有动作均按原始时间戳重新排序，未将来源 IP 相同作为关联前提。",</code> |
| L0034 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>        "timeline_analysis": f"聚合窗口从 {cluster['started_at']} 至 {cluster['last_action_at']}，持续约 {duration} 分钟；同一目标和紧密时间关系支持对代理轮换假设进行进一步调查。",</code> |
| L0035 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>        "technique_analysis": f"检测到 {cluster['distinct_action_types']} 类技术动作：{'、'.join(labels)}。动作跨越 {len(cluster['stages'])} 个攻击阶段，风险由动作置信度、阶段深度、频次和来源多样性共同计算。",</code> |
| L0036 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>        "evidence_assessment": f"证据来自 {cluster['sensor_count']} 类传感器、{cluster['situation_count']} 条单 IP 态势和 {len(cluster['actions'])} 条归一化动作；原始来源与证据引用均保留，可回溯复核。",</code> |
| L0037 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>        "impact_assessment": "若后续出现执行控制、敏感数据访问或持久化证据，应立即将事件升级为疑似失陷；当前应优先限制恶意来源并核查目标服务日志。",</code> |
| L0038 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>        "compromise_assessment": "当前证据能够证明持续攻击活动，但不能仅凭网络请求断言主机已经失陷。",</code> |
| L0039 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>        "conclusion": f"该集群符合多来源协同或代理池轮换攻击特征，综合风险为{cluster['risk_level']}，建议按一个攻击行动统一处置，同时保留各 IP 的独立封禁与溯源记录。",</code> |
| L0040 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>        "investigation_steps": [</code> |
| L0041 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>            "按时间轴核对 Web、SSH、WAF 与系统登录日志，确认多个来源是否共享账户、载荷或指纹。",</code> |
| L0042 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>            "比对 User-Agent、TLS 指纹、请求路径、Payload 模板与失败响应，判断是否来自同一工具链。",</code> |
| L0043 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>            "检查目标接口后续是否出现成功登录、命令执行、异常文件写入或外联行为。",</code> |
| L0044 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _build_report。 | <code>        ],</code> |
| L0045 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>        "protection_measures": [</code> |
| L0046 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>            "对高置信恶意来源实施入站与出站双向封禁，并保留可回滚规则。",</code> |
| L0047 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>            "对被集中探测的接口启用速率限制、强认证与最小暴露策略。",</code> |
| L0048 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>            "若来源规模持续扩大，优先在上游网关或云防护侧按 ASN、网段和行为特征联动阻断。",</code> |
| L0049 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _build_report。 | <code>        ],</code> |
| L0050 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>        "detection_improvements": [</code> |
| L0051 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>            "将时间窗、目标资产、载荷相似度和客户端指纹纳入跨 IP 关联评分。",</code> |
| L0052 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>            "为代理轮换集群建立独立阈值，避免仅依赖单 IP 请求频率。",</code> |
| L0053 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _build_report。 | <code>        ],</code> |
| L0054 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>        "improvement_suggestions": [</code> |
| L0055 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>            "持续沉淀已确认代理集群样本，用于回归评估和阈值校准。",</code> |
| L0056 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>            "接入反向代理真实来源头校验，防止伪造 X-Forwarded-For 干扰关联结果。",</code> |
| L0057 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _build_report。 | <code>        ],</code> |
| L0058 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>        "evidence_limitations": [</code> |
| L0059 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>            "多个 IP 的时间相关性不能单独证明其属于同一攻击者。",</code> |
| L0060 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>            "NAT、共享出口和合法扫描服务可能造成多来源或多用户混淆，需结合指纹与业务日志复核。",</code> |
| L0061 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _build_report。 | <code>        ],</code> |
| L0062 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>        "generated_by": "cross_ip_correlation_engine",</code> |
| L0063 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _build_report。 | <code>        "rag_hits": 0,</code> |
| L0064 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _build_report。 | <code>    }</code> |
| L0065 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0066 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0067 | 定义finishcluster函数 &#96;_finish_cluster&#96;，封装可复用业务逻辑。 | <code>def _finish_cluster(rows: List[Dict[str, Any]], window_minutes: int) -&gt; Dict[str, Any] &#124; None:</code> |
| L0068 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _finish_cluster。 | <code>    if not rows:</code> |
| L0069 | 结束当前函数并把结果返回给调用方，当前位于函数 _finish_cluster。 | <code>        return None</code> |
| L0070 | 计算并保存 &#96;actions&#96;（actions），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>    actions: List[Dict[str, Any]] = []</code> |
| L0071 | 计算并保存 &#96;source_ips&#96;（来源ips），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>    source_ips = sorted({str(row.get("source_ip") or "").strip() for row in rows if row.get("source_ip")})</code> |
| L0072 | 遍历集合中的数据项并逐项处理，当前位于函数 _finish_cluster。 | <code>    for row in rows:</code> |
| L0073 | 遍历集合中的数据项并逐项处理，当前位于函数 _finish_cluster。 | <code>        for action in row.get("actions") or []:</code> |
| L0074 | 计算并保存 &#96;item&#96;（item），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>            item = dict(action)</code> |
| L0075 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>            item["source_ip"] = str(item.get("source_ip") or row.get("source_ip") or "")</code> |
| L0076 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>            item["situation_id"] = str(row.get("situation_id") or "")</code> |
| L0077 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 _finish_cluster。 | <code>            actions.append(item)</code> |
| L0078 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>    actions.sort(key=lambda item: (_time(item.get("occurred_at")), str(item.get("action_id") or "")))</code> |
| L0079 | 遍历集合中的数据项并逐项处理，当前位于函数 _finish_cluster。 | <code>    for index, action in enumerate(actions, start=1):</code> |
| L0080 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        action["sequence_no"] = index</code> |
| L0081 | 计算并保存 &#96;types&#96;（types），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>    types = []</code> |
| L0082 | 遍历集合中的数据项并逐项处理，当前位于函数 _finish_cluster。 | <code>    for action in actions:</code> |
| L0083 | 计算并保存 &#96;kind&#96;（kind），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>        kind = _action_type(action)</code> |
| L0084 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _finish_cluster。 | <code>        if kind != "IP_BLOCKED" and kind not in types:</code> |
| L0085 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 _finish_cluster。 | <code>            types.append(kind)</code> |
| L0086 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 _finish_cluster。 | <code>    if len(source_ips) &lt; 2 or len(types) &lt; 3:</code> |
| L0087 | 结束当前函数并把结果返回给调用方，当前位于函数 _finish_cluster。 | <code>        return None</code> |
| L0088 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0089 | 计算并保存 &#96;started&#96;（started），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>    started = min(_time(row.get("started_at")) for row in rows)</code> |
| L0090 | 计算并保存 &#96;ended&#96;（ended），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>    ended = max(_time(row.get("last_action_at")) for row in rows)</code> |
| L0091 | 计算并保存 &#96;stages&#96;（stages），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>    stages = sorted({ACTION_CATALOG[kind]["stage"] for kind in types}, key=lambda item: STAGE_ORDER.get(item, 0))</code> |
| L0092 | 计算并保存 &#96;maximum_stage&#96;（maximumstage），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>    maximum_stage = max(stages, key=lambda item: STAGE_ORDER.get(item, 0), default="unknown")</code> |
| L0093 | 计算并保存 &#96;maximum_risk&#96;（maximumrisk），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>    maximum_risk = max(float(row.get("risk_score") or 0) for row in rows)</code> |
| L0094 | 计算并保存 &#96;diversity_boost&#96;（diversityboost），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>    diversity_boost = min(0.14, (len(source_ips) - 1) * 0.025 + (len(types) - 3) * 0.015)</code> |
| L0095 | 计算并保存 &#96;score&#96;（score），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>    score = min(1.0, maximum_risk + diversity_boost)</code> |
| L0096 | 计算并保存 &#96;target&#96;（target），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>    target = str(rows[0].get("target_asset") or "local-server")</code> |
| L0097 | 计算并保存 &#96;situation_ids&#96;（态势ids），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>    situation_ids = sorted(str(row.get("situation_id") or "") for row in rows)</code> |
| L0098 | 计算并保存 &#96;signature&#96;（signature），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>    signature = "&#124;".join([target, started.isoformat(), *situation_ids])</code> |
| L0099 | 计算并保存 &#96;cluster_id&#96;（clusterid），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>    cluster_id = "CLUSTER-" + hashlib.sha256(signature.encode("utf-8")).hexdigest()[:16].upper()</code> |
| L0100 | 计算并保存 &#96;counts_by_ip&#96;（countsbyip），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>    counts_by_ip = {ip: 0 for ip in source_ips}</code> |
| L0101 | 遍历集合中的数据项并逐项处理，当前位于函数 _finish_cluster。 | <code>    for action in actions:</code> |
| L0102 | 计算并保存 &#96;ip&#96;（ip），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>        ip = str(action.get("source_ip") or "")</code> |
| L0103 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        counts_by_ip[ip] = counts_by_ip.get(ip, 0) + int(action.get("action_count") or action.get("count") or 1)</code> |
| L0104 | 计算并保存 &#96;labels&#96;（labels），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>    labels = [str(ACTION_CATALOG[kind]["label"]) for kind in types]</code> |
| L0105 | 计算并保存 &#96;cluster&#96;（cluster），供后续逻辑使用，当前位于函数 _finish_cluster。 | <code>    cluster: Dict[str, Any] = {</code> |
| L0106 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "cluster_id": cluster_id,</code> |
| L0107 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "mode": "cross_ip",</code> |
| L0108 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "source_ip": f"多来源集群（{len(source_ips)} IP）",</code> |
| L0109 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "source_ips": source_ips,</code> |
| L0110 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "source_ip_counts": counts_by_ip,</code> |
| L0111 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "target_asset": target,</code> |
| L0112 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "started_at": started.isoformat(),</code> |
| L0113 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "last_action_at": ended.isoformat(),</code> |
| L0114 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "duration_seconds": max(0, int((ended - started).total_seconds())),</code> |
| L0115 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "status": "handled" if all(row.get("status") == "handled" for row in rows) else "open",</code> |
| L0116 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "distinct_action_types": len(types),</code> |
| L0117 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "total_action_count": sum(int(action.get("action_count") or action.get("count") or 1) for action in actions),</code> |
| L0118 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "current_stage": maximum_stage,</code> |
| L0119 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "risk_score": round(score, 6),</code> |
| L0120 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "risk_level": risk_level(score),</code> |
| L0121 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "situation_count": len(rows),</code> |
| L0122 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "situation_ids": situation_ids,</code> |
| L0123 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "action_types": types,</code> |
| L0124 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "action_labels": labels,</code> |
| L0125 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "stages": stages,</code> |
| L0126 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "sensor_count": len({str(action.get("sensor") or "unknown") for action in actions}),</code> |
| L0127 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "proxy_rotation_suspected": len(source_ips) &gt;= 3 or (len(source_ips) &gt;= 2 and len(types) &gt;= 4),</code> |
| L0128 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "window_minutes": int(window_minutes),</code> |
| L0129 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "actions": actions,</code> |
| L0130 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>        "ai_status": "complete",</code> |
| L0131 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 _finish_cluster。 | <code>    }</code> |
| L0132 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>    cluster["ai_report"] = _build_report(cluster)</code> |
| L0133 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 _finish_cluster。 | <code>    cluster["graph"] = build_cluster_graph(cluster)</code> |
| L0134 | 结束当前函数并把结果返回给调用方，当前位于函数 _finish_cluster。 | <code>    return cluster</code> |
| L0135 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0136 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0137 | 定义构建proxyclusters函数 &#96;build_proxy_clusters&#96;，封装可复用业务逻辑。 | <code>def build_proxy_clusters(</code> |
| L0138 | 计算并保存 &#96;situations&#96;（situations），供后续逻辑使用，当前位于函数 build_proxy_clusters。 | <code>    situations: Iterable[Dict[str, Any]], *, window_minutes: int = 60, lookback_hours: int = 24</code> |
| L0139 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_proxy_clusters。 | <code>) -&gt; List[Dict[str, Any]]:</code> |
| L0140 | 计算并保存 &#96;window_minutes&#96;（windowminutes），供后续逻辑使用，当前位于函数 build_proxy_clusters。 | <code>    window_minutes = max(5, min(1440, int(window_minutes)))</code> |
| L0141 | 计算并保存 &#96;lookback_hours&#96;（lookbackhours），供后续逻辑使用，当前位于函数 build_proxy_clusters。 | <code>    lookback_hours = max(1, min(24 * 30, int(lookback_hours)))</code> |
| L0142 | 计算并保存 &#96;cutoff&#96;（cutoff），供后续逻辑使用，当前位于函数 build_proxy_clusters。 | <code>    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)</code> |
| L0143 | 计算并保存 &#96;rows&#96;（数据库记录），供后续逻辑使用，当前位于函数 build_proxy_clusters。 | <code>    rows = [dict(row) for row in situations if _time(row.get("last_action_at")) &gt;= cutoff]</code> |
| L0144 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_proxy_clusters。 | <code>    rows.sort(key=lambda row: (str(row.get("target_asset") or ""), _time(row.get("started_at"))))</code> |
| L0145 | 计算并保存 &#96;clusters&#96;（clusters），供后续逻辑使用，当前位于函数 build_proxy_clusters。 | <code>    clusters: List[Dict[str, Any]] = []</code> |
| L0146 | 计算并保存 &#96;active&#96;（active），供后续逻辑使用，当前位于函数 build_proxy_clusters。 | <code>    active: List[Dict[str, Any]] = []</code> |
| L0147 | 计算并保存 &#96;active_target&#96;（activetarget），供后续逻辑使用，当前位于函数 build_proxy_clusters。 | <code>    active_target = ""</code> |
| L0148 | 计算并保存 &#96;active_start&#96;（active启动），供后续逻辑使用，当前位于函数 build_proxy_clusters。 | <code>    active_start: datetime &#124; None = None</code> |
| L0149 | 计算并保存 &#96;gap&#96;（gap），供后续逻辑使用，当前位于函数 build_proxy_clusters。 | <code>    gap = timedelta(minutes=window_minutes)</code> |
| L0150 | 遍历集合中的数据项并逐项处理，当前位于函数 build_proxy_clusters。 | <code>    for row in rows:</code> |
| L0151 | 计算并保存 &#96;target&#96;（target），供后续逻辑使用，当前位于函数 build_proxy_clusters。 | <code>        target = str(row.get("target_asset") or "local-server")</code> |
| L0152 | 计算并保存 &#96;started&#96;（started），供后续逻辑使用，当前位于函数 build_proxy_clusters。 | <code>        started = _time(row.get("started_at"))</code> |
| L0153 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_proxy_clusters。 | <code>        if active and (target != active_target or active_start is None or started &gt; active_start + gap):</code> |
| L0154 | 计算并保存 &#96;completed&#96;（completed），供后续逻辑使用，当前位于函数 build_proxy_clusters。 | <code>            completed = _finish_cluster(active, window_minutes)</code> |
| L0155 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_proxy_clusters。 | <code>            if completed:</code> |
| L0156 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_proxy_clusters。 | <code>                clusters.append(completed)</code> |
| L0157 | 计算并保存 &#96;active&#96;（active），供后续逻辑使用，当前位于函数 build_proxy_clusters。 | <code>            active = []</code> |
| L0158 | 计算并保存 &#96;active_start&#96;（active启动），供后续逻辑使用，当前位于函数 build_proxy_clusters。 | <code>            active_start = None</code> |
| L0159 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_proxy_clusters。 | <code>        if not active:</code> |
| L0160 | 计算并保存 &#96;active_start&#96;（active启动），供后续逻辑使用，当前位于函数 build_proxy_clusters。 | <code>            active_start = started</code> |
| L0161 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_proxy_clusters。 | <code>        active.append(row)</code> |
| L0162 | 计算并保存 &#96;active_target&#96;（activetarget），供后续逻辑使用，当前位于函数 build_proxy_clusters。 | <code>        active_target = target</code> |
| L0163 | 计算并保存 &#96;completed&#96;（completed），供后续逻辑使用，当前位于函数 build_proxy_clusters。 | <code>    completed = _finish_cluster(active, window_minutes)</code> |
| L0164 | 判断条件是否成立，成立时进入对应处理分支，当前位于函数 build_proxy_clusters。 | <code>    if completed:</code> |
| L0165 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_proxy_clusters。 | <code>        clusters.append(completed)</code> |
| L0166 | 结束当前函数并把结果返回给调用方，当前位于函数 build_proxy_clusters。 | <code>    return sorted(clusters, key=lambda item: item["last_action_at"], reverse=True)</code> |
| L0167 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0168 | 分隔相邻逻辑块，便于阅读和定位。 | <code>&lt;空行&gt;</code> |
| L0169 | 定义构建clustergraph函数 &#96;build_cluster_graph&#96;，封装可复用业务逻辑。 | <code>def build_cluster_graph(cluster: Dict[str, Any]) -&gt; Dict[str, Any]:</code> |
| L0170 | 计算并保存 &#96;nodes&#96;（nodes），供后续逻辑使用，当前位于函数 build_cluster_graph。 | <code>    nodes: List[Dict[str, Any]] = []</code> |
| L0171 | 遍历集合中的数据项并逐项处理，当前位于函数 build_cluster_graph。 | <code>    for index, action in enumerate(cluster.get("actions") or []):</code> |
| L0172 | 计算并保存 &#96;kind&#96;（kind），供后续逻辑使用，当前位于函数 build_cluster_graph。 | <code>        kind = _action_type(action)</code> |
| L0173 | 计算并保存 &#96;catalog&#96;（catalog），供后续逻辑使用，当前位于函数 build_cluster_graph。 | <code>        catalog = ACTION_CATALOG[kind]</code> |
| L0174 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_cluster_graph。 | <code>        nodes.append(</code> |
| L0175 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cluster_graph。 | <code>            {</code> |
| L0176 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cluster_graph。 | <code>                "id": f"cluster-action-{index + 1}",</code> |
| L0177 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cluster_graph。 | <code>                "name": str(catalog["label"]),</code> |
| L0178 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cluster_graph。 | <code>                "action_type": kind,</code> |
| L0179 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cluster_graph。 | <code>                "stage": str(catalog["stage"]),</code> |
| L0180 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cluster_graph。 | <code>                "stage_label": STAGE_LABELS[str(catalog["stage"])],</code> |
| L0181 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cluster_graph。 | <code>                "count": int(action.get("action_count") or action.get("count") or 1),</code> |
| L0182 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cluster_graph。 | <code>                "confidence": float(action.get("confidence") or 0),</code> |
| L0183 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cluster_graph。 | <code>                "occurred_at": action.get("occurred_at"),</code> |
| L0184 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cluster_graph。 | <code>                "last_seen_at": action.get("last_seen_at") or action.get("occurred_at"),</code> |
| L0185 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cluster_graph。 | <code>                "source_ip": action.get("source_ip"),</code> |
| L0186 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_cluster_graph。 | <code>            }</code> |
| L0187 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_cluster_graph。 | <code>        )</code> |
| L0188 | 计算并保存 &#96;edges&#96;（edges），供后续逻辑使用，当前位于函数 build_cluster_graph。 | <code>    edges = []</code> |
| L0189 | 遍历集合中的数据项并逐项处理，当前位于函数 build_cluster_graph。 | <code>    for index in range(1, len(nodes)):</code> |
| L0190 | 计算并保存 &#96;previous&#96;（previous），供后续逻辑使用，当前位于函数 build_cluster_graph。 | <code>        previous = nodes[index - 1]</code> |
| L0191 | 计算并保存 &#96;current&#96;（current），供后续逻辑使用，当前位于函数 build_cluster_graph。 | <code>        current = nodes[index]</code> |
| L0192 | 把当前结果加入集合，供后续聚合、排序或返回，当前位于函数 build_cluster_graph。 | <code>        edges.append(</code> |
| L0193 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cluster_graph。 | <code>            {</code> |
| L0194 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cluster_graph。 | <code>                "source": previous["id"],</code> |
| L0195 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cluster_graph。 | <code>                "target": current["id"],</code> |
| L0196 | 执行当前业务语句，完成数据构造、函数调用或状态更新，当前位于函数 build_cluster_graph。 | <code>                "gap_seconds": max(0, int((_time(current["occurred_at"]) - _time(previous["last_seen_at"])).total_seconds())),</code> |
| L0197 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_cluster_graph。 | <code>            }</code> |
| L0198 | 结束前面开始的字典、列表、参数或表达式结构，当前位于函数 build_cluster_graph。 | <code>        )</code> |
| L0199 | 结束当前函数并把结果返回给调用方，当前位于函数 build_cluster_graph。 | <code>    return {"nodes": nodes, "edges": edges, "mode": "cross_ip", "source_ips": cluster.get("source_ips") or []}</code> |
