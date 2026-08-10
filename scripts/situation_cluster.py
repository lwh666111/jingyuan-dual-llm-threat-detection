from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List

from situation_core import ACTION_CATALOG, STAGE_LABELS, STAGE_ORDER, parse_timestamp, risk_level


def _time(value: Any) -> datetime:
    parsed = parse_timestamp(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _action_type(action: Dict[str, Any]) -> str:
    value = str(action.get("action_type") or "UNKNOWN").strip().upper()
    return value if value in ACTION_CATALOG else "UNKNOWN"


def _build_report(cluster: Dict[str, Any]) -> Dict[str, Any]:
    ips = cluster["source_ips"]
    labels = cluster["action_labels"]
    duration = max(1, int(cluster["duration_seconds"] / 60))
    ip_sample = "、".join(ips[:5]) + (f" 等 {len(ips)} 个地址" if len(ips) > 5 else "")
    action_chain = " → ".join(labels)
    proxy_note = "来源地址高频切换，具有代理池或分布式协同行为特征" if cluster["proxy_rotation_suspected"] else "多个来源在相近时间针对同一资产执行相似动作"
    return {
        "executive_summary": (
            f"系统在 {duration} 分钟内关联到 {len(ips)} 个来源 IP，针对 {cluster['target_asset']} "
            f"累计实施 {cluster['total_action_count']} 次、{cluster['distinct_action_types']} 类安全动作。{proxy_note}。"
        ),
        "likely_intent": "通过轮换代理隐藏真实来源并推进侦察、凭据攻击或漏洞利用",
        "narrative": f"主要来源为 {ip_sample}。融合后的动作链为：{action_chain}。所有动作均按原始时间戳重新排序，未将来源 IP 相同作为关联前提。",
        "timeline_analysis": f"聚合窗口从 {cluster['started_at']} 至 {cluster['last_action_at']}，持续约 {duration} 分钟；同一目标和紧密时间关系支持对代理轮换假设进行进一步调查。",
        "technique_analysis": f"检测到 {cluster['distinct_action_types']} 类技术动作：{'、'.join(labels)}。动作跨越 {len(cluster['stages'])} 个攻击阶段，风险由动作置信度、阶段深度、频次和来源多样性共同计算。",
        "evidence_assessment": f"证据来自 {cluster['sensor_count']} 类传感器、{cluster['situation_count']} 条单 IP 态势和 {len(cluster['actions'])} 条归一化动作；原始来源与证据引用均保留，可回溯复核。",
        "impact_assessment": "若后续出现执行控制、敏感数据访问或持久化证据，应立即将事件升级为疑似失陷；当前应优先限制恶意来源并核查目标服务日志。",
        "compromise_assessment": "当前证据能够证明持续攻击活动，但不能仅凭网络请求断言主机已经失陷。",
        "conclusion": f"该集群符合多来源协同或代理池轮换攻击特征，综合风险为{cluster['risk_level']}，建议按一个攻击行动统一处置，同时保留各 IP 的独立封禁与溯源记录。",
        "investigation_steps": [
            "按时间轴核对 Web、SSH、WAF 与系统登录日志，确认多个来源是否共享账户、载荷或指纹。",
            "比对 User-Agent、TLS 指纹、请求路径、Payload 模板与失败响应，判断是否来自同一工具链。",
            "检查目标接口后续是否出现成功登录、命令执行、异常文件写入或外联行为。",
        ],
        "protection_measures": [
            "对高置信恶意来源实施入站与出站双向封禁，并保留可回滚规则。",
            "对被集中探测的接口启用速率限制、强认证与最小暴露策略。",
            "若来源规模持续扩大，优先在上游网关或云防护侧按 ASN、网段和行为特征联动阻断。",
        ],
        "detection_improvements": [
            "将时间窗、目标资产、载荷相似度和客户端指纹纳入跨 IP 关联评分。",
            "为代理轮换集群建立独立阈值，避免仅依赖单 IP 请求频率。",
        ],
        "improvement_suggestions": [
            "持续沉淀已确认代理集群样本，用于回归评估和阈值校准。",
            "接入反向代理真实来源头校验，防止伪造 X-Forwarded-For 干扰关联结果。",
        ],
        "evidence_limitations": [
            "多个 IP 的时间相关性不能单独证明其属于同一攻击者。",
            "NAT、共享出口和合法扫描服务可能造成多来源或多用户混淆，需结合指纹与业务日志复核。",
        ],
        "generated_by": "cross_ip_correlation_engine",
        "rag_hits": 0,
    }


def _finish_cluster(rows: List[Dict[str, Any]], window_minutes: int) -> Dict[str, Any] | None:
    if not rows:
        return None
    actions: List[Dict[str, Any]] = []
    source_ips = sorted({str(row.get("source_ip") or "").strip() for row in rows if row.get("source_ip")})
    for row in rows:
        for action in row.get("actions") or []:
            item = dict(action)
            item["source_ip"] = str(item.get("source_ip") or row.get("source_ip") or "")
            item["situation_id"] = str(row.get("situation_id") or "")
            actions.append(item)
    actions.sort(key=lambda item: (_time(item.get("occurred_at")), str(item.get("action_id") or "")))
    for index, action in enumerate(actions, start=1):
        action["sequence_no"] = index
    types = []
    for action in actions:
        kind = _action_type(action)
        if kind != "IP_BLOCKED" and kind not in types:
            types.append(kind)
    if len(source_ips) < 2 or len(types) < 3:
        return None

    started = min(_time(row.get("started_at")) for row in rows)
    ended = max(_time(row.get("last_action_at")) for row in rows)
    stages = sorted({ACTION_CATALOG[kind]["stage"] for kind in types}, key=lambda item: STAGE_ORDER.get(item, 0))
    maximum_stage = max(stages, key=lambda item: STAGE_ORDER.get(item, 0), default="unknown")
    maximum_risk = max(float(row.get("risk_score") or 0) for row in rows)
    diversity_boost = min(0.14, (len(source_ips) - 1) * 0.025 + (len(types) - 3) * 0.015)
    score = min(1.0, maximum_risk + diversity_boost)
    target = str(rows[0].get("target_asset") or "local-server")
    situation_ids = sorted(str(row.get("situation_id") or "") for row in rows)
    signature = "|".join([target, started.isoformat(), *situation_ids])
    cluster_id = "CLUSTER-" + hashlib.sha256(signature.encode("utf-8")).hexdigest()[:16].upper()
    counts_by_ip = {ip: 0 for ip in source_ips}
    for action in actions:
        ip = str(action.get("source_ip") or "")
        counts_by_ip[ip] = counts_by_ip.get(ip, 0) + int(action.get("action_count") or action.get("count") or 1)
    labels = [str(ACTION_CATALOG[kind]["label"]) for kind in types]
    cluster: Dict[str, Any] = {
        "cluster_id": cluster_id,
        "mode": "cross_ip",
        "source_ip": f"多来源集群（{len(source_ips)} IP）",
        "source_ips": source_ips,
        "source_ip_counts": counts_by_ip,
        "target_asset": target,
        "started_at": started.isoformat(),
        "last_action_at": ended.isoformat(),
        "duration_seconds": max(0, int((ended - started).total_seconds())),
        "status": "handled" if all(row.get("status") == "handled" for row in rows) else "open",
        "distinct_action_types": len(types),
        "total_action_count": sum(int(action.get("action_count") or action.get("count") or 1) for action in actions),
        "current_stage": maximum_stage,
        "risk_score": round(score, 6),
        "risk_level": risk_level(score),
        "situation_count": len(rows),
        "situation_ids": situation_ids,
        "action_types": types,
        "action_labels": labels,
        "stages": stages,
        "sensor_count": len({str(action.get("sensor") or "unknown") for action in actions}),
        "proxy_rotation_suspected": len(source_ips) >= 3 or (len(source_ips) >= 2 and len(types) >= 4),
        "window_minutes": int(window_minutes),
        "actions": actions,
        "ai_status": "complete",
    }
    cluster["ai_report"] = _build_report(cluster)
    cluster["graph"] = build_cluster_graph(cluster)
    return cluster


def build_proxy_clusters(
    situations: Iterable[Dict[str, Any]], *, window_minutes: int = 60, lookback_hours: int = 24
) -> List[Dict[str, Any]]:
    window_minutes = max(5, min(1440, int(window_minutes)))
    lookback_hours = max(1, min(24 * 30, int(lookback_hours)))
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    rows = [dict(row) for row in situations if _time(row.get("last_action_at")) >= cutoff]
    rows.sort(key=lambda row: (str(row.get("target_asset") or ""), _time(row.get("started_at"))))
    clusters: List[Dict[str, Any]] = []
    active: List[Dict[str, Any]] = []
    active_target = ""
    active_start: datetime | None = None
    gap = timedelta(minutes=window_minutes)
    for row in rows:
        target = str(row.get("target_asset") or "local-server")
        started = _time(row.get("started_at"))
        if active and (target != active_target or active_start is None or started > active_start + gap):
            completed = _finish_cluster(active, window_minutes)
            if completed:
                clusters.append(completed)
            active = []
            active_start = None
        if not active:
            active_start = started
        active.append(row)
        active_target = target
    completed = _finish_cluster(active, window_minutes)
    if completed:
        clusters.append(completed)
    return sorted(clusters, key=lambda item: item["last_action_at"], reverse=True)


def build_cluster_graph(cluster: Dict[str, Any]) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    for index, action in enumerate(cluster.get("actions") or []):
        kind = _action_type(action)
        catalog = ACTION_CATALOG[kind]
        nodes.append(
            {
                "id": f"cluster-action-{index + 1}",
                "name": str(catalog["label"]),
                "action_type": kind,
                "stage": str(catalog["stage"]),
                "stage_label": STAGE_LABELS[str(catalog["stage"])],
                "count": int(action.get("action_count") or action.get("count") or 1),
                "confidence": float(action.get("confidence") or 0),
                "occurred_at": action.get("occurred_at"),
                "last_seen_at": action.get("last_seen_at") or action.get("occurred_at"),
                "source_ip": action.get("source_ip"),
            }
        )
    edges = []
    for index in range(1, len(nodes)):
        previous = nodes[index - 1]
        current = nodes[index]
        edges.append(
            {
                "source": previous["id"],
                "target": current["id"],
                "gap_seconds": max(0, int((_time(current["occurred_at"]) - _time(previous["last_seen_at"])).total_seconds())),
            }
        )
    return {"nodes": nodes, "edges": edges, "mode": "cross_ip", "source_ips": cluster.get("source_ips") or []}
