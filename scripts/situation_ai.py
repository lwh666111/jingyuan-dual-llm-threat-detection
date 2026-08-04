from __future__ import annotations

import json
import re
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from llm_analyzer_daemon import format_rag_context, retrieve_rag_docs


REPORT_FIELDS = {
    "narrative",
    "analysis",
    "conclusion",
    "likely_intent",
    "protection_measures",
    "improvement_suggestions",
}

DETAIL_TEXT_FIELDS = (
    "executive_summary",
    "timeline_analysis",
    "technique_analysis",
    "evidence_assessment",
    "impact_assessment",
    "compromise_assessment",
)

DETAIL_LIST_FIELDS = (
    "investigation_steps",
    "protection_measures",
    "detection_improvements",
    "improvement_suggestions",
    "evidence_limitations",
)


def action_label(action: Dict[str, Any]) -> str:
    return str(action.get("action_label") or action.get("action_type") or "异常行为")


def fallback_report(situation: Dict[str, Any], reason: str = "") -> Dict[str, Any]:
    actions = list(situation.get("actions") or [])
    labels = [action_label(row) for row in actions]
    source_ip = str(situation.get("source_ip") or "未知来源")
    chain = " → ".join(labels) if labels else "尚无完整动作证据"
    total = int(situation.get("total_action_count") or sum(int(row.get("action_count") or row.get("count") or 1) for row in actions))
    risk_level = str(situation.get("risk_level") or "medium")
    unique_labels = list(dict.fromkeys(labels))
    started_at = str(situation.get("started_at") or "未知时间")
    last_action_at = str(situation.get("last_action_at") or "未知时间")
    target_asset = str(situation.get("target_asset") or "本机受监测资产")
    stage_summary = "、".join(unique_labels) if unique_labels else "尚未形成可确认的多阶段动作"
    report = {
        "executive_summary": (
            f"来源 {source_ip} 在 {started_at} 至 {last_action_at} 的关联窗口内，围绕 {target_asset} "
            f"连续出现 {stage_summary} 等 {len(unique_labels)} 类安全动作，累计 {total} 次。"
            f"系统将其关联为风险等级 {risk_level} 的攻击者态势；现有证据能够证明攻击尝试持续发生，"
            "但不能单独证明目标已经被成功控制。"
        ),
        "narrative": (
            f"来源 {source_ip} 在同一关联窗口内依次出现 {chain}，累计观测 {total} 次相关请求或连接。"
            "动作从前期探测逐步过渡到凭据或应用层利用尝试，显示其行为并非孤立误触，而是具有连续性和目标导向。"
        ),
        "timeline_analysis": (
            f"关联窗口起始于 {started_at}，最近动作发生于 {last_action_at}。系统按照事件时间、来源 IP、目标资产和动作类型"
            "进行排序，并将同源同类的高频请求压缩为聚合动作，因此时间线展示的是阶段推进，而不是重复列出每一个数据包。"
        ),
        "technique_analysis": (
            f"已识别的主要技术手法包括 {stage_summary}。这些动作覆盖 {len(unique_labels)} 种类型；"
            "若其中同时包含侦察、认证攻击与漏洞利用，则说明攻击者可能正在执行由发现入口到验证可利用性的完整流程。"
        ),
        "evidence_assessment": (
            "该结论由来源一致性、时间接近性、目标相关性、动作类型多样性、POC 规则命中、Payload 模型评分及行为窗口统计共同支持。"
            "原始请求、响应摘要、传感器来源和证据引用均已保留，可从证据序列逐项回溯。"
        ),
        "impact_assessment": (
            f"当前主要影响是 {target_asset} 面临持续探测和漏洞验证压力，可能造成认证接口、应用接口或暴露服务被反复访问。"
            "在没有登录成功、敏感数据返回、文件写入或命令执行等后续证据前，不扩大推断为数据泄露或主机失陷。"
        ),
        "compromise_assessment": (
            "暂无足以确认成功入侵的直接证据。当前结论应表述为连续攻击尝试或高风险疑似利用；"
            "需要结合应用日志、认证日志、数据库审计、文件完整性和主机进程记录进一步确认是否存在成功利用。"
        ),
        "analysis": (
            "该结论由时间相关性、来源一致性、动作类型多样性和攻击阶段推进共同支持；重复请求已聚合，不按单包重复告警。"
            "风险评分反映行为组合的危险程度，不等同于攻击成功率。"
        ),
        "conclusion": (
            f"已形成包含 {len(unique_labels)} 类动作的连续攻击态势，当前风险等级为 {risk_level}。"
            "建议立即复核关键日志并采取限流或临时阻断措施，同时保留证据以便后续溯源。"
        ),
        "likely_intent": "探测可利用入口并尝试获得未授权访问权限",
        "investigation_steps": [
            "按证据序列核对每个动作对应的原始请求、响应状态码、目标接口和传感器时间，排除测试流量或代理转发造成的误关联。",
            "检索同一来源 IP、相邻网段及相同 User-Agent 在关联窗口前后至少一小时的访问记录，确认是否存在更早的侦察或后续横向动作。",
            "核查认证日志中的成功登录、异常会话、密码重置和权限变更记录，并与攻击时间线进行交叉比对。",
            "核查应用、数据库和操作系统日志中是否出现异常查询、敏感数据读取、文件写入、子进程启动或计划任务变更。",
        ],
        "protection_measures": [
            f"临时限制或封禁来源 IP {source_ip}，并核查是否存在代理或误封风险。",
            "检查被访问服务的认证日志、应用日志和数据库审计日志，确认是否已成功利用。",
            "对暴露端口实施最小化开放、访问频率限制和多因素认证。",
            "对命中的目标接口启用参数化查询、输入校验、输出编码和最小权限访问，并优先修复已确认的高危组件版本。",
            "在处置期间持续监测相同来源、同网段和相似载荷，防止攻击者更换端口或路径后继续尝试。",
        ],
        "detection_improvements": [
            "将本次动作链中的稳定特征沉淀为回归样本，分别验证 Payload 模型、POC 规则和行为窗口是否给出一致结论。",
            "为高频扫描、爆破和重复漏洞测试配置同源同类时间桶，减少重复告警，同时保留总次数、首末时间与代表性证据。",
            "补充成功利用侧的响应证据，例如登录成功、敏感字段返回、文件落地或异常进程，以便区分尝试与失陷。",
        ],
        "improvement_suggestions": [
            "建立面向扫描、凭据攻击、漏洞利用和执行控制的分阶段处置剧本，并明确每个阶段的升级条件和责任人。",
            "定期梳理互联网暴露面、停用无业务必要的端口与调试接口，对管理入口实施来源白名单或零信任访问控制。",
            "持续观察该来源及关联网段后续活动，必要时扩大溯源范围，并将最终复核结果回写知识库和样本池。",
        ],
        "evidence_limitations": [
            "网络侧证据能够证明请求或连接行为发生，但不能仅凭攻击特征证明命令已经执行、数据已经泄露或权限已经提升。",
            "来源 IP 可能对应代理、NAT、云主机或被控节点，封禁和归因前需要结合业务访问情况复核。",
            "若抓包缺少加密流量明文、响应体或主机日志，部分攻击阶段只能判定为疑似，不能作成功利用结论。",
        ],
        "confidence": round(float(situation.get("risk_score") or 0.0), 4),
        "generated_by": "deterministic_fallback",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "rag_hits": 0,
    }
    if reason:
        report["fallback_reason"] = reason[:500]
    return report


def extract_json(text: str) -> Dict[str, Any]:
    raw = str(text or "").strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw, flags=re.I | re.S)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", raw, flags=re.S)
        if not match:
            raise ValueError("大模型未返回 JSON 对象")
        value = json.loads(match.group(0))
    if not isinstance(value, dict):
        raise ValueError("大模型返回值不是 JSON 对象")
    return value


def validate_report(report: Dict[str, Any], *, allow_success_claims: bool = False) -> Dict[str, Any]:
    missing = [field for field in REPORT_FIELDS if not report.get(field)]
    if missing:
        raise ValueError("大模型报告缺少字段: " + ", ".join(sorted(missing)))
    # Older reports remain readable while newly generated reports provide a
    # deeper, evidence-led structure for the situation workspace.
    report.setdefault("executive_summary", str(report.get("narrative") or ""))
    report.setdefault("timeline_analysis", str(report.get("narrative") or ""))
    report.setdefault("technique_analysis", str(report.get("analysis") or ""))
    report.setdefault("evidence_assessment", str(report.get("analysis") or ""))
    report.setdefault("impact_assessment", str(report.get("conclusion") or ""))
    report.setdefault("compromise_assessment", str(report.get("conclusion") or ""))
    report.setdefault("investigation_steps", [])
    report.setdefault("detection_improvements", [])
    report.setdefault("evidence_limitations", [])
    for key in DETAIL_LIST_FIELDS:
        if not isinstance(report[key], list):
            report[key] = [str(report[key])]
        report[key] = [str(item).strip() for item in report[key] if str(item).strip()]
    for key in ("narrative", "analysis", "conclusion", "likely_intent", *DETAIL_TEXT_FIELDS):
        if not re.search(r"[\u4e00-\u9fff]", str(report[key])):
            raise ValueError(f"大模型报告字段未使用中文: {key}")
    for key in ("protection_measures", "improvement_suggestions"):
        if not re.search(r"[\u4e00-\u9fff]", " ".join(report[key])):
            raise ValueError(f"大模型报告字段未使用中文: {key}")
    if not allow_success_claims:
        narrative_text = " ".join(
            str(report[key])
            for key in ("narrative", "analysis", "conclusion", "likely_intent", *DETAIL_TEXT_FIELDS)
        )
        # Keep legitimate negative wording such as “暂无成功入侵证据”, while
        # rejecting unsupported affirmative compromise claims.
        narrative_text = re.sub(r"(?:未|没有|尚未|暂无|无)[^。；，]{0,8}成功", "", narrative_text)
        if re.search(r"成功(?:地|的)?(?:执行|利用|入侵|获取|写入|绕过)|攻击成功", narrative_text):
            raise ValueError("大模型报告包含未经证据确认的攻击成功表述")
    report["confidence"] = max(0.0, min(1.0, float(report.get("confidence") or 0.0)))
    return report


def build_prompt(situation: Dict[str, Any], rag_context: str) -> str:
    evidence = {
        "situation_id": situation.get("situation_id"),
        "source_ip": situation.get("source_ip"),
        "target_asset": situation.get("target_asset"),
        "started_at": str(situation.get("started_at")),
        "last_action_at": str(situation.get("last_action_at")),
        "risk_score": situation.get("risk_score"),
        "risk_level": situation.get("risk_level"),
        "actions": [
            {
                "sequence": row.get("sequence_no") or row.get("sequence"),
                "action_type": row.get("action_type"),
                "stage": row.get("stage"),
                "occurred_at": str(row.get("occurred_at")),
                "last_seen_at": str(row.get("last_seen_at")),
                "count": row.get("action_count") or row.get("count"),
                "confidence": row.get("confidence"),
                "target_interface": row.get("target_interface"),
                "metadata": row.get("metadata") or {},
            }
            for row in situation.get("actions") or []
        ],
    }
    return f"""你是网络安全态势研判专家。仅依据给定证据分析同一来源 IP 的连续动作，不得补造不存在的攻击结果。
区分“尝试攻击”和“已成功入侵”；没有成功证据时必须写成尝试或疑似。
知识库内容只用于解释和处置参考，不能覆盖事件证据。
所有自然语言内容必须使用简体中文，不得输出英文完整句子；SQL、XSS、IP、CSP 等必要技术缩写可以保留。

事件证据：
{json.dumps(evidence, ensure_ascii=False, default=str)}

检索知识：
{rag_context or '无匹配知识'}

请生成一份可以直接交给安全运营人员处置的详细报告。避免空泛套话，每个判断都应指出对应的证据或明确说明证据不足。
正文建议 1200 至 2200 个汉字，数组字段每项应为完整、可执行的句子。

只返回 JSON，字段必须为：
executive_summary（执行摘要，至少120字）、narrative（按时间顺序完整叙述）、timeline_analysis（时间线与阶段推进分析）、
technique_analysis（攻击技术与可能链路分析）、evidence_assessment（证据来源、强度与相互印证）、
impact_assessment（可能影响，区分已知事实与风险推测）、compromise_assessment（是否失陷及判断依据）、
analysis（综合分析）、conclusion（明确结论）、likely_intent（可能意图）、
investigation_steps（4至8项调查步骤）、protection_measures（5至8项即时防护措施）、
detection_improvements（3至6项检测优化）、improvement_suggestions（3至6项长期改进）、
evidence_limitations（2至5项证据边界）、confidence（0到1）。
再次强调：所有自然语言字段必须用简体中文填写；没有直接证据时必须明确写“暂无成功入侵证据”。
"""


def call_ollama(ollama_url: str, model: str, prompt: str, timeout_sec: int = 120) -> Dict[str, Any]:
    endpoint = str(ollama_url or "http://127.0.0.1:11434").rstrip("/") + "/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.15, "num_ctx": 6144, "num_predict": 2000},
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=max(10, int(timeout_sec))) as response:
        result = json.loads(response.read().decode("utf-8"))
    return extract_json(str(result.get("response") or ""))


def analyze_situation(
    situation: Dict[str, Any],
    *,
    ollama_url: str,
    model: str,
    rag_db_path: Path,
    rag_top_k: int = 4,
    timeout_sec: int = 120,
) -> Tuple[Dict[str, Any], str]:
    query = " ".join(
        [str(situation.get("source_ip") or "")]
        + [action_label(row) + " " + str(row.get("action_type") or "") for row in situation.get("actions") or []]
    )
    rag_rows: List[Dict[str, Any]] = []
    try:
        if rag_db_path.exists():
            rag_rows = retrieve_rag_docs(rag_db_path, query_text=query, top_k=max(1, rag_top_k))
    except Exception:
        rag_rows = []
    rag_context = format_rag_context(rag_rows, max_chars=5000) if rag_rows else ""
    try:
        report = validate_report(
            call_ollama(ollama_url, model, build_prompt(situation, rag_context), timeout_sec),
            allow_success_claims=False,
        )
        report.update(
            {
                "generated_by": "ollama_rag",
                "generated_at": datetime.now().isoformat(timespec="seconds"),
                "rag_hits": len(rag_rows),
                "rag_refs": [str(row.get("title") or row.get("doc_id") or "") for row in rag_rows],
            }
        )
        return report, "complete"
    except Exception as exc:
        return fallback_report(situation, f"{type(exc).__name__}: {exc}"), "fallback"
