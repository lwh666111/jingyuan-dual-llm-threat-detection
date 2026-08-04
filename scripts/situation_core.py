from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from zoneinfo import ZoneInfo


LOCAL_TIMEZONE = ZoneInfo("Asia/Shanghai")


STAGE_LABELS = {
    "recon": "侦察探测",
    "credential": "凭据攻击",
    "exploit": "漏洞利用",
    "execution": "执行控制",
    "impact": "影响处置",
    "unknown": "其他行为",
}

STAGE_ORDER = {
    "unknown": 0,
    "recon": 1,
    "credential": 2,
    "exploit": 3,
    "execution": 4,
    "impact": 5,
}

ACTION_CATALOG: Dict[str, Dict[str, Any]] = {
    "PORT_SCAN": {"label": "端口扫描", "stage": "recon", "weight": 0.35},
    "SERVICE_PROBE": {"label": "服务探测", "stage": "recon", "weight": 0.40},
    "DIRECTORY_SCAN": {"label": "目录扫描", "stage": "recon", "weight": 0.42},
    "GRAPHQL_PROBE": {"label": "GraphQL 探测", "stage": "recon", "weight": 0.45},
    "SSH_BRUTEFORCE": {"label": "SSH 爆破", "stage": "credential", "weight": 0.68},
    "HTTP_BRUTEFORCE": {"label": "HTTP 爆破", "stage": "credential", "weight": 0.62},
    "AUTH_ABUSE": {"label": "认证滥用", "stage": "credential", "weight": 0.62},
    "SQL_INJECTION": {"label": "SQL 注入", "stage": "exploit", "weight": 0.78},
    "XSS": {"label": "XSS", "stage": "exploit", "weight": 0.65},
    "PATH_TRAVERSAL": {"label": "路径遍历", "stage": "exploit", "weight": 0.72},
    "FILE_UPLOAD": {"label": "危险文件上传", "stage": "exploit", "weight": 0.82},
    "SSRF": {"label": "SSRF", "stage": "exploit", "weight": 0.76},
    "XXE": {"label": "XXE", "stage": "exploit", "weight": 0.78},
    "SSTI": {"label": "SSTI", "stage": "exploit", "weight": 0.78},
    "DESERIALIZATION": {"label": "反序列化", "stage": "execution", "weight": 0.88},
    "FASTJSON_NDAY": {"label": "Fastjson 反序列化探测", "stage": "execution", "weight": 0.89},
    "LOG4J_NDAY": {"label": "Log4j JNDI 探测", "stage": "execution", "weight": 0.94},
    "SPRING_NDAY": {"label": "Spring 数据绑定探测", "stage": "exploit", "weight": 0.86},
    "SHIRO_NDAY": {"label": "Shiro 认证探测", "stage": "credential", "weight": 0.80},
    "UNKNOWN_THREAT": {"label": "未知威胁探测", "stage": "exploit", "weight": 0.78},
    "COMMAND_INJECTION": {"label": "命令注入", "stage": "execution", "weight": 0.92},
    "WEB_SHELL": {"label": "WebShell 行为", "stage": "execution", "weight": 0.95},
    "IP_BLOCKED": {"label": "IP 已封禁", "stage": "impact", "weight": 0.20},
    "UNKNOWN": {"label": "其他异常", "stage": "unknown", "weight": 0.30},
}

ATTACK_TYPE_ALIASES = {
    "端口扫描": "PORT_SCAN",
    "网络扫描": "PORT_SCAN",
    "服务探测": "SERVICE_PROBE",
    "扫描探测": "SERVICE_PROBE",
    "目录扫描": "DIRECTORY_SCAN",
    "目录探测": "DIRECTORY_SCAN",
    "路径探测": "DIRECTORY_SCAN",
    "graphql探测": "GRAPHQL_PROBE",
    "graphql introspection探测": "GRAPHQL_PROBE",
    "ssh爆破": "SSH_BRUTEFORCE",
    "ssh暴力破解": "SSH_BRUTEFORCE",
    "http爆破": "HTTP_BRUTEFORCE",
    "暴力破解": "HTTP_BRUTEFORCE",
    "疑似暴力破解": "HTTP_BRUTEFORCE",
    "认证滥用": "AUTH_ABUSE",
    "sql注入": "SQL_INJECTION",
    "sql injection": "SQL_INJECTION",
    "xss": "XSS",
    "跨站脚本": "XSS",
    "路径遍历": "PATH_TRAVERSAL",
    "敏感文件读取": "PATH_TRAVERSAL",
    "危险文件上传": "FILE_UPLOAD",
    "文件上传": "FILE_UPLOAD",
    "ssrf": "SSRF",
    "xxe": "XXE",
    "ssti": "SSTI",
    "反序列化": "DESERIALIZATION",
    "fastjson反序列化探测": "FASTJSON_NDAY",
    "fastjson探测": "FASTJSON_NDAY",
    "log4j jndi探测": "LOG4J_NDAY",
    "log4j探测": "LOG4J_NDAY",
    "spring数据绑定探测": "SPRING_NDAY",
    "spring探测": "SPRING_NDAY",
    "shiro认证探测": "SHIRO_NDAY",
    "shiro探测": "SHIRO_NDAY",
    "未知威胁探测": "UNKNOWN_THREAT",
    "零日特征模拟": "UNKNOWN_THREAT",
    "命令注入": "COMMAND_INJECTION",
    "webshell": "WEB_SHELL",
    "ip已封禁": "IP_BLOCKED",
}


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value or "").strip()
        if not text:
            return datetime.now(timezone.utc)
        text = text.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            dt = datetime.strptime(text.split(".", 1)[0], "%Y-%m-%d %H:%M:%S")
    if dt.tzinfo is None:
        # Existing MySQL event timestamps are server-local values without an offset.
        return dt.replace(tzinfo=LOCAL_TIMEZONE).astimezone(timezone.utc)
    return dt.astimezone(timezone.utc)


def timestamp_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def normalize_action_type(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "UNKNOWN"
    upper = text.upper().replace("-", "_").replace(" ", "_")
    if upper in ACTION_CATALOG:
        return upper
    compact = text.lower().replace(" ", "")
    compact_aliases = [
        (alias.lower().replace(" ", ""), action_type)
        for alias, action_type in ATTACK_TYPE_ALIASES.items()
    ]
    for alias_compact, action_type in compact_aliases:
        if compact == alias_compact:
            return action_type
    # Prefer the most specific phrase when a label contains both a product
    # name and a generic family such as “Fastjson反序列化探测”.
    for alias_compact, action_type in sorted(compact_aliases, key=lambda item: len(item[0]), reverse=True):
        if alias_compact in compact:
            return action_type
    return "UNKNOWN"


def severity_value(severity: str) -> float:
    return {
        "critical": 1.0,
        "high": 0.82,
        "medium": 0.58,
        "low": 0.30,
        "info": 0.10,
    }.get(str(severity or "").lower(), 0.45)


def risk_level(score: float) -> str:
    if score >= 0.82:
        return "critical"
    if score >= 0.68:
        return "high"
    if score >= 0.48:
        return "medium"
    return "low"


@dataclass
class SecurityAction:
    action_id: str
    source_ip: str
    target_asset: str
    action_type: str
    occurred_at: datetime
    last_seen_at: Optional[datetime] = None
    target_port: Optional[int] = None
    target_interface: str = ""
    protocol: str = ""
    sensor: str = ""
    count: int = 1
    confidence: float = 0.0
    severity: str = "medium"
    evidence_refs: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.action_type = normalize_action_type(self.action_type)
        self.occurred_at = parse_timestamp(self.occurred_at)
        self.last_seen_at = parse_timestamp(self.last_seen_at or self.occurred_at)
        self.source_ip = str(self.source_ip or "").strip()
        self.target_asset = str(self.target_asset or "local-server").strip() or "local-server"
        self.target_interface = str(self.target_interface or "").strip()
        self.protocol = str(self.protocol or "").upper().strip()
        self.sensor = str(self.sensor or "unknown").strip()
        self.count = max(1, int(self.count or 1))
        self.confidence = max(0.0, min(1.0, float(self.confidence or 0.0)))
        self.evidence_refs = [str(x) for x in self.evidence_refs if str(x).strip()]

    @property
    def stage(self) -> str:
        return str(ACTION_CATALOG[self.action_type]["stage"])

    @property
    def label(self) -> str:
        return str(ACTION_CATALOG[self.action_type]["label"])

    @property
    def weight(self) -> float:
        return float(ACTION_CATALOG[self.action_type]["weight"])

    def as_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "source_ip": self.source_ip,
            "target_asset": self.target_asset,
            "target_port": self.target_port,
            "target_interface": self.target_interface,
            "protocol": self.protocol,
            "action_type": self.action_type,
            "action_label": self.label,
            "stage": self.stage,
            "stage_label": STAGE_LABELS[self.stage],
            "sensor": self.sensor,
            "occurred_at": timestamp_text(self.occurred_at),
            "last_seen_at": timestamp_text(self.last_seen_at or self.occurred_at),
            "count": self.count,
            "confidence": round(self.confidence, 6),
            "severity": self.severity,
            "evidence_refs": list(self.evidence_refs),
            "metadata": dict(self.metadata),
        }


@dataclass
class Situation:
    situation_id: str
    source_ip: str
    target_asset: str
    started_at: datetime
    last_action_at: datetime
    actions: List[SecurityAction] = field(default_factory=list)
    status: str = "observing"
    risk_score: float = 0.0
    risk_level: str = "low"
    current_stage: str = "unknown"
    sequence_hash: str = ""

    @property
    def distinct_action_types(self) -> int:
        return len({x.action_type for x in self.actions if x.action_type != "IP_BLOCKED"})

    @property
    def total_action_count(self) -> int:
        return sum(x.count for x in self.actions)

    def refresh(self, minimum_distinct_actions: int) -> None:
        self.actions.sort(key=lambda x: (x.occurred_at, x.action_id))
        if self.actions:
            self.started_at = self.actions[0].occurred_at
            self.last_action_at = max((x.last_seen_at or x.occurred_at) for x in self.actions)
        self.current_stage = max(
            (x.stage for x in self.actions),
            key=lambda stage: STAGE_ORDER.get(stage, 0),
            default="unknown",
        )
        self.risk_score = calculate_situation_risk(self.actions)
        self.risk_level = risk_level(self.risk_score)
        self.status = "open" if self.distinct_action_types >= minimum_distinct_actions else "observing"
        signature = "|".join(
            f"{x.action_type}:{timestamp_text(x.occurred_at)}:{x.count}" for x in self.actions
        )
        self.sequence_hash = hashlib.sha256(signature.encode("utf-8")).hexdigest()[:24]

    def as_dict(self) -> Dict[str, Any]:
        ordered = sorted(self.actions, key=lambda x: (x.occurred_at, x.action_id))
        action_rows: List[Dict[str, Any]] = []
        previous: Optional[SecurityAction] = None
        for seq, action in enumerate(ordered, start=1):
            row = action.as_dict()
            row["sequence"] = seq
            row["gap_seconds"] = (
                max(0, int((action.occurred_at - (previous.last_seen_at or previous.occurred_at)).total_seconds()))
                if previous
                else 0
            )
            action_rows.append(row)
            previous = action
        return {
            "situation_id": self.situation_id,
            "source_ip": self.source_ip,
            "target_asset": self.target_asset,
            "started_at": timestamp_text(self.started_at),
            "last_action_at": timestamp_text(self.last_action_at),
            "duration_seconds": max(0, int((self.last_action_at - self.started_at).total_seconds())),
            "status": self.status,
            "distinct_action_types": self.distinct_action_types,
            "total_action_count": self.total_action_count,
            "current_stage": self.current_stage,
            "current_stage_label": STAGE_LABELS[self.current_stage],
            "risk_score": round(self.risk_score, 6),
            "risk_level": self.risk_level,
            "sequence_hash": self.sequence_hash,
            "actions": action_rows,
        }


def calculate_situation_risk(actions: Sequence[SecurityAction]) -> float:
    if not actions:
        return 0.0
    types = {x.action_type for x in actions if x.action_type != "IP_BLOCKED"}
    stages = {x.stage for x in actions if x.stage not in {"unknown", "impact"}}
    action_danger = max((x.weight for x in actions), default=0.0)
    confidence = max((x.confidence for x in actions), default=0.0)
    severity = max((severity_value(x.severity) for x in actions), default=0.0)
    diversity = min(1.0, len(types) / 5.0)
    stage_depth = min(1.0, max((STAGE_ORDER.get(x.stage, 0) for x in actions), default=0) / 4.0)
    frequency = min(1.0, sum(x.count for x in actions) / 100.0)
    progression = min(1.0, len(stages) / 3.0)
    score = (
        action_danger * 0.25
        + confidence * 0.20
        + severity * 0.15
        + diversity * 0.15
        + stage_depth * 0.10
        + frequency * 0.05
        + progression * 0.10
    )
    return round(max(0.0, min(1.0, score)), 6)


def aggregate_actions(actions: Sequence[SecurityAction]) -> List[SecurityAction]:
    grouped: Dict[Tuple[str, str, str, Optional[int], str], SecurityAction] = {}
    for action in sorted(actions, key=lambda x: (x.occurred_at, x.action_id)):
        key = (
            action.source_ip,
            action.target_asset,
            action.action_type,
            action.target_port,
            action.target_interface,
        )
        current = grouped.get(key)
        if current is None:
            grouped[key] = SecurityAction(
                **{
                    **action.__dict__,
                    "evidence_refs": list(action.evidence_refs),
                    "metadata": deepcopy(action.metadata),
                }
            )
            continue
        current.occurred_at = min(current.occurred_at, action.occurred_at)
        current.last_seen_at = max(current.last_seen_at or current.occurred_at, action.last_seen_at or action.occurred_at)
        current.count += action.count
        current.confidence = max(current.confidence, action.confidence)
        if severity_value(action.severity) > severity_value(current.severity):
            current.severity = action.severity
        current.evidence_refs = list(dict.fromkeys(current.evidence_refs + action.evidence_refs))
        current.metadata = {**current.metadata, **action.metadata}
    return sorted(grouped.values(), key=lambda x: (x.occurred_at, x.action_id))


class SituationCorrelator:
    def __init__(
        self,
        minimum_distinct_actions: int = 3,
        window_minutes: int = 30,
        inactivity_minutes: int = 15,
    ) -> None:
        self.minimum_distinct_actions = max(2, int(minimum_distinct_actions))
        self.window = timedelta(minutes=max(1, int(window_minutes)))
        self.inactivity = timedelta(minutes=max(1, int(inactivity_minutes)))

    def correlate(self, actions: Iterable[SecurityAction], include_observing: bool = True) -> List[Situation]:
        valid = [x for x in actions if x.source_ip]
        valid.sort(key=lambda x: (x.source_ip, x.target_asset, x.occurred_at, x.action_id))
        grouped: Dict[Tuple[str, str], List[SecurityAction]] = {}
        for action in valid:
            grouped.setdefault((action.source_ip, action.target_asset), []).append(action)

        situations: List[Situation] = []
        for (source_ip, target_asset), rows in grouped.items():
            bucket: List[SecurityAction] = []
            for action in rows:
                if bucket:
                    first = bucket[0].occurred_at
                    last = max((x.last_seen_at or x.occurred_at) for x in bucket)
                    if action.occurred_at - last > self.inactivity or action.occurred_at - first > self.window:
                        situations.append(self._build(source_ip, target_asset, bucket))
                        bucket = []
                bucket.append(action)
            if bucket:
                situations.append(self._build(source_ip, target_asset, bucket))

        if not include_observing:
            situations = [x for x in situations if x.status == "open"]
        situations.sort(key=lambda x: x.last_action_at, reverse=True)
        return situations

    def _build(self, source_ip: str, target_asset: str, rows: Sequence[SecurityAction]) -> Situation:
        aggregated = aggregate_actions(rows)
        first = min(x.occurred_at for x in aggregated)
        token = f"{source_ip}|{target_asset}|{timestamp_text(first)}"
        situation_id = "SIT-" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:20].upper()
        situation = Situation(
            situation_id=situation_id,
            source_ip=source_ip,
            target_asset=target_asset,
            started_at=first,
            last_action_at=max((x.last_seen_at or x.occurred_at) for x in aggregated),
            actions=aggregated,
        )
        situation.refresh(self.minimum_distinct_actions)
        return situation


def action_from_attack_event(row: Dict[str, Any], target_asset: str = "local-server") -> SecurityAction:
    event_id = str(row.get("event_id") or row.get("case_id") or "")
    action_type = normalize_action_type(row.get("attack_type"))
    evidence = row.get("evidence_json")
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except Exception:
            evidence = [evidence] if evidence.strip() else []
    return SecurityAction(
        action_id=f"ACT-{event_id or hashlib.sha1(json.dumps(row, sort_keys=True, default=str).encode()).hexdigest()[:16]}",
        source_ip=str(row.get("source_ip") or ""),
        target_asset=str(row.get("target_asset") or row.get("target_node") or target_asset),
        target_port=int(row["target_port"]) if str(row.get("target_port") or "").isdigit() else None,
        target_interface=str(row.get("target_interface") or row.get("uri") or ""),
        protocol=str(row.get("protocol") or ("SSH" if action_type == "SSH_BRUTEFORCE" else "HTTP")),
        action_type=action_type,
        occurred_at=parse_timestamp(row.get("occurred_at") or row.get("event_time") or row.get("created_at")),
        sensor=str(row.get("sensor") or "detection_v2"),
        count=int(row.get("request_count") or row.get("count") or 1),
        confidence=float(row.get("confidence") or row.get("final_score") or 0.0),
        severity=str(row.get("risk_level") or row.get("severity") or "medium"),
        evidence_refs=[event_id] if event_id else [],
        metadata={"evidence": evidence or []},
    )
