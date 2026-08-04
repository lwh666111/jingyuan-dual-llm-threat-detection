from __future__ import annotations

import html
import json
import math
import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote_plus, urlsplit

import joblib

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES_PATH = PROJECT_ROOT / "rules" / "poc_rules.json"
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "payload_model_v2.joblib"
DEFAULT_BEHAVIOR_MODEL_PATH = PROJECT_ROOT / "models" / "behavior_model_v2.joblib"

ATTACK_TYPE_PRIORITY = {
    "XXE": 100,
    "命令注入": 95,
    "SQL注入": 90,
    "XSS": 88,
    "路径遍历": 85,
    "SSRF": 84,
    "SSTI": 83,
    "危险文件上传": 82,
    "反序列化": 80,
    "GraphQL探测": 60,
}

SEVERITY_SCORE = {
    "info": 0.05,
    "low": 0.35,
    "medium": 0.65,
    "high": 0.9,
    "critical": 0.98,
}

SAFE_PAGE_PATHS = {
    "/",
    "/login",
    "/sql",
    "/xss",
    "/upload",
    "/command",
    "/traversal",
    "/ssrf",
    "/xxe",
    "/deserialize",
    "/graphql",
    "/ssti",
    "/bruteforce",
}

SENSITIVE_CONTEXT_PATTERNS = [
    (re.compile(r"(?i)(/login|/auth|/signin|/session|/api/auth)"), 0.85, "认证接口"),
    (re.compile(r"(?i)(/upload|/file|/import)"), 0.75, "文件/导入接口"),
    (re.compile(r"(?i)(/admin|/manage|/config)"), 0.8, "管理接口"),
    (re.compile(r"(?i)(/search|/comment|/profile|/message)"), 0.6, "可回显接口"),
    (re.compile(r"(?i)(/ping|/system|/exec|/cmd)"), 0.9, "系统命令相关接口"),
]


def normalize_text(text: Any, rounds: int = 4) -> str:
    current = str(text or "")
    variants = []
    for _ in range(rounds):
        if current not in variants:
            variants.append(current)
        decoded = html.unescape(unquote_plus(current))
        if decoded == current:
            break
        current = decoded
    return "\n".join(variants)


def lower_norm(text: Any) -> str:
    return normalize_text(text).lower()


def split_request_response_summary(text: str) -> Tuple[str, str]:
    text = str(text or "")
    marker = "RESPONSE_EXCERPT="
    idx = text.upper().find(marker)
    if idx >= 0:
        return text[:idx], text[idx + len(marker):]
    return text, ""


def extract_body_from_raw_request(raw: str) -> str:
    raw = str(raw or "")
    if "\r\n\r\n" in raw:
        return raw.split("\r\n\r\n", 1)[1].strip()
    if "\n\n" in raw:
        return raw.split("\n\n", 1)[1].strip()
    m = re.search(r"(?is)\bBody:\s*(.*)$", raw)
    if m:
        return m.group(1).strip()
    m = re.search(r"(?is)REQUEST_BODY=(.*?)(?:\n[A-Z_]+=|$)", raw)
    if m:
        return m.group(1).strip()
    return ""


def extract_request_from_record(record: Dict[str, Any]) -> Dict[str, Any]:
    request_text = str(record.get("request_text") or record.get("request_text_summary") or "")
    request_side, response_side = split_request_response_summary(request_text)
    raw_request = str(record.get("raw_request_block") or record.get("request_content") or "")
    raw_response = str(record.get("raw_response_block") or record.get("response_content") or response_side or "")

    method = str(record.get("method") or "").upper()
    uri = str(record.get("uri") or "")
    host = str(record.get("host") or "")
    status_code = record.get("status_code")
    content_type = str(record.get("content_type") or "")
    user_agent = str(record.get("user_agent") or "")
    body = str(record.get("request_body") or "") or extract_body_from_raw_request(raw_request or request_side)

    if not method:
        m = re.search(r"(?im)^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)", raw_request or request_side)
        if m:
            method = m.group(1).upper()
            uri = uri or m.group(2)
    if not host:
        m = re.search(r"(?im)^\s*Host:\s*(.+?)\s*$", raw_request or request_side)
        if m:
            host = m.group(1).strip()
    if not content_type:
        m = re.search(r"(?im)^\s*Content-Type:\s*(.+?)\s*$", raw_request or request_side)
        if m:
            content_type = m.group(1).strip()
    if not user_agent:
        m = re.search(r"(?im)^\s*User-Agent:\s*(.+?)\s*$", raw_request or request_side)
        if m:
            user_agent = m.group(1).strip()

    return {
        "case_id": record.get("case_id"),
        "file_id": record.get("file_id"),
        "seq_id": record.get("seq_id"),
        "timestamp": record.get("attack_event_time") or record.get("created_at") or record.get("time"),
        "source_ip": record.get("source_ip") or record.get("attack_ip") or record.get("src_ip"),
        "destination_ip": record.get("destination_ip") or record.get("dst_ip"),
        "source_port": record.get("source_port") or record.get("src_port"),
        "destination_port": record.get("destination_port") or record.get("dst_port"),
        "method": method,
        "uri": uri,
        "host": host,
        "status_code": status_code,
        "content_type": content_type,
        "user_agent": user_agent,
        "body": body,
        "request_side": request_side,
        "response_side": response_side or raw_response,
        "raw_request": raw_request or request_side,
        "raw_response": raw_response,
    }


def request_detection_text(event: Dict[str, Any]) -> str:
    return "\n".join(
        str(x or "")
        for x in [
            event.get("method"),
            event.get("uri"),
            event.get("host"),
            event.get("content_type"),
            event.get("user_agent"),
            event.get("body"),
            event.get("request_side"),
            event.get("raw_request"),
        ]
    )


def payload_model_text(event: Dict[str, Any]) -> str:
    return normalize_text(
        "\n".join(
            [
                f"METHOD={event.get('method') or ''}",
                f"URI={event.get('uri') or ''}",
                f"HOST={event.get('host') or ''}",
                f"CONTENT_TYPE={event.get('content_type') or ''}",
                f"USER_AGENT={event.get('user_agent') or ''}",
                f"BODY={event.get('body') or ''}",
            ]
        )
    )


def parse_event_time(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            if fmt is None:
                return datetime.fromisoformat(text.replace("Z", "+00:00").replace(" ", "T"))
            return datetime.strptime(text, fmt)
        except Exception:
            continue
    return None


def is_simple_page_view(event: Dict[str, Any]) -> bool:
    method = str(event.get("method") or "").upper()
    uri = str(event.get("uri") or "")
    path = urlsplit(uri).path or uri
    body = str(event.get("body") or "").strip()
    if method != "GET":
        return False
    if "?" in uri or body:
        return False
    return path in SAFE_PAGE_PATHS


def context_score(event: Dict[str, Any]) -> Tuple[float, str]:
    uri = str(event.get("uri") or "")
    for pattern, score, reason in SENSITIVE_CONTEXT_PATTERNS:
        if pattern.search(uri):
            return score, reason
    return 0.15, "普通接口"


@dataclass
class POCMatch:
    rule_id: str
    name: str
    attack_type: str
    severity: str
    score: float
    evidence: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


class POCRuleEngine:
    def __init__(self, rules_path: Path | str = DEFAULT_RULES_PATH):
        self.rules_path = Path(rules_path)
        if not self.rules_path.is_file():
            raise FileNotFoundError(f"POC rule file is missing: {self.rules_path}")
        self.rules = json.loads(self.rules_path.read_text(encoding="utf-8-sig"))
        if not isinstance(self.rules, list) or not self.rules:
            raise ValueError(f"POC rule file contains no rules: {self.rules_path}")

    def match(self, event: Dict[str, Any]) -> List[POCMatch]:
        text = normalize_text(request_detection_text(event))
        path = str(urlsplit(str(event.get("uri") or "")).path or event.get("uri") or "")
        matches: List[POCMatch] = []
        for rule in self.rules:
            req = rule.get("request") or {}
            evidence: List[str] = []
            path_patterns = req.get("path_regex") or []
            if path_patterns and not any(re.search(p, path, flags=re.I | re.S) for p in path_patterns):
                continue
            ok = False
            for pattern in req.get("text_regex") or []:
                if re.search(pattern, text, flags=re.I | re.S):
                    ok = True
                    evidence.append(pattern)
            if ok or (path_patterns and not (req.get("text_regex") or [])):
                matches.append(
                    POCMatch(
                        rule_id=str(rule.get("id") or ""),
                        name=str(rule.get("name") or ""),
                        attack_type=str(rule.get("attack_type") or "可疑流量"),
                        severity=str(rule.get("severity") or "medium"),
                        score=float(rule.get("score") or SEVERITY_SCORE.get(str(rule.get("severity") or "medium"), 0.65)),
                        evidence=evidence,
                        tags=list(rule.get("tags") or []),
                    )
                )
        return matches


class PayloadModel:
    def __init__(self, model_path: Path | str = DEFAULT_MODEL_PATH):
        self.model_path = Path(model_path)
        self.bundle = joblib.load(self.model_path) if self.model_path.exists() else None
        self.model = self.bundle.get("model") if isinstance(self.bundle, dict) else self.bundle
        self.labels = list(self.bundle.get("labels", [])) if isinstance(self.bundle, dict) else []

    @property
    def available(self) -> bool:
        return self.model is not None

    def predict(self, event: Dict[str, Any]) -> Dict[str, Any]:
        if not self.available:
            return {"label": "unknown", "score": 0.0, "proba": {}}
        text = payload_model_text(event)
        label = str(self.model.predict([text])[0])
        proba: Dict[str, float] = {}
        if hasattr(self.model, "predict_proba"):
            values = self.model.predict_proba([text])[0]
            labels = list(getattr(self.model, "classes_", self.labels))
            proba = {str(k): float(v) for k, v in zip(labels, values)}
            score = float(max(proba.values())) if proba else 0.0
        else:
            score = 0.8 if label != "normal" else 0.1
        attack_score = 0.0 if label == "normal" else score
        return {"label": label, "score": attack_score, "confidence": score, "proba": proba}


class BehaviorWindowAnalyzer:
    def __init__(self, window_minutes: int = 5, model_path: Path | str = DEFAULT_BEHAVIOR_MODEL_PATH):
        self.window = timedelta(minutes=window_minutes)
        self.events_by_ip: Dict[str, deque] = defaultdict(deque)
        self.model_path = Path(model_path)
        self.model_bundle = None
        self.model = None
        self.model_features = []
        if self.model_path.exists():
            try:
                self.model_bundle = joblib.load(self.model_path)
                self.model = self.model_bundle.get("model") if isinstance(self.model_bundle, dict) else self.model_bundle
                self.model_features = list(self.model_bundle.get("features", [])) if isinstance(self.model_bundle, dict) else []
            except Exception:
                self.model_bundle = None
                self.model = None
                self.model_features = []

    def observe(self, event: Dict[str, Any], payload_or_rule_hit: bool = False) -> Dict[str, Any]:
        ip = str(event.get("source_ip") or "")
        t = parse_event_time(event.get("timestamp")) or datetime.now()
        if not ip:
            return {"score": 0.0, "type": "normal", "evidence": [], "features": {}}
        dq = self.events_by_ip[ip]
        item = {
            "time": t,
            "uri": str(event.get("uri") or ""),
            "path": urlsplit(str(event.get("uri") or "")).path,
            "method": str(event.get("method") or "").upper(),
            "status_code": int(event.get("status_code") or 0) if str(event.get("status_code") or "").isdigit() else 0,
            "ua": str(event.get("user_agent") or ""),
            "payload_or_rule_hit": bool(payload_or_rule_hit),
            "body": str(event.get("body") or ""),
        }
        dq.append(item)
        while dq and t - dq[0]["time"] > self.window:
            dq.popleft()
        return self.score_window(ip)

    def score_window(self, ip: str) -> Dict[str, Any]:
        items = list(self.events_by_ip.get(ip) or [])
        if not items:
            return {"score": 0.0, "type": "normal", "evidence": [], "features": {}}
        req_count = len(items)
        paths = {x["path"] for x in items if x["path"]}
        statuses = [x["status_code"] for x in items]
        login_items = [x for x in items if re.search(r"(?i)(/login|/auth|/signin|/session)", x["uri"])]
        login_fail = sum(1 for x in login_items if x["status_code"] in {0, 401, 403, 429} or re.search(r"(?i)(wrong|fail|invalid|error|denied)", x["body"]))
        not_found = sum(1 for x in items if x["status_code"] == 404)
        ua_count = len({x["ua"] for x in items if x["ua"]})
        payload_hits = sum(1 for x in items if x["payload_or_rule_hit"])
        status_5xx = sum(1 for x in items if 500 <= int(x["status_code"] or 0) <= 599)
        features = {
            "request_count": req_count,
            "distinct_path_count": len(paths),
            "login_request_count": len(login_items),
            "login_fail_count": login_fail,
            "not_found_count": not_found,
            "user_agent_count": ua_count,
            "payload_hit_count": payload_hits,
            "status_5xx_count": status_5xx,
        }
        evidence: List[str] = []
        score = 0.0
        typ = "normal"
        if login_fail >= 20:
            score, typ = 0.95, "暴力破解"
            evidence.append(f"{self.window} 内登录失败 {login_fail} 次")
        elif login_fail >= 8:
            score, typ = 0.82, "疑似暴力破解"
            evidence.append(f"{self.window} 内登录失败 {login_fail} 次")
        if len(paths) >= 25 and req_count >= 30:
            if score < 0.88:
                score, typ = 0.88, "扫描探测"
            evidence.append(f"{self.window} 内访问 {len(paths)} 个不同路径/{req_count} 次请求")
        elif len(paths) >= 10 and req_count >= 15:
            if score < 0.72:
                score, typ = 0.72, "疑似扫描探测"
            evidence.append(f"{self.window} 内访问 {len(paths)} 个不同路径/{req_count} 次请求")
        if not_found >= 10 and req_count >= 15:
            if score < 0.78:
                score, typ = 0.78, "目录探测"
            evidence.append(f"{self.window} 内 404 响应 {not_found} 次")
        if req_count >= 200:
            score, typ = max(score, 0.9), "高频请求"
            evidence.append(f"{self.window} 内请求 {req_count} 次")

        model_supported = self.behavior_model_supported(features)
        model_result = self.score_with_model(features) if model_supported else {"score": 0.0, "label": "not_enough_context", "type": "normal"}
        if float(model_result.get("score") or 0.0) > score:
            score = float(model_result.get("score") or 0.0)
            typ = str(model_result.get("type") or typ)
            evidence.append(f"行为模型判定 {typ}, score={score:.3f}")
        features["behavior_model_label"] = model_result.get("label") or ""
        features["behavior_model_score"] = model_result.get("score") or 0.0
        features["behavior_model_supported"] = model_supported
        return {"score": score, "type": typ, "evidence": evidence, "features": features}

    def behavior_model_supported(self, features: Dict[str, Any]) -> bool:
        req_count = int(features.get("request_count") or 0)
        distinct_path_count = int(features.get("distinct_path_count") or 0)
        login_fail_count = int(features.get("login_fail_count") or 0)
        not_found_count = int(features.get("not_found_count") or 0)
        payload_hit_count = int(features.get("payload_hit_count") or 0)
        status_5xx_count = int(features.get("status_5xx_count") or 0)
        if req_count < 12:
            return False
        return (
            login_fail_count >= 4
            or distinct_path_count >= 8
            or not_found_count >= 6
            or payload_hit_count >= 3
            or status_5xx_count >= 5
            or req_count >= 60
        )

    def score_with_model(self, features: Dict[str, Any]) -> Dict[str, Any]:
        if self.model is None or not self.model_features:
            return {"score": 0.0, "label": "unavailable", "type": "normal"}
        vector = [[float(features.get(k) or 0.0) for k in self.model_features]]
        try:
            label = str(self.model.predict(vector)[0])
            proba = {}
            if hasattr(self.model, "predict_proba"):
                values = self.model.predict_proba(vector)[0]
                labels = list(getattr(self.model, "classes_", []))
                proba = {str(k): float(v) for k, v in zip(labels, values)}
                normal_score = float(proba.get("normal", 0.0))
                score = max(0.0, 1.0 - normal_score)
            else:
                score = 0.75 if label != "normal" else 0.0
        except Exception:
            return {"score": 0.0, "label": "error", "type": "normal"}
        type_map = {
            "bruteforce": "暴力破解",
            "scan": "扫描探测",
            "high_frequency": "高频请求",
            "dir_probe": "目录探测",
            "payload_burst": "Payload异常突增",
            "normal": "normal",
        }
        return {"score": score if label != "normal" else 0.0, "label": label, "type": type_map.get(label, label)}


def severity_from_score(score: float) -> str:
    if score >= 0.9:
        return "critical"
    if score >= 0.75:
        return "high"
    if score >= 0.55:
        return "medium"
    if score >= 0.3:
        return "low"
    return "info"


def fuse_detection(
    event: Dict[str, Any],
    payload_pred: Dict[str, Any],
    poc_matches: List[POCMatch],
    behavior: Dict[str, Any],
    candidate_threshold: float = 0.65,
    event_threshold: float = 0.75,
) -> Dict[str, Any]:
    if is_simple_page_view(event) and not poc_matches:
        return {
            "decision": "raw_only",
            "final_score": 0.0,
            "attack_type": "正常访问",
            "risk_level": "info",
            "reason": "普通页面访问，无 query/body/POC 命中",
            "candidate": False,
            "attack_event": False,
            "evidence": [],
        }

    payload_label = str(payload_pred.get("label") or "unknown")
    payload_score = float(payload_pred.get("score") or 0.0)
    poc_score = max([m.score for m in poc_matches], default=0.0)
    behavior_score = float(behavior.get("score") or 0.0)
    ctx_score, ctx_reason = context_score(event)

    final_score = payload_score * 0.45 + behavior_score * 0.30 + poc_score * 0.20 + ctx_score * 0.05
    strong_poc = any(m.severity in {"high", "critical"} for m in poc_matches)
    # The bundled lab emits safe reconnaissance simulations instead of running a
    # real scanner. Promote only these explicitly tagged rules so their recon
    # stages reach the situation chain without weakening ordinary medium rules.
    simulation_recon_poc = any(
        m.attack_type in {"端口扫描", "目录扫描"}
        and m.score >= 0.75
        and "simulation" in {str(tag).strip().lower() for tag in m.tags}
        for m in poc_matches
    )
    behavior_features = behavior.get("features") or {}
    behavior_supported = bool(behavior_features.get("behavior_model_supported", True))
    strong_behavior = behavior_score >= 0.82 and behavior_supported
    high_payload = payload_score >= 0.90 and payload_label != "normal"

    candidate = final_score >= candidate_threshold or strong_poc or simulation_recon_poc or strong_behavior or high_payload
    attack_event = (
        final_score >= event_threshold
        or strong_poc
        or simulation_recon_poc
        or strong_behavior
        or payload_score >= 0.94
        or (payload_score >= 0.80 and poc_score >= 0.65)
    )

    strong_poc_matches = [m for m in poc_matches if m.severity in {"high", "critical"}]
    if strong_poc_matches:
        attack_type = sorted(
            strong_poc_matches,
            key=lambda m: (SEVERITY_SCORE.get(m.severity, 0), ATTACK_TYPE_PRIORITY.get(m.attack_type, 0), m.score),
            reverse=True,
        )[0].attack_type
    elif payload_label and payload_label not in {"normal", "unknown"}:
        attack_type = payload_label
    elif behavior_score >= 0.82:
        attack_type = str(behavior.get("type") or "行为异常")
    elif poc_matches:
        attack_type = sorted(poc_matches, key=lambda m: (ATTACK_TYPE_PRIORITY.get(m.attack_type, 0), m.score), reverse=True)[0].attack_type
    else:
        attack_type = "可疑流量"

    evidence = []
    evidence.extend([f"POC {m.rule_id}: {m.name}" for m in poc_matches[:5]])
    evidence.extend(list(behavior.get("evidence") or []))
    if payload_label not in {"normal", "unknown"}:
        evidence.append(f"Payload模型判定 {payload_label}, score={payload_score:.3f}")
    if ctx_score >= 0.75:
        evidence.append(f"上下文：{ctx_reason}")

    decision = "attack_event" if attack_event else ("candidate" if candidate else "raw_only")
    return {
        "decision": decision,
        "final_score": round(float(final_score), 6),
        "attack_type": attack_type,
        "risk_level": severity_from_score(max(final_score, poc_score, behavior_score, payload_score if payload_label != "normal" else 0.0)),
        "reason": "融合评分/规则/行为检测结果",
        "candidate": candidate,
        "attack_event": attack_event,
        "payload_score": round(payload_score, 6),
        "payload_label": payload_label,
        "behavior_score": round(behavior_score, 6),
        "behavior_type": behavior.get("type"),
        "poc_score": round(poc_score, 6),
        "context_score": round(ctx_score, 6),
        "context_reason": ctx_reason,
        "simulation_recon_poc": simulation_recon_poc,
        "poc_matches": [m.__dict__ for m in poc_matches],
        "behavior_features": behavior.get("features") or {},
        "evidence": evidence,
    }


class DetectionEngineV2:
    def __init__(
        self,
        model_path: Path | str = DEFAULT_MODEL_PATH,
        rules_path: Path | str = DEFAULT_RULES_PATH,
        behavior_model_path: Path | str = DEFAULT_BEHAVIOR_MODEL_PATH,
        behavior_window_minutes: int = 5,
    ):
        self.payload_model = PayloadModel(model_path)
        self.poc_engine = POCRuleEngine(rules_path)
        self.behavior = BehaviorWindowAnalyzer(behavior_window_minutes, behavior_model_path)

    def detect(self, record: Dict[str, Any]) -> Dict[str, Any]:
        event = extract_request_from_record(record)
        poc_matches = self.poc_engine.match(event)
        payload_pred = self.payload_model.predict(event)
        behavior = self.behavior.observe(event, payload_or_rule_hit=bool(poc_matches) or payload_pred.get("label") not in {"normal", "unknown"})
        fused = fuse_detection(event, payload_pred, poc_matches, behavior)
        return {"event": event, "payload": payload_pred, "poc_matches": [m.__dict__ for m in poc_matches], "behavior": behavior, "fusion": fused}


def iter_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)

