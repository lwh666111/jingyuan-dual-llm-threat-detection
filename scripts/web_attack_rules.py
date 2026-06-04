import html
import re
from typing import Dict, Optional
from urllib.parse import unquote_plus


AttackSignal = Dict[str, object]


def request_only_text(candidate: dict) -> str:
    """Build request-side text only, avoiding false positives from response summaries."""
    request_text = str(candidate.get("request_text") or "")
    request_lines = []
    for line in request_text.splitlines():
        if line.upper().startswith("RESPONSE_EXCERPT="):
            continue
        request_lines.append(line)

    return "\n".join(
        [
            str(candidate.get("method") or ""),
            str(candidate.get("uri") or ""),
            "\n".join(request_lines),
            str(candidate.get("raw_request_block") or ""),
        ]
    )


def normalize_attack_text(text: str) -> str:
    variants = []
    current = str(text or "")
    for _ in range(4):
        if current not in variants:
            variants.append(current)
        decoded = html.unescape(unquote_plus(current))
        if decoded == current:
            break
        current = decoded
    return "\n".join(variants).lower()


ATTACK_RULES = [
    {
        "attack_type": "XSS",
        "rule_score": 0.94,
        "reason": "请求中包含脚本标签、事件处理器或 JavaScript 协议等 XSS 特征",
        "patterns": [
            r"<\s*/?\s*script\b",
            r"<\s*(?:img|svg|iframe|body|input|details|marquee)\b[^>]*(?:onerror|onload|onclick|onmouseover)\s*=",
            r"\bon(?:error|load|click|mouseover|focus|submit)\s*=",
            r"\bjavascript\s*:",
            r"\balert\s*\(",
            r"\bdocument\s*\.\s*cookie\b",
            r"\beval\s*\(",
        ],
    },
    {
        "attack_type": "SQL注入",
        "rule_score": 0.93,
        "reason": "请求参数或请求体中包含 UNION SELECT、OR 1=1、注释截断或延时函数等 SQL 注入特征",
        "patterns": [
            r"\bunion\s+(?:all\s+)?select\b",
            r"(?:'|%27|\"|%22)?\s*\bor\b\s+(?:'|\")?\d+(?:'|\")?\s*=\s*(?:'|\")?\d+",
            r"(?:'|%27|\"|%22)?\s*\band\b\s+(?:'|\")?\d+(?:'|\")?\s*=\s*(?:'|\")?\d+",
            r"\binformation_schema\b",
            r"\bsleep\s*\(",
            r"\bbenchmark\s*\(",
            r"(?:--|#|/\*)\s*(?:$|[+\s])",
        ],
    },
    {
        "attack_type": "命令注入",
        "rule_score": 0.94,
        "reason": "请求中包含 shell 分隔符和系统命令调用特征",
        "patterns": [
            r"(?:;|\|\||&&)\s*(?:cat|whoami|id|uname|curl|wget|powershell|cmd\.exe|nc|bash|sh)\b",
            r"\b(?:powershell|cmd\.exe|/bin/sh|/bin/bash)\b",
        ],
    },
    {
        "attack_type": "路径遍历",
        "rule_score": 0.90,
        "reason": "请求路径或参数中包含目录回退和敏感系统文件访问特征",
        "patterns": [
            r"(?:\.\./|\.\.\\){2,}",
            r"(?:/etc/passwd|/etc/shadow|\\windows\\system32\\config)",
        ],
    },
    {
        "attack_type": "SSRF",
        "rule_score": 0.88,
        "reason": "请求中包含访问本机、内网或文件协议的 URL 参数特征",
        "patterns": [
            r"(?:url|target|redirect|callback|next)\s*=\s*(?:https?://)?(?:127\.0\.0\.1|localhost|0\.0\.0\.0|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)",
            r"(?:url|target|redirect|callback|next)\s*=\s*file://",
        ],
    },
    {
        "attack_type": "危险文件上传",
        "rule_score": 0.89,
        "reason": "上传文件名包含可执行脚本或系统可执行文件后缀",
        "patterns": [
            r"filename\s*=\s*[\"']?[^\"'\r\n]+\.(?:php|jsp|jspx|asp|aspx|exe|bat|cmd|ps1|sh)\b",
        ],
    },
]


def detect_request_attack(candidate: dict) -> Optional[AttackSignal]:
    text = normalize_attack_text(request_only_text(candidate))
    for rule in ATTACK_RULES:
        for pattern in rule["patterns"]:
            if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL):
                return {
                    "attack_type": rule["attack_type"],
                    "rule_score": float(rule["rule_score"]),
                    "rule_reason": rule["reason"],
                    "rule_pattern": pattern,
                }
    return None


def numeric_score(value, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def apply_rule_signal(candidate: dict, signal: Optional[AttackSignal]) -> dict:
    if not signal:
        return candidate

    original_score = numeric_score(
        candidate.get("original_model_score", candidate.get("raw_score", candidate.get("score")))
    )
    rule_score = numeric_score(signal.get("rule_score"))
    effective_score = max(original_score, rule_score)

    updated = dict(candidate)
    updated["original_model_score"] = original_score
    updated["raw_score"] = round(effective_score, 6)
    updated["rule_score"] = rule_score
    updated["rule_reason"] = signal.get("rule_reason")
    updated["rule_pattern"] = signal.get("rule_pattern")
    updated["attack_type"] = signal.get("attack_type")
    updated["label"] = "suspicious"
    updated["detection_source"] = "model+rule" if original_score >= rule_score else "rule"
    return updated
