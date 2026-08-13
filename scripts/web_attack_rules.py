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


def candidate_full_text(candidate: dict) -> str:
    return "\n".join(
        [
            str(candidate.get("method") or ""),
            str(candidate.get("uri") or ""),
            str(candidate.get("request_text") or ""),
            str(candidate.get("raw_request_block") or ""),
            str(candidate.get("raw_response_block") or ""),
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
        "reason": "Request contains script tag, event handler, JavaScript protocol, or sensitive script call.",
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
        "attack_type": "\u0053\u0051\u004c\u6ce8\u5165",
        "rule_score": 0.93,
        "reason": "Request contains UNION SELECT, OR 1=1, SQL comments, or time-delay SQL function.",
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
        "attack_type": "\u547d\u4ee4\u6ce8\u5165",
        "rule_score": 0.94,
        "reason": "Request contains shell separators and system command execution features.",
        "patterns": [
            r"(?:;|\|\||&&)\s*(?:cat|whoami|id|uname|curl|wget|powershell|cmd\.exe|nc|bash|sh)\b",
            r"\b(?:powershell|cmd\.exe|/bin/sh|/bin/bash)\b",
        ],
    },
    {
        "attack_type": "\u8def\u5f84\u904d\u5386",
        "rule_score": 0.90,
        "reason": "Request path or parameter contains directory traversal and sensitive file access features.",
        "patterns": [
            r"(?:\.\./|\.\.\\){2,}",
            r"(?:/etc/passwd|/etc/shadow|\\windows\\system32\\config)",
        ],
    },
    {
        "attack_type": "SSRF",
        "rule_score": 0.88,
        "reason": "Request contains URL parameters pointing to localhost, internal networks, or file protocol.",
        "patterns": [
            r"(?:url|target|redirect|callback|next)\s*=\s*(?:https?://)?(?:127\.0\.0\.1|localhost|0\.0\.0\.0|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)",
            r"(?:url|target|redirect|callback|next)\s*=\s*file://",
        ],
    },
    {
        "attack_type": "\u5371\u9669\u6587\u4ef6\u4e0a\u4f20",
        "rule_score": 0.89,
        "reason": "Uploaded filename uses executable script or system executable extension.",
        "patterns": [
            r"filename\s*=\s*[\"']?[^\"'\r\n]+\.(?:php|jsp|jspx|asp|aspx|exe|bat|cmd|ps1|sh)\b",
            r"(?s)(?=.*[\"']?filename[\"']?\s*[:=]\s*[\"'][^\"']+\.(?:php|phtml|php[3457]?|phar|jsp|jspx|asp|aspx|ashx|asmx)[\"'])(?=.*(?:<\?php|<%@\s*page|<%\s*(?:eval|runtime)|runtime\.getruntime\(\)\.exec|processbuilder\s*\(|(?:system|exec|passthru|shell_exec)\s*\())",
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


def is_plain_auth_attempt(candidate: dict) -> bool:
    """Return True for a single ordinary login attempt without attack/rate-limit signals."""
    method = str(candidate.get("method") or "").upper()
    uri = str(candidate.get("uri") or "").lower()
    if method not in {"POST", "PUT"}:
        return False
    if not re.search(r"(?:/login|/auth|/signin|/session|/api/auth/login)", uri, flags=re.I):
        return False

    # Payload attacks on login endpoints must still be exported.
    if detect_request_attack(candidate):
        return False

    request_text = normalize_attack_text(request_only_text(candidate))
    full_text = normalize_attack_text(candidate_full_text(candidate))
    if not re.search(r"(?:username|user|account|login|password|passwd|pwd)", request_text, flags=re.I):
        return False

    # Multiple failures / throttling can be a real brute-force signal, so do not whitelist it.
    if re.search(
        r"(?:too\s+many|rate\s*limit|brute\s*force|errauth|captcha|locked|blocked|attempts?\s*[:=]\s*(?:[5-9]|\d{2,}))",
        full_text,
        flags=re.I,
    ):
        return False

    return True


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
