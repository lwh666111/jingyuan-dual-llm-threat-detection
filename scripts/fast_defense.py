from __future__ import annotations

import hashlib
import html
import json
import queue
import re
import threading
import time
import unicodedata
import urllib.parse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

import pymysql
from pymysql.cursors import DictCursor

try:
    from firewall_control import firewall_block_ip, firewall_status, is_safe_automatic_target, normalize_ip_literal
except ImportError:  # package import during tests
    from scripts.firewall_control import firewall_block_ip, firewall_status, is_safe_automatic_target, normalize_ip_literal


AUDIT_DDL = """
CREATE TABLE IF NOT EXISTS demo_fast_defense_audit (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  request_fingerprint CHAR(64) NOT NULL,
  source_ip VARCHAR(64) NOT NULL,
  destination_ip VARCHAR(64) NOT NULL DEFAULT '',
  method VARCHAR(16) NOT NULL DEFAULT '',
  uri TEXT NOT NULL,
  category VARCHAR(64) NOT NULL,
  score INT NOT NULL,
  rule_ids_json TEXT NOT NULL,
  decision VARCHAR(32) NOT NULL,
  firewall_success TINYINT(1) NOT NULL DEFAULT 0,
  firewall_detail TEXT NOT NULL,
  request_time DATETIME(3) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_fast_ip_time (source_ip, created_at),
  KEY idx_fast_category_time (category, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
"""


@dataclass(frozen=True)
class FastRule:
    rule_id: str
    category: str
    score: int
    all_patterns: Sequence[re.Pattern[str]]
    any_patterns: Sequence[re.Pattern[str]]
    exclude_patterns: Sequence[re.Pattern[str]]


@dataclass(frozen=True)
class FastDecision:
    source_ip: str
    destination_ip: str
    method: str
    uri: str
    request_time: Optional[datetime]
    category: str
    score: int
    rule_ids: Sequence[str]
    fingerprint: str


def _compile_many(values: Iterable[str]) -> List[re.Pattern[str]]:
    return [re.compile(str(value), re.I | re.S) for value in values if str(value).strip()]


def normalize_request_text(request: Dict[str, Any]) -> str:
    raw = "\n".join(
        str(request.get(key) or "")
        for key in ("method", "uri", "host", "content_type", "request_body")
    )
    variants: List[str] = []
    current = raw
    for _ in range(4):
        current = html.unescape(urllib.parse.unquote_plus(current))
        current = unicodedata.normalize("NFKC", current).replace("\x00", "")
        current = re.sub(r"[\t\r\f\v]+", " ", current)
        current = re.sub(r" +", " ", current).lower()
        if current in variants:
            break
        variants.append(current)
    return "\n".join(variants)


class FastRuleEngine:
    def __init__(self, rules_path: Path | str):
        self.rules_path = Path(rules_path)
        rows = json.loads(self.rules_path.read_text(encoding="utf-8-sig"))
        if not isinstance(rows, list) or not rows:
            raise ValueError(f"fast defense rules are empty: {self.rules_path}")
        self.rules = [
            FastRule(
                rule_id=str(row["id"]),
                category=str(row["category"]),
                score=int(row.get("score", 10)),
                all_patterns=_compile_many(row.get("all_regex") or []),
                any_patterns=_compile_many(row.get("any_regex") or []),
                exclude_patterns=_compile_many(row.get("exclude_regex") or []),
            )
            for row in rows
            if bool(row.get("instant_block", True))
        ]

    def match(self, request: Dict[str, Any]) -> List[FastRule]:
        text = normalize_request_text(request)
        matches: List[FastRule] = []
        for rule in self.rules:
            if rule.exclude_patterns and any(pattern.search(text) for pattern in rule.exclude_patterns):
                continue
            if rule.all_patterns and not all(pattern.search(text) for pattern in rule.all_patterns):
                continue
            if rule.any_patterns and not any(pattern.search(text) for pattern in rule.any_patterns):
                continue
            if rule.all_patterns or rule.any_patterns:
                matches.append(rule)
        return matches

    def decide(self, request: Dict[str, Any]) -> Optional[FastDecision]:
        source_ip = normalize_ip_literal(request.get("src_ip"))
        if not is_safe_automatic_target(source_ip, allow_private=False):
            return None
        matches = self.match(request)
        if not matches:
            return None
        highest = max(matches, key=lambda item: item.score)
        rule_ids = tuple(dict.fromkeys(rule.rule_id for rule in matches))
        fingerprint_text = "|".join(
            [
                source_ip,
                str(request.get("frame_no") or ""),
                str(request.get("time") or ""),
                str(request.get("method") or ""),
                str(request.get("uri") or ""),
                str(request.get("request_body") or ""),
            ]
        )
        request_time = None
        try:
            timestamp = float(request.get("time") or 0)
            request_time = datetime.fromtimestamp(timestamp) if timestamp > 0 else None
        except (TypeError, ValueError, OSError):
            pass
        return FastDecision(
            source_ip=source_ip,
            destination_ip=normalize_ip_literal(request.get("dst_ip")),
            method=str(request.get("method") or "").upper(),
            uri=str(request.get("uri") or "")[:8192],
            request_time=request_time,
            category=highest.category,
            score=max(rule.score for rule in matches),
            rule_ids=rule_ids,
            fingerprint=hashlib.sha256(fingerprint_text.encode("utf-8", errors="replace")).hexdigest(),
        )


class FastDefenseGuard:
    """Evaluate requests inline and enforce decisions on a bounded worker queue."""

    def __init__(
        self,
        rules_path: Path | str,
        mysql_config: Dict[str, Any],
        log_path: Path | str,
        policy_cache_seconds: float = 1.0,
    ):
        self.engine = FastRuleEngine(rules_path)
        self.mysql_config = dict(mysql_config)
        self.log_path = Path(log_path)
        self.policy_cache_seconds = max(0.2, float(policy_cache_seconds))
        self._enabled = False
        self._policy_checked_at = 0.0
        self._queue: queue.Queue[Optional[FastDecision]] = queue.Queue(maxsize=256)
        self._pending_ips: set[str] = set()
        self._lock = threading.Lock()
        self._closed = False
        self._worker = threading.Thread(target=self._worker_loop, name="fast-defense", daemon=True)
        self._worker.start()

    def _connect(self, autocommit: bool = False):
        return pymysql.connect(
            host=self.mysql_config["host"],
            port=int(self.mysql_config["port"]),
            user=self.mysql_config["user"],
            password=self.mysql_config["password"],
            database=self.mysql_config["database"],
            charset="utf8mb4",
            cursorclass=DictCursor,
            autocommit=autocommit,
            connect_timeout=2,
            read_timeout=3,
            write_timeout=3,
        )

    def _log(self, message: str) -> None:
        line = f"[{datetime.now().isoformat(timespec='seconds')}] {message}"
        print(line, flush=True)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def enabled(self) -> bool:
        now = time.monotonic()
        if now - self._policy_checked_at < self.policy_cache_seconds:
            return self._enabled
        self._policy_checked_at = now
        try:
            conn = self._connect(autocommit=True)
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT config_value FROM demo_system_config WHERE config_key='auto_defense_enabled' LIMIT 1"
                    )
                    row = cur.fetchone() or {}
                self._enabled = str(row.get("config_value") or "0") == "1"
            finally:
                conn.close()
        except Exception as exc:
            self._enabled = False
            self._log(f"policy read failed; fast path disabled: {type(exc).__name__}: {exc}")
        return self._enabled

    def inspect(self, request: Dict[str, Any]) -> Optional[FastDecision]:
        if self._closed or not self.enabled():
            return None
        decision = self.engine.decide(request)
        if decision is None:
            return None
        with self._lock:
            if decision.source_ip in self._pending_ips:
                return decision
            self._pending_ips.add(decision.source_ip)
        try:
            self._queue.put_nowait(decision)
        except queue.Full:
            with self._lock:
                self._pending_ips.discard(decision.source_ip)
            self._log(f"decision queue full; ip={decision.source_ip}")
        return decision

    def _already_blocked(self, cur: Any, ip_address: str) -> bool:
        cur.execute("SELECT id FROM demo_blocked_ips WHERE ip_address=%s LIMIT 1", (ip_address,))
        return bool(cur.fetchone()) and bool(firewall_status(ip_address).get("active"))

    def _enforce(self, decision: FastDecision) -> None:
        conn = self._connect(autocommit=False)
        try:
            with conn.cursor() as cur:
                cur.execute(AUDIT_DDL)
                already_blocked = self._already_blocked(cur, decision.source_ip)
                if already_blocked:
                    firewall_ok, firewall_detail = True, "already_blocked"
                else:
                    firewall_ok, firewall_detail = firewall_block_ip(decision.source_ip)
                cur.execute(
                    """
                    INSERT INTO demo_fast_defense_audit(
                      request_fingerprint,source_ip,destination_ip,method,uri,category,score,
                      rule_ids_json,decision,firewall_success,firewall_detail,request_time
                    ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        decision.fingerprint,
                        decision.source_ip,
                        decision.destination_ip,
                        decision.method,
                        decision.uri,
                        decision.category,
                        decision.score,
                        json.dumps(list(decision.rule_ids), ensure_ascii=False),
                        "silent_block" if firewall_ok else "block_failed",
                        1 if firewall_ok else 0,
                        firewall_detail[:4000],
                        decision.request_time,
                    ),
                )
                if firewall_ok:
                    cur.execute("DELETE FROM demo_auto_defense_releases WHERE ip_address=%s", (decision.source_ip,))
                    cur.execute(
                        """
                        INSERT INTO demo_blocked_ips(ip_address,source_event_id,reason,blocked_by,blocked_role)
                        VALUES(%s,'','automatic_protection','auto-defense','system')
                        ON DUPLICATE KEY UPDATE source_event_id='',reason='automatic_protection',
                          blocked_by='auto-defense',blocked_role='system',blocked_at=CURRENT_TIMESTAMP
                        """,
                        (decision.source_ip,),
                    )
            conn.commit()
            self._log(
                f"silent decision ip={decision.source_ip} category={decision.category} "
                f"rules={','.join(decision.rule_ids)} success={int(firewall_ok)}"
            )
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _worker_loop(self) -> None:
        while True:
            decision = self._queue.get()
            if decision is None:
                self._queue.task_done()
                return
            try:
                self._enforce(decision)
            except Exception as exc:
                self._log(f"enforcement failed ip={decision.source_ip}: {type(exc).__name__}: {exc}")
            finally:
                with self._lock:
                    self._pending_ips.discard(decision.source_ip)
                self._queue.task_done()

    def close(self, timeout: float = 8.0) -> None:
        self._closed = True
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            return
        self._worker.join(timeout=max(0.1, timeout))
