import argparse
import json
import os
import re
import sqlite3
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pipeline_events import LLM_READY_EVENT, wait_event


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _cached_review_ready_at(event_time, now=None) -> Optional[datetime]:
    if isinstance(event_time, str):
        try:
            event_time = datetime.fromisoformat(event_time)
        except (TypeError, ValueError):
            return None
    if not isinstance(event_time, datetime):
        return None

    if event_time.tzinfo is not None:
        current = now if isinstance(now, datetime) else datetime.now(tz=event_time.tzinfo)
        if current.tzinfo is None:
            current = current.replace(tzinfo=event_time.tzinfo)
        else:
            current = current.astimezone(event_time.tzinfo)
    else:
        current = now if isinstance(now, datetime) else datetime.now()
        if current.tzinfo is not None:
            current = current.astimezone().replace(tzinfo=None)

    age = current - event_time
    if age < timedelta(seconds=-60) or age > timedelta(minutes=10):
        return current + timedelta(seconds=5)
    return event_time + timedelta(seconds=5)


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", flush=True)


def read_json(path: Path, default=None):
    if default is None:
        default = {}
    if not path.exists():
        return default
    for enc in ("utf-8", "utf-8-sig", "gbk", "latin1"):
        try:
            return json.loads(path.read_text(encoding=enc))
        except Exception:
            continue
    return default


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def read_text(path: Path, default: str = "") -> str:
    if not path.exists():
        return default
    return path.read_text(encoding="utf-8", errors="replace")


def load_system_prompt(prompt_path: Path) -> Tuple[str, float]:
    system_prompt = read_text(prompt_path)
    if not system_prompt.strip():
        raise RuntimeError(f"prompt 为空: {prompt_path}")
    prompt_mtime = prompt_path.stat().st_mtime if prompt_path.exists() else 0.0
    return system_prompt, prompt_mtime


def find_case_dirs(result_dir: Path) -> List[Path]:
    dirs = []
    for p in result_dir.glob("b.*"):
        if p.is_dir():
            dirs.append(p)
    dirs.sort(key=lambda x: int(x.name.split(".", 1)[1]) if x.name.split(".", 1)[1].isdigit() else 10**9)
    return dirs


def parse_ip_from_text(text: str) -> Optional[str]:
    if not text:
        return None
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    return m.group(0) if m else None


def parse_case_ips_from_input(input_file: Path, seq_id: int) -> Tuple[Optional[str], Optional[str]]:
    if not input_file.exists():
        return None, None

    text = read_text(input_file)
    if "### CASE_START ###" not in text:
        return None, None

    blocks = re.findall(r"### CASE_START ###(.*?)### CASE_END ###", text, flags=re.DOTALL)
    for block in blocks:
        data = {}
        for line in block.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                data[k.strip()] = v.strip()
        try:
            sid = int(data.get("seq_id", "0"))
        except Exception:
            sid = 0
        if sid == seq_id:
            return data.get("src_ip"), data.get("dst_ip")

    return None, None


def build_user_payload(
    case_obj: Dict,
    request_text: str,
    response_text: str,
    src_ip: str,
    dst_ip: str,
    rag_context: str = "",
    detection_context: Optional[Dict] = None,
) -> str:
    safe_case = {
        "case_id": case_obj.get("case_id"),
        "file_id": case_obj.get("file_id"),
        "seq_id": case_obj.get("seq_id"),
        "method": case_obj.get("method"),
        "uri": case_obj.get("uri"),
        "host": case_obj.get("host"),
        "status_code": case_obj.get("status_code"),
        "source_ip": src_ip,
        "destination_ip": dst_ip,
    }

    body = {
        "meta": safe_case,
        # The deterministic layers already retain the full packet. Keep the
        # semantic review payload compact so CPU-only Ollama can answer fast.
        "request_block": request_text[:3000],
        "response_block": response_text[:1200],
        "detection_context": detection_context or {},
        "retrieved_knowledge": rag_context[:6000] if rag_context else "",
    }
    return json.dumps(body, ensure_ascii=False)


def ensure_rag_db(db_path: Path, seed_path: Path, auto_build: bool = True) -> None:
    if db_path.exists():
        return
    if not auto_build:
        log(f"RAG db not found and auto build disabled: {db_path}")
        return
    if not seed_path.exists():
        log(f"RAG seed file not found, skip auto build: {seed_path}")
        return
    try:
        from build_rag_db import build_rag_db, read_seed

        rows = read_seed(seed_path)
        count = build_rag_db(db_path, rows)
        log(f"RAG db auto built: {db_path} rows={count}")
    except Exception as exc:  # noqa: BLE001
        log(f"RAG db auto build failed: {exc}")


def build_rag_match_query(text: str, max_terms: int = 12) -> str:
    terms = re.findall(r"[a-zA-Z0-9_./:-]{2,}", (text or "").lower())
    uniq: List[str] = []
    seen = set()
    for t in terms:
        if t in seen:
            continue
        seen.add(t)
        uniq.append(t)
        if len(uniq) >= max_terms:
            break
    if not uniq:
        return ""
    escaped = [f'"{t.replace("\"", "")}"' for t in uniq if t.strip()]
    return " OR ".join(escaped)


def retrieve_rag_docs(db_path: Path, query_text: str, top_k: int = 3) -> List[Dict]:
    if not db_path.exists():
        return []

    rows: List[Dict] = []
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        match_query = build_rag_match_query(query_text, max_terms=14)

        if match_query:
            try:
                cur.execute(
                    """
                    SELECT
                      doc_id, title, attack_type, evidence, mitigation, severity, source,
                      bm25(rag_docs) AS score
                    FROM rag_docs
                    WHERE rag_docs MATCH ?
                    ORDER BY score ASC
                    LIMIT ?
                    """,
                    (match_query, max(1, top_k)),
                )
                for row in cur.fetchall():
                    rows.append(dict(row))
            except sqlite3.OperationalError:
                rows = []

        if rows:
            return rows

        fallback_tokens = re.findall(r"[a-zA-Z0-9_./:-]{2,}", (query_text or "").lower())
        keyword = fallback_tokens[0] if fallback_tokens else "login"
        pattern = f"%{keyword}%"
        cur.execute(
            """
            SELECT
              doc_id, title, attack_type, evidence, mitigation, severity, source,
              0.0 AS score
            FROM rag_docs
            WHERE tags LIKE ? OR content LIKE ? OR title LIKE ?
            LIMIT ?
            """,
            (pattern, pattern, pattern, max(1, top_k)),
        )
        return [dict(r) for r in cur.fetchall()]


def retrieve_advanced_rag(args, query_text: str) -> List[Dict]:
    """Run the cloud-embedding hybrid retriever and map results to legacy fields."""
    try:
        from rag_service import hybrid_search, list_kbs, load_api_config, mysql_connect

        mysql_conf = {
            "host": args.rag_mysql_host,
            "port": args.rag_mysql_port,
            "user": args.rag_mysql_user,
            "password": args.rag_mysql_password,
            "database": args.rag_mysql_database,
        }
        api_config = load_api_config(args.rag_api_config)
        if not api_config.get("api_key"):
            return []
        with mysql_connect(mysql_conf, autocommit=False) as conn:
            kbs = list_kbs(conn, include_disabled=False)
            if not kbs:
                return []
            result = hybrid_search(
                conn,
                args.rag_data_dir,
                api_config,
                int(kbs[0]["id"]),
                query_text,
                username="llm-daemon",
                save_test=False,
            )
        return [
            {
                "doc_id": f"DOC-{item.get('document_id')}-CHUNK-{item.get('chunk_id')}",
                "title": item.get("title_path") or item.get("document_name") or "知识片段",
                "attack_type": "",
                "evidence": item.get("content") or "",
                "mitigation": "",
                "severity": "",
                "source": item.get("document_name") or "advanced-rag",
                "score": item.get("score") or 0,
            }
            for item in (result.get("items") or [])[: max(1, int(args.rag_top_k))]
        ]
    except Exception as exc:
        log(f"advanced RAG fallback to legacy: {exc}")
        return []


def format_rag_context(rows: List[Dict], max_chars: int = 3200) -> str:
    if not rows:
        return ""
    lines: List[str] = []
    for idx, row in enumerate(rows, start=1):
        lines.append(
            (
                f"[RAG#{idx}] title={row.get('title','')} attack_type={row.get('attack_type','')} "
                f"severity={row.get('severity','')} evidence={row.get('evidence','')} "
                f"mitigation={row.get('mitigation','')}"
            )
        )
    text = "\n".join(lines)
    return text[:max_chars]


def build_rag_references(rows: List[Dict]) -> List[str]:
    """Build citations only from chunks actually retrieved for this request."""
    references: List[str] = []
    for idx, row in enumerate(rows[:4], start=1):
        title = str(row.get("title") or row.get("source") or "知识片段").strip()
        doc_id = str(row.get("doc_id") or "").strip()
        label = f"RAG#{idx} {title}"
        if doc_id:
            label += f"（{doc_id}）"
        if label not in references:
            references.append(label)
    return references


def call_ollama_chat(
    base_url: str,
    model: str,
    system_prompt: str,
    user_payload: str,
    schema_obj: Dict,
    timeout_sec: int,
    num_ctx: int,
    num_gpu: int,
    temperature: float,
) -> Tuple[Dict, str]:
    url = base_url.rstrip("/") + "/api/chat"

    req_obj = {
        "model": model,
        "stream": False,
        "keep_alive": os.environ.get("OLLAMA_KEEP_ALIVE", "5m"),
        "format": schema_obj,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_payload},
        ],
        "options": {
            "num_ctx": max(2048, num_ctx),
            "num_gpu": num_gpu,
            "temperature": temperature,
            "num_predict": 512,
        },
    }

    data = json.dumps(req_obj, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        url=url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout_sec) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    except Exception as exc:
        raise RuntimeError(str(exc)) from exc

    outer = json.loads(raw)
    content = outer.get("message", {}).get("content", "")

    try:
        parsed = json.loads(content)
    except Exception:
        # 容错：如果模型没有严格输出 JSON，包一层
        parsed = {
            "verdict": "unknown",
            "source_ip": "unknown",
            "destination_ip": "unknown",
            "attack_interface": "unknown",
            "attack_method": "unknown",
            "attack_path": "unknown",
            "attack_time": now_iso(),
            "severity": "unknown",
            "confidence": 0.0,
            "evidence": [],
            "analysis_reasoning": content[:500],
            "potential_impact": ["模型未返回合法 JSON，暂无法确认具体影响"],
            "immediate_actions": ["保留原始请求并转人工复核"],
            "hardening_actions": ["核验接口输入校验与安全日志配置"],
            "false_positive_notes": "模型输出格式异常，不能据此确认攻击。",
            "knowledge_references": [],
            "summary": content[:500],
        }

    return parsed, content


def warm_ollama_model(base_url: str, model: str, timeout_sec: int = 60) -> None:
    """Load model weights before traffic arrives and retain them for the demo window."""
    data = json.dumps(
        {
            "model": model, "prompt": "ready", "stream": False,
            "keep_alive": os.environ.get("OLLAMA_KEEP_ALIVE", "15m"),
            "options": {"num_predict": 1},
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        base_url.rstrip("/") + "/api/generate", data=data,
        method="POST", headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=max(5, int(timeout_sec))) as response:
        response.read()


def fetch_available_models(base_url: str, timeout_sec: int = 10) -> List[str]:
    url = base_url.rstrip("/") + "/api/tags"
    req = urllib.request.Request(url=url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        obj = json.loads(raw)
    except Exception:
        return []

    rows = obj.get("models")
    if not isinstance(rows, list):
        return []
    names: List[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip()
        if name:
            names.append(name)
    return names


def resolve_model_name(base_url: str, preferred_model: str, timeout_sec: int = 10) -> str:
    preferred = str(preferred_model or "").strip()
    if not preferred:
        preferred = "qwen3:8b"

    models = fetch_available_models(base_url=base_url, timeout_sec=timeout_sec)
    if not models:
        log(f"cannot read Ollama model list, keep configured model: {preferred}")
        return preferred

    if preferred in models:
        return preferred

    fallback = models[0]
    log(f"configured model '{preferred}' not found, fallback to installed model: {fallback}")
    return fallback


def infer_trusted_attack_type(case_obj: Dict, parsed: Dict) -> str:
    for key in ("attack_type", "v2_payload_label"):
        label = str(case_obj.get(key) or "").strip()
        if label and "\ufffd" not in label:
            return label

    text = "\n".join(
        str(case_obj.get(key) or "") for key in ("uri", "request_text", "rule_reason")
    ).lower()
    rules = [
        (r"(?:union\s+select|information_schema|sleep\s*\(|\bor\s+1\s*=\s*1)", "SQL注入"),
        (r"(?:<script|javascript:|onerror\s*=|onload\s*=)", "XSS"),
        (r"(?:\.\./|%2e%2e|/etc/passwd|windows[\\/]system32)", "路径遍历"),
        (r"(?:cmd\.exe|/bin/sh|powershell|runtime\.getruntime|processbuilder)", "命令注入"),
        (r"(?:multipart/form-data|\.php\b|\.jsp\b|\.aspx\b)", "文件上传"),
    ]
    for pattern, label in rules:
        if re.search(pattern, text, re.I):
            return label

    parsed_label = str(parsed.get("attack_method") or "").strip()
    return parsed_label if parsed_label and "\ufffd" not in parsed_label else "可疑流量"


def normalize_analysis(parsed: Dict, case_obj: Dict, src_ip: str, dst_ip: str, model_name: str) -> Dict:
    uri = str(case_obj.get("uri") or "unknown")
    method = str(case_obj.get("method") or "")
    trusted_source_ip = str(case_obj.get("source_ip") or src_ip or "unknown")
    trusted_destination_ip = str(case_obj.get("destination_ip") or dst_ip or "unknown")
    trusted_attack_type = infer_trusted_attack_type(case_obj, parsed)
    trusted_attack_path = f"{method} {uri}".strip() or uri
    trusted_attack_time = str(case_obj.get("export_time") or now_iso())
    verdict_raw = str(parsed.get("verdict") or "unknown").strip().lower()
    if any(token in verdict_raw for token in ("attack", "malicious", "攻击", "恶意")):
        verdict = "attack"
    elif any(token in verdict_raw for token in ("benign", "normal", "safe", "正常", "安全")):
        verdict = "benign"
    else:
        verdict = "unknown"
    severity = str(parsed.get("severity") or case_obj.get("v2_risk_level") or "unknown")
    confidence = float(parsed.get("confidence", 0.0) or 0.0)
    if 1 < confidence <= 100:
        confidence /= 100.0
    confidence = max(0.0, min(1.0, confidence))
    confidence_percent = confidence * 100
    source_material = "\n".join(
        str(case_obj.get(key) or "")
        for key in ("uri", "request_text", "response_text", "detection_context")
    ).lower()

    signature_terms = {
        "xss": ("script", "onerror", "onload", "javascript:", "xss"),
        "sql": ("union", "select", "information_schema", "sleep(", "sql", "or 1=1"),
        "命令": ("cmd.exe", "/bin/sh", "powershell", "whoami", "命令注入", "$(`", "&&"),
        "路径": ("../", "..\\", "%2e%2e", "/etc/passwd", "win.ini", "路径遍历"),
    }

    def evidence_is_grounded(item: str) -> bool:
        lowered = item.lower()
        for label, terms in signature_terms.items():
            if label in lowered and not any(term in source_material for term in terms):
                return False
        if "script" in lowered and "script" not in source_material:
            return False
        if re.search(r"(?:参数|parameter)\s*[qQ](?:\s|：|:)", item) and not re.search(r"[?&]q=|\"q\"", source_material):
            return False
        return True

    parsed_evidence = parsed.get("evidence") if isinstance(parsed.get("evidence"), list) else []
    grounded_evidence = [
        str(item).strip() for item in parsed_evidence
        if str(item).strip() and evidence_is_grounded(str(item))
    ][:6]
    context = case_obj.get("detection_context") if isinstance(case_obj.get("detection_context"), dict) else {}
    fusion_score = float(context.get("fusion_score") or 0.0)
    poc_rows = context.get("poc_matches") if isinstance(context.get("poc_matches"), list) else []
    payload_rows = context.get("payload_models") if isinstance(context.get("payload_models"), list) else []
    strong_payload = any(float(item.get("score") or 0.0) >= 0.85 for item in payload_rows if isinstance(item, dict))
    model_summary = str(parsed.get("summary") or "").strip()
    if verdict == "benign" and fusion_score >= 0.8 and poc_rows and strong_payload:
        verdict = "unknown"
        severity = "unknown"
        confidence = min(confidence, 0.49)
        model_summary = "大模型结论与多源强证据发生冲突，系统已阻止其发布为正常流量并转入人工复核。"
    if not grounded_evidence:
        pocs = poc_rows
        predictions = payload_rows
        if pocs:
            grounded_evidence.append(f"POC 规则：{pocs[0].get('rule_name') or pocs[0].get('rule_id') or '明确规则命中'}")
        elif predictions:
            pred = predictions[0]
            grounded_evidence.append(
                f"Payload 模型：{pred.get('label') or 'unknown'}，评分 {float(pred.get('score') or 0):.2f}"
            )
        else:
            grounded_evidence.append("大模型复核：输入中未发现可独立验证的明确攻击特征")
    if verdict == "attack" and confidence >= 0.8:
        model_summary = model_summary.replace("证据不足", "尚无成功利用证据")
    trusted_summary = model_summary or (
        f"来源 {trusted_source_ip} 对 {uri} 的请求经大模型复核为 {verdict}，"
        f"攻击类型为 {trusted_attack_type}，风险等级 {severity}，"
        f"置信度约 {confidence_percent:.1f}%。"
    )

    def clean_list(name: str, limit: int = 4) -> List[str]:
        value = parsed.get(name)
        if not isinstance(value, list):
            return []
        return [str(item).strip() for item in value if str(item).strip()][:limit]

    immediate_actions = clean_list("immediate_actions")
    hardening_actions = clean_list("hardening_actions")
    attack_type_lower = trusted_attack_type.lower()
    if "xss" in attack_type_lower:
        hardening_actions = [item for item in hardening_actions if "参数化查询" not in item and "sql" not in item.lower()]
        defaults = ["按 HTML/属性/JavaScript 上下文执行输出编码", "部署 CSP 并使用可信 HTML Sanitizer 处理富文本"]
        hardening_actions = (hardening_actions + [item for item in defaults if item not in hardening_actions])[:4]
    elif "sql" in attack_type_lower:
        defaults = ["数据库访问统一使用参数化查询或预编译语句", "限制数据库账户权限并隐藏详细数据库错误"]
        hardening_actions = (hardening_actions + [item for item in defaults if item not in hardening_actions])[:4]

    if verdict == "benign":
        immediate_actions = [item for item in immediate_actions if "封禁" not in item and "拦截" not in item]

    analysis_reasoning = str(parsed.get("analysis_reasoning") or "").strip()
    if analysis_reasoning and not evidence_is_grounded(analysis_reasoning):
        analysis_reasoning = (
            f"大模型结合抓包事实、融合评分及可复核证据，将该请求判定为 {verdict}；"
            "原模型推理包含无法在输入中定位的特征，已由一致性校验移除。"
        )

    return {
        "case_id": str(case_obj.get("case_id") or ""),
        "file_id": str(case_obj.get("file_id") or ""),
        "seq_id": int(case_obj.get("seq_id") or 0),
        # Network facts come from packet capture and the deterministic detector.
        # A small LLM may hallucinate these fields, so it must not overwrite them.
        "source_ip": trusted_source_ip,
        "destination_ip": trusted_destination_ip,
        "attack_interface": uri,
        "attack_method": trusted_attack_type,
        "attack_path": trusted_attack_path,
        "attack_time": trusted_attack_time,
        "severity": severity,
        "confidence": confidence,
        "verdict": verdict,
        "evidence": grounded_evidence,
        "summary": trusted_summary,
        "llm_explanation": analysis_reasoning or model_summary,
        "analysis_reasoning": analysis_reasoning,
        "potential_impact": clean_list("potential_impact"),
        "immediate_actions": immediate_actions,
        "hardening_actions": hardening_actions,
        "false_positive_notes": str(parsed.get("false_positive_notes") or "").strip(),
        "knowledge_references": clean_list("knowledge_references"),
        "model_name": model_name,
        "analyzed_at": now_iso(),
    }


def should_retry_llm_error(err_text: str) -> bool:
    text = (err_text or "").lower()
    retry_tokens = [
        "timed out",
        "connection refused",
        "winerror 10061",
        "llama runner process has terminated",
        "http 500",
        "internal server error",
    ]
    return any(tok in text for tok in retry_tokens)


def process_case(
    case_dir: Path,
    input_dir: Path,
    system_prompt: str,
    schema_obj: Dict,
    args,
) -> str:
    case_json_path = case_dir / "case.json"
    request_path = case_dir / "request.txt"
    response_path = case_dir / "response.txt"
    analysis_path = case_dir / "analysis.json"
    analysis_raw_path = case_dir / "analysis_raw.txt"

    case_obj = read_json(case_json_path, default={})
    if not case_obj:
        return "skip(no_case_json)"

    llm_status = str(case_obj.get("llm_status") or "pending").lower()
    if llm_status == "done" and analysis_path.exists():
        return "skip(done)"

    if llm_status == "processing":
        return "skip(processing)"

    # mark processing
    case_obj["llm_status"] = "processing"
    case_obj["llm_started_at"] = now_iso()
    write_json(case_json_path, case_obj)

    request_text = read_text(request_path)
    response_text = read_text(response_path)

    file_id = str(case_obj.get("file_id") or "")
    seq_id = int(case_obj.get("seq_id") or 0)
    src_ip, dst_ip = parse_case_ips_from_input(input_dir / f"{file_id}.txt", seq_id)

    if not src_ip:
        src_ip = parse_ip_from_text(request_text) or "unknown"
    if not dst_ip:
        dst_ip = parse_ip_from_text(response_text) or "unknown"

    rag_rows: List[Dict] = []
    rag_context = ""
    if args.rag_enable:
        query_text = "\n".join(
            [
                str(case_obj.get("attack_type") or ""),
                str(case_obj.get("method") or ""),
                str(case_obj.get("uri") or ""),
                str(case_obj.get("host") or ""),
                request_text[:2500],
                response_text[:1200],
            ]
        )
        rag_rows = retrieve_advanced_rag(args, query_text=query_text)
        if not rag_rows:
            rag_rows = retrieve_rag_docs(args.rag_db_path, query_text=query_text, top_k=args.rag_top_k)
        rag_context = format_rag_context(rag_rows, max_chars=args.rag_max_chars)

    user_payload = build_user_payload(case_obj, request_text, response_text, src_ip, dst_ip, rag_context=rag_context)

    models_to_try: List[str] = [args.model]
    fallback_model = str(getattr(args, "fallback_model_resolved", "") or "").strip()
    if fallback_model and fallback_model not in models_to_try:
        models_to_try.append(fallback_model)

    last_exc: Optional[Exception] = None
    for idx, model_name in enumerate(models_to_try):
        try:
            parsed, raw_content = call_ollama_chat(
                base_url=args.ollama_url,
                model=model_name,
                system_prompt=system_prompt,
                user_payload=user_payload,
                schema_obj=schema_obj,
                timeout_sec=args.timeout_sec,
                num_ctx=args.num_ctx,
                num_gpu=args.num_gpu,
                temperature=args.temperature,
            )

            analysis = normalize_analysis(parsed, case_obj, src_ip, dst_ip, model_name)
            analysis["rag_hits"] = len(rag_rows)
            analysis["rag_enabled"] = bool(args.rag_enable)
            analysis["knowledge_references"] = build_rag_references(rag_rows) if args.rag_enable else []
            write_json(analysis_path, analysis)
            analysis_raw_path.write_text(raw_content or "", encoding="utf-8")

            case_obj["llm_status"] = "done"
            case_obj.pop("llm_error", None)
            case_obj.pop("llm_failed_at", None)
            case_obj["analysis_file"] = str(analysis_path.resolve())
            case_obj["analysis_raw_file"] = str(analysis_raw_path.resolve())
            case_obj["rag_hits"] = len(rag_rows)
            case_obj["analyzed_at"] = now_iso()
            case_obj["status"] = case_obj.get("status") or "pending"
            write_json(case_json_path, case_obj)
            return "done"
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if idx < len(models_to_try) - 1 and should_retry_llm_error(str(exc)):
                next_model = models_to_try[idx + 1]
                log(f"{case_dir.name}: model={model_name} failed ({exc}), retry with {next_model}")
                continue
            break

    case_obj["llm_status"] = "failed"
    case_obj["llm_error"] = str(last_exc) if last_exc else "unknown_error"
    case_obj["llm_failed_at"] = now_iso()
    write_json(case_json_path, case_obj)
    return f"failed({last_exc})"


def open_review_conn(args):
    from build_result_db import MySQLConfig
    from sync_detection_v2_db import mysql_connect

    return mysql_connect(
        MySQLConfig(
            args.rag_mysql_host,
            args.rag_mysql_port,
            args.rag_mysql_user,
            args.rag_mysql_password,
            args.rag_mysql_database,
        )
    )


def build_fusion_only_analysis(row: Dict, case_obj: Dict, context: Dict) -> Dict:
    attack_type = str(row.get("attack_type") or "可疑流量")
    risk = str(row.get("risk_level") or "medium").lower()
    score = max(0.0, min(1.0, float(row.get("final_score") or 0.0)))
    evidence: List[str] = []
    for value in context.get("fusion_evidence") or []:
        text = str(value).strip()
        if text and text not in evidence:
            evidence.append(text)
    for item in context.get("poc_matches") or []:
        name = str(item.get("rule_name") or item.get("rule_id") or "POC规则").strip()
        text = f"POC规则命中：{name}"
        if text not in evidence:
            evidence.append(text)
    for item in context.get("payload_models") or []:
        label = str(item.get("label") or "").strip()
        if label:
            evidence.append(f"Payload模型判定为{label}，评分{float(item.get('score') or 0):.3f}")
    evidence = evidence[:6] or [f"多模型融合评分为{score:.3f}，建议人工复核原始请求与响应"]
    verdict = "attack" if str(row.get("preliminary_decision")) == "attack_event" else "unknown"
    return {
        "verdict": verdict,
        "source_ip": str(row.get("source_ip") or "unknown"),
        "destination_ip": str(row.get("destination_ip") or "unknown"),
        "attack_interface": str(row.get("uri") or ""),
        "attack_method": attack_type,
        "attack_path": f"{row.get('method') or ''} {row.get('uri') or ''}".strip(),
        "attack_time": str(row.get("event_time") or ""),
        "severity": risk if risk in {"low", "medium", "high", "critical"} else "unknown",
        "confidence": score,
        "evidence": evidence,
        "analysis_reasoning": "Payload模型、POC规则与行为窗口完成交叉验证；当前未调用实时生成模型。",
        "potential_impact": [f"若该{attack_type}请求成功，可能影响目标接口的数据或服务完整性。"],
        "immediate_actions": ["核验来源IP与同时间窗口请求，必要时限流或封禁。", "检查目标接口日志与异常响应。"],
        "hardening_actions": ["针对目标接口实施参数校验、最小权限和安全审计。", "持续更新POC规则与行为基线。"],
        "false_positive_notes": "如请求来自授权测试或内部扫描，应结合资产台账降级处置。",
        "knowledge_references": [],
        "summary": f"多模型融合发现{attack_type}特征，风险等级为{risk}，融合置信度{score:.1%}。",
    }


def process_next_raw_review(system_prompt: str, schema_obj: Dict, args) -> Optional[str]:
    from raw_llm_review import (
        claim_next_review,
        complete_review,
        defer_review,
        detection_context,
        ensure_review_schema,
        fail_review,
        find_cached_review,
        mark_cache_hit,
        realtime_llm_enabled,
    )

    conn = open_review_conn(args)
    try:
        ensure_review_schema(conn)
        row = claim_next_review(conn, max_attempts=args.raw_review_max_attempts)
        if not row:
            return None

        event_id = str(row.get("event_id") or "")
        case_id = str(row.get("case_id") or "")
        started = time.perf_counter()
        request_text = str(row.get("request_text") or "")
        response_text = str(row.get("response_text") or "")
        context = detection_context(row)
        case_obj = {
            "case_id": case_id,
            "file_id": row.get("file_id"),
            "seq_id": row.get("seq_id"),
            "method": row.get("method"),
            "uri": row.get("uri"),
            "host": row.get("host"),
            "status_code": row.get("status_code"),
            "source_ip": row.get("source_ip"),
            "destination_ip": row.get("destination_ip"),
            "attack_type": row.get("attack_type"),
            "v2_risk_level": row.get("risk_level"),
            "export_time": row.get("event_time"),
            "request_text": request_text,
            "response_text": response_text,
            "detection_context": context,
        }

        realtime_enabled = realtime_llm_enabled(conn)
        if not realtime_enabled:
            cached = find_cached_review(conn, row)
            if cached:
                ready_at = _cached_review_ready_at(row.get("event_time"))
                if ready_at is not None:
                    current = datetime.now(tz=ready_at.tzinfo) if ready_at.tzinfo is not None else datetime.now()
                    if current < ready_at:
                        defer_review(conn, event_id, ready_at)
                        return f"{event_id}: cached review deferred until {ready_at.isoformat(timespec='milliseconds')}"
                analysis = normalize_analysis(
                    dict(cached["analysis"]), case_obj,
                    str(row.get("source_ip") or "unknown"),
                    str(row.get("destination_ip") or "unknown"),
                    str(cached.get("model_name") or args.model),
                )
                analysis["knowledge_references"] = list(analysis.get("knowledge_references") or [])
                latency_ms = max(0, int(round((time.perf_counter() - started) * 1000)))
                confirmed = complete_review(
                    conn, row=row, analysis=analysis,
                    raw_content=json.dumps(analysis, ensure_ascii=False),
                    model_name=str(cached.get("model_name") or args.model),
                    rag_enabled=bool(analysis.get("knowledge_references")),
                    rag_hits=len(analysis.get("knowledge_references") or []),
                    latency_ms=latency_ms, review_source="verified_cache",
                )
                mark_cache_hit(conn, str(cached["fingerprint"]))
                return f"{event_id}: done cached=1 published={int(confirmed)} latency_ms={latency_ms}"

            analysis = build_fusion_only_analysis(row, case_obj, context)
            latency_ms = max(0, int(round((time.perf_counter() - started) * 1000)))
            confirmed = complete_review(
                conn, row=row, analysis=analysis,
                raw_content=json.dumps(analysis, ensure_ascii=False),
                model_name="AI多模型融合", rag_enabled=False, rag_hits=0,
                latency_ms=latency_ms, review_source="fusion_only",
            )
            return f"{event_id}: done fusion_only=1 published={int(confirmed)} latency_ms={latency_ms}"

        rag_rows: List[Dict] = []
        rag_context = ""
        if args.rag_enable:
            query_text = "\n".join(
                [
                    str(row.get("attack_type") or ""),
                    str(row.get("method") or ""),
                    str(row.get("uri") or ""),
                    request_text[:2500],
                    response_text[:1200],
                    json.dumps(context, ensure_ascii=False)[:2500],
                ]
            )
            rag_rows = retrieve_advanced_rag(args, query_text=query_text)
            if not rag_rows:
                rag_rows = retrieve_rag_docs(args.rag_db_path, query_text=query_text, top_k=args.rag_top_k)
            rag_context = format_rag_context(rag_rows, max_chars=args.rag_max_chars)

        user_payload = build_user_payload(
            case_obj,
            request_text,
            response_text,
            str(row.get("source_ip") or "unknown"),
            str(row.get("destination_ip") or "unknown"),
            rag_context=rag_context,
            detection_context=context,
        )
        models_to_try = [args.model]
        fallback_model = str(getattr(args, "fallback_model_resolved", "") or "").strip()
        if fallback_model and fallback_model not in models_to_try:
            models_to_try.append(fallback_model)

        last_exc: Optional[Exception] = None
        for idx, model_name in enumerate(models_to_try):
            try:
                parsed, raw_content = call_ollama_chat(
                    base_url=args.ollama_url,
                    model=model_name,
                    system_prompt=system_prompt,
                    user_payload=user_payload,
                    schema_obj=schema_obj,
                    timeout_sec=args.timeout_sec,
                    num_ctx=args.num_ctx,
                    num_gpu=args.num_gpu,
                    temperature=args.temperature,
                )
                analysis = normalize_analysis(
                    parsed,
                    case_obj,
                    str(row.get("source_ip") or "unknown"),
                    str(row.get("destination_ip") or "unknown"),
                    model_name,
                )
                analysis["knowledge_references"] = build_rag_references(rag_rows) if args.rag_enable else []
                latency_ms = max(0, int(round((time.perf_counter() - started) * 1000)))
                confirmed = complete_review(
                    conn,
                    row=row,
                    analysis=analysis,
                    raw_content=raw_content,
                    model_name=model_name,
                    rag_enabled=bool(args.rag_enable),
                    rag_hits=len(rag_rows),
                    latency_ms=latency_ms,
                )
                return (
                    f"{event_id}: done verdict={analysis.get('verdict')} "
                    f"published={int(confirmed)} latency_ms={latency_ms}"
                )
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if idx < len(models_to_try) - 1 and should_retry_llm_error(str(exc)):
                    continue
                break

        fail_review(
            conn,
            event_id=event_id,
            case_id=case_id,
            error=str(last_exc or "unknown_error"),
            max_attempts=args.raw_review_max_attempts,
        )
        return f"{event_id}: failed({last_exc})"
    finally:
        conn.close()


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent

    parser = argparse.ArgumentParser(description="监听 result/b.n 并自动调用本地大模型分析（不重复处理）")
    parser.add_argument("--result-dir", default="result", help="result 根目录")
    parser.add_argument("--input-dir", default="input", help="input 根目录，用于回查 source_ip/destination_ip")
    parser.add_argument("--model", default="qwen3:8b", help="Ollama 模型名")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434", help="Ollama 服务地址")
    parser.add_argument("--prompt", default="llm/prompts/system_prompt.txt", help="系统提示词文件")
    parser.add_argument("--schema", default="llm/schemas/analysis.schema.json", help="输出 JSON schema 文件")
    parser.add_argument("--poll-seconds", type=int, default=5)
    parser.add_argument("--timeout-sec", type=int, default=300)
    parser.add_argument("--num-ctx", type=int, default=1024)
    parser.add_argument("--num-gpu", type=int, default=0, help="0=CPU 更稳；设大于0可尝试GPU")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--once", action="store_true", help="仅扫描一次并处理后退出")
    parser.add_argument("--max-cases", type=int, default=0, help="每轮最多处理多少条，0=不限制")
    parser.add_argument(
        "--legacy-result-review",
        action="store_true",
        help="兼容处理历史 result/b.* 队列；默认关闭以保证 RAW 实时候选优先",
    )
    parser.add_argument("--fallback-model", default="", help="主模型失败时的回退模型，留空则自动选择已安装的其他模型")
    parser.add_argument(
        "--processing-timeout-sec",
        type=int,
        default=180,
        help="case 长时间停留 processing 的超时秒数，超时后自动重置为 pending",
    )
    parser.add_argument("--rag-enable", dest="rag_enable", action="store_true", help="启用 RAG 检索增强")
    parser.add_argument("--no-rag", dest="rag_enable", action="store_false", help="关闭 RAG 检索增强")
    parser.set_defaults(rag_enable=True)
    parser.add_argument("--rag-db-path", default="llm/rag/rag_knowledge.db", help="RAG sqlite db 文件路径")
    parser.add_argument("--rag-seed-file", default="llm/rag/rag_seed.json", help="RAG seed JSON 文件路径")
    parser.add_argument("--rag-data-dir", default="D:/JingyuanTrafficPipelineData/rag", help="高级 RAG 向量与上传目录")
    parser.add_argument("--rag-api-config", default="config/ai_api.local.json", help="百炼 API 本地配置")
    parser.add_argument("--rag-mysql-host", default="127.0.0.1")
    parser.add_argument("--rag-mysql-port", type=int, default=3306)
    parser.add_argument("--rag-mysql-user", default="root")
    parser.add_argument("--rag-mysql-password", default="123456")
    parser.add_argument("--rag-mysql-database", default="traffic_pipeline")
    parser.add_argument("--raw-review-max-attempts", type=int, default=3)
    parser.add_argument("--rag-top-k", type=int, default=3, help="RAG 每次检索条数")
    parser.add_argument("--rag-max-chars", type=int, default=3200, help="注入 LLM 的 RAG 上下文最大字符数")
    parser.add_argument("--rag-auto-build", dest="rag_auto_build", action="store_true", help="若 RAG db 不存在则自动构建")
    parser.add_argument("--no-rag-auto-build", dest="rag_auto_build", action="store_false", help="不自动构建 RAG db")
    parser.set_defaults(rag_auto_build=True)
    args = parser.parse_args()

    result_dir = (project_root / args.result_dir).resolve()
    input_dir = (project_root / args.input_dir).resolve()
    prompt_path = (project_root / args.prompt).resolve()
    schema_path = (project_root / args.schema).resolve()
    args.rag_db_path = (project_root / args.rag_db_path).resolve()
    args.rag_seed_file = (project_root / args.rag_seed_file).resolve()
    args.rag_data_dir = Path(args.rag_data_dir).resolve()
    args.rag_api_config = (project_root / args.rag_api_config).resolve()

    result_dir.mkdir(parents=True, exist_ok=True)
    input_dir.mkdir(parents=True, exist_ok=True)

    system_prompt = read_text(prompt_path)
    if not system_prompt.strip():
        raise RuntimeError(f"prompt 为空: {prompt_path}")
    prompt_mtime = prompt_path.stat().st_mtime if prompt_path.exists() else 0.0

    schema_obj = read_json(schema_path, default={})
    if not schema_obj:
        raise RuntimeError(f"schema 无效: {schema_path}")

    if args.rag_enable:
        ensure_rag_db(args.rag_db_path, args.rag_seed_file, auto_build=args.rag_auto_build)
        log(f"RAG enabled db={args.rag_db_path} top_k={args.rag_top_k}")
    else:
        log("RAG disabled")

    args.model = resolve_model_name(args.ollama_url, args.model, timeout_sec=10)
    installed_models = fetch_available_models(base_url=args.ollama_url, timeout_sec=10)
    fallback_model = str(args.fallback_model or "").strip()
    if fallback_model and fallback_model not in installed_models:
        log(f"configured fallback model '{fallback_model}' not found, ignore fallback")
        fallback_model = ""
    if not fallback_model:
        for m in installed_models:
            if m != args.model:
                fallback_model = m
                break
    args.fallback_model_resolved = fallback_model
    if args.fallback_model_resolved:
        log(f"fallback model enabled: {args.fallback_model_resolved}")
    log(f"LLM daemon started model={args.model} url={args.ollama_url}")
    log(f"result_dir={result_dir}")
    try:
        warm_ollama_model(args.ollama_url, args.model, timeout_sec=min(90, args.timeout_sec))
        log(f"LLM model warmed and kept alive: {args.model}")
    except Exception as exc:
        log(f"LLM warmup skipped: {exc}")

    try:
        review_conn = open_review_conn(args)
        try:
            from raw_llm_review import ensure_review_schema

            ensure_review_schema(review_conn)
        finally:
            review_conn.close()
        log("RAW LLM review queue enabled")
    except Exception as exc:
        log(f"RAW LLM review queue unavailable: {exc}")

    while True:
        processed = 0
        try:
            current_prompt_mtime = prompt_path.stat().st_mtime if prompt_path.exists() else 0.0
            if current_prompt_mtime != prompt_mtime:
                system_prompt, prompt_mtime = load_system_prompt(prompt_path)
                log(f"prompt reloaded: {prompt_path}")
        except Exception as exc:
            log(f"prompt reload skipped: {exc}")

        try:
            raw_result = process_next_raw_review(system_prompt, schema_obj, args)
        except Exception as exc:
            raw_result = None
            log(f"RAW LLM review cycle failed: {exc}")
        if raw_result:
            processed += 1
            log(raw_result)
            if args.once:
                log(f"once done processed={processed}")
                break
            # Prioritize new suspicious traffic instead of waiting behind the
            # historical result/b.* retry backlog.
            continue

        if not args.legacy_result_review:
            if args.once:
                log(f"once done processed={processed}")
                break
            wait_event(LLM_READY_EVENT, max(1, args.poll_seconds))
            continue

        case_dirs = find_case_dirs(result_dir)

        for case_dir in case_dirs:
            case_obj = read_json(case_dir / "case.json", default={})
            llm_status = str(case_obj.get("llm_status") or "pending").lower()

            if llm_status == "processing":
                started_at = str(case_obj.get("llm_started_at") or "").strip()
                stale = False
                if started_at:
                    try:
                        elapsed = time.time() - datetime.fromisoformat(started_at).timestamp()
                        stale = elapsed >= max(30, int(args.processing_timeout_sec))
                    except Exception:
                        stale = True
                else:
                    stale = True

                if stale:
                    case_obj["llm_status"] = "pending"
                    case_obj["llm_recovered_at"] = now_iso()
                    write_json(case_dir / "case.json", case_obj)
                    log(f"{case_dir.name}: stale processing recovered -> pending")
                    llm_status = "pending"
                else:
                    continue

            if llm_status not in ("pending", "failed"):
                continue

            ret = process_case(case_dir, input_dir, system_prompt, schema_obj, args)
            if not ret.startswith("skip"):
                processed += 1
                log(f"{case_dir.name}: {ret}")

            if args.max_cases > 0 and processed >= args.max_cases:
                break

        if args.once:
            log(f"once done processed={processed}")
            break

        wait_event(LLM_READY_EVENT, max(args.poll_seconds, 1))


if __name__ == "__main__":
    main()
