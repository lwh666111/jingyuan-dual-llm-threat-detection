import argparse
import json
import re
import sqlite3
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


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
        "request_block": request_text[:12000],
        "response_block": response_text[:12000],
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
        "format": schema_obj,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_payload},
        ],
        "options": {
            "num_ctx": num_ctx,
            "num_gpu": num_gpu,
            "temperature": temperature,
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
            "summary": content[:500],
        }

    return parsed, content


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


def normalize_analysis(parsed: Dict, case_obj: Dict, src_ip: str, dst_ip: str, model_name: str) -> Dict:
    uri = str(case_obj.get("uri") or "unknown")
    method = str(case_obj.get("method") or "")

    return {
        "case_id": str(case_obj.get("case_id") or ""),
        "file_id": str(case_obj.get("file_id") or ""),
        "seq_id": int(case_obj.get("seq_id") or 0),
        "source_ip": parsed.get("source_ip") or src_ip or "unknown",
        "destination_ip": parsed.get("destination_ip") or dst_ip or "unknown",
        "attack_interface": parsed.get("attack_interface") or uri,
        "attack_method": parsed.get("attack_method") or "unknown",
        "attack_path": parsed.get("attack_path") or f"{method} {uri}".strip(),
        "attack_time": parsed.get("attack_time") or now_iso(),
        "severity": parsed.get("severity") or "unknown",
        "confidence": float(parsed.get("confidence", 0.0) or 0.0),
        "verdict": parsed.get("verdict") or "unknown",
        "evidence": parsed.get("evidence") if isinstance(parsed.get("evidence"), list) else [],
        "summary": parsed.get("summary") or "",
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

    result_dir.mkdir(parents=True, exist_ok=True)
    input_dir.mkdir(parents=True, exist_ok=True)

    system_prompt = read_text(prompt_path)
    if not system_prompt.strip():
        raise RuntimeError(f"prompt 为空: {prompt_path}")

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

    while True:
        processed = 0
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

        time.sleep(max(args.poll_seconds, 1))


if __name__ == "__main__":
    main()

