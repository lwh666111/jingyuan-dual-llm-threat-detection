import argparse
import json
import re
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


def build_user_payload(case_obj: Dict, request_text: str, response_text: str, src_ip: str, dst_ip: str) -> str:
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
    }
    return json.dumps(body, ensure_ascii=False)


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

    user_payload = build_user_payload(case_obj, request_text, response_text, src_ip, dst_ip)

    try:
        parsed, raw_content = call_ollama_chat(
            base_url=args.ollama_url,
            model=args.model,
            system_prompt=system_prompt,
            user_payload=user_payload,
            schema_obj=schema_obj,
            timeout_sec=args.timeout_sec,
            num_ctx=args.num_ctx,
            num_gpu=args.num_gpu,
            temperature=args.temperature,
        )

        analysis = normalize_analysis(parsed, case_obj, src_ip, dst_ip, args.model)
        write_json(analysis_path, analysis)
        analysis_raw_path.write_text(raw_content or "", encoding="utf-8")

        case_obj["llm_status"] = "done"
        case_obj.pop("llm_error", None)
        case_obj.pop("llm_failed_at", None)
        case_obj["analysis_file"] = str(analysis_path.resolve())
        case_obj["analysis_raw_file"] = str(analysis_raw_path.resolve())
        case_obj["analyzed_at"] = now_iso()
        case_obj["status"] = case_obj.get("status") or "pending"
        write_json(case_json_path, case_obj)
        return "done"

    except Exception as exc:  # noqa: BLE001
        case_obj["llm_status"] = "failed"
        case_obj["llm_error"] = str(exc)
        case_obj["llm_failed_at"] = now_iso()
        write_json(case_json_path, case_obj)
        return f"failed({exc})"


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
    args = parser.parse_args()

    result_dir = (project_root / args.result_dir).resolve()
    input_dir = (project_root / args.input_dir).resolve()
    prompt_path = (project_root / args.prompt).resolve()
    schema_path = (project_root / args.schema).resolve()

    result_dir.mkdir(parents=True, exist_ok=True)
    input_dir.mkdir(parents=True, exist_ok=True)

    system_prompt = read_text(prompt_path)
    if not system_prompt.strip():
        raise RuntimeError(f"prompt 为空: {prompt_path}")

    schema_obj = read_json(schema_path, default={})
    if not schema_obj:
        raise RuntimeError(f"schema 无效: {schema_path}")

    args.model = resolve_model_name(args.ollama_url, args.model, timeout_sec=10)
    log(f"LLM daemon started model={args.model} url={args.ollama_url}")
    log(f"result_dir={result_dir}")

    while True:
        processed = 0
        case_dirs = find_case_dirs(result_dir)

        for case_dir in case_dirs:
            case_obj = read_json(case_dir / "case.json", default={})
            llm_status = str(case_obj.get("llm_status") or "pending").lower()

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
