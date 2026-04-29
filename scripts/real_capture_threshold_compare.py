import argparse
import os
import json
import random
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from http.client import HTTPConnection
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import quote_plus


@dataclass
class CaseTemplate:
    name: str
    method: str
    uri: str
    body: str = ""
    content_type: str = ""
    is_attack: int = 0


def append_trace(uri: str, trace_value: str) -> str:
    if "?" in uri:
        return f"{uri}&trace={trace_value}"
    return f"{uri}?trace={trace_value}"


def default_attack_templates() -> List[CaseTemplate]:
    return [
        CaseTemplate("sqli_or", "POST", "/api/auth/login", '{"username":"admin","password":"\' OR 1=1 -- "}', "application/json", 1),
        CaseTemplate("sqli_union", "POST", "/api/auth/login", '{"username":"admin\' UNION SELECT 1,2,3 -- ","password":"x"}', "application/json", 1),
        CaseTemplate("xss_script", "GET", "/api/search?q=" + quote_plus("<script>alert(1)</script>"), "", "", 1),
        CaseTemplate("xss_onerror", "POST", "/api/comment", '{"author":"a","content":"<img src=x onerror=alert(1)>"}', "application/json", 1),
        CaseTemplate("traversal_linux", "GET", "/api/file/read?path=" + quote_plus("../../../../etc/passwd"), "", "", 1),
        CaseTemplate("traversal_win", "GET", "/api/file/read?path=" + quote_plus("..\\..\\..\\Windows\\win.ini"), "", "", 1),
        CaseTemplate("cmdi", "POST", "/api/system/ping", '{"host":"8.8.8.8 && whoami"}', "application/json", 1),
        CaseTemplate("ssrf", "GET", "/api/fetch?url=" + quote_plus("http://169.254.169.254/latest/meta-data"), "", "", 1),
        CaseTemplate("ssti", "POST", "/api/template/render", '{"template":"{{7*7}}"}', "application/json", 1),
        CaseTemplate("xxe", "POST", "/api/xml/import", '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>', "application/xml", 1),
        CaseTemplate("graphql_inj", "POST", "/api/graphql", '{"query":"{user(id:\\"1 OR 1=1\\"){id}}"}', "application/json", 1),
        CaseTemplate("rce_eval", "POST", "/api/eval", '{"code":"__import__(\\"os\\").system(\\"id\\")"}', "application/json", 1),
    ]


def default_benign_templates() -> List[CaseTemplate]:
    return [
        CaseTemplate("home", "GET", "/", "", "", 0),
        CaseTemplate("health", "GET", "/health", "", "", 0),
        CaseTemplate("products", "GET", "/api/products", "", "", 0),
        CaseTemplate("news", "GET", "/api/news", "", "", 0),
        CaseTemplate("search_normal", "GET", "/api/search?q=" + quote_plus("security monitor"), "", "", 0),
        CaseTemplate("login_ok", "POST", "/api/auth/login", '{"username":"admin","password":"admin"}', "application/json", 0),
        CaseTemplate("comment", "POST", "/api/comment", '{"author":"alice","content":"hello"}', "application/json", 0),
        CaseTemplate("file_safe", "GET", "/api/file/read?path=" + quote_plus("notes/todo.txt"), "", "", 0),
        CaseTemplate("ping_safe", "POST", "/api/system/ping", '{"host":"8.8.8.8"}', "application/json", 0),
        CaseTemplate("fetch_safe", "GET", "/api/fetch?url=" + quote_plus("https://example.com"), "", "", 0),
        CaseTemplate("xml_safe", "POST", "/api/xml/import", '<?xml version="1.0"?><root><x>ok</x></root>', "application/xml", 0),
        CaseTemplate("graphql_safe", "POST", "/api/graphql", '{"query":"{viewer{id name}}"}', "application/json", 0),
    ]


def send_http(host: str, port: int, method: str, uri: str, body: str, content_type: str) -> Tuple[int, str]:
    conn = HTTPConnection(host, port, timeout=8)
    status = 599
    reason = "client_error"
    try:
        headers = {"Host": "ctf.ski:3000", "User-Agent": "real-capture-threshold-compare/1.0"}
        if content_type:
            headers["Content-Type"] = content_type
        payload = body.encode("utf-8") if body else None
        conn.request(method=method, url=uri, body=payload, headers=headers)
        resp = conn.getresponse()
        status = int(resp.status)
        reason = str(resp.reason or "")
        _ = resp.read(256)
    except Exception as exc:  # noqa: BLE001
        reason = str(exc)
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return status, reason


def calc_metrics(rows: List[Dict[str, Any]], threshold: float) -> Dict[str, Any]:
    tp = fp = tn = fn = 0
    for row in rows:
        pred = 1 if float(row["score"]) >= threshold else 0
        y = int(row["is_attack"])
        if pred == 1 and y == 1:
            tp += 1
        elif pred == 1 and y == 0:
            fp += 1
        elif pred == 0 and y == 0:
            tn += 1
        else:
            fn += 1
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "threshold": round(float(threshold), 4),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "accuracy": round(accuracy, 6),
        "fpr": round(fpr, 6),
        "sample_count": total,
    }


def parse_thresholds(text: str) -> List[float]:
    out: List[float] = []
    for token in re.split(r"[\s,]+", (text or "").strip()):
        if not token:
            continue
        v = float(token)
        if v < 0 or v > 1:
            raise ValueError(f"invalid threshold: {v}")
        out.append(v)
    if not out:
        raise ValueError("empty thresholds")
    return out


def resolve_default_model_paths(project_root: Path) -> Tuple[Path, Path]:
    local_models = project_root / "models"
    local_pre = local_models / "preprocessor.joblib"
    local_mdl = local_models / "best_mlp.pth"
    if local_pre.exists() and local_mdl.exists():
        return local_pre, local_mdl
    fallback_models = project_root.parent / "traffic_mlp" / "models"
    return fallback_models / "preprocessor.joblib", fallback_models / "best_mlp.pth"


def wait_http_ready(url: str, timeout_sec: float = 20.0) -> None:
    import urllib.request

    end = time.time() + timeout_sec
    while time.time() < end:
        try:
            with urllib.request.urlopen(url, timeout=1.5) as resp:
                if int(resp.status) < 500:
                    return
        except Exception:
            time.sleep(0.25)
    raise RuntimeError(f"service not ready: {url}")


def newest_capture_file(input_dir: Path) -> Path:
    files = sorted(input_dir.glob("1.1.*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        raise FileNotFoundError(f"no capture file under: {input_dir}")
    return files[0]


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare thresholds on real packet-capture pipeline.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3000)
    parser.add_argument("--interface", default="1", help="capture interface keyword or index")
    parser.add_argument("--attacks", type=int, default=250)
    parser.add_argument("--benign", type=int, default=250)
    parser.add_argument("--capture-batch-size", type=int, default=0, help="0 means attacks+benign")
    parser.add_argument("--capture-timeout-seconds", type=int, default=420)
    parser.add_argument("--capture-ready-timeout-seconds", type=int, default=45)
    parser.add_argument("--request-interval-ms", type=int, default=20)
    parser.add_argument("--thresholds", default="0.79,0.46")
    parser.add_argument("--seed", type=int, default=20260426)
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--output-root", default="output/real_capture_threshold_compare")
    parser.add_argument("--preprocessor", default="")
    parser.add_argument("--model", default="")
    args = parser.parse_args()

    random.seed(int(args.seed))
    thresholds = parse_thresholds(args.thresholds)

    project_root = Path(args.project_root).resolve()
    output_root = (project_root / args.output_root).resolve()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = output_root / ts
    input_dir = run_dir / "input"
    run_dir.mkdir(parents=True, exist_ok=True)
    input_dir.mkdir(parents=True, exist_ok=True)

    pre_default, model_default = resolve_default_model_paths(project_root)
    pre_path = Path(args.preprocessor).resolve() if args.preprocessor else pre_default
    model_path = Path(args.model).resolve() if args.model else model_default
    if not pre_path.exists():
        raise FileNotFoundError(f"preprocessor not found: {pre_path}")
    if not model_path.exists():
        raise FileNotFoundError(f"model not found: {model_path}")

    wait_http_ready(f"http://{args.host}:{args.port}/health", timeout_sec=25.0)

    attacks = [random.choice(default_attack_templates()) for _ in range(int(args.attacks))]
    benigns = [random.choice(default_benign_templates()) for _ in range(int(args.benign))]
    mixed = attacks + benigns
    random.shuffle(mixed)
    total = len(mixed)
    bench_id = f"bench{datetime.now().strftime('%H%M%S')}"

    capture_batch_size = int(args.capture_batch_size) if int(args.capture_batch_size) > 0 else total

    capture_cmd = [
        sys.executable,
        "-u",
        str(project_root / "scripts" / "capture_http_request_batches.py"),
        "--port",
        str(args.port),
        "--ports",
        str(args.port),
        "--batch-size",
        str(capture_batch_size),
        "--input-dir",
        str(input_dir),
        "--once",
        "--interface",
        str(args.interface),
    ]

    capture_proc = subprocess.Popen(
        capture_cmd,
        cwd=str(project_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    # Avoid blocking reads on pipes: give capture process a configurable warm-up window.
    warmup = max(1, int(args.capture_ready_timeout_seconds))
    time.sleep(warmup)

    truth_by_trace: Dict[str, Dict[str, Any]] = {}
    interval = max(0, int(args.request_interval_ms)) / 1000.0
    for idx, tmpl in enumerate(mixed, start=1):
        trace = f"{bench_id}_{idx:04d}"
        uri = append_trace(tmpl.uri, trace)
        status, reason = send_http(args.host, int(args.port), tmpl.method, uri, tmpl.body, tmpl.content_type)
        truth_by_trace[trace] = {
            "trace": trace,
            "is_attack": int(tmpl.is_attack),
            "template": tmpl.name,
            "method": tmpl.method,
            "uri": uri,
            "response_status": int(status),
            "response_reason": reason,
        }
        if interval > 0:
            time.sleep(interval)

    try:
        capture_proc.wait(timeout=max(30, int(args.capture_timeout_seconds)))
    except subprocess.TimeoutExpired as exc:
        capture_proc.kill()
        raise RuntimeError(
            f"capture process timed out before producing one batch: batch_size={capture_batch_size}"
        ) from exc

    cap_stdout = capture_proc.stdout.read() if capture_proc.stdout else ""
    cap_stderr = capture_proc.stderr.read() if capture_proc.stderr else ""
    if capture_proc.returncode != 0:
        raise RuntimeError(f"capture failed rc={capture_proc.returncode}\nstdout={cap_stdout}\nstderr={cap_stderr}")

    capture_txt = newest_capture_file(input_dir)
    file_id = capture_txt.stem

    subprocess.run(
        [
            sys.executable,
            str(project_root / "scripts" / "extract_old_model_features_from_txt.py"),
            "--input",
            str(capture_txt),
            "--preprocessor",
            str(pre_path),
            "--output-dir",
            str(run_dir),
            "--keep-static",
        ],
        cwd=str(project_root),
        check=True,
    )

    old_input = run_dir / f"{file_id}.old_model_input.csv"
    model_jsonl = run_dir / f"{file_id}.model_result.jsonl"
    model_csv = run_dir / f"{file_id}.model_result.csv"
    subprocess.run(
        [
            sys.executable,
            str(project_root / "scripts" / "run_old_model_direct.py"),
            "--input",
            str(old_input),
            "--preprocessor",
            str(pre_path),
            "--model",
            str(model_path),
            "--output-jsonl",
            str(model_jsonl),
            "--output-csv",
            str(model_csv),
            "--label-threshold",
            "0.5",
        ],
        cwd=str(project_root),
        check=True,
    )

    raw_index = run_dir / f"{file_id}.raw_index.jsonl"
    seq_to_uri: Dict[int, str] = {}
    with raw_index.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            obj = json.loads(line)
            seq_to_uri[int(obj.get("seq_id") or 0)] = str(obj.get("uri") or "")

    seq_to_score: Dict[int, float] = {}
    with model_jsonl.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            obj = json.loads(line)
            seq_to_score[int(obj.get("seq_id") or 0)] = float(obj.get("score") or 0.0)

    eval_rows: List[Dict[str, Any]] = []
    trace_pattern = re.compile(rf"trace=({bench_id}_[0-9]{{4}})")
    for seq_id, uri in seq_to_uri.items():
        m = trace_pattern.search(uri)
        if not m:
            continue
        trace = m.group(1)
        truth = truth_by_trace.get(trace)
        if not truth or seq_id not in seq_to_score:
            continue
        eval_rows.append(
            {
                "trace": trace,
                "seq_id": seq_id,
                "uri": uri,
                "is_attack": int(truth["is_attack"]),
                "score": float(seq_to_score[seq_id]),
            }
        )

    threshold_results = [calc_metrics(eval_rows, t) for t in thresholds]
    threshold_results.sort(key=lambda x: x["threshold"], reverse=True)

    summary = {
        "run_at": datetime.now().isoformat(timespec="seconds"),
        "host": args.host,
        "port": int(args.port),
        "interface": str(args.interface),
        "attacks_sent": int(args.attacks),
        "benign_sent": int(args.benign),
        "sent_total": total,
        "capture_batch_size": capture_batch_size,
        "captured_file": str(capture_txt),
        "capture_return_code": int(capture_proc.returncode),
        "capture_stdout_tail": cap_stdout[-1200:],
        "capture_stderr_tail": cap_stderr[-1200:],
        "scored_total": len(seq_to_score),
        "trace_matched_total": len(eval_rows),
        "coverage_ratio": round((len(eval_rows) / total) if total else 0.0, 6),
        "threshold_results": threshold_results,
    }
    summary_path = run_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"\n[real-capture-threshold-compare] summary: {summary_path}")


if __name__ == "__main__":
    main()
