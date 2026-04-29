import argparse
import json
import random
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


def wait_http_ready(url: str, timeout_sec: float = 20.0) -> None:
    end = time.time() + timeout_sec
    while time.time() < end:
        try:
            import urllib.request

            with urllib.request.urlopen(url, timeout=1.5) as resp:
                if int(resp.status) < 500:
                    return
        except Exception:
            time.sleep(0.25)
    raise RuntimeError(f"service not ready: {url}")


def safe_terminate(proc: subprocess.Popen | None) -> None:
    if proc is None:
        return
    try:
        proc.terminate()
    except Exception:
        return
    try:
        proc.wait(timeout=6)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def send_http(host: str, port: int, method: str, uri: str, body: str, content_type: str) -> Dict[str, Any]:
    conn = HTTPConnection(host, port, timeout=6)
    t0 = time.time()
    status = 599
    reason = "CLIENT_ERROR"
    resp_text = ""
    src_ip = "127.0.0.1"
    src_port = random.randint(20000, 65000)
    dst_ip = host
    dst_port = port
    try:
        headers = {"Host": "ctf.ski:4000", "User-Agent": "iterative-threshold-tuner/1.0"}
        if content_type:
            headers["Content-Type"] = content_type
        payload = body.encode("utf-8") if body else None
        conn.request(method=method, url=uri, body=payload, headers=headers)
        sock = conn.sock
        if sock:
            try:
                src_ip, src_port = sock.getsockname()[0], int(sock.getsockname()[1])
                dst_ip, dst_port = sock.getpeername()[0], int(sock.getpeername()[1])
            except Exception:
                pass
        resp = conn.getresponse()
        status = int(resp.status)
        reason = str(resp.reason or "")
        resp_text = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        reason = str(exc)
    finally:
        try:
            conn.close()
        except Exception:
            pass
    t1 = time.time()
    return {
        "status_code": status,
        "reason": reason,
        "response_text_raw": resp_text,
        "time_req": t0,
        "time_resp": t1,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
    }


def default_attack_templates() -> List[CaseTemplate]:
    return [
        CaseTemplate("sqli_or_login", "POST", "/api/auth/login", '{"username":"admin","password":"\' OR 1=1 -- "}', "application/json", 1),
        CaseTemplate("sqli_union_login", "POST", "/api/auth/login", '{"username":"admin\' UNION SELECT 1,2,3 -- ","password":"x"}', "application/json", 1),
        CaseTemplate("sqli_sleep_login", "POST", "/api/auth/login", '{"username":"admin","password":"\' AND SLEEP(1)-- "}', "application/json", 1),
        CaseTemplate("sqli_waitfor_login", "POST", "/api/auth/login", '{"username":"admin","password":"\'; WAITFOR DELAY \'0:0:1\'--"}', "application/json", 1),
        CaseTemplate("xss_search_script", "GET", "/api/search?q=" + quote_plus("<script>alert(1)</script>"), "", "", 1),
        CaseTemplate("xss_comment_onerror", "POST", "/api/comment", '{"author":"attacker","content":"<img src=x onerror=alert(1)>"}', "application/json", 1),
        CaseTemplate("traversal_linux", "GET", "/api/file/read?path=" + quote_plus("../../../../etc/passwd"), "", "", 1),
        CaseTemplate("traversal_windows", "GET", "/api/file/read?path=" + quote_plus("..\\..\\..\\Windows\\win.ini"), "", "", 1),
        CaseTemplate("cmdi_semicolon", "POST", "/api/system/ping", '{"host":"127.0.0.1; cat /etc/passwd"}', "application/json", 1),
        CaseTemplate("cmdi_ampamp", "POST", "/api/system/ping", '{"host":"8.8.8.8 && whoami"}', "application/json", 1),
        CaseTemplate("ssrf_metadata", "GET", "/api/fetch?url=" + quote_plus("http://169.254.169.254/latest/meta-data/iam"), "", "", 1),
        CaseTemplate("ssrf_localhost", "GET", "/api/fetch?url=" + quote_plus("http://127.0.0.1:6379/info"), "", "", 1),
        CaseTemplate("ssti_jinja", "POST", "/api/template/render", '{"template":"{{7*7}}"}', "application/json", 1),
        CaseTemplate("xxe_file", "POST", "/api/xml/import", '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>', "application/xml", 1),
        CaseTemplate("deserialize_java", "POST", "/api/deserialize", '{"data":"rO0ABXNyABNqYXZhLmxhbmcuUnVudGltZQ=="}', "application/json", 1),
        CaseTemplate("upload_php_shell", "POST", "/api/upload", '{"filename":"shell.php","content":"<?php system($_GET[\'c\']); ?>"}', "application/json", 1),
        CaseTemplate("upload_jsp_shell", "POST", "/api/upload", '{"filename":"cmd.jsp","content":"<% Runtime.getRuntime().exec(request.getParameter(\\"c\\")); %>"}', "application/json", 1),
        CaseTemplate("graphql_schema_dump", "POST", "/api/graphql", '{"query":"{__schema{types{name}}}"}', "application/json", 1),
        CaseTemplate("graphql_sqli", "POST", "/api/graphql", '{"query":"{user(id:\\"1 OR 1=1\\"){id name}}"}', "application/json", 1),
        CaseTemplate("admin_weak_token", "POST", "/api/admin/reset", '{"token":"000000"}', "application/json", 1),
        CaseTemplate("admin_none_token", "GET", "/api/admin/reset?token=alg:none.admin", "", "", 1),
        CaseTemplate("open_redirect_js", "GET", "/api/redirect?next=" + quote_plus("javascript:alert(1)"), "", "", 1),
        CaseTemplate("scan_git", "GET", "/.git/config", "", "", 1),
        CaseTemplate("scan_wp", "GET", "/wp-admin/install.php", "", "", 1),
        CaseTemplate("eval_rce", "POST", "/api/eval", '{"code":"__import__(\\"os\\").system(\\"id\\")"}', "application/json", 1),
    ]


def default_benign_templates() -> List[CaseTemplate]:
    return [
        CaseTemplate("home_page", "GET", "/", "", "", 0),
        CaseTemplate("health", "GET", "/health", "", "", 0),
        CaseTemplate("products", "GET", "/api/products", "", "", 0),
        CaseTemplate("news", "GET", "/api/news", "", "", 0),
        CaseTemplate("search_normal", "GET", "/api/search?q=" + quote_plus("security analytics"), "", "", 0),
        CaseTemplate("login_admin_ok", "POST", "/api/auth/login", '{"username":"admin","password":"admin"}', "application/json", 0),
        CaseTemplate("login_user_ok", "POST", "/api/auth/login", '{"username":"alice","password":"alice123"}', "application/json", 0),
        CaseTemplate("login_wrong", "POST", "/api/auth/login", '{"username":"guest","password":"guest"}', "application/json", 0),
        CaseTemplate("comment_normal", "POST", "/api/comment", '{"author":"alice","content":"hello team"}', "application/json", 0),
        CaseTemplate("file_read_safe", "GET", "/api/file/read?path=" + quote_plus("notes/todo.txt"), "", "", 0),
        CaseTemplate("ping_safe", "POST", "/api/system/ping", '{"host":"8.8.8.8"}', "application/json", 0),
        CaseTemplate("fetch_external", "GET", "/api/fetch?url=" + quote_plus("https://example.com/index"), "", "", 0),
        CaseTemplate("template_safe", "POST", "/api/template/render", '{"template":"hello ${name}"}', "application/json", 0),
        CaseTemplate("xml_safe", "POST", "/api/xml/import", '<?xml version="1.0"?><root><x>ok</x></root>', "application/xml", 0),
        CaseTemplate("deserialize_safe", "POST", "/api/deserialize", '{"data":"eyJmb28iOiJiYXIifQ=="}', "application/json", 0),
        CaseTemplate("upload_png", "POST", "/api/upload", '{"filename":"photo.png","content":"PNGDATA"}', "application/json", 0),
        CaseTemplate("graphql_safe", "POST", "/api/graphql", '{"query":"{viewer{id name}}"}', "application/json", 0),
        CaseTemplate("admin_strict_token", "GET", "/api/admin/reset?token=safe-token", "", "", 0),
        CaseTemplate("eval_safe", "GET", "/api/eval?code=1%2B1", "", "", 0),
        CaseTemplate("orders_list", "GET", "/api/orders", "", "", 0),
        CaseTemplate("orders_create", "POST", "/api/orders", '{"user_id":1001,"sku":"SKU-2001","amount":2}', "application/json", 0),
        CaseTemplate("redirect_normal", "GET", "/api/redirect?next=/home", "", "", 0),
        CaseTemplate("products_again", "GET", "/api/products?id=1002", "", "", 0),
        CaseTemplate("search_docs", "GET", "/api/search?q=" + quote_plus("documentation"), "", "", 0),
        CaseTemplate("news_again", "GET", "/api/news?page=1", "", "", 0),
    ]


def build_request_text(method: str, uri: str, status_code: int, body: str, excerpt: str, content_type: str) -> str:
    return "\\n".join(
        [
            f"METHOD={method}",
            f"URI={uri}",
            "HOST=ctf.ski:4000",
            f"CONTENT_TYPE={content_type}",
            f"STATUS_CODE={status_code}",
            f"REQUEST_BODY={body}",
            f"RESPONSE_EXCERPT={excerpt}",
        ]
    )


def build_response_text(status_code: int, reason: str, excerpt: str) -> str:
    return "\\n".join(
        [
            f"HTTP_STATUS={status_code}",
            f"MESSAGE={reason}",
            f"RESPONSE_EXCERPT={excerpt}",
        ]
    )


def write_canonical_file(
    path: Path,
    file_id: str,
    records: List[Dict[str, Any]],
) -> None:
    lines: List[str] = []
    lines.append("### BATCH_START ###")
    lines.append(f"file_id={file_id}")
    lines.append(f"batch_size={len(records)}")
    lines.append("source=iterative_threshold_tuning")
    lines.append("port=3000")
    lines.append("capture_mode=canonical_http_batch")
    lines.append("### BATCH_META_END ###")
    lines.append("")
    for rec in records:
        lines.extend(
            [
                "### CASE_START ###",
                f"file_id={file_id}",
                f"seq_id={rec['seq_id']}",
                f"frame_req={100000 + rec['seq_id'] * 2}",
                f"frame_resp={100001 + rec['seq_id'] * 2}",
                f"time_req={rec['time_req']}",
                f"time_resp={rec['time_resp']}",
                f"src_ip={rec['src_ip']}",
                f"dst_ip={rec['dst_ip']}",
                f"src_port={rec['src_port']}",
                f"dst_port={rec['dst_port']}",
                f"method={rec['method']}",
                f"uri={rec['uri']}",
                "host=ctf.ski:4000",
                f"status_code={rec['status_code']}",
                f"content_type={rec['content_type']}",
                f"request_text={rec['request_text']}",
                f"response_text={rec['response_text']}",
                "[REQUEST_BLOCK]",
                rec["raw_request_block"],
                "[/REQUEST_BLOCK]",
                "[RESPONSE_BLOCK]",
                rec["raw_response_block"],
                "[/RESPONSE_BLOCK]",
                "### CASE_END ###",
                "",
            ]
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def calc_metrics(rows: List[Dict[str, Any]], threshold: float) -> Dict[str, Any]:
    tp = fp = tn = fn = 0
    for r in rows:
        pred = 1 if float(r["score"]) >= threshold else 0
        y = int(r["is_attack"])
        if pred == 1 and y == 1:
            tp += 1
        elif pred == 1 and y == 0:
            fp += 1
        elif pred == 0 and y == 0:
            tn += 1
        else:
            fn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    tnr = tn / (tn + fp) if (tn + fp) else 0.0
    return {
        "threshold": round(float(threshold), 4),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "fpr": fpr,
        "tnr": tnr,
        "youden_j": recall + tnr - 1,
    }


def find_best_threshold(rows: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    all_metrics: List[Dict[str, Any]] = []
    for i in range(5, 96):
        th = i / 100.0
        all_metrics.append(calc_metrics(rows, th))
    all_metrics.sort(
        key=lambda x: (
            x["accuracy"],
            x["f1"],
            x["precision"],
            -x["fpr"],
            x["recall"],
        ),
        reverse=True,
    )
    return all_metrics[0], all_metrics


def run_round(
    round_id: int,
    current_threshold: float,
    output_root: Path,
    host: str,
    port: int,
    attacks_per_round: int,
    benign_per_round: int,
    preprocessor: Path,
    model: Path,
    project_root: Path,
) -> Dict[str, Any]:
    round_dir = output_root / f"round_{round_id:02d}"
    round_dir.mkdir(parents=True, exist_ok=True)
    file_id = f"iter.{round_id:02d}.{datetime.now().strftime('%H%M%S')}"

    attacks = [random.choice(default_attack_templates()) for _ in range(attacks_per_round)]
    benigns = [random.choice(default_benign_templates()) for _ in range(benign_per_round)]
    mixed = attacks + benigns
    random.shuffle(mixed)

    truth_rows: List[Dict[str, Any]] = []
    canonical_rows: List[Dict[str, Any]] = []
    for idx, c in enumerate(mixed, start=1):
        resp = send_http(host, port, c.method, c.uri, c.body, c.content_type)
        excerpt = (resp["response_text_raw"] or "")[:320].replace("\n", " ")
        req_text = build_request_text(
            c.method,
            c.uri,
            int(resp["status_code"]),
            c.body,
            excerpt,
            c.content_type,
        )
        res_text = build_response_text(int(resp["status_code"]), str(resp["reason"]), excerpt)
        raw_req = f"{c.method} {c.uri} HTTP/1.1\nHost: ctf.ski:4000"
        if c.content_type:
            raw_req += f"\nContent-Type: {c.content_type}"
        raw_req += f"\nBody:\n{c.body}"
        raw_resp = f"HTTP/1.1 {resp['status_code']} {resp['reason']}\nBody:\n{resp['response_text_raw'][:800]}"
        canonical_rows.append(
            {
                "seq_id": idx,
                "time_req": resp["time_req"],
                "time_resp": resp["time_resp"],
                "src_ip": resp["src_ip"],
                "dst_ip": resp["dst_ip"],
                "src_port": resp["src_port"],
                "dst_port": resp["dst_port"],
                "method": c.method,
                "uri": c.uri,
                "status_code": int(resp["status_code"]),
                "content_type": c.content_type,
                "request_text": req_text,
                "response_text": res_text,
                "raw_request_block": raw_req,
                "raw_response_block": raw_resp,
            }
        )
        truth_rows.append(
            {
                "seq_id": idx,
                "is_attack": int(c.is_attack),
                "template": c.name,
                "method": c.method,
                "uri": c.uri,
                "status_code": int(resp["status_code"]),
            }
        )

    input_txt = round_dir / f"{file_id}.txt"
    write_canonical_file(input_txt, file_id=file_id, records=canonical_rows)
    truth_path = round_dir / "truth.jsonl"
    with truth_path.open("w", encoding="utf-8") as f:
        for row in truth_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    subprocess.run(
        [
            sys.executable,
            str(project_root / "scripts" / "extract_old_model_features_from_txt.py"),
            "--input",
            str(input_txt),
            "--preprocessor",
            str(preprocessor),
            "--output-dir",
            str(round_dir),
            "--keep-static",
        ],
        check=True,
    )

    old_model_input = round_dir / f"{file_id}.old_model_input.csv"
    model_jsonl = round_dir / f"{file_id}.model_result.jsonl"
    model_csv = round_dir / f"{file_id}.model_result.csv"
    subprocess.run(
        [
            sys.executable,
            str(project_root / "scripts" / "run_old_model_direct.py"),
            "--input",
            str(old_model_input),
            "--preprocessor",
            str(preprocessor),
            "--model",
            str(model),
            "--output-jsonl",
            str(model_jsonl),
            "--output-csv",
            str(model_csv),
            "--label-threshold",
            str(current_threshold),
        ],
        check=True,
    )

    truth_map = {int(x["seq_id"]): x for x in truth_rows}
    eval_rows: List[Dict[str, Any]] = []
    with model_jsonl.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            obj = json.loads(line)
            seq_id = int(obj["seq_id"])
            if seq_id not in truth_map:
                continue
            eval_rows.append(
                {
                    "seq_id": seq_id,
                    "score": float(obj.get("score") or 0.0),
                    "is_attack": int(truth_map[seq_id]["is_attack"]),
                }
            )

    current_metrics = calc_metrics(eval_rows, current_threshold)
    best_metrics, all_metrics = find_best_threshold(eval_rows)
    gain = best_metrics["accuracy"] - current_metrics["accuracy"]
    round_summary = {
        "round_id": round_id,
        "file_id": file_id,
        "input_total": len(mixed),
        "scored_total": len(eval_rows),
        "coverage_ratio": (len(eval_rows) / len(mixed)) if mixed else 0.0,
        "current_threshold": current_threshold,
        "current_metrics": current_metrics,
        "best_metrics": best_metrics,
        "accuracy_gain": gain,
        "threshold_scan": all_metrics,
    }
    (round_dir / "round_summary.json").write_text(json.dumps(round_summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return round_summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Iterative threshold tuning with 1000 attack + 1000 benign mixed traffic")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3000)
    parser.add_argument("--attacks-per-round", type=int, default=1000)
    parser.add_argument("--benign-per-round", type=int, default=1000)
    parser.add_argument("--initial-threshold", type=float, default=0.46)
    parser.add_argument("--max-rounds", type=int, default=6)
    parser.add_argument("--min-rounds", type=int, default=2)
    parser.add_argument("--min-accuracy-gain", type=float, default=0.002)
    parser.add_argument("--seed", type=int, default=20260425)
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--output-root", default="output/iterative_threshold_tuning")
    parser.add_argument("--preprocessor", default="../traffic_mlp/models/preprocessor.joblib")
    parser.add_argument("--model", default="../traffic_mlp/models/best_mlp.pth")
    parser.add_argument("--start-lab", action="store_true", help="start target_multivuln_lab automatically")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    random.seed(args.seed)
    project_root = Path(args.project_root).resolve()
    output_root = (project_root / args.output_root).resolve()
    output_root.mkdir(parents=True, exist_ok=True)

    pre = (project_root / args.preprocessor).resolve()
    model = (project_root / args.model).resolve()
    if not pre.exists():
        raise FileNotFoundError(f"preprocessor not found: {pre}")
    if not model.exists():
        raise FileNotFoundError(f"model not found: {model}")

    lab_proc: subprocess.Popen | None = None
    if args.start_lab:
        lab_proc = subprocess.Popen(
            [
                sys.executable,
                str(project_root / "scripts" / "target_multivuln_lab.py"),
                "--host",
                args.host,
                "--port",
                str(args.port),
            ],
            cwd=str(project_root),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    try:
        wait_http_ready(f"http://{args.host}:{args.port}/health", timeout_sec=30.0)
        history: List[Dict[str, Any]] = []
        threshold = float(args.initial_threshold)

        for rid in range(1, int(args.max_rounds) + 1):
            summary = run_round(
                round_id=rid,
                current_threshold=threshold,
                output_root=output_root,
                host=args.host,
                port=int(args.port),
                attacks_per_round=int(args.attacks_per_round),
                benign_per_round=int(args.benign_per_round),
                preprocessor=pre,
                model=model,
                project_root=project_root,
            )
            history.append(summary)
            threshold = float(summary["best_metrics"]["threshold"])

            if rid >= int(args.min_rounds) and float(summary["accuracy_gain"]) < float(args.min_accuracy_gain):
                break

        final = {
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "initial_threshold": float(args.initial_threshold),
            "final_threshold": float(threshold),
            "round_count": len(history),
            "stop_rule": {
                "min_accuracy_gain": float(args.min_accuracy_gain),
                "min_rounds": int(args.min_rounds),
            },
            "history": history,
        }
        final_path = output_root / "final_summary.json"
        final_path.write_text(json.dumps(final, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(final, ensure_ascii=False, indent=2))
        print(f"\n[iterative-threshold-tuning] final summary: {final_path}")
    finally:
        safe_terminate(lab_proc)


if __name__ == "__main__":
    main()
