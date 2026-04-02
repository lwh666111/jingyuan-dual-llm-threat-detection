import argparse
import csv
import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

SUSPICIOUS_CHARS = ["'", "\"", "<", ">", ";", "--", "../", "%27", "%3c", "%3e", "%2e%2e", " or ", " and "]
LOGIN_KEYWORDS = ["login", "auth", "signin", "session"]
CAPTCHA_KEYWORDS = ["captcha", "verify"]
ADMIN_KEYWORDS = ["admin", "root", "system", "manage", "panel"]
TOKEN_KEYWORDS = ["token", "jwt", "bearer", "authorization"]
PASSWORD_KEYWORDS = ["password", "passwd", "pwd"]


def read_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def safe_str(value):
    if value is None:
        return ""
    return str(value)


def clean_http_text(value) -> str:
    text = safe_str(value)
    text = text.replace("\\r\\n", " ").replace("\\n", " ").replace("\\r", " ")
    return text.strip()


def count_special_chars(text: str) -> int:
    text_lower = text.lower()
    count = 0
    for item in SUSPICIOUS_CHARS:
        count += text_lower.count(item.lower())
    return count


def count_path_depth(uri: str) -> int:
    if not uri:
        return 0
    path = uri.split("?", 1)[0]
    return len([x for x in path.split("/") if x])


def get_query_len(uri: str) -> int:
    if not uri or "?" not in uri:
        return 0
    return len(uri.split("?", 1)[1])


def contains_keywords(text: str, keywords) -> int:
    text_lower = text.lower()
    return 1 if any(k in text_lower for k in keywords) else 0


def has_json_body(content_type: str, body: str) -> int:
    ct = content_type.lower()
    if "json" in ct:
        return 1
    body = body.strip()
    if body.startswith("{") and body.endswith("}"):
        return 1
    return 0


def resp_is_error(status_code) -> int:
    try:
        code = int(status_code)
        return 1 if code >= 400 else 0
    except Exception:
        return 0


def build_request_text(record: dict) -> str:
    parts = [
        f"METHOD={safe_str(record.get('method'))}",
        f"URI={safe_str(record.get('uri'))}",
        f"HOST={safe_str(record.get('host'))}",
        f"CONTENT_TYPE={safe_str(record.get('content_type'))}",
        f"STATUS_CODE={safe_str(record.get('status_code'))}",
        f"REQUEST_BODY={safe_str(record.get('request_body'))}",
        f"RESPONSE_EXCERPT={safe_str(record.get('response_body_excerpt'))}",
    ]
    return "\n".join(parts)


def transform_record(record: dict) -> dict:
    method = safe_str(record.get("method")).upper()
    uri = safe_str(record.get("uri"))
    host = clean_http_text(record.get("host"))
    content_type = clean_http_text(record.get("content_type"))
    request_body = safe_str(record.get("request_body"))
    status_code = safe_str(record.get("status_code"))
    user_agent = safe_str(record.get("user_agent"))
    response_body_excerpt = safe_str(record.get("response_body_excerpt"))

    merged_text = " ".join([uri, host, request_body, response_body_excerpt, user_agent, content_type])

    transformed = {
        "file_id": safe_str(record.get("file_id")),
        "seq_id": record.get("seq_id"),
        "method": method,
        "uri": uri,
        "host": host,
        "status_code": status_code,
        "uri_len": len(uri),
        "query_len": get_query_len(uri),
        "path_depth": count_path_depth(uri),
        "special_char_count": count_special_chars(merged_text),
        "body_len": len(request_body),
        "user_agent_len": len(user_agent),
        "is_get": 1 if method == "GET" else 0,
        "is_post": 1 if method == "POST" else 0,
        "has_json_body": has_json_body(content_type, request_body),
        "has_login_keyword": contains_keywords(merged_text, LOGIN_KEYWORDS),
        "has_captcha_keyword": contains_keywords(merged_text, CAPTCHA_KEYWORDS),
        "has_admin_keyword": contains_keywords(merged_text, ADMIN_KEYWORDS),
        "has_token_keyword": contains_keywords(merged_text, TOKEN_KEYWORDS),
        "has_password_keyword": contains_keywords(merged_text, PASSWORD_KEYWORDS),
        "resp_is_error": resp_is_error(status_code),
        "request_text": build_request_text(
            {
                "method": method,
                "uri": uri,
                "host": host,
                "content_type": content_type,
                "status_code": status_code,
                "request_body": request_body,
                "response_body_excerpt": response_body_excerpt,
            }
        ),
    }
    return transformed


def write_jsonl(records, path: Path):
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def write_csv(records, path: Path):
    if not records:
        return
    fieldnames = list(records[0].keys())
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow(r)


def main():
    parser = argparse.ArgumentParser(description="将 parsed.jsonl 转成模型输入文件")
    parser.add_argument("--input", required=True, help="输入 parsed jsonl 文件")
    parser.add_argument("--output-dir", default="output", help="输出目录")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"输入文件不存在: {input_path}")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    file_id = input_path.stem.replace(".parsed", "")
    model_jsonl = output_dir / f"{file_id}.model_input.jsonl"
    model_csv = output_dir / f"{file_id}.model_input.csv"

    records = [transform_record(record) for record in read_jsonl(input_path)]

    write_jsonl(records, model_jsonl)
    write_csv(records, model_csv)

    logging.info("总记录数: %d", len(records))
    logging.info("JSONL 输出: %s", model_jsonl)
    logging.info("CSV 输出: %s", model_csv)

    for item in records[:5]:
        logging.info(
            "seq=%s method=%s uri=%s status=%s special=%s",
            item["seq_id"],
            item["method"],
            item["uri"],
            item["status_code"],
            item["special_char_count"],
        )


if __name__ == "__main__":
    main()
