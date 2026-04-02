import argparse
import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

STATIC_EXTENSIONS = {
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".map",
}

SQL_KEYWORDS = [
    " or ",
    "or1=1",
    "or 1=1",
    "union",
    "select",
    "sleep(",
    "benchmark(",
    "--",
    "../",
    "%27",
    "%3c",
    "%3e",
    "'",
]


def read_text_file(path: Path) -> str:
    for encoding in ("utf-8", "utf-8-sig", "gbk", "latin1"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
    raise RuntimeError(f"无法解码文件: {path}")


def is_canonical_format(text: str) -> bool:
    return "### BATCH_START ###" in text and "### CASE_START ###" in text


def split_blocks(text: str) -> List[str]:
    normalized = text.replace("\r\n", "\n")

    pattern_header = re.compile(
        r"(?=^No\.\s+Time\s+Source\s+Destination\s+Protocol\s+Length\s+Info)", re.MULTILINE
    )
    parts = [p.strip() for p in pattern_header.split(normalized) if p.strip()]
    if len(parts) > 1:
        return parts

    pattern_frame = re.compile(r"(?=^Frame\s+\d+\s*:)", re.MULTILINE)
    parts = [p.strip() for p in pattern_frame.split(normalized) if p.strip()]
    if len(parts) > 1:
        return parts

    summary_re = re.compile(r"^\s*\d+\s+[0-9.]+\s+\S+\s+\S+\s+\S+\s+\d+\s+.+$")
    lines = normalized.split("\n")
    blocks: List[str] = []
    current: List[str] = []
    for line in lines:
        if summary_re.match(line) and current:
            blocks.append("\n".join(current).strip())
            current = [line]
        else:
            current.append(line)
    if current:
        blocks.append("\n".join(current).strip())
    return [b for b in blocks if b]


def extract_first(pattern: str, text: str, flags=0) -> Optional[str]:
    m = re.search(pattern, text, flags)
    return m.group(1) if m else None


def is_http_request_block(block: str) -> bool:
    return bool(
        re.search(r"^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP/1\.[01]", block, re.MULTILINE)
    )


def is_http_response_block(block: str) -> bool:
    return bool(re.search(r"^\s*HTTP/1\.[01]\s+\d{3}", block, re.MULTILINE))


def is_static_resource(uri: Optional[str]) -> bool:
    if not uri:
        return False
    uri_lower = uri.lower().split("?", 1)[0]
    return any(uri_lower.endswith(ext) for ext in STATIC_EXTENSIONS)


def mask_sensitive_text(text: str) -> str:
    if not text:
        return text
    text = re.sub(r'("password"\s*:\s*")[^"]+(")', r"\1***\2", text, flags=re.I)
    text = re.sub(r"(?i)(Authorization:\s*)(.+)", r"\1***", text)
    text = re.sub(r"(?i)(Cookie:\s*)(.+)", r"\1***", text)
    text = re.sub(r"(data:image/[^;]+;base64,)[A-Za-z0-9+/=]{100,}", r"\1<BASE64_TRUNCATED>", text)
    return text


def _is_mostly_readable(text: str) -> bool:
    if not text:
        return False
    bad = 0
    total = 0
    for ch in text:
        total += 1
        code = ord(ch)
        if code in (9, 10, 13):
            continue
        if code < 32 or code == 127:
            bad += 1
    if total == 0:
        return False
    return (bad / total) <= 0.1


def decode_hex_payload_if_needed(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""

    compact = raw
    if re.fullmatch(r"(?:[0-9A-Fa-f]{2}:)+[0-9A-Fa-f]{2}", compact):
        compact = compact.replace(":", "")
    elif re.fullmatch(r"(?:[0-9A-Fa-f]{2}\s+)+[0-9A-Fa-f]{2}", compact):
        compact = re.sub(r"\s+", "", compact)

    if not re.fullmatch(r"[0-9A-Fa-f]+", compact):
        return raw
    if len(compact) < 8 or len(compact) % 2 != 0:
        return raw

    try:
        data = bytes.fromhex(compact)
    except Exception:
        return raw

    for enc in ("utf-8", "gb18030", "latin1"):
        try:
            decoded = data.decode(enc)
        except Exception:
            continue
        if _is_mostly_readable(decoded):
            return decoded

    return raw


def load_preprocessor_schema(preprocessor):
    numeric_cols = []
    categorical_cols = []
    categorical_choices = {}

    for name, transformer, cols in preprocessor.transformers_:
        if name == "num":
            numeric_cols = list(cols)
        elif name == "cat":
            categorical_cols = list(cols)
            onehot = None
            try:
                onehot = transformer.named_steps.get("onehot")
            except Exception:
                onehot = None

            if onehot is not None and hasattr(onehot, "categories_"):
                for col_name, cats in zip(categorical_cols, onehot.categories_):
                    categorical_choices[col_name] = [str(x) for x in cats]

    return numeric_cols, categorical_cols, categorical_choices


# ----------------------
# Canonical format parser
# ----------------------

def parse_kv_lines(lines: List[str]) -> Dict[str, str]:
    data = {}
    for line in lines:
        if "=" in line:
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip()
    return data


def _extract_case_blocks(case_text: str) -> Tuple[Dict[str, str], str, str]:
    lines = case_text.splitlines()
    meta_lines: List[str] = []
    request_lines: List[str] = []
    response_lines: List[str] = []

    state = "meta"
    for line in lines:
        s = line.strip()
        if s == "[REQUEST_BLOCK]":
            state = "request"
            continue
        if s == "[/REQUEST_BLOCK]":
            state = "meta"
            continue
        if s == "[RESPONSE_BLOCK]":
            state = "response"
            continue
        if s == "[/RESPONSE_BLOCK]":
            state = "meta"
            continue

        if state == "meta":
            meta_lines.append(line)
        elif state == "request":
            request_lines.append(line)
        elif state == "response":
            response_lines.append(line)

    return parse_kv_lines(meta_lines), "\n".join(request_lines).strip(), "\n".join(response_lines).strip()


def _get_body_from_request_text(req_text: str) -> str:
    for line in req_text.split("\n"):
        if line.startswith("REQUEST_BODY="):
            return decode_hex_payload_if_needed(line.split("=", 1)[1])
    return decode_hex_payload_if_needed(req_text)


def _get_response_excerpt(req_text: str, resp_text: str) -> str:
    for line in req_text.split("\n"):
        if line.startswith("RESPONSE_EXCERPT="):
            return decode_hex_payload_if_needed(line.split("=", 1)[1])
    for line in resp_text.split("\n"):
        if line.startswith("RESPONSE_EXCERPT="):
            return decode_hex_payload_if_needed(line.split("=", 1)[1])
    return decode_hex_payload_if_needed(resp_text)


def _normalize_request_text(req_text: str) -> str:
    out = []
    for line in req_text.split("\n"):
        line = line.rstrip("\\")
        if line.startswith("REQUEST_BODY="):
            out.append("REQUEST_BODY=" + decode_hex_payload_if_needed(line.split("=", 1)[1]))
        elif line.startswith("RESPONSE_EXCERPT="):
            out.append("RESPONSE_EXCERPT=" + decode_hex_payload_if_needed(line.split("=", 1)[1]))
        else:
            out.append(line)
    return "\n".join(out)


def _normalize_response_text(resp_text: str) -> str:
    out = []
    for line in resp_text.split("\n"):
        line = line.rstrip("\\")
        if line.startswith("RESPONSE_EXCERPT="):
            out.append("RESPONSE_EXCERPT=" + decode_hex_payload_if_needed(line.split("=", 1)[1]))
        else:
            out.append(line)
    return "\n".join(out)


def _normalize_http_block_body(block_text: str) -> str:
    marker = "\nBody:\n"
    if marker not in block_text:
        return block_text
    head, tail = block_text.split(marker, 1)
    return head + marker + decode_hex_payload_if_needed(tail)


def parse_canonical_records(text: str, file_id_fallback: str) -> Tuple[Dict[int, Dict], Dict[int, Dict]]:
    requests: Dict[int, Dict] = {}
    responses: Dict[int, Dict] = {}

    case_blocks = re.findall(r"### CASE_START ###(.*?)### CASE_END ###", text, flags=re.DOTALL)
    for idx, block in enumerate(case_blocks, start=1):
        meta, req_block, resp_block = _extract_case_blocks(block)

        file_id = meta.get("file_id", file_id_fallback)
        seq_id = int(meta.get("seq_id", idx)) if str(meta.get("seq_id", "")).isdigit() else idx
        frame_req = int(meta.get("frame_req", seq_id)) if str(meta.get("frame_req", "")).isdigit() else seq_id

        frame_resp = None
        if str(meta.get("frame_resp", "")).isdigit():
            frame_resp = int(meta.get("frame_resp"))

        time_req = None
        try:
            time_req = float(meta.get("time_req", ""))
        except Exception:
            time_req = float(seq_id)

        time_resp = None
        try:
            time_resp = float(meta.get("time_resp", ""))
        except Exception:
            time_resp = (time_req + 0.01) if time_req is not None else None

        req_text_raw = meta.get("request_text", "")
        resp_text_raw = meta.get("response_text", "")
        request_text_value = _normalize_request_text(req_text_raw.replace("\\\\n", "\n").replace("\\n", "\n"))
        response_text_value = _normalize_response_text(resp_text_raw.replace("\\\\n", "\n").replace("\\n", "\n"))
        req_block = _normalize_http_block_body(req_block)
        resp_block = _normalize_http_block_body(resp_block)

        method = meta.get("method", "")
        uri = meta.get("uri", "")
        host = meta.get("host", "")
        content_type = meta.get("content_type", "")

        req = {
            "frame_no": frame_req,
            "time": time_req,
            "src_ip": meta.get("src_ip", ""),
            "dst_ip": meta.get("dst_ip", ""),
            "src_port": int(meta.get("src_port", 0)) if str(meta.get("src_port", "")).isdigit() else 0,
            "dst_port": int(meta.get("dst_port", 0)) if str(meta.get("dst_port", "")).isdigit() else 0,
            "raw_block": req_block,
            "type": "request",
            "method": method,
            "uri": uri,
            "host": host,
            "full_uri": "",
            "user_agent": "",
            "content_type": content_type,
            "response_frame": frame_resp,
            "request_body": _get_body_from_request_text(request_text_value),
            "_request_text": request_text_value,
            "_file_id": file_id,
            "_seq_id": seq_id,
        }
        requests[frame_req] = req

        if frame_resp is not None:
            status_code = None
            try:
                status_code = int(meta.get("status_code", ""))
            except Exception:
                status_code = None

            resp = {
                "frame_no": frame_resp,
                "time": time_resp,
                "src_ip": meta.get("dst_ip", ""),
                "dst_ip": meta.get("src_ip", ""),
                "src_port": int(meta.get("dst_port", 0)) if str(meta.get("dst_port", "")).isdigit() else 0,
                "dst_port": int(meta.get("src_port", 0)) if str(meta.get("src_port", "")).isdigit() else 0,
                "raw_block": resp_block,
                "type": "response",
                "status_code": status_code,
                "request_frame": frame_req,
                "response_body_excerpt": _get_response_excerpt(request_text_value, response_text_value),
                "_response_text": response_text_value,
            }
            responses[frame_resp] = resp

    return requests, responses


# ----------------------
# Verbose format parser
# ----------------------

def parse_block_meta(block: str) -> Dict:
    result = {
        "frame_no": None,
        "time": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "raw_block": block,
    }

    summary_match = re.search(
        r"^\s*(\d+)\s+([0-9.]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(.+)$", block, re.MULTILINE
    )
    if summary_match:
        result["frame_no"] = int(summary_match.group(1))
        result["time"] = float(summary_match.group(2))
        result["src_ip"] = summary_match.group(3)
        result["dst_ip"] = summary_match.group(4)

    if result["frame_no"] is None:
        frame_match = re.search(r"^Frame\s+(\d+)\s*:", block, re.MULTILINE)
        if frame_match:
            result["frame_no"] = int(frame_match.group(1))

    if result["time"] is None:
        epoch_match = re.search(r"Epoch Time:\s*([0-9.]+)", block)
        if epoch_match:
            result["time"] = float(epoch_match.group(1))

    tcp_match = re.search(r"Transmission Control Protocol,\s+Src Port:\s*(\d+),\s+Dst Port:\s*(\d+)", block)
    if not tcp_match:
        tcp_match = re.search(r"Source Port:\s*(\d+).*?Destination Port:\s*(\d+)", block, re.DOTALL)
    if tcp_match:
        result["src_port"] = int(tcp_match.group(1))
        result["dst_port"] = int(tcp_match.group(2))
    return result


def parse_http_request(block: str) -> Dict:
    meta = parse_block_meta(block)

    method = None
    uri = None
    m = re.search(r"^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/1\.[01]", block, re.MULTILINE)
    if m:
        method = m.group(1)
        uri = m.group(2)

    host = extract_first(r"^\s*Host:\s*(.+?)\r?$", block, re.MULTILINE)
    full_uri = extract_first(r"\[Full request URI:\s*(.+?)\]", block)
    user_agent = extract_first(r"^\s*User-Agent:\s*(.+?)\r?$", block, re.MULTILINE)
    content_type = extract_first(r"^\s*Content-Type:\s*(.+?)\r?$", block, re.MULTILINE)

    response_frame = extract_first(r"\[Response in frame:\s*(\d+)\]", block)
    if not response_frame:
        response_frame = extract_first(r"Response in frame:\s*(\d+)", block)
    response_frame_int = int(response_frame) if response_frame else None

    json_value_lines = []
    for line in block.splitlines():
        if any(k in line for k in ("String value:", "Number value:", "False value", "True value", "Null value")):
            json_value_lines.append(line.strip())
    request_body = " | ".join(json_value_lines[:50]) if json_value_lines else ""

    return {
        **meta,
        "type": "request",
        "method": method,
        "uri": uri,
        "host": host.strip() if host else None,
        "full_uri": full_uri,
        "user_agent": user_agent.strip() if user_agent else None,
        "content_type": content_type.strip() if content_type else None,
        "response_frame": response_frame_int,
        "request_body": request_body,
    }


def parse_http_response(block: str) -> Dict:
    meta = parse_block_meta(block)

    status_code = extract_first(r"^\s*HTTP/1\.[01]\s+(\d{3})", block, re.MULTILINE)
    status_code_int = int(status_code) if status_code else None

    request_frame = extract_first(r"\[Request in frame:\s*(\d+)\]", block)
    if not request_frame:
        request_frame = extract_first(r"Request in frame:\s*(\d+)", block)
    request_frame_int = int(request_frame) if request_frame else None

    json_value_lines = []
    for line in block.splitlines():
        if any(k in line for k in ("String value:", "Number value:", "False value", "True value", "Null value")):
            json_value_lines.append(line.strip())
    response_body_excerpt = " | ".join(json_value_lines[:50]) if json_value_lines else ""

    return {
        **meta,
        "type": "response",
        "status_code": status_code_int,
        "request_frame": request_frame_int,
        "response_body_excerpt": response_body_excerpt,
    }


# ----------------------
# Shared feature mapping
# ----------------------

def lower_text(*parts) -> str:
    return " ".join([str(x or "") for x in parts]).lower()


def choose_category(col_name, choices, request_rec, response_rec):
    cats = choices.get(col_name, [])

    if col_name == "proto":
        preferred = ["tcp", "udp", "icmp"]
    elif col_name == "service":
        preferred = ["http", "https", "-", "dns"]
    elif col_name == "state":
        text = lower_text(
            request_rec.get("request_body"),
            response_rec.get("response_body_excerpt") if response_rec else "",
            request_rec.get("uri"),
        )
        http_code = int(response_rec.get("status_code") or 0) if response_rec else 0
        biz_error = 1 if ("errauth" in text or "errcaptcha" in text or "number value: 406" in text) else 0
        if http_code >= 400 or biz_error:
            preferred = ["INT", "FIN", "CON", "REQ"]
        else:
            preferred = ["FIN", "CON", "REQ", "INT"]
    else:
        preferred = []

    for item in preferred:
        if item in cats:
            return item

    return cats[0] if cats else {"proto": "tcp", "service": "http", "state": "FIN"}.get(col_name, "unknown")


def count_sql_signals(text: str) -> int:
    text = text.lower()
    count = 0
    for kw in SQL_KEYWORDS:
        count += text.count(kw.lower())
    return count


def contains_any(text: str, words: List[str]) -> int:
    t = text.lower()
    return 1 if any(w in t for w in words) else 0


def build_request_text(req: Dict, resp: Optional[Dict]) -> str:
    return "\n".join(
        [
            f"METHOD={req.get('method') or ''}",
            f"URI={req.get('uri') or ''}",
            f"HOST={req.get('host') or ''}",
            f"CONTENT_TYPE={req.get('content_type') or ''}",
            f"STATUS_CODE={resp.get('status_code') if resp else ''}",
            f"REQUEST_BODY={req.get('request_body') or ''}",
            f"RESPONSE_EXCERPT={resp.get('response_body_excerpt') if resp else ''}",
        ]
    )


def build_numeric_value(col, req: Dict, resp: Optional[Dict]):
    uri = str(req.get("uri") or "")
    host = str(req.get("host") or "")
    user_agent = str(req.get("user_agent") or "")
    content_type = str(req.get("content_type") or "")
    request_body = str(req.get("request_body") or "")
    response_excerpt = str(resp.get("response_body_excerpt") or "") if resp else ""

    req_time = float(req.get("time") or 0.0)
    resp_time = float(resp.get("time") or 0.0) if resp else 0.0
    time_gap = max(0.001, resp_time - req_time) if resp else 0.05

    merged_text = lower_text(uri, host, request_body, response_excerpt, user_agent, content_type)

    sql_signal = count_sql_signals(merged_text)
    login_kw = contains_any(merged_text, ["login", "auth", "signin", "session"])
    captcha_kw = contains_any(merged_text, ["captcha", "verify"])
    password_kw = contains_any(merged_text, ["password", "passwd", "pwd"])
    admin_kw = contains_any(merged_text, ["admin", "root", "manage", "panel"])
    token_kw = contains_any(merged_text, ["token", "jwt", "bearer", "authorization"])
    json_kw = 1 if "json" in content_type.lower() else 0
    business_error = 1 if ("errauth" in merged_text or "errcaptcha" in merged_text or "number value: 406" in merged_text) else 0
    suspicious_bonus = sql_signal * 3 + password_kw * 2 + login_kw + business_error * 3 + token_kw

    uri_len = len(uri)
    path_depth = len([x for x in uri.split("?", 1)[0].split("/") if x])
    body_len = len(request_body)
    ua_len = len(user_agent)
    text_len = len(build_request_text(req, resp))

    dur = min(5.0, 0.03 + time_gap + body_len / 5000.0 + sql_signal * 0.02)
    spkts = 2.0 + path_depth + (1 if req.get("method") == "POST" else 0) + suspicious_bonus
    dpkts = 2.0 + (1 if resp else 0) + business_error
    sbytes = 100.0 + uri_len + body_len + ua_len + suspicious_bonus * 30
    dbytes = 80.0 + min(text_len, 5000) * 0.2 + business_error * 50
    rate = (spkts + dpkts) / max(dur, 0.001)
    sload = sbytes / max(dur, 0.001)
    dload = dbytes / max(dur, 0.001)
    sinpkt = dur / max(spkts, 1.0)
    dinpkt = dur / max(dpkts, 1.0)
    smean = sbytes / max(spkts, 1.0)
    dmean = dbytes / max(dpkts, 1.0)
    sjit = sql_signal * 0.5 + suspicious_bonus * 0.2
    djit = business_error * 0.8 + sql_signal * 0.3

    known = {
        "dur": dur,
        "spkts": spkts,
        "dpkts": dpkts,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "rate": rate,
        "sttl": 64.0,
        "dttl": 64.0,
        "sload": sload,
        "dload": dload,
        "sloss": 0.0,
        "dloss": 0.0,
        "sinpkt": sinpkt,
        "dinpkt": dinpkt,
        "sjit": sjit,
        "djit": djit,
        "swin": 255.0,
        "stcpb": 1000.0 + (req.get("frame_no") or 0) * 10.0,
        "dtcpb": 2000.0 + ((resp.get("frame_no") if resp else 0) or 0) * 10.0,
        "dwin": 255.0,
        "tcprtt": min(1.0, time_gap + business_error * 0.05),
        "synack": min(1.0, time_gap / 2),
        "ackdat": min(1.0, time_gap / 2),
        "smean": smean,
        "dmean": dmean,
        "trans_depth": 1.0 + json_kw + password_kw + login_kw + suspicious_bonus,
        "response_body_len": min(text_len + business_error * 100, 20000),
        "ct_srv_src": 1.0 + login_kw + captcha_kw + admin_kw,
        "ct_state_ttl": 1.0 + business_error + sql_signal,
        "ct_dst_ltm": 1.0 + login_kw + business_error,
        "ct_src_dport_ltm": 1.0 + suspicious_bonus,
        "ct_dst_sport_ltm": 1.0 + suspicious_bonus,
        "ct_dst_src_ltm": 1.0 + suspicious_bonus,
        "is_ftp_login": 0.0,
        "ct_ftp_cmd": 0.0,
        "ct_flw_http_mthd": 2.0 if req.get("method") == "POST" else 1.0,
        "ct_src_ltm": 1.0 + password_kw + token_kw + sql_signal,
        "ct_srv_dst": 1.0 + admin_kw + business_error,
        "is_sm_ips_ports": 0.0,
    }

    if col in known:
        return known[col]

    c = col.lower()
    if "byte" in c:
        return sbytes
    if "pkt" in c:
        return spkts
    if "load" in c:
        return sload
    if "ttl" in c:
        return 64.0
    if "mean" in c:
        return smean
    if "jit" in c:
        return sjit
    if c.startswith("ct_"):
        return 1.0 + suspicious_bonus
    if c.startswith("is_"):
        return 0.0
    return 0.0


def write_jsonl(records: List[Dict], path: Path):
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def maybe_mask(text: str, enabled: bool) -> str:
    if not enabled:
        return text or ""
    return mask_sensitive_text(text or "")


def parse_records(text: str, file_id: str) -> Tuple[Dict[int, Dict], Dict[int, Dict], str]:
    if is_canonical_format(text):
        req, resp = parse_canonical_records(text, file_id)
        return req, resp, "canonical"

    blocks = split_blocks(text)
    requests = {}
    responses = {}
    for block in blocks:
        try:
            if is_http_request_block(block):
                r = parse_http_request(block)
                if r["frame_no"] is not None:
                    requests[r["frame_no"]] = r
            elif is_http_response_block(block):
                s = parse_http_response(block)
                if s["frame_no"] is not None:
                    responses[s["frame_no"]] = s
        except Exception as exc:  # noqa: BLE001
            logging.warning("解析 block 失败: %s", exc)
    return requests, responses, "verbose"


def main():
    parser = argparse.ArgumentParser(description="从 txt 提取旧模型兼容输入（支持 canonical + verbose）")
    parser.add_argument("--input", required=True, help="Wireshark/canonical txt 文件路径")
    parser.add_argument("--preprocessor", required=True, help="旧 preprocessor.joblib 路径")
    parser.add_argument("--output-dir", required=True, help="输出目录")
    parser.add_argument("--keep-static", action="store_true", help="保留静态资源")
    parser.add_argument("--mask-sensitive", action="store_true", help="开启敏感字段脱敏（默认关闭）")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    file_id = input_path.stem

    text = read_text_file(input_path)
    preprocessor = joblib.load(args.preprocessor)
    numeric_cols, categorical_cols, categorical_choices = load_preprocessor_schema(preprocessor)

    schema_json = output_dir / "old_preprocessor_schema.json"
    schema_json.write_text(
        json.dumps(
            {
                "numeric_cols": numeric_cols,
                "categorical_cols": categorical_cols,
                "categorical_choices": categorical_choices,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    requests, responses, mode = parse_records(text, file_id)

    logging.info("解析模式: %s", mode)
    logging.info("识别到请求数量: %d", len(requests))
    logging.info("识别到响应数量: %d", len(responses))
    logging.info("当前为 compatibility mode：输出仅用于流程验证，不代表最终检测效果。")

    response_by_req = {r.get("request_frame"): r for r in responses.values() if r.get("request_frame") is not None}

    feature_rows = []
    raw_rows = []
    seq_id = 1

    for frame_req in sorted(requests.keys()):
        req = requests[frame_req]
        resp = None

        if req.get("response_frame") and req.get("response_frame") in responses:
            resp = responses[req.get("response_frame")]
        elif frame_req in response_by_req:
            resp = response_by_req[frame_req]

        if not args.keep_static and is_static_resource(req.get("uri")):
            continue

        row = {"file_id": file_id, "seq_id": seq_id}

        for col in categorical_cols:
            row[col] = choose_category(col, categorical_choices, req, resp)

        for col in numeric_cols:
            row[col] = build_numeric_value(col, req, resp)

        feature_rows.append(row)

        req_text = req.get("_request_text") or build_request_text(req, resp)
        raw_rows.append(
            {
                "file_id": file_id,
                "seq_id": seq_id,
                "frame_req": req.get("frame_no"),
                "frame_resp": resp.get("frame_no") if resp else None,
                "method": req.get("method"),
                "uri": req.get("uri"),
                "host": req.get("host"),
                "status_code": resp.get("status_code") if resp else None,
                "request_text": maybe_mask(req_text, args.mask_sensitive),
                "response_text": maybe_mask(resp.get("_response_text", "") if resp else "", args.mask_sensitive),
                "raw_request_block": maybe_mask(req.get("raw_block", ""), args.mask_sensitive),
                "raw_response_block": maybe_mask(resp.get("raw_block", "") if resp else "", args.mask_sensitive),
            }
        )
        seq_id += 1

    feature_df = pd.DataFrame(feature_rows)
    raw_index_jsonl = output_dir / f"{file_id}.raw_index.jsonl"
    old_input_csv = output_dir / f"{file_id}.old_model_input.csv"

    ordered_cols = ["file_id", "seq_id"] + categorical_cols + numeric_cols
    if feature_df.empty:
        feature_df = pd.DataFrame(columns=ordered_cols)
    else:
        feature_df = feature_df[ordered_cols]

    feature_df.to_csv(old_input_csv, index=False, encoding="utf-8-sig")
    write_jsonl(raw_rows, raw_index_jsonl)

    logging.info("最终进入 old_model_input.csv 的记录数: %d", len(feature_df))
    logging.info("old_model_input.csv 列数: %d", len(feature_df.columns))
    logging.info("old_model_input.csv: %s", old_input_csv)
    logging.info("raw_index.jsonl: %s", raw_index_jsonl)

    print("=" * 80)
    preview_cols = ["file_id", "seq_id"] + [c for c in ["proto", "service", "state"] if c in feature_df.columns]
    print(feature_df[preview_cols].head(5))
    print("=" * 80)


if __name__ == "__main__":
    main()
