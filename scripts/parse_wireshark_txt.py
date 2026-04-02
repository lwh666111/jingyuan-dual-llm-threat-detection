import argparse
import csv
import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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

REQUEST_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def read_text_file(path: Path) -> str:
    for encoding in ("utf-8", "utf-8-sig", "gbk", "latin1"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError("unknown", b"", 0, 1, f"无法解码文件: {path}")


def split_blocks(text: str) -> List[str]:
    """尽量兼容不同 Wireshark 导出样式做切块。"""
    normalized = text.replace("\r\n", "\n")

    # 样式 A: 每个包前带 No./Time/Source... 表头
    pattern_header = re.compile(
        r"(?=^No\.\s+Time\s+Source\s+Destination\s+Protocol\s+Length\s+Info)",
        re.MULTILINE,
    )
    parts = [p.strip() for p in pattern_header.split(normalized) if p.strip()]
    if len(parts) > 1:
        return parts

    # 样式 B: 每个包细节里带 Frame <n>:
    pattern_frame = re.compile(r"(?=^Frame\s+\d+\s*:)", re.MULTILINE)
    parts = [p.strip() for p in pattern_frame.split(normalized) if p.strip()]
    if len(parts) > 1:
        return parts

    # 样式 C: 用概要行起始（No Time Source Destination ...）
    lines = normalized.split("\n")
    blocks: List[str] = []
    current: List[str] = []
    summary_re = re.compile(r"^\s*\d+\s+[0-9.]+\s+\S+\s+\S+\s+\S+\s+\d+\s+.+$")
    for line in lines:
        if summary_re.match(line) and current:
            blocks.append("\n".join(current).strip())
            current = [line]
        else:
            current.append(line)
    if current:
        blocks.append("\n".join(current).strip())

    return [b for b in blocks if b]


def extract_first(pattern: str, text: str, flags: int = 0) -> Optional[str]:
    m = re.search(pattern, text, flags)
    return m.group(1) if m else None


def is_http_request_block(block: str) -> bool:
    return bool(
        re.search(
            r"^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP/1\.[01]",
            block,
            re.MULTILINE,
        )
    )


def is_http_response_block(block: str) -> bool:
    return bool(re.search(r"^\s*HTTP/1\.[01]\s+\d{3}", block, re.MULTILINE))


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

    # 优先从概要行读取
    summary_match = re.search(
        r"^\s*(\d+)\s+([0-9.]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(.+)$",
        block,
        re.MULTILINE,
    )
    if summary_match:
        result["frame_no"] = int(summary_match.group(1))
        result["time"] = summary_match.group(2)
        result["src_ip"] = summary_match.group(3)
        result["dst_ip"] = summary_match.group(4)

    # 兼容 Frame n: time 格式
    if result["frame_no"] is None:
        frame_match = re.search(r"^Frame\s+(\d+)\s*:", block, re.MULTILINE)
        if frame_match:
            result["frame_no"] = int(frame_match.group(1))

    if result["time"] is None:
        time_match = re.search(r"Epoch Time:\s*([0-9.]+)", block)
        if time_match:
            result["time"] = time_match.group(1)

    # 兼容 IPv4 行
    if result["src_ip"] is None or result["dst_ip"] is None:
        ip_match = re.search(r"Internet Protocol Version 4,\s+Src:\s*(\S+),\s+Dst:\s*(\S+)", block)
        if ip_match:
            result["src_ip"] = ip_match.group(1)
            result["dst_ip"] = ip_match.group(2)

    # 端口提取（兼容多种导出文本）
    tcp_match = re.search(
        r"Transmission Control Protocol,\s+Src Port:\s*(\d+),\s+Dst Port:\s*(\d+)",
        block,
    )
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
    m = re.search(
        r"^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/1\.[01]",
        block,
        re.MULTILINE,
    )
    if m:
        method = m.group(1)
        uri = m.group(2)

    host = extract_first(r"^\s*Host:\s*(.+?)\r?$", block, re.MULTILINE)
    full_uri = extract_first(r"\[Full request URI:\s*(.+?)\]", block)
    if not full_uri and host and uri:
        scheme = "https" if ":443" in host else "http"
        full_uri = f"{scheme}://{host}{uri}"

    user_agent = extract_first(r"^\s*User-Agent:\s*(.+?)\r?$", block, re.MULTILINE)
    content_type = extract_first(r"^\s*Content-Type:\s*(.+?)\r?$", block, re.MULTILINE)

    response_frame = extract_first(r"\[Response in frame:\s*(\d+)\]", block)
    if not response_frame:
        response_frame = extract_first(r"Response in frame:\s*(\d+)", block)
    response_frame_int = int(response_frame) if response_frame else None

    request_body = ""
    body_match = re.search(r"File Data:\s*\d+\s*bytes(.*?)(?:JavaScript Object Notation:|$)", block, re.DOTALL)
    if body_match:
        request_body = body_match.group(1).strip()

    if not request_body:
        json_lines = []
        for line in block.splitlines():
            if any(k in line for k in ("String value:", "Number value:", "False value", "True value", "Null value")):
                json_lines.append(line.strip())
        if json_lines:
            request_body = " | ".join(json_lines[:20])

    return {
        **meta,
        "type": "request",
        "method": method,
        "uri": uri,
        "host": host,
        "full_uri": full_uri,
        "user_agent": user_agent,
        "content_type": content_type,
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

    response_body_excerpt = ""
    json_lines = []
    for line in block.splitlines():
        if any(k in line for k in ("String value:", "Number value:", "False value", "True value", "Null value")):
            json_lines.append(line.strip())
    if json_lines:
        response_body_excerpt = " | ".join(json_lines[:20])
    else:
        file_data_match = re.search(r"File Data:\s*\d+\s*bytes(.*)$", block, re.DOTALL)
        if file_data_match:
            response_body_excerpt = file_data_match.group(1).strip()[:500]

    return {
        **meta,
        "type": "response",
        "status_code": status_code_int,
        "request_frame": request_frame_int,
        "response_body_excerpt": response_body_excerpt,
    }


def is_static_resource(uri: Optional[str]) -> bool:
    if not uri:
        return False
    uri_path = uri.lower().split("?", 1)[0]
    return any(uri_path.endswith(ext) for ext in STATIC_EXTENSIONS)


def mask_sensitive_text(text: str) -> str:
    if not text:
        return text

    replacements = [
        (r'("password"\s*:\s*")[^"]+(")', r"\\1***\\2"),
        (r'("token"\s*:\s*")[^"]+(")', r"\\1***\\2"),
        (r'("authorization"\s*:\s*")[^"]+(")', r"\\1***\\2"),
        (r"(?i)(Authorization:\s*)(.+)", r"\\1***"),
        (r"(?i)(Cookie:\s*)(.+)", r"\\1***"),
    ]

    result = text
    for pattern, repl in replacements:
        result = re.sub(pattern, repl, result)

    result = re.sub(r"(data:image/[^;]+;base64,)[A-Za-z0-9+/=]{100,}", r"\\1<BASE64_TRUNCATED>", result)
    return result


def build_records(requests: Dict[int, Dict], responses: Dict[int, Dict], file_id: str, keep_static: bool = False) -> List[Dict]:
    records: List[Dict] = []
    seq_id = 1

    # 建立反向映射：response.request_frame -> response
    response_by_req_frame = {resp.get("request_frame"): resp for resp in responses.values() if resp.get("request_frame") is not None}

    for frame_req in sorted(requests.keys()):
        req = requests[frame_req]
        resp: Optional[Dict] = None

        if req.get("response_frame") and req["response_frame"] in responses:
            resp = responses[req["response_frame"]]
        elif frame_req in response_by_req_frame:
            resp = response_by_req_frame[frame_req]

        if not keep_static and is_static_resource(req.get("uri")):
            continue

        records.append(
            {
                "file_id": file_id,
                "seq_id": seq_id,
                "frame_req": req.get("frame_no"),
                "frame_resp": resp.get("frame_no") if resp else None,
                "time": req.get("time"),
                "src_ip": req.get("src_ip"),
                "dst_ip": req.get("dst_ip"),
                "src_port": req.get("src_port"),
                "dst_port": req.get("dst_port"),
                "method": req.get("method"),
                "uri": req.get("uri"),
                "host": req.get("host"),
                "full_uri": req.get("full_uri"),
                "user_agent": req.get("user_agent"),
                "content_type": req.get("content_type"),
                "request_body": mask_sensitive_text(req.get("request_body", "")),
                "status_code": resp.get("status_code") if resp else None,
                "response_body_excerpt": mask_sensitive_text(resp.get("response_body_excerpt", "")) if resp else "",
                "raw_request_block": mask_sensitive_text(req.get("raw_block", "")),
                "raw_response_block": mask_sensitive_text(resp.get("raw_block", "")) if resp else "",
            }
        )
        seq_id += 1

    return records


def write_jsonl(records: List[Dict], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_index_csv(records: List[Dict], path: Path) -> None:
    fieldnames = ["file_id", "seq_id", "frame_req", "frame_resp", "method", "uri", "status_code"]
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for rec in records:
            writer.writerow({k: rec.get(k) for k in fieldnames})


def parse_wireshark_txt(input_path: Path, output_dir: Path, keep_static: bool = False) -> Tuple[Path, Path]:
    text = read_text_file(input_path)
    blocks = split_blocks(text)
    logging.info("共切分出 %d 个 block", len(blocks))

    requests: Dict[int, Dict] = {}
    responses: Dict[int, Dict] = {}

    for block in blocks:
        try:
            if is_http_request_block(block):
                req = parse_http_request(block)
                if req["frame_no"] is not None:
                    requests[req["frame_no"]] = req
            elif is_http_response_block(block):
                resp = parse_http_response(block)
                if resp["frame_no"] is not None:
                    responses[resp["frame_no"]] = resp
        except Exception as exc:  # noqa: BLE001
            logging.warning("解析 block 失败: %s", exc)

    logging.info("识别到请求块: %d", len(requests))
    logging.info("识别到响应块: %d", len(responses))

    file_id = input_path.stem
    records = build_records(requests, responses, file_id=file_id, keep_static=keep_static)

    orphan_responses = [r for r in responses.values() if r.get("request_frame") not in requests]
    if orphan_responses:
        logging.info("未匹配到请求的响应块: %d", len(orphan_responses))

    logging.info("最终输出记录数: %d", len(records))

    output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = output_dir / f"{file_id}.parsed.jsonl"
    csv_path = output_dir / f"{file_id}.index_map.csv"

    write_jsonl(records, jsonl_path)
    write_index_csv(records, csv_path)

    return jsonl_path, csv_path


def main() -> None:
    parser = argparse.ArgumentParser(description="解析 Wireshark 导出的 txt 文件")
    parser.add_argument("--input", required=True, help="输入 txt 文件路径")
    parser.add_argument("--output-dir", default="output", help="输出目录")
    parser.add_argument("--keep-static", action="store_true", help="保留静态资源请求")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"输入文件不存在: {input_path}")

    output_dir = Path(args.output_dir)
    jsonl_path, csv_path = parse_wireshark_txt(input_path=input_path, output_dir=output_dir, keep_static=args.keep_static)

    logging.info("JSONL 输出: %s", jsonl_path)
    logging.info("索引 CSV 输出: %s", csv_path)


if __name__ == "__main__":
    main()
