import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def find_executable(name: str) -> str:
    candidates = []
    if not name.lower().endswith(".exe"):
        candidates.append(f"{name}.exe")
    candidates.append(name)

    for candidate in candidates:
        exe = shutil.which(candidate)
        if exe:
            return exe

    local_appdata = os.environ.get("LOCALAPPDATA", "")
    user_profile = os.environ.get("USERPROFILE", "")
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")

    fallback_dirs = [
        Path(user_profile) / "Wireshark" if user_profile else None,
        Path(local_appdata) / "Programs" / "Wireshark" if local_appdata else None,
        Path(program_files) / "Wireshark",
        Path(program_files_x86) / "Wireshark",
    ]

    for d in fallback_dirs:
        if not d:
            continue
        for candidate in candidates:
            full = d / candidate
            if full.exists():
                return str(full)

    raise FileNotFoundError(
        f"未找到可执行文件: {name}，请确认 Wireshark/TShark 已安装并加入 PATH，"
        "或位于常见目录（如 C:\\Users\\<你>\\Wireshark / C:\\Program Files\\Wireshark）"
    )


def run_text_command(cmd: List[str]) -> str:
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"命令执行失败: {' '.join(cmd)}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    return result.stdout


def list_interfaces(tshark_exe: str):
    output = run_text_command([tshark_exe, "-D"])
    interfaces = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^(\d+)\.\s+(.+)$", line)
        if not m:
            continue
        idx = m.group(1)
        rest = m.group(2)
        interfaces.append({"index": idx, "raw": rest})
    return interfaces


def choose_interface(interfaces, preferred_name: str = "") -> str:
    if preferred_name:
        for iface in interfaces:
            if preferred_name.lower() in iface["raw"].lower():
                return iface["index"]

    preferred_keywords = ["wi-fi", "wlan", "wireless", "wifi"]
    for kw in preferred_keywords:
        for iface in interfaces:
            if kw in iface["raw"].lower():
                return iface["index"]

    for iface in interfaces:
        raw = iface["raw"].lower()
        if "loopback" not in raw and "npcap loopback" not in raw:
            return iface["index"]

    if interfaces:
        return interfaces[0]["index"]

    raise RuntimeError("没有找到可用抓包网卡")


def detect_http_link_fields(tshark_exe: str) -> Tuple[str, str]:
    """
    返回 (request_in_field, response_in_field)：
    - request_in_field: 响应中指向请求帧
    - response_in_field: 请求中指向响应帧
    """
    fields_text = run_text_command([tshark_exe, "-G", "fields"])

    has_request_in = "http.request_in" in fields_text
    has_prev_request_in = "http.prev_request_in" in fields_text
    has_response_in = "http.response_in" in fields_text
    has_next_response_in = "http.next_response_in" in fields_text

    request_in_field = "http.request_in" if has_request_in else "http.prev_request_in" if has_prev_request_in else ""
    response_in_field = "http.response_in" if has_response_in else "http.next_response_in" if has_next_response_in else ""

    if not request_in_field or not response_in_field:
        raise RuntimeError(
            "当前 tshark 缺少 HTTP 请求/响应关联字段，无法稳定配对。"
            f"request_in 可用={has_request_in or has_prev_request_in}, "
            f"response_in 可用={has_response_in or has_next_response_in}"
        )

    return request_in_field, response_in_field


def next_file_index(input_dir: Path, prefix: str = "1.1.") -> int:
    max_n = 0
    for p in input_dir.glob(f"{prefix}*.txt"):
        m = re.match(rf"{re.escape(prefix)}(\d+)\.txt$", p.name)
        if m:
            max_n = max(max_n, int(m.group(1)))
    return max_n + 1


def parse_tshark_line(line: str, headers: List[str]) -> Dict[str, str]:
    reader = csv.reader([line], delimiter="\t", quotechar='"')
    row = next(reader, [])
    if len(row) < len(headers):
        row += [""] * (len(headers) - len(row))
    if len(row) > len(headers):
        row = row[: len(headers)]
    return dict(zip(headers, row))


def clean(v: str) -> str:
    if v is None:
        return ""
    return str(v).strip()


def to_int(v: str) -> Optional[int]:
    v = clean(v)
    if not v:
        return None
    try:
        return int(float(v))
    except Exception:
        return None


def to_float(v: str) -> Optional[float]:
    v = clean(v)
    if not v:
        return None
    try:
        return float(v)
    except Exception:
        return None


def is_mostly_readable(text: str) -> bool:
    if not text:
        return False
    bad = 0
    total = 0
    for ch in text:
        total += 1
        code = ord(ch)
        if code in (9, 10, 13):  # \t \n \r
            continue
        # 控制字符与明显乱码字符
        if code < 32 or code == 127:
            bad += 1
    if total == 0:
        return False
    return (bad / total) <= 0.1


def decode_http_file_data(value: str) -> str:
    raw = clean(value)
    if not raw:
        return ""

    # tshark 的 http.file_data 常见是连续 hex（或带分隔符）
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
        if is_mostly_readable(decoded):
            return decoded

    return raw


def request_text(req: Dict, resp: Optional[Dict]) -> str:
    return "\n".join(
        [
            f"METHOD={req.get('method','')}",
            f"URI={req.get('uri','')}",
            f"HOST={req.get('host','')}",
            f"CONTENT_TYPE={req.get('content_type','')}",
            f"STATUS_CODE={resp.get('status_code','') if resp else ''}",
            f"REQUEST_BODY={req.get('request_body','')}",
            f"RESPONSE_EXCERPT={resp.get('response_body_excerpt','') if resp else ''}",
        ]
    )


def response_text(resp: Optional[Dict]) -> str:
    if not resp:
        return ""
    return "\n".join(
        [
            f"HTTP_STATUS={resp.get('status_code','')}",
            f"MESSAGE={resp.get('response_phrase','')}",
            f"RESPONSE_EXCERPT={resp.get('response_body_excerpt','')}",
        ]
    )


def request_block(req: Dict) -> str:
    lines = [f"{req.get('method','')} {req.get('uri','')} HTTP/1.1"]
    if req.get("host"):
        lines.append(f"Host: {req.get('host')}")
    if req.get("content_type"):
        lines.append(f"Content-Type: {req.get('content_type')}")
    lines.append("Body:")
    lines.append(req.get("request_body") or "")
    return "\n".join(lines)


def response_block(resp: Optional[Dict]) -> str:
    if not resp:
        return ""
    lines = [f"HTTP/1.1 {resp.get('status_code','')} {resp.get('response_phrase','')}"]
    lines.append("Body:")
    lines.append(resp.get("response_body_excerpt") or "")
    return "\n".join(lines)


def write_canonical_batch(path: Path, file_id: str, batch_size: int, port: int, cases: List[Dict]):
    lines: List[str] = []
    lines.append("### BATCH_START ###")
    lines.append(f"file_id={file_id}")
    lines.append(f"batch_size={batch_size}")
    lines.append("source=live_capture")
    lines.append(f"port={port}")
    lines.append("capture_mode=canonical_http_batch")
    lines.append("### BATCH_META_END ###")
    lines.append("")

    for idx, case in enumerate(cases, start=1):
        req = case["request"]
        resp = case.get("response")

        lines.append("### CASE_START ###")
        lines.append(f"file_id={file_id}")
        lines.append(f"seq_id={idx}")
        lines.append(f"frame_req={req.get('frame_no','')}")
        lines.append(f"frame_resp={resp.get('frame_no','') if resp else ''}")
        lines.append(f"time_req={req.get('time','')}")
        lines.append(f"time_resp={resp.get('time','') if resp else ''}")
        lines.append(f"src_ip={req.get('src_ip','')}")
        lines.append(f"dst_ip={req.get('dst_ip','')}")
        lines.append(f"src_port={req.get('src_port','')}")
        lines.append(f"dst_port={req.get('dst_port','')}")
        lines.append(f"method={req.get('method','')}")
        lines.append(f"uri={req.get('uri','')}")
        lines.append(f"host={req.get('host','')}")
        lines.append(f"status_code={resp.get('status_code','') if resp else ''}")
        lines.append(f"content_type={req.get('content_type','')}")
        lines.append(f"request_text={request_text(req, resp).replace(chr(10), r'\n')}")
        lines.append(f"response_text={response_text(resp).replace(chr(10), r'\n')}")
        lines.append("[REQUEST_BLOCK]")
        lines.append(request_block(req))
        lines.append("[/REQUEST_BLOCK]")
        lines.append("[RESPONSE_BLOCK]")
        lines.append(response_block(resp))
        lines.append("[/RESPONSE_BLOCK]")
        lines.append("### CASE_END ###")
        lines.append("")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def build_request_from_fields(fields: Dict[str, str], response_in_field: str) -> Dict:
    return {
        "frame_no": to_int(fields.get("frame.number")) or 0,
        "time": to_float(fields.get("frame.time_epoch")) or 0.0,
        "src_ip": clean(fields.get("ip.src")),
        "dst_ip": clean(fields.get("ip.dst")),
        "src_port": to_int(fields.get("tcp.srcport")) or 0,
        "dst_port": to_int(fields.get("tcp.dstport")) or 0,
        "stream": to_int(fields.get("tcp.stream")) or -1,
        "method": clean(fields.get("http.request.method")),
        "uri": clean(fields.get("http.request.uri")),
        "host": clean(fields.get("http.host")),
        "content_type": clean(fields.get("http.content_type")),
        "request_body": decode_http_file_data(fields.get("http.file_data")),
        "response_in_frame": to_int(fields.get(response_in_field)),
    }


def build_response_from_fields(fields: Dict[str, str], request_in_field: str) -> Dict:
    return {
        "frame_no": to_int(fields.get("frame.number")) or 0,
        "time": to_float(fields.get("frame.time_epoch")) or 0.0,
        "src_ip": clean(fields.get("ip.src")),
        "dst_ip": clean(fields.get("ip.dst")),
        "src_port": to_int(fields.get("tcp.srcport")) or 0,
        "dst_port": to_int(fields.get("tcp.dstport")) or 0,
        "stream": to_int(fields.get("tcp.stream")) or -1,
        "status_code": to_int(fields.get("http.response.code")) or 0,
        "response_phrase": clean(fields.get("http.response.phrase")),
        "response_body_excerpt": decode_http_file_data(fields.get("http.file_data")),
        "request_in_frame": to_int(fields.get(request_in_field)),
    }


def main():
    parser = argparse.ArgumentParser(description="持续抓包并按完整 HTTP 请求/响应记录生成 1.1.n.txt")
    parser.add_argument("--port", type=int, default=10086, help="抓包端口，默认 10086")
    parser.add_argument("--batch-size", type=int, default=20, help="每个 batch 的完整请求/响应数量")
    parser.add_argument("--input-dir", default="input", help="输出 txt 目录")
    parser.add_argument("--interface", default="", help="手动指定网卡关键字")
    parser.add_argument("--decode-http-port", type=int, default=None, help="强制 HTTP 解码端口，默认等于 --port")
    parser.add_argument("--keep-running", action="store_true", default=True, help="持续运行直到 Ctrl+C")
    parser.add_argument("--once", action="store_true", help="仅生成一个 batch 后退出")
    args = parser.parse_args()

    decode_port = args.decode_http_port if args.decode_http_port is not None else args.port

    tshark_exe = find_executable("tshark")
    request_in_field, response_in_field = detect_http_link_fields(tshark_exe)

    input_dir = Path(args.input_dir)
    input_dir.mkdir(parents=True, exist_ok=True)

    interfaces = list_interfaces(tshark_exe)
    iface = choose_interface(interfaces, preferred_name=args.interface)

    print("=" * 80)
    print("自动抓包启动（完整 HTTP 请求/响应配对模式）")
    print("tshark:", tshark_exe)
    print("网卡:", iface)
    print("端口:", args.port)
    print("HTTP decode 端口:", decode_port)
    print("batch 大小:", args.batch_size)
    print("input 目录:", input_dir.resolve())
    print("request_in 字段:", request_in_field)
    print("response_in 字段:", response_in_field)
    print("=" * 80)

    headers = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
        "http.request.method",
        "http.request.uri",
        "http.host",
        "http.content_type",
        "http.file_data",
        "http.response.code",
        "http.response.phrase",
        request_in_field,
        response_in_field,
    ]

    cmd = [
        tshark_exe,
        "-l",
        "-n",
        "-i",
        str(iface),
        "-f",
        f"tcp port {args.port}",
        "-Y",
        "http.request or http.response",
        "-d",
        f"tcp.port=={decode_port},http",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]

    for h in headers:
        cmd.extend(["-e", h])

    print("执行命令:")
    print(" ".join(cmd))

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )

    pending_by_frame: Dict[int, Dict] = {}
    pending_stream_queue: Dict[int, List[int]] = {}
    completed_cases: List[Dict] = []

    next_idx = next_file_index(input_dir, prefix="1.1.")
    print(f"下一个输出编号从 1.1.{next_idx}.txt 开始")

    try:
        while True:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                time.sleep(0.05)
                continue

            line = line.rstrip("\r\n")
            if not line:
                continue

            fields = parse_tshark_line(line, headers)

            method = clean(fields.get("http.request.method"))
            code = clean(fields.get("http.response.code"))

            if method:
                req = build_request_from_fields(fields, response_in_field=response_in_field)
                frame_no = req["frame_no"]
                pending_by_frame[frame_no] = req
                stream = req.get("stream", -1)
                if stream not in pending_stream_queue:
                    pending_stream_queue[stream] = []
                pending_stream_queue[stream].append(frame_no)

            elif code:
                resp = build_response_from_fields(fields, request_in_field=request_in_field)
                req = None

                request_frame = resp.get("request_in_frame")
                if request_frame and request_frame in pending_by_frame:
                    req = pending_by_frame.pop(request_frame)
                    q = pending_stream_queue.get(req.get("stream", -1), [])
                    if request_frame in q:
                        q.remove(request_frame)
                else:
                    stream = resp.get("stream", -1)
                    q = pending_stream_queue.get(stream, [])
                    while q:
                        candidate_frame = q.pop(0)
                        if candidate_frame in pending_by_frame:
                            req = pending_by_frame.pop(candidate_frame)
                            break

                if req:
                    completed_cases.append({"request": req, "response": resp})

                    if len(completed_cases) >= args.batch_size:
                        file_id = f"1.1.{next_idx}"
                        output_txt = input_dir / f"{file_id}.txt"
                        to_write = completed_cases[: args.batch_size]
                        write_canonical_batch(output_txt, file_id=file_id, batch_size=args.batch_size, port=decode_port, cases=to_write)

                        seq_from = 1
                        seq_to = len(to_write)
                        preview_uris = [c["request"].get("uri", "") for c in to_write[:3]]

                        print(f"[OK] generated {output_txt}")
                        print(f"cases={len(to_write)}")
                        print(f"seq_range={seq_from}-{seq_to}")
                        print(f"uri_preview={preview_uris}")

                        completed_cases = completed_cases[args.batch_size :]
                        next_idx += 1

                        if args.once:
                            break

            if args.once and proc.poll() is not None:
                break

    except KeyboardInterrupt:
        print("\n收到 Ctrl+C，正在停止抓包...")
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

        if proc.stderr:
            err = proc.stderr.read().strip()
            if err:
                print("\n[tshark STDERR]")
                print(err)

        print("抓包已停止。")


if __name__ == "__main__":
    main()
